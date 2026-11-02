#!/usr/bin/env python
"""
Controls the fan speed of IPMI servers that don't allow adjusting their fan curve,
by reading CPU temperatures and setting the fan zones manually.
"""
import getopt
import logging
import signal
import sys
from array import array
from time import sleep

import pyipmi
import pyipmi.interfaces
import yaml

from logging_setup import logger, set_log_level

# Seconds between control loop iterations
LOOP_INTERVAL = 3

# Consecutive loops without a CPU temperature before giving up and
# handing control back to the BMC
MAX_FAILED_READS = 10

SENSOR_RECORD_TYPES = (
    pyipmi.sdr.SDR_TYPE_FULL_SENSOR_RECORD,
    pyipmi.sdr.SDR_TYPE_COMPACT_SENSOR_RECORD,
)


def sigterm_handler(_signum, _frame):
    """
    Turn SIGTERM into a normal exit, so cleanup in main() runs
    """
    logger.warning("Received SIGTERM, exiting")
    sys.exit(0)


def handle_exception(message, error=None, exit_code=None):
    """
    Standardize how we output exceptions and errors.

    Parameters:
    - message (str): The main error message.
    - error (Exception or str): The exception object or additional error details.
    - exit_code (int): The exit code to use when exiting the program.
    """
    if error:
        if isinstance(error, str):
            logger.error("%s: %s", message, error)
        else:
            logger.exception("%s: %s", message, str(error))
    else:
        logger.error(message)

    if exit_code is not None:
        sys.exit(exit_code)


class IPMI:
    """
    Handles the ipmi communication and related functions
    Also takes care of the configuration handling
    """

    # pylint: disable=too-many-instance-attributes

    def __init__(self, config_file_path="config.yaml"):
        self.configuration = None
        self.ipmi_session = None
        self.ipmi_interface = None

        self.ambient_temp_sensor_ids = []
        self.cpu_temp_sensor_ids = []
        self.fanspeed_sensor_ids = []
        self.fan_zone_ids = []
        self.sdr_records = {}

        self.load_configuration(config_file_path)

    def close_session(self):
        """
        Tries to switch back to automatic fan profile and closes the session
        """
        if not self.ipmi_session:
            return
        logger.warning("Trying to switch back to automatic fan control")
        self.set_automatic_fanspeed()
        try:
            self.ipmi_session.session.close()
        except Exception as e:
            handle_exception("Error closing IPMI session", e)
        self.ipmi_session = None

    def load_configuration(self, config_file_path):
        """
        Loads and verifies the configuration file
        """
        try:
            with open(config_file_path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f)
        except Exception as e:
            handle_exception(f"Can't load {config_file_path}", e, exit_code=3)

        if cfg is None or "ipmi" not in cfg:
            handle_exception("Please define 'ipmi' object", exit_code=2)

        ipmi_config = cfg["ipmi"]

        for key in ("hostname", "username", "password"):
            if key not in ipmi_config:
                handle_exception(f"Please define 'ipmi.{key}'", exit_code=2)

        if not cfg.get("temp_speed"):
            handle_exception("Please define 'temp_speed'", exit_code=2)

        self.configuration = {
            "port": ipmi_config.get("port", 623),
            "hostname": ipmi_config["hostname"],
            "username": ipmi_config["username"],
            "password": ipmi_config["password"],
            "temp_speed_curve": cfg["temp_speed"]
        }

        logger.info("Configuration loaded successfully")

    def _set_fan_zones(self, speed, manual):
        """
        Sends the IBM/Lenovo OEM fan command to every fan zone.
        With manual=False the BMC takes back control and speed is ignored.
        """
        data_mode = 0x01 if manual else 0x00
        for (index, fanzone) in enumerate(self.fan_zone_ids):
            data = array('B', [0x07, index + 1, speed, data_mode]).tobytes()
            output = self.ipmi_session.raw_command(0, 0x3a, data)
            logger.log(
                logging.DEBUG if manual else logging.WARNING,
                "Switching fan profile in zone %d (ID: %x) to %s",
                index,
                fanzone,
                f"manual control at {int(speed / 255 * 100)}%" if manual else "automatic",
                extra={"output": output}
            )

    def set_automatic_fanspeed(self):
        """
        Hands fan control back to the BMC
        """
        try:
            self._set_fan_zones(0xff, manual=False)
            return True
        except Exception as e:
            handle_exception("Setting fan profile to automatic failed", e)
            return False

    def set_fanspeed(self, speed=255):
        """
        Sets all fan zones to a manual speed (0-255)
        """
        try:
            self._set_fan_zones(speed, manual=True)
            return True
        except Exception as e:
            handle_exception("Setting fan profile to manual failed", e)
            self.set_automatic_fanspeed()
            return False

    def get_device_attributes(self):
        """
        Retrieves and logs IPMI device attributes
        """
        try:
            device_id = self.ipmi_session.get_device_id()
            logoutput = {}

            attribute_mapping = {
                "device_id": "device_id",
                "revision": "device_revision",
                "fw_revision": "fw_revision",
                "ipmi_version": "ipmi_version",
                "manufacturer_id": "manufacturer_id",
                "product_id": "product_id",
                "available": "available",
                "provides_sdrs": "SDRs",
                "aux": "aux_firmware"
            }

            for attribute_name, output_key in attribute_mapping.items():
                if hasattr(device_id, attribute_name):
                    logoutput[output_key] = getattr(device_id, attribute_name)

            functions = (
                ('SENSOR', 'Sensor Device'),
                ('SDR_REPOSITORY', 'SDR Repository Device'),
                ('SEL', 'SEL Device'),
                ('FRU_INVENTORY', 'FRU Inventory Device'),
                ('IPMB_EVENT_RECEIVER', 'IPMB Event Receiver'),
                ('IPMB_EVENT_GENERATOR', 'IPMB Event Generator'),
                ('BRIDGE', 'Bridge'),
                ('CHASSIS', 'Chassis Device')
            )
            logoutput["functions"] = [s for n, s in functions if device_id.supports_function(n)]

            logger.debug("Device information", extra={"device_information": logoutput})
        except Exception as e:
            handle_exception("Can't get device attributes", e, exit_code=2)

    def initialize(self):
        """
        Initialize the IPMI handler and configuration
        """
        try:
            logger.debug("Creating IPMI interface")

            self.ipmi_interface = pyipmi.interfaces.create_interface(
                interface='rmcp',
                keep_alive_interval=10
            )

            logger.debug("Creating IPMI session")

            self.ipmi_session = pyipmi.create_connection(self.ipmi_interface)

            self.ipmi_session.session.set_session_type_rmcp(
                host=self.configuration["hostname"],
                port=self.configuration["port"]
            )
            self.ipmi_session.session.set_auth_type_user(
                username=self.configuration["username"],
                password=self.configuration["password"]
            )

            self.ipmi_session.target = pyipmi.Target(ipmb_address=0x20)

            logger.debug("Trying to establish IPMI connection")
            self.ipmi_session.session.establish()
            logger.info("IPMI connection established!")

        except Exception as e:
            handle_exception("Can't establish IPMI session", e, exit_code=2)

    def parse_sdr_list_entry(self, record_id, number, id_string, value, states):
        """
        Sorts a scanned sensor into the right list based on its name and state
        """
        # pylint: disable=too-many-arguments,too-many-positional-arguments
        foundtype = None
        name = (id_string or "").lower()

        if states == 0xc0:
            if "temp" in name:
                if "ambient" in name:
                    self.ambient_temp_sensor_ids.append(record_id)
                    foundtype = "Ambient temp"
                elif "cpu" in name:
                    self.cpu_temp_sensor_ids.append(record_id)
                    foundtype = "CPU temp"
                else:
                    foundtype = "UNKNOWN"
            if "fan" in name:
                self.fanspeed_sensor_ids.append(record_id)
                foundtype = "fan"

        if states == 0x8001 and "fan zone" in name:
            self.fan_zone_ids.append(record_id)
            foundtype = "fan zone"

        logger.debug("SDR_repository_scan", extra={
            "record_id": record_id,
            "number": str(number) if number else 'na',
            "id_string": id_string,
            "value": value,
            "states": hex(states) if states else 'na',
            "found_type": foundtype
        })

    def read_sensor(self, sdr):
        """
        Returns (value, states) for a sensor record, value converted to its unit when possible
        """
        (value, states) = self.ipmi_session.get_sensor_reading(sdr.number)
        if value is not None and sdr.type is pyipmi.sdr.SDR_TYPE_FULL_SENSOR_RECORD:
            value = sdr.convert_sensor_raw_to_value(value)
        return (value, states)

    def get_sdr_list(self):
        """
        Scans the SDR repository for temperature sensors and fan zones
        """
        logger.info("Starting scan of SDRs")

        device_id = self.ipmi_session.get_device_id()
        if device_id.supports_function('sdr_repository'):
            iter_fct = self.ipmi_session.sdr_repository_entries
        elif device_id.supports_function('sensor'):
            iter_fct = self.ipmi_session.device_sdr_entries
        else:
            handle_exception("BMC provides neither an SDR repository nor sensors", exit_code=2)
            return

        for s in iter_fct():
            self.sdr_records[s.id] = s
            if s.type not in SENSOR_RECORD_TYPES:
                continue
            try:
                (value, states) = self.read_sensor(s)
                self.parse_sdr_list_entry(s.id, s.number, s.device_id_string, value, states)
            except pyipmi.errors.CompletionCodeError as e:
                logger.warning("unknown CC", extra={
                    "id": s.id,
                    "number": s.number,
                    "device_id_string": s.device_id_string,
                    "CC": e.cc
                })
        logger.info("Done scanning SDRs")

    def get_sensor_readings(self, ids):
        """
        Reads the given sensors, skipping any that fail or return no value
        """
        readings = []

        for sensor in ids:
            try:
                # Use the SDR cached during the startup scan; re-fetching it
                # needs an SDR reservation, which the BMC sometimes rejects
                s = self.sdr_records.get(sensor)
                if s is None:
                    s = self.ipmi_session.get_repository_sdr(sensor)
                    self.sdr_records[sensor] = s

                (value, _) = self.read_sensor(s)
                if value is not None:
                    readings.append(value)

            except Exception:
                logger.exception("couldn't get sensor reading!")

        return readings


def interpolate_speed(temperature_dict, target_temp):
    """
    Linearly interpolates a fan speed (percent) from a {temperature: speed} curve,
    clamping to the ends of the curve
    """
    temperatures = sorted(temperature_dict.keys())

    if target_temp <= temperatures[0]:
        return temperature_dict[temperatures[0]]
    if target_temp >= temperatures[-1]:
        return temperature_dict[temperatures[-1]]
    if target_temp in temperature_dict:
        return temperature_dict[target_temp]

    low_temp = max(t for t in temperatures if t < target_temp)
    high_temp = min(t for t in temperatures if t > target_temp)
    low_speed = temperature_dict[low_temp]
    high_speed = temperature_dict[high_temp]

    return low_speed + (high_speed - low_speed) * (target_temp - low_temp) / (high_temp - low_temp)


def get_opts():
    """
    Parses command line options
    """
    try:
        opts, _ = getopt.getopt(sys.argv[1:], 'vd', ['verbose', 'debug'])
    except getopt.GetoptError as err:
        handle_exception("Couldn't parse opts", err, 2)

    for o, _ in opts:
        if o in ('-v', '--verbose', '-d', '--debug'):
            set_log_level(logging.DEBUG)
    logger.debug("parsed opts")


def control_loop(ipmicontroller):
    """
    Reads temperatures and sets fan speeds until something goes wrong
    """
    failed_reads = 0
    while True:
        cpu_temps = ipmicontroller.get_sensor_readings(ipmicontroller.cpu_temp_sensor_ids)
        ambient_temps = ipmicontroller.get_sensor_readings(ipmicontroller.ambient_temp_sensor_ids)

        if not cpu_temps:
            failed_reads += 1
            if failed_reads >= MAX_FAILED_READS:
                raise RuntimeError(f"no CPU temperature readings in {failed_reads} attempts")
            logger.warning("no CPU temperature readings, retrying", extra={"failed_reads": failed_reads})
            sleep(LOOP_INTERVAL)
            continue
        failed_reads = 0

        cpu_temp = max(cpu_temps)
        ambient_temp = max(ambient_temps) if ambient_temps else None

        target_pct = interpolate_speed(ipmicontroller.configuration["temp_speed_curve"], cpu_temp)
        targetspeed = round(target_pct * 2.55)

        logger.info("status", extra={
            "ambient_temp": ambient_temp,
            "cpu_temp": cpu_temp,
            "target_speed": targetspeed,
            "target_speed_pct": int(targetspeed / 255 * 100)
        })

        ipmicontroller.set_fanspeed(targetspeed)
        sleep(LOOP_INTERVAL)


def main():
    """
    Sets up the IPMI connection and runs the control loop.
    Always tries to hand fan control back to the BMC on the way out.
    """
    signal.signal(signal.SIGTERM, sigterm_handler)
    get_opts()

    ipmicontroller = IPMI()
    ipmicontroller.initialize()
    try:
        ipmicontroller.get_device_attributes()
        ipmicontroller.get_sdr_list()
        logger.info("Starting the control loop")
        control_loop(ipmicontroller)
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        handle_exception("Main control loop error", e, exit_code=9)
    finally:
        logger.warning("Exiting gracefully if possible, if it gets stuck, try ^C")
        ipmicontroller.close_session()


if __name__ == '__main__':
    main()

#!/usr/bin/env python
"""
Does stuff you know
"""
import sys
import signal
import getopt
import atexit
import yaml

import pyipmi
import pyipmi.interfaces

from array import array
from time import sleep

from logging_setup import logger, set_log_level
import logging

def sigterm_handler(signum, frame):
    print("Received SIGTERM. Exiting...")
    # Perform any cleanup or additional actions here
    if ipmicontroller in globals():
        ipmicontroller.close_session()
    sys.exit(0)

def handle_exception(message, error=None, exit_code=None):
    """
    Standardize how we output exceptions and errors.

    Parameters:
    - message (str): The main error message.
    - error (Exception or str): The exception object or additional error details.
    - exit_code (int): The exit code to use when exiting the program.
    - ipmi_session (IPMISession): An optional IPMI session to close.
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

        self.sigint_count = 0
        self.register_exit_handler()

        self.load_configuration(config_file_path)

    def register_exit_handler(self):
        atexit.register(self.exit_handler)

    def exit_handler(self):
        try:
            if self.sigint_count == 0:
                self.sigint_count += 1
                logger.warning("Exiting gracefully if possible, if it gets stuck, try ^C")
                try:
                    self.close_session()
                except Exception as e:
                    handle_exception("Couldn't close IPMI session", e, exit_code=5)
            else:
                try:
                    sys.exit(130)
                except SystemExit as se:
                    # Ignore the SystemExit exception
                    pass
        except Exception as e:
            handle_exception("Couldn't exit gracefully", e)

    def close_session(self):
        """
        Tries to switch back to automatic fan profile and closes the session
        """
        if self.ipmi_session:
            try:
                try:
                    logger.warning("Trying to switch back to automatic fan control")
                    self.set_automatic_fanspeed()
                except Exception as e:
                    handle_exception("Couldn't switch back to automatic fan control", e)
                self.ipmi_session.session.close()
                self.ipmi_session = None  # Reset session after closing
            except Exception as e:
                handle_exception("Error closing IPMI session", e)

    def load_configuration(self, config_file_path):
        """
        Loads and verifies the configuration file
        """
        try:
            with open(config_file_path, encoding="utf-8") as f:
                cfg = yaml.load(f, Loader=yaml.FullLoader)
        except Exception as e:
            handle_exception(f"Can't load {config_file_path}", e, exit_code=3)

        if cfg == None or "ipmi" not in cfg:
            handle_exception("Please define 'ipmi' object", exit_code=2)

        ipmi_config = cfg["ipmi"]

        required_keys = ["hostname", "username", "password"]
        for key in required_keys:
            if key not in ipmi_config:
                handle_exception(f"Please define 'ipmi.{key}'", exit_code=2)

        if "temp_speed" not in cfg:
            handle_exception("Please define 'temp_speed_curve'", exit_code=2)

        self.configuration = {
            "port": ipmi_config.get("port", 623),
            "hostname": ipmi_config["hostname"],
            "username": ipmi_config["username"],
            "password": ipmi_config["password"],
            "temp_speed_curve": cfg["temp_speed"]
        }

        logger.info("Configuration loaded successfully")


    def set_automatic_fanspeed(self):
        try:
            for (index, fanzone) in enumerate(self.fan_zone_ids):
                data = array('B', [0x07, index + 1, 0xff, 0x00]).tobytes()
                output = self.ipmi_session.raw_command(0, 0x3a, data)
                # output = cmd_raw(ipmi, ["0x3a", "0x07", "0x01", "0xff", "0x01"])
                logger.warning(
                    "Switching fan profile in zone %d (ID: %x) to automatic",
                    index,
                    fanzone,
                    extra={"output": output}
                )
            return True
        except Exception as err:
            logger.error("setting fan profile to automatic failed", err)
            return False

    def get_device_attributes(self):
        """
        Retrieves and prints IPMI device attributes
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
            logoutput["functions"] = []
            for n, s in functions:
                if device_id.supports_function(n):
                    logoutput["functions"].append(s)

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
        foundtype = None

        if number:
            number = str(number)
        else:
            number = 'na'

        if states:
            states = hex(states)
        else:
            states = 'na'

        if states == hex(0xc0):
            if "temp" in id_string.lower():
                if "ambient" in id_string.lower():
                    self.ambient_temp_sensor_ids.append(record_id)
                    foundtype = "Ambient temp"
                elif "cpu" in id_string.lower():
                    self.cpu_temp_sensor_ids.append(record_id)
                    foundtype = "CPU temp"
                else:
                    foundtype = "UNKNOWN"
            if "fan" in id_string.lower():
                self.fanspeed_sensor_ids.append(record_id)
                foundtype = "fan"

        if states == hex(0x8001):
            if "fan zone" in id_string.lower():
                self.fan_zone_ids.append(record_id)
                foundtype = "fan zone"

        logger.debug("SDR_repository_scan", extra={
            "record_id": record_id,
            "number": number,
            "id_string": id_string,
            "value": value,
            "states": states,
            "found_type": foundtype
        })


    def get_sdr_list(self):
        logger.info("Starting scan of SDRs")
        iter_fct = None

        device_id = self.ipmi_session.get_device_id()
        if device_id.supports_function('sdr_repository'):
            iter_fct = self.ipmi_session.sdr_repository_entries
        elif device_id.supports_function('sensor'):
            iter_fct = self.ipmi_session.device_sdr_entries

        for s in iter_fct():
            try:
                number = None
                value = None
                states = None

                if s.type is pyipmi.sdr.SDR_TYPE_FULL_SENSOR_RECORD:
                    (value, states) = self.ipmi_session.get_sensor_reading(s.number)
                    number = s.number
                    if value is not None:
                        value = s.convert_sensor_raw_to_value(value)

                elif s.type is pyipmi.sdr.SDR_TYPE_COMPACT_SENSOR_RECORD:
                    (value, states) = self.ipmi_session.get_sensor_reading(s.number)
                    number = s.number

                id_string = getattr(s, 'device_id_string', None)

                self.parse_sdr_list_entry(s.id, number, id_string, value, states)

            except pyipmi.errors.CompletionCodeError as e:
                if s.type in (
                  pyipmi.sdr.SDR_TYPE_COMPACT_SENSOR_RECORD,
                  pyipmi.sdr.SDR_TYPE_FULL_SENSOR_RECORD):
                    logger.warning("unknown CC", extra={
                        "id": s.id,
                        "number": s.number,
                        "device_id_string": s.device_id_string,
                        "CC": e.cc
                    })
        logger.info("Done scanning SDRs")


    def get_sensor_readings(self, ids):
        if len(ids) <1:
            return

        readings = []

        for sensor in ids:
            try:
                number = None
                value = None
                states = None

                s = self.ipmi_session.get_repository_sdr(sensor)

                if s.type is pyipmi.sdr.SDR_TYPE_FULL_SENSOR_RECORD:
                    (value, states) = self.ipmi_session.get_sensor_reading(s.number)
                    number = s.number
                    if value is not None:
                        value = s.convert_sensor_raw_to_value(value)

                elif s.type is pyipmi.sdr.SDR_TYPE_COMPACT_SENSOR_RECORD:
                    (value, states) = self.ipmi_session.get_sensor_reading(s.number)
                    number = s.number

                readings.append(value)

            except Exception as err:
                logger.exception("couldn't get sensor reading!")

        return readings


    def set_fanspeed(self, speed=255):
        try:
            for (index, fanzone) in enumerate(self.fan_zone_ids):
                data = array('B', [0x07, index + 1, speed, 0x01]).tobytes()
                output = self.ipmi_session.raw_command(0, 0x3a, data)
                # output = cmd_raw(ipmi, ["0x3a", "0x07", "0x01", "0xff", "0x01"])
                logger.debug(
                    "Switching fan profile in zone %d (ID: %x) to manual control at %d%%",
                    index,
                    fanzone,
                    int(float(speed/255)*100),
                    extra={"output": output}
                )
            return True
        except Exception as err:
            logger.error("setting fan profile to manual failed", err)
            set_automatic_fanspeed(zones)
            return False

    def interpolate_speed(self, temperature_dict, target_temp):
        temperatures = sorted(temperature_dict.keys())

        # If target_temp is outside the range, return the lowest or highest speed
        if target_temp < temperatures[0]:
            return temperature_dict[temperatures[0]]
        elif target_temp > temperatures[-1]:
            return temperature_dict[temperatures[-1]]

        # Finding the nearest temperatures
        low_temp = max(t for t in temperatures if t <= target_temp)
        high_temp = min(t for t in temperatures if t >= target_temp)

        # If the target_temp is in the dictionary
        if target_temp in temperature_dict:
            return temperature_dict[target_temp]

        # Perform linear interpolation
        low_speed = temperature_dict[low_temp]
        high_speed = temperature_dict[high_temp]

        # Calculate the speed at the target temperature using
        # linear interpolation formula
        target_speed = low_speed + (high_speed - low_speed) *\
            (target_temp - low_temp) / (high_temp - low_temp)

        return target_speed



def get_opts():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'vd', ['verbose', 'debug'])
    except getopt.GetoptError as err:
        handle_exception("Couldn't parse opts", err, 2)

    for o, a in opts:
        if o in ('-v','--verbose'):
            set_log_level(logging.DEBUG)
        elif o in ('-d', '--debug'):
            set_log_level(logging.DEBUG)
        else:
            assert False, 'unhandled option'
    logger.debug("parsed opts")


def main():
    get_opts()

    global ipmicontroller
    ipmicontroller = IPMI()
    ipmicontroller.initialize()
    ipmicontroller.get_device_attributes()
    ipmicontroller.get_sdr_list()
    logger.info(
        "Telling we've started up by setting the fans to 100%% for 2 secs, "
        "then 1% for 2 secs, then 100% for 2 secs, and then starting the control loop"
    )
    ipmicontroller.set_fanspeed(255)
    sleep(2)
    ipmicontroller.set_fanspeed(1)
    sleep(2)
    ipmicontroller.set_fanspeed(255)
    sleep(2)
    try:
        while True:
            cpu_temp = max(ipmicontroller.get_sensor_readings(ipmicontroller.cpu_temp_sensor_ids))
            ambient_temp = max(ipmicontroller.get_sensor_readings(ipmicontroller.ambient_temp_sensor_ids))

            targetspeed = round(ipmicontroller.interpolate_speed(ipmicontroller.configuration["temp_speed_curve"], cpu_temp) * 2.55)

            logger.info("status", extra={
                "ambient_temp": ambient_temp,
                "cpu_temp": cpu_temp,
                "target_speed": targetspeed,
                "target_speed_pct": int(float(targetspeed/255)*100)
            })

            ipmicontroller.set_fanspeed(targetspeed)
            sleep(3)
    except Exception as err:
        handle_exception("Main control loop error", err)
        try:
            ipmicontroller.set_automatic_fanspeed()
        except:
            logger.error("couldn't switch to automatic fan profile")
        ipmicontroller.close_session()
        sys.exit(9)

    ipmicontroller.close_session()

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, sigterm_handler)
    try:
        main()
    except KeyboardInterrupt:
        # Handle Ctrl+C or other exceptions gracefully
        sys.exit(1)
    except Exception as e:
        handle_exception("Shit hit the fan", e, exit_code=1)
    finally:
        # Ensure exit_handler is called on normal program termination
        if 'ipmicontroller' in globals():
            ipmicontroller.exit_handler()

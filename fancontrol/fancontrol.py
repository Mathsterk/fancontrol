#!/usr/bin/env python
import sys
import signal
import getopt
import logging
import datetime
from array import array
from time import sleep

import pyipmi
import pyipmi.interfaces

import yaml
from pythonjsonlogger import jsonlogger

ctrl_c_counter = 0


def signal_handler(
    sig,
    frame,
    logger,
    ipmi_session
):
    """
    Handle ctrl+c
    on the first one, try to exit cleanly
    on the second, exit forcefully
    """
    global ctrl_c_counter
    logger.warning("You pressed Ctrl+C! %d times", ctrl_c_counter)
    if ctrl_c_counter <= 1:
        if ipmi_session:
            ipmi_session.close_session()
    else:
        logger.error("Closing forcefully, goodbye!")
        sys.exit(130)


def handle_exception(
    logger,
    message,
    err=None,
    exit_code=None,
    ipmi_session=None
):
    """
    Standardise how we output exceptions and errors
    """
    if err:
        if isinstance(err, str):
            logger.error(f"{message}: {err}")
        else:
            logger.exception(f"{message}: {str(err)}")
    else:
        logger.error(message)

    if ipmi_session:
        try:
            ipmi_session.close()  # Close the IPMI session
        except Exception as e:
            logger.error(f"Error while closing IPMI session: {str(e)}")

    if exit_code is not None:
        sys.exit(exit_code)


class IPMI:
    """
    Handles the ipmi communication and related functions
    Also takes care of the configuration handling
    """

    def __init__(self, configuration):
        self.configuration = configuration
        self.ipmi_session = None

    def close_session(self):
        """
        Tries to switch back to automatic fan profile and closes the session
        """
        if self.ipmi_session:
            try:
                try:
                    logger.warning("Trying to switch back to automatic fan control")
                    self.set_automatic_fanspeed()
                except as e:
                    handle_exception(logger, "Couldn't switch back to automatic fan control", e)
                self.ipmi_session.close()
                self.ipmi_session = None  # Reset session after closing
            except Exception as e:
                raise RuntimeError("Error closing IPMI session") from e

    def load_configuration(self):
        """
        Loads and verifies the configuration file
        """
        configuration = {
            "port": 623,
            "hostname": None,
            "username": None,
            "password": None,
            "temp_speed": {
                None: None
            }
        }

        logger.info("Trying to open and parse configuration file")

        try:
            with open("config.yaml", encoding="utf-8") as f:
                cfg = yaml.load(f, Loader=yaml.FullLoader)
        except Exception as e:
            handle_exception(logger, "Can't load config.yaml", e, exit_code=1)

        if "ipmi" not in cfg:
            handle_exception(logger, "please define ipmi object")

        if "port" in cfg["ipmi"]:
            configuration["port"] = cfg["ipmi"]["port"]

        if "hostname" in cfg["ipmi"]:
            configuration["hostname"] = cfg["ipmi"]["hostname"]
        else:
            handle_exception(logger, "please define ipmi.hostname", exit_code=1)

        if "username" in cfg["ipmi"]:
            configuration["username"] = cfg["ipmi"]["username"]
        else:
            handle_exception(logger, "please define ipmi.username", exit_code=1)

        if "password" in cfg["ipmi"]:
            configuration["password"] = cfg["ipmi"]["password"]
        else:
            handle_exception(logger, "please define ipmi.password", exit_code=1)

        if "temp_speed" in cfg:
            configuration["temp_speed"] = cfg["temp_speed"]
        else:
            handle_exception(logger, "please define temp_speed", exit_code=1)

        logger.info("Configuration loaded successfully")
        return configuration


    def get_device_attributes(self):
        """
        Retrieves and prints IPMI device attributes
        """
        try:
            device_id = ipmi.get_device_id()
            logoutput = {}
            if "device_id" in device_id.__dict__:
                logoutput["device_id"] = device_id.device_id
            if "revision" in device_id.__dict__:
                logoutput["device_revision"] = device_id.revision
            if "fw_revision" in device_id.__dict__:
                logoutput["fw_revision"] = device_id.fw_revision
            if "ipmi_version" in device_id.__dict__:
                logoutput["ipmi_version"] = device_id.ipmi_version
            if "manufacturer_id" in device_id.__dict__:
                logoutput["manufacturer_id"] = device_id.manufacturer_id
            if "product_id" in device_id.__dict__:
                logoutput["product_id"] = device_id.product_id
            if "available" in device_id.__dict__:
                logoutput["available"] = device_id.available
            if "provides_sdrs" in device_id.__dict__:
                logoutput["SDRs"] = device_id.provides_sdrs
            if "aux" in device_id.__dict__:
                logoutput["aux_firmware"] = device_id.aux
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

            logger.info("Device information", extra=logoutput)
        except Exception as e:
            handle_exception(logger, "Can't establish IPMI session", e, exit_code=2)


    def initialize(self):
        """
        Initialize the IPMI handler and configuration
        """
        configuration = self.load_configuration()

        try:
            logger.info("Trying to establish IPMI session")
            logger.debug("trying to establish ipmi conenction")
            interface = pyipmi.interfaces.create_interface(
                interface='rmcp',
                keep_alive_interval=1
            )

            global ipmi
            ipmi = pyipmi.create_connection(interface)
            ipmi.session.set_session_type_rmcp(
                host=configuration["hostname"],
                port=configuration["port"]
            )
            ipmi.session.set_auth_type_user(
                username=configuration["username"],
                password=configuration["password"]
            )
            ipmi.target = pyipmi.Target(ipmb_address=0x20)
            ipmi.session.establish()

            return configuration, ipmi
        except Exception as e:
            handle_exception(logger, "Can't establish IPMI session", e, exit_code=2)


def print_sdr_list_entry(record_id, number, id_string, value, states):
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
                ambient_temp_sensor_ids.append(record_id)
                foundtype = "Ambient temp"
            elif "cpu" in id_string.lower():
                cpu_temp_sensor_ids.append(record_id)
                foundtype = "CPU temp"
            else:
                foundtype = "UNKNOWN"
        if "fan" in id_string.lower():
            fanspeed_sensor_ids.append(record_id)
            foundtype = "fan"

    if states == hex(0x8001):
        if "fan zone" in id_string.lower():
            zone_ids.append(record_id)
            foundtype = "fan zone"

    # if states == hex(0x8001) or states == hex(0xc0):
    # print("0x%04x | %3s | %-18s | %9s | %s" % (record_id, number, id_string, value, states))
    if foundtype == "UNKNOWN":
        logger.warning("SDR_repository_scan", extra={
            "record_id": record_id,
            "number": number,
            "id_string": id_string,
            "value": value,
            "states": states,
            "found_type": foundtype
        })
    else:
        logger.info("SDR_repository_scan", extra={
            "record_id": record_id,
            "number": number,
            "id_string": id_string,
            "value": value,
            "states": states,
            "found_type": foundtype
        })


def cmd_sdr_list():
    iter_fct = None

    device_id = ipmi.get_device_id()
    if device_id.supports_function('sdr_repository'):
        iter_fct = ipmi.sdr_repository_entries
    elif device_id.supports_function('sensor'):
        iter_fct = ipmi.device_sdr_entries

    for s in iter_fct():
        try:
            number = None
            value = None
            states = None

            if s.type is pyipmi.sdr.SDR_TYPE_FULL_SENSOR_RECORD:
                (value, states) = ipmi.get_sensor_reading(s.number)
                number = s.number
                if value is not None:
                    value = s.convert_sensor_raw_to_value(value)

            elif s.type is pyipmi.sdr.SDR_TYPE_COMPACT_SENSOR_RECORD:
                (value, states) = ipmi.get_sensor_reading(s.number)
                number = s.number

            id_string = getattr(s, 'device_id_string', None)

            print_sdr_list_entry(s.id, number, id_string, value, states)

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


def get_sensor_readings(ids):
    if len(ids) <1:
        return

    readings = []

    for fan in ids:
        try:
            number = None
            value = None
            states = None

            s = ipmi.get_repository_sdr(fan)

            if s.type is pyipmi.sdr.SDR_TYPE_FULL_SENSOR_RECORD:
                (value, states) = ipmi.get_sensor_reading(s.number)
                number = s.number
                if value is not None:
                    value = s.convert_sensor_raw_to_value(value)

            elif s.type is pyipmi.sdr.SDR_TYPE_COMPACT_SENSOR_RECORD:
                (value, states) = ipmi.get_sensor_reading(s.number)
                number = s.number

            readings.append(value)

        except Exception as err:
            logger.exception("couldn't get sensor reading!")

    return readings


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        if not log_record.get('timestamp'):
            # this doesn't use record.created, so it is slightly off
            now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            log_record['timestamp'] = now
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname


def set_fanspeed(zones, speed=255):
    try:
        for (index, fanzone) in enumerate(zones):
            data = array('B', [0x07, index + 1, speed, 0x01]).tobytes()
            output = ipmi.raw_command(0, 0x3a, data)
            # output = cmd_raw(ipmi, ["0x3a", "0x07", "0x01", "0xff", "0x01"])
            logger.warning(
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


def set_automatic_fanspeed(zones):
    try:
        for (index, fanzone) in enumerate(zones):
            data = array('B', [0x07, index + 1, 0xff, 0x00]).tobytes()
            output = ipmi.raw_command(0, 0x3a, data)
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


def interpolate_speed(temperature_dict, target_temp):
    # thanks to chatgpt
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


def main():
    global logger
    logger = logging.getLogger()

    log_handler = logging.StreamHandler()
    formatter = CustomJsonFormatter(
        '%(timestamp)s %(level)s %(name)s %(message)s')
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)
    logger.setLevel(logging.WARNING)

    global ambient_temp_sensor_ids
    ambient_temp_sensor_ids = []
    global cpu_temp_sensor_ids
    cpu_temp_sensor_ids = []
    global fanspeed_sensor_ids
    fanspeed_sensor_ids = []
    global zone_ids
    zone_ids = []

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'vd', ['verbose', 'debug'])
    except getopt.GetoptError as err:
        print(str(err))
        sys.exit(2)

    for o, a in opts:
        if o in ('-v','--verbose'):
            logger.setLevel(logging.INFO)
        elif o in ('-d', '--debug'):
            logger.setLevel(logging.DEBUG)
        else:
            assert False, 'unhandled option'

    initialize()

    signal.signal(
        signal.SIGINT,
        lambda sig,
        frame: signal_handler(sig, frame, ipmi_session)
    )


    try:
        cmd_sdr_list()

        # define manually for testing
        # zone_ids = [455, 456, 457, 458, 459]
        # fanspeed_sensor_ids = [435, 436, 437, 438, 439, 440, 441, 442, 443, 444,
        #                        445, 446, 447, 448, 449, 450, 451, 452, 453, 454]
        # cpu_temp_sensor_ids = [404, 405, 406, 407]
        # ambient_temp_sensor_ids = [6]

        # temp_speed_curve = {
        #     10: 20,
        #     25: 30,
        #     30: 60,
        #     40: 80,
        #     50: 90,
        #     60: 95,
        #     70: 100,
        # }

        logger.info("CPU temps:", extra={
            "count": len(cpu_temp_sensor_ids),
            "ids": cpu_temp_sensor_ids
        })

        logger.info("ambient temps:", extra={
            "count": len(ambient_temp_sensor_ids),
            "ids": ambient_temp_sensor_ids
        })

        logger.info("fans:", extra={
            "count": len(fanspeed_sensor_ids),
            "ids": fanspeed_sensor_ids
        })

        logger.info("zones:", extra={
            "count": len(zone_ids),
            "ids": zone_ids
        })

        try:
            while True:
                cpu_temp = max(get_sensor_readings(cpu_temp_sensor_ids))
                ambient_temp = max(get_sensor_readings(ambient_temp_sensor_ids))

                targetspeed = round(interpolate_speed(temp_speed_curve, cpu_temp) * 2.55)

                logger.info("status", extra={
                    "ambient_temp": ambient_temp,
                    "cpu_temp": cpu_temp,
                    "target_speed": targetspeed,
                    "target_speed_pct": int(float(targetspeed/255)*100)
                })

                set_fanspeed(zone_ids, targetspeed)
                sleep(3)
        except Exception as err:
            logger.error("Main control loop error", extra=err)
            try:
                set_automatic_fanspeed(zone_ids)
            except:
                logger.error("couldn't switch to automatic fan profile")
            ipmi.session.close()
            sys.exit(9)

    except Exception as err:
        logger.exception("SDR fuckery?")
        if "ipmi" in globals():
            try:
                set_automatic_fanspeed(zone_ids)
            except:
                logger.error("couldn't switch to automatic fan profile")
            ipmi.session.close()
        sys.exit(2)

if __name__ == '__main__':
    try:
        main()
        sys.exit(0)
    except Exception as e:
        handle_exception(logger, "Shit hit the fan...", e, exit_code=1)

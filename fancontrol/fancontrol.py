#!/usr/bin/env python
import sys
import signal
import getopt

import pyipmi
import pyipmi.interfaces

import time
import datetime

import yaml
import logging
from pythonjsonlogger import jsonlogger

import pprint
pp = pprint.PrettyPrinter(indent=2)

def configure():
  configuration = {
    "port": 623,
    "hostname": None,
    "username": None,
    "password": None
  }
  try:
    with open("config.yaml") as f:
      cfg = yaml.load(f, Loader=yaml.FullLoader)
  except:
    logger.exception("can't load config.yaml")
    sys.exit(5)

  if "ipmi" not in cfg:
    logger.exception("please define ipmi object")
    sys.exit(5)

  configuration["port"] = 623
  if "port" in cfg["ipmi"]:
    configuration["port"] = cfg["ipmi"]["port"]

  if "hostname" in cfg["ipmi"]:
    configuration["hostname"] = cfg["ipmi"]["hostname"]
  else:
    logger.exception("please define ipmi.hostname")
    sys.exit(5)

  if "username" in cfg["ipmi"]:
    configuration["username"] = cfg["ipmi"]["username"]
  else:
    logger.exception("please define ipmi.username")
    sys.exit(5)

  if "password" in cfg["ipmi"]:
    configuration["password"] = cfg["ipmi"]["password"]
  else:
    logger.exception("please define ipmi.password")
    sys.exit(5)

  # logger.debug("configuration", extra=configuration)
  return configuration

def initialize():
  try:
    configuration = configure()
  except:
    logger.exception("unable to configure")
    sys.exit(5)

  try:
    logger.debug("trying to establish ipmi conenction")
    interface = pyipmi.interfaces.create_interface(interface='rmcp', keep_alive_interval=1)

    global ipmi
    ipmi = pyipmi.create_connection(interface)
    ipmi.session.set_session_type_rmcp(host=configuration["hostname"], port=configuration["port"])
    ipmi.session.set_auth_type_user(username=configuration["username"], password=configuration["password"])
    ipmi.target = pyipmi.Target(ipmb_address=0x20)
    ipmi.session.establish()
    device_id = ipmi.get_device_id()

    # Below code used only to print out the device ID information
    # print('''
    # Device ID:          %(device_id)s
    # Device Revision:    %(revision)s
    # Firmware Revision:  %(fw_revision)s
    # IPMI Version:       %(ipmi_version)s
    # Manufacturer ID:    %(manufacturer_id)d (0x%(manufacturer_id)04x)
    # Product ID:         %(product_id)d (0x%(product_id)04x)
    # Device Available:   %(available)d
    # Provides SDRs:      %(provides_sdrs)d
    # Additional Device Support:
    # '''[1:-1] % device_id.__dict__)


    # Below code used only to print out the device ID information

    logoutput = {}
    if "device_id" in device_id.__dict__:
      logoutput["device_id"] = device_id.device_id
    if "revision" in device_id.__dict__:
      logoutput["device_revision"] = device_id.revision,
    if "fw_revision" in device_id.__dict__:
      logoutput["fw_revision"] = device_id.fw_revision,
    if "ipmi_version" in device_id.__dict__:
      logoutput["ipmi_version"] = device_id.ipmi_version,
    if "manufacturer_id" in device_id.__dict__:
      logoutput["manufacturer_id"] = device_id.manufacturer_id,
    if "product_id" in device_id.__dict__:
      logoutput["product_id"] = device_id.product_id,
    if "available" in device_id.__dict__:
      logoutput["available"] = device_id.available,
    if "provides_sdrs" in device_id.__dict__:
      logoutput["SDRs"] = device_id.provides_sdrs,
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

  except Exception as err:
    logger.exception("unable to establish ipmi connection")
    ipmi.session.close()
    sys.exit(1)

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

def cmd_sdr_list(ipmi):
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

def get_sensor_readings(ipmi, ids):
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

def main():
  global logger
  logger = logging.getLogger()

  logHandler = logging.StreamHandler()
  formatter = CustomJsonFormatter('%(timestamp)s %(level)s %(name)s %(message)s')
  logHandler.setFormatter(formatter)
  logger.addHandler(logHandler)
  logger.setLevel(logging.INFO)

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
    if o == '-v' or o == '--verbose':
      logger.setLevel(logging.INFO)
    elif o == '-d' or o == '--debug':
      logger.setLevel(logging.DEBUG)
    else:
        assert False, 'unhandled option'

  initialize()
  try:
    logger.debug("test")
    cmd_sdr_list(ipmi)
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


    for x in range(1, 10):
      start = datetime.datetime.now()
      logger.info("fanspeed", extra={"readings": get_sensor_readings(ipmi, fanspeed_sensor_ids)})
      logger.info("cpu_temp", extra={"readings": get_sensor_readings(ipmi, cpu_temp_sensor_ids)})
      logger.info("ambient_temp", extra={"readings": get_sensor_readings(ipmi, ambient_temp_sensor_ids)})
      logger.info("sensor reading time: " + str((datetime.datetime.now() - start).total_seconds()))
  except Exception as err:
    logger.exception("unable to get SDR")
    if "ipmi" in globals():
      ipmi.session.close()
    sys.exit(2)

def signal_handler(sig, frame):
  global ctrlC_counter
  logger.warning('You pressed Ctrl+C! ' + str(ctrlC_counter) +" times")
  if "ipmi" in globals() and ctrlC_counter < 1:
    ctrlC_counter += 1
    logger.warning("Disconnecting from IPMI")
    ipmi.session.close()
    logger.warning("Disconnected")
  sys.exit(130)

# handle Ctrl+C
global ctrlC_counter
ctrlC_counter = 0
signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
  try:
    main()
    ipmi.session.close()
    sys.exit(0)
  except Exception as err:
    if "ipmi" in globals():
      ipmi.session.close()
    logger.exception("Shit hit the fan...")
    sys.exit(1)

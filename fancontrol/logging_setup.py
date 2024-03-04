# logging_setup.py
"""
Sets up a logger that outputs JSON
"""
import logging
from pythonjsonlogger import jsonlogger
import datetime

class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        if not log_record.get('timestamp'):
            now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            log_record['timestamp'] = now
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname

# Set up the global logger
logger = logging.getLogger()
log_handler = logging.StreamHandler()
formatter = CustomJsonFormatter('%(timestamp)s %(level)s %(name)s %(message)s')
log_handler.setFormatter(formatter)
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)
logger.debug("Logging has been set up")

def set_log_level(level):
    """
    Set the log level dynamically.
    :param level: Logging level (e.g., logging.DEBUG, logging.INFO)
    """
    logger.setLevel(level)

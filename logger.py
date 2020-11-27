__author__ = "Moath Maharmeh"
__project_page__ = "https://github.com/iomoath/yara-scanner"

import logging
from settings import debug_log_file_path
from settings import debug_log_enabled
from settings import log_file_path
from settings import date_time_format
import common_functions


logging.basicConfig(handlers=[logging.FileHandler(filename=debug_log_file_path, encoding='utf-8', mode='a+')],
                    level=logging.DEBUG,
                    format="%(asctime)s  %(levelname)-8s %(message)s",
                    datefmt=date_time_format)


def log_error(message, module_name):
    if not debug_log_enabled:
        return

    logging.error("({}): {}".format(module_name, message))


def log_debug(message, module_name):
    if not debug_log_enabled:
        return
    logging.debug("({}): {}".format(module_name, message))


def log_critical(message, module_name):
    if not debug_log_enabled:
        return
    logging.critical("({}): {}".format(module_name, message))


def log_warning(message, module_name):
    if not debug_log_enabled:
        return
    logging.warning("({}): {}".format(module_name, message))


def log_info(message, module_name):
    if not debug_log_enabled:
        return
    logging.info("({}): {}".format(module_name, message))


def log_incident(file_path, rules_matched, yara_rules_file_name):
    try:
        # Log format: [%time%] "%file_path%" "%rules_matched%" "yara_rules_file_name"
        log_row = "[{}] \"{}\" \"{}\" \"{}\"".format(common_functions.get_datetime(), file_path, rules_matched, yara_rules_file_name)

        with open(log_file_path, 'a+', encoding='utf8') as f:
            f.write(log_row)
            f.write("\n")
    except Exception as e:
        log_critical(e, "logger.py")
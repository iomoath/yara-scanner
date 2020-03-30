__author__ = "Moath Maharmeh"
__license__ = "GNU General Public License v2.0"
__version__ = "1.0"
__email__ = "moath@vegalayer.com"
__created__ = "4/Apr/2019"
__modified__ = "4/Apr/2019"
__status__ = "Production"
__project_page__ = "https://github.com/iomoath/yara-scanner"

import logging
from settings import debug_log_file_path

debug_log_enabled = True


logging.basicConfig(filename=debug_log_file_path,
                    level=logging.INFO,
                    format="%(asctime)s  %(levelname)-10s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")

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

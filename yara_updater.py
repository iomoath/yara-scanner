__author__ = "Moath Maharmeh"
__license__ = "GNU General Public License v2.0"
__version__ = "1.0"
__email__ = "moath@vegalayer.com"
__created__ = "4/Apr/2019"
__modified__ = "30/Mar/2020"
__status__ = "Production"
__project_page__ = "https://github.com/iomoath/yara-scanner"

import os
import common_functions
import logger
import settings


module_name = os.path.basename(__file__)


# More rules can be added, checkout Yara-Rule Repo at https://github.com/Yara-Rules/rules
yara_rules_file_list = [
    'webshells_index.yar',
    'exploit_kits_index.yar',
    'suspicious_strings.yar'
]



def init_directories():
    """
    Create temp & Yara rules directories if not exists
    :return:
    """
    if not os.path.isdir(settings.tmp_directory):
        os.makedirs(settings.tmp_directory)

    if not os.path.isdir(settings.yara_rules_directory):
        os.makedirs(settings.yara_rules_directory)


def find_yara_files():
    """
    Search for Yara-Rules files path(s) defined in given list within directory $tmp_directory/rules-master
    :return: List contains yara rules path(s)
    """
    yara_rule_path_list = []

    for r in yara_rules_file_list:
        yara_rule_path = common_functions.find_files(r, os.path.join(settings.tmp_directory, settings.yara_rules_directory_name_in_zip))
        if yara_rule_path is not None:
            yara_rule_path_list.append(yara_rule_path)

    return yara_rule_path_list



def clean_up():
    common_functions.delete_directory_content(settings.tmp_directory)


def update():
    """
    Update yara-rules in yara_rules_directory by downloading latest files from yara rules github repo yara_rules_repo_url
    :return: True on success, False on fail
    """
    try:
        logger.log_info('Started Yara-Rules update', module_name)
        logger.log_debug('Initializing directories', module_name)
        print('[+] Started Yara-Rules update')
        print('[+] Initializing directories..')
        init_directories()

        logger.log_debug('Fetching latest Yara-Rules from {}'.format(settings.yara_rules_repo_download_url), module_name)
        print('[+] Fetching latest Yara-Rules from {}'.format(settings.yara_rules_repo_download_url))
        save_path = os.path.join(settings.tmp_directory, settings.yara_rules_zipped_name)

        common_functions.download(settings.yara_rules_repo_download_url, save_path)
        common_functions.extract_zip(save_path, settings.tmp_directory)

        yara_rule_path_list = find_yara_files()

        if yara_rule_path_list is None or len(yara_rule_path_list) <= 0:
            logger.log_error('Could not find any yara files that matches the specified in $yara_rules_file_list', module_name)
            print('[-] ERROR: Could not find any yara files that matches the specified in $yara_rules_file_list')
            return False

        logger.log_debug('Compiling rules', module_name)
        print('[+] Compiling rules..')
        common_functions.compile_yara_rules(yara_rule_path_list, settings.yara_rules_directory)

        logger.log_debug('Cleaning up', module_name)
        print('[+] Cleaning up..')
        clean_up()
        logger.log_info('Update complete', module_name)
        print('[+] Update complete.')
        return True
    except Exception as e:
        print('[-] ERROR: {}'.format(e))
        logger.log_error(e, module_name)
        return False

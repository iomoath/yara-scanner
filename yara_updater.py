__author__ = "Moath Maharmeh"
__project_page__ = "https://github.com/iomoath/yara-scanner"

import os
import common_functions
import logger
import settings


module_name = os.path.basename(__file__)


# Excluded rules that causes cause errors stating an undefined identifier, as stated in https://github.com/Neo23x0/signature-base#external-variables-in-yara-rules
excluded_rules_file_list = [
    'generic_anomalies.yar',
    'general_cloaking.yar',
    'thor_inverse_matches.yar',
    'yara_mixed_ext_vars.yar'
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


def find_yara_files(path):
    """
    Search for Yara-Rules files path(s) in a given directory path
    :return: List contains yara rules path(s)
    """
    rule_path_list = []

    rules_dir_absolute_path = os.path.abspath(path)
    file_list = common_functions.get_file_set_in_dir(rules_dir_absolute_path, True)

    for file_path in file_list:
        file_name = os.path.basename(file_path)
        if file_name in excluded_rules_file_list:
            continue

        rule_path_list.append(file_path)

    return rule_path_list



def clean_up():
    common_functions.delete_directory_content(settings.tmp_directory)



def update():
    """
    Update yara-rules in yara_rules_directory by downloading latest files from yara rules github repo yara_rules_repo_url
    :return: True on success, False on fail
    """

    logger.log_info('Started Yara rules update', module_name)
    logger.log_debug('Initializing directories', module_name)
    print('[+] Started Yara rules update')
    print('[+] Initializing directories..')
    init_directories()

    try:
        for entry in settings.yara_rules_repo_download_urls:
            try:
                if not entry['enabled']:
                    continue

                logger.log_debug('Fetching signatures from {}'.format(entry['download_url']), module_name)
                print('[+] Fetching signatures from {}'.format(entry['download_url']))

                if entry['file_type'] == 'zip':
                    file_name = entry['name'] + '.zip'
                    save_path = os.path.join(settings.tmp_directory, file_name)
                    common_functions.download(entry['download_url'], save_path)
                    common_functions.extract_zip(save_path, settings.tmp_directory)
                    rules_dir_absolute_path = os.path.abspath(
                        os.path.join(settings.tmp_directory, entry['yara_rules_directory_name_in_zip']))
                    yara_rule_path_list = find_yara_files(rules_dir_absolute_path)

                    if yara_rule_path_list is None or len(yara_rule_path_list) <= 0:
                        logger.log_error(
                            'Could not find any yara files that matches the specified in $yara_rules_file_list',
                            module_name)
                        print(
                            '[-] ERROR: Could not find any yara files that matches the specified in $yara_rules_file_list')
                        continue

                    logger.log_debug('Compiling rules..', module_name)
                    print('[+] Compiling rules..')
                    common_functions.compile_yara_rules(yara_rule_path_list, settings.yara_rules_directory)
                elif entry['file_type'] == 'yara':
                    file_name = entry['name'] + '.yar'
                    save_path = os.path.join(settings.tmp_directory, file_name)
                    common_functions.download(entry['download_url'], save_path)

                    logger.log_debug('Compiling rules..', module_name)
                    print('[+] Compiling rules..')
                    common_functions.compile_yara_rules([save_path], settings.yara_rules_directory)
            except Exception as e:
                print('[-] ERROR fetching rules from {} : {}'.format(entry['name'], e))
                logger.log_error(e, module_name)
                continue
    finally:
        logger.log_debug('Cleaning up', module_name)
        print('[+] Cleaning up..')
        clean_up()
        logger.log_info('Update complete', module_name)
        print('[+] Update complete.')
        return True
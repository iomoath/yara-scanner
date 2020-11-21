__author__ = "Moath Maharmeh"
__project_page__ = "https://github.com/iomoath/yara-scanner"

import os
import glob
from pathlib import Path
import zipfile
import urllib.request
import shutil
import logger
import yara
import settings
from datetime import datetime
import email_sender
import fnmatch


module_name = os.path.basename(__file__)


def find_files(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


def get_file_set_in_dir(dir_path, files_only, filters = None):
    """
    Scan for files in a given directory path
    :param dir_path: directory path
    :param files_only: If set to False then will get files and directories list. True will get only files list in given directory path
    :param filters: file extensions: example ['*', '*.*', '*.txt']
    :return: Set of files that matches given filters
    """

    root_dir_path = u"{}".format(dir_path)

    file_path_set = set()
    if filters is None:
        filters = '*'

    for path in glob.glob(os.path.join(root_dir_path, filters)):
        if files_only:
            if os.path.isfile(path):
                file_path_set.add(path)
        else:
            file_path_set.add(path)

    return file_path_set



def recursive_file_scan(root_dir_path, files_only, filters):
    """
    Scan for files and directories recursively in a given directory path
    :param root_dir_path: directory path
    :param files_only: If set to False then will get files and directories list. True will get only files list in given directory path
    :param filters: file extensions: example ['*.txt']
    :return: Set of files that matches given filters
    """
    root_dir_path = u"{}".format(root_dir_path)
    file_path_set = set()

    if filters is None or filters == "":
        filters = '*'

    for root, dirnames, filenames in os.walk(root_dir_path):
        for filename in fnmatch.filter(filenames, filters):
            file_path = os.path.join(root, filename)

            if files_only:
                if not os.path.isfile(file_path):
                    continue

            file_path_set.add(file_path)

    return file_path_set




def delete_directory_content(dir_path):
    for file in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path): shutil.rmtree(file_path)
        except Exception as e:
            print('[-] ERROR {}'.format(e))
            logger.log_error(e, module_name)


def download(url, path):
    with urllib.request.urlopen(url) as response, open(path, 'wb') as out_file:
        shutil.copyfileobj(response, out_file)


def extract_zip(zip_file_path, directory_to_extract_to):
    if not os.path.isfile(zip_file_path):
        return

    with zipfile.ZipFile(zip_file_path) as zf:
        zf.extractall(directory_to_extract_to)


def compile_yara_rules(yara_rule_path_list, save_directory):
    for path in yara_rule_path_list:

        try:
            save_path = os.path.join(save_directory, os.path.basename(path))
            compiled = yara.compile(filepath=path, includes=True)
            compiled.save(save_path)
        except Exception as e:
            if settings.verbose_enabled:
                print("[-] Could not compile the file {}. {}".format(path, e))


def compile_yara_rules_src_dir():

    dir = os.path.abspath(settings.yara_rules_src_directory)
    path_list = get_file_set_in_dir(dir, True, "*.yar")

    if get_file_set_in_dir is None or len(path_list) < 1:
        return


    compile_yara_rules(path_list, settings.yara_rules_directory)


def write_to_file(file_path, content):
    with open(file_path, mode='w') as file:
        file.write(content)

def print_verbose(msg):
    if not settings.verbose_enabled:
        return
    print(msg)


def open_file(file_path):
    try:
        return open(file_path, "r")
    except IOError as e:
        print('[-] ERROR {}'.format(e))
        logger.log_error(e, module_name)
        return None

def close_file(file_stream):
    try:
        file_stream.close()
        return True
    except IOError as e:
        print('[-] ERROR {}'.format(e))
        logger.log_error(e, module_name)
        return False


def read_file_lines(file_path):
    with open(file_path) as fp:
        return fp.readlines()


def get_datetime():
    return datetime.now().strftime(settings.date_time_format)


def tail(file_path, lines=1, _buffer=4098):
    """
    Tail a file and get X lines from the end
    Source: https://stackoverflow.com/a/13790289/5974057
    """

    # place holder for the lines found
    lines_found = []

    # block counter will be multiplied by buffer
    # to get the block size from the end
    block_counter = -1

    f = open_file(file_path)

    # loop until we find X lines
    while len(lines_found) < lines:
        try:

            f.seek(block_counter * _buffer, os.SEEK_END)
        except IOError:  # either file is too small, or too many lines requested
            f.seek(0)
            lines_found = f.readlines()
            break

        lines_found = f.readlines()
        block_counter -= 1

    close_file(f)
    return lines_found[-lines:]


def build_smtp_config_dict():
    t = {
        "host": settings.smtp_host,
        "port": settings.smtp_port,
        "ssl": settings.smtp_ssl,
        "username": settings.smtp_username,
        "password": settings.smtp_password,
        "from": settings.smtp_from,
        "recipients": settings.email_alert_recipients,
    }
    return t


def report_incident_by_email(file_path, rules_matched, yara_rules_file_name, event_time):
    if not settings.email_alerts_enabled:
        return

    try:
        file_name = os.path.basename(file_path)
        short_file_name = file_name
        if file_name is not None and len(file_name) > 40:
            short_file_name = file_name[0 : 39]

        smtp_mailer_param = build_smtp_config_dict()
        smtp_mailer_param['message_body'] = build_incident_email_message_body(file_name, file_path, rules_matched, yara_rules_file_name, event_time)
        smtp_mailer_param['subject'] = 'Match Found: {}'.format(short_file_name)

        print('[+] Sending incident info to {}'.format(settings.email_alert_recipients))
        email_sender.send_message(smtp_mailer_param)
        print('[+] Incident info sent to {}'.format(settings.email_alert_recipients))
    except Exception as e:
        print('[-] ERROR: {}'.format(e))
        logger.log_error(e, module_name)


def build_incident_email_message_body(file_name, file_path, rules_matched, yara_rules_file_name, event_time):
    message = settings.email_body_match_found
    message += "\n\n"
    message += "Event time: {}".format(event_time)
    message += "\n"
    message += "File name: {}".format(file_name)
    message += "\n"
    message += "File path: {}".format(file_path)
    message += "\n"
    message += "Rules matches: {}".format(rules_matched)
    message += "\n"
    message += "Yara rules file: {}".format(yara_rules_file_name)
    message += "\n\n"
    return message
__author__ = "Moath Maharmeh"
__license__ = "GNU General Public License v2.0"
__version__ = "1.0"
__email__ = "moath@vegalayer.com"
__created__ = "4/Apr/2019"
__modified__ = "4/Apr/2019"
__status__ = "Production"
__project_page__ = "https://github.com/iomoath/yara-scanner"

import os
import glob
from pathlib import Path
import zipfile
import urllib.request
import shutil
import logger
import yara
import constants
from datetime import datetime

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
    file_path_set = set()
    if filters is None:
        filters = ['*']

    for f in filters:
        for path in glob.glob(os.path.join(dir_path, f)):
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
    :param filters: file extensions: example ['*', '*.*', '*.txt']
    :return: Set of files that matches given filters
    """
    file_path_set = set()

    if filters is None:
        filters = ['*']

    for f in filters:
        for path in Path(root_dir_path).glob('**/{}'.format(f)):
            if files_only:
                if os.path.isfile(path):
                    file_path_set.add(path)
            else:
                file_path_set.add(path)
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

        save_path = os.path.join(save_directory, os.path.basename(path))
        compiled = yara.compile(filepath=path, includes=True)
        compiled.save(save_path)

def write_to_file(file_path, content):
    with open(file_path, mode='w') as file:
        file.write(content)

def print_verbose(msg):
    if not constants.verbose_enabled:
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
    return datetime.now().strftime('%Y-%B-%d %H:%M:%S')

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


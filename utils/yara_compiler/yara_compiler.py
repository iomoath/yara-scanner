__author__ = "Moath Maharmeh"
__project_page__ = "https://github.com/iomoath/yara-scanner"

import os
from pathlib import Path
import glob
import yara


output_directory = 'output'
source_directory = 'source'


def recursive_file_scan(root_dir_path, filters):
    """scans a directory recursively for files"""
    file_path_set = set()

    for f in filters:
        for file_path in Path(root_dir_path).glob('**/{}'.format(f)):
            if os.path.isfile(file_path):
                file_path_set.add(file_path)
    return file_path_set


def get_file_list_in_dir(dir_path, recursive, filters = None):
    file_path_list = []

    if filters is None:
        filters = ['*', '.*']

    if not recursive:
        for f in filters:
            file_path_list.extend(glob.glob(os.path.join(dir_path, f)))
        return file_path_list
    else:
        return recursive_file_scan(dir_path, filters)

def compile_yara_rules(yara_rule_path_list, save_directory):
    for path in yara_rule_path_list:

        try:
            save_path = os.path.join(save_directory, os.path.basename(path))
            compiled = yara.compile(filepath=path, includes=True)
            compiled.save(save_path)
        except Exception as e:
            print("[-] Could not compile the file {}. {}".format(path, e))


file_list = get_file_list_in_dir(source_directory, False, ['*.yar'])
compile_yara_rules(file_list, output_directory)

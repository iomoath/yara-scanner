__author__ = "Moath Maharmeh"
__license__ = "GNU General Public License v2.0"
__version__ = "1.0"
__email__ = "moath@vegalayer.com"
__created__ = "4/Apr/2019"
__modified__ = "4/Apr/2019"
__status__ = "Production"
__project_page__ = "https://github.com/iomoath/yara-scanner"

import re

rx = re.compile(r'"(?:GET|POST)\s+([^\s?]*)', re.M)


def parse_accessed_file_name_list(request_string) :
    return rx.findall(request_string)


def get_accessed_files_list(access_logs):
    accessed_file_set = set()
    for line in access_logs:
            matches = parse_accessed_file_name_list(line) # passing a single line, the list will contain only 1 element
            if matches is None or len(matches) <= 0:
                continue
            accessed_file_set.add(matches[0])

    return accessed_file_set


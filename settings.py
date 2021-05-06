################ Internal settings, usually remains the same! ################
tmp_directory = 'tmp'

# Compiled rules directory
yara_rules_directory = 'yara-rules'

# Uncompiled rules directory (Src). Yara rules in this diectory will be compiled automatically when start
yara_rules_src_directory = 'yara-rules-src'

yara_rules_repo_download_urls = [
    {'name': 'red_team_tool_countermeasures',
     'enabled': True,
     'file_type': 'yara',
     'download_url': 'https://raw.githubusercontent.com/fireeye/red_team_tool_countermeasures/master/all-yara.yar',
     'yara_rules_directory_name_in_zip': True
     },
    {'name': 'Neo23x0',
     'enabled': True,
     'file_type': 'zip',
     'download_url': 'https://github.com/Neo23x0/signature-base/archive/master.zip',
     'yara_rules_directory_name_in_zip': 'signature-base-master/yara'
     }
]

#yara_rules_repo_url = 'https://github.com/Neo23x0/signature-base'
#yara_rules_repo_download_url = yara_rules_repo_url + '/archive/master.zip'
#yara_rules_zipped_name = 'signature-base.zip'
#yara_rules_directory_name_in_zip = 'signature-base-master/yara'

yara_matching_timeout = 30 # timeout in seconds
max_file_size = 16777216 # Max file size 16 MB
debug_log_enabled = False
debug_log_file_path = 'debug.log'
log_file_path = 'matches.log'
verbose_enabled = False

# time format used across modules [logging, alerts]
date_time_format = '%Y-%m-%d %H:%M:%S'

################ Email Alerts settings ################
EMAIL_ALERTS_ENABLED = False
SMTP_HOST = "localhost"
SMTP_PORT = 25
SMTP_SEC_PROTOCOL = 'none' # valid vlaues: tls, ssl, none

SMTP_REQUIRE_AUTH = False
SMTP_USERNAME = ""
SMTP_PASSWORD = ""

FROM = "soc@example.org"
FROM_NAME = "File WatchTower"
TO = "soc@example.org"


# Email body for scan report
email_body_scan_complete = """
YaraScanner has completed a scan process. The attached report contains scan process results.
"""

email_body_match_found = """
YaraScanner has found a pattern match, here's the details:
"""

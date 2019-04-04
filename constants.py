tmp_directory = 'tmp'
yara_rules_directory = 'yara-rules'
yara_rules_repo_url = 'https://github.com/Yara-Rules/rules'
yara_rules_repo_download_url = yara_rules_repo_url + '/archive/master.zip'
yara_rules_zipped_name = 'yara-rules.zip'
yara_rules_directory_name_in_zip = 'rules-master'
log_file_path = 'log.log'
verbose_enabled = False

email_message_body_scan_complete = """
YaraScanner has completed a scan process. The attached report contains scan process results.
"""

# timeout in seconds
yara_matching_timeout = 60
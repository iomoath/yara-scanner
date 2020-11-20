################ Internal settings, usually remains the same! ################
tmp_directory = 'tmp'

# Compiled rules directory
yara_rules_directory = 'yara-rules'

# Uncompiled rules directory (Src). Yara rules in this diectory will be compiled automatically when start
yara_rules_src_directory = 'yara-rules-rc'

yara_rules_repo_url = 'https://github.com/Neo23x0/signature-base'
yara_rules_repo_download_url = yara_rules_repo_url + '/archive/master.zip'
yara_rules_zipped_name = 'signature-base.zip'
yara_rules_directory_name_in_zip = 'signature-base-master/yara'
yara_matching_timeout = 30 # timeout in seconds
max_file_size = 6777216 # Max file size 16 MB
debug_log_enabled = False
debug_log_file_path = 'debug.log'
log_file_path = 'matches.log'
verbose_enabled = False

# time format used across modules [logging, alerts]
date_time_format = '%Y-%m-%d %H:%M:%S'
################ Email Alerts settings ################
email_alerts_enabled = False
smtp_host = ""
smtp_port = 25

# SMTP server require SSL/TLS ?
smtp_ssl = True
smtp_username = ""
smtp_password = ""

# Message sender email to be included in message sender field
smtp_from = "YaraScanner <email@example.org>"

# Reports & alerts will be sent to this email(s)
email_alert_recipients = ["email@example.org"]


# Email body for scan report
email_body_scan_complete = """
YaraScanner has completed a scan process. The attached report contains scan process results.
"""

email_body_match_found = """
YaraScanner has found a pattern match, here's the details:
"""

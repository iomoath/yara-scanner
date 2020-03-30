################ Internal settings, usually remains the same! ################
tmp_directory = 'tmp'
yara_rules_directory = 'yara-rules'
yara_rules_repo_url = 'https://github.com/Yara-Rules/rules'
yara_rules_repo_download_url = yara_rules_repo_url + '/archive/master.zip'
yara_rules_zipped_name = 'yara-rules.zip'
yara_rules_directory_name_in_zip = 'rules-master'
yara_matching_timeout = 30 # timeout in seconds
debug_log_enabled = False
debug_log_file_path = 'debug.log'
log_file_path = 'matches.log'
verbose_enabled = False

# If enabled, report scan results will saved to current YaraScanner directory
generate_report_file = False

# time format used across modules [logging, alerts]
date_time_format = '%Y-%m-%d %H:%M:%S'
################ Email Alerts settings ################
email_alerts_enabled = False
smtp_host = "smtp.gmail.com"
smtp_port = 587

# SMTP server require SSL/TLS ?
smtp_ssl = True
smtp_username = "foxbots.sec@gmail.com"
smtp_password = "Vp3aSAuXfc3TgN3D"

# Message sender email to be included in message sender field
smtp_from = "YaraScanner <foxbots.sec@gmail.com>"

# Reports & alerts will be sent to this email(s)
email_alert_recipients = ["moath@vegalayer.com"]


# Email body for scan report
email_body_scan_complete = """
YaraScanner has completed a scan process. The attached report contains scan process results.
"""

email_body_match_found = """
YaraScanner has found a pattern match, here's the details:
"""

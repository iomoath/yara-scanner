__author__ = "Moath Maharmeh"
__license__ = "GNU General Public License v2.0"
__version__ = "1.0"
__email__ = "moath@vegalayer.com"
__created__ = "4/Apr/2019"
__modified__ = "4/Apr/2019"
__status__ = "Production"
__project_page__ = "https://github.com/iomoath/yara-scanner"

import argparse
import sys
import yara_updater
import yara_scanner
import constants
import report_generator
import common_functions
import email_sender
from datetime import datetime


arg_parser = None

def build_smtp_mailer_param(args, message_body):
    t = {
        "host": args['smtp_host'],
        "port": args['smtp_port'],
        "ssl": args['smtp_ssl'],
        "username": args['smtp_username'],
        "password": args['smtp_password'],
        "from": "YaraScanner <{}>".format(args['smtp_from']),
        "recipients": [args['smtp_recipient']],
        "message_body": message_body,
        "subject": 'YaraScanner - Scan Report {}'.format(common_functions.get_datetime()),
        "attachments": args['attachments']
    }
    return t


def run_scanner(args):
    is_recursive = args["recursive"]

    try:
        if args["scan_dir"] is not None:
            match_result = yara_scanner.scan_directory(args["scan_dir"].strip(), is_recursive)
        elif args["scan_file"] is not None:
            match_result = yara_scanner.scan_file(args["scan_file"].strip())
        elif args["scan_access_logs"] is not None and args["www_path"] is not None:
            access_log_file_path = args["scan_access_logs"].strip()
            www_dir_path = args["www_path"].strip()
            match_result = yara_scanner.scan_access_logs(access_log_file_path, www_dir_path, args["tail"])
        else:
            arg_parser.print_help()
            sys.exit(0)
        if match_result is None:
            raise Exception()
    except:
        sys.exit(0)


    # Generate report
    report_file_name = 'YaraScanner_Report_{}.html'.format(datetime.now().strftime('%Y_%B_%d_%H_%M_%S'))
    if args['gen_report'] or args['smtp_host'] is not None:
        print('[+] Generating report..')

    if args['gen_report']:
        report = report_generator.generate_report(match_result)
        common_functions.write_to_file(report_file_name, report)
        print('[+] Report saved to "{}"'.format(report_file_name))


    # send email notification
    if args['smtp_host'] is not None and args['smtp_port'] > 0:
        report = report_generator.generate_report(match_result)

        attachment = [{'text': report, 'file_name': report_file_name}]
        args['attachments'] = attachment
        smtp_mailer_param = build_smtp_mailer_param(args, constants.email_message_body_scan_complete)
        print('[+] Delivering report to {}'.format(args['smtp_recipient']))
        email_sender.send_message(smtp_mailer_param)
        print('[+] Report sent to {}'.format(args['smtp_recipient']))



def run_yara_updater():
    yara_updater.update()


def run(args):

    if args["verbose"]:
        constants.verbose_enabled = True

    if args["update"]:
        run_yara_updater()
    else:
        run_scanner(args)


def generate_argparser():
    ap = argparse.ArgumentParser()

    ap.add_argument("--update", action='store_true',
                    help="Fetch latest Yara-Rules and update the current.")

    ap.add_argument("--scan-access-logs", action='store',type=str,
                    help="Path to a access logs file. Get list of accessed file paths from access logs and attempt to find a pattern matching with Yara Rules.")

    ap.add_argument("--www-path", action='store', type=str,
                    help="Path to public web directory ex; /var/www/html, /home/user/public_html' required for option '--scan-access-logs' ")

    ap.add_argument("--tail",  action='store', type=int, default=0,
                    help="Number of lines to read from access logs file, starting from the end of the file. If not set then will read the entire file")


    ap.add_argument("--scan-dir", action='store', type=str,
                    help="Path to a directory to be scanned. Scan for file(s) in given directory path and attempt to find a pattern matching with Yara-Ruels.")

    ap.add_argument("-r", "--recursive", action='store_true',
                    help="Scan sub directories. Optional Used with option '--scan-dir' ")

    ap.add_argument("--scan-file", action='store', type=str,
                    help="Path to a file to be scanned. Attempt to find a pattern matching with given file.")

    ap.add_argument("--gen-report", action='store_true',
                    help="Generate an HTML report.")

    ap.add_argument("--smtp-host", action='store',
                    help="SMTP Host. If SMTP settings is set, then a report copy for the pattern matching process will be sent by email.")

    ap.add_argument("--smtp-port", action='store', type=int,
                    help="SMTP server port.")

    ap.add_argument("--smtp-ssl", action='store_true',
                    help="SMTP server require SSL/TLS.")

    ap.add_argument("--smtp-username", action='store',
                    help="SMTP account username.")

    ap.add_argument("--smtp-password", action='store',
                    help="SMTP account password.")

    ap.add_argument("--smtp-from", action='store',
                    help="Message sender email to be included in message sender field.")

    ap.add_argument("--smtp-recipient", action='store',
                    help="Reports will be sent to this email.")

    ap.add_argument("-v", "--verbose", action='store_true',
                    help="Show more information while processing.")

    ap.add_argument("--version", action="version", version='Yara-Scanner Version 1.0')
    return ap


def main():
    global arg_parser
    arg_parser = generate_argparser()
    args = vars(arg_parser.parse_args())
    run(args)


if __name__ == "__main__":
    main()

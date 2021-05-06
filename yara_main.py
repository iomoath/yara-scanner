__author__ = "Moath Maharmeh"
__project_page__ = "https://github.com/iomoath/yara-scanner"

import argparse
import sys
import yara_updater
import yara_scanner
import settings
import report_generator
import common_functions
import email_sender
from datetime import datetime

arg_parser = None



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
    if args['gen_report']:
        print('[+] Generating report..')

    if args['gen_report']:
        report = report_generator.generate_report(match_result)
        common_functions.write_to_file(report_file_name, report)
        print('[+] Report saved to "{}"'.format(report_file_name))

    # send report by email
    if args['gen_report'] and settings.EMAIL_ALERTS_ENABLED:
        report = report_generator.generate_report(match_result)

        attachment = [{'text': report, 'file_name': report_file_name}]
        smtp_mailer_param = {}
        smtp_mailer_param['message'] = settings.email_body_scan_complete
        smtp_mailer_param['subject'] = 'Scan Report {}'.format(common_functions.get_datetime())
        smtp_mailer_param['attachments'] = attachment

        print('[+] Delivering report to {}'.format(settings.TO))
        email_sender.send_message(smtp_mailer_param)
        print('[+] Report sent to {}'.format(settings.TO))


def run_yara_updater():
    yara_updater.update()


def run(args):
    if args["verbose"]:
        settings.verbose_enabled = True

    if args["update"]:
        run_yara_updater()
    else:
        run_scanner(args)


def generate_argparser():
    ascii_logo = """
 ____  ____                          ______                                                 
|_  _||_  _|                       .' ____ \                                                
  \ \  / / ,--.   _ .--.  ,--.     | (___ \_| .---.  ,--.   _ .--.   _ .--.  .---.  _ .--.  
   \ \/ / `'_\ : [ `/'`\]`'_\ :     _.____`. / /'`\]`'_\ : [ `.-. | [ `.-. |/ /__\\[ `/'`\] 
   _|  |_ // | |, | |    // | |,   | \____) || \__. // | |, | | | |  | | | || \__., | |     
  |______|\'-;__/[___]   \'-;__/    \______.''.___.'\'-;__/[___||__][___||__]'.__.'[___]    

    https://github.com/iomoath/yara-scanner
    """
    ap = argparse.ArgumentParser(ascii_logo)

    ap.add_argument("--update", action='store_true',
                    help="Fetch latest Yara-Rules and update the current.")

    ap.add_argument("--scan-access-logs", action='store', type=str,
                    help="Path to a access logs file. Get list of accessed file paths from access logs and attempt to find a pattern matching with Yara Rules.")

    ap.add_argument("--www-path", action='store', type=str,
                    help="Path to public web directory ex; /var/www/html, /home/user/public_html' required for option '--scan-access-logs' ")

    ap.add_argument("--tail", action='store', type=int, default=0,
                    help="Number of lines to read from access logs file, starting from the end of the file. If not set then will read the entire file")

    ap.add_argument("--scan-dir", action='store', type=str,
                    help="Path to a directory to be scanned. Scan for file(s) in given directory path and attempt to find a pattern matching with Yara-Ruels.")

    ap.add_argument("-r", "--recursive", action='store_true',
                    help="Scan sub directories. Optional Used with option '--scan-dir' ")

    ap.add_argument("--scan-file", action='store', type=str,
                    help="Path to a file to be scanned. Attempt to find a pattern matching with given file.")

    ap.add_argument("--gen-report", action='store_true',
                    help="Generate an HTML report.")

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

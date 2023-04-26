# Yara Scanner
#### yara-scanner

YaraScanner is a file pattern-matching tool based on YARA rules.



### Features
* Scan a single file. Attempt to find a pattern matching with given file.
* Scan a directory. Scan for file(s) in given directory path and attempt to find a pattern matching with Yara rules.
* Scan web access logs. By getting list of accessed file paths from access logs and attempt to find a pattern matching with Yara Rules.
* Auto fetch Yara rules from [Neo23x0](https://github.com/Neo23x0/signature-base)
* Flexibility, using custom Yara rules
* HTML scan reports
* Deliver reports by email
* Email alerts, when a pattern match is found
* Logging.



### Prerequisites
* Python 3
* yara-python library


## Installing

1. Clone or download the project files.
2. Install ```yara-python``` library. ```pip3 install yara-python```
3. Open ```settings.py``` in any text editor and adjust settings if you need to change the default settings.
4. Update Yara rules:  ``` python3 yara_main.py --update```
5. (Optinal) Create a cron in your system cron manager to run the yara scanner and updater.
The following cron will run on 12:00 AM every week, and update yara-rules. Adjust as your requirements.

```
$ crontab -e
# append the following line, adjust project path

0 0 * * */7 python3 /opt/yara-scanner/yara_main.py --update
```

For automated scans, This cron will run every week on 3:00 AM
```
0 3 * * */7 python3 /opt/yara-scanner/yara_main.py --scan-dir '/home/xxx/dir' --gen-report --recursive
```


## Installing on Windows Systems
The tool has been tested with Python 3.7

1. Download & Install Python 3.7 and make sure to check the option “Add Python to PATH”
2. Open a new CMD console, and run the command ```pip install yara-python```
3. Update Yara rules:  ``` python yara_main.py --update```


At this step, YaraScanner is ready to use with default setup.


#### Steps for adding more Yara rules:
* Compiled rules should be placed under "yara-rules" directory.
* Place un-compiled rules source codes files should be placed under "yara-rules-src" directory and, it will be automatically compiled at runtime.


## Arugments
```
yara $python3 yara_main.py --help
usage:
       [-h] [--update] [--scan-access-logs SCAN_ACCESS_LOGS]
       [--www-path WWW_PATH] [--tail TAIL] [--scan-dir SCAN_DIR] [-r]
       [--scan-file SCAN_FILE] [--gen-report] [-v] [--version]

optional arguments:
  -h, --help            show this help message and exit
  --update              Fetch latest Yara-Rules and update the current.
  --scan-access-logs SCAN_ACCESS_LOGS
                        Path to a access logs file. Get list of accessed file
                        paths from access logs and attempt to find a pattern
                        matching with Yara Rules.
  --www-path WWW_PATH   Path to public web directory ex; /var/www/html,
                        /home/user/public_html' required for option '--scan-
                        access-logs'
  --tail TAIL           Number of lines to read from access logs file,
                        starting from the end of the file. If not set then
                        will read the entire file
  --scan-dir SCAN_DIR   Path to a directory to be scanned. Scan for file(s) in
                        given directory path and attempt to find a pattern
                        matching with Yara-Ruels.
  -r, --recursive       Scan sub directories. Optional Used with option '--
                        scan-dir'
  --scan-file SCAN_FILE
                        Path to a file to be scanned. Attempt to find a
                        pattern matching with given file.
  --gen-report          Generate an HTML report.
  -v, --verbose         Show more information while processing.
  --version             show program's version number and exit
  ```


## Usage example

* Attempt to find a matching with a single file:
```
Dot-lab:yara-scanner moath$ python3 yara_main.py --scan-file '/var/www/html/head.php' --verbose
[+] Single file scan started
[+] Getting Yara Rules..
[+] Attempting to match "/var/www/html/webshells/backupsql.php" with "Webshells_index.yar
[+] Attempting to match "/var/www/html/webshells/backupsql.php" with "Exploit-Kits_index.yar
[*] Found 6 matches: [backupsql_php_often_with_c99shell, Dx_php_php, Moroccan_Spamers_Ma_EditioN_By_GhOsT_php, mysql_php_php, mysql_tool_php_php, WebShell_backupsql]
[+] File scan complete.
Dot-lab:yara-scanner moath$ 
```

* Scan a directory files and attempt to find matching with Yara rules:
```
Dot-lab:yara-scanner moath$ python3 yara_main.py --scan-dir '/var/www/html/webshells/' --verbose --gen-report
[+] Directory scan started
[+] Getting files path(s) for scan..
[+] 3 File to process.
[+] Getting Yara-Rules..
[+] Attempting to match "/var/www/html/webshells/c0derz_shell.php" with "Webshells_index.yar
[*] Found 3 match: [webshell_NIX_REMOTE_WEB_SHELL_NIX_REMOTE_WEB_xxx1, csh_php_php, WebShell_Generic_PHP_6]
[+] Attempting to match "/var/www/html/webshells/c0derz_shell.php" with "Exploit-Kits_index.yar
[+] Attempting to match "/var/www/html/webshells/Crystal.php" with "Webshells_index.yar
[*] Found 6 match: [webshell_Crystal_Crystal, multiple_webshells_0026, WebShell_Generic_PHP_2, WebShell__CrystalShell_v_1_erne_stres, WebShell_Generic_PHP_4, WebShell_Generic_PHP_6]
[+] Attempting to match "/var/www/html/webshells/Crystal.php" with "Exploit-Kits_index.yar
[+] Attempting to match "/var/www/html/webshells/bypass529.php" with "Webshells_index.yar
[+] Attempting to match "/var/www/html/webshells/bypass529.php" with "Exploit-Kits_index.yar
[+] Directory scan complete.
[+] Generating report..
[+] Report saved to "YaraScanner_Report_2019_April_04_09_45_30.html"
Dot-lab:yara-scanner moath$ 
```

* Scan a web access logs file, get list of accessed file paths and, attempt to find matching with Yara rules:
by using --tail 10 option, only last 10 of the log file will be parsed. 
```
Dot-lab:yara-scanner$ python3 yara_main.py --scan-access-logs '/var/httpd/apache/access_log' --tail 10 --www-path '/var/www/html' --gen-report --verbose
[+] Access logs scan started
[+] Reading access logs file..
[+] Attempting to parse accessed files path(s) from access logs..
[+] 3 File to process.
[+] Getting Yara-Rules..
[+] Attempting to match "/var/www/html/blog/temp.php" with "Exploit-Kits_index.yar
[+] Attempting to match "/var/www/html/blog/temp.php" with "Webshells_index.yar
[+] Attempting to match "/var/www/html/blog/cpanel.php" with "Exploit-Kits_index.yar
[+] Attempting to match "/var/www/html/blog/cpanel.php" with "Webshells_index.yar
[*] Found 1 matches: [WebShell_php_webshells_cpanel]
[+] Attempting to match "/var/www/html/blog/fatal.php" with "Exploit-Kits_index.yar
[+] Attempting to match "/var/www/html/blog/fatal.php" with "Webshells_index.yar
[*] Found 2 matches: [multiple_webshells_0024, WebShell_Generic_PHP_3]
[+] Access logs scan complete.
[+] Generating report..
[+] Report saved to "YaraScanner_Report_2019_April_04_09_59_12.html"
Dot-lab:yara-scanner$ 

```





### Project License

This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file for details


### Signature-Base License
This project uses yara rules from [Neo23x0](https://github.com/Neo23x0/signature-base) repository and, it's licensed except the YARA rules created by 3rd parties, are licensed under the [Creative Commons Attribution-NonCommercial 4.0 International License](http://creativecommons.org/licenses/by-nc/4.0/).


### Meta
Moath Maharmeh -  moath@vegalayer.com

https://github.com/iomoath/yara-scanner

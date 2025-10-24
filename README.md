# LyncTools
LyncTools is a security tool for Skype for Business that performs user enumeration and password spraying attacks with lockout protection.

## Features

🔍 Discovery: Automatically discover Lync/Skype for Business subdomains

👥 Enumeration: Identify valid usernames using timing-based attacks

🔑 Password Spraying: Perform controlled password spraying with account lockout protection

🛡️ Safety Features: Built-in delays and attempt limits to prevent account lockouts

📊 Progress Tracking: Real-time progress monitoring during attacks

🎯 Smart Waiting: Intelligent lockout management with visual progress indicators

## Installation
### Prerequisites
- Python 3.6 or higher

### Required Python packages:
```
pip install requests
```
### Download
```
git clone https://github.com/yourusername/lynctools.git
cd lynctools
```
## Usage
LyncTools operates in three main modes:

Discover Mode

Find Lync/Skype for Business subdomains:
```
python lynctools.py discover -H company.com
```

Enumeration Mode

Enumerate valid usernames using timing attacks:

```bash
python lynctools.py enum -H lync.company.com -U users.txt -d DOMAIN -p Password123 -o results.log
```

Password Spray Mode

Perform safe password spraying with lockout protection:

```bash
python lynctools.py spray -H lync.company.com -U users.txt -d DOMAIN -P passwords.txt -a 3 -delay 30 -s 1
```
## Command Line Options

Common Arguments

-U USERNAMES - File containing usernames 

-d DOMAIN - Internal domain name 

-p PASSWD - Single password to test

-P PASSWDFILE - File containing passwords 

-a ATTEMPTS - Max attempts per user before delay 

-delay DELAY - Delay time in minutes after max attempts 

-s SLEEP - Sleep time between requests 

## Examples
```
python lynctools.py discover -H target-company.com
python lynctools.py enum -H lync.target-company.com -U users.txt -d DOMAIN -p "Password123" -o enum_results.log
python lynctools.py spray -H lync.target-company.com -U users.txt -d DOMAIN -P common_passwords.txt -a 2 -delay 45 -s 2 -o spray_results.log
```
## Output

The tool provides color-coded output:

🟢 Green ([+]): Valid credentials or successful operations

🔵 Blue ([*]): Informational messages and progress

🟡 Yellow ([!]): Warnings and waiting periods

🔴 Red ([-]): Errors and invalid attempts

Results are also logged to the specified output file with timestamps.

Legal Disclaimer
This tool is intended for:

- Security professionals conducting authorized penetration tests

- Organizations testing their own systems

- Educational and research purposes

⚠️ Warning: Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal. The developers are not responsible for any misuse or damage caused by this tool.

Always ensure you have proper authorization before conducting any security testing.

### Acknowledgments
- Original concept and development by @nyxgeek

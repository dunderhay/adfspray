## Simple ADFS Brute-Force Login Script 

Python3 script to perform password spraying against Microsoft ADFS endpoint.

```
usage: adfspray.py [-h] -t TARGET [-u USERNAME] [-U USERNAME_LIST] [-p PASSWORD] [-P PASSWORD_LIST] [-v] [-o OUTPUT] [-mfa] [-d DELAY]

ADFS Brute-Force Login Script

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        ADFS target host URL (e.g., https://adfs.example.com)
  -u USERNAME, --username USERNAME
                        Single username to try
  -U USERNAME_LIST, --username-list USERNAME_LIST
                        File containing a list of usernames
  -p PASSWORD, --password PASSWORD
                        Single password to use for login attempts
  -P PASSWORD_LIST, --password-list PASSWORD_LIST
                        File containing a list of passwords
  -v, --verbose         Enable verbose mode to show all print statements
  -o OUTPUT, --output OUTPUT
                        File to log the login results
  -mfa, --mfa           Check if Multi-Factor Authentication (MFA) is required after successful login
  -d DELAY, --delay DELAY
                        Delay in seconds between login attempts (e.g., --delay 2 for 2 seconds delay)

Usage examples:
  python script.py -t https://adfs.example.com -u user -p password123
  python script.py -t https://adfs.example.com -U userlist.txt -p password123 -mfa
  python script.py -t https://adfs.example.com -u user -P passwordlist.txt -v -o output.txt
  python script.py -t https://adfs.example.com -U userlist.txt -P passwordlist.txt -d 2

Note: Provide either a single password (-p) or a password list file (-P).
```

**Note**: the  script currently assumes the login is done at `/adfs/ls/`.
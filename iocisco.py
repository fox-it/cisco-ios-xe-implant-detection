#!/usr/bin/env python3
#
# file:     iocisco.py
# author:   Fox-IT Security Research Team / NCC Group
#
#  Scan a Cisco IOS XE device to determine if implant is present.
#  Reference: https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/
#
#  Example usage:
#
#      $ python3 iocisco.py <DEVICE_IP>
#
#  Results are only reliable when checked against a Cisco IOS XE device.
#
import sys
import argparse

try:
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    raise ImportError(f"Could not find requests. Please run `pip install requests`.")


IMPLANT_V1_V2_RESPONSE = "<h1>404 Not Found</h1>"
IMPLANT_V3_RESPONSE = 'name="Username"'


def determine_compromise(url: str, timeout: int = 10) -> str:
    headers = {
        "User-Agent": "iocisco.py - https://github.com/fox-it/cisco-ios-xe-implant-detection",
    }
    s = requests.Session()
    r = requests.Request(method="GET", url=url, headers=headers)
    prep = r.prepare()
    prep.url = url
    try:
        response = s.send(prep, verify=False, timeout=timeout)
        if IMPLANT_V1_V2_RESPONSE in response.text:
            # Version 1 / 2 return a 404 with an html body, unlike normal Cisco IOS XE for this URL
            return "v1/v2"
        elif IMPLANT_V3_RESPONSE in response.text:
            # Version 3 returns the login page, instead of a javascript redirect
            return "v3"
        return False
    except requests.exceptions.RequestException as e:
        print(f"    Error: {e}")
    return None


def check_target(target: str):
    http_url = f"http://{target}/%25"
    https_url = f"https://{target}/%25"

    checked_urls_without_compromise = 0
    for url in [http_url, https_url]:
        print(f"[!] Checking {url}")
        verdict = determine_compromise(url)
        if verdict:
            print(
                f"    WARNING: Possible implant found for {target} (implant {verdict})! Please perform a forensic investigation!"
            )
            possible_compromise = True
        elif verdict is None:
            print(f"[!] Could not determine status of {url}")
        else:
            checked_urls_without_compromise += 1

    if checked_urls_without_compromise == 2:
        print(f"[*] Found no sign of compromise for either {http_url} or {https_url}")


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Scan Cisco IOS XE device(s) to determine if implant is present.",
    )
    parser.add_argument("targets", nargs="*", help="Cisco IOS XE Device IP or hostname")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="timeout for HTTP requests")
    parser.add_argument(
        "-f",
        "--file",
        action="store",
        dest="filename",
        help="file containing a list of target hosts (one per line)",
    )
    args = parser.parse_args()
    if not args.targets and not args.filename:
        parser.print_help()
        return 1

    if args.targets:
        for target in args.targets:
            check_target(target)

    if args.filename:
        with open(args.filename, mode="r", encoding="utf-8") as file_handle:
            for line in file_handle:
                target = line.strip()
                if not target or target.startswith("#"):
                    continue
                check_target(target)


if __name__ == "__main__":
    sys.exit(main())

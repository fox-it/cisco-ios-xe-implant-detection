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


def is_compromised(url: str, timeout: int = 10) -> bool:
    headers = {
        "User-Agent": "iocisco.py - https://github.com/fox-it/cisco-ios-xe-implant-detection",
    }
    s = requests.Session()
    r = requests.Request(method="GET", url=url, headers=headers)
    prep = r.prepare()
    prep.url = url
    try:
        response = s.send(prep, verify=False, timeout=timeout)
        return "<h1>404 Not Found</h1>" in response.text
    except requests.exceptions.RequestException as e:
        print(f"    Error: {e}")
    return False


def check_target(target: str):
    http_url = f"http://{target}/%25"
    https_url = f"https://{target}/%25"

    possible_compromise = False
    for url in [http_url, https_url]:
        print(f"[!] Checking {url}")
        if is_compromised(url):
            print(f"    WARNING: Possible implant found for {target}! Please perform a forensic investigation!")
            possible_compromise = True

    if not possible_compromise:
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

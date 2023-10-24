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


def is_compromised(url) -> bool:
    headers = {
        "User-Agent": "iocisco.py - https://github.com/fox-it/cisco-ios-xe-implant-detection",
    }
    s = requests.Session()
    r = requests.Request(method="GET", url=url, headers=headers)
    prep = r.prepare()
    prep.url = url
    try:
        response = s.send(prep, verify=False)
        return "<h1>404 Not Found</h1>" in response.text
    except requests.exceptions.RequestException as e:
        print(f"    Error: {e}")
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', action="store", dest="target", help="Cisco IOS XE Device IP or hostname")
    parser.add_argument('-f', action="store", dest="filename", help="The filename of a file listing IP addresses")
    args = parser.parse_args()

    if args.target:
        http_url = f"http://{args.target}/%25"
        https_url = f"https://{args.target}/%25"

        possible_compromise = False
        print(f"[!] Checking {http_url}")
        if is_compromised(http_url):
            print(f"WARNING: Possible implant found for {target}! Please perform a forensic investigation!")
            possible_compromise = True

        print(f"[!] Checking {https_url}")
        if is_compromised(https_url):
            print(f"WARNING: Possible implant found for {target}! Please perform a forensic investigation!")
            possible_compromise = True

        if not possible_compromise:
            print(f"[*] Found no sign of compromise for either {http_url} or {https_url}")

    elif args.filename:
        with open(args.filename) as f:
            data = f.read()
            data_ips = data.split("\n")

            for ip in data_ips:
                http_url = f"http://{ip}/%25"
                https_url = f"https://{ip}/%25"

                possible_compromise = False
                #print(f"[!] Checking {http_url}")
                if is_compromised(http_url):
                    print(f"WARNING: Possible implant found for {ip}! Please perform a forensic investigation!")
                    possible_compromise = True

                #print(f"[!] Checking {https_url}")
                if is_compromised(https_url):
                    print(f"WARNING: Possible implant found for {ip}! Please perform a forensic investigation!")
                    possible_compromise = True

                if not possible_compromise:
                    print(f"[*] Found no sign of compromise for either {http_url} or {https_url}")


if __name__ == "__main__":
    sys.exit(main())

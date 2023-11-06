# Cisco IOS XE implant scanning & network detection
Network detection of `CVE-2023-20198` exploitation and fingerprinting of post-exploitation of Cisco IOS XE devices.

## CVE-2023-20198 Suricata network detection
The [suricata/](suricata/) folder contains Suricata detection rules for exploitation of `CVE-2023-20198`. These rules monitor for a percent-encoded-percent which can be used to bypass authentication on Cisco IOS XE devices not patched for `CVE-2023-20198`.

This directory also contains reference PCAPs based on observed in-the-wild exploitation traffic:

* [fox-it-cisco-cve-2023-20198-auth-bypass-wsma-exec.pcap](suricata/fox-it-cisco-cve-2023-20198-auth-bypass-wsma-exec.pcap?raw=true) -- CVE-2019-20198 exploit with wsma-exec
* [fox-it-cisco-cve-2023-20198-auth-bypass-wsma-config.pcap](suricata/fox-it-cisco-cve-2023-20198-auth-bypass-wsma-config.pcap?raw=true) -- CVE-2019-20198 exploit with wsma-config

## Cisco IOS XE implant scanning
This repository also contains information regarding post-exploitation activities linked to the Cisco IOS XE Software Web Management User Interface mass exploitations. Cisco Talos [^1] published a fingerprint that could check if the implant was active on Cisco IOS XE devices. For reference:

```shell
curl -k -X POST "https://DEVICEIP/webui/logoutconfirm.html?logon_hash=1"
```

If the HTTP response consists of a hexadecimal string, this is a high-confidence indicator that the device is compromised. However, as multiple sources have mentioned [^2] [^3], the number of implants that can be discovered using this method has gone down significantly.

## Upgraded Implant

Investigated network traffic to a compromised device has shown that the threat actor has upgraded the implant to do an extra header check.
Thus, for a lot of devices, the implant is still active, but now only responds if the correct `Authorization` HTTP header is set.

## Alternate method for Cisco IOS XE implant scanning

We took another look at the [initial blogpost by Cisco Talos](https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/) and noticed an extra location check in the implant code:

![implant-location-percent](implant-location-percent.png?raw=true "Extra location check")

Based on the above screenshot of the implant code shared by Cisco Talos we found another method that can be used to fingerprint the presence of the implant.

```shell
curl -k "https://DEVICEIP/%25"
```
Using the `%25` (percent encoded percent), we meet the conditions specified in the extra location check. This will cause the server to respond with a different HTTP response than it normally would when the implant is not running.

There are currently three known versions of the implant. 

### V1 / V2 response
A telltale of implant operation is a `<head><title>404 Not Found</title></head>` in the body. An example HTTP body is as such:

```html
$ curl -k 'https://DEVICEIP/%25'
<html>
<head><title>404 Not Found</title></head>
<body bgcolor="white">
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

### V3 reponse
The third variant returns the login page rather than the 404. As one would still normally expect a javascript redirect rather than this login page, we can still determine the presence of the implant by checking whether or not a login page is returned:

```html
curl -k 'https://DEVICEIP/%25'
<!DOCTYPE html>
<html>
        <!--
        Copyright (c) 2015-2019 by Cisco Systems, Inc.
        All rights reserved.
        -->
        <head lang="en">
                <meta charset="UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <title id="loginTitle"></title>
```

We found different login responses in our scanning results, and ended up with the `name="Username"` string as an identifier to determine whether or not a login page is being returned.

###  Other responses
If the implant is not present, you will get a different response. For example:

```html
$ curl -k 'https://DEVICEIP/%25'
<script>window.onload=function(){ url ='/webui';window.location.href=url;}</script>
```

## Script to check for compromise

We created a small script that checks for compromise using the above fingerprinting method. Script can be found here:

 * [iocisco.py](iocisco.py)

Example usage:

```shell
$ pip3 install requests

$ python3 iocisco.py 192.168.1.1
[!] Checking http://192.168.1.1/%25
    WARNING: Possible implant found for 192.168.1.1 (impant v3)! Please perform a forensic investigation!
[!] Checking https://192.168.1.1/%25
    WARNING: Possible implant found for 192.168.1.1 (implant v3)! Please perform a forensic investigation!
```

It is also possible to scan a list of hosts, seperated by newlines.

```shell
$ python3 iocisco.py --file cisco-ips.txt
```

## References

[^1]: https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/
[^2]: https://www.bleepingcomputer.com/news/security/number-of-hacked-cisco-ios-xe-devices-plummets-from-50k-to-hundreds/
[^3]: https://twitter.com/onyphe/status/1715633541264900217

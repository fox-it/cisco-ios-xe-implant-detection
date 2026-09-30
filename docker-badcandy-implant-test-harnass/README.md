# Cisco IOS XE "BADCANDY" Implant Test Harness

A self-contained Docker test harness that emulates the malicious Lua/nginx
implant (dubbed **BADCANDY**) dropped on Cisco IOS XE devices following the
exploitation of **CVE-2023-20198** (Web UI privilege escalation) and
**CVE-2023-20273** (privilege escalation to root / arbitrary command
execution).

The goal of this harness is **not** to reproduce an exploitable Cisco device,
but to provide a stable, safe, and repeatable HTTP endpoint that behaves like
an infected device so you can develop and validate **detection and scanning
scripts** (e.g. `curl` probes, Nuclei templates, Suricata rules, etc.).

> ⚠️ **For research and detection engineering only.** This harness intentionally
> reproduces the network-observable behaviour of a known implant. Do not deploy
> it on untrusted networks or expose it to the public internet.

---

## Background

In October 2023 threat actors mass-exploited internet-facing Cisco IOS XE Web
UIs. After gaining access they installed an implant by appending a malicious
`location` block to the device's nginx configuration file:

```
/usr/binos/conf/nginx-conf/cisco_service.conf
```

The implant hooks the legitimate-looking path `/webui/logoutconfirm.html` and
turns it into a covert command-execution backdoor. Operators interact with it
by sending `POST` requests carrying specific parameters and a hard-coded
"magic" value that authenticates the operator to the implant.

The implant exposes a small protocol:

| Request                                                     | Behaviour                                                        |
| ----------------------------------------------------------- | --------------------------------------------------------------- |
| `POST` with `menu=<non-empty>`                              | Returns the implant version string (e.g. `/1010202301/`).       |
| `POST` with `logon_hash=1`                                  | Returns a hard-coded hex "check" string, confirming infection.  |
| `POST` with `logon_hash=<magic>&common_type=subsystem`     | Executes the request body as a shell command (via `io.popen`).  |
| `POST` with `logon_hash=<magic>&common_type=iox`           | Runs body as a privileged (Priv-Level 15) IOS command via `/lua5`. |

Any request that does not match the implant's expectations falls through to a
plain `404 Not Found`, mimicking the behaviour of a clean device.

---

## What's in this repo

| File                  | Purpose                                                                                       |
| --------------------- | --------------------------------------------------------------------------------------------- |
| `docker-compose.yml`  | Spins up an `openresty/openresty:alpine` container exposing the emulated device on port 8080. |
| `nginx.conf`          | Outer server block that mimics the Cisco IOS XE nginx/openresty setup and `include`s the implant config. |
| `implant_v1.conf`     | **Version 1** of the implant — unauthenticated backdoor (original public reporting).          |
| `implant_v2.conf`     | **Version 2** of the implant — adds an `Authorization` header check (SHA-1 gated) as seen after operators hardened the implant. |

The two implant configs are dropped into the container at the same path the
real implant uses (`/usr/binos/conf/nginx-conf/cisco_service.conf`), and the
outer `nginx.conf` includes them via the same wildcard `include` directive the
genuine Cisco config uses.

### Implant versions

- **v1 (`implant_v1.conf`)** — No operator authentication. Anyone who knows the
  protocol and the `logon_hash` magic value
  (`1c434aab70312466bf9eda31018abd9d0b7cc97b`) can execute commands.
  - Version marker: `/1010202301/`
  - `logon_hash=1` response: `deadc0de11acce55ed`
- **v2 (`implant_v2.conf`)** — Adds a gate: requests must carry an
  `Authorization` header whose value, when hashed with `sha1sum`, matches
  `7cb8aae6c6634b4eb92c70aa360bd76f2fc36da8`. Unauthorized requests are served
  the normal Web UI login page instead of the backdoor, making the implant
  stealthier.
  - Version marker: `/2010202301/`
  - `logon_hash=1` response: `123cf807cc05cf59bc`
  - Command `logon_hash` magic value: `9fb903ef26fac758c70acc29190152168eea7765`

Select which version to emulate by editing the `volumes` section of
`docker-compose.yml`:

```yaml
volumes:
  - ./nginx.conf:/etc/nginx/conf.d/default.conf
  # v1: unauthenticated implant
  #- ./implant_v1.conf:/usr/binos/conf/nginx-conf/cisco_service.conf
  # v2: Authorization-gated implant (default)
  - ./implant_v2.conf:/usr/binos/conf/nginx-conf/cisco_service.conf
```

---

## Requirements

- Docker
- Docker Compose

## Usage

Start the harness:

```bash
docker compose up
```

The emulated device is now listening on:

```
http://localhost:8080/
```

Stop it with `Ctrl-C`, or `docker compose down` if run detached.

---

## Verifying / probing the implant

The following examples target the **v1** implant. For **v2**, add an
`Authorization` header whose value hashes (via `sha1sum`) to the expected
digest.

### Baseline: a clean-looking device

```bash
curl -i http://localhost:8080/webui/logoutconfirm.html
# -> HTTP/1.1 200 with an empty body (GET is not a POST, so nothing happens)

curl -i http://localhost:8080/nope
# -> HTTP/1.1 404 Not Found
```

### Detect infection (implant version marker)

```bash
curl -s -X POST 'http://localhost:8080/webui/logoutconfirm.html?menu=x'
# v1 -> /1010202301/
# v2 -> /2010202301/   (only if authorized)
```

### Detect infection (logon_hash check string)

```bash
curl -s -X POST 'http://localhost:8080/webui/logoutconfirm.html?logon_hash=1'
# v1 -> deadc0de11acce55ed
# v2 -> 123cf807cc05cf59bc   (only if authorized)
```

Note that the content returned here is just an example. The values can be different.

### Command execution (v1)

```bash
curl -s -X POST \
  'http://localhost:8080/webui/logoutconfirm.html?logon_hash=1c434aab70312466bf9eda31018abd9d0b7cc97b&common_type=subsystem' \
  --data 'id'
# -> output of the `id` command running inside the container
```

### Command execution (v2, with authorization)

The v2 implant expects an `Authorization` header value that, when piped to
`sha1sum`, contains `7cb8aae6c6634b4eb92c70aa360bd76f2fc36da8`. Supply the
correct secret token in the header, then:

```bash
curl -s -X POST \
  -H 'Authorization: <secret-token>' \
  'http://localhost:8080/webui/logoutconfirm.html?logon_hash=9fb903ef26fac758c70acc29190152168eea7765&common_type=subsystem' \
  --data 'id'
```

Without a valid `Authorization` header, v2 returns the Web UI login page,
just like an uninfected device would for that path.

---

## Detection notes

Useful, observable indicators reproduced by this harness:

- A `POST` to `/webui/logoutconfirm.html` returning a non-empty body such as a
  version string of the form `/NNNNNNNNNN/` or a fixed hex "check" token.
- A device that answers `logon_hash=1` with a static hex string.
- Distinct behaviour between `GET` (benign) and crafted `POST` requests.

The upstream repository contains reference detection tooling (see
`iocisco.py` and the `suricata/` rules at the repository root) that can be
pointed at `http://localhost:8080/` to validate coverage against both implant
versions.

---

## References

- Cisco Security Advisory: CVE-2023-20198
- Cisco Security Advisory: CVE-2023-20273
- https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/

## Disclaimer

This project is provided for defensive security research, detection
engineering, and educational purposes only. The command-execution paths run
against the disposable OpenResty container, not a real Cisco device. Use
responsibly and only in environments you own or are authorized to test.

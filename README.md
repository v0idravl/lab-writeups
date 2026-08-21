```text
██╗    ██╗██████╗ ██╗████████╗███████╗██╗   ██╗██████╗ ███████╗
██║    ██║██╔══██╗██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗██╔════╝
██║ █╗ ██║██████╔╝██║   ██║   █████╗  ██║   ██║██████╔╝███████╗
██║███╗██║██╔══██╗██║   ██║   ██╔══╝  ██║   ██║██╔═══╝ ╚════██║
╚███╔███╔╝██║  ██║██║   ██║   ███████╗╚██████╔╝██║     ███████║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝
   AI-accelerated offensive-security lab writeups · htb · pg · thm
```

[![site](https://img.shields.io/badge/read-v0idravl.github.io%2Flab--writeups-3DA639)](https://v0idravl.github.io/lab-writeups/)
![platforms](https://img.shields.io/badge/platforms-HTB%20·%20PG%20·%20THM-557C94)
![writeups](https://img.shields.io/badge/boxes-45%2B-7C3AED)
![focus](https://img.shields.io/badge/focus-AI--accelerated%20offense-E03C31)

A public-safe portfolio of **AI-accelerated offensive-security methodology** — recon, attack-path
reasoning, exploitation, privilege escalation, and reviewer-ready reporting, with AI driving the
repetitive work so the operator moves faster and documents better. Live at
**[v0idravl.github.io/lab-writeups](https://v0idravl.github.io/lab-writeups/)**.

These writeups are the **supporting-depth evidence** behind the
[ai-offsec stack](https://github.com/v0idravl/dagar-red) — the lab reps that prove the operator
can direct *and verify* AI across Active Directory, Windows, Linux, and reverse engineering, not
just run it. More context and the full evidence map: **[v0idravl.github.io/whoami](https://v0idravl.github.io/whoami)**.

---

## 🎯 Start here

| If you are reviewing for... | Start with |
|---|---|
| AI-accelerated methodology + reporting | any recent box — note the attack-path reasoning, decision points, and clean reporting |
| Active Directory / internal pentest depth | `Sauna`, `Retro`, `Resolute`, `Forest`, `Certified`, `Escape`, `Attacktive Directory`, `VulnNet-Active` |
| Enterprise network enumeration | `Return`, `Netmon`, `Sense`, `Poison`, `Twiggy` |
| Web-to-host attack paths | `Orion`, `Broker`, `Bashed`, `Horizontall`, `Knife`, `Paper`, `Exfiltrated`, `CozyHosting` |
| Privilege escalation discipline | Linux and Windows boxes with documented foothold → privesc → proof workflow |

## 🧠 Technique matrix (supporting depth)

| Technique area | Evidence in this repo |
|---|---|
| Active Directory enumeration | LDAP/SMB/Kerberos recon, domain user/computer discovery, share review, BloodHound-style path reasoning |
| Credential attacks | AS-REP/Kerberoast patterns, password spraying constraints, hash capture/cracking workflow, credential validation |
| Windows internal services | SMB, WinRM, IIS, RPC, RDP, service misconfiguration review |
| Linux services | SSH, web stacks, NFS/RPC, cron/systemd, file permission and SUID/GTFOBins-style escalation |
| Web exploitation | Directory/vhost enumeration, upload abuse, LFI/RFI-style discovery, command injection, CMS/plugin triage |
| Privilege escalation | Evidence-first local enumeration, exploit fit checks, config/secret review, safe proof capture |
| Reporting hygiene | Reproducible steps, impact-focused notes, public-safe redaction of secrets and proof values |

## 📚 Writeup index

| Category | Machines |
|---|---|
| Active Directory | HTB: Active, Administrator, Baby, Certified, Cicada, Escape, Forest, Resolute, Retro, Sauna, Support · THM: Attacktive Directory, VulnNet-Active, VulnNet-Roasted |
| Linux | HTB: Analytics, Antique, Backdoor, Bashed, Blocky, BoardLight, Broker, Busqueda, Chemistry, Code, CodePartTwo, Connected, Conversor, CozyHosting, Data, Devvortex, Dog, Down, Editor, Expressway, Greenhorn, Headless, Horizontall, Keeper, Knife, Lame, Manage, Mirai, Nibbles, Orion, Pandora, Paper, PermX, Poison, Sau, Sense, Shocker, UnderPass, Validation, Wifinetic · PG: Bratarina, Exfiltrated, Flimsy, Twiggy, Wombo · THM: ChillHack, GamingServer, Tomghost |
| Windows | HTB: Arctic, Blue, Chatterbox, Devel, Grandpa, Granny, Jerry, Netmon, Optimum, Return |

## 📝 Reviewer notes

- Written for authorized lab environments, with transferable methodology for internal pentest and
  enterprise network review.
- Prioritizes attack-path explanation, decision points, and repeatable enumeration over one-off
  command dumps.

> **Public-safe note:** writeups intentionally redact target IPs, proof values, exact hashes, and
> reusable credentials where those details are not needed to teach the attack path.

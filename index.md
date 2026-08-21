---
layout: default
title: "lab writeups"
---

# lab writeups

---

## Enterprise Networks

| Platform | Machine | Key Technique |
|---|---|---|
| HTB | [Administrator](windows/htb-administrator/htb-administrator.md) | BloodHound ACL chain (GenericAll, ForceChangePassword, GenericWrite), psafe3 Twofish offline crack, Kerberoast via SPN write, DCSync, pass-the-hash, Sliver mTLS beacon |
| HTB | [Cicada](active-directory/htb-cicada/htb-cicada.md) | Guest SMB HR share default password, password spray, LDAP description password leak, DEV share PowerShell script credential, Backup Operators SeBackupPrivilege reg save SAM+SYSTEM, secretsdump, pass-the-hash |
| HTB | [Baby](active-directory/htb-baby/htb-baby.md) | Anonymous LDAP description leak, password spray, RPC-SAMR password change, Backup Operators SeBackupPrivilege, shadow copy NTDS.dit, secretsdump, pass-the-hash |
| HTB | [Support](active-directory/htb-support/htb-support.md) | Guest SMB share, .NET binary XOR credential recovery, LDAP info attribute leak, WinRM, Shared Support Accounts write on DC$, RBCD S4U2Proxy, Sliver C2 |
| HTB | [Sauna](active-directory/htb-sauna/htb-sauna.md) | Web roster username generation, ASREPRoast, password reuse, autologon registry creds, BloodHound DCSync, pass-the-hash, Sliver C2 |
| HTB | [Retro](active-directory/htb-retro/htb-retro.md) | Guest SMB share, shared weak credential, pre-2k computer account, ADCS ESC1, PassTheCert Schannel LDAP, DCSync |
| HTB | [Resolute](active-directory/htb-resolute/htb-resolute.md) | Anonymous LDAP, description-stored credential, password spray, PowerShell transcript creds, DnsAdmins ServerLevelPluginDll to SYSTEM |
| HTB | [Certified](active-directory/htb-certified/htb-certified.md) | WriteOwner ACL chain, Shadow Credentials, ADCS ESC9 UPN spoofing |
| HTB | [Escape](active-directory/htb-escape/htb-escape.md) | Guest SMB share, PDF credential disclosure, MSSQL xp_dirtree NTLMv2 capture, SQL Server error log credentials, ADCS ESC1 |
| HTB | [Active](active-directory/htb-active/htb-active.md) | Anonymous SMB, GPP credential disclosure, Kerberoasting |
| HTB | [Forest](active-directory/htb-forest/htb-forest.md) | Anonymous LDAP/SMB, ASREPRoast, BloodHound, Account Operators WriteDACL, DCSync, pass-the-hash |
| THM | [VulnNet Active](active-directory/thm-vulnnet-active/thm-vulnnet-active.md) | Redis NTLM capture via Responder, scheduled task hijack, GPO GenericWrite, SharpGPOAbuse |
| THM | [Attacktive Directory](active-directory/thm-attacktivedirect/thm-attacktivedirect.md) | Kerbrute, ASREPRoast, SMB share access, DCSync, pass-the-hash |
| THM | [VulnNet Roasted](active-directory/thm-vulnnet-roasted/thm-vulnnet-roasted.md) | Anonymous SMB, username generation, ASREPRoast, NETLOGON script creds, DCSync, pass-the-hash |

---

## Linux

| Platform | Machine | Key Technique |
|---|---|---|
| HTB | [Manage](linux/htb-manage/htb-manage.md) | JMX unauthenticated RMI credential/firewall bypass via jmxterm, Tomcat Manager WAR deploy, world-readable backup (SSH key + TOTP seed), sudo adduser admin-group creation |
| HTB | [Editor](linux/htb-editor/htb-editor.md) | XWiki Groovy RCE (CVE-2025-24893), ndsudo PATH injection (CVE-2024-32019) |
| HTB | [Conversor](linux/htb-conversor/htb-conversor.md) | lxml module hijacking via upload path traversal, MD5 hash crack (fismathack), needrestart CVE-2024-48990 PYTHONPATH injection to root |
| HTB | [PermX](linux/htb-permx/htb-permx.md) | CVE-2023-4220 Chamilo 1.11.10 unauthenticated file upload RCE, DB password SSH reuse (mtz), sudo acl.sh symlink setfacl /etc/sudoers write to root |
| HTB | [Greenhorn](linux/htb-greenhorn/htb-greenhorn.md) | Gitea public repo SHA-512 hash crack, Pluck 4.7.18 module upload RCE, password reuse (junior), Depix block-pixelation recovery of root password |
| HTB | [Dog](linux/htb-dog/htb-dog.md) | Exposed .git source dump, DB cred reuse for CMS admin, Backdrop tar.gz module install RCE, DB password SSH reuse (johncusack), sudo bee eval PHP-as-root |
| HTB | [Code](linux/htb-code/htb-code.md) | Python sandbox keyword filter bypass (`chr()`/string concat/`globals()`), SQLite MD5 hash crack + SSH reuse, `sudo backy.sh` jq `gsub` non-recursive `../` strip (`....//` → `../`) leaks `/root/` tar to user-readable backups |
| HTB | [Chemistry](linux/htb-chemistry/htb-chemistry.md) | CVE-2024-23346 pymatgen CIF `eval()` RCE, MD5 hash crack credential reuse, CVE-2024-23334 AIOHTTP `%2e%2e/` path traversal to root SSH key |
| HTB | [Validation](linux/htb-validation/htb-validation.md) | Second-order SQLi (country field, no server-side validation), MySQL INTO OUTFILE PHP webshell, DB plaintext credential reused as root OS password |
| HTB | [Data](linux/htb-data/htb-data.md) | CVE-2021-43798 Grafana unauthenticated path traversal, grafana.db PBKDF2-SHA256 hash crack, SSH reuse, sudo docker exec NOPASSWD host disk mount to root |
| HTB | [Connected](linux/htb-connected/htb-connected.md) | CVE-2025-57819 FreePBX unauthenticated SQLi cron_jobs injection, incron sysadmin_ha PHP include injection via writable modules path to root |
| HTB | [Busqueda](linux/htb-busqueda/htb-busqueda.md) | Searchor 2.4.0 eval() Python injection (CVE-2023-43364), .git/config plaintext creds, sudo system-checkup.py full-checkup relative path hijack to root |
| HTB | [Down](linux/htb-down/htb-down.md) | escapeshellcmd() curl flag injection SSRF (file read), nc -e connect-mode RCE, pswm vault offline crack (scrypt/AES-GCM), sudo ALL |
| HTB | [UnderPass](linux/htb-underpass/htb-underpass.md) | SNMP public community application disclosure, daloRADIUS default creds, RADIUS user MD5 hash crack, SSH credential reuse, sudo mosh-server NOPASSWD GTFOBins root |
| HTB | [BoardLight](linux/htb-boardlight/htb-boardlight.md) | Dolibarr 17.0.0 default creds, CVE-2023-30253 PHP injection via uppercase bypass, DB password reuse to SSH, CVE-2022-37706 enlightenment_sys SUID shell injection to root |
| HTB | [Devvortex](linux/htb-devvortex/htb-devvortex.md) | Joomla 4.2.6 CVE-2023-23752 unauthenticated API config leak, admin template PHP webshell, MySQL bcrypt hash dump, john crack (rockyou), sudo apport-cli CVE-2023-1326 less pager escape to root |
| HTB | [CodePartTwo](linux/htb-codeparttwo/htb-codeparttwo.md) | js2py 0.74 sandbox escape via Python MRO subclass chain to subprocess.Popen RCE, MD5 hash crack + SSH reuse, sudo npbackup-cli custom config pre_exec_commands hook to SUID bash |
| HTB | [Analytics](linux/htb-analytics/htb-analytics.md) | Metabase pre-auth RCE (CVE-2023-38646) via leaked setup-token H2 JDBC trigger, Docker container env-var credential leak, SSH reuse, GameOver(lay) OverlayFS local root (CVE-2023-2640 / CVE-2023-32629) |
| HTB | [Expressway](linux/htb-expressway/htb-expressway.md) | IKEv1 aggressive-mode PSK capture (ike-scan) + offline crack (psk-crack), VPN-PSK-to-SSH credential reuse, sudo 1.9.17 `--chroot` NSS local root (CVE-2025-32463) |
| HTB | [Headless](linux/htb-headless/htb-headless.md) | Header-based blind XSS (User-Agent) to steal admin cookie, non-HttpOnly signed cookie theft, authenticated command injection, sudo script relative-path `./initdb.sh` writable-CWD hijack |
| HTB | [Sau](linux/htb-sau/htb-sau.md) | Request Baskets SSRF (CVE-2023-27163) to firewalled internal service, Maltrail 0.53 unauthenticated command injection, sudo systemctl status less pager break-out |
| HTB | [CozyHosting](linux/htb-cozyhosting/htb-cozyhosting.md) | Spring Boot Actuator `/actuator/sessions` leak, JSESSIONID hijack, `/executessh` command injection (`${IFS}`), DB creds in jar, bcrypt crack + SSH reuse, sudo `/usr/bin/ssh` ProxyCommand escape (GTFOBins) |
| HTB | [Broker](linux/htb-broker/htb-broker.md) | Apache ActiveMQ OpenWire deserialization RCE (CVE-2023-46604) via Spring ClassPathXmlApplicationContext, sudo nginx with WebDAV PUT to write root's authorized_keys |
| HTB | [Orion](linux/htb-orion/htb-orion.md) | Craft CMS pre-auth RCE (CVE-2025-32432) via asset-transform object injection, phpinfo secret leak, bcrypt crack + credential reuse, custom telnetd environment passthrough to glibc GCONV_PATH gconv module for root |
| HTB | [Inject](linux/htb-inject/htb-inject.md) | Spring Cloud Function SpEL injection (CVE-2022-22963), Maven settings credential recovery, Ansible cron abuse |
| HTB | [Keeper](linux/htb-keeper/htb-keeper.md) | Request Tracker default creds, credential in user-record comment, KeePass memory dump (CVE-2023-32784), PuTTY key conversion |
| HTB | [Paper](linux/htb-paper/htb-paper.md) | Header-based vhost leak, WordPress draft disclosure, chatbot path traversal, polkit bypass |
| HTB | [Poison](linux/htb-poison/htb-poison.md) | LFI, repeated base64 decode, VNC session tunneling |
| HTB | [Sense](linux/htb-sense/htb-sense.md) | `system-users.txt` credential disclosure, CVE-2016-10709 pfSense `graph` param pipe/octal injection as root, PHP webshell flag read |
| HTB | [Horizontall](linux/htb-horizontall/htb-horizontall.md) | Strapi RCE (CVE-2019-19609), Laravel debug RCE via SSH port forward |
| HTB | [Backdoor](linux/htb-backdoor/htb-backdoor.md) | WordPress LFI, gdbserver RCE, screen session hijack |
| THM | [Chill Hack](linux/thm-chillhack/thm-chillhack.md) | Command injection bypass, sudo script injection, SSH forward, SQLi, steghide, docker escape |
| HTB | [Pandora](linux/htb-pandora/htb-pandora.md) | SNMP credential disclosure, PwnKit (CVE-2021-4034) |
| HTB | [Antique](linux/htb-antique/htb-antique.md) | SNMP-leaked HP JetDirect password, telnet console `exec` as `lp`, CUPS `lpadmin` ErrorLog arbitrary file read as root (CVE-2012-5519) |
| PG | [Flimsy](linux/pg-flimsy/pg-flimsy.md) | Apache APISIX RCE (CVE-2022-24112), apt.conf.d cron abuse |
| HTB | [Shocker](linux/htb-shocker/htb-shocker.md) | Shellshock CGI (CVE-2014-6271), perl sudo |
| PG | [Twiggy](linux/pg-twiggy/pg-twiggy.md) | SaltStack auth bypass RCE (CVE-2020-11651) |
| THM | [Tomghost](linux/thm-tomghost/thm-tomghost.md) | Ghostcat (CVE-2020-1938), GPG key crack, zip sudo |
| PG | [Bratarina](linux/pg-bratarina/pg-bratarina.md) | OpenSMTPD RCE (CVE-2020-7247) |
| THM | [GamingServer](linux/thm-gamingserver/thm-gamingserver.md) | RSA key crack, SSH, lxd container escape |
| HTB | [Nibbles](linux/htb-nibbles/htb-nibbles.md) | NibbleBlog file upload (CVE-2015-6967), missing sudo script |
| HTB | [Knife](linux/htb-knife/htb-knife.md) | PHP 8.1.0-dev supply chain backdoor, knife sudo |
| HTB | [Lame](linux/htb-lame/htb-lame.md) | distcc RCE (CVE-2004-2687), nmap SUID |
| HTB | [Blocky](linux/htb-blocky/htb-blocky.md) | JAR decompilation, credential reuse, sudo ALL |
| PG | [Exfiltrated](linux/pg-exfiltrated/pg-exfiltrated.md) | Subrion file upload RCE, PwnKit |
| HTB | [Mirai](linux/htb-mirai/htb-mirai.md) | Raspberry Pi default creds, deleted file recovery with strings |
| HTB | [Bashed](linux/htb-bashed/htb-bashed.md) | phpbash webshell left in production, cron script replace |
| PG | [Wombo](linux/pg-wombo/pg-wombo.md) | Unauthenticated Redis replication RCE |

---

## Windows

| Platform | Machine | Key Technique |
|---|---|---|
| HTB | [Arctic](windows/htb-arctic/htb-arctic.md) | CVE-2010-2861 ColdFusion 8 path traversal hash leak, CF scheduled-task webshell, MS16-075 SeImpersonatePrivilege Juicy Potato |
| HTB | [Return](windows/htb-return/htb-return.md) | Printer LDAP credential capture, Server Operators service binary hijack |
| HTB | [Chatterbox](windows/htb-chatterbox/htb-chatterbox.md) | Achat buffer overflow, AutoLogon registry credential dump |
| HTB | [Netmon](windows/htb-netmon/htb-netmon.md) | FTP PRTG config backup, credential year-increment, notification RCE |
| HTB | [Devel](windows/htb-devel/htb-devel.md) | Anonymous FTP to IIS webroot, KiTrap0D (MS10-015) |
| HTB | [Grandpa](windows/htb-grandpa/htb-grandpa.md) | CVE-2017-7269 IIS 6.0 WebDAV ScStoragePathFromUrl ROP buffer overflow, KiTrap0D (MS10-015) kernel LPE |
| HTB | [Granny](windows/htb-granny/htb-granny.md) | IIS 6.0 WebDAV PUT/MOVE to .aspx webshell, MS15-051 win32k kernel LPE |
| HTB | [Optimum](windows/htb-optimum/htb-optimum.md) | Rejetto HFS RCE (CVE-2014-6287), MS16-032 |
| HTB | [Blue](windows/htb-blue/htb-blue.md) | EternalBlue (MS17-010) |
| HTB | [Jerry](windows/htb-jerry/htb-jerry.md) | Tomcat default credentials, WAR file upload RCE |

---

## Reference

- [writeup-template.md](writeup-template.md)
- [oscp-findings-reference.md](oscp-findings-reference.md)

---

## Public-Safe Reporting Standard

These writeups preserve methodology, reasoning, tooling, remediation, and detection opportunities while redacting target-specific secrets such as flags, exact hashes, plaintext passwords, and lab IP addresses when they are not required for learning value.

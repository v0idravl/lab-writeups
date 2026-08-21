---
layout: default
title: "Linux Writeups"
---

# Linux

| Platform | Machine | Key Technique |
|---|---|---|
| HTB | [Manage](htb-manage/htb-manage.md) | JMX unauthenticated RMI credential/firewall bypass via jmxterm, Tomcat Manager WAR deploy, world-readable backup (SSH key + TOTP seed), sudo adduser admin-group creation |
| HTB | [Editor](htb-editor/htb-editor.md) | XWiki Groovy RCE (CVE-2025-24893), ndsudo PATH injection (CVE-2024-32019) |
| HTB | [Conversor](htb-conversor/htb-conversor.md) | lxml module hijacking via upload path traversal, MD5 hash crack (fismathack), needrestart CVE-2024-48990 PYTHONPATH injection to root |
| HTB | [PermX](htb-permx/htb-permx.md) | CVE-2023-4220 Chamilo 1.11.10 unauthenticated file upload RCE, DB password SSH reuse (mtz), sudo acl.sh symlink setfacl /etc/sudoers write to root |
| HTB | [Greenhorn](htb-greenhorn/htb-greenhorn.md) | Gitea public repo SHA-512 hash crack, Pluck 4.7.18 module upload RCE, password reuse (junior), Depix block-pixelation recovery of root password |
| HTB | [Dog](htb-dog/htb-dog.md) | Exposed .git source dump, DB cred reuse for CMS admin, Backdrop tar.gz module install RCE, DB password SSH reuse (johncusack), sudo bee eval PHP-as-root |
| HTB | [Code](htb-code/htb-code.md) | Python sandbox keyword filter bypass (`chr()`/string concat/`globals()`), SQLite MD5 hash crack + SSH reuse, `sudo backy.sh` jq `gsub` non-recursive `../` strip (`....//` → `../`) leaks `/root/` tar to user-readable backups |
| HTB | [Chemistry](htb-chemistry/htb-chemistry.md) | CVE-2024-23346 pymatgen CIF `eval()` RCE, MD5 hash crack credential reuse (su rosa), CVE-2024-23334 AIOHTTP `%2e%2e/` path traversal to root SSH key |
| HTB | [Validation](htb-validation/htb-validation.md) | Second-order SQLi (country field, no server-side validation), MySQL INTO OUTFILE PHP webshell, DB plaintext credential reused as root OS password |
| HTB | [Data](htb-data/htb-data.md) | CVE-2021-43798 Grafana unauthenticated path traversal, grafana.db PBKDF2-SHA256 hash crack, SSH reuse, sudo docker exec NOPASSWD host disk mount to root |
| HTB | [Connected](htb-connected/htb-connected.md) | CVE-2025-57819 FreePBX unauthenticated SQLi cron_jobs injection, incron sysadmin_ha PHP include injection via writable modules path to root |
| HTB | [Busqueda](htb-busqueda/htb-busqueda.md) | Searchor 2.4.0 eval() Python injection (CVE-2023-43364), .git/config plaintext creds, sudo system-checkup.py full-checkup relative path hijack to root |
| HTB | [Down](htb-down/htb-down.md) | escapeshellcmd() curl flag injection SSRF (file read), nc -e connect-mode RCE, pswm vault offline crack (scrypt/AES-GCM), sudo ALL |
| HTB | [UnderPass](htb-underpass/htb-underpass.md) | SNMP public community application disclosure, daloRADIUS default creds, RADIUS user MD5 hash crack, SSH credential reuse, sudo mosh-server NOPASSWD GTFOBins root |
| HTB | [BoardLight](htb-boardlight/htb-boardlight.md) | Dolibarr 17.0.0 default creds, CVE-2023-30253 PHP injection via uppercase bypass, DB password reuse to SSH, CVE-2022-37706 enlightenment_sys SUID shell injection to root |
| HTB | [Devvortex](htb-devvortex/htb-devvortex.md) | Joomla 4.2.6 CVE-2023-23752 unauthenticated API config leak, admin template PHP webshell, MySQL bcrypt hash dump, john crack (rockyou), sudo apport-cli CVE-2023-1326 less pager escape to root |
| HTB | [CodePartTwo](htb-codeparttwo/htb-codeparttwo.md) | js2py 0.74 sandbox escape via Python MRO subclass chain to subprocess.Popen RCE, MD5 hash crack + SSH reuse, sudo npbackup-cli custom config pre_exec_commands hook to SUID bash |
| HTB | [Analytics](htb-analytics/htb-analytics.md) | Metabase pre-auth RCE (CVE-2023-38646) via leaked setup-token H2 JDBC trigger, Docker container env-var credential leak, SSH reuse, GameOver(lay) OverlayFS local root (CVE-2023-2640 / CVE-2023-32629) |
| HTB | [Expressway](htb-expressway/htb-expressway.md) | IKEv1 aggressive-mode PSK capture (ike-scan) + offline crack (psk-crack), VPN-PSK-to-SSH credential reuse, sudo 1.9.17 `--chroot` NSS local root (CVE-2025-32463) |
| HTB | [Sau](htb-sau/htb-sau.md) | Request Baskets SSRF (CVE-2023-27163) to firewalled internal service, Maltrail 0.53 unauthenticated command injection, sudo systemctl status less pager break-out |
| HTB | [CozyHosting](htb-cozyhosting/htb-cozyhosting.md) | Spring Boot Actuator `/actuator/sessions` leak, JSESSIONID hijack, `/executessh` command injection (`${IFS}`), DB creds in jar, bcrypt crack + SSH reuse, sudo `/usr/bin/ssh` ProxyCommand escape (GTFOBins) |
| HTB | [Broker](htb-broker/htb-broker.md) | Apache ActiveMQ OpenWire deserialization RCE (CVE-2023-46604) via Spring ClassPathXmlApplicationContext, sudo nginx with WebDAV PUT to write root's authorized_keys |
| HTB | [Orion](htb-orion/htb-orion.md) | Craft CMS pre-auth RCE (CVE-2025-32432) via asset-transform object injection, phpinfo secret leak, bcrypt crack + credential reuse, custom telnetd environment passthrough to glibc GCONV_PATH gconv module for root |
| HTB | [Wifinetic](htb-wifinetic/htb-wifinetic.md) | Anonymous-FTP OpenWrt config backup, WPA passphrase reuse, WPS PIN attack (Reaver) via `cap_net_raw`, credential reuse to root |
| HTB | [Inject](htb-inject/htb-inject.md) | Spring Cloud Function SpEL injection (CVE-2022-22963), Maven settings credential recovery, Ansible cron abuse |
| HTB | [Keeper](htb-keeper/htb-keeper.md) | Request Tracker default creds, credential in user-record comment, KeePass memory dump (CVE-2023-32784), PuTTY key conversion |
| HTB | [Paper](htb-paper/htb-paper.md) | Header-based vhost leak, WordPress draft disclosure, chatbot path traversal, polkit bypass |
| HTB | [Poison](htb-poison/htb-poison.md) | LFI, repeated base64 decode, VNC session tunneling |
| HTB | [Sense](htb-sense/htb-sense.md) | `system-users.txt` credential disclosure, CVE-2016-10709 pfSense `graph` param pipe/octal injection as root, PHP webshell flag read |
| HTB | [Horizontall](htb-horizontall/htb-horizontall.md) | Strapi RCE (CVE-2019-19609), Laravel debug RCE via SSH port forward |
| HTB | [Backdoor](htb-backdoor/htb-backdoor.md) | WordPress LFI, gdbserver RCE, screen session hijack |
| THM | [Chill Hack](thm-chillhack/thm-chillhack.md) | Command injection bypass, sudo script injection, SSH forward, SQLi, steghide, docker escape |
| HTB | [Pandora](htb-pandora/htb-pandora.md) | SNMP credential disclosure, PwnKit (CVE-2021-4034) |
| HTB | [Antique](htb-antique/htb-antique.md) | SNMP-leaked HP JetDirect password, telnet console `exec` as `lp`, CUPS `lpadmin` ErrorLog arbitrary file read as root (CVE-2012-5519) |
| PG | [Flimsy](pg-flimsy/pg-flimsy.md) | Apache APISIX RCE (CVE-2022-24112), apt.conf.d cron abuse |
| HTB | [Shocker](htb-shocker/htb-shocker.md) | Shellshock CGI (CVE-2014-6271), perl sudo |
| PG | [Twiggy](pg-twiggy/pg-twiggy.md) | SaltStack auth bypass RCE (CVE-2020-11651) |
| THM | [Tomghost](thm-tomghost/thm-tomghost.md) | Ghostcat (CVE-2020-1938), GPG key crack, zip sudo |
| PG | [Bratarina](pg-bratarina/pg-bratarina.md) | OpenSMTPD RCE (CVE-2020-7247) |
| THM | [GamingServer](thm-gamingserver/thm-gamingserver.md) | RSA key crack, SSH, lxd container escape |
| HTB | [Nibbles](htb-nibbles/htb-nibbles.md) | NibbleBlog file upload (CVE-2015-6967), missing sudo script |
| HTB | [Knife](htb-knife/htb-knife.md) | PHP 8.1.0-dev supply chain backdoor, knife sudo |
| HTB | [Lame](htb-lame/htb-lame.md) | distcc RCE (CVE-2004-2687), nmap SUID |
| HTB | [Blocky](htb-blocky/htb-blocky.md) | JAR decompilation, credential reuse, sudo ALL |
| PG | [Exfiltrated](pg-exfiltrated/pg-exfiltrated.md) | Subrion file upload RCE, PwnKit |
| HTB | [Mirai](htb-mirai/htb-mirai.md) | Raspberry Pi default creds, deleted file recovery with strings |
| HTB | [Bashed](htb-bashed/htb-bashed.md) | phpbash webshell left in production, cron script replace |
| PG | [Wombo](pg-wombo/pg-wombo.md) | Unauthenticated Redis replication RCE |

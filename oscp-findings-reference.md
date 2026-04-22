## 1. Outdated or Vulnerable Software

### **Finding:** Unauthenticated Command Injection in Network Monitoring or Logging Service

**Severity:** Critical

**Description:**
A network monitoring or logging service contained a vulnerability that allowed unauthenticated command injection through user-controlled input.

**Impact:**
Attackers could execute arbitrary commands on the system and gain unauthorized access.

**Recommendation:**
Upgrade to a patched version, restrict access to the service, and implement input validation and authentication controls.

### **Finding:** Outdated or End-of-Life Software

**Severity:** Critical

**Description:**
The target system was running outdated or unsupported software containing publicly known vulnerabilities.

**Impact:**
An attacker could exploit these vulnerabilities to execute arbitrary code and gain full system compromise.

**Recommendation:**
Upgrade to a supported version, apply all available security patches, and implement a formal patch management process.

### **Finding:** Vulnerable Web Application Allowing Remote Code Execution

**Severity:** Critical

**Description:**
A publicly accessible web application contained a known vulnerability that allowed arbitrary command execution.

**Impact:**
Unauthenticated attackers could gain system-level access to the host.

**Recommendation:**
Remove or upgrade the vulnerable application, restrict administrative interfaces, and isolate legacy services.

---

## 2. Weak or Exposed Credentials

### **Finding:** Weak FTP Credentials

**Severity:** Critical

**Description:**
The FTP service allowed authentication using weak or default credentials (e.g., `admin:admin`).

**Impact:**
Attackers could gain authenticated access to the FTP service and potentially upload malicious files or access sensitive data.

**Recommendation:**
Enforce strong password policies, disable default credentials, and implement account lockout mechanisms.

### **Finding:** Hardcoded Credentials in Configuration Files

**Severity:** High

**Description:**
Credentials were stored in configuration files and exposed through application vulnerabilities.

**Impact:**
Attackers could retrieve credentials and use them to authenticate or execute commands on the system.

**Recommendation:**
Store credentials securely using protected storage mechanisms and restrict access to configuration files.

### **Finding:** SSH Key Misconfiguration Allowing Root Access

**Severity:** Critical

**Description:**
An SSH key was configured to allow direct root login without sufficient restrictions.

**Impact:**
Attackers possessing the private key could gain immediate root access to the system.

**Recommendation:**
Disable root SSH login, restrict authorized keys, enforce key passphrases, and audit SSH configurations regularly.

### **Finding:** Default phpMyAdmin Credentials

**Severity:** Critical

**Description:**
The phpMyAdmin interface allowed authentication using default credentials (e.g., root with no password).

**Impact:**
Attackers could gain full database access, modify data, and potentially write files to the underlying system.

**Recommendation:**
Disable default credentials, enforce strong authentication, and restrict access to administrative interfaces.

### **Finding:** Weak MSSQL Credentials

**Severity:** High

**Description:**
The MSSQL service accepted weak or easily guessable credentials, allowing unauthorized database access.

**Impact:**
Attackers could authenticate to the database, enumerate data, and potentially leverage the service for further compromise.

**Recommendation:**
Enforce strong password policies, disable default or weak credentials, and restrict database access to authorized users and hosts.

### **Finding:** Stored Administrative Credentials via Windows Credential Manager

**Severity:** Critical

**Description:**
Administrative credentials were stored locally and retrievable using Windows Credential Manager (e.g., `cmdkey`).

**Impact:**
Attackers could extract stored credentials and reuse them to escalate privileges or access additional systems.

**Recommendation:**
Avoid storing administrative credentials on systems, enforce credential protection mechanisms such as Credential Guard, and regularly audit stored credentials.

### **Finding:** Hardcoded Authorization Key in Application Binary

**Severity:** High

**Description:**
An application binary (e.g., `redis-status`) contained a hardcoded authorization key that could be retrieved through static analysis.

**Impact:**
Attackers could extract the key and bypass authentication controls to execute privileged functionality.

**Recommendation:**
Remove hardcoded credentials from application binaries, implement secure key storage mechanisms, and rotate any exposed keys.

### **Finding:** Weak Credential Management and Reuse

**Severity:** High

**Description:**
Passwords were reused across multiple services and stored insecurely.

**Impact:**
Attackers could reuse compromised credentials to access additional services and escalate privileges.

**Recommendation:**
Implement strong password policies, enforce credential uniqueness, and ensure secure storage of authentication data.

### **Finding:** Exposed Credentials in Configuration Files

**Severity:** Critical

**Description:**
Credentials were stored in plaintext within configuration files accessible via SMB shares.

**Impact:**
Attackers could retrieve valid credentials and use them to gain unauthorized access to services.

**Recommendation:**
Remove plaintext credentials from configuration files, use secure credential storage mechanisms, and restrict access to sensitive files.

### **Finding:** Weak or Predictable Credentials

**Severity:** High

**Description:**
The system used predictable or easily guessable credentials.

**Impact:**
Attackers could gain unauthorized access to services such as SSH using valid credentials.

**Recommendation:**
Enforce strong password policies, eliminate default or guessable credentials, and implement account lockout mechanisms.

### **Finding:** Hardcoded Cryptographic Key in Application Binary

**Severity:** High

**Description:**
An application binary contained a hardcoded cryptographic key used for protecting sensitive data.

**Impact:**
Attackers could extract the embedded key and decrypt protected information or bypass application security mechanisms.

**Recommendation:**
Avoid embedding cryptographic keys in application code, use secure key management solutions, and rotate any exposed keys immediately.

### **Finding:** Plaintext Password Stored in LDAP Attribute

**Severity:** Critical

**Description:**
A domain user password was stored in plaintext within an Active Directory attribute (such as the description field), making it accessible to authenticated users.

**Impact:**
Attackers could retrieve the exposed credential and use it to authenticate as the affected user, potentially leading to privilege escalation or lateral movement.

**Recommendation:**
Prohibit storage of credentials in Active Directory attributes, implement auditing for sensitive attribute exposure, and perform credential rotation for affected accounts.

### **Finding:** Hardcoded Credentials in Source Code

**Severity:** High

**Description:**
Sensitive credentials were embedded directly within application source code accessible to low-privileged users.

**Impact:**
Attackers could retrieve credentials and use them to gain unauthorized access to services or escalate privileges.

**Recommendation:**
Remove hardcoded credentials from source code, use secure configuration storage or secret management solutions, and restrict access to sensitive files.

### **Finding:** Credentials Stored in Registry or System Files (Windows)

**Severity:** High

**Description:**
Sensitive credentials were stored in the Windows registry or system configuration files accessible to low-privileged users.

**Impact:**
Attackers could extract credentials and escalate privileges or move laterally.

**Recommendation:**
Avoid storing plaintext credentials in the registry or system files. Use secure credential storage mechanisms and restrict access permissions.

### **Finding:** Default or Weak Credentials

**Severity:** High

**Description:**
The application used weak or guessable credentials.

**Impact:**
Attackers could gain unauthorized access to administrative interfaces or services.

**Recommendation:**
Enforce strong password policies, implement account lockout mechanisms, and require unique credentials per service.

### **Finding:** Credential Exposure in Files or Web Content

**Severity:** Critical

**Description:**
Sensitive credentials were stored in web-accessible files or user-readable locations.

**Impact:**
Attackers could retrieve credentials and escalate privileges.

**Recommendation:**
Remove sensitive files from web directories, restrict file permissions, and use centralized secret management solutions.

### **Finding:** Credential Reuse Across Services

**Severity:** High

**Description:**
The same credentials were used across multiple services.

**Impact:**
Compromise of one service could lead to compromise of additional services.

**Recommendation:**
Enforce unique credentials per service and implement credential rotation policies.

### **Finding:** Credentials Stored in Configuration Files

**Severity:** High

**Description:**
Service or application credentials were stored in plaintext configuration files accessible to low-privileged users.

**Impact:**
Attackers could retrieve credentials and reuse them to access other services or escalate privileges.

**Recommendation:**
Store credentials securely using protected configuration storage or secret management systems and restrict file permissions.

### **Finding:** Password Recovered from Local History or Scripts

**Severity:** High

**Description:**
Sensitive credentials were found in shell history, scripts, or user-accessible files.

**Impact:**
Attackers could use the credentials to escalate privileges or access other systems.

**Recommendation:**
Avoid storing credentials in plaintext. Sanitize scripts, clear history files, and enforce strict file permissions.

---

## 3. Unauthenticated or Misconfigured Network Services

### **Finding:** Anonymous FTP Access Enabled

**Severity:** Medium

**Description:**
The FTP service permitted anonymous login without authentication.

**Impact:**
Attackers could enumerate directory structures and gather sensitive information.

**Recommendation:**
Disable anonymous FTP access unless explicitly required, and restrict access to authorized users only.

### **Finding:** SMB Anonymous Access Allowing Sensitive File Retrieval

**Severity:** Medium

**Description:**
An SMB share allowed unauthenticated access to files containing sensitive information.

**Impact:**
Attackers could retrieve configuration files, credentials, or other sensitive data to aid further compromise.

**Recommendation:**
Disable anonymous access to SMB shares, enforce authentication, and apply least-privilege permissions.

### **Finding:** Unauthenticated Service Allowing Command Execution

**Severity:** Critical

**Description:**
A network service (e.g., FreeSWITCH event socket) allowed unauthenticated users to execute commands.

**Impact:**
Attackers could execute arbitrary commands and gain shell access to the system.

**Recommendation:**
Restrict access to the service, enforce authentication, and limit exposure to trusted networks.

### **Finding:** Lack of Egress Filtering

**Severity:** High

**Description:**
The system allowed unrestricted outbound network connections to external hosts.

**Impact:**
Attackers could establish reverse shells and maintain persistent remote access.

**Recommendation:**
Implement outbound firewall rules to restrict unauthorized connections and monitor network traffic for suspicious activity.

### **Finding:** Open Proxy Allowing Access to Internal Services

**Severity:** High

**Description:**
A proxy service (e.g., Squid) allowed unrestricted access to internal services, enabling users to connect to otherwise inaccessible hosts and ports.

**Impact:**
Attackers could pivot into internal networks, enumerate hidden services, and identify additional attack paths.

**Recommendation:**
Restrict proxy access using authentication and IP whitelisting, and limit accessible destinations to trusted networks only.

### **Finding:** NTLM Hash Exposure via MSSQL UNC Path Injection

**Severity:** Critical

**Description:**
The MSSQL service allowed execution of functionality (e.g., via extended stored procedures) that triggered outbound authentication to attacker-controlled UNC paths.

**Impact:**
Attackers could capture NTLM authentication hashes and perform relay or offline cracking attacks to gain unauthorized access.

**Recommendation:**
Disable or restrict dangerous stored procedures (e.g., `xp_dirtree`, `xp_fileexist`), block outbound SMB traffic, and enforce SMB signing where possible.

### **Finding:** Anonymous FTP Access Exposing Sensitive Files

**Severity:** High

**Description:**
The FTP service allowed anonymous login and exposed sensitive backup and configuration files.

**Impact:**
Attackers could retrieve internal data, including credential databases and archived files, aiding further compromise.

**Recommendation:**
Disable anonymous FTP access, restrict file permissions, and ensure sensitive files are not stored in publicly accessible directories.

### **Finding:** Unauthenticated Redis Service Exposure

**Severity:** Critical

**Description:**
The Redis service was exposed without authentication, allowing remote interaction with the database.

**Impact:**
Attackers could execute commands on the Redis instance, potentially leading to remote code execution and initial system compromise.

**Recommendation:**
Enable authentication for Redis, bind the service to localhost or restrict access via firewall rules, and enable protected mode.

### **Finding:** User Enumeration via Finger Service

**Severity:** Medium

**Description:**
The Finger service allowed unauthenticated users to enumerate valid system usernames.

**Impact:**
Attackers could identify valid user accounts and use them for further attacks such as brute force or credential spraying.

**Recommendation:**
Disable the Finger service if not required, or restrict access using firewall rules and access controls.

### **Finding:** DNS Zone Transfer Enabled

**Severity:** High

**Description:**
The DNS server permitted unauthenticated zone transfers, allowing attackers to retrieve the full list of DNS records for the domain.

**Impact:**
Attackers could enumerate internal hosts, services, and infrastructure components, aiding further reconnaissance and potential lateral movement.

**Recommendation:**
Restrict zone transfers to trusted DNS servers only and configure the DNS server to deny unauthorized transfer requests.

### **Finding:** Anonymous Writable SMB Share

**Severity:** High

**Description:**
An SMB share allowed anonymous users to write files without authentication.

**Impact:**
Attackers could upload malicious files or tools to the share, potentially enabling credential harvesting attacks or facilitating further compromise.

**Recommendation:**
Disable anonymous access to SMB shares, restrict share permissions to authenticated users, and monitor file shares for unauthorized uploads.

### **Finding:** Anonymous SMB Share Access

**Severity:** Critical

**Description:**
SMB shares were accessible without authentication, allowing anonymous enumeration of files and directories.

**Impact:**
Attackers could access sensitive data, identify credential files, or discover information useful for further compromise.

**Recommendation:**
Disable null sessions, restrict anonymous access to SMB shares, and enforce authentication for all file share access.

### **Finding:** Unrestricted SMB Share Access

**Severity:** High

**Description:**
An SMB share was accessible without authentication or with overly permissive access controls.

**Impact:**
Attackers could read or modify sensitive files, potentially leading to credential exposure or privilege escalation.

**Recommendation:**
Restrict SMB shares to authenticated users, apply least-privilege permissions, and disable guest or anonymous access.

### **Finding:** Unrestricted NFS Share

**Severity:** Critical

**Description:**
An NFS share was accessible without proper access restrictions.

**Impact:**
Attackers could mount the share, access sensitive files, or introduce malicious content to escalate privileges.

**Recommendation:**
Restrict NFS access to trusted hosts, enforce proper export permissions, and apply root-squash where appropriate.

### **Finding:** Insecure SNMP Configuration

**Severity:** Medium

**Description:**
SNMP was accessible using default or weak community strings.

**Impact:**
Attackers could enumerate system information, users, and services.

**Recommendation:**
Disable SNMP if not required or enforce strong community strings and restrict access via firewall rules.

### **Finding:** Unauthenticated Service Exposure

**Severity:** Critical

**Description:**
A network service was accessible without authentication.

**Impact:**
Attackers could directly execute commands or access sensitive data.

**Recommendation:**
Restrict service access to localhost or trusted networks, enforce authentication, and apply firewall rules.

### **Finding:** Anonymous File Transfer Access

**Severity:** Critical

**Description:**
Anonymous login allowed file uploads into a web-accessible directory.

**Impact:**
Attackers could upload malicious files and gain remote code execution.

**Recommendation:**
Disable anonymous access, separate file transfer directories from web roots, and monitor file transfer activity.

---

## 4. Web Application Vulnerabilities

### **Finding:** Database Command Execution via xp_cmdshell

**Severity:** High

**Description:**
The database service allowed execution of operating system commands through functionality such as `xp_cmdshell`.

**Impact:**
Attackers could execute arbitrary system commands, potentially leading to full system compromise.

**Recommendation:**
Disable `xp_cmdshell`, restrict database permissions, and ensure database services run with minimal privileges.

### **Finding:** Insecure File Upload Mechanism via FTP

**Severity:** High

**Description:**
Authenticated FTP users were able to upload arbitrary files to a web-accessible directory.

**Impact:**
Attackers could upload web shells and achieve remote code execution.

**Recommendation:**
Validate uploaded files, restrict executable file types, and disable execution in upload directories.

### **Finding:** Directory Traversal Leading to Arbitrary File Read

**Severity:** Critical

**Description:**
The application was vulnerable to directory traversal, allowing attackers to access arbitrary files on the system.

**Impact:**
Attackers could read sensitive files such as configuration files, credentials, and SSH keys.

**Recommendation:**
Sanitize user input, enforce strict path validation, and restrict file access to intended directories only.

### **Finding:** SQL Injection Leading to Operating System Command Execution

**Severity:** Critical

**Description:**
The application was vulnerable to SQL injection, allowing attackers to manipulate database queries and leverage database functionality to execute operating system commands.

**Impact:**
Attackers could achieve remote code execution on the underlying system, potentially as a highly privileged user, resulting in full system compromise.

**Recommendation:**
Use parameterized queries and prepared statements, restrict database privileges, ensure database and application services do not run with elevated privileges, and apply security patches to vulnerable software.

### **Finding:** Arbitrary File Write via Database Service

**Severity:** Critical

**Description:**
The database service (e.g., MySQL) permitted writing files to the server filesystem, including web-accessible directories.

**Impact:**
Attackers could upload malicious files such as web shells and achieve remote code execution.

**Recommendation:**
Restrict FILE privileges, prevent database services from writing to web directories, and enforce least-privilege access controls.

### **Finding:** Server-Side Request Forgery (SSRF)

**Severity:** High

**Description:**
The application allowed user-controlled HTTP requests to be forwarded to internal or external services without proper validation.

**Impact:**
Attackers could access internal services not exposed externally, potentially leading to sensitive data exposure or further exploitation.

**Recommendation:**
Validate and restrict outbound requests, implement allowlists for permitted destinations, and disable or secure request forwarding functionality.

### **Finding:** NoSQL Injection in Authentication

**Severity:** Critical

**Description:**
The application login functionality was vulnerable to NoSQL injection, allowing attackers to manipulate backend queries using MongoDB operators such as `$regex` and `$ne`.

**Impact:**
Attackers could bypass authentication mechanisms and extract valid user credentials.

**Recommendation:**
Sanitize and validate all user input, implement strict query validation, use parameterized queries, and avoid directly passing user-controlled input into database queries.

### **Finding:** Credential Exposure via Application Logic

**Severity:** High

**Description:**
The application returned differential responses during authentication attempts, allowing attackers to brute force credentials.

**Impact:**
Attackers could enumerate valid usernames and passwords, leading to unauthorized access.

**Recommendation:**
Implement account lockout policies, enforce rate limiting, and use consistent error messages for authentication failures.

### **Finding:** Command Injection

**Severity:** Critical

**Description:**
A web-based diagnostic tool executed system commands using unsanitized user input.

**Impact:**
Attackers could execute arbitrary commands on the server, potentially leading to full system compromise.

**Recommendation:**
Validate and sanitize user input, avoid passing user input directly to system command execution functions, and restrict commands to predefined safe operations.

### **Finding:** SQL Injection Vulnerability

**Severity:** Critical

**Description:**
The application login form was vulnerable to SQL injection, allowing attackers to manipulate backend database queries.

**Impact:**
Attackers could bypass authentication controls, retrieve sensitive data, or modify database contents.

**Recommendation:**
Use prepared statements and parameterized queries, implement input validation, and avoid directly embedding user input in SQL queries.

### **Finding:** WebDAV Authenticated File Upload Enabled

**Severity:** Critical

**Description:**
The WebDAV service allowed authenticated users to upload arbitrary files to the IIS web root using the HTTP PUT method.

**Impact:**
Attackers could upload malicious files and achieve remote code execution on the server.

**Recommendation:**
Disable WebDAV if not required, restrict the HTTP PUT method, and enforce secure upload directory controls with execution restrictions.

### **Finding:** Broken Access Control in API Endpoint

**Severity:** High

**Description:**
An API endpoint lacked proper authorization checks, allowing unauthorized users to access restricted functionality.

**Impact:**
Attackers could perform privileged actions or access sensitive data without proper authentication.

**Recommendation:**
Implement proper access control checks on all API endpoints and enforce role-based access control.

### **Finding:** Insecure File Permissions on Web Root

**Severity:** High

**Description:**
The web root directory or application files were writable by a low-privileged user.

**Impact:**
Attackers could modify web content or upload malicious scripts, leading to remote code execution.

**Recommendation:**
Restrict write permissions on web directories and enforce least-privilege access controls.

### **Finding:** Backup or Archive Files Exposed on Web Server

**Severity:** High

**Description:**
Backup or archive files containing sensitive data were accessible through the web server.

**Impact:**
Attackers could retrieve credentials, source code, or configuration files.

**Recommendation:**
Remove backup files from web-accessible directories and enforce strict access controls.

### **Finding:** Information Disclosure via Directory Listing

**Severity:** Medium

**Description:**
Directory listing was enabled on a web server, exposing sensitive files and internal structure.

**Impact:**
Attackers could identify sensitive files, credentials, or application components.

**Recommendation:**
Disable directory listing and restrict access to sensitive directories.

### **Finding:** Hardcoded Credentials in Web Application

**Severity:** High

**Description:**
Credentials were embedded directly within application code or client-side responses.

**Impact:**
Attackers could extract credentials and gain unauthorized access.

**Recommendation:**
Remove hardcoded credentials and use secure configuration or secret management solutions.

### **Finding:** Arbitrary File Upload

**Severity:** Critical

**Description:**
The web application allowed uploading executable files.

**Impact:**
Attackers could gain remote code execution.

**Recommendation:**
Enforce strict file-type validation, disable execution in upload directories, and apply secure coding practices.

### **Finding:** Local or Remote File Inclusion

**Severity:** Critical

**Description:**
User-controlled input was used in file inclusion operations.

**Impact:**
Attackers could read sensitive files or execute code.

**Recommendation:**
Validate all file paths, implement allowlists, and disable dynamic inclusion where unnecessary.

### **Finding:** Directory Traversal

**Severity:** Critical

**Description:**
User input allowed access to unintended file paths.

**Impact:**
Sensitive system files could be disclosed.

**Recommendation:**
Sanitize user input, enforce fixed directory paths, and reject traversal sequences.

### **Finding:** Command Injection

**Severity:** Critical

**Description:**
User-controlled input was executed as system commands.

**Impact:**
Attackers could execute arbitrary commands on the system.

**Recommendation:**
Validate and sanitize inputs, avoid direct shell execution, and use parameterized commands.

---

## 5. Misconfigured Privileges and Sudo Rights

### **Finding:** Token Impersonation Privilege Allowing SYSTEM Escalation

**Severity:** Critical

**Description:**
The system permitted exploitation of token impersonation privileges (e.g., SeImpersonatePrivilege), enabling escalation through known techniques such as Juicy Potato.

**Impact:**
Attackers could escalate privileges to SYSTEM and fully compromise the host.

**Recommendation:**
Apply security patches, restrict high-risk privileges, and ensure services run with least privilege.

### **Finding:** Misconfigured Sudo Permissions Allowing Privileged Execution

**Severity:** Critical

**Description:**
A user was permitted to execute a service or application (e.g., Cassandra Web) with root privileges via sudo without restrictions.

**Impact:**
Attackers could escalate privileges to root and fully compromise the system.

**Recommendation:**
Remove unnecessary sudo permissions, restrict execution to required commands only, and enforce least-privilege principles.

### **Finding:** SeImpersonatePrivilege Assigned to Service Account

**Severity:** Critical

**Description:**
A service account possessed the SeImpersonatePrivilege privilege, allowing token impersonation attacks.

**Impact:**
Attackers could exploit token impersonation techniques to escalate privileges to SYSTEM.

**Recommendation:**
Remove unnecessary impersonation privileges, harden service account permissions, and monitor for abnormal privilege usage.

### **Finding:** Insecure Sudo Configuration Allowing Shell Escape via systemctl Pager

**Severity:** Critical

**Description:**
A user was permitted to execute `systemctl` via sudo, which invoked a pager allowing shell escape.

**Impact:**
Attackers could exploit the pager functionality to spawn a root shell and achieve full system compromise.

**Recommendation:**
Restrict sudo permissions to only required commands, disable pager invocation where possible, and avoid allowing commands that enable interactive shell escape.

### **Finding:** Insecure Sudo Configuration Allowing Shell Escape via Pager

**Severity:** Critical

**Description:**
A user was permitted to execute a binary (e.g., `redis-status`) via sudo that invoked a pager, allowing shell escape.

**Impact:**
Attackers could exploit the pager functionality to spawn a root shell and achieve full system compromise.

**Recommendation:**
Remove unnecessary sudo privileges, disable pager invocation or sanitize the execution environment, and avoid granting sudo access to binaries capable of shell escape.

### **Finding:** Insecure Sudo Configuration Allowing Arbitrary Command Execution

**Severity:** Critical

**Description:**
A user was allowed to execute a privileged binary via sudo without restrictions.

**Impact:**
Attackers could leverage the binary to execute commands as root and achieve full system compromise.

**Recommendation:**
Remove unnecessary sudo privileges, restrict execution of privileged binaries, and enforce least-privilege access controls.

### **Finding:** Insecure Sudo Configuration Allowing Shell Escape via Binary

**Severity:** Critical

**Description:**
A user was permitted to execute a binary via sudo that allowed shell escape or arbitrary command execution.

**Impact:**
Attackers could exploit the binary to execute commands as root and fully compromise the system.

**Recommendation:**
Avoid granting sudo access to binaries capable of shell execution, restrict sudo permissions to required commands only, and enforce least-privilege policies.

### **Finding:** Insecure SUID Binary Allowing Arbitrary File Write

**Severity:** Critical

**Description:**
A binary was configured with SUID permissions and allowed arbitrary file write operations with elevated privileges.

**Impact:**
Attackers could modify sensitive system files and escalate privileges to root.

**Recommendation:**
Remove SUID permissions from unnecessary binaries, restrict execution of interpreters with elevated privileges, and audit SUID binaries regularly.

### **Finding:** SeLoadDriverPrivilege Assigned to Non-Administrator Account

**Severity:** Critical

**Description:**
A non-administrative user possessed the SeLoadDriverPrivilege privilege, allowing the loading of arbitrary drivers.

**Impact:**
Attackers could exploit this privilege to execute code at the SYSTEM level and fully compromise the host.

**Recommendation:**
Restrict SeLoadDriverPrivilege to trusted administrators only, review privilege assignments regularly, and enforce the principle of least privilege.

### **Finding:** SeRestorePrivilege Assigned to Non-Administrator Account

**Severity:** Critical

**Description:**
A non-administrative user account possessed the SeRestorePrivilege privilege, allowing modification of protected system files.

**Impact:**
Attackers could abuse this privilege to replace protected files and escalate privileges to SYSTEM.

**Recommendation:**
Restrict SeRestorePrivilege to administrative accounts only, review user privilege assignments regularly, and enforce the principle of least privilege.

### **Finding:** SeImpersonatePrivilege Assigned to Service Account

**Severity:** Critical

**Description:**
A service account possessed the SeImpersonatePrivilege privilege, allowing token impersonation attacks.

**Impact:**
Attackers could exploit token impersonation techniques to escalate privileges to SYSTEM.

**Recommendation:**
Harden service account privileges, remove unnecessary impersonation rights, apply Microsoft privilege hardening guidance, and monitor for abnormal token impersonation activity.

### **Finding:** Improperly Configured SUID Binary Allowing Arbitrary Backups

**Severity:** Critical

**Description:**
A SUID binary allowed low-privileged users to perform backup operations with elevated privileges, enabling arbitrary command execution.

**Impact:**
Attackers could exploit the SUID binary to escalate privileges to root.

**Recommendation:**
Remove unnecessary SUID permissions, restrict privileged binaries, and enforce least-privilege principles.

### **Finding:** Insecure Command Execution via MongoDB Scheduler

**Severity:** Critical

**Description:**
A scheduled task executed user-controlled commands through a MongoDB-backed scheduler, allowing arbitrary command execution with elevated privileges.

**Impact:**
Attackers could execute arbitrary commands and escalate privileges to root or SYSTEM.

**Recommendation:**
Sanitize and validate all scheduler commands, restrict MongoDB access, and enforce least-privilege execution for scheduled tasks.

### **Finding:** Sudo Rights on Dangerous Binaries

**Severity:** Critical

**Description:**
A user was permitted to execute dangerous binaries via sudo that allowed shell escape or arbitrary command execution.

**Impact:**
Attackers could escalate privileges to root.

**Recommendation:**
Restrict sudo access to only required binaries and avoid allowing interactive or shell-capable programs.

### **Finding:** SUID Binary Allowing Privilege Escalation

**Severity:** Critical

**Description:**
A SUID binary was present that allowed execution of commands with elevated privileges.

**Impact:**
Attackers could exploit the binary to escalate privileges to root.

**Recommendation:**
Remove unnecessary SUID permissions and audit privileged binaries regularly.

### **Finding:** PATH Environment Variable Abuse

**Severity:** High

**Description:**
A privileged script or binary relied on the system PATH and executed commands without absolute paths.

**Impact:**
Attackers could place malicious binaries in writable directories to escalate privileges.

**Recommendation:**
Use absolute paths in privileged scripts and restrict write access to directories in the PATH.

### **Finding:** Misconfigured Sudo Permissions

**Severity:** Critical

**Description:**
A user was allowed to execute privileged commands via sudo without a password.

**Impact:**
Attackers could escalate privileges to root.

**Recommendation:**
Remove unnecessary NOPASSWD entries and enforce least-privilege sudo policies.

### **Finding:** Excessive Token or Service Privileges

**Severity:** High

**Description:**
A service account possessed high-risk privileges such as token impersonation rights.

**Impact:**
Attackers could escalate privileges through token impersonation.

**Recommendation:**
Restrict high-risk privileges and assign only required permissions to service accounts.

---

## 6. Writable Files, Services, or Scheduled Tasks

### **Finding:** Vulnerable File Processing in Privileged Scheduled Task

**Severity:** Critical

**Description:**
A scheduled task executed a file-processing utility (e.g., ExifTool) on user-controlled files without proper validation.

**Impact:**
Attackers could craft malicious files to trigger command execution with elevated privileges, leading to root compromise.

**Recommendation:**
Update vulnerable utilities, avoid processing untrusted files with privileged tasks, and validate or isolate input before execution.

### **Finding:** Insecure Cron Job Processing User-Controlled Input

**Severity:** High

**Description:**
A cron job running with elevated privileges processed files from a user-accessible or web-exposed directory.

**Impact:**
Attackers could manipulate input files to achieve privilege escalation.

**Recommendation:**
Avoid executing privileged tasks on user-controlled input, restrict directory permissions, and validate all inputs processed by scheduled tasks.

### **Finding:** Insecure Cron Job Privilege Escalation

**Severity:** Critical

**Description:**
A cron job executed a script that was writable by a lower-privileged user.

**Impact:**
Attackers could modify the script to execute arbitrary commands with root privileges.

**Recommendation:**
Ensure scripts executed by privileged cron jobs are owned by root and not writable by other users.

### **Finding:** Writable Configuration File Used by Privileged Service

**Severity:** Critical

**Description:**
A configuration file used by a privileged service was writable by a low-privileged user.

**Impact:**
Attackers could modify the configuration to execute malicious commands with elevated privileges.

**Recommendation:**
Restrict write permissions on service configuration files and enforce least-privilege access.

### **Finding:** Writable Service Executable

**Severity:** Critical

**Description:**
A service executable or configuration was writable by a low-privileged user.

**Impact:**
Attackers could replace the executable and gain elevated privileges.

**Recommendation:**
Restrict write permissions on service binaries and enforce least-privilege access controls.

### **Finding:** Writable Script Executed by Root

**Severity:** Critical

**Description:**
A user had write access to a script executed by a privileged account.

**Impact:**
Attackers could inject commands and gain root access.

**Recommendation:**
Ensure privileged scripts are owned by root, remove write permissions for other users, and monitor file integrity.

### **Finding:** Writable Scheduled Task or Service Binary

**Severity:** Critical

**Description:**
A scheduled task or service executed files from writable directories.

**Impact:**
Attackers could replace binaries and escalate privileges.

**Recommendation:**
Restrict write access to service paths, apply least-privilege permissions, and monitor scheduled tasks.

---

## 7. Kernel or OS Privilege Escalation

### **Finding:** Vulnerable Local Service Allowing Privilege Escalation

**Severity:** High

**Description:**
A locally installed service contained a known vulnerability (such as a buffer overflow) that could be exploited by a low-privileged user.

**Impact:**
Attackers could exploit the vulnerable service to escalate privileges to Administrator or SYSTEM.

**Recommendation:**
Update or remove the vulnerable service, apply available security patches, and implement exploit mitigation mechanisms such as DEP and ASLR.

### **Finding:** Unquoted Service Path

**Severity:** High

**Description:**
A Windows service used an unquoted service path containing spaces.

**Impact:**
Attackers could place malicious executables in the path and gain SYSTEM privileges.

**Recommendation:**
Quote all service paths and restrict write permissions on service directories.

### **Finding:** Misconfigured Windows Service Permissions

**Severity:** High

**Description:**
A Windows service allowed modification by low-privileged users.

**Impact:**
Attackers could alter service configuration to execute code as SYSTEM.

**Recommendation:**
Restrict service permissions and audit service configurations regularly.

### **Finding:** Local Kernel Exploit

**Severity:** High

**Description:**
The operating system contained a vulnerable kernel component.

**Impact:**
Attackers could escalate privileges to root or SYSTEM.

**Recommendation:**
Apply all security patches, upgrade to a supported OS version, and implement a patch management program.

---

## 8. Insecure Development or Administrative Interfaces

### **Finding:** Application Exposed in Configuration Mode Without Authentication

**Severity:** Critical

**Description:**
An application (e.g., PWM) was exposed in configuration mode without authentication, allowing modification of backend settings.

**Impact:**
Attackers could manipulate LDAP configurations and capture credentials, potentially leading to domain compromise.

**Recommendation:**
Disable configuration mode in production environments, enforce authentication for administrative interfaces, and restrict access to trusted users.

### **Finding:** Exposed Development or Administrative Interface

**Severity:** High

**Description:**
A development or administrative interface was publicly accessible.

**Impact:**
Attackers could execute commands or access sensitive functionality.

**Recommendation:**
Remove development tools from production, require authentication, and restrict access via network controls.

---

## 9. Insecure Internal Service Exposure

### **Finding:** Weak Access Control in SSH Configuration

**Severity:** Medium

**Description:**
SSH configuration allowed insufficient access restrictions, enabling unintended lateral movement between user accounts.

**Impact:**
Attackers could reuse credentials to pivot between accounts and escalate privileges.

**Recommendation:**
Enforce strict SSH access controls, restrict user login permissions, and prevent credential reuse across accounts.

### **Finding:** Insecure Internal Service Exposure

**Severity:** High

**Description:**
An internal service was exposed without proper access controls or authentication mechanisms.

**Impact:**
Attackers could interact with the service to enumerate functionality, access sensitive data, or exploit it for privilege escalation or lateral movement.

**Recommendation:**
Restrict access to internal services using firewall rules, enforce authentication, and limit exposure to trusted users or networks only.

### **Finding:** Internal Service Accessible via Port Forwarding

**Severity:** High

**Description:**
Internal services were accessible through SSH tunneling or port forwarding.

**Impact:**
Attackers could reach privileged services and escalate access.

**Recommendation:**
Restrict SSH port forwarding, enforce access controls, and monitor tunneling activity.

---

## 10. Weak SMB or NTLM Security

### **Finding:** NTLM Authentication Exposure via SMB Share

**Severity:** High

**Description:**
Users accessing files within the SMB share triggered NTLM authentication attempts that could be captured by attacker-controlled infrastructure.

**Impact:**
Attackers could capture NTLM authentication hashes and attempt relay or offline cracking attacks to gain unauthorized access.

**Recommendation:**
Disable NTLM authentication where possible, enforce SMB signing, and restrict outbound SMB connections to prevent credential relay attacks.

### **Finding:** SMBv1 Enabled

**Severity:** High

**Description:**
The system supported the legacy SMBv1 protocol.

**Impact:**
SMBv1 is vulnerable to multiple remote code execution and relay attacks.

**Recommendation:**
Disable SMBv1 and enforce modern SMB protocols with signing enabled.

### **Finding:** Weak SMB or NTLM Configuration

**Severity:** High

**Description:**
SMB signing or secure authentication was not enforced.

**Impact:**
Attackers could perform relay or pass-the-hash attacks.

**Recommendation:**
Enforce SMB signing, disable NTLM where possible, and implement credential protection mechanisms.

---

## 11. Sensitive Data Exposure

### **Finding:** Sensitive Configuration File Exposure (.htpasswd)

**Severity:** High

**Description:**
A `.htpasswd` file containing hashed credentials was publicly accessible.

**Impact:**
Attackers could retrieve password hashes and perform offline cracking to gain unauthorized access.

**Recommendation:**
Restrict access to sensitive configuration files, ensure proper file permissions, and prevent exposure of authentication data.

### **Finding:** Credential Exposure in Log Files

**Severity:** Critical

**Description:**
Sensitive credentials were stored in plaintext within application or system log files.

**Impact:**
Attackers could retrieve credentials from logs and use them to escalate privileges or access additional services.

**Recommendation:**
Sanitize logs to prevent storage of sensitive information, restrict access to log files, and implement secure credential handling practices.

### **Finding:** Credential Exposure in Backup Files

**Severity:** Critical

**Description:**
Sensitive credentials were stored in plaintext within backup database files accessible to unauthorized users.

**Impact:**
Attackers could recover valid credentials through offline analysis and gain unauthorized access to systems or services.

**Recommendation:**
Encrypt sensitive data within backups, restrict access to backup storage locations, and implement secure backup handling procedures.

### **Finding:** Exposed Backup Files Containing Password Hashes

**Severity:** High

**Description:**
Sensitive backup files containing password hashes were accessible to unauthorized users.

**Impact:**
Attackers could retrieve the hashes and perform offline cracking to recover valid credentials.

**Recommendation:**
Restrict access to backup directories, encrypt sensitive data at rest, and ensure backups are stored securely.

### **Finding:** Credential Leakage via Device or Service Configuration

**Severity:** Critical

**Description:**
Service credentials were exposed within device or service configuration files (e.g., printer configuration).

**Impact:**
Attackers could retrieve credentials and escalate privileges to a higher-privileged service account.

**Recommendation:**
Remove credentials from configuration files, use secure credential storage mechanisms, and restrict access to sensitive configuration data.

### **Finding:** Credential Exposure via Application Logs

**Severity:** High

**Description:**
Sensitive usernames and operational data were exposed through publicly accessible application logs.

**Impact:**
Attackers could enumerate valid user accounts and identify potential attack paths.

**Recommendation:**
Restrict access to log files, sanitize sensitive information from logs, and implement proper logging and access control policies.

### **Finding:** PowerShell Transcripts Containing Credentials

**Severity:** High

**Description:**
PowerShell transcript logs contained administrative commands with plaintext credentials.

**Impact:**
Attackers with access to the transcript logs could retrieve credentials and potentially escalate privileges or move laterally within the environment.

**Recommendation:**
Avoid executing commands containing plaintext credentials, restrict access to PowerShell transcript logs, and implement secure credential storage mechanisms.

### **Finding:** Sensitive Active Directory Database Files Exposed via SMB Share

**Severity:** Critical

**Description:**
An SMB share exposed sensitive Active Directory database files, including NTDS.dit and registry hive files.

**Impact:**
Attackers could download the files and extract domain password hashes, potentially leading to full domain compromise.

**Recommendation:**
Restrict SMB share permissions to authorized administrators only, store backups in secured locations, and monitor file shares for exposure of sensitive Active Directory data.

### **Finding:** Group Policy Preference Password Exposure

**Severity:** Critical

**Description:**
Group Policy Preferences stored credentials using a reversible encryption method with a publicly known key, allowing password recovery.

**Impact:**
Attackers could extract and decrypt stored credentials, potentially gaining administrative access to the domain.

**Recommendation:**
Remove all Group Policy Preference passwords, implement LAPS or gMSA accounts, and audit SYSVOL and replication permissions.

### **Finding:** Sensitive Data Stored Insecurely

**Severity:** High

**Description:**
Sensitive files or credentials were stored in accessible locations.

**Impact:**
Attackers could retrieve confidential data and escalate privileges.

**Recommendation:**
Restrict file permissions, use centralized secret storage, and conduct regular audits.

---

## 12. Active Directory Weaknesses

### **Finding:** Excessive Privileges Allowing Password Reset via RPC

**Severity:** Critical

**Description:**
Users were granted excessive privileges that allowed them to reset passwords of other accounts via RPC or directory services.

**Impact:**
Attackers could reset passwords of privileged users, leading to privilege escalation and lateral movement.

**Recommendation:**
Restrict permissions on user management operations, review delegated privileges, and enforce least-privilege access controls.

### **Finding:** Vulnerable Active Directory Certificate Services Configuration (ESC1)

**Severity:** Critical

**Description:**
A certificate template allowed user-controlled subject alternative names (e.g., UPN), enabling abuse of Active Directory Certificate Services (ADCS).

**Impact:**
Attackers could request certificates impersonating privileged users such as Administrator, leading to full domain compromise.

**Recommendation:**
Restrict enrollment permissions on certificate templates, remove vulnerable templates, and audit ADCS configurations for misconfigurations.

### **Finding:** Excessive Machine Account Creation Privileges

**Severity:** Medium

**Description:**
Domain users were permitted to create machine accounts due to a non-restricted machine account quota.

**Impact:**
Attackers could create controlled machine accounts and leverage them in delegation or certificate-based attacks.

**Recommendation:**
Set `ms-DS-MachineAccountQuota` to 0 if not required and restrict machine account creation to authorized administrators only.

### **Finding:** Vulnerable Active Directory Certificate Services Configuration (ESC1)

**Severity:** Critical

**Description:**
A certificate template allowed user-controlled subject alternative names (e.g., UPN), enabling abuse of Active Directory Certificate Services (ADCS).

**Impact:**
Attackers could request certificates impersonating privileged users such as Administrator, leading to full domain compromise.

**Recommendation:**
Restrict enrollment permissions on certificate templates, remove vulnerable templates, and audit ADCS configurations for misconfigurations.

### **Finding:** Weak Access Controls Allowing Resource-Based Constrained Delegation Abuse

**Severity:** Critical

**Description:**
Improper access controls within Active Directory allowed a non-privileged group (e.g., "Shared Support Accounts") to modify delegation-related attributes, enabling Resource-Based Constrained Delegation (RBCD) attacks.

**Impact:**
Attackers could configure delegation to impersonate privileged users, including domain administrators, leading to full domain compromise.

**Recommendation:**
Restrict delegation-related permissions to authorized administrators, review group memberships with elevated rights, and regularly audit Active Directory objects for misconfigured access controls.

### **Finding:** SeBackupPrivilege Assigned to Non-Administrator Account

**Severity:** Critical

**Description:**
A non-administrative account possessed the SeBackupPrivilege privilege, allowing access to sensitive system files regardless of file permissions.

**Impact:**
Attackers could abuse this privilege to extract sensitive data such as registry hives or Active Directory database files, leading to credential compromise and privilege escalation.

**Recommendation:**
Remove SeBackupPrivilege from non-administrative accounts, restrict backup privileges to authorized users only, and audit privilege assignments regularly.

### **Finding:** Excessive Delegated Privileges Allowing Password Reset Abuse

**Severity:** Critical

**Description:**
A domain account was granted delegated privileges such as ForceChangePassword over other users, allowing unauthorized password resets.

**Impact:**
Attackers could reset passwords for privileged accounts and gain unauthorized access, potentially leading to domain compromise.

**Recommendation:**
Restrict delegated privileges to only required accounts, review Active Directory ACLs regularly, and enforce the principle of least privilege.

### **Finding:** Privileged DNSAdmins Group Abuse

**Severity:** Critical

**Description:**
Membership in the DNSAdmins group allowed modification of DNS server configuration, enabling attackers to load arbitrary DLLs into the DNS service.

**Impact:**
Attackers could execute malicious code as SYSTEM on the domain controller, leading to full domain compromise.

**Recommendation:**
Limit membership of the DNSAdmins group to authorized administrators, monitor DNS server configuration changes, and implement application whitelisting to prevent unauthorized DLL execution.

### **Finding:** Excessive Delegation Permissions Allowing Resource-Based Constrained Delegation Abuse

**Severity:** Critical

**Description:**
Improper delegation permissions allowed attackers to configure Resource-Based Constrained Delegation (RBCD), enabling impersonation of privileged domain users.

**Impact:**
Attackers could impersonate domain administrators and gain full control of the domain.

**Recommendation:**
Review and restrict delegation permissions, limit machine account creation privileges, and regularly audit Active Directory objects for improper delegation configuration.

### **Finding:** Excessive Privileges Assigned to Service Account

**Severity:** Critical

**Description:**
A service account was granted excessive domain privileges beyond operational requirements.

**Impact:**
Attackers compromising the account could perform privileged actions such as dumping domain secrets or escalating to domain administrator.

**Recommendation:**
Review service account privileges, remove unnecessary rights, and apply the principle of least privilege. Regularly audit privileged group memberships.

### **Finding:** Autologon Credentials Stored in Registry

**Severity:** Critical

**Description:**
Autologon credentials were stored in the Windows registry, allowing retrieval of plaintext service account credentials.

**Impact:**
Attackers with local access could extract credentials and escalate privileges or move laterally within the domain.

**Recommendation:**
Remove stored autologon credentials, disable automatic logon functionality where unnecessary, and implement LAPS or managed service accounts.

### **Finding:** Weak Domain Password Policy

**Severity:** High

**Description:**
The domain password policy allowed weak or easily guessable passwords that could be cracked using common wordlists.

**Impact:**
Attackers could recover user credentials through offline cracking or password spraying, potentially leading to privilege escalation.

**Recommendation:**
Enforce strong password complexity requirements, implement account lockout policies, and monitor for excessive authentication attempts.

### **Finding:** Over-Permissive Account Operators Membership

**Severity:** High

**Description:**
The Account Operators group contained users with excessive privileges, allowing modification of privileged domain groups.

**Impact:**
Attackers could manipulate group memberships and escalate privileges within the domain.

**Recommendation:**
Remove unnecessary users from the Account Operators group, carefully restrict delegated administration, and regularly audit privileged group memberships.

### **Finding:** Excessive Privileges via Exchange Windows Permissions

**Severity:** Critical

**Description:**
Members of the Exchange Windows Permissions group had excessive permissions on the domain object, including the ability to modify ACLs.

**Impact:**
Attackers could grant themselves DCSync rights and extract domain credentials, leading to full domain compromise.

**Recommendation:**
Remove unnecessary WriteDACL permissions on the domain object, audit Exchange-related security groups, and apply the principle of least privilege to delegated administrative roles.

### **Finding:** AS-REP Roastable Service Account

**Severity:** Critical

**Description:**
A service account was configured without Kerberos preauthentication enabled, making it vulnerable to AS-REP roasting attacks.

**Impact:**
Attackers could request authentication material and perform offline password cracking without valid domain credentials, potentially leading to privilege escalation.

**Recommendation:**
Enforce Kerberos preauthentication for all accounts, audit for accounts with the UF_DONT_REQUIRE_PREAUTH flag set, and ensure strong, complex passwords are used for service accounts.

### **Finding:** Kerberoastable Administrator Account

**Severity:** Critical

**Description:**
A highly privileged account had a Service Principal Name (SPN) configured, making it vulnerable to Kerberoasting attacks.

**Impact:**
Attackers could request service tickets, crack the password offline, and gain domain administrator privileges.

**Recommendation:**
Remove SPNs from privileged accounts, use dedicated service accounts, and enforce strong, random passwords.

### **Finding:** Weak Domain Administrator Password

**Severity:** Critical

**Description:**
A domain administrator account used a weak password that was susceptible to offline cracking.

**Impact:**
Attackers could recover the password and gain full control of the domain.

**Recommendation:**
Enforce long, random passwords for privileged accounts, monitor Event ID 4769 for suspicious ticket activity, and implement regular password rotation policies.

### **Finding:** Kerberoastable Service Account

**Severity:** High

**Description:**
A service account had a Service Principal Name (SPN) and could be targeted for Kerberoasting.

**Impact:**
Attackers could extract and crack service account passwords offline.

**Recommendation:**
Use strong, complex passwords for service accounts and rotate them regularly.

### **Finding:** AS-REP Roastable User Account

**Severity:** High

**Description:**
A user account did not require Kerberos preauthentication.

**Impact:**
Attackers could retrieve and crack authentication material offline.

**Recommendation:**
Enable Kerberos preauthentication and enforce strong password policies.

### **Finding:** Excessive Domain Privileges

**Severity:** Critical

**Description:**
A domain account possessed excessive privileges allowing lateral movement or domain compromise.

**Impact:**
Attackers could escalate privileges across the domain.

**Recommendation:**
Apply least-privilege principles and regularly audit group memberships.

---

## 13. Scheduled Task and Service Misconfigurations

### **Finding:** Misconfigured Scheduled Task

**Severity:** Critical

**Description:**
A scheduled task executed with elevated privileges was modifiable by a low-privileged user.

**Impact:**
Attackers could alter the task to execute malicious commands and gain elevated privileges.

**Recommendation:**
Restrict write permissions on scheduled tasks and enforce least-privilege access controls.

### **Finding:** Service Running as Root or SYSTEM with Excessive Permissions

**Severity:** High

**Description:**
A service running with elevated privileges had insecure file or directory permissions.

**Impact:**
Attackers could modify service files and escalate privileges.

**Recommendation:**
Restrict service file permissions and run services with the minimum required privileges.
---

## Ultra-Short Emergency Exam Reference (1-Line Fixes)

- Outdated software → Patch or upgrade.
- Default credentials → Enforce strong passwords.
- Credential exposure → Remove from web paths.
- Anonymous FTP → Disable anonymous access.
- File upload → Validate files, disable execution.
- LFI/RFI → Sanitize input, use allowlists.
- Command injection → Validate input, avoid shell.
- Sudo misconfig → Remove NOPASSWD.
- Writable cron/service → Restrict permissions.
- Kernel exploit → Patch OS.
- Exposed admin interface → Restrict access.
- Unauthenticated service → Require authentication.
- Weak SMB/NTLM → Enforce SMB signing, disable NTLM.

---

## Highest-Probability OSCP Additions (Top 10)

If you only add a few, prioritize these:

- SUID privilege escalation
- Writable service binary
- PATH hijacking
- Credentials in config files
- NFS misconfiguration
- SNMP default community string
- Directory listing disclosure
- Kerberoasting
- AS-REP roasting
- Windows service permission abuse

These appear in a large percentage of OSCP-style machines.
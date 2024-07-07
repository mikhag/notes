


## Examples


** Dictionary **

``` 
#Extract a wordlist
gunzip /usr/share/wordlists/rockyou.gz

#Hash to file
echo  '$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZR' > pass_file

#Lets crack!
john --wordlist=rockyou.txt  pass_file 


```

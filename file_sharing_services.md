
### SMB
En snabb samba-tjänst
```
user@attackerpc$ mkdir share
user@attackerpc$ python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
```     


### HTTP
Create HTTP-server local
```
python3 -m http.server
```
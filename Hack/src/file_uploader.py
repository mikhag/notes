import base64
import re
import win32api
import subprocess
import os
import time
import socket
import platform
import pysftp
import logging
import sys
#import cv2
import shlex
import pprint
import paramiko
from stat import S_ISDIR, S_ISREG


import base64
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from datetime import datetime

root = logging.getLogger()
root.setLevel(logging.DEBUG)

hostname = platform.uname()[1]

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

TMP =  os.getenv('TMP')
ftp = None




class Ftp:
    connection=None

    def __init__(self,host,port,username,password):
        self.hostname = platform.uname()[1]
        if self.connection == None:
            cnopts = pysftp.CnOpts()
            cnopts.hostkeys = None
            self.connection = pysftp.Connection(host,port=port, username=username, password=password,cnopts=cnopts)
     



    def upload_file(self,filename):
        #sftp = MySFTPClient.from_transport(self.connection)
        sftp = self.connection
        sftp.makedirs(hostname,mode=755)
        self.put_r_portable(filename, "/%s"%hostname)
        return True

    def close(self):
        if self.connection != None:
            self.connection.close()

    def put_r_portable(self, localdir, remotedir, preserve_mtime=False):
        sftp = self.connection
        for entry in os.listdir(localdir):
            remotepath = remotedir + "/" + entry
            localpath = os.path.join(localdir, entry)
            if not os.path.isfile(localpath):
                try:
                    sftp.mkdir(remotepath)
                except OSError:     
                    pass
                self.put_r_portable(localpath, remotepath, preserve_mtime)
            else:
                sftp.put(localpath, remotepath, preserve_mtime=preserve_mtime)   

def connect_ftp():
    global ftp
    host = "94.198.43.76"
    port = 56604
    ftp = Ftp(host,port,'ftpupload','foobar32')
    return ftp

if __name__ == '__main__':
    try:

        #cmd = sys.argv
        #cmd.pop(0)

        #pprint.pprint(cmd)
        #sys.exit(0)
        
              
        if ftp==None:
            logging.debug("Trying to connect")
            ftp = connect_ftp()
            
       
        try:
            ftp.upload_file(sys.argv[1])
            print("Uploading file,  source: %s " %(sys.argv[1]))
        except Exception as e:
            print("Failed...(%s)"%e)
            
        ftp.close()            
    except Exception as e:
        logging.debug("Crash :( (%s)"%e)
        ftp.close()
    
        
        

    
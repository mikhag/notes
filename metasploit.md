
### Multi/Handler
1. Open Metasploit with msfconsole
1. Type use multi/handler, and press enter
1. type options
1. 
    - set PAYLOAD \<payload>
    - set LHOST \<listen-address>
    - set LPORT \<listen-port>
1. exploit -j

Notice that, because the multi/handler was originally backgrounded, we needed to use sessions 1 to foreground it again. This worked as it was the only session running. Had there been other sessions active, we would have needed to use sessions to see all active sessions, then use sessions <number> to select the appropriate session to foreground. 

### Windows Exploit finder

multi/recon/local_exploit_suggester
NMAP

Nmap ARP scan
​​nmap -PR -sn 10.10.210.6/24

Nmap ICMP scan (reply)
nmap -PE -sn 10.10.210.6/24

Nmap ICMP scan (timestamp) (type14)
nmap -PP -sn 10.10.210.6/24

Nmap ICMP scan (type17)
nmap -PM -sn 10.10.210.6/24

NMAP TCP-SYN 
nmap -PS80,443,8080 -sn MACHINE_IP/24
NMAP TCP-SYN-ACK 
nmap -PA80,443,8080 -sn MACHINE_IP/24
NMAP UDP-PING 
nmap -PU -sn MACHINE_IP/24
-n = Number, no reverseDNS
-R = resolve reverseDNS even if host is offline

#Scan host for open ports (TCP)
Nmap -sT $HOST

#Scan host for open ports (TCP No ACK)
Nmap -sS $HOST

#Scan host for open ports (UDP)
Nmap -sU $HOST

#Scan host for openports (Ack-SCAN)
nmap -sA 10.10.70.35

#Scan host for openports (TCP-window-scan) (Can find ports behind fw)
nmap -sA 10.10.70.35

#Scan host for versions running on openports
nmap -sV $host

#Guess OS
nmap -sS -O 10.10.179.15


#Scan host for open port (Nullscan) Will respond if port is closed, not if open - work without root
Nmap -sN $HOST

You can control the scan timing using -T<0-5>. -T0 is the slowest (paranoid), while -T5 is the fastest. According to Nmap manual page, there are six templates:
paranoid (0)
sneaky (1)
polite (2)
normal (3)
aggressive (4)
insane (5)

# Diskret sökning
nmap -F -sN 10.10.183.193

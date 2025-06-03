# Network Scanning and Analysis Lab

## Objective
Learn to use network scanning tools to discover hosts, services, and vulnerabilities while understanding the ethical and legal implications.

## Prerequisites
- Understanding of TCP/IP networking
- Basic Linux command line skills
- Virtual lab environment with multiple hosts

## Lab Overview
In this lab, you will:
1. Perform network discovery
2. Conduct port scanning
3. Identify services and versions
4. Analyze network vulnerabilities
5. Understand defensive measures

## Part 1: Network Discovery

### Exercise 1.1: ARP Scanning
Discover hosts on the local network:
```bash
# Using arp-scan
sudo arp-scan -l

# Using nmap
nmap -sn 192.168.1.0/24

# Using netdiscover
sudo netdiscover -r 192.168.1.0/24
```

### Exercise 1.2: ICMP Scanning
```bash
# Ping sweep
nmap -sn -PE 192.168.1.0/24

# Disable ping and use TCP ACK
nmap -sn -PA80,443 192.168.1.0/24

# Timestamp request
nmap -sn -PP 192.168.1.0/24
```

## Part 2: Port Scanning Techniques

### Exercise 2.1: Basic Port Scans
```bash
# TCP SYN scan (stealth scan)
sudo nmap -sS 192.168.1.100

# TCP connect scan
nmap -sT 192.168.1.100

# UDP scan
sudo nmap -sU 192.168.1.100

# Scan specific ports
nmap -p 80,443,22,21,25 192.168.1.100

# Scan port ranges
nmap -p 1-1000 192.168.1.100

# Scan all ports
nmap -p- 192.168.1.100
```

### Exercise 2.2: Advanced Scanning
```bash
# FIN scan (bypass some firewalls)
sudo nmap -sF 192.168.1.100

# Xmas scan
sudo nmap -sX 192.168.1.100

# ACK scan (firewall rule mapping)
sudo nmap -sA 192.168.1.100

# Window scan
sudo nmap -sW 192.168.1.100

# Idle scan (zombie scan)
sudo nmap -sI zombie_host 192.168.1.100
```

## Part 3: Service and Version Detection

### Exercise 3.1: Service Enumeration
```bash
# Version detection
nmap -sV 192.168.1.100

# Aggressive version detection
nmap -sV --version-intensity 9 192.168.1.100

# OS detection
sudo nmap -O 192.168.1.100

# Combined scan
sudo nmap -A 192.168.1.100
```

### Exercise 3.2: Banner Grabbing
```bash
# Using netcat
nc -nv 192.168.1.100 80
HEAD / HTTP/1.0

# Using telnet
telnet 192.168.1.100 25

# Using nmap scripts
nmap -sV --script=banner 192.168.1.100
```

## Part 4: Vulnerability Scanning

### Exercise 4.1: Nmap Scripting Engine (NSE)
```bash
# Run default scripts
nmap -sC 192.168.1.100

# Run specific vulnerability scripts
nmap --script vuln 192.168.1.100

# Check for specific vulnerabilities
nmap --script smb-vuln* 192.168.1.100
nmap --script ssl-heartbleed 192.168.1.100

# HTTP enumeration
nmap --script http-enum 192.168.1.100
```

### Exercise 4.2: OpenVAS/GVM Setup
```bash
# Install OpenVAS
sudo apt update
sudo apt install openvas

# Initialize OpenVAS
sudo gvm-setup

# Check setup
sudo gvm-check-setup

# Start services
sudo gvm-start
```

## Part 5: Network Analysis with Wireshark

### Exercise 5.1: Packet Capture
```bash
# Capture packets with tcpdump
sudo tcpdump -i eth0 -w capture.pcap

# Capture specific traffic
sudo tcpdump -i eth0 port 80 -w http_traffic.pcap

# Read capture file
tcpdump -r capture.pcap
```

### Exercise 5.2: Wireshark Filters
Common display filters:
```
# HTTP traffic
http

# TCP port 443
tcp.port == 443

# IP address
ip.addr == 192.168.1.100

# TCP SYN packets
tcp.flags.syn == 1

# DNS queries
dns.qry.name contains "example"
```

## Part 6: Specialized Scanning Tools

### Exercise 6.1: Web Application Scanning
```bash
# Nikto web scanner
nikto -h http://192.168.1.100

# dirb directory brute force
dirb http://192.168.1.100

# gobuster
gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt
```

### Exercise 6.2: SMB Enumeration
```bash
# Enum4linux
enum4linux -a 192.168.1.100

# smbclient
smbclient -L //192.168.1.100

# nmap SMB scripts
nmap --script smb-enum* 192.168.1.100
```

## Part 7: Defensive Measures

### Exercise 7.1: Detecting Port Scans
Configure detection with iptables:
```bash
# Log port scans
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "NULL scan: "
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "XMAS scan: "
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j LOG --log-prefix "FIN scan: "

# Drop suspicious packets
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
```

### Exercise 7.2: IDS Configuration
Basic Snort rule for port scan detection:
```
alert tcp any any -> $HOME_NET any (msg:"Possible TCP Port Scan"; flags:S; threshold: type both, track by_src, count 10, seconds 60; sid:1000001; rev:1;)
```

## Scanning Best Practices

### Ethical Guidelines:
1. **Always get written permission** before scanning
2. **Understand local laws** regarding port scanning
3. **Document all activities** for accountability
4. **Respect boundaries** - only scan authorized targets
5. **Be responsible** with discovered vulnerabilities

### Scanning Methodology:
1. **Reconnaissance**: Gather information passively
2. **Discovery**: Identify live hosts
3. **Port Scanning**: Find open ports
4. **Service Enumeration**: Identify running services
5. **Vulnerability Assessment**: Check for known issues
6. **Documentation**: Record all findings

## Lab Challenges

### Challenge 1: Stealth Scanning
Perform a complete network scan while:
- Avoiding IDS detection
- Using fragmented packets
- Randomizing scan timing
- Spoofing source addresses

### Challenge 2: Service Fingerprinting
Identify all services running on a target system:
- Without using -sV flag
- Manual banner grabbing only
- Document service versions
- Find non-standard ports

### Challenge 3: Vulnerability Discovery
Find and document vulnerabilities:
- Use multiple scanning tools
- Verify findings manually
- Assess risk levels
- Propose remediation

## Advanced Techniques

### Evasion Methods:
```bash
# Fragmentation
nmap -f 192.168.1.100

# Specify MTU
nmap --mtu 24 192.168.1.100

# Decoy scanning
nmap -D decoy1,decoy2,ME 192.168.1.100

# Timing options (0=paranoid to 5=insane)
nmap -T1 192.168.1.100

# Randomize hosts
nmap --randomize-hosts 192.168.1.0/24
```

### Custom Scripts:
```python
#!/usr/bin/env python3
# Simple port scanner
import socket
import sys

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

# Usage
host = sys.argv[1]
for port in range(1, 1001):
    if scan_port(host, port):
        print(f"Port {port}: Open")
```

## Conclusion
This lab covered essential network scanning techniques:
- Host discovery methods
- Port scanning techniques
- Service identification
- Vulnerability assessment
- Defensive measures

Remember: These tools are powerful and must be used responsibly and legally.

## Additional Resources
- Nmap Documentation
- Wireshark User Guide
- SANS Port Scanning Techniques
- OpenVAS Documentation 
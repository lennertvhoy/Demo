# Lab 1: Basic Network Reconnaissance

## 🎯 Lab Objectives

In this lab, you will:
- Perform network discovery to identify live hosts
- Conduct port scanning to find open services
- Enumerate services to gather version information
- Create a network map of the target environment
- Document findings in a professional manner

## 📋 Prerequisites

- Basic understanding of TCP/IP networking
- Familiarity with Linux command line
- Completed Module 1 & 2 of the course
- Lab environment set up (see below)

## 🔧 Lab Setup

### **Option 1: Local Setup**
```bash
# 1. Install VirtualBox
# 2. Download and import:
#    - Kali Linux (attacker machine)
#    - Metasploitable 2 (target machine)
# 3. Configure network:
#    - Both VMs on same NAT network
#    - Note IP addresses
```

### **Option 2: Online Lab**
- Use TryHackMe room: "Basic Pentesting"
- Or set up free tier AWS instances

## 📝 Exercise 1: Network Discovery

### **Objective**
Identify all live hosts on the target network.

### **Instructions**

1. **Identify your network range**
```bash
# Check your IP address
ip addr show
# or
ifconfig

# Identify the network range (e.g., 192.168.1.0/24)
```

2. **Perform host discovery**
```bash
# Method 1: Ping sweep
nmap -sn 192.168.1.0/24

# Method 2: ARP scan (local network only)
arp-scan -l

# Method 3: More stealthy ping sweep
nmap -sn -PS21,22,25,80,443 192.168.1.0/24
```

3. **Document live hosts**
Create a table of discovered hosts:
| IP Address | Hostname | Notes |
|------------|----------|-------|
| 192.168.1.1 | gateway | Router |
| 192.168.1.100 | target01 | Target machine |

### **Expected Output**
```
Starting Nmap 7.91 ( https://nmap.org )
Nmap scan report for 192.168.1.100
Host is up (0.00032s latency).
Nmap scan report for 192.168.1.105
Host is up (0.00028s latency).
```

## 📝 Exercise 2: Port Scanning

### **Objective**
Identify open ports and services on discovered hosts.

### **Instructions**

1. **Quick TCP scan**
```bash
# Fast scan of common ports
nmap -F 192.168.1.100

# Top 1000 ports
nmap --top-ports 1000 192.168.1.100
```

2. **Comprehensive TCP scan**
```bash
# All TCP ports (slow but thorough)
nmap -p- 192.168.1.100

# Specific port ranges
nmap -p 1-1000,8000-9000 192.168.1.100
```

3. **UDP scan (selected ports)**
```bash
# Common UDP services
nmap -sU --top-ports 20 192.168.1.100
```

4. **Service version detection**
```bash
# Detailed service enumeration
nmap -sV -sC -p 21,22,80,443,3306 192.168.1.100
```

### **Analysis Questions**
- Which ports are open?
- What services are running?
- Are there any unusual ports open?
- Which services might be vulnerable?

## 📝 Exercise 3: Service Enumeration

### **Objective**
Gather detailed information about discovered services.

### **Instructions**

1. **Web Service Enumeration (Port 80/443)**
```bash
# Basic web enumeration
curl -I http://192.168.1.100
whatweb http://192.168.1.100

# Directory enumeration
gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt

# Nikto scan
nikto -h http://192.168.1.100
```

2. **SSH Enumeration (Port 22)**
```bash
# SSH version
nc -nv 192.168.1.100 22

# SSH algorithms
nmap --script ssh2-enum-algos -p 22 192.168.1.100
```

3. **SMB Enumeration (Port 445)**
```bash
# SMB version and shares
smbclient -L //192.168.1.100 -N
enum4linux 192.168.1.100

# Nmap SMB scripts
nmap --script smb-enum-* -p 445 192.168.1.100
```

4. **FTP Enumeration (Port 21)**
```bash
# Check for anonymous access
ftp 192.168.1.100
# Try: anonymous / anonymous@

# Nmap FTP scripts
nmap --script ftp-* -p 21 192.168.1.100
```

## 📝 Exercise 4: OS Fingerprinting

### **Objective**
Identify the operating system of target hosts.

### **Instructions**

```bash
# TCP/IP fingerprinting
nmap -O 192.168.1.100

# Aggressive OS detection
nmap -O --osscan-guess 192.168.1.100

# Combined with version detection
nmap -sV -O 192.168.1.100
```

### **Analysis**
- What OS is the target running?
- What version/kernel?
- How confident is the detection?

## 📝 Exercise 5: Network Mapping

### **Objective**
Create a visual network map of findings.

### **Instructions**

1. **Collect all information**
   - IP addresses
   - Open ports
   - Services and versions
   - OS information

2. **Create network diagram**
```
Internet
    |
[Router/Firewall]
192.168.1.1
    |
    +---[Kali Linux]
    |   192.168.1.50
    |
    +---[Target Server]
        192.168.1.100
        OS: Ubuntu 8.04
        Services:
        - SSH (22): OpenSSH 4.7p1
        - HTTP (80): Apache 2.2.8
        - MySQL (3306): MySQL 5.0.51a
```

3. **Document vulnerabilities**
Based on versions found, research potential vulnerabilities:
- OpenSSH 4.7p1: CVE-XXXX-XXXX
- Apache 2.2.8: Multiple vulnerabilities
- MySQL 5.0.51a: Authentication bypass

## 🚨 Challenge Exercise

### **Advanced Reconnaissance**

Perform a stealthy scan that:
1. Avoids IDS detection
2. Uses decoy addresses
3. Fragments packets
4. Randomizes target order

```bash
# Stealthy scan example
nmap -sS -sV -T2 -f -D RND:5 --randomize-hosts -p 21,22,80,443 192.168.1.0/24
```

## 📊 Lab Report Template

```markdown
# Network Reconnaissance Lab Report

## Executive Summary
Performed network reconnaissance on 192.168.1.0/24 network. Discovered X live hosts with Y total open ports. Identified potential vulnerabilities in outdated services.

## Methodology
- Tool: Nmap 7.91
- Scan types: Ping sweep, TCP SYN scan, Version detection
- Duration: 45 minutes

## Findings

### Host: 192.168.1.100
- **OS**: Ubuntu 8.04 (Hardy)
- **Open Ports**: 
  - 22/tcp - OpenSSH 4.7p1 (protocol 2.0)
  - 80/tcp - Apache httpd 2.2.8
  - 3306/tcp - MySQL 5.0.51a-3ubuntu5

### Vulnerabilities Identified
1. **Outdated SSH Version**
   - Current: OpenSSH 4.7p1
   - Multiple vulnerabilities including CVE-2008-5161
   
2. **Apache Version Disclosure**
   - Server header reveals version information
   - Multiple known vulnerabilities

## Recommendations
1. Update all services to latest versions
2. Implement firewall rules to restrict access
3. Disable version disclosure in service banners
```

## 🎯 Learning Outcomes

After completing this lab, you should be able to:
- ✅ Perform network discovery using multiple techniques
- ✅ Conduct thorough port scans
- ✅ Enumerate services and gather version information
- ✅ Identify potential vulnerabilities based on versions
- ✅ Document findings professionally

## 💡 Tips and Tricks

1. **Speed vs Stealth**: Faster scans are noisier
2. **UDP Scanning**: Much slower than TCP, scan selectively
3. **False Positives**: Verify findings with multiple tools
4. **Documentation**: Take screenshots and save all outputs
5. **Legal**: Only scan networks you own or have permission to test

## 🔍 Troubleshooting

### **Common Issues**

1. **No hosts found**
   - Check network connectivity
   - Verify IP range
   - Try different discovery methods

2. **Scans are too slow**
   - Reduce port range
   - Increase timing template (-T4)
   - Skip DNS resolution (-n)

3. **Permission denied**
   - Run with sudo for SYN scans
   - Check firewall rules

## 📚 Further Reading

- [Nmap Network Scanning Guide](https://nmap.org/book/)
- [SANS Network Penetration Testing](https://www.sans.org/sec560)
- [Nmap Scripting Engine Documentation](https://nmap.org/nsedoc/)

## ✅ Lab Completion Checklist

- [ ] Identified all live hosts
- [ ] Scanned for open ports
- [ ] Enumerated service versions
- [ ] Performed OS fingerprinting
- [ ] Created network diagram
- [ ] Completed lab report
- [ ] Identified 3+ potential vulnerabilities

---

*Congratulations on completing Lab 1! Proceed to Lab 2: Web Application Security Testing* 
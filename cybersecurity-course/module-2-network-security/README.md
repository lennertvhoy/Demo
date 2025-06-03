# Module 2: Network Security

## 📌 Module Overview

Network security is crucial for protecting data as it travels across networks. This module covers network fundamentals, common attack vectors, and defensive technologies used to secure network infrastructure.

## 🎯 Learning Objectives

After completing this module, you will be able to:
- Understand network protocols and the OSI model
- Identify common network-based attacks
- Configure and manage firewalls
- Implement network monitoring with IDS/IPS
- Set up secure communications using VPNs

## 📖 Content

### 1. Network Fundamentals Review

#### **OSI Model**
Understanding the 7 layers:
1. **Physical**: Hardware, cables, signals
2. **Data Link**: Switching, MAC addresses
3. **Network**: Routing, IP addresses
4. **Transport**: TCP/UDP, ports
5. **Session**: Session establishment
6. **Presentation**: Encryption, compression
7. **Application**: HTTP, FTP, SMTP

#### **TCP/IP Model**
Simplified 4-layer model:
1. **Network Access**: Physical + Data Link
2. **Internet**: IP protocol
3. **Transport**: TCP/UDP
4. **Application**: All upper layers

#### **Common Protocols and Ports**
- **HTTP**: Port 80 (unencrypted web)
- **HTTPS**: Port 443 (encrypted web)
- **FTP**: Ports 20/21 (file transfer)
- **SSH**: Port 22 (secure shell)
- **Telnet**: Port 23 (insecure remote access)
- **SMTP**: Port 25 (email sending)
- **DNS**: Port 53 (domain name resolution)
- **RDP**: Port 3389 (remote desktop)

### 2. Common Network Attacks

#### **Reconnaissance Attacks**
- **Port Scanning**: Identifying open ports and services
  - Tools: Nmap, Masscan
  - Types: TCP connect, SYN scan, UDP scan
- **Network Mapping**: Discovering network topology
- **OS Fingerprinting**: Identifying operating systems

#### **Denial of Service (DoS/DDoS)**
- **Volume-based**: Flooding with traffic
  - UDP flood
  - ICMP flood
  - Amplification attacks
- **Protocol attacks**: Exploiting protocol weaknesses
  - SYN flood
  - Ping of death
  - Smurf attack
- **Application layer attacks**
  - HTTP flood
  - Slowloris

#### **Man-in-the-Middle (MITM)**
- **ARP Spoofing**: Poisoning ARP tables
- **DNS Spoofing**: Redirecting DNS queries
- **Session Hijacking**: Stealing session tokens
- **SSL Stripping**: Downgrading HTTPS to HTTP

#### **Sniffing and Eavesdropping**
- **Packet Capture**: Intercepting network traffic
- **Password Sniffing**: Capturing credentials
- **Tools**: Wireshark, tcpdump, Ettercap

### 3. Firewalls

#### **Types of Firewalls**

**1. Packet Filtering Firewalls**
- Examine packet headers
- Work at Network/Transport layers
- Fast but limited functionality
- Example: iptables

**2. Stateful Inspection Firewalls**
- Track connection states
- More intelligent than packet filters
- Can detect protocol anomalies
- Example: pfSense, Cisco ASA

**3. Application Layer Firewalls**
- Deep packet inspection
- Understand application protocols
- Can filter based on content
- Example: WAF (Web Application Firewall)

**4. Next-Generation Firewalls (NGFW)**
- Combine traditional firewall with:
  - IPS capabilities
  - Application awareness
  - User identity integration
  - Advanced threat protection

#### **Firewall Rules Best Practices**
```
1. Default Deny: Block all traffic by default
2. Least Privilege: Only allow necessary traffic
3. Rule Order: Most specific rules first
4. Documentation: Comment all rules
5. Regular Review: Audit rules periodically
```

Example iptables rules:
```bash
# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from specific IP
iptables -A INPUT -p tcp -s 192.168.1.100 --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Drop all other traffic
iptables -A INPUT -j DROP
```

### 4. Intrusion Detection and Prevention Systems (IDS/IPS)

#### **IDS vs IPS**
- **IDS**: Detects and alerts on suspicious activity
- **IPS**: Detects and blocks suspicious activity

#### **Types of IDS/IPS**

**1. Network-based (NIDS/NIPS)**
- Monitor network traffic
- Deployed at network choke points
- Examples: Snort, Suricata

**2. Host-based (HIDS/HIPS)**
- Monitor individual hosts
- Can see encrypted traffic
- Examples: OSSEC, Tripwire

#### **Detection Methods**
- **Signature-based**: Known attack patterns
- **Anomaly-based**: Deviations from baseline
- **Heuristic**: Behavioral analysis

#### **Snort Rule Example**
```
alert tcp any any -> 192.168.1.0/24 80 (msg:"Possible SQL Injection"; content:"union select"; nocase; sid:100001;)
```

### 5. Network Segmentation

#### **Benefits**
- Limit attack surface
- Contain breaches
- Improve performance
- Regulatory compliance

#### **Implementation Methods**

**1. VLANs (Virtual LANs)**
- Logical network separation
- Based on switch port or MAC address
- 802.1Q tagging

**2. DMZ (Demilitarized Zone)**
- Buffer zone between internal and external networks
- Hosts public-facing services
- Dual firewall architecture

**3. Network Zones**
```
Internet → Firewall → DMZ → Firewall → Internal Network
                ↓                              ↓
        Web Servers, Mail            Workstations, DB Servers
```

**4. Zero Trust Architecture**
- Never trust, always verify
- Microsegmentation
- Identity-based access

### 6. VPNs and Secure Communications

#### **VPN Types**

**1. Remote Access VPN**
- Individual users connect to corporate network
- Client-to-site configuration
- Protocols: OpenVPN, IPSec, SSL/TLS

**2. Site-to-Site VPN**
- Connect entire networks
- Router-to-router configuration
- Always-on connectivity

#### **VPN Protocols**

**1. IPSec**
- Network layer security
- Two modes: Transport and Tunnel
- Components: AH (Authentication Header), ESP (Encapsulating Security Payload)

**2. SSL/TLS VPN**
- Application layer security
- Works through web browsers
- Easier firewall traversal

**3. OpenVPN**
- Open-source VPN solution
- Uses SSL/TLS
- Highly configurable

#### **VPN Security Considerations**
- Strong authentication (2FA)
- Encryption strength (AES-256)
- Perfect Forward Secrecy
- DNS leak protection
- Kill switch functionality

### 7. Network Monitoring and Logging

#### **What to Monitor**
- Bandwidth usage
- Connection attempts
- Protocol anomalies
- Geographic anomalies
- Failed authentication

#### **Tools**
- **NetFlow/sFlow**: Traffic flow analysis
- **SIEM**: Security Information and Event Management
- **Packet Capture**: Full packet analysis
- **Log Aggregation**: Centralized logging

#### **Key Metrics**
- Packets per second
- Bandwidth utilization
- Connection count
- Error rates
- Latency

## 🛠️ Practical Exercises

1. **Port Scanning Lab**: Use Nmap to scan a test network
2. **Firewall Configuration**: Set up iptables rules
3. **IDS Setup**: Install and configure Snort
4. **VPN Configuration**: Set up OpenVPN server
5. **Traffic Analysis**: Use Wireshark to analyze packets

## 💡 Key Takeaways

1. Understanding network protocols is fundamental to network security
2. Defense in depth applies to networks through multiple security layers
3. Firewalls are the first line of defense but not sufficient alone
4. IDS/IPS provide visibility into network attacks
5. Network segmentation limits the impact of breaches
6. VPNs protect data in transit but require proper configuration

## 🔗 Additional Resources

- [SANS Network Security Resources](https://www.sans.org/network-security/)
- [Nmap Documentation](https://nmap.org/docs.html)
- [Snort User Manual](https://www.snort.org/documents)
- [pfSense Documentation](https://docs.netgate.com/pfsense/en/latest/)

## ✅ Module Quiz

1. What are the 7 layers of the OSI model?
2. Explain the difference between IDS and IPS
3. What is ARP spoofing and how can it be prevented?
4. Name three types of firewalls and their characteristics
5. What is the purpose of a DMZ in network architecture?

## 🚀 Next Steps

Continue to [Module 3: Web Application Security](../module-3-web-security/) to learn about securing web applications.

---

*Remember: A chain is only as strong as its weakest link. Secure every layer!* 
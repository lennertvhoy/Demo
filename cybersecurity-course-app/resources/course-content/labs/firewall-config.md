# Firewall Configuration Lab

## Objective
Learn how to configure and manage firewalls to protect network infrastructure from unauthorized access and attacks.

## Prerequisites
- Basic understanding of networking concepts (TCP/IP, ports, protocols)
- Familiarity with command line interface
- Access to a Linux system or virtual machine

## Lab Overview
In this lab, you will:
1. Understand firewall types and concepts
2. Configure iptables firewall rules
3. Implement zone-based security policies
4. Test and verify firewall configurations
5. Monitor and log firewall activity

## Part 1: Firewall Fundamentals

### Exercise 1.1: Understanding Firewall Types
**Types of Firewalls:**
1. **Packet Filtering Firewall**: Examines packet headers
2. **Stateful Inspection Firewall**: Tracks connection states
3. **Application Layer Firewall**: Inspects application data
4. **Next-Generation Firewall (NGFW)**: Combines multiple technologies

### Exercise 1.2: Firewall Rules Basics
Understand the components of a firewall rule:
- **Source IP/Network**
- **Destination IP/Network**
- **Protocol** (TCP, UDP, ICMP)
- **Port Numbers**
- **Action** (ALLOW, DROP, REJECT)

## Part 2: iptables Configuration

### Exercise 2.1: Basic iptables Commands
```bash
# View current rules
sudo iptables -L -v -n

# View rules with line numbers
sudo iptables -L -v -n --line-numbers

# Save current rules
sudo iptables-save > firewall-rules.txt

# Restore rules
sudo iptables-restore < firewall-rules.txt
```

### Exercise 2.2: Creating Basic Rules
```bash
# Allow all loopback traffic
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (port 22) from specific IP
sudo iptables -A INPUT -p tcp -s 192.168.1.100 --dport 22 -j ACCEPT

# Allow HTTP and HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Drop all other incoming traffic
sudo iptables -A INPUT -j DROP
```

## Part 3: Advanced Firewall Configuration

### Exercise 3.1: Rate Limiting
Protect against brute force attacks:
```bash
# Limit SSH connections to 3 per minute
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT

# Limit ICMP ping requests
sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
```

### Exercise 3.2: Port Knocking Configuration
Implement a simple port knocking sequence:
```bash
# Create chains for port knocking
sudo iptables -N KNOCKING
sudo iptables -N GATE1
sudo iptables -N GATE2
sudo iptables -N PASSED

# Configure the knocking sequence (7000, 8000, 9000)
sudo iptables -A INPUT -m state --state NEW -p tcp --dport 7000 -m recent --name AUTH1 --set -j DROP
sudo iptables -A INPUT -m state --state NEW -p tcp --dport 8000 -m recent --name AUTH1 --rcheck -m recent --name AUTH2 --set -j DROP
sudo iptables -A INPUT -m state --state NEW -p tcp --dport 9000 -m recent --name AUTH2 --rcheck -m recent --name AUTH3 --set -j DROP
sudo iptables -A INPUT -m state --state NEW -p tcp --dport 22 -m recent --name AUTH3 --rcheck -j ACCEPT
```

## Part 4: Network Address Translation (NAT)

### Exercise 4.1: Configuring SNAT
Source NAT for outgoing connections:
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configure SNAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# For specific source network
sudo iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o eth0 -j SNAT --to-source 203.0.113.5
```

### Exercise 4.2: Configuring DNAT
Destination NAT for incoming connections:
```bash
# Forward external port 8080 to internal web server
sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.10:80

# Allow forwarded traffic
sudo iptables -A FORWARD -p tcp -d 192.168.1.10 --dport 80 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
```

## Part 5: Firewall Testing

### Exercise 5.1: Testing Rules
Test your firewall configuration:
```bash
# Test from another machine
# Allowed connection
nc -zv target-ip 80

# Blocked connection
nc -zv target-ip 23

# Port scan test
nmap -p 1-1000 target-ip
```

### Exercise 5.2: Logging Configuration
Enable logging for debugging and monitoring:
```bash
# Log dropped packets
sudo iptables -A INPUT -j LOG --log-prefix "DROPPED: " --log-level 4
sudo iptables -A INPUT -j DROP

# Log specific rules
sudo iptables -I INPUT -p tcp --dport 22 -j LOG --log-prefix "SSH-ATTEMPT: "

# View logs
sudo tail -f /var/log/syslog | grep "DROPPED:"
```

## Part 6: UFW (Uncomplicated Firewall)

### Exercise 6.1: Basic UFW Configuration
Simpler firewall management with UFW:
```bash
# Enable UFW
sudo ufw enable

# Allow SSH
sudo ufw allow 22/tcp

# Allow from specific IP
sudo ufw allow from 192.168.1.100 to any port 22

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Deny specific port
sudo ufw deny 23/tcp

# Check status
sudo ufw status verbose
```

### Exercise 6.2: UFW Application Profiles
```bash
# List application profiles
sudo ufw app list

# Allow application
sudo ufw allow 'Apache Full'

# Create custom application profile
cat > /etc/ufw/applications.d/mycustomapp << EOF
[MyCustomApp]
title=My Custom Application
description=Custom application firewall profile
ports=8080,8443/tcp
EOF

sudo ufw allow 'MyCustomApp'
```

## Part 7: Firewall Best Practices

### Exercise 7.1: Implementing Defense in Depth
Create a multi-layered firewall strategy:

1. **Perimeter Firewall**: Block unwanted traffic at network edge
2. **Host-based Firewall**: Additional protection on individual systems
3. **Application Firewall**: Protect specific applications
4. **Segmentation**: Separate network zones

### Exercise 7.2: Security Policy Template
```bash
#!/bin/bash
# Firewall Security Policy Script

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Anti-spoofing
iptables -A INPUT -s 10.0.0.0/8 -i eth0 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -i eth0 -j DROP
iptables -A INPUT -s 192.168.0.0/16 -i eth0 -j DROP

# ICMP rate limiting
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j ACCEPT

# Service rules
iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Log dropped packets
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-DROP: "
```

## Lab Challenges

### Challenge 1: Secure Web Server
Configure a firewall for a web server that:
- Allows HTTP/HTTPS from anywhere
- Allows SSH only from management network (192.168.100.0/24)
- Blocks all other incoming traffic
- Logs all connection attempts to SSH

### Challenge 2: DMZ Configuration
Set up a DMZ with:
- Public web server in DMZ
- Database server in internal network
- Allow web server to connect to database
- Block direct internet access to database

### Challenge 3: DDoS Protection
Implement rules to mitigate DDoS attacks:
- Connection rate limiting
- SYN flood protection
- ICMP flood protection
- Invalid packet dropping

## Monitoring and Maintenance

### Firewall Monitoring Tools:
```bash
# Real-time connection tracking
watch -n 1 'netstat -an | grep ESTABLISHED'

# Connection tracking with conntrack
sudo conntrack -L

# iptables packet/byte counters
sudo iptables -L -v -n

# Firewall log analysis
sudo grep "IPT-DROP" /var/log/syslog | awk '{print $9}' | sort | uniq -c | sort -nr
```

## Troubleshooting Guide

### Common Issues:
1. **Locked Out**: Always test rules before applying DROP policy
2. **Rule Order**: Remember iptables processes rules sequentially
3. **State Tracking**: Ensure connection tracking modules are loaded
4. **Persistence**: Save rules to survive reboot

### Debug Commands:
```bash
# Trace packet flow
sudo iptables -t raw -A PREROUTING -p tcp --dport 80 -j TRACE
sudo iptables -t raw -A OUTPUT -p tcp --sport 80 -j TRACE

# Check kernel modules
lsmod | grep nf_conntrack
```

## Conclusion
This lab covered essential firewall configuration skills:
- Basic and advanced iptables rules
- NAT configuration
- Security best practices
- Monitoring and troubleshooting

Remember: A firewall is just one layer of defense. Combine it with other security measures for comprehensive protection.

## Additional Resources
- iptables Tutorial
- UFW Documentation
- SANS Firewall Checklist
- Linux Advanced Routing & Traffic Control 
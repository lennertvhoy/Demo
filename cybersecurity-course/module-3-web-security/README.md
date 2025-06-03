# Module 3: Web Application Security

## 📌 Module Overview

Web applications are prime targets for attackers due to their accessibility and potential for sensitive data exposure. This module covers the OWASP Top 10, common web vulnerabilities, and how to build secure web applications.

## 🎯 Learning Objectives

After completing this module, you will be able to:
- Understand the OWASP Top 10 vulnerabilities
- Identify and exploit common web vulnerabilities (ethically)
- Implement secure coding practices
- Use web application security testing tools
- Design secure authentication and session management

## 📖 Content

### 1. Introduction to Web Application Security

#### **Why Web Applications Are Targeted**
- Publicly accessible
- Often contain sensitive data
- Complex with multiple attack vectors
- Connected to backend systems
- User input handling challenges

#### **Web Application Architecture**
```
[Client Browser] ←→ [Web Server] ←→ [Application Server] ←→ [Database]
      ↓                   ↓                    ↓                 ↓
   HTML/JS            Apache/Nginx         PHP/Python         MySQL
```

### 2. OWASP Top 10 (2021)

#### **A01: Broken Access Control**
**Description**: Failures in enforcing user restrictions

**Common Issues**:
- Accessing unauthorized functionality
- Viewing/editing someone else's account
- Elevation of privilege
- CORS misconfiguration

**Example Attack**:
```
// Vulnerable: Direct object reference
https://example.com/user/profile?id=123
// Attacker changes to:
https://example.com/user/profile?id=456
```

**Prevention**:
- Implement proper access controls
- Use indirect object references
- Verify permissions server-side
- Default deny approach

#### **A02: Cryptographic Failures**
**Description**: Failures related to cryptography that expose sensitive data

**Common Issues**:
- Weak encryption algorithms
- Poor key management
- Transmitting data in clear text
- Using weak hashing for passwords

**Example**:
```python
# Vulnerable: MD5 for password hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# Secure: bcrypt with salt
import bcrypt
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
```

**Prevention**:
- Use strong encryption (AES-256)
- Implement proper key management
- Use HTTPS everywhere
- Strong password hashing (bcrypt, scrypt, Argon2)

#### **A03: Injection**
**Description**: Untrusted data sent to interpreter as part of command/query

**Types**:
- SQL Injection
- NoSQL Injection
- Command Injection
- LDAP Injection
- XPath Injection

**SQL Injection Example**:
```sql
-- Vulnerable code
String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

-- Attack input: ' OR '1'='1' --
-- Resulting query:
SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = ''
```

**Prevention**:
```python
# Use parameterized queries
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))

# Use ORM with parameterized queries
user = User.query.filter_by(username=username, password=password).first()
```

#### **A04: Insecure Design**
**Description**: Missing or ineffective security controls by design

**Examples**:
- No rate limiting on sensitive operations
- Insufficient business logic validation
- Missing security requirements

**Prevention**:
- Threat modeling
- Secure design patterns
- Security requirements in SDLC
- Defense in depth

#### **A05: Security Misconfiguration**
**Description**: Incorrect security settings

**Common Issues**:
- Default configurations
- Unnecessary features enabled
- Error messages revealing information
- Out-of-date software

**Example**:
```apache
# Vulnerable: Directory listing enabled
Options +Indexes

# Secure: Disable directory listing
Options -Indexes
```

**Prevention**:
- Hardening guides
- Minimal platform
- Regular updates
- Security headers

#### **A06: Vulnerable and Outdated Components**
**Description**: Using components with known vulnerabilities

**Example**:
```json
// Vulnerable package.json
{
  "dependencies": {
    "express": "3.0.0",  // Old version with vulnerabilities
    "lodash": "4.17.11"  // CVE-2019-10744
  }
}
```

**Prevention**:
- Component inventory
- Regular updates
- Vulnerability scanning
- Remove unused dependencies

#### **A07: Identification and Authentication Failures**
**Description**: Failures in authentication mechanisms

**Common Issues**:
- Weak passwords allowed
- Credential stuffing
- Session fixation
- Missing MFA

**Secure Implementation**:
```python
# Strong password requirements
def validate_password(password):
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# Implement account lockout
def check_login_attempts(username):
    attempts = get_failed_attempts(username)
    if attempts >= 5:
        lockout_time = get_lockout_time(username)
        if datetime.now() < lockout_time:
            return False
    return True
```

#### **A08: Software and Data Integrity Failures**
**Description**: Code and infrastructure without integrity verification

**Examples**:
- Insecure deserialization
- CI/CD pipeline attacks
- Unsigned updates

**Prevention**:
- Digital signatures
- Integrity checks
- Secure CI/CD
- Input validation for serialized data

#### **A09: Security Logging and Monitoring Failures**
**Description**: Insufficient logging and monitoring

**What to Log**:
```python
# Authentication events
logger.info(f"Successful login: user={username}, ip={ip_address}, timestamp={datetime.now()}")
logger.warning(f"Failed login attempt: user={username}, ip={ip_address}, timestamp={datetime.now()}")

# Access control failures
logger.error(f"Unauthorized access attempt: user={username}, resource={resource}, ip={ip_address}")

# Input validation failures
logger.warning(f"Invalid input detected: user={username}, input_type={input_type}, value={sanitized_value}")
```

**Prevention**:
- Comprehensive logging
- Log management system
- Real-time alerting
- Regular log review

#### **A10: Server-Side Request Forgery (SSRF)**
**Description**: Web application fetches remote resource without validating user-supplied URL

**Example Attack**:
```python
# Vulnerable code
def fetch_url(url):
    return requests.get(url).text

# Attack: fetch_url("http://169.254.169.254/latest/meta-data/")
# Accesses AWS metadata
```

**Prevention**:
```python
# Whitelist allowed domains
ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

def fetch_url_safe(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError("Domain not allowed")
    return requests.get(url).text
```

### 3. Cross-Site Scripting (XSS) Deep Dive

#### **Types of XSS**

**1. Reflected XSS**
```html
<!-- Vulnerable search page -->
<p>You searched for: <?php echo $_GET['query']; ?></p>

<!-- Attack URL -->
https://example.com/search?query=<script>alert('XSS')</script>
```

**2. Stored XSS**
```python
# Vulnerable comment system
comment = request.form['comment']
db.execute("INSERT INTO comments (text) VALUES (?)", (comment,))

# Later displayed without encoding
<div class="comment">{{ comment }}</div>
```

**3. DOM-based XSS**
```javascript
// Vulnerable JavaScript
document.getElementById('welcome').innerHTML = 'Hello ' + location.hash.slice(1);

// Attack URL
https://example.com/#<img src=x onerror=alert('XSS')>
```

#### **XSS Prevention**
```python
# 1. Output encoding
from markupsafe import escape
safe_output = escape(user_input)

# 2. Content Security Policy
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'nonce-{}'".format(nonce)

# 3. Input validation
import bleach
clean_html = bleach.clean(user_html, tags=['p', 'br', 'strong', 'em'])
```

### 4. SQL Injection Deep Dive

#### **Types of SQL Injection**

**1. Classic SQL Injection**
```python
# Vulnerable
query = f"SELECT * FROM products WHERE category = '{category}'"

# Attack: category = "' OR '1'='1"
```

**2. Blind SQL Injection**
```sql
-- Boolean-based blind
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --

-- Time-based blind
' AND IF(1=1, SLEEP(5), 0) --
```

**3. Second-Order SQL Injection**
```python
# First request - store malicious data
username = "admin'--"
db.execute("INSERT INTO users (username) VALUES (?)", (username,))

# Second request - vulnerable usage
query = f"SELECT * FROM messages WHERE recipient = '{username}'"
```

#### **Advanced SQL Injection Prevention**
```python
# 1. Parameterized queries with type checking
def get_user(user_id: int):
    if not isinstance(user_id, int):
        raise ValueError("Invalid user ID type")
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# 2. Stored procedures
cursor.callproc('GetUserById', [user_id])

# 3. Input validation whitelist
ALLOWED_SORT_COLUMNS = ['name', 'date', 'price']
if sort_column not in ALLOWED_SORT_COLUMNS:
    sort_column = 'name'  # default
```

### 5. Authentication and Session Management

#### **Secure Authentication Implementation**

```python
# 1. Secure password storage
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

def verify_password(password, hash):
    return bcrypt.checkpw(password.encode('utf-8'), hash)

# 2. Secure session management
import secrets

def create_session(user_id):
    session_id = secrets.token_urlsafe(32)
    # Store in secure, server-side session store
    redis_client.setex(
        f"session:{session_id}",
        3600,  # 1 hour expiry
        json.dumps({
            'user_id': user_id,
            'created': datetime.now().isoformat(),
            'ip': request.remote_addr
        })
    )
    return session_id

# 3. Multi-factor authentication
import pyotp

def setup_2fa(user):
    secret = pyotp.random_base32()
    # Store encrypted secret
    user.totp_secret = encrypt(secret)
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        user.email, issuer_name="SecureApp"
    )
    return totp_uri

def verify_2fa(user, token):
    totp = pyotp.TOTP(decrypt(user.totp_secret))
    return totp.verify(token, valid_window=1)
```

### 6. Security Headers

```python
# Essential security headers
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response
```

### 7. Web Application Security Testing Tools

#### **Automated Scanners**
- **OWASP ZAP**: Open-source web app scanner
- **Burp Suite**: Comprehensive testing platform
- **Nikto**: Web server scanner
- **SQLMap**: SQL injection testing

#### **Manual Testing Tools**
- **Browser DevTools**: Inspect and modify requests
- **Postman/Insomnia**: API testing
- **CyberChef**: Data encoding/decoding

#### **Code Analysis**
- **SonarQube**: Static code analysis
- **Bandit**: Python security linter
- **ESLint security plugins**: JavaScript security

## 🛠️ Practical Exercises

1. **XSS Challenge**: Find and exploit XSS vulnerabilities in a test app
2. **SQL Injection Lab**: Practice different SQL injection techniques
3. **Authentication Bypass**: Attempt to bypass weak authentication
4. **Security Headers**: Configure proper security headers
5. **OWASP ZAP Scan**: Run automated security scan

## 💡 Key Takeaways

1. Never trust user input - always validate and sanitize
2. Use parameterized queries to prevent injection attacks
3. Implement defense in depth with multiple security layers
4. Keep all components updated and patched
5. Log security events for monitoring and incident response
6. Follow secure coding practices from the start

## 🔗 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [SANS Web Application Security](https://www.sans.org/cyber-security-courses/web-app-security/)

## ✅ Module Quiz

1. What are the three types of XSS attacks?
2. How do parameterized queries prevent SQL injection?
3. What is the difference between authentication and authorization?
4. Name five important security headers and their purposes
5. What are the OWASP Top 3 vulnerabilities in 2021?

## 🚀 Next Steps

Proceed to [Module 4: Cryptography](../module-4-cryptography/) to understand encryption and secure communications.

---

*Remember: Security is not a feature, it's a requirement. Build it in from day one!* 
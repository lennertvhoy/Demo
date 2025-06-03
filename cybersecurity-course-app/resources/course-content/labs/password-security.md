# Password Security Lab

## Objective
Learn about password security best practices and test password strength using various tools.

## Prerequisites
- Basic understanding of cybersecurity concepts
- Access to a terminal/command line

## Lab Overview
In this lab, you will:
1. Analyze password strength
2. Learn about password hashing
3. Implement secure password policies
4. Test password cracking techniques

## Part 1: Password Strength Analysis

### Exercise 1.1: Understanding Password Complexity
Create passwords that meet the following criteria and analyze their strength:

1. **Weak Password**: `password123`
2. **Medium Password**: `P@ssw0rd!2023`
3. **Strong Password**: `kT9$mN2@pQ5!xR8#vL3&`

**Questions:**
- What makes a password strong?
- How does length affect password security?
- Why are special characters important?

### Exercise 1.2: Password Entropy Calculation
Calculate the entropy for different password types:

```
Entropy = log2(number of possible combinations)
```

For a password with:
- Lowercase letters only (26 characters)
- Lowercase + uppercase (52 characters)
- Alphanumeric (62 characters)
- Alphanumeric + special characters (94 characters)

## Part 2: Password Hashing

### Exercise 2.1: Understanding Hash Functions
Learn about common hashing algorithms:

1. **MD5** (deprecated for passwords)
2. **SHA-256** (better but still not ideal for passwords)
3. **bcrypt** (designed for password hashing)
4. **Argon2** (modern password hashing)

### Exercise 2.2: Hashing Demonstration
```python
import hashlib
import bcrypt

# Simple hashing (NOT recommended for passwords)
password = "MySecurePassword123!"
md5_hash = hashlib.md5(password.encode()).hexdigest()
sha256_hash = hashlib.sha256(password.encode()).hexdigest()

print(f"MD5: {md5_hash}")
print(f"SHA-256: {sha256_hash}")

# Proper password hashing with bcrypt
salt = bcrypt.gensalt()
bcrypt_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
print(f"bcrypt: {bcrypt_hash}")
```

## Part 3: Password Policies

### Exercise 3.1: Implementing Password Requirements
Design a password policy that includes:
- Minimum length: 12 characters
- Must contain: uppercase, lowercase, numbers, special characters
- Cannot contain dictionary words
- Cannot reuse last 5 passwords
- Must be changed every 90 days

### Exercise 3.2: Password Policy Validation
```python
import re

def validate_password(password):
    # Check length
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    # Check for uppercase
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    # Check for lowercase
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    # Check for numbers
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    
    # Check for special characters
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets all requirements"

# Test the function
test_passwords = [
    "short",
    "thisisalongpasswordbutnospecialchars",
    "ThisIsAGoodP@ssw0rd!"
]

for pwd in test_passwords:
    valid, message = validate_password(pwd)
    print(f"Password: {pwd[:3]}... - {message}")
```

## Part 4: Password Cracking (Educational Purpose)

### Exercise 4.1: Dictionary Attacks
Understanding how dictionary attacks work:

```python
# Simulated dictionary attack (educational purpose only)
import hashlib

# Common passwords (top 10)
common_passwords = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon"
]

# Target hash (SHA-256 of "password")
target_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

print("Attempting dictionary attack...")
for password in common_passwords:
    hash_attempt = hashlib.sha256(password.encode()).hexdigest()
    if hash_attempt == target_hash:
        print(f"Password found: {password}")
        break
else:
    print("Password not found in dictionary")
```

## Part 5: Best Practices

### Password Management Tips:
1. Use a password manager
2. Enable two-factor authentication (2FA)
3. Use unique passwords for each account
4. Regularly update passwords
5. Avoid personal information in passwords

### Creating Strong Passwords:
1. **Passphrase Method**: Combine random words
   - Example: "correct-horse-battery-staple"
2. **Acronym Method**: Use first letters of a sentence
   - "I love cybersecurity and graduated in 2023!" → "Ilc&gi2023!"
3. **Random Generation**: Use password generators

## Lab Questions

1. Calculate the time it would take to brute-force a 12-character password with:
   - Only lowercase letters
   - Mixed case alphanumeric
   - Full character set (94 characters)

2. Explain why bcrypt is preferred over SHA-256 for password hashing.

3. Design a password policy for a financial institution. What additional measures would you implement?

4. Research and explain what a "rainbow table" is and how salting prevents rainbow table attacks.

## Conclusion
This lab has covered the fundamentals of password security, including:
- Password strength and complexity
- Proper password hashing techniques
- Password policy implementation
- Understanding attack vectors

Remember: The techniques shown for password cracking are for educational purposes only and should never be used maliciously.

## Additional Resources
- NIST Password Guidelines
- OWASP Password Storage Cheat Sheet
- Have I Been Pwned (password breach checking)
- Password manager recommendations 
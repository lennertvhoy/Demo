# Module 4: Cryptography

## 📌 Module Overview

Cryptography is the foundation of information security, providing confidentiality, integrity, and authentication. This module covers encryption fundamentals, cryptographic algorithms, and practical implementations for securing data.

## 🎯 Learning Objectives

After completing this module, you will be able to:
- Understand fundamental cryptographic concepts
- Differentiate between symmetric and asymmetric encryption
- Implement secure hashing and digital signatures
- Understand Public Key Infrastructure (PKI)
- Apply cryptography in real-world scenarios

## 📖 Content

### 1. Introduction to Cryptography

#### **What is Cryptography?**
The practice and study of techniques for secure communication in the presence of adversaries.

#### **Core Cryptographic Goals**
- **Confidentiality**: Keep information secret
- **Integrity**: Detect unauthorized modifications
- **Authentication**: Verify identity
- **Non-repudiation**: Prevent denial of actions

#### **Basic Terminology**
- **Plaintext**: Original message
- **Ciphertext**: Encrypted message
- **Encryption**: Converting plaintext to ciphertext
- **Decryption**: Converting ciphertext to plaintext
- **Key**: Secret parameter for encryption/decryption
- **Algorithm/Cipher**: Method of encryption

### 2. Symmetric Encryption

#### **How It Works**
Same key used for both encryption and decryption.

```
Plaintext → [Encryption with Key K] → Ciphertext
Ciphertext → [Decryption with Key K] → Plaintext
```

#### **Common Symmetric Algorithms**

**1. AES (Advanced Encryption Standard)**
- Block cipher with 128-bit blocks
- Key sizes: 128, 192, or 256 bits
- Most widely used symmetric algorithm

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_aes(plaintext, key):
    # Generate random IV
    iv = os.urandom(16)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # Encrypt
    encryptor = cipher.encryptor()
    
    # Pad plaintext to multiple of 16 bytes
    pad_len = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([pad_len] * pad_len)
    
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return iv + ciphertext  # Prepend IV to ciphertext

def decrypt_aes(ciphertext, key):
    # Extract IV
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # Decrypt
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    
    # Remove padding
    pad_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-pad_len]
    
    return plaintext
```

**2. ChaCha20**
- Stream cipher
- Faster than AES on devices without AES hardware
- Used in TLS 1.3

**3. DES/3DES (Legacy)**
- DES: 56-bit key (insecure)
- 3DES: Applies DES three times
- Should not be used in new systems

#### **Modes of Operation**

**ECB (Electronic Codebook)** - Insecure
```
Block1 → Encrypt → Ciphertext1
Block2 → Encrypt → Ciphertext2
```

**CBC (Cipher Block Chaining)**
```
Block1 ⊕ IV → Encrypt → Ciphertext1
Block2 ⊕ Ciphertext1 → Encrypt → Ciphertext2
```

**GCM (Galois/Counter Mode)**
- Provides both encryption and authentication
- Recommended for most use cases

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_aes_gcm(plaintext, key, associated_data=None):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext

def decrypt_aes_gcm(ciphertext, key, associated_data=None):
    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    actual_ciphertext = ciphertext[12:]
    plaintext = aesgcm.decrypt(nonce, actual_ciphertext, associated_data)
    return plaintext
```

### 3. Asymmetric Encryption

#### **How It Works**
Different keys for encryption and decryption:
- **Public Key**: Can be shared openly
- **Private Key**: Must be kept secret

```
Plaintext → [Encrypt with Public Key] → Ciphertext
Ciphertext → [Decrypt with Private Key] → Plaintext
```

#### **Common Asymmetric Algorithms**

**1. RSA (Rivest-Shamir-Adleman)**
- Based on factoring large primes
- Key sizes: 2048, 3072, 4096 bits
- Slower than symmetric encryption

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generate RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt with RSA
def encrypt_rsa(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Decrypt with RSA
def decrypt_rsa(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
```

**2. Elliptic Curve Cryptography (ECC)**
- Based on elliptic curve mathematics
- Smaller keys for same security (256-bit ECC ≈ 3072-bit RSA)
- Faster than RSA

```python
from cryptography.hazmat.primitives.asymmetric import ec

# Generate ECC key pair
def generate_ecc_keys():
    private_key = ec.generate_private_key(
        ec.SECP256R1(),  # NIST P-256 curve
        default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# ECDH (Elliptic Curve Diffie-Hellman) for key agreement
def perform_ecdh(private_key, peer_public_key):
    shared_key = private_key.exchange(
        ec.ECDH(), 
        peer_public_key
    )
    return shared_key
```

### 4. Hashing

#### **What is Hashing?**
One-way function that produces fixed-size output from arbitrary input.

#### **Properties of Secure Hash Functions**
1. **Deterministic**: Same input always produces same output
2. **One-way**: Cannot derive input from output
3. **Avalanche effect**: Small input change causes large output change
4. **Collision resistant**: Hard to find two inputs with same hash

#### **Common Hash Algorithms**

**1. SHA-256/SHA-3**
```python
import hashlib

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def hash_sha3_256(data):
    return hashlib.sha3_256(data.encode()).hexdigest()
```

**2. BLAKE2**
- Faster than SHA-256
- Variable output size

```python
def hash_blake2b(data, digest_size=32):
    h = hashlib.blake2b(digest_size=digest_size)
    h.update(data.encode())
    return h.hexdigest()
```

**3. MD5/SHA-1 (Deprecated)**
- MD5: Completely broken
- SHA-1: Collision attacks exist
- Never use for security

#### **Password Hashing**
Special algorithms designed for password storage:

```python
import bcrypt
import argon2
from passlib.context import CryptContext

# Bcrypt
def hash_password_bcrypt(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

def verify_password_bcrypt(password, hash):
    return bcrypt.checkpw(password.encode('utf-8'), hash)

# Argon2 (recommended)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password_argon2(password):
    return pwd_context.hash(password)

def verify_password_argon2(password, hash):
    return pwd_context.verify(password, hash)
```

### 5. Digital Signatures

#### **How They Work**
Provide authentication and integrity using asymmetric cryptography:

```
Message → Hash → [Sign with Private Key] → Signature
Message + Signature → [Verify with Public Key] → Valid/Invalid
```

#### **Implementation**

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Generate signature
def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify signature
def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
```

### 6. Message Authentication Codes (MAC)

#### **HMAC (Hash-based MAC)**
Combines hashing with a secret key:

```python
import hmac

def create_hmac(message, key):
    h = hmac.new(key, message.encode(), hashlib.sha256)
    return h.hexdigest()

def verify_hmac(message, key, mac):
    expected_mac = create_hmac(message, key)
    return hmac.compare_digest(mac, expected_mac)
```

### 7. Public Key Infrastructure (PKI)

#### **Components of PKI**

**1. Certificate Authority (CA)**
- Issues and signs certificates
- Trusted third party

**2. Digital Certificates**
- Bind public key to identity
- X.509 standard

**3. Certificate Chain**
```
Root CA → Intermediate CA → End Entity Certificate
```

#### **Working with Certificates**

```python
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

# Generate self-signed certificate
def generate_self_signed_cert(private_key, common_name):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    return cert
```

### 8. TLS/SSL

#### **How TLS Works**
1. **Client Hello**: Client sends supported ciphers
2. **Server Hello**: Server selects cipher, sends certificate
3. **Key Exchange**: Establish shared secret
4. **Finished**: Begin encrypted communication

#### **TLS Best Practices**
- Use TLS 1.2 or 1.3
- Strong cipher suites only
- Valid certificates
- HSTS (HTTP Strict Transport Security)
- Certificate pinning for mobile apps

### 9. Cryptographic Best Practices

#### **Key Management**
```python
# Secure key generation
key = os.urandom(32)  # 256-bit key

# Key derivation from password
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key
```

#### **Common Mistakes to Avoid**
1. **Rolling your own crypto**: Use established libraries
2. **Weak random numbers**: Use cryptographically secure RNG
3. **Key reuse**: Generate new keys/IVs for each operation
4. **Hardcoded keys**: Use key management systems
5. **Outdated algorithms**: Stay current with recommendations

### 10. Practical Applications

#### **File Encryption**
```python
def encrypt_file(filename, key):
    with open(filename, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = encrypt_aes_gcm(plaintext, key)
    
    with open(filename + '.enc', 'wb') as f:
        f.write(ciphertext)
```

#### **Secure Communication**
```python
# Hybrid encryption (RSA + AES)
def hybrid_encrypt(plaintext, recipient_public_key):
    # Generate random AES key
    aes_key = os.urandom(32)
    
    # Encrypt data with AES
    encrypted_data = encrypt_aes_gcm(plaintext, aes_key)
    
    # Encrypt AES key with RSA
    encrypted_key = encrypt_rsa(aes_key, recipient_public_key)
    
    return encrypted_key + encrypted_data
```

## 🛠️ Practical Exercises

1. **Implement AES Encryption**: Build file encryption tool
2. **RSA Key Exchange**: Implement secure message exchange
3. **Password Manager**: Create secure password storage
4. **Digital Signatures**: Sign and verify documents
5. **Certificate Validation**: Verify TLS certificates

## 💡 Key Takeaways

1. Symmetric encryption is fast but requires secure key exchange
2. Asymmetric encryption solves key distribution but is slower
3. Never use broken algorithms (MD5, SHA-1, DES)
4. Proper key management is crucial
5. Use established cryptographic libraries
6. Combine multiple techniques for complete security

## 🔗 Additional Resources

- [Cryptography Engineering (Book)](https://www.schneier.com/books/cryptography-engineering/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Crypto 101 (Free Book)](https://www.crypto101.io/)
- [Khan Academy Cryptography](https://www.khanacademy.org/computing/computer-science/cryptography)

## ✅ Module Quiz

1. What is the main difference between symmetric and asymmetric encryption?
2. Why should MD5 never be used for password hashing?
3. Explain how digital signatures provide non-repudiation
4. What is the purpose of a salt in password hashing?
5. How does PKI establish trust in digital certificates?

## 🚀 Next Steps

Continue to [Module 5: Ethical Hacking](../module-5-ethical-hacking/) to apply your security knowledge in penetration testing.

---

*Remember: Cryptography is a tool, not a solution. Proper implementation is key!* 
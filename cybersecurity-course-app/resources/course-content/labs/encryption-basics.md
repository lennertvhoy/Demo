# Encryption Basics Lab

## Objective
Learn fundamental encryption concepts, implement basic cryptographic algorithms, and understand the difference between symmetric and asymmetric encryption.

## Prerequisites
- Basic programming knowledge (Python preferred)
- Understanding of binary and hexadecimal
- Basic mathematical concepts

## Lab Overview
In this lab, you will:
1. Understand encryption fundamentals
2. Implement classical ciphers
3. Work with modern symmetric encryption
4. Explore asymmetric encryption
5. Practice key management

## Part 1: Classical Ciphers

### Exercise 1.1: Caesar Cipher
Implement a basic Caesar cipher:
```python
def caesar_encrypt(plaintext, shift):
    result = ""
    for char in plaintext:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            result += encrypted_char
        else:
            result += char
    return result

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# Test
plaintext = "HELLO WORLD"
shift = 3
encrypted = caesar_encrypt(plaintext, shift)
print(f"Encrypted: {encrypted}")  # KHOOR ZRUOG
print(f"Decrypted: {caesar_decrypt(encrypted, shift)}")
```

### Exercise 1.2: Vigenère Cipher
```python
def vigenere_encrypt(plaintext, key):
    result = ""
    key_index = 0
    
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)].upper()) - 65
            if char.isupper():
                result += chr((ord(char) - 65 + shift) % 26 + 65)
            else:
                result += chr((ord(char) - 97 + shift) % 26 + 97)
            key_index += 1
        else:
            result += char
    
    return result

def vigenere_decrypt(ciphertext, key):
    decryption_key = ""
    for char in key:
        shift = 26 - (ord(char.upper()) - 65)
        decryption_key += chr(shift + 65)
    return vigenere_encrypt(ciphertext, decryption_key)

# Test
plaintext = "ATTACKATDAWN"
key = "LEMON"
encrypted = vigenere_encrypt(plaintext, key)
print(f"Encrypted: {encrypted}")  # LXFOPVEFRNHR
```

### Exercise 1.3: Frequency Analysis
Break a Caesar cipher using frequency analysis:
```python
import string
from collections import Counter

def frequency_analysis(ciphertext):
    # English letter frequency (approximate)
    english_freq = {
        'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
        'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
        'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
        'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
        'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10,
        'Z': 0.07
    }
    
    # Count letter frequencies in ciphertext
    letters_only = ''.join(filter(str.isalpha, ciphertext.upper()))
    letter_counts = Counter(letters_only)
    total_letters = sum(letter_counts.values())
    
    # Calculate frequencies
    cipher_freq = {}
    for letter, count in letter_counts.items():
        cipher_freq[letter] = (count / total_letters) * 100
    
    # Find likely shift by comparing with English frequencies
    best_shift = 0
    min_difference = float('inf')
    
    for shift in range(26):
        difference = 0
        for letter in string.ascii_uppercase:
            shifted_letter = chr((ord(letter) - 65 - shift) % 26 + 65)
            expected_freq = english_freq.get(letter, 0)
            actual_freq = cipher_freq.get(shifted_letter, 0)
            difference += abs(expected_freq - actual_freq)
        
        if difference < min_difference:
            min_difference = difference
            best_shift = shift
    
    return best_shift

# Test with encrypted message
ciphertext = "WKLV LV D WHVW PHVVDJH"
shift = frequency_analysis(ciphertext)
print(f"Detected shift: {shift}")
print(f"Decrypted: {caesar_decrypt(ciphertext, shift)}")
```

## Part 2: Symmetric Encryption

### Exercise 2.1: XOR Cipher
```python
def xor_encrypt_decrypt(data, key):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key[i % len(key)])
    return bytes(result)

# Test
plaintext = b"Hello, World!"
key = b"SECRET"

encrypted = xor_encrypt_decrypt(plaintext, key)
print(f"Encrypted (hex): {encrypted.hex()}")

decrypted = xor_encrypt_decrypt(encrypted, key)
print(f"Decrypted: {decrypted.decode()}")
```

### Exercise 2.2: AES Encryption
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def aes_encrypt(plaintext, key):
    # Generate random IV
    iv = get_random_bytes(AES.block_size)
    
    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad plaintext and encrypt
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    
    # Return IV + ciphertext
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(encrypted_data, key):
    # Decode from base64
    encrypted_bytes = base64.b64decode(encrypted_data)
    
    # Extract IV and ciphertext
    iv = encrypted_bytes[:AES.block_size]
    ciphertext = encrypted_bytes[AES.block_size:]
    
    # Create cipher and decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Remove padding
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode()

# Test
key = get_random_bytes(32)  # 256-bit key
plaintext = "This is a secret message!"

encrypted = aes_encrypt(plaintext, key)
print(f"Encrypted: {encrypted}")

decrypted = aes_decrypt(encrypted, key)
print(f"Decrypted: {decrypted}")
```

### Exercise 2.3: Different AES Modes
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time

# ECB Mode (insecure for patterns)
def aes_ecb_demo():
    key = get_random_bytes(16)
    plaintext = b"SAME_BLOCK_DATA!" * 4  # Repeated blocks
    
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    
    print("ECB Mode - Notice repeated patterns:")
    for i in range(0, len(ciphertext), 16):
        print(f"Block {i//16}: {ciphertext[i:i+16].hex()}")

# CTR Mode (stream cipher mode)
def aes_ctr_demo():
    key = get_random_bytes(16)
    plaintext = b"Stream cipher mode test"
    
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(plaintext)
    nonce = cipher.nonce
    
    # Decrypt
    cipher_dec = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted = cipher_dec.decrypt(ciphertext)
    
    print(f"\nCTR Mode:")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted: {decrypted}")

# GCM Mode (authenticated encryption)
def aes_gcm_demo():
    key = get_random_bytes(16)
    plaintext = b"Authenticated encryption"
    aad = b"Additional authenticated data"
    
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    
    # Decrypt and verify
    cipher_dec = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher_dec.update(aad)
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)
    
    print(f"\nGCM Mode:")
    print(f"Authenticated and encrypted successfully")
    print(f"Decrypted: {decrypted}")

# Run demos
aes_ecb_demo()
aes_ctr_demo()
aes_gcm_demo()
```

## Part 3: Asymmetric Encryption

### Exercise 3.1: RSA Key Generation
```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_rsa_keypair():
    # Generate 2048-bit RSA key pair
    key = RSA.generate(2048)
    
    # Export keys
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    # Import public key
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    
    # Encrypt
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(ciphertext, private_key):
    # Import private key
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    
    # Decrypt
    ciphertext_bytes = base64.b64decode(ciphertext)
    plaintext = cipher.decrypt(ciphertext_bytes)
    return plaintext.decode()

# Test
private_key, public_key = generate_rsa_keypair()
print("Keys generated successfully!")

message = "RSA encryption test"
encrypted = rsa_encrypt(message, public_key)
print(f"Encrypted: {encrypted[:50]}...")

decrypted = rsa_decrypt(encrypted, private_key)
print(f"Decrypted: {decrypted}")
```

### Exercise 3.2: Digital Signatures
```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def sign_message(message, private_key):
    # Import private key
    key = RSA.import_key(private_key)
    
    # Hash the message
    h = SHA256.new(message.encode())
    
    # Sign the hash
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode()

def verify_signature(message, signature, public_key):
    # Import public key
    key = RSA.import_key(public_key)
    
    # Hash the message
    h = SHA256.new(message.encode())
    
    # Verify signature
    try:
        signature_bytes = base64.b64decode(signature)
        pkcs1_15.new(key).verify(h, signature_bytes)
        return True
    except (ValueError, TypeError):
        return False

# Test
private_key, public_key = generate_rsa_keypair()

message = "This message is authenticated"
signature = sign_message(message, private_key)
print(f"Signature: {signature[:50]}...")

# Verify genuine signature
is_valid = verify_signature(message, signature, public_key)
print(f"Signature valid: {is_valid}")

# Test tampered message
tampered_message = "This message was tampered"
is_valid_tampered = verify_signature(tampered_message, signature, public_key)
print(f"Tampered message signature valid: {is_valid_tampered}")
```

## Part 4: Hashing and Key Derivation

### Exercise 4.1: Hash Functions
```python
import hashlib

def demonstrate_hash_functions():
    message = "Hello, Cryptography!"
    
    # MD5 (deprecated, shown for educational purposes)
    md5_hash = hashlib.md5(message.encode()).hexdigest()
    print(f"MD5: {md5_hash}")
    
    # SHA-1 (deprecated)
    sha1_hash = hashlib.sha1(message.encode()).hexdigest()
    print(f"SHA-1: {sha1_hash}")
    
    # SHA-256 (recommended)
    sha256_hash = hashlib.sha256(message.encode()).hexdigest()
    print(f"SHA-256: {sha256_hash}")
    
    # SHA-512
    sha512_hash = hashlib.sha512(message.encode()).hexdigest()
    print(f"SHA-512: {sha512_hash}")
    
    # Demonstrate avalanche effect
    message2 = "Hello, Cryptography."  # Changed one character
    sha256_hash2 = hashlib.sha256(message2.encode()).hexdigest()
    print(f"\nOriginal SHA-256: {sha256_hash}")
    print(f"Modified SHA-256: {sha256_hash2}")
    print(f"Hashes are {'different' if sha256_hash != sha256_hash2 else 'same'}")

demonstrate_hash_functions()
```

### Exercise 4.2: Password Hashing
```python
import bcrypt
import hashlib
import os
from Crypto.Protocol.KDF import PBKDF2

def insecure_password_storage(password):
    # DON'T DO THIS - Educational purposes only
    return hashlib.sha256(password.encode()).hexdigest()

def secure_password_hashing():
    password = "MySecurePassword123!"
    
    # bcrypt (recommended)
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    print(f"bcrypt hash: {hashed}")
    
    # Verify password
    is_valid = bcrypt.checkpw(password.encode(), hashed)
    print(f"Password valid: {is_valid}")
    
    # PBKDF2
    salt = os.urandom(32)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    print(f"PBKDF2 key: {key.hex()}")

secure_password_hashing()
```

## Part 5: Practical Applications

### Exercise 5.1: Hybrid Encryption
```python
def hybrid_encrypt(plaintext, recipient_public_key):
    # Generate random AES key
    aes_key = get_random_bytes(32)
    
    # Encrypt data with AES
    iv = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher_aes.encrypt(padded_plaintext)
    
    # Encrypt AES key with RSA
    key_rsa = RSA.import_key(recipient_public_key)
    cipher_rsa = PKCS1_OAEP.new(key_rsa)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Return encrypted key + IV + ciphertext
    return {
        'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
        'iv': base64.b64encode(iv).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }

def hybrid_decrypt(encrypted_data, recipient_private_key):
    # Decrypt AES key with RSA
    key_rsa = RSA.import_key(recipient_private_key)
    cipher_rsa = PKCS1_OAEP.new(key_rsa)
    aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_data['encrypted_key']))
    
    # Decrypt data with AES
    iv = base64.b64decode(encrypted_data['iv'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher_aes.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    return plaintext.decode()

# Test hybrid encryption
private_key, public_key = generate_rsa_keypair()
large_message = "This is a large message that would be inefficient to encrypt with RSA alone." * 10

encrypted = hybrid_encrypt(large_message, public_key)
print("Hybrid encryption successful!")

decrypted = hybrid_decrypt(encrypted, private_key)
print(f"Decrypted: {decrypted[:50]}...")
```

### Exercise 5.2: File Encryption
```python
def encrypt_file(input_file, output_file, password):
    # Derive key from password
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    
    # Read file
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    # Encrypt
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # Write encrypted file
    with open(output_file, 'wb') as f:
        f.write(salt)  # 16 bytes
        f.write(cipher.nonce)  # 16 bytes
        f.write(tag)  # 16 bytes
        f.write(ciphertext)

def decrypt_file(input_file, output_file, password):
    # Read encrypted file
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    
    # Derive key from password
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    
    # Decrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    # Write decrypted file
    with open(output_file, 'wb') as f:
        f.write(plaintext)

# Test file encryption
test_file = "test.txt"
with open(test_file, 'w') as f:
    f.write("This is a secret file!")

password = "StrongPassword123!"
encrypt_file(test_file, "test.enc", password)
print("File encrypted successfully!")

decrypt_file("test.enc", "test_decrypted.txt", password)
print("File decrypted successfully!")
```

## Lab Challenges

### Challenge 1: Break Vigenère Cipher
Given this ciphertext encrypted with Vigenère cipher, find the key:
```
LXFOPVEFRNHR
```
Hint: The key length is 5 and contains only letters.

### Challenge 2: Implement Diffie-Hellman
Implement the Diffie-Hellman key exchange algorithm to establish a shared secret.

### Challenge 3: Create a Password Manager
Build a simple password manager that:
- Derives a master key from a password
- Encrypts passwords with AES
- Stores encrypted passwords securely
- Can retrieve and decrypt passwords

## Best Practices

### Encryption Guidelines:
1. **Never roll your own crypto** - Use established libraries
2. **Use strong key sizes** - AES-256, RSA-2048 minimum
3. **Proper key management** - Secure storage and rotation
4. **Use authenticated encryption** - GCM mode or similar
5. **Secure random numbers** - Use cryptographically secure PRNGs
6. **Salt passwords** - Always use unique salts
7. **Key derivation** - Use PBKDF2, bcrypt, or Argon2

### Common Mistakes to Avoid:
- Using ECB mode for AES
- Reusing IVs or nonces
- Weak passwords for key derivation
- Storing keys in code
- Using deprecated algorithms (MD5, SHA-1, DES)
- Not validating signatures/MACs
- Poor random number generation

## Conclusion
This lab covered essential encryption concepts:
- Classical and modern ciphers
- Symmetric encryption (AES)
- Asymmetric encryption (RSA)
- Hashing and key derivation
- Practical applications

Remember: Cryptography is complex. Always use well-tested libraries and follow best practices.

## Additional Resources
- Cryptography Engineering by Schneier
- The Cryptopals Crypto Challenges
- NIST Cryptographic Standards
- OpenSSL Documentation 
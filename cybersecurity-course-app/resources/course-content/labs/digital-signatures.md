# Digital Signatures Workshop

## Objective
Learn about digital signatures, understand their importance in cybersecurity, and implement various signature schemes.

## Prerequisites
- Understanding of public key cryptography
- Basic knowledge of hash functions
- Python programming skills

## Lab Overview
In this workshop, you will:
1. Understand digital signature concepts
2. Implement RSA signatures
3. Work with DSA and ECDSA
4. Create certificate chains
5. Build a document signing system

## Part 1: Digital Signature Fundamentals

### Exercise 1.1: Understanding Digital Signatures
Digital signatures provide:
- **Authentication**: Verify the sender's identity
- **Integrity**: Ensure message hasn't been altered
- **Non-repudiation**: Sender cannot deny sending the message

### Exercise 1.2: Basic RSA Signature
```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode()

def verify_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

# Test
private_key, public_key = generate_keys()
message = "This is an important document"
signature = sign_message(message, private_key)
print(f"Signature: {signature[:50]}...")
print(f"Valid: {verify_signature(message, signature, public_key)}")
```

## Part 2: Advanced Signature Schemes

### Exercise 2.1: DSA (Digital Signature Algorithm)
```python
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def generate_dsa_keys():
    key = DSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def dsa_sign(message, private_key):
    key = DSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)
    return base64.b64encode(signature).decode()

def dsa_verify(message, signature, public_key):
    key = DSA.import_key(public_key)
    h = SHA256.new(message.encode())
    verifier = DSS.new(key, 'fips-186-3')
    try:
        verifier.verify(h, base64.b64decode(signature))
        return True
    except ValueError:
        return False

# Test DSA
dsa_private, dsa_public = generate_dsa_keys()
message = "DSA signature test"
dsa_sig = dsa_sign(message, dsa_private)
print(f"DSA Signature valid: {dsa_verify(message, dsa_sig, dsa_public)}")
```

### Exercise 2.2: ECDSA (Elliptic Curve DSA)
```python
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def generate_ecdsa_keys():
    key = ECC.generate(curve='P-256')
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    return private_key, public_key

def ecdsa_sign(message, private_key):
    key = ECC.import_key(private_key)
    h = SHA256.new(message.encode())
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)
    return base64.b64encode(signature).decode()

def ecdsa_verify(message, signature, public_key):
    key = ECC.import_key(public_key)
    h = SHA256.new(message.encode())
    verifier = DSS.new(key, 'fips-186-3')
    try:
        verifier.verify(h, base64.b64decode(signature))
        return True
    except ValueError:
        return False

# Test ECDSA
ecdsa_private, ecdsa_public = generate_ecdsa_keys()
message = "ECDSA signature test"
ecdsa_sig = ecdsa_sign(message, ecdsa_private)
print(f"ECDSA Signature valid: {ecdsa_verify(message, ecdsa_sig, ecdsa_public)}")
```

## Part 3: Certificate Creation and Validation

### Exercise 3.1: Self-Signed Certificate
```python
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime

def create_self_signed_cert():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Certificate details
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])
    
    # Create certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"mysite.com"),
            x509.DNSName(u"www.mysite.com"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Serialize
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    return private_pem, cert_pem

# Create certificate
private_key, certificate = create_self_signed_cert()
print("Certificate created successfully!")
```

### Exercise 3.2: Certificate Chain Validation
```python
def verify_certificate_chain(cert_chain, trusted_root):
    """
    Verify a certificate chain
    cert_chain: list of certificates from leaf to root
    trusted_root: trusted root certificate
    """
    from cryptography.x509.verification import PolicyBuilder, Store
    from cryptography.x509.oid import ExtendedKeyUsageOID
    
    # Build trust store
    store = Store([trusted_root])
    
    # Build verification policy
    builder = PolicyBuilder().store(store)
    verifier = builder.build_server_verifier(
        x509.DNSName("example.com"),
    )
    
    # Verify the chain
    try:
        chain = verifier.verify(cert_chain[0], cert_chain[1:])
        return True, "Certificate chain is valid"
    except Exception as e:
        return False, str(e)
```

## Part 4: Document Signing System

### Exercise 4.1: PDF Document Signing
```python
import hashlib
import json
from datetime import datetime

class DocumentSigner:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
    
    def sign_document(self, document_path):
        # Read document
        with open(document_path, 'rb') as f:
            document_data = f.read()
        
        # Create document hash
        doc_hash = hashlib.sha256(document_data).hexdigest()
        
        # Create signature metadata
        metadata = {
            'timestamp': datetime.utcnow().isoformat(),
            'document_hash': doc_hash,
            'signer': 'John Doe',
            'algorithm': 'RSA-SHA256'
        }
        
        # Sign the metadata
        metadata_json = json.dumps(metadata, sort_keys=True)
        signature = sign_message(metadata_json, self.private_key)
        
        # Create signed document package
        signed_package = {
            'document': base64.b64encode(document_data).decode(),
            'metadata': metadata,
            'signature': signature,
            'public_key': self.public_key.decode()
        }
        
        return signed_package
    
    def verify_signed_document(self, signed_package):
        # Extract components
        document_data = base64.b64decode(signed_package['document'])
        metadata = signed_package['metadata']
        signature = signed_package['signature']
        public_key = signed_package['public_key'].encode()
        
        # Verify document hash
        calculated_hash = hashlib.sha256(document_data).hexdigest()
        if calculated_hash != metadata['document_hash']:
            return False, "Document has been tampered with"
        
        # Verify signature
        metadata_json = json.dumps(metadata, sort_keys=True)
        if not verify_signature(metadata_json, signature, public_key):
            return False, "Invalid signature"
        
        return True, "Document is authentic and unmodified"

# Test document signing
private_key, public_key = generate_keys()
signer = DocumentSigner(private_key, public_key)

# Create a test document
with open('test_document.txt', 'w') as f:
    f.write("This is an important legal document.")

# Sign the document
signed_doc = signer.sign_document('test_document.txt')
print("Document signed successfully!")

# Verify the signature
valid, message = signer.verify_signed_document(signed_doc)
print(f"Verification: {message}")
```

### Exercise 4.2: Timestamping Service
```python
import requests
from datetime import datetime

class TimestampAuthority:
    def __init__(self, ta_private_key, ta_public_key):
        self.private_key = ta_private_key
        self.public_key = ta_public_key
    
    def create_timestamp(self, document_hash):
        timestamp_data = {
            'hash': document_hash,
            'timestamp': datetime.utcnow().isoformat(),
            'ta_id': 'TrustedTimeAuthority'
        }
        
        # Sign the timestamp
        timestamp_json = json.dumps(timestamp_data, sort_keys=True)
        signature = sign_message(timestamp_json, self.private_key)
        
        return {
            'timestamp_data': timestamp_data,
            'signature': signature,
            'ta_public_key': self.public_key.decode()
        }
    
    def verify_timestamp(self, timestamp_token):
        timestamp_data = timestamp_token['timestamp_data']
        signature = timestamp_token['signature']
        ta_public_key = timestamp_token['ta_public_key'].encode()
        
        # Verify signature
        timestamp_json = json.dumps(timestamp_data, sort_keys=True)
        return verify_signature(timestamp_json, signature, ta_public_key)

# Create timestamp authority
ta_private, ta_public = generate_keys()
ta = TimestampAuthority(ta_private, ta_public)

# Create timestamp for a document
doc_hash = hashlib.sha256(b"Important document").hexdigest()
timestamp_token = ta.create_timestamp(doc_hash)
print(f"Timestamp created: {timestamp_token['timestamp_data']['timestamp']}")
print(f"Timestamp valid: {ta.verify_timestamp(timestamp_token)}")
```

## Part 5: Advanced Applications

### Exercise 5.1: Multi-Signature Scheme
```python
class MultiSigDocument:
    def __init__(self, required_signatures=2):
        self.required_signatures = required_signatures
        self.signatures = []
    
    def add_signature(self, signer_id, signature, public_key):
        self.signatures.append({
            'signer_id': signer_id,
            'signature': signature,
            'public_key': public_key,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    def verify_signatures(self, document):
        valid_signatures = 0
        
        for sig_data in self.signatures:
            if verify_signature(document, sig_data['signature'], sig_data['public_key']):
                valid_signatures += 1
                print(f"Valid signature from {sig_data['signer_id']}")
            else:
                print(f"Invalid signature from {sig_data['signer_id']}")
        
        return valid_signatures >= self.required_signatures

# Test multi-signature
doc = "Multi-party agreement"
multisig = MultiSigDocument(required_signatures=2)

# Create multiple signers
for i in range(3):
    private, public = generate_keys()
    signature = sign_message(doc, private)
    multisig.add_signature(f"Signer{i+1}", signature, public)

print(f"Document valid: {multisig.verify_signatures(doc)}")
```

### Exercise 5.2: Blind Signatures
```python
def blind_signature_demo():
    """
    Simplified blind signature demonstration
    Note: This is a conceptual demo, not cryptographically secure
    """
    from Crypto.Util.number import inverse
    
    # Generate RSA keys
    key = RSA.generate(2048)
    n = key.n
    e = key.e
    d = key.d
    
    # Message to be blindly signed
    message = "Secret vote for candidate A"
    m = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
    
    # Blinding factor
    import random
    r = random.randint(2, n-1)
    while gcd(r, n) != 1:
        r = random.randint(2, n-1)
    
    # Blind the message
    blinded = (m * pow(r, e, n)) % n
    
    # Sign the blinded message
    blind_signature = pow(blinded, d, n)
    
    # Unblind the signature
    r_inv = inverse(r, n)
    signature = (blind_signature * r_inv) % n
    
    # Verify the signature
    verified = pow(signature, e, n) == m
    print(f"Blind signature valid: {verified}")

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a
```

## Lab Challenges

### Challenge 1: Signature Forgery Detection
Create a system that:
- Detects tampered signatures
- Identifies the type of tampering
- Logs security incidents

### Challenge 2: Certificate Authority
Build a mini CA that:
- Issues certificates
- Maintains a certificate revocation list (CRL)
- Validates certificate chains

### Challenge 3: Blockchain Signatures
Implement a simple blockchain where:
- Each block is digitally signed
- Signatures chain together
- Tampering is detectable

## Best Practices

### Digital Signature Guidelines:
1. **Use appropriate key sizes** (RSA-2048+, ECDSA-P256+)
2. **Include timestamps** in signatures
3. **Verify certificates** before trusting public keys
4. **Protect private keys** with hardware security modules
5. **Use standard formats** (PKCS#7, CMS, XMLDSig)
6. **Implement key rotation** policies
7. **Log all signature operations**

### Common Vulnerabilities:
- Weak random number generation
- Missing timestamp validation
- No certificate revocation checking
- Improper signature verification
- Key reuse across different contexts
- Side-channel attacks on signing operations

## Conclusion
This workshop covered:
- Digital signature algorithms (RSA, DSA, ECDSA)
- Certificate creation and validation
- Document signing systems
- Advanced signature schemes
- Security best practices

Digital signatures are crucial for:
- Document authenticity
- Code signing
- Email security (S/MIME)
- Blockchain transactions
- Legal documents

## Additional Resources
- PKCS Standards
- X.509 Certificate Format
- RFC 5652 (Cryptographic Message Syntax)
- NIST Digital Signature Standard 
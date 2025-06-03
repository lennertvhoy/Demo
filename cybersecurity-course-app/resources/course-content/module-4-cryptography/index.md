---
title: "Module 4: Cryptography and Encryption"
labs:
  - encryption-basics
  - digital-signatures
video: "https://www.youtube.com/embed/example4"
case_studies:
  - title: "Cryptography in Finance"
    description: "Usage of cryptographic protocols in banking."
    url: "/case-studies/crypto-finance"
---

# Overview

Cryptography underpins secure communications and data protection. This module explores the theory and practical application of encryption, hashing, and digital signatures to ensure confidentiality, integrity, and non-repudiation.

### Why Cryptography is Essential

Without cryptography, sensitive information like passwords, financial transactions, and personal data would be exposed in transit and at rest. Proper use of cryptographic techniques prevents eavesdropping, tampering, and impersonation.

## Topics

### Symmetric vs. Asymmetric Encryption

Symmetric encryption uses a single shared key for encryption and decryption (e.g., AES). It's fast and suitable for bulk data. Asymmetric encryption uses key pairs (public/private) such as RSA or ECC, enabling secure key exchange and digital signatures.

### Common Cryptographic Algorithms (AES, RSA)

AES is a widely used symmetric cipher known for its performance and security. RSA is a foundational public-key algorithm for secure key exchange and digital signatures. You will see how each algorithm works and compare key lengths and security levels.

### Hash Functions and Integrity Checks

Hash functions produce fixed-size outputs from arbitrary input data (e.g., SHA-256). They ensure data integrity by detecting any alteration. You'll learn about collision resistance, pre image attacks, and practical uses like password storage.

### Digital Signatures and PKI

Digital signatures use asymmetric keys to verify the authenticity and integrity of messages. Public Key Infrastructure (PKI) manages certificates and trust chains. You will create and verify signatures and understand certificate authorities.

### SSL/TLS Basics

SSL/TLS protocols secure internet communications. You'll examine the handshake process, cipher suite negotiation, and how certificates establish trust. Best practices for server configuration and avoiding common pitfalls will be covered.

## Self-Assessment

1. Compare symmetric and asymmetric encryption and give an example use case for each.
2. Explain what makes a hash function secure and list two common hash algorithms.
3. Describe how digital signatures work and why they provide non-repudiation.
4. Outline the SSL/TLS handshake steps. 
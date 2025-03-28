# Key-Distribution-System

### Introduction
In this digital era, conducting a secure communication and data protection is very much important.
So, in order to address this problem I have come up with a Key Distribution System, where symmetric encryption is taken care by a Centralized Key Management System and asymmetric key is taken care by a Public Key Interface (PKI). This provides a secure way of exchanging encryption and decryption keys between 2 parties.

This Key Distribution System is designed to handle the following things:
1. Generate a suitable symmetric and asymmetric keys
2. Storing the generated keys
3. Exchanging keys using Diffie-Helman for symmetric key and PKI based certification for asymmetric keys
4. Revocation of keys

In a nutshell, this project focuses on generating, storing and exchanging cryptography keys securly by mitigating Man In the Middle Attack (MIMA) and revocing keys in case of key compromise.

### Design Goals
- Centralized Key Distribution (CKD) for symmetric encryption.
- Public Key Infrastructure (PKI) for asymmetric encryption.
- Secure key generation and storage.
- Secure key exchange using Diffie-Hellman for symmetric key.
- Revocation of keys in case of compromise.

### Steps in Design
- Centralized Key Distribution (CKD) for symmetric encryption.
  - Diffie-Helman shared key generation.
  - Encrypting the generated AES Key with the shared key.
  - Storing the encrypted AES key in CKD and sending the same to receiver.
  - Verifying the received encrypted AES key with the stored key in CKD.
  - Revoking the key if in case of any compromise.
- Public Key Infrastructure (PKI) for asymmetric encryption.
  - RSA key pair generation
  - Certificating the public key with X.509 certification by the root Certificating Authority (CA).
  - Storing the certificate and the private key in .pem format in the PKI.
  - Verifying the certificate
  - Revoking the certificate in case of any key compromise.

### Project Structure
```
Key Distribution System
│──key_and_certificates             # Stores the keys and certificates
│   │── revoked_certificates.txt    # Stoes the serial number of the revoked certificates (asymmetric)
│   │── revoked_keys.txt            # Stoes the serial number of the revoked keys (symmetric)
│   │── root_ca.pem                 # Certificate of the root CA
│   │── root_crl.pem                # Certificate revokation list
│   │── root_private_key.pem        # Pivate key ofroot CA
│
│── D_H_key_exchange.py             # Diffie-Helman key generation and exchange
│── key_generation.py               # AES and RSA key generation
│── key_revocation.py               # Haedles the key revokation in case compromise
│── main.py                         # The terminal based Menu system for navigation between functions
│── PKI.py                          # Handels the certificate generation and storage

```

### Installation and Setup

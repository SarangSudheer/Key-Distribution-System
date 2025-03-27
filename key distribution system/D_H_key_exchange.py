import os
import base64
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime, UTC

# Generate AES Key
def generate_aes_key():
    aes_key = os.urandom(32)  # 256-bit AES key
    return aes_key

# Generating D-H keys for A and B
def generate_dh_keys():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key, parameters

# Generating Shared Keys
def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"DH Key Exchange",
    ).derive(shared_secret)
    return derived_key

# Encrypt AES Key using DH-derived Key
def encrypt_aes_key(aes_key, encryption_key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(aes_key) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

# Decrypt AES Key
def decrypt_aes_key(iv, ciphertext, tag, encryption_key):
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decrypted_key = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_key

# Generate a Serial Number
def generate_serial_number():
    return int.from_bytes(os.urandom(4), "big")

# Save Encrypted AES Key to PEM File (with Serial Number)
def save_encrypted_aes_key(serial_number, iv, ciphertext, tag, sender_name, receiver_name):
    filename=f"key_and_certificates/{sender_name}_{receiver_name}_aes_key.pem"
    with open(filename, "wb") as f:
        f.write(b"-----BEGIN ENCRYPTED AES KEY-----\n")
        f.write(f"Serial Number: {serial_number}\n".encode())  
        f.write(base64.b64encode(iv) + b"\n")
        f.write(base64.b64encode(ciphertext) + b"\n")
        f.write(base64.b64encode(tag) + b"\n")
        f.write(b"-----END ENCRYPTED AES KEY-----\n")
    print(f"🔐 AES Key Encrypted & Stored in PEM File with Serial: {serial_number}")

# Load Encrypted AES Key from PEM File
def load_encrypted_aes_key(sender_name, receiver_name):
    filename=f"key_and_certificates/{sender_name}_{receiver_name}_aes_key.pem"
    if not os.path.exists(filename):
        print("❌ Error: AES Key file does not exist!")
        ch=input("Do u want to check if the key is revoked [y/n]: ").lower()
        if(ch=="y"):
            is_aes_key_revoked(sender_name,receiver_name)
        return None, None, None, None

    with open(filename, "rb") as f:
        lines = f.readlines()
        serial_number = int(lines[1].strip().split(b": ")[1])  # Extract serial number
        iv = base64.b64decode(lines[2].strip())
        ciphertext = base64.b64decode(lines[3].strip())
        tag = base64.b64decode(lines[4].strip())
    
    return serial_number, iv, ciphertext, tag

REVOKED_KEYS_FILE = "key_and_certificates/revoked_keys.txt"

# Get Serial Number from AES Key PEM File
def get_serial_number(sender_name, receiver_name):
    filename = f"key_and_certificates/{sender_name}_{receiver_name}_aes_key.pem"
    
    if not os.path.exists(filename):
        print("❌ Error: AES Key file does not exist!")
        return None

    with open(filename, "rb") as f:
        lines = f.readlines()
        try:
            serial_number = int(lines[1].strip().split(b": ")[1])  # Extract serial number
            return serial_number
        except (IndexError, ValueError):
            print("❌ Error: Invalid file format! Could not extract serial number.")
            return None

# Revoke AES Key
def revoke_aes_key(sender_name, receiver_name):
    serial_number = get_serial_number(sender_name, receiver_name)
    
    if serial_number is None:
        print("⚠️ Skipping revocation. No valid serial number found.")
        return

    revoked_keys = load_revoked_keys()
    
    # Avoid duplicate revocations
    if serial_number in [serial for serial, _ in revoked_keys]:
        print(f"🔴 AES Key with Serial {serial_number} is already revoked!")
        return
    
    revoked_keys.append((serial_number, datetime.now(UTC).isoformat()))
    save_revoked_keys(revoked_keys)
    
    print(f"🔴 AES Key with Serial {serial_number} has been REVOKED!")

# Save Revoked Keys (Append Instead of Overwriting)
def save_revoked_keys(revoked_keys, filename=REVOKED_KEYS_FILE):
    with open(filename, "w") as f:
        for serial, date in revoked_keys:
            f.write(f"{serial},{date}\n")

# Load Revoked Keys
def load_revoked_keys(filename=REVOKED_KEYS_FILE):
    revoked_keys = []
    
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for line in f:
                serial, date = line.strip().split(",")
                revoked_keys.append((int(serial), date))
    return revoked_keys

# Check if AES Key is Revoked
def is_aes_key_revoked(sender_name, receiver_name):
    serial_number = get_serial_number(sender_name, receiver_name)
    
    if serial_number is None:
        print("⚠️ Cannot check revocation. No valid serial number found.")
        return False

    revoked_keys = load_revoked_keys()
    
    for serial, _ in revoked_keys:
        if serial == serial_number:
            print(f"🚫 AES Key with Serial {serial_number} is REVOKED!")
            return True
        
    print(f"✅ AES Key with Serial {serial_number} is VALID! (Not REVOKED)")
    return False


import sys, os, base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from key_generation import generate_aes_key
from PKI import root_ca_cert_generation, issue_client_certificate, verify_client_certificate
from D_H_key_exchange import (
    generate_dh_keys, derive_shared_secret, encrypt_aes_key, decrypt_aes_key, generate_serial_number,
    save_encrypted_aes_key, load_encrypted_aes_key, revoke_aes_key, is_aes_key_revoked
)
from key_revocation import revoke_certificate, is_certificate_revoked

def dh_public_key_to_pem(dh_public_key):
    return dh_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def AES_menu():
    while True:
        print("\n🔐 === Symmetric Key Management System (AES) === 🔐")
        print("1️⃣  Generate and Exchange AES Key")
        print("2️⃣  Verify the AES Key")
        print("3️⃣  Revoke an AES Key")
        print("4️⃣  Check if an AES Key is Revoked")
        print("0️⃣  Return to Main Menu")

        choice = int(input("👉 Enter your choice: "))
        if choice == 0:
            break

        A = input("👤 Enter your name: ")
        B = input("📩 Enter the recipient's name: ")

        if choice == 1:
            print(f"\n🔑 Generating Diffie-Hellman keys for {A} and {B}...")
            private_key_A, public_key_A, parameters = generate_dh_keys()
            private_key_B = parameters.generate_private_key()
            public_key_B = private_key_B.public_key()

            print(f"✅ {A}'s Public Key: {dh_public_key_to_pem(public_key_A)}")
            print(f"✅ {B}'s Public Key: {dh_public_key_to_pem(public_key_B)}")
            print("🔄 Exchanging public keys securely...")

            shared_secret_A = derive_shared_secret(private_key_A, public_key_B)
            shared_secret_B = derive_shared_secret(private_key_B, public_key_A)
            
            print(f"Shared Key A: {base64.b64encode(shared_secret_A).decode()}")
            print(f"Shared Key B: {base64.b64encode(shared_secret_B).decode()}")

            if shared_secret_A == shared_secret_B:
                print("🔓 Secure shared key established successfully!\n")
            else:
                print("❌ Shared key mismatch! Possible tampering detected.\n")
                continue

            print("\n🔑 Generating AES encryption key...")
            aes_key = generate_aes_key()
            print(f"🛡️ AES Key: {base64.b64encode(aes_key).decode()}\n")

            print("\n🔒 Encrypting the AES key before transmission...")
            iv, encrypted_aes_key, tag = encrypt_aes_key(aes_key, shared_secret_A)
            serial_number = generate_serial_number()

            print("📡 Storing the encrypted AES key in the Key Distribution System...")
            save_encrypted_aes_key(serial_number, iv, encrypted_aes_key, tag, A, B)
            print("✅ AES key successfully shared with the recipient!\n")

        elif choice == 2:
            print(f"\n🔍 {B} Verifying AES key integrity of {A}...")
            Ddecrypt = decrypt_aes_key(iv, encrypted_aes_key, tag, shared_secret_B)
            print(f"🔑 Decrypted AES key: {base64.b64encode(Ddecrypt).decode()}")

            print("📡 Fetching the stored AES key from the Key Distribution System...")
            loaded_serial_number, iv_loaded, ciphertext_loaded, tag_loaded = load_encrypted_aes_key(A, B)
            Fdecrypt = decrypt_aes_key(iv_loaded, ciphertext_loaded, tag_loaded, shared_secret_B)
            
            if Ddecrypt == Fdecrypt:
                print("✅ AES key verification successful!")
            else:
                print("❌ Verification failed! Possible security issue.")

        elif choice == 3:
            print(f"\n⚠️ Revoking AES key for communication between {A} and {B}...")
            revoke_aes_key(A, B)
            print("✅ AES key revoked successfully!")

        elif choice == 4:
            print(f"\n🔍 Checking if AES key for {A} and {B} is revoked...")
            is_aes_key_revoked(A, B)

        else:
            print("❌ Invalid choice! Please enter a valid option.")


def RSA_menu():
    while True:
        print("\n🔐 === Asymmetric Key Management System (RSA) === 🔐")
        print("1️⃣  Generate RSA Key Pair")
        print("2️⃣  Verify a Certificate")
        print("3️⃣  Revoke a Certificate")
        print("4️⃣  Check Certificate Revocation Status")
        print("0️⃣  Return to Main Menu")

        choice = int(input("👉 Enter your choice: "))
        if choice == 0:
            break

        if not os.path.exists("key_and_certificates/root_ca.pem") and not os.path.exists("key_and_certificates/root_private_key.pem"):
            print("🏗️ Root CA not found. Generating Root CA Certificate...")
            root_ca_cert_generation()

        with open("key_and_certificates/root_private_key.pem", "rb") as f:
            root_private_key = serialization.load_pem_private_key(f.read(), password=None)

        with open("key_and_certificates/root_ca.pem", "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        root_subject = root_cert.subject
        client_name = input("👤 Enter the client name: ")

        if choice == 1:
            print(f"\n🔑 Generating RSA key pair for {client_name}...")
            issue_client_certificate(client_name, root_private_key, root_subject)
            print(f"✅ Certificate issued for {client_name}!")

        elif choice == 2:
            print(f"\n🔍 Verifying certificate for {client_name}...")
            verify_client_certificate(f"key_and_certificates/{client_name}_cert.pem")

        elif choice == 3:
            print(f"\n⚠️ Revoking certificate for {client_name}...")
            revoke_certificate(f"key_and_certificates/{client_name}_cert.pem", root_private_key, root_subject)
            print("✅ Certificate revoked successfully!")

        elif choice == 4:
            print(f"\n🔍 Checking if {client_name}'s certificate is revoked...")
            is_certificate_revoked(f"key_and_certificates/{client_name}_cert.pem")

        else:
            print("❌ Invalid choice! Please enter a valid option.")


def main_menu():
    while True:
        print("\n🔑 === Key Management System === 🔑")
        print("1️⃣  Symmetric Key Management (AES)")
        print("2️⃣  Asymmetric Key Management (RSA)")
        print("0️⃣  Exit")

        choice = int(input("👉 Enter your choice: "))
        if choice == 1:
            AES_menu()
        elif choice == 2:
            RSA_menu()
        elif choice == 0:
            print("👋 Exiting... Have a great day!")
            sys.exit()
        else:
            print("❌ Invalid choice! Please try again.")

main_menu()

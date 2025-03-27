import os
from cryptography import x509
from datetime import datetime,UTC,timedelta
from cryptography.hazmat.primitives import hashes, serialization


# Load previously revoked certificates from a file
def load_revoked_certificates(CRL_RECORDS_FILE = "key_and_certificates/revoked_certificates.txt"):
    revoked_certificates = []
    if os.path.exists(CRL_RECORDS_FILE):
        with open(CRL_RECORDS_FILE, "r") as f:
            for line in f:
                serial, date = line.strip().split(",")
                revoked_certificates.append((int(serial), datetime.fromisoformat(date)))
    return revoked_certificates

#Save revoked certificates to a file
def save_revoked_certificates(revoked_certificates, CRL_RECORDS_FILE = "key_and_certificates/revoked_certificates.txt"):
    with open(CRL_RECORDS_FILE, "w") as f:
        for serial, date in revoked_certificates:
            f.write(f"{serial},{date.isoformat()}\n")

# generating a certificate revocation list
def generate_crl(root_private_key, root_subject, crl_path="key_and_certificates/root_crl.pem"):
    revoked_certificates=load_revoked_certificates()

    crl_builder=x509.CertificateRevocationListBuilder().issuer_name(root_subject)
    crl_builder=crl_builder.last_update(datetime.now(UTC)).next_update(datetime.now(UTC) + timedelta(days=30))

    for serial_number, revocation_date in revoked_certificates:
        revoked_cert=x509.RevokedCertificateBuilder().serial_number(serial_number).revocation_date(revocation_date).build()
        crl_builder=crl_builder.add_revoked_certificate(revoked_cert)

    crl=crl_builder.sign(private_key=root_private_key, algorithm=hashes.SHA256())

    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    print("✅ CRL Updated and Saved Successfully!")

# checking if certificate is already revoked
def is_certificate_revoked(cert_path, crl_path="key_and_certificates/root_crl.pem"):
    
    with open(cert_path, "rb") as f:
        cert=x509.load_pem_x509_certificate(f.read())

    cert_serial=cert.serial_number 

    if not os.path.exists(crl_path):
        print("❌ CRL file not found!")
        return False

    with open(crl_path, "rb") as f:
        crl=x509.load_pem_x509_crl(f.read())

    # Check if the certificate's serial number is in the CRL
    for revoked_cert in crl:
        if revoked_cert.serial_number == cert_serial:
            print(f"🚫 Certificate with Serial Number {cert_serial} is REVOKED!")
            return True

    print(f"✅ Certificate with Serial Number {cert_serial} is VALID (Not Revoked).")
    return False

# revoke a certificate
def revoke_certificate(client_cert_path, root_private_key, root_subject, crl_path="key_and_certificates/root_crl.pem"):
    if (is_certificate_revoked(client_cert_path)):# checking if already revoked
        return False
    
    with open(client_cert_path, "rb") as f:
        client_cert = x509.load_pem_x509_certificate(f.read())

    serial_number = client_cert.serial_number
    print(f"Revoking certificate with serial number: {serial_number}")

    revoked_certificates = load_revoked_certificates()
    revoked_certificates.append((serial_number, datetime.now(UTC)))

    save_revoked_certificates(revoked_certificates)
    generate_crl(root_private_key, root_subject, crl_path)

    print("✅ Certificate Revoked and CRL Updated!")

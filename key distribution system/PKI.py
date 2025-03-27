from cryptography.x509.oid import NameOID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, UTC, timedelta
import os
from cryptography.hazmat.primitives.asymmetric import padding

def root_ca_cert_generation():
    # 1. Generate Root CA Key Pair
    root_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_public_key = root_private_key.public_key()

    # 2. Create Root CA Certificate
    root_subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Mangalore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ClownsCyberCorp Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ClownsCyberCorp Root CA"),
    ])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(issuer)
        .public_key(root_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3650))  # 10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_private_key, hashes.SHA256())
    )

    #saving the root CA certificate as pem file
    with open("key_and_certificates/root_ca.pem", "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    print("Root CA certificate Generated!!!!!")
        
    #saving the root's private key as pem file
    with open("key_and_certificates/root_private_key.pem", "wb") as f:
        f.write(root_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
        
if(not os.path.exists("key_and_certificates/root_ca.pem") and not os.path.exists("key_and_certificates/root_private_key.pem")):
    root_ca_cert_generation()

# to retrive the root's private key object from the pem file
with open("key_and_certificates/root_private_key.pem","rb") as f:
    root_private_key=serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# to retrive the root's CA certificate object from the pem file, to get the root's subject
with open("key_and_certificates/root_ca.pem","rb") as f:
    root_cert=x509.load_pem_x509_certificate(f.read())
root_subject=root_cert.subject


# creating client certificate authenticated by the root CA
from key_generation import generate_rsa_keys


def issue_client_certificate(client_name, root_private_key, root_subject):
    
    client_private_key, client_public_key=generate_rsa_keys()#generating public and private rsa keys of the client
    print("The Public and Private key has been generated....")
    print(f"Public Key: {client_public_key}")
    print(f"Private Key: {client_private_key}\n")
    
    print(f"Generating the client certificate by the Certificate Authority....")
    # Create Client Certificate
    client_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Mangalore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"ClownsCyberCorp {client_name}"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{client_name}.clownscybercorp.com"),
    ])

    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_subject)
        .issuer_name(root_subject)
        .public_key(client_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))  # 1 year
        .sign(root_private_key, hashes.SHA256())
    )
    
    with open(f"key_and_certificates/{client_name}_cert.pem","wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))

    with open(f"key_and_certificates/{client_name}_private_key.pem","wb") as f:
        f.write(client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"✅ Certificate and Private key of {client_name} is generated and stored in PKI....")
    

def verify_client_certificate(client_cert_path, root_cert_path="key_and_certificates/root_ca.pem"):
    # Load Root CA Certificate
    with open(root_cert_path, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())

    # Load Client Certificate
    with open(client_cert_path, "rb") as f:
        client_cert = x509.load_pem_x509_certificate(f.read())

    try:
        # Verify that the client certificate is signed by the root CA
        root_cert.public_key().verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            client_cert.signature_hash_algorithm
        )
        print("✅ Client certificate is valid and signed by the Root CA.")
        return True
    except Exception as e:
        print(f"❌ Certificate verification failed: {e}")
        return False
    
def peer_public_key_extraction(peer_name):# to get the public key from the peer certificate for encryption
    with open(f"{peer_name}_cert.pem","rb") as f:
        client_cert=x509.load_pem_x509_certificate(f.read())
    client_public_key=client_cert.public_key()
    return client_public_key
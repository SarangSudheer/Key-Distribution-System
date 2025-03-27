import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_aes_key():#AES Key generation
    aes_key = os.urandom(32) # 256-bit AES Key
    print("Generated AES Key:", base64.b64encode(aes_key).decode())
    return aes_key

def generate_rsa_keys():# RSA Key Pair Generation
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

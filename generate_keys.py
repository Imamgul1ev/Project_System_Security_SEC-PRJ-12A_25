
"""
generate_keys.py - Run once before starting the project.
Generates RSA-2048 key pairs and registers the edge device in the cloud.
"""

import os
import shutil
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

os.makedirs("edge/keys", exist_ok=True)
os.makedirs("cloud/keys", exist_ok=True)

# Private key to sign JWT and file manifest
sign_priv = rsa.generate_private_key(65537, 2048)
sign_pub = sign_priv.public_key()

with open("edge/keys/sign_private.pem", "wb") as f:
    f.write(sign_priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

# Public key to verify JWT and signatures
with open("edge/keys/sign_public.pem", "wb") as f:
    f.write(sign_pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Keys for hybrid encryption
enc_priv = rsa.generate_private_key(65537, 2048)
enc_pub = enc_priv.public_key()

with open("edge/keys/enc_private.pem", "wb") as f:
    f.write(enc_priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

with open("edge/keys/enc_public.pem", "wb") as f:
    f.write(enc_pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Register edge device in cloud
shutil.copy(
    "edge/keys/sign_public.pem",
    "cloud/keys/edge01_sign_public.pem"
)

print("Keys created and edge01 registered successfully!")

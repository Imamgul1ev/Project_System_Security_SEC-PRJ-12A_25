"""
crypto_utils.py - all the cryptography used by the edge device.
"""
import base64
import hashlib
import json
import os
import time
import uuid

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Padding for RSA encryption (OAEP) and for RSA signatures (PSS)
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


# Raised when a downloaded file fails any check
class IntegrityError(Exception):
    pass


# Load the keys from the PEM files
def load_private(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# Base64 turns bytes into text, so they can travel inside JSON (it is NOT encryption)
def b64e(data):
    return base64.b64encode(data).decode()


def b64d(text):
    return base64.b64decode(text)


# Extra data that AES-GCM checks but does not encrypt: binds the file to its name and version
def aad_for(device, filename, version):
    return f"{device}|{filename}|{version}".encode()


# SHA-256 hash of everything that is stored in the cloud
def digest_of(nonce, wrapped_key, ciphertext):
    return hashlib.sha256(nonce + wrapped_key + ciphertext).hexdigest()


# The text that gets signed: who, which file, which version, which content
def manifest_bytes(device, filename, version, sha256_hex):
    manifest = {"device": device, "filename": filename, "version": version, "sha256": sha256_hex}
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


# Encrypt and sign a file before it leaves the edge
def protect_file(device, filename, data, version, enc_public, sign_private):
    # 1. new AES-256 key and nonce, only for this file
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    # 2. encrypt the file with AES-GCM
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, aad_for(device, filename, version))

    # 3. encrypt (wrap) the AES key with the RSA public key
    wrapped_key = enc_public.encrypt(aes_key, OAEP)

    # 4. hash everything and sign the result with the RSA private key
    sha256_hex = digest_of(nonce, wrapped_key, ciphertext)
    signature = sign_private.sign(manifest_bytes(device, filename, version, sha256_hex),
                                  PSS, hashes.SHA256())

    return {
        "device": device,
        "filename": filename,
        "version": version,
        "nonce": b64e(nonce),
        "wrapped_key": b64e(wrapped_key),
        "ciphertext": b64e(ciphertext),
        "sha256": sha256_hex,
        "signature": b64e(signature),
    }


# Check a downloaded file and decrypt it
def open_package(package, device, expected_filename, expected_version, sign_public, enc_private):
    nonce = b64d(package["nonce"])
    wrapped_key = b64d(package["wrapped_key"])
    ciphertext = b64d(package["ciphertext"])

    # Check 1: recompute the hash from the bytes we received
    sha256_hex = digest_of(nonce, wrapped_key, ciphertext)
    if sha256_hex != package["sha256"]:
        raise IntegrityError("SHA-256 digest mismatch - stored data was modified")

    # Check 2: verify the signature with our public key
    manifest = manifest_bytes(package["device"], package["filename"], package["version"], sha256_hex)
    try:
        sign_public.verify(b64d(package["signature"]), manifest, PSS, hashes.SHA256())
    except InvalidSignature:
        raise IntegrityError("RSA-PSS signature invalid - manifest was forged or modified")

    # Check 3: is it the file we asked for? (file swap attack)
    if package["device"] != device or package["filename"] != expected_filename:
        raise IntegrityError(
            f"wrong file: asked for '{expected_filename}', received '{package['filename']}'")

    # Check 4: is it the latest version? (rollback attack)
    if package["version"] != expected_version:
        raise IntegrityError(
            f"stale version: expected v{expected_version}, received v{package['version']}")

    # All checks passed: unwrap the AES key, then decrypt (GCM checks its tag again)
    aes_key = enc_private.decrypt(wrapped_key, OAEP)
    return AESGCM(aes_key).decrypt(nonce, ciphertext,
                                   aad_for(device, package["filename"], package["version"]))


# Short-lived JWT that proves the device's identity to the cloud
def make_token(sign_private, device, ttl_seconds=60):
    now = int(time.time())
    payload = {
        "iss": device,              # issuer: the device itself
        "sub": device,              # subject: the device being authenticated
        "aud": "cloud-storage",     # audience: only valid for the storage service
        "iat": now,                 # issued at
        "exp": now + ttl_seconds,   # expires after 60 seconds
        "jti": str(uuid.uuid4()),   # unique id: each token can be used once
    }
    return jwt.encode(payload, sign_private, algorithm="RS256")

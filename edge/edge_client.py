"""
edge_client.py - the edge device (a Raspberry Pi).
Run it to see the normal flow: read a CSV file, upload it, download it, check it, decrypt it.

    python edge_client.py                    -> uses data/diabetes.csv
    python edge_client.py data/other.csv     -> uses any other file
"""
import json
import os
import platform
import sys

import requests

import crypto_utils as cu

DEVICE_ID = "edge01"
CLOUD_URL = os.environ.get("CLOUD_URL", "http://localhost:5001")
STATE_FILE = "state/versions.json"
DATA_FILE = "data/diabetes.csv"     # the real file the edge protects

# Load the four keys of the edge device
sign_private = cu.load_private("keys/sign_private.pem")
sign_public = cu.load_public("keys/sign_public.pem")
enc_private = cu.load_private("keys/enc_private.pem")
enc_public = cu.load_public("keys/enc_public.pem")


# The edge remembers the latest version of each file (defence against rollback)
def load_versions():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE) as f:
        return json.load(f)


def current_version(filename):
    return load_versions().get(filename, 0)


def save_version(filename, version):
    versions = load_versions()
    versions[filename] = version
    os.makedirs("state", exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(versions, f, indent=2)


# Every request carries a new JWT and the device id
def headers(token=None):
    if token is None:
        token = cu.make_token(sign_private, DEVICE_ID)
    return {"Authorization": "Bearer " + token, "X-Device-ID": DEVICE_ID}


def upload(filename, data):
    version = current_version(filename) + 1
    package = cu.protect_file(DEVICE_ID, filename, data, version, enc_public, sign_private)
    r = requests.post(f"{CLOUD_URL}/upload/{filename}", json=package, headers=headers(), timeout=10)
    r.raise_for_status()
    save_version(filename, version)
    return package


# Download the package exactly as the cloud sends it (no checks)
def fetch(filename, token=None):
    r = requests.get(f"{CLOUD_URL}/download/{filename}", headers=headers(token), timeout=10)
    r.raise_for_status()
    return r.json()


# Download, check and decrypt (raises IntegrityError if anything is wrong)
def download(filename, token=None):
    package = fetch(filename, token)
    return cu.open_package(package, DEVICE_ID, filename, current_version(filename),
                           sign_public, enc_private)


# Read a file from disk; the cloud stores it under its own name (e.g. "diabetes.csv")
def read_file(path):
    with open(path, "rb") as f:
        return os.path.basename(path), f.read()


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DATA_FILE
    filename, original = read_file(path)
    lines = original.decode(errors="replace").splitlines()

    print("=" * 70)
    print(f" EDGE DEVICE {DEVICE_ID}  |  CPU architecture: {platform.machine()}")
    print(f" Cloud: {CLOUD_URL}")
    print("=" * 70)

    print(f"\n[1] Uploading '{filename}' ({len(original)} bytes, {len(lines)} lines)")
    package = upload(filename, original)
    print(f"    version      : v{package['version']}")
    print(f"    AES-256-GCM  : ciphertext {package['ciphertext'][:40]}...")
    print(f"    RSA-OAEP     : wrapped key {package['wrapped_key'][:40]}...")
    print(f"    SHA-256      : {package['sha256']}")
    print(f"    RSA-PSS sig  : {package['signature'][:40]}...")

    print(f"\n[2] Downloading '{filename}' and verifying")
    recovered = download(filename)
    print("    digest, signature, filename, version and GCM tag all valid")
    print("    decrypted content (first 3 lines):")
    for line in recovered.decode(errors="replace").splitlines()[:3]:
        print("      " + line)

    print("\n[3] Comparing with the original")
    if recovered == original:
        print(f"    [OK] identical ({len(recovered)} bytes)")
    else:
        print("    [FAIL] different!")

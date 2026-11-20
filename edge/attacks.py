"""
attacks.py - simulates 3 attacks (one for each part of the CIA triad) and shows each defence.

The script plays two roles:
  - the LEGITIMATE edge device (edge_client), doing normal uploads and downloads
  - the ATTACKER, who only has: the breached cloud disk, his own RSA key,
    and the edge's PUBLIC key. He never uses the edge's private keys.

    python attacks.py                    -> uses data/diabetes.csv
    python attacks.py data/other.csv     -> uses any other file
"""
import json
import os
import sys
import time

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

import crypto_utils as cu
import edge_client as edge

BREACHED_STORAGE = os.environ.get("BREACHED_STORAGE", "../cloud/storage")
RATE_WINDOW = float(os.environ.get("RATE_WINDOW", "10"))
PATH = sys.argv[1] if len(sys.argv) > 1 else edge.DATA_FILE
FILENAME, DATA = edge.read_file(PATH)
SECRET = DATA.splitlines()[0]     # the CSV header row (column names) - surely in the plaintext


def title(n, text, cia):
    print("\n" + "=" * 72)
    print(f" ATTACK {n}: {text}   [{cia}]")
    print("=" * 72)


def result(blocked, reason):
    if blocked:
        print(f"  RESULT: [BLOCKED] {reason}")
    else:
        print(f"  RESULT: [!! ATTACK SUCCEEDED !!] {reason}")


# The attacker reads and writes the file directly on the breached cloud disk
def read_stored():
    with open(f"{BREACHED_STORAGE}/{edge.DEVICE_ID}/{FILENAME}.json") as f:
        return json.load(f)


def write_stored(package):
    with open(f"{BREACHED_STORAGE}/{edge.DEVICE_ID}/{FILENAME}.json", "w") as f:
        json.dump(package, f, indent=2)


# The edge downloads the file; returns the error message, or None if it was accepted
def edge_download_error():
    try:
        edge.download(FILENAME)
        return None
    except cu.IntegrityError as e:
        return str(e)


# ---------- 1. Confidentiality: the breached cloud reads the file ----------
def attack_1():
    title(1, "Breached cloud reads the stored file", "Confidentiality")
    package = read_stored()
    print("  Attacker opens the file on the cloud disk:")
    print(f"    filename    : {package['filename']}")
    print(f"    ciphertext  : {package['ciphertext'][:56]}...")
    print(f"    wrapped_key : {package['wrapped_key'][:56]}...")

    found = SECRET in cu.b64d(package["ciphertext"])
    print(f"  Searching the ciphertext for the CSV header: {SECRET[:50].decode(errors='replace')}...")
    print(f"  -> {'FOUND' if found else 'not found'}")
    print("  To decrypt, the attacker needs the AES key -> it is wrapped with RSA-OAEP")
    print("  -> unwrapping needs enc_private.pem, which exists ONLY on the edge device.")
    result(not found, "the cloud stores only AES-256-GCM ciphertext; no key is stored in the cloud")


# ---------- 2. Integrity: the attacker modifies the file ----------
def attack_2():
    title(2, "Attacker modifies the stored file", "Integrity")
    original = read_stored()

    # 2a: flip one bit of the ciphertext
    tampered = dict(original)
    ct = bytearray(cu.b64d(original["ciphertext"]))
    ct[0] ^= 0x01
    tampered["ciphertext"] = cu.b64e(bytes(ct))
    write_stored(tampered)
    print("  2a) one bit of the ciphertext flipped")
    error = edge_download_error()
    result(error is not None, error)

    # 2b: a smarter attacker also recomputes the SHA-256 hash
    tampered["sha256"] = cu.digest_of(cu.b64d(tampered["nonce"]),
                                      cu.b64d(tampered["wrapped_key"]), bytes(ct))
    write_stored(tampered)
    print("  2b) bit flipped AND SHA-256 recomputed by the attacker")
    error = edge_download_error()
    result(error is not None, f"{error} (a new signature needs sign_private.pem, "
                              f"which the attacker does not have)")

    write_stored(original)   # put the real file back


# ---------- 3. Availability: the attacker floods the cloud ----------
def attack_3():
    title(3, "Flood: many requests with forged tokens", "Availability")
    print(f"  waiting {RATE_WINDOW:.0f}s so earlier requests do not count...")
    time.sleep(RATE_WINDOW)

    # Each request carries a token signed with the attacker's own key (not the edge's)
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    codes = []
    for i in range(40):
        token = jwt.encode({"iss": edge.DEVICE_ID, "sub": edge.DEVICE_ID, "aud": "cloud-storage",
                            "iat": now, "exp": now + 60, "jti": f"flood-{i}"},
                           attacker_key, algorithm="RS256")
        r = requests.get(f"{edge.CLOUD_URL}/download/{FILENAME}", timeout=10,
                         headers={"Authorization": "Bearer " + token, "X-Device-ID": edge.DEVICE_ID})
        codes.append(r.status_code)

    rejected = codes.count(401)
    dropped = codes.count(429)
    print(f"  40 requests sent: {rejected} rejected by the JWT check (401), "
          f"{dropped} dropped by the rate limit (429)")
    print("  request status codes: " + " ".join(str(c) for c in codes))

    print(f"  waiting {RATE_WINDOW:.0f}s for the window to reset...")
    time.sleep(RATE_WINDOW)
    data = edge.download(FILENAME)
    print(f"  legitimate edge request afterwards: OK ({len(data)} bytes decrypted)")
    result(dropped > 0 and 200 not in codes,
           f"no forged token was accepted, and {dropped} requests were dropped "
           f"before any cryptographic work")


if __name__ == "__main__":
    print(f"Cloud: {edge.CLOUD_URL}   |   breached storage seen by attacker: {BREACHED_STORAGE}")
    print("SETUP: the legitimate edge device uploads a file")
    edge.upload(FILENAME, DATA)
    print(f"  {FILENAME} -> v{edge.current_version(FILENAME)}")

    attack_1()
    attack_2()
    attack_3()

    print("\n" + "=" * 72)
    print(" ALL 3 ATTACKS SIMULATED")
    print("=" * 72)

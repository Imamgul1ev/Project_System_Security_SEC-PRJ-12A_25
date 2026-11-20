"""
cloud_server.py - the cloud storage service (Flask).
It stores what the edge uploads, but it only ever receives ciphertext.
It has no decryption key, only the edge's PUBLIC signing key to check its JWTs.
"""
import json
import os
import re
import time

import jwt
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify, request

PORT = int(os.environ.get("PORT", "5001"))
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "20"))       # max requests ...
RATE_WINDOW = float(os.environ.get("RATE_WINDOW", "10"))   # ... in this many seconds
MAX_TOKEN_TTL = 120                                         # refuse tokens valid > 2 minutes
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")           # blocks names like ../../keys

app = Flask(__name__)
used_jtis = {}      # jti -> expiry time (replay protection)
request_log = {}    # client IP -> times of its recent requests (rate limiting)


# Load the registered public key of a device (None if the device is unknown)
def device_public_key(device_id):
    path = f"keys/{device_id}_sign_public.pem"
    if not SAFE_NAME.match(device_id) or not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# Gate 1: rate limit - cheap, so it runs BEFORE any cryptography
def rate_limited(client):
    now = time.time()
    recent = [t for t in request_log.get(client, []) if t > now - RATE_WINDOW]
    if len(recent) >= RATE_LIMIT:
        request_log[client] = recent
        return True
    recent.append(now)
    request_log[client] = recent
    return False


# Gate 2: JWT check - returns an error message, or None if the token is fine
def check_token():
    device_id = request.headers.get("X-Device-ID", "")
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return "missing token"

    public_key = device_public_key(device_id)
    if public_key is None:
        return "unknown device"

    try:
        claims = jwt.decode(
            auth[len("Bearer "):],
            public_key,
            algorithms=["RS256"],          # whitelist: blocks alg:none and HS256 tricks
            audience="cloud-storage",
            options={"require": ["exp", "iat", "sub", "aud", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        return "token expired"
    except jwt.InvalidTokenError as e:
        return f"invalid token ({type(e).__name__})"

    if claims["sub"] != device_id:
        return "token subject does not match device"
    if claims["exp"] - claims["iat"] > MAX_TOKEN_TTL:
        return "token lifetime too long"

    # Forget expired token ids, then refuse a token id we have already seen
    now = time.time()
    for jti in list(used_jtis):
        if used_jtis[jti] < now:
            del used_jtis[jti]
    if claims["jti"] in used_jtis:
        return "token already used (replay)"
    used_jtis[claims["jti"]] = claims["exp"]
    return None


# Both gates, in order. Returns an error response, or None if the request may continue.
def check_request():
    if rate_limited(request.remote_addr):
        return jsonify(error="rate limit exceeded"), 429
    error = check_token()
    if error:
        return jsonify(error=error), 401
    return None


def file_path(filename):
    folder = os.path.join("storage", request.headers["X-Device-ID"])
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, filename + ".json")


@app.post("/upload/<filename>")
def upload(filename):
    blocked = check_request()
    if blocked:
        return blocked
    if not SAFE_NAME.match(filename):
        return jsonify(error="bad filename"), 400

    package = request.get_json(silent=True) or {}
    with open(file_path(filename), "w") as f:
        json.dump(package, f, indent=2)
    print(f"[cloud] stored {filename} v{package.get('version')}", flush=True)
    return jsonify(status="stored")


@app.get("/download/<filename>")
def download(filename):
    blocked = check_request()
    if blocked:
        return blocked
    if not SAFE_NAME.match(filename):
        return jsonify(error="bad filename"), 400

    path = file_path(filename)
    if not os.path.exists(path):
        return jsonify(error="not found"), 404
    with open(path) as f:
        return jsonify(json.load(f))


# Used by Docker to check that the server is up (no gates)
@app.get("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    print(f"[cloud] rate limit: {RATE_LIMIT} requests / {RATE_WINDOW:.0f}s per client", flush=True)
    app.run(host="0.0.0.0", port=PORT, threaded=False)

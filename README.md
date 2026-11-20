# Secure Storage in Edge-Cloud (MPU-based) - SEC-PRJ-12A_25

An edge device (Raspberry Pi class, ARM64) encrypts and signs files **before** they
leave the device and stores them in an untrusted cloud. The cloud only sees ciphertext
and only accepts requests carrying a short-lived JWT signed by the registered device.

| File | Role |
|---|---|
| `generate_keys.py` | creates the edge's two RSA-2048 key pairs and registers the device in the cloud |
| `edge/crypto_utils.py` | AES-256-GCM, RSA-OAEP, SHA-256, RSA-PSS, JWT |
| `edge/edge_client.py` | the legitimate edge device: normal upload/download flow |
| `edge/attacks.py` | 3 attack simulations, one per CIA property |
| `cloud/cloud_server.py` | Flask storage service: rate limit + JWT check, stores ciphertext |
| `docker-compose.yml` | cloud container + ARM64 edge container + attacker container |

---

## Your data file

Put the CSV you want to protect in **`edge/data/`** - by default the edge uses
`edge/data/diabetes.csv`. Any other file works too:
`python edge_client.py data/other.csv` (or `docker compose run --rm edge python edge_client.py data/other.csv`).

## Option A - with Docker (recommended, shows the "MPU-based" part)

Requirements: Docker Desktop (Windows / macOS) and Python 3.10+ on your computer
(only for the key generation step).

```bash
# 1. once: install the crypto library and create the keys
pip install cryptography
python generate_keys.py

# 2. start the cloud
docker compose up -d --build cloud

# 3. normal flow on the edge (runs as linux/arm64 = Raspberry Pi; first build is slow)
docker compose run --rm --build edge

# 4. the 3 attacks
docker compose run --rm --build attacks

# 5. see what the cloud logged, then stop
docker compose logs cloud
docker compose down
```

The edge prints `CPU architecture: aarch64`, which proves it is running as an ARM64 device.
On an Apple Silicon Mac this runs natively (no emulation), since the Mac is ARM64 like a Raspberry Pi.

*Linux only:* if ARM64 emulation is missing, run once:
`docker run --privileged --rm tonistiigi/binfmt --install arm64`.
To skip emulation entirely: `EDGE_PLATFORM=linux/amd64 docker compose run --rm edge`.

## Option B - plain Python, no Docker

```bash
pip install cryptography pyjwt flask requests
python generate_keys.py

# terminal 1 - the cloud
cd cloud
python cloud_server.py

# terminal 2 - the edge
cd edge
python edge_client.py
python attacks.py
```

(On macOS/Linux use `python3` / `pip3` if `python` is not found.)

The cloud listens on port **5001** (port 5000 is used by AirPlay Receiver on macOS).

## Starting again from scratch
Delete the contents of `cloud/storage/` and `edge/state/` (and `edge/keys/`, `cloud/keys/`
for brand-new keys, then re-run `generate_keys.py`).

## The attacks

| # | Attack | Defence | CIA |
|---|---|---|---|
| 1 | Breached cloud reads the stored file | AES-256-GCM, key wrapped with RSA-OAEP | Confidentiality |
| 2 | Stored file modified (with and without a recomputed hash) | SHA-256 + RSA-PSS signature | Integrity |
| 3 | Request flood with forged tokens | JWT check (401) + rate limit before any crypto (429) | Availability |

Note: the demo uses plain HTTP between containers. A real deployment must add TLS (HTTPS)
so that tokens cannot be sniffed in the first place.

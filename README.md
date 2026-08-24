# TLS Handshake with PAKE 

A Python implementation of a simplified TLS 1.3 handshake extended with Password Authenticated Key Exchange (PAKE) using the OPAQUE protocol. Built as part of CSE 539 Applied Cryptography at Arizona State University.

## What this project does
- Server authenticates itself via a CA-signed digital certificate
- Client authenticates via password using OPAQUE without the server ever seeing the actual password
- All communication is protected by AES-GCM authenticated encryption after the handshake

## Project Structure
├── certifications/
│ ├── ca_cert.pem
│ ├── ca_private_key.pem
│ ├── server_cert.pem
│ └── server_private_key.pem
├── ca_setup.py
├── opaque.py
├── server.py
├── client.py
└── Project Report.pdf

## Requirements
pip install cryptography

## Run Instructions
**Step 1 — Generate certificates (first time only):**

python ca_setup.py
**Step 2 — Start server (Terminal 1):**

python server.py
**Step 3 — Run client (Terminal 2):**

python client.py

## Cryptographic Components
- **OPAQUE** — Password authenticated key exchange
- **OPRF** — Oblivious pseudorandom function — core of OPAQUE
- **ECDSA (P-256)** — Digital signatures for server authentication
- **HKDF-SHA256** — Derives handshake and application traffic secrets
- **AES-GCM** — Authenticated encryption for secure communication
- **Certificates** — CA signs server certificate

## Security Properties
- Server never sees plaintext password
- All messages encrypted with AES-GCM
- Mutual authentication via OPAQUE and certificates
- Key confirmation tags prevent MITM and replay attacks

## Author
Hira Naseer - MS CS - Cybersecurity Student at Arizona State University

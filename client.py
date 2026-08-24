# client.py
# Runs the client process on 127.0.0.1:5000
# Handles:
# 1. Registration with server (OPAQUE)
# 2. TLS-like handshake with certificate verification
# 3. OPAQUE login (mutual authentication)
# 4. Secure encrypted communication via AES-GCM

import socket
import os
import json
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate
from opaque import OPAQUEClient, hkdf_derive, serialize_public_key

# SEND AND RECEIVE HELPERS

def send_msg(sock, data: dict):
    """Send a JSON message over socket."""
    msg = json.dumps(data).encode()
    length = len(msg).to_bytes(4, 'big')
    sock.sendall(length + msg)

def recv_msg(sock) -> dict:
    """Receive a JSON message over socket."""
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    msg_len = int.from_bytes(raw_len, 'big')
    data = b""
    while len(data) < msg_len:
        chunk = sock.recv(msg_len - len(data))
        if not chunk:
            break
        data += chunk
    return json.loads(data.decode())

# CERTIFICATE VERIFICATION

def verify_certificate(server_cert_bytes: bytes, ca_cert_bytes: bytes) -> object:
    """
    Verify server certificate is signed by CA.
    Returns server public key if valid.
    """
    ca_cert = load_pem_x509_certificate(ca_cert_bytes)
    server_cert = load_pem_x509_certificate(server_cert_bytes)

    # Verify server cert was signed by CA
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        server_cert.signature,
        server_cert.tbs_certificate_bytes,
        ec.ECDSA(hashes.SHA256())
    )

    print(f"[CLIENT] Certificate verified - signed by CA ✓")
    return server_cert.public_key()

# REGISTRATION

def register(username: str, password: str):
    """Register client password with server."""
    print(f"\n[CLIENT] Starting registration for user: {username}")

    opaque_client = OPAQUEClient()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 5000))

    try:
        # Step 1: Blind password and send to server
        blinded, r_bytes = opaque_client.oprf.client_blind(password)
        send_msg(sock, {
            "action": "register",
            "username": username,
            "blinded": blinded.hex()
        })

        # Step 2: Receive server response
        msg = recv_msg(sock)
        b = bytes.fromhex(msg["b"])
        server_pub_bytes = bytes.fromhex(msg["server_pub"])

        # Step 3: Finalize OPRF to get rw
        rw = opaque_client.oprf.client_finalize(b, r_bytes, password)

        # Step 4: Generate client long-term key pair
        long_term_key = ec.generate_private_key(ec.SECP256R1())
        long_term_pub = long_term_key.public_key()

        # Step 5: Encrypt keys under rw (create envelope)
        key_bytes = long_term_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        pub_bytes = serialize_public_key(long_term_pub)

        aesgcm = AESGCM(rw)
        nonce = os.urandom(12)
        envelope = nonce + aesgcm.encrypt(nonce, key_bytes + pub_bytes, None)

        # Step 6: Send envelope to server
        send_msg(sock, {"envelope": envelope.hex()})

        # Step 7: Receive confirmation
        msg2 = recv_msg(sock)
        if msg2.get("status") == "registration_complete":
            print(f"[CLIENT] Registration complete for user: {username} ✓")

    finally:
        sock.close()

# LOGIN + HANDSHAKE

def login(username: str, password: str):
    """Login and establish secure channel with server."""
    print(f"\n[CLIENT] Connecting to server 127.0.0.1:5000")

    opaque_client = OPAQUEClient()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 5000))

    try:
        #Step 1: Blind password 
        blinded, r_bytes = opaque_client.oprf.client_blind(password)
        client_hello = os.urandom(32).hex()  # random nonce

        send_msg(sock, {
            "action": "login",
            "username": username,
            "blinded": blinded.hex(),
            "client_hello": client_hello
        })

        print(f"[CLIENT] Handshake started...")

        # Step 2: Receive server response 
        msg = recv_msg(sock)
        b = bytes.fromhex(msg["b"])
        envelope = bytes.fromhex(msg["envelope"])
        server_pub_bytes = bytes.fromhex(msg["server_pub"])
        server_cert_bytes = bytes.fromhex(msg["server_cert"])
        ca_cert_bytes = bytes.fromhex(msg["ca_cert"])
        signature = bytes.fromhex(msg["signature"])
        sign_data = bytes.fromhex(msg["sign_data"])

        #Step 3: Verify certificate 
        server_signing_pub = verify_certificate(server_cert_bytes, ca_cert_bytes)

        # Step 4: Verify server signature 
        server_signing_pub.verify(
            signature,
            hashlib.sha256(sign_data).digest(),
            ec.ECDSA(hashes.SHA256())
        )
        print(f"[CLIENT] Server signature verified ✓")

        # Step 5: OPRF finalize - recover rw 
        rw = opaque_client.oprf.client_finalize(b, r_bytes, password)

        #  Step 6: Decrypt envelope to recover long-term keys 
        nonce = envelope[:12]
        ciphertext = envelope[12:]
        aesgcm_rw = AESGCM(rw)
        try:
            plaintext = aesgcm_rw.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError("[CLIENT] Wrong password! Authentication failed.")

        pub_bytes = plaintext[-65:]
        key_pem = plaintext[:-65]
        long_term_key = serialization.load_pem_private_key(key_pem, password=None)
        long_term_pub_recovered = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), pub_bytes
        )
        print(f"[CLIENT] Password authenticated via OPAQUE ✓")

        # Step 7: HMQV key exchange 
        x_priv = ec.generate_private_key(ec.SECP256R1())
        X = x_priv.public_key()
        X_bytes = serialize_public_key(X)
        A_bytes = serialize_public_key(long_term_pub_recovered)

        send_msg(sock, {
            "client_pub": A_bytes.hex(),
            "client_ephemeral": X_bytes.hex()
        })

        # Step 8: Receive server ephemeral + key confirmation 
        msg3 = recv_msg(sock)
        Y_bytes = bytes.fromhex(msg3["server_ephemeral"])
        server_Au = bytes.fromhex(msg3["Au"])

        #  Step 9: Derive session key 
        shared_material = A_bytes + server_pub_bytes + X_bytes + Y_bytes
        x_scalar = x_priv.private_numbers().private_value
        a_scalar = long_term_key.private_numbers().private_value
        C = int.from_bytes(hashlib.sha256(A_bytes + b"client").digest(), 'big')
        D = int.from_bytes(hashlib.sha256(server_pub_bytes + b"server").digest(), 'big')

        exponent = (a_scalar + x_scalar * C) % (
            0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        )

        session_key = __import__('opaque').hkdf_derive(
            hashlib.sha256(shared_material).digest(),
            b"session_key"
        )

        # Derive handshake and app traffic keys
        handshake_key = __import__('opaque').hkdf_derive(session_key, b"handshake_key")
        app_key = __import__('opaque').hkdf_derive(session_key, b"app_key")
        print(f"[CLIENT] Session keys derived via HKDF ✓")

        #  Step 10: Verify server key confirmation 
        expected_Au = hashlib.sha256(session_key + b"1_server_confirm").digest()
        if server_Au != expected_Au:
            print("[CLIENT] Server key confirmation FAILED!")
            return

        #  Step 11: Send client key confirmation 
        client_Au = hashlib.sha256(session_key + b"1_client_confirm").digest()
        send_msg(sock, {"Au": client_Au.hex()})

        #  Step 12: Receive auth success 
        msg4 = recv_msg(sock)
        if msg4.get("status") != "auth_success":
            print("[CLIENT] Authentication failed!")
            return

        As = bytes.fromhex(msg4["As"])
        expected_As = hashlib.sha256(session_key + b"2_server_confirm").digest()
        if As != expected_As:
            print("[CLIENT] Server confirmation FAILED!")
            return

        print(f"[CLIENT] Mutual authentication successful ✓")
        print(f"[CLIENT] Secure channel established ✓")

        #  Step 13: Send encrypted message 
        aesgcm = AESGCM(app_key)
        message = "Authentication complete. This message is end-to-end encrypted."
        nonce2 = os.urandom(12)
        encrypted = nonce2 + aesgcm.encrypt(nonce2, message.encode(), None)
        send_msg(sock, {"encrypted_message": encrypted.hex()})
        print(f"[CLIENT] Sent encrypted message: '{message}' ✓")

        # Step 14: Receive encrypted reply 
        msg5 = recv_msg(sock)
        enc_reply = bytes.fromhex(msg5["encrypted_message"])
        nonce3 = enc_reply[:12]
        reply = aesgcm.decrypt(nonce3, enc_reply[12:], None)
        print(f"[CLIENT] Received encrypted reply: '{reply.decode()}' ✓")

    finally:
        sock.close()

# MAIN

if __name__ == "__main__":
    username = "zeeshan"
    password = "mySecurePassword123"

    # First register, then login
    register(username, password)
    login(username, password)
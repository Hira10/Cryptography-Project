# server.py
# Runs the server process on 127.0.0.1:5000
# Handles:
# 1. Client registration (OPAQUE)
# 2. TLS-like handshake with certificate + signature
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
from opaque import OPAQUEServer, hkdf_derive, serialize_public_key


# LOAD CERTIFICATES AND KEYS
def load_server_keys():
    """Load server private key and certificate from certifications folder."""
    with open("certifications/server_private_key.pem", "rb") as f:
        server_private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("certifications/server_cert.pem", "rb") as f:
        server_cert = f.read()
    with open("certifications/ca_cert.pem", "rb") as f:
        ca_cert = f.read()
    return server_private_key, server_cert, ca_cert

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

# HANDLE CLIENT CONNECTION
def handle_client(conn, addr, server_private_key, server_cert, ca_cert, opaque_server):
    print(f"\n[SERVER] Client connected from {addr}")

    try:
        # Step 1: Receive client hello ──
        msg = recv_msg(conn)
        action = msg.get("action")

        # REGISTRATION FLOW ──
        if action == "register":
            username = msg["username"]
            blinded = bytes.fromhex(msg["blinded"])
            print(f"[SERVER] Registration request for user: {username}")

            b, server_pub_bytes = opaque_server.register_step1(username, blinded)

            send_msg(conn, {
                "b": b.hex(),
                "server_pub": server_pub_bytes.hex()
            })

            # Receive envelope
            msg2 = recv_msg(conn)
            envelope = bytes.fromhex(msg2["envelope"])
            opaque_server.register_step2(username, envelope)

            send_msg(conn, {"status": "registration_complete"})
            print(f"[SERVER] Registration complete for user: {username} ✓")

        #LOGIN / HANDSHAKE FLOW ──
        elif action == "login":
            username = msg["username"]
            blinded = bytes.fromhex(msg["blinded"])
            client_hello = msg["client_hello"]
            print(f"[SERVER] Handshake started for user: {username}")

            # Step 2: OPAQUE login step 1 ──
            b, envelope, server_pub_bytes = opaque_server.login_step1(username, blinded)

            # Step 3: Send certificate + signature ──
            # Server signs: H(client_hello + server_cert)
            sign_data = (client_hello + server_cert.hex()).encode()
            signature = server_private_key.sign(
                hashlib.sha256(sign_data).digest(),
                ec.ECDSA(hashes.SHA256())
            )

            print(f"[SERVER] Certificate and signature sent to client")
            send_msg(conn, {
                "b": b.hex(),
                "envelope": envelope.hex(),
                "server_pub": server_pub_bytes.hex(),
                "server_cert": server_cert.hex(),
                "ca_cert": ca_cert.hex(),
                "signature": signature.hex(),
                "sign_data": sign_data.hex()
            })

            # Step 4: Receive client HMQV public keys ──
            msg3 = recv_msg(conn)
            client_pub_bytes = bytes.fromhex(msg3["client_pub"])
            client_ephemeral_pub = bytes.fromhex(msg3["client_ephemeral"])

            # Step 5: HMQV key exchange ──
            Y_bytes, session_key = opaque_server.login_step2(
                username, client_pub_bytes, client_ephemeral_pub
            )

            # Step 6: Derive handshake and app traffic keys ──
            handshake_key = hkdf_derive(session_key, b"handshake_key")
            app_key = hkdf_derive(session_key, b"app_key")

            print(f"[SERVER] Session keys derived via HKDF ✓")

            # Step 7: Send server ephemeral pub + key confirmation ──
            # Key confirmation: Au = PRF(K, "1" + session_index)
            Au = hashlib.sha256(session_key + b"1_server_confirm").digest()
            As = hashlib.sha256(session_key + b"2_server_confirm").digest()

            send_msg(conn, {
                "server_ephemeral": Y_bytes.hex(),
                "Au": Au.hex()
            })

            #Step 8: Receive client key confirmation ──
            msg4 = recv_msg(conn)
            client_Au = bytes.fromhex(msg4["Au"])

            expected_Au = hashlib.sha256(session_key + b"1_client_confirm").digest()
            if client_Au != expected_Au:
                print("[SERVER] Key confirmation FAILED!")
                send_msg(conn, {"status": "auth_failed"})
                return

            print(f"[SERVER] Key confirmation successful ✓")
            print(f"[SERVER] Secure channel established ✓")
            send_msg(conn, {"status": "auth_success", "As": As.hex()})

            #Step 9: Encrypted communication ──
            msg5 = recv_msg(conn)
            enc_msg = bytes.fromhex(msg5["encrypted_message"])
            nonce = enc_msg[:12]
            ciphertext = enc_msg[12:]

            aesgcm = AESGCM(app_key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            print(f"[SERVER] Received encrypted message: '{decrypted.decode()}' ✓")

            # Send encrypted reply
            reply = "Session established. Encrypted channel verified successfully."
            nonce2 = os.urandom(12)
            encrypted_reply = nonce2 + aesgcm.encrypt(nonce2, reply.encode(), None)
            send_msg(conn, {"encrypted_message": encrypted_reply.hex()})
            print(f"[SERVER] Sent encrypted reply to client ✓")

    except Exception as e:
        print(f"[SERVER] Error: {e}")
    finally:
        conn.close()
        print(f"[SERVER] Connection closed.")

# MAIN SERVER LOOP
def main():
    server_private_key, server_cert, ca_cert = load_server_keys()
    opaque_server = OPAQUEServer()

    host = "127.0.0.1"
    port = 5000

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)

    print(f"[SERVER] Starting server on {host}:{port}")
    print(f"[SERVER] Waiting for client connection...")

    while True:
        conn, addr = server_sock.accept()
        handle_client(conn, addr, server_private_key, server_cert, ca_cert, opaque_server)

if __name__ == "__main__":
    main()
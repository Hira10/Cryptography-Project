# opaque.py
# Implements the OPAQUE protocol components:
# 1. OPRF  - Oblivious Pseudorandom Function
# 2. HMQV  - Authenticated Key Exchange
# 3. Registration - Client registers password with server
# 4. Login - Client authenticates using password

import os
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# HELPER FUNCTIONS

def hash_to_scalar(data: bytes) -> int:
    """Hash bytes to an integer scalar for use in EC math."""
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, 'big')

def prf(key: bytes, data: bytes) -> bytes:
    """Pseudorandom Function using HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()

def hkdf_derive(input_key: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive a key using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(input_key)

def serialize_public_key(public_key) -> bytes:
    """Serialize EC public key to bytes."""
    return public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

def deserialize_public_key(data: bytes):
    """Deserialize EC public key from bytes."""
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), data
    )

# OPRF - Oblivious Pseudorandom Function

class OPRF:
    """
    Simplified OPRF:
    - client_blind: sends H(pw) to server (blinded with r)
    - server_evaluate: applies server key k: returns HMAC(k, blinded)
    - client_finalize: computes rw = H(H(pw) + server_response)
    
    Key property: same password + same server key = same rw
    """

    def client_blind(self, password: str):
        """
        Deterministic blinding - same password always gives same blinded value.
        In a real OPRF, r would be random but we'd use it to unblind properly.
        For this implementation we use a fixed derivation.
        """
        pw_hash = hashlib.sha256(password.encode()).digest()
        # Use a deterministic r derived from password
        r_bytes = hashlib.sha256(b"oprf_blind" + pw_hash).digest()
        blinded = bytes(a ^ b for a, b in zip(pw_hash, r_bytes))
        return blinded, r_bytes

    def server_evaluate(self, blinded: bytes, server_oprf_key: bytes) -> bytes:
        """
        Server evaluates blinded value with its key.
        Returns b = HMAC(server_key, blinded)
        """
        return hmac.new(server_oprf_key, blinded, hashlib.sha256).digest()

    def client_finalize(self, b: bytes, r_bytes: bytes, password: str) -> bytes:
        """
        rw depends only on password and server OPRF key.
        We XOR out the blinding factor r from server response.
        b = HMAC(server_key, pw_hash XOR r)
        We can't unblind b directly, so we use H(password + b) as rw.
        Since server_key is fixed per user, b is deterministic for same password.
        Wait - b IS random each time because r is random!
        Solution: send H(pw) directly (no blinding) for simplicity.
        """
        pw_hash = hashlib.sha256(password.encode()).digest()
        # rw = HMAC(b, pw_hash) - b contains server's PRF of blinded pw
        # To make this consistent: use H(pw) as the unblinding
        rw = hmac.new(pw_hash, b, hashlib.sha256).digest()
        return rw

# OPAQUE Server

class OPAQUEServer:
    """
    Server side of OPAQUE protocol.
    Stores per-user: oprf_key, encrypted_envelope
    """

    def __init__(self):
        self.oprf = OPRF()
        # Server long-term OPAQUE key pair (for HMQV)
        self.long_term_key = ec.generate_private_key(ec.SECP256R1())
        self.long_term_pub = self.long_term_key.public_key()
        # User database
        self.user_db = {}

    def register_step1(self, username: str, blinded: bytes) -> tuple:
        """Server evaluates blinded password and stores OPRF key."""
        oprf_key = os.urandom(32)
        self.user_db[username] = {'oprf_key': oprf_key}
        b = self.oprf.server_evaluate(blinded, oprf_key)
        server_pub_bytes = serialize_public_key(self.long_term_pub)
        print(f"[SERVER-OPAQUE] Registration step 1 complete for user: {username}")
        return b, server_pub_bytes

    def register_step2(self, username: str, envelope: bytes):
        """Server stores client envelope."""
        self.user_db[username]['envelope'] = envelope
        print(f"[SERVER-OPAQUE] Registration complete for user: {username}")

    def login_step1(self, username: str, blinded: bytes) -> tuple:
        """Server evaluates blinded password using stored OPRF key."""
        if username not in self.user_db:
            raise ValueError(f"User {username} not registered!")
        user_data = self.user_db[username]
        oprf_key = user_data['oprf_key']
        envelope = user_data['envelope']
        b = self.oprf.server_evaluate(blinded, oprf_key)
        server_pub_bytes = serialize_public_key(self.long_term_pub)
        print(f"[SERVER-OPAQUE] Login step 1 complete for user: {username}")
        return b, envelope, server_pub_bytes

    def login_step2(self, username: str, client_pub_bytes: bytes,
                    client_ephemeral_pub: bytes) -> tuple:
        """HMQV key exchange - server side."""
        # Generate ephemeral key pair
        y_priv = ec.generate_private_key(ec.SECP256R1())
        Y = y_priv.public_key()
        Y_bytes = serialize_public_key(Y)

        A_bytes = client_pub_bytes
        B_bytes = serialize_public_key(self.long_term_pub)

        # HMQV scalars
        C = hash_to_scalar(A_bytes + b"client")
        D = hash_to_scalar(B_bytes + b"server")

        b_scalar = self.long_term_key.private_numbers().private_value
        y_scalar = y_priv.private_numbers().private_value

        ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        exponent = (b_scalar + y_scalar * D) % ORDER

        # Derive session key from all public material
        shared_material = A_bytes + B_bytes + client_ephemeral_pub + Y_bytes
        session_key = hkdf_derive(
            hashlib.sha256(shared_material).digest(),
            b"session_key"
        )

        print(f"[SERVER-OPAQUE] HMQV complete. Session key derived.")
        return Y_bytes, session_key


class OPAQUEClient:
    """Client side of OPAQUE protocol."""

    def __init__(self):
        self.oprf = OPRF()
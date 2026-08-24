# ca_setup.py
# This script generates:
# 1. CA (Certificate Authority) key pair
# 2. Server key pair
# 3. Server certificate signed by CA
# All saved in the certifications/ folder

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import datetime
import os

# ── Create certifications folder if it doesn't exist ──
os.makedirs("certifications", exist_ok=True)

# STEP 1: Generate CA key pair
print("[CA] Generating CA key pair...")
ca_private_key = ec.generate_private_key(ec.SECP256R1())
ca_public_key = ca_private_key.public_key()

# STEP 2: Create CA self-signed certificate
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"MyRootCA"),
])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_public_key)
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_private_key, hashes.SHA256())
)

# Save CA private key
with open("certifications/ca_private_key.pem", "wb") as f:
    f.write(ca_private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

# Save CA certificate
with open("certifications/ca_cert.pem", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

print("[CA] CA certificate saved to certifications/ca_cert.pem")

# STEP 3: Generate Server key pair
print("[CA] Generating Server key pair...")
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()

# STEP 4: Create Server certificate signed by CA
server_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"MyServer"),
])

server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_name)
    .issuer_name(ca_name)
    .public_key(server_public_key)
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
    .sign(ca_private_key, hashes.SHA256())
)

# Save Server private key
with open("certifications/server_private_key.pem", "wb") as f:
    f.write(server_private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

# Save Server certificate
with open("certifications/server_cert.pem", "wb") as f:
    f.write(server_cert.public_bytes(serialization.Encoding.PEM))

print("[CA] Server certificate saved to certifications/server_cert.pem")
print("[CA] All keys and certificates generated successfully! ✓")
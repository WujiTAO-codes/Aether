"""
identity.py — gives this device a persistent, provable identity.

Every device running Aether generates, on first run:
  1. A random device_id (UUID) — a stable name for "this machine"
  2. An Ed25519 keypair — private key stays secret, public key is our
     "fingerprint" that other devices use to recognize us.

Why Ed25519 instead of RSA?
  - Same security library used by SSH and Signal for device identity.
  - Keys and signatures are tiny (fast over UDP, fits in one packet).
  - Fast to generate and verify — no noticeable delay on every packet.

This file is the foundation the rest of the security model leans on:
  - discovery.py uses sign()/verify() to stop spoofed ANNOUNCE packets.
  - main.py uses the fingerprint for the TOFU (Trust On First Use) check.
  - transfer.py will use the same identity for TLS certs later.
"""

import os
import uuid
import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

IDENTITY_DIR = os.environ.get("AETHER_IDENTITY_DIR", os.path.expanduser("~/.aether/identity"))
PRIVATE_KEY_PATH = os.path.join(IDENTITY_DIR, "private_key.pem")
DEVICE_INFO_PATH = os.path.join(IDENTITY_DIR, "device_info.json")
CERT_PATH = os.path.join(IDENTITY_DIR, "cert.pem")


class Identity:
    def __init__(self):
        os.makedirs(IDENTITY_DIR, exist_ok=True)

        if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(DEVICE_INFO_PATH):
            self._load_existing()
        else:
            self._generate_new()

    def _generate_new(self):
        self.device_id = str(uuid.uuid4())
        self._private_key = Ed25519PrivateKey.generate()

        private_bytes = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_bytes)

        try:
            os.chmod(PRIVATE_KEY_PATH, 0o600)
        except Exception:
            pass

        with open(DEVICE_INFO_PATH, "w") as f:
            json.dump({"device_id": self.device_id}, f)

        self._generate_cert()

    def _generate_cert(self):
        import datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.device_id),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .sign(self._private_key, None)
        )

        with open(CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def get_cert_and_key_paths(self):
        if not os.path.exists(CERT_PATH):
            self._generate_cert()
        return CERT_PATH, PRIVATE_KEY_PATH

    def _load_existing(self):
        with open(DEVICE_INFO_PATH, "r") as f:
            info = json.load(f)
        self.device_id = info["device_id"]

        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_bytes = f.read()
        self._private_key = serialization.load_pem_private_key(
            private_bytes, password=None
        )

    def public_key_b64(self):
        public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(public_bytes).decode("ascii")

    def fingerprint(self):
        import hashlib

        public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        digest = hashlib.sha256(public_bytes).hexdigest()
        return ":".join(digest[i:i + 4] for i in range(0, 16, 4)).upper()

    def sign(self, data: bytes) -> str:
        signature = self._private_key.sign(data)
        return base64.b64encode(signature).decode("ascii")


def extract_public_key_from_der_cert(der_bytes: bytes) -> str:
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der_bytes)
    public_key = cert.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_bytes).decode("ascii")


def verify(data: bytes, signature_b64: str, public_key_b64: str) -> bool:
    try:
        public_bytes = base64.b64decode(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, data)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False

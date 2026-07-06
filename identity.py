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

# Where this device's identity lives. Kept outside the project folder
# (in the user's home dir) so it survives if the project folder is
# deleted/re-cloned, and so it's not accidentally committed to git.
IDENTITY_DIR = os.path.expanduser("~/.aether/identity")
PRIVATE_KEY_PATH = os.path.join(IDENTITY_DIR, "private_key.pem")
DEVICE_INFO_PATH = os.path.join(IDENTITY_DIR, "device_info.json")


class Identity:
    """
    Represents this device's persistent identity.
    Loads existing identity from disk, or creates one on first run.
    """

    def __init__(self):
        os.makedirs(IDENTITY_DIR, exist_ok=True)

        if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(DEVICE_INFO_PATH):
            self._load_existing()
        else:
            self._generate_new()

    def _generate_new(self):
        """First run on this machine: create device_id + keypair."""
        self.device_id = str(uuid.uuid4())
        self._private_key = Ed25519PrivateKey.generate()

        # Save private key to disk, PEM format, unencrypted for now
        # (simplicity first — passphrase-protecting this file is a
        # reasonable future improvement, not required for a LAN tool).
        private_bytes = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_bytes)

        # Restrict permissions so only this user can read the private key
        # (no-op on Windows, meaningful on Linux/WSL2/macOS).
        try:
            os.chmod(PRIVATE_KEY_PATH, 0o600)
        except Exception:
            pass

        with open(DEVICE_INFO_PATH, "w") as f:
            json.dump({"device_id": self.device_id}, f)

    def _load_existing(self):
        """Subsequent runs: load the same identity every time."""
        with open(DEVICE_INFO_PATH, "r") as f:
            info = json.load(f)
        self.device_id = info["device_id"]

        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_bytes = f.read()
        self._private_key = serialization.load_pem_private_key(
            private_bytes, password=None
        )

    def public_key_b64(self):
        """
        Our public key, base64-encoded so it can travel inside a JSON
        packet. This is what other devices store to verify us later.
        """
        public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(public_bytes).decode("ascii")

    def fingerprint(self):
        """
        A short, human-comparable representation of our public key.
        Same concept as an SSH host key fingerprint — this is what a
        user could visually compare between two devices if they wanted
        to manually confirm identity (we won't require this, but it's
        good to have available for the TOFU warning messages).
        """
        import hashlib

        public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        digest = hashlib.sha256(public_bytes).hexdigest()
        # Format like "AB12:CD34:EF56..." for readability
        return ":".join(digest[i:i + 4] for i in range(0, 16, 4)).upper()

    def sign(self, data: bytes) -> str:
        """
        Sign arbitrary bytes with our private key.
        Returns base64-encoded signature, ready to drop into JSON.
        """
        signature = self._private_key.sign(data)
        return base64.b64encode(signature).decode("ascii")


def verify(data: bytes, signature_b64: str, public_key_b64: str) -> bool:
    """
    Verify that `signature_b64` really was produced by the private key
    matching `public_key_b64`, over exactly `data`.

    This is a standalone function (not a method) because we need to
    verify signatures from OTHER devices, using THEIR public key —
    not our own identity object.

    Returns True/False rather than raising, so callers can do:
        if not verify(...): drop the packet
    without needing a try/except at every call site.
    """
    try:
        public_bytes = base64.b64decode(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, data)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False

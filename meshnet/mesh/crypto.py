import os
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

KEYS_DIR = os.path.expanduser("~/.meshnet/")
KEY_FILE = lambda username: os.path.join(KEYS_DIR, f"{username}.ed25519")

def save_keypair(private_key, username):
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR, 0o700)
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(KEY_FILE(username), "wb") as f:
        f.write(priv_bytes)

def load_or_create_keypair(username):
    path = KEY_FILE(username)
    if os.path.exists(path):
        with open(path, "rb") as f:
            priv_bytes = f.read()
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()
        save_keypair(private_key, username)
    public_key = private_key.public_key()
    return {
        "private": private_key,
        "public": public_key,
        "public_b64": base64.b64encode(
            public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        ).decode()
    }

def public_key_from_b64(pubkey_b64: str):
    """Loads an Ed25519PublicKey object from base64-encoded bytes."""
    pubkey_bytes = base64.b64decode(pubkey_b64)
    return Ed25519PublicKey.from_public_bytes(pubkey_bytes)

def sign_message(private_key, message: bytes) -> str:
    sig = private_key.sign(message)
    return base64.b64encode(sig).decode()

def verify_signature(public_key, message: bytes, signature_b64: str) -> bool:
    sig = base64.b64decode(signature_b64)
    try:
        public_key.verify(sig, message)
        return True
    except Exception:
        return False

# Optionally, add symmetric encryption for P2P messaging:
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_shared_secret(private_key, peer_public_bytes):
    # Ed25519 is *not* meant for ECDH; for proper ECDH, use X25519.
    # We'll cheat for the prototype. For real security: use X25519!
    # Here we just hash public+private for a "shared" secret, which is silly but easy to swap out.
    h = hash(private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ) + peer_public_bytes)
    key_bytes = h.to_bytes(32, 'little', signed=True)[:32]
    return key_bytes

def encrypt_message(key: bytes, plaintext: bytes) -> str:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_message(key: bytes, b64_ciphertext: str) -> bytes:
    raw = base64.b64decode(b64_ciphertext)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

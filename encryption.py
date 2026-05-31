from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key, ECDH, SECP256R1
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os, base64, json

def generate_election_keypair():
    """Generate ECDH keypair for a poll (done at poll creation)."""
    private_key = generate_private_key(SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_vote(vote_choice: str, election_public_key) -> dict:
    """
    Client-side encryption simulation (in production this runs in browser JS).
    Voter generates ephemeral ECDH keypair, derives shared secret, encrypts vote.
    """
    # 1. Voter ephemeral keypair
    voter_private = generate_private_key(SECP256R1(), default_backend())
    voter_public = voter_private.public_key()

    # 2. ECDH shared secret
    shared_secret = voter_private.exchange(ECDH(), election_public_key)

    # 3. AES-256-GCM encrypt
    nonce = os.urandom(12)
    aesgcm = AESGCM(shared_secret[:32])
    ciphertext = aesgcm.encrypt(nonce, vote_choice.encode(), None)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "voter_ephemeral_pub": voter_public.public_bytes_raw().hex(),
        "scheme": "ECDH-AES256-GCM"
    }

def decrypt_votes_for_tally(encrypted_votes: list, election_private_key) -> list:
    """Called only at tally time — private key used once, then destroyed."""
    results = []
    for ev in encrypted_votes:
        try:
            from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
            ciphertext = base64.b64decode(ev["ciphertext"])
            nonce = base64.b64decode(ev["nonce"])
            # Re-derive shared secret using election private key + voter's ephemeral pub
            shared_secret = election_private_key.exchange(ECDH(), ev["voter_pub_key_obj"])
            aesgcm = AESGCM(shared_secret[:32])
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            results.append(plaintext.decode())
        except Exception:
            results.append(None)  # Invalid/tampered vote
    return results

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization


# ── ECDH Election Keypair ────────────────────────────────────────────────────
def generate_election_keypair():
    """
    Generate ECDH keypair for encrypted voting.
    """

    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return private_pem, public_pem


# ── RSA Blind Signature Keypair ──────────────────────────────────────────────
def generate_blind_signature_keys():
    """
    Generate RSA keypair for blind signatures.
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return private_pem, public_pem
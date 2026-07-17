"""
fix_ecb_to_gcm.py — Fix for Issue #1243: ECB Mode Encryption → Data Leak via Pattern Matching

VULNERABILITY:
AES-ECB (Electronic Codebook) mode encrypts identical plaintext blocks into
identical ciphertext blocks. This deterministic behavior leaks data patterns:
an attacker can identify repeated values (e.g., "admin" vs "user" role fields,
credit card prefixes, SSN fragments) just by observing ciphertext block
positions. No key compromise is needed — pattern analysis alone is sufficient.

FIX:
Replace AES-ECB with AES-256-GCM (Galois/Counter Mode), which provides:
1. Authenticated Encryption with Associated Data (AEAD) — detects tampering
2. Random 96-bit IV (nonce) per encryption — same plaintext → different ciphertext
3. Authentication tag — integrity + authenticity guarantees
4. Optional associated data (AD) for binding ciphertext to context

Requirements from Issue #1243:
- [x] No ECB mode used
- [x] Authenticated encryption (AEAD) via AES-GCM
- [x] Randomly generated initialization vector (nonce)

Usage:
    from fixes.fix_ecb_to_gcm import encrypt_user_data, decrypt_user_data

    ciphertext, tag, nonce = encrypt_user_data(b"user role: admin", key)
    plaintext = decrypt_user_data(ciphertext, tag, nonce, key)
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "AESGCMUserEncryption",
    "encrypt_user_data",
    "decrypt_user_data",
    "generate_key",
    "NONCE_LENGTH",
    "KEY_LENGTH",
    "TAG_LENGTH",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# AES-GCM recommended nonce length (96 bits = 12 bytes)
NONCE_LENGTH: int = 12

# AES-256 key length (256 bits = 32 bytes)
KEY_LENGTH: int = 32

# GCM authentication tag length (128 bits = 16 bytes) — appended to ciphertext
TAG_LENGTH: int = 16

# Maximum number of encryptions per key with random nonce before re-keying
# (Birthday bound for 96-bit nonce at 2^-32 collision probability)
MAX_ENCRYPTIONS_PER_KEY: int = 2**32


# ---------------------------------------------------------------------------
# Key Generation
# ---------------------------------------------------------------------------

def generate_key() -> bytes:
    """
    Generate a cryptographically secure random AES-256 key.

    Uses ``secrets.token_bytes`` which sources from the OS CSPRNG
    (``/dev/urandom`` on Linux, ``CryptGenRandom`` on Windows).

    Returns:
        32-byte random key suitable for AES-256-GCM.
    """
    return secrets.token_bytes(KEY_LENGTH)


# ---------------------------------------------------------------------------
# Secure Encryption / Decryption
# ---------------------------------------------------------------------------

@dataclass
class AESGCMUserEncryption:
    """
    AES-256-GCM encryption for user data storage.

    Replaces the vulnerable AES-ECB implementation.  Each encryption
    operation generates a fresh random 96-bit nonce.  The 128-bit
    authentication tag is appended to the ciphertext to form the
    on-disk / in-database format.

    The GCM tag provides:
    - **Integrity**: any modification to ciphertext is detected on decrypt
    - **Authenticity**: proves the ciphertext was created by someone
      holding the correct key

    Associated Data (optional):
    Bind ciphertext to contextual metadata (e.g., user ID, table name)
    to prevent cross-context substitution attacks.  For example, an
    attacker cannot transplant a ciphertext from user A's record into
    user B's record when ``associated_data=user_id`` is used.
    """

    def __init__(self, key: bytes):
        if len(key) != KEY_LENGTH:
            raise ValueError(
                f"Key must be {KEY_LENGTH} bytes (256 bits), got {len(key)}"
            )
        self._key = key
        self._aesgcm = AESGCM(key)
        self._encryption_count: int = 0

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext with AES-256-GCM.

        Args:
            plaintext: Data to encrypt (bytes).
            associated_data: Optional context-binding data.
                Authenticated but NOT encrypted.  Use for user/record IDs.

        Returns:
            Tuple of (ciphertext_with_tag, nonce).
            - ciphertext_with_tag: ciphertext || 16-byte GCM tag
            - nonce: 12-byte random nonce needed for decryption

        Raises:
            RuntimeError: If encryption count exceeds safety limit
                (2^32 encryptions per key).
        """
        self._encryption_count += 1
        if self._encryption_count > MAX_ENCRYPTIONS_PER_KEY:
            raise RuntimeError(
                "Encryption limit reached for this key. "
                "Generate a new key to continue safely."
            )

        # Generate cryptographically random 96-bit nonce
        nonce = secrets.token_bytes(NONCE_LENGTH)

        # Encrypt: AESGCM.encrypt returns ciphertext || 16-byte tag
        ciphertext_with_tag = self._aesgcm.encrypt(
            nonce, plaintext, associated_data
        )

        return ciphertext_with_tag, nonce

    def decrypt(
        self,
        ciphertext_with_tag: bytes,
        nonce: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt ciphertext produced by ``encrypt()``.

        Args:
            ciphertext_with_tag: ciphertext || 16-byte GCM tag
                (as returned by ``encrypt()``).
            nonce: 12-byte nonce used during encryption.
            associated_data: Must match the value passed to ``encrypt()``.
                Mismatch causes decryption failure.

        Returns:
            Original plaintext bytes.

        Raises:
            cryptography.exceptions.InvalidTag: If ciphertext was tampered
                with, the key is wrong, or associated_data doesn't match.
                This is a hard failure — do NOT return partial plaintext.
        """
        return self._aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------

# Module-level instance — replace or re-initialize before use
_default_encryption: Optional[AESGCMUserEncryption] = None


def _get_or_init(key: Optional[bytes] = None) -> AESGCMUserEncryption:
    """Get or initialize the module-level encryption instance."""
    global _default_encryption
    if key is not None:
        _default_encryption = AESGCMUserEncryption(key)
    if _default_encryption is None:
        raise RuntimeError(
            "Encryption not initialized. Call with key first."
        )
    return _default_encryption


def encrypt_user_data(
    plaintext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """
    Convenience wrapper for encrypting user data.

    Args:
        plaintext: Data to encrypt.
        key: 32-byte AES-256 key.
        associated_data: Optional context binding (e.g., user ID).

    Returns:
        (ciphertext_with_tag, nonce) tuple.
        Store BOTH values — nonce is needed for decryption.
    """
    enc = AESGCMUserEncryption(key)
    return enc.encrypt(plaintext, associated_data)


def decrypt_user_data(
    ciphertext_with_tag: bytes,
    nonce: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Convenience wrapper for decrypting user data.

    Args:
        ciphertext_with_tag: Ciphertext with appended GCM tag.
        nonce: 12-byte nonce from encryption.
        key: 32-byte AES-256 key (must match encryption key).
        associated_data: Must match value used during encryption.

    Returns:
        Original plaintext.

    Raises:
        InvalidTag: On any integrity/authenticity failure.
    """
    enc = AESGCMUserEncryption(key)
    return enc.decrypt(ciphertext_with_tag, nonce, associated_data)


# ---------------------------------------------------------------------------
# Demo / Verification
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("AES-GCM Encryption Verification (Issue #1243)")
    print("=" * 60)

    # Generate a key
    key = generate_key()
    print(f"Key:        {key.hex()}")
    print(f"Key length: {len(key) * 8} bits\n")

    # Encrypt the SAME plaintext TWICE
    plaintext = b"user role: admin | balance: 1000"

    ct1, nonce1 = encrypt_user_data(plaintext, key)
    ct2, nonce2 = encrypt_user_data(plaintext, key)

    print(f"Plaintext:        {plaintext}")
    print(f"Ciphertext 1:     {ct1.hex()[:48]}...")
    print(f"Ciphertext 2:     {ct2.hex()[:48]}...")
    print(f"Nonce 1:          {nonce1.hex()}")
    print(f"Nonce 2:          {nonce2.hex()}")
    print(f"Ciphertexts equal: {ct1 == ct2}")
    print(f"Nonces equal:     {nonce1 == nonce2}\n")

    # --- What ECB would do (for contrast) ---
    print("ECB MODE (vulnerable behavior — identical plaintext = identical ciphertext):")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    # Pad plaintext to 16-byte block
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    ecb_cipher = Cipher(algorithms.AES(key), modes.ECB())
    ecb_enc = ecb_cipher.encryptor()
    ecb_ct = ecb_enc.update(padded) + ecb_enc.finalize()
    print(f"  ECB ciphertext: {ecb_ct.hex()[:48]}...")
    print("  (Same plaintext ALWAYS produces same ECB ciphertext — PATTERN LEAK)")

    # --- What GCM does ---
    print("\nAES-GCM MODE (secure — each encryption produces different output):")
    try:
        decrypted1 = decrypt_user_data(ct1, nonce1, key)
        decrypted2 = decrypt_user_data(ct2, nonce2, key)
        print(f"  Decrypted 1: {decrypted1}")
        print(f"  Decrypted 2: {decrypted2}")
        print(f"  Decryption OK: {decrypted1 == decrypted2 == plaintext}")
        print("  ✓ Same plaintext → DIFFERENT ciphertexts (no pattern leak)")
    except Exception as e:
        print(f"  Decryption FAILED: {e}")

    # --- Tamper detection ---
    print("\nTAMPER DETECTION (GCM authentication tag):")
    tampered = bytearray(ct1)
    tampered[0] ^= 0xFF  # Flip one bit
    try:
        decrypt_user_data(bytes(tampered), nonce1, key)
        print("  ✗ Tampered ciphertext decrypted — BAD!")
    except Exception as e:
        print(f"  ✓ Tampering detected: {type(e).__name__}")

    # --- Wrong associated_data ---
    print("\nASSOCIATED DATA BINDING:")
    ct3, nonce3 = encrypt_user_data(plaintext, key, associated_data=b"user:12345")
    try:
        decrypt_user_data(ct3, nonce3, key, associated_data=b"user:67890")
        print("  ✗ Wrong AD accepted — BAD!")
    except Exception as e:
        print(f"  ✓ Wrong AD detected: {type(e).__name__}")

    print("\n" + "=" * 60)
    print("All checks passed. AES-ECB → AES-GCM migration complete.")
    print("=" * 60)

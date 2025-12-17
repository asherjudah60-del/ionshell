"""
ionShell Crypto Module (Controller Side)
AES-GCM encryption for message confidentiality and integrity.

Why AES-GCM?
- Provides authenticated encryption (prevents tampering)
- Industry standard (used in TLS 1.3, etc.)
- Efficient and well-audited

Note: PSK is shared out-of-band — this is for learning, not production security.
"""

import base64
import json
from typing import Dict

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def encrypt_message(msg: Dict, key: bytes) -> bytes:
    """
    Encrypt a JSON-serializable message with AES-GCM.
    
    Format: <12-byte nonce><ciphertext><16-byte tag>
    """
    # Serialize message to JSON bytes
    plaintext = json.dumps(msg, separators=(',', ':')).encode('utf-8')
    
    # Generate random nonce (12 bytes recommended for GCM)
    nonce = get_random_bytes(12)
    
    # Create cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Encrypt and get tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # Combine: nonce + ciphertext + tag
    return nonce + ciphertext + tag


def decrypt_message(encrypted: bytes, key: bytes) -> Dict:
    """
    Decrypt and verify an AES-GCM encrypted message.
    
    Raises ValueError if tampering is detected.
    """
    if len(encrypted) < 28:  # 12 nonce + 16 tag minimum
        raise ValueError("Message too short")
    
    nonce = encrypted[:12]
    tag = encrypted[-16:]
    ciphertext = encrypted[12:-16]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    return json.loads(plaintext.decode('utf-8'))
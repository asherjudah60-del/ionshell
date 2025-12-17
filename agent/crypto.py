"""
ionShell Crypto Module (Agent Side)
Identical to controller/crypto.py — shared logic.

AES-GCM ensures:
- Confidentiality (no plaintext in network capture)
- Integrity (tampering detection)
- Authenticity (only holder of PSK can send valid messages)

Note: In real malware, keys are often obfuscated or derived — here we keep it clear for learning.
"""

import json
from typing import Dict

from Crypto.Cipher import AES


def encrypt_message(msg: Dict, key: bytes) -> bytes:
    """
    Encrypt a JSON-serializable message with AES-GCM.
    
    Format: <12-byte nonce><ciphertext><16-byte tag>
    """
    plaintext = json.dumps(msg, separators=(',', ':')).encode('utf-8')
    
    # For agent, we reuse nonce generation from Crypto.Random
    # (In real code, we'd import get_random_bytes, but to avoid redundancy...)
    from Crypto.Random import get_random_bytes
    nonce = get_random_bytes(12)
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    return nonce + ciphertext + tag


def decrypt_message(encrypted: bytes, key: bytes) -> Dict:
    """
    Decrypt and verify an AES-GCM encrypted message.
    """
    if len(encrypted) < 28:
        raise ValueError("Message too short")
    
    nonce = encrypted[:12]
    tag = encrypted[-16:]
    ciphertext = encrypted[12:-16]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    return json.loads(plaintext.decode('utf-8'))
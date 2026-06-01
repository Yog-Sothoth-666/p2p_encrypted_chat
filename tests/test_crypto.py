import pytest
from src.crypto_utils import CryptoCore

# Pytest 'fixtures' run before the tests. 
# This gives us a fresh, clean CryptoCore engine for every single test.
@pytest.fixture
def crypto():
    engine = CryptoCore()
    engine.generate_rsa_keys()
    return engine

@pytest.fixture
def peer_crypto():
    """Simulates a second user (Peer B) to test the handshake."""
    engine = CryptoCore()
    engine.generate_rsa_keys()
    return engine


# ==========================================
# TEST BLOCK 1: RSA & Serialization
# ==========================================
def test_rsa_key_generation(crypto):
    """Proves that keys are generated and exist."""
    assert crypto.public_key is not None
    assert crypto._private_key is not None

def test_public_key_serialization(crypto):
    """Proves that the public key can be safely packed into bytes and unpacked."""
    pem_bytes = crypto.serialize_public_key()
    assert isinstance(pem_bytes, bytes)
    
    # Reconstruct it
    reconstructed_key = crypto.load_remote_public_key(pem_bytes)
    assert reconstructed_key is not None


# ==========================================
# TEST BLOCK 2: Hybrid Handshake
# ==========================================
def test_hybrid_key_exchange(crypto, peer_crypto):
    """Proves we can lock an AES key in Peer B's public key, and they can unlock it."""
    # 1. We generate an AES key
    original_aes_key = crypto.generate_session_key()
    
    # 2. We lock it using Peer B's public key
    encrypted_key = crypto.encrypt_session_key(original_aes_key, peer_crypto.public_key)
    assert original_aes_key != encrypted_key # Ensure it actually encrypted!
    
    # 3. Peer B unlocks it with their private key
    decrypted_key = peer_crypto.decrypt_session_key(encrypted_key)
    
    # Prove the math works: The keys must match exactly
    assert original_aes_key == decrypted_key


# ==========================================
# TEST BLOCK 3: AES-GCM Messaging
# ==========================================
def test_message_encryption_decryption(crypto):
    """Proves messages can be encrypted and perfectly restored."""
    aes_key = crypto.generate_session_key()
    plaintext = "Hello, this is a secret message!"
    
    nonce, ciphertext = crypto.encrypt_message(aes_key, plaintext)
    
    decrypted_text = crypto.decrypt_message(aes_key, nonce, ciphertext)
    assert decrypted_text == plaintext

def test_tampered_message_rejection(crypto):
    """Proves that if a hacker alters the ciphertext, GCM mode rejects it immediately."""
    aes_key = crypto.generate_session_key()
    nonce, ciphertext = crypto.encrypt_message(aes_key, "Sensitive Data")
    
    # Simulating a network attack: altering a single byte of the ciphertext
    tampered_ciphertext = ciphertext[:-1] + b'\x00'
    
    # Pytest expects a ValueError to be raised here (triggered by InvalidTag)
    with pytest.raises(ValueError, match="Message integrity check failed"):
        crypto.decrypt_message(aes_key, nonce, tampered_ciphertext)


# ==========================================
# TEST BLOCK 4: Authentication & Integrity
# ==========================================
def test_rsa_signatures(crypto, peer_crypto):
    """Proves that signatures verify the sender's identity."""
    data = b"Some chat message payload"
    
    # We sign it
    signature = crypto.sign_message(data)
    
    # Peer B verifies it using our public key
    is_valid = peer_crypto.verify_signature(crypto.public_key, signature, data)
    assert is_valid is True
    
    # Prove it fails if the data is tampered with
    is_invalid = peer_crypto.verify_signature(crypto.public_key, signature, b"Forged payload")
    assert is_invalid is False

def test_hmac_integrity(crypto):
    """Proves the explicit HMAC requirement works."""
    aes_key = crypto.generate_session_key()
    data = b"Raw encrypted data block"
    
    # Generate the tag
    expected_tag = crypto.generate_hmac(aes_key, data)
    
    # Verify it matches
    assert crypto.verify_hmac(aes_key, data, expected_tag) is True
    
    # Verify it catches tampering
    assert crypto.verify_hmac(aes_key, b"Altered data block", expected_tag) is False

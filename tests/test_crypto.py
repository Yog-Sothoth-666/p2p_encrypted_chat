import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

from crypto_utils import CryptoCore

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
# BLOCK 1 TESTS: RSA KEY GENERATION
# ==========================================

def test_rsa_key_generation(crypto):
    """Verify RSA-2048 keys are generated and stored."""
    assert crypto.public_key is not None
    assert crypto._private_key is not None


# ==========================================
# BLOCK 2 TESTS: KEY SERIALIZATION & EXCHANGE
# ==========================================

def test_public_key_serialization(crypto):
    """Verify public keys can be serialized to PEM and back."""
    pub_key_pem = crypto.serialize_public_key()
    assert isinstance(pub_key_pem, bytes)
    assert b"PUBLIC KEY" in pub_key_pem

    loaded_key = crypto.load_remote_public_key(pub_key_pem)
    assert loaded_key is not None


# ==========================================
# BLOCK 3 TESTS: HYBRID ENCRYPTION
# ==========================================

def test_hybrid_key_exchange(crypto, peer_crypto):
    """Test the full RSA/AES hybrid key exchange handshake."""
    # Alice generates and sends her public key
    alice_pub_pem = crypto.serialize_public_key()

    # Bob receives and loads Alice's public key
    bob_loaded_alice_pub = peer_crypto.load_remote_public_key(alice_pub_pem)

    # Bob generates his AES session key and wraps it with Alice's RSA key
    bob_session_key = peer_crypto.generate_session_key()
    encrypted_session_key = peer_crypto.encrypt_session_key(bob_session_key, bob_loaded_alice_pub)

    # Alice receives the encrypted session key and decrypts it with her private key
    decrypted_session_key = crypto.decrypt_session_key(encrypted_session_key)

    # Verify the keys match (successful handshake)
    assert decrypted_session_key == bob_session_key


def test_message_encryption_decryption(crypto):
    """Test AES-GCM encryption and decryption of a message."""
    session_key = crypto.generate_session_key()
    plaintext = "This is a secret message"

    nonce, ciphertext = crypto.encrypt_message(session_key, plaintext)
    decrypted = crypto.decrypt_message(session_key, nonce, ciphertext)

    assert decrypted == plaintext
    assert nonce is not None
    assert ciphertext is not None


def test_tampered_message_rejection(crypto):
    """Verify that tampering with ciphertext causes decryption to fail."""
    session_key = crypto.generate_session_key()
    plaintext = "This message should not be tampered with"

    nonce, ciphertext = crypto.encrypt_message(session_key, plaintext)

    # Tamper with the ciphertext
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF  # Flip all bits in the first byte
    tampered_ciphertext = bytes(tampered_ciphertext)

    # Attempt to decrypt the tampered message
    with pytest.raises(ValueError):
        crypto.decrypt_message(session_key, nonce, tampered_ciphertext)


# ==========================================
# BLOCK 4 TESTS: RSA SIGNATURES & HMAC
# ==========================================

def test_rsa_signatures(crypto, peer_crypto):
    """Test RSA-PSS digital signatures."""
    data = b"Sign this critical message"

    # Alice signs the data
    signature = crypto.sign_message(data)

    # Bob loads Alice's public key and verifies the signature
    alice_pub_pem = crypto.serialize_public_key()
    bob_loaded_alice_pub = peer_crypto.load_remote_public_key(alice_pub_pem)

    is_valid = peer_crypto.verify_signature(bob_loaded_alice_pub, signature, data)
    assert is_valid


def test_hmac_integrity(crypto):
    """Test HMAC generation and verification."""
    session_key = crypto.generate_session_key()
    data = b"Verify the integrity of this message"

    # Generate HMAC
    hmac_tag = crypto.generate_hmac(session_key, data)

    # Verify HMAC with same data
    is_valid = crypto.verify_hmac(session_key, data, hmac_tag)
    assert is_valid

    # Verify HMAC fails with tampered data
    tampered_data = b"Tampered message"
    is_valid = crypto.verify_hmac(session_key, tampered_data, hmac_tag)
    assert not is_valid

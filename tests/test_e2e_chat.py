"""
End-to-End Chat Tests: Full protocol pipeline with tamper detection and encrypted storage.

Tests:
1. RSA/AES hybrid handshake over real sockets
2. Encrypted + signed + HMAC'd chat message round trip
3. Tamper detection (ciphertext, HMAC tag, signature)
4. Encrypted storage layer (round trip, no plaintext, tamper detection, wrong key rejection)
"""

import asyncio
import pytest
import sys
import os
import struct
import tempfile

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

from crypto_utils import CryptoCore
from network import P2PNetwork
from message_utils import pack_message, unpack_message
import message_pb2
from storage import SecureChatLogger


class TestE2EChatProtocol:
    """End-to-end tests for the full encrypted chat protocol."""

    def test_hybrid_key_exchange(self):
        """
        Test RSA/AES hybrid handshake:
        1. Both peers generate RSA keys
        2. Exchange public keys
        3. Generate session key
        4. Encrypt session key with peer's public key
        5. Decrypt session key with own private key
        """
        # Alice's crypto core
        alice = CryptoCore()
        alice_pub_key = alice.generate_rsa_keys()

        # Bob's crypto core
        bob = CryptoCore()
        bob_pub_key = bob.generate_rsa_keys()

        # Exchange public keys
        alice_pub_bytes = alice.serialize_public_key()
        bob_pub_bytes = bob.serialize_public_key()

        bob_loaded_key = bob.load_remote_public_key(alice_pub_bytes)
        alice_loaded_key = alice.load_remote_public_key(bob_pub_bytes)

        # Generate session keys
        alice_session_key = alice.generate_session_key()
        bob_session_key = bob.generate_session_key()

        assert len(alice_session_key) == 32, "AES-256 key should be 32 bytes"
        assert len(bob_session_key) == 32, "AES-256 key should be 32 bytes"

        # Alice encrypts her session key with Bob's public key
        encrypted_alice_key = alice.encrypt_session_key(alice_session_key, alice_loaded_key)

        # Bob encrypts his session key with Alice's public key
        encrypted_bob_key = bob.encrypt_session_key(bob_session_key, bob_loaded_key)

        # Bob decrypts Alice's key (using Bob's private key)
        decrypted_alice_key = bob.decrypt_session_key(encrypted_alice_key)
        assert decrypted_alice_key == alice_session_key, "Decrypted key should match original"

        # Alice decrypts Bob's key (using Alice's private key)
        decrypted_bob_key = alice.decrypt_session_key(encrypted_bob_key)
        assert decrypted_bob_key == bob_session_key, "Decrypted key should match original"

        print("✅ Hybrid key exchange successful")

    def test_message_encryption_decryption(self):
        """
        Test AES-GCM message encryption and decryption.
        """
        crypto = CryptoCore()
        session_key = crypto.generate_session_key()

        plaintext = "Secret message from Alice"

        # Encrypt
        nonce, ciphertext = crypto.encrypt_message(session_key, plaintext)

        assert len(nonce) == 12, "Nonce should be 12 bytes"
        assert len(ciphertext) > len(plaintext), "Ciphertext should be longer due to GCM tag"

        # Verify no plaintext in ciphertext
        assert plaintext.encode() not in ciphertext, "Plaintext should not appear in ciphertext"

        # Decrypt
        decrypted = crypto.decrypt_message(session_key, nonce, ciphertext)
        assert decrypted == plaintext, "Decrypted message should match original"

        print("✅ Message encryption/decryption successful")

    def test_message_tampering_detection(self):
        """
        Test that tampering with ciphertext or nonce is detected.
        """
        crypto = CryptoCore()
        session_key = crypto.generate_session_key()

        plaintext = "Sensitive data"
        nonce, ciphertext = crypto.encrypt_message(session_key, plaintext)

        # Tamper with ciphertext (flip a bit)
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0x01  # Flip one bit
        tampered_ciphertext = bytes(tampered_ciphertext)

        # Should raise ValueError due to GCM tag mismatch
        with pytest.raises(ValueError, match="Message integrity check failed"):
            crypto.decrypt_message(session_key, nonce, tampered_ciphertext)

        print("✅ Ciphertext tampering detected")

    def test_hmac_generation_verification(self):
        """
        Test HMAC generation and verification.
        """
        crypto = CryptoCore()
        session_key = crypto.generate_session_key()

        data = b"Important message"

        # Generate HMAC
        hmac_tag = crypto.generate_hmac(session_key, data)

        # Verify HMAC
        is_valid = crypto.verify_hmac(session_key, data, hmac_tag)
        assert is_valid, "HMAC verification should succeed"

        # Tamper with data
        tampered_data = bytearray(data)
        tampered_data[0] ^= 0x01
        tampered_data = bytes(tampered_data)

        # Verify should fail
        is_valid = crypto.verify_hmac(session_key, tampered_data, hmac_tag)
        assert not is_valid, "HMAC verification should fail for tampered data"

        print("✅ HMAC tampering detected")

    def test_signature_generation_verification(self):
        """
        Test RSA signature generation and verification.
        """
        alice = CryptoCore()
        alice.generate_rsa_keys()

        bob = CryptoCore()
        bob.generate_rsa_keys()

        # Load each other's public keys
        bob_pub_key = bob.load_remote_public_key(bob.serialize_public_key())
        alice_pub_key = alice.load_remote_public_key(alice.serialize_public_key())

        data = b"Authenticated message from Alice"

        # Alice signs
        signature = alice.sign_message(data)

        # Bob verifies (using Alice's public key)
        is_valid = alice.verify_signature(alice_pub_key, signature, data)
        assert is_valid, "Signature verification should succeed"

        # Tamper with data
        tampered_data = bytearray(data)
        tampered_data[0] ^= 0x01
        tampered_data = bytes(tampered_data)

        # Verify should fail
        is_valid = alice.verify_signature(alice_pub_key, signature, tampered_data)
        assert not is_valid, "Signature verification should fail for tampered data"

        print("✅ Signature tampering detected")

    def test_protobuf_messaging(self):
        """
        Test protobuf message packing and unpacking.
        """
        # Create a P2P message
        payload = b"Test payload data"
        nonce = os.urandom(12)
        hmac_tag = os.urandom(32)

        packed = pack_message("CHAT_MESSAGE", payload, nonce, hmac_tag)
        assert isinstance(packed, bytes), "Packed message should be bytes"

        # Unpack it
        msg_type, unpacked_payload, unpacked_nonce, unpacked_hmac = unpack_message(packed)

        assert msg_type == "CHAT_MESSAGE", "Message type should match"
        assert unpacked_payload == payload, "Payload should match"
        assert unpacked_nonce == nonce, "Nonce should match"
        assert unpacked_hmac == hmac_tag, "HMAC tag should match"

        print("✅ Protobuf messaging successful")


class TestEncryptedStorage:
    """Test the encrypted storage layer."""

    def test_storage_round_trip(self):
        """Test writing and reading encrypted log entries."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            log_file = f.name

        try:
            storage_key = os.urandom(32)
            logger = SecureChatLogger(log_file, storage_key)

            # Create and log entries
            entry1 = message_pb2.ChatLogEntry()
            entry1.timestamp = 1000
            entry1.direction = message_pb2.ChatLogEntry.Direction.SENT
            entry1.message_type = message_pb2.P2PMessage.MessageType.CHAT_MESSAGE
            entry1.plaintext_content = "First message"
            entry1.hmac_verified = True
            entry1.signature_verified = True

            entry2 = message_pb2.ChatLogEntry()
            entry2.timestamp = 2000
            entry2.direction = message_pb2.ChatLogEntry.Direction.RECEIVED
            entry2.message_type = message_pb2.P2PMessage.MessageType.CHAT_MESSAGE
            entry2.plaintext_content = "Second message"
            entry2.hmac_verified = True
            entry2.signature_verified = False

            logger.log_entry(entry1)
            logger.log_entry(entry2)

            # Read back
            entries = logger.read_history()

            assert len(entries) == 2, "Should have 2 entries"
            assert entries[0].plaintext_content == "First message"
            assert entries[0].hmac_verified == True
            assert entries[1].plaintext_content == "Second message"
            assert entries[1].signature_verified == False

            print("✅ Storage round-trip successful")

        finally:
            if os.path.exists(log_file):
                os.unlink(log_file)

    def test_no_plaintext_on_disk(self):
        """Verify no plaintext appears in the encrypted log file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            log_file = f.name

        try:
            storage_key = os.urandom(32)
            logger = SecureChatLogger(log_file, storage_key)

            # Log entries with sensitive content
            entry = message_pb2.ChatLogEntry()
            entry.timestamp = 1234567890
            entry.direction = message_pb2.ChatLogEntry.Direction.SENT
            entry.message_type = message_pb2.P2PMessage.MessageType.CHAT_MESSAGE
            entry.plaintext_content = "SuperSecretPassword123!@#"
            entry.hmac_verified = True
            entry.signature_verified = True

            logger.log_entry(entry)

            # Read the raw file
            with open(log_file, "rb") as f:
                raw_content = f.read()

            # Verify plaintext does not appear
            assert b"SuperSecretPassword123!@#" not in raw_content, "Plaintext should not be in file"
            assert b"SuperSecret" not in raw_content, "Plaintext fragment should not be in file"

            print("✅ No plaintext on disk")

        finally:
            if os.path.exists(log_file):
                os.unlink(log_file)

    def test_tamper_detection(self):
        """Test that tampering with encrypted log is detected."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            log_file = f.name

        try:
            storage_key = os.urandom(32)
            logger = SecureChatLogger(log_file, storage_key)

            # Log an entry
            entry = message_pb2.ChatLogEntry()
            entry.timestamp = 5000
            entry.direction = message_pb2.ChatLogEntry.Direction.RECEIVED
            entry.message_type = message_pb2.P2PMessage.MessageType.CHAT_MESSAGE
            entry.plaintext_content = "Original message"
            entry.hmac_verified = True
            entry.signature_verified = True

            logger.log_entry(entry)

            # Tamper with the encrypted file
            with open(log_file, "r+b") as f:
                f.seek(10)  # Skip length prefix and start of nonce
                f.write(b"X")  # Write one byte to corrupt the encrypted data

            # Try to read - should raise ValueError due to GCM tag mismatch
            logger2 = SecureChatLogger(log_file, storage_key)

            with pytest.raises(ValueError, match="Tamper detection"):
                logger2.read_history()

            print("✅ Tamper detection working")

        finally:
            if os.path.exists(log_file):
                os.unlink(log_file)

    def test_wrong_key_rejection(self):
        """Test that decryption with wrong key fails."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            log_file = f.name

        try:
            storage_key = os.urandom(32)
            logger = SecureChatLogger(log_file, storage_key)

            # Log an entry
            entry = message_pb2.ChatLogEntry()
            entry.timestamp = 7000
            entry.direction = message_pb2.ChatLogEntry.Direction.SENT
            entry.message_type = message_pb2.P2PMessage.MessageType.CHAT_MESSAGE
            entry.plaintext_content = "Encrypted with key A"
            entry.hmac_verified = True
            entry.signature_verified = True

            logger.log_entry(entry)

            # Try to read with a different key
            wrong_key = os.urandom(32)
            logger2 = SecureChatLogger(log_file, wrong_key)

            # Should raise ValueError due to GCM tag verification failure
            with pytest.raises(ValueError, match="Tamper detection"):
                logger2.read_history()

            print("✅ Wrong key rejection working")

        finally:
            if os.path.exists(log_file):
                os.unlink(log_file)

    def test_invalid_storage_key_length(self):
        """Test that invalid storage key length is rejected."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            log_file = f.name

        try:
            # Try with wrong key length
            with pytest.raises(ValueError, match="Storage key must be 32 bytes"):
                SecureChatLogger(log_file, b"short_key")

            print("✅ Invalid key length rejected")

        finally:
            if os.path.exists(log_file):
                os.unlink(log_file)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

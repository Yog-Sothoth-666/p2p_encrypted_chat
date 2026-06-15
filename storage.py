"""
SecureChatLogger: Encrypted local storage for chat messages with tamper detection.

Each ChatLogEntry is encrypted with AES-256-GCM using a storage key independent
of the rotating session key (for forward secrecy). Records are length-prefixed
and appended to disk. Deserialization includes GCM tag verification for tamper detection.
"""

import os
import struct
from typing import List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

import message_pb2


class SecureChatLogger:
    """
    Encrypts and logs ChatLogEntry messages to disk with tamper detection.
    """

    def __init__(self, storage_file_path: str, storage_key: bytes):
        """
        Initialize the logger with a storage file path and encryption key.

        Args:
            storage_file_path: Path to the encrypted log file
            storage_key: 32-byte AES-256 key (independent of session key for forward secrecy)

        Raises:
            ValueError: If storage_key is not 32 bytes
        """
        if len(storage_key) != 32:
            raise ValueError(f"Storage key must be 32 bytes (256-bit), got {len(storage_key)}")

        self.storage_file_path = storage_file_path
        self.storage_key = storage_key

    def log_entry(self, entry: message_pb2.ChatLogEntry) -> None:
        """
        Serialize, encrypt, and append a ChatLogEntry to the log file.

        Args:
            entry: ChatLogEntry protobuf message to log

        Raises:
            IOError: If the file cannot be written
        """
        # Serialize the ChatLogEntry to protobuf bytes
        serialized_entry = entry.SerializeToString()

        # Generate a fresh 12-byte nonce (NIST standard for GCM)
        nonce = os.urandom(12)

        # Encrypt with AES-256-GCM
        # Note: GCM automatically appends a 16-byte authentication tag to the ciphertext
        aesgcm = AESGCM(self.storage_key)
        ciphertext = aesgcm.encrypt(nonce, serialized_entry, None)

        # Prepend nonce to ciphertext (nonce is public, ciphertext includes GCM tag)
        # Format: [12-byte nonce][16-byte GCM tag + encrypted data]
        encrypted_record = nonce + ciphertext

        # Length-prefix the encrypted record (4 bytes, big-endian)
        record_length = struct.pack(">I", len(encrypted_record))

        # Append to file (create if doesn't exist)
        with open(self.storage_file_path, "ab") as f:
            f.write(record_length)
            f.write(encrypted_record)

    def read_history(self) -> List[message_pb2.ChatLogEntry]:
        """
        Read and decrypt all entries from the log file.

        Returns:
            List of ChatLogEntry messages

        Raises:
            ValueError: If any record fails GCM tag verification (tamper detection)
            IOError: If the file cannot be read
        """
        entries = []

        # Return empty list if file doesn't exist
        if not os.path.exists(self.storage_file_path):
            return entries

        with open(self.storage_file_path, "rb") as f:
            while True:
                # Read 4-byte length prefix
                length_bytes = f.read(4)
                if not length_bytes:
                    break

                record_length = struct.unpack(">I", length_bytes)[0]

                # Read encrypted record (nonce + ciphertext with GCM tag)
                encrypted_record = f.read(record_length)

                if len(encrypted_record) < 12:
                    raise ValueError("Corrupted log file: encrypted record too short")

                # Extract nonce (first 12 bytes)
                nonce = encrypted_record[:12]

                # Extract ciphertext (includes 16-byte GCM tag appended by aesgcm.encrypt)
                ciphertext = encrypted_record[12:]

                # Decrypt and verify GCM tag
                try:
                    aesgcm = AESGCM(self.storage_key)
                    serialized_entry = aesgcm.decrypt(nonce, ciphertext, None)
                except InvalidTag as e:
                    raise ValueError(
                        "Tamper detection: GCM tag verification failed. "
                        "The log file may have been modified."
                    ) from e

                # Deserialize the ChatLogEntry
                entry = message_pb2.ChatLogEntry()
                entry.ParseFromString(serialized_entry)
                entries.append(entry)

        return entries

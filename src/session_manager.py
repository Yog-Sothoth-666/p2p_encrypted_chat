"""
SessionManager: Orchestrates the encrypted chat protocol.

Responsibilities:
1. Run the key exchange handshake (RSA + AES)
2. Manage the chat loop (send/receive encrypted messages)
3. Handle message signing, HMAC verification
4. Manage session key rotation
5. Integrate crypto, network, and storage layers
"""

import asyncio
import os
import time
import logging
from typing import Optional, Tuple

from crypto_utils import CryptoCore
from network import P2PNetwork
from message_utils import pack_message, unpack_message
import message_pb2
from storage import SecureChatLogger

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Orchestrates the full encrypted chat protocol between two peers.
    """

    def __init__(
        self,
        role: str,  # "initiator" or "receiver"
        my_port: int,
        peer_address: str,
        peer_port: int,
        storage_key: Optional[bytes] = None,
        storage_file: Optional[str] = None,
    ):
        """
        Initialize the SessionManager.

        Args:
            role: "initiator" or "receiver"
            my_port: Port this peer listens on
            peer_address: IP/hostname of the peer
            peer_port: Port the peer listens on
            storage_key: 32-byte key for encrypting local chat logs (generated if None)
            storage_file: Path to encrypted chat log file
        """
        if role not in ("initiator", "receiver"):
            raise ValueError(f"Invalid role: {role}. Must be 'initiator' or 'receiver'")

        self.role = role
        self.my_port = my_port
        self.peer_address = peer_address
        self.peer_port = peer_port

        # Crypto layer
        self.crypto = CryptoCore()

        # Network layer
        self.message_queue = asyncio.Queue()
        self.network = P2PNetwork(
            my_port=my_port,
            peer_address=peer_address,
            peer_port=peer_port,
            on_message_callback=self._on_network_message,
        )

        # Storage layer (optional)
        self.storage_key = storage_key or os.urandom(32)
        self.storage_file = storage_file or f"chat_log_{role}_{int(time.time())}.bin"
        self.logger = SecureChatLogger(self.storage_file, self.storage_key)

        # Session state
        self.session_key: Optional[bytes] = None
        self.peer_public_key = None
        self.peer_pub_key_bytes: Optional[bytes] = None

        # State machine
        self.state = "INIT"

        logger.info(f"SessionManager initialized as {role} on port {my_port}")

    async def _on_network_message(self, message: bytes, conn_type: str):
        """
        Callback invoked by the network layer when a message arrives.
        """
        await self.message_queue.put(message)

    async def run_handshake(self):
        """
        Execute the key exchange handshake.
        For initiator: INIT -> SEND_RSA_PUB -> WAIT_RSA_PUB -> GEN_AND_SEND_AES -> ESTABLISHED
        For receiver: INIT -> WAIT_RSA_PUB -> SEND_RSA_PUB -> WAIT_AES_KEY -> ESTABLISHED
        """
        # Generate our RSA keys
        self.crypto.generate_rsa_keys()
        my_pub_key_bytes = self.crypto.serialize_public_key()

        print(f"\n=== Starting P2P Handshake ({self.role.upper()} Node) ===")

        # Start the network
        while self.state == "INIT":
            await self.network.start()
            if self.network.outgoing_ws or self.network.incoming_ws:
                if self.role == "initiator":
                    self.state = "SEND_RSA_PUB"
                else:
                    self.state = "WAIT_RSA_PUB"
            else:
                await asyncio.sleep(1)

        # Initiator: Send RSA public key
        if self.role == "initiator":
            while self.state != "ESTABLISHED":
                if self.state == "SEND_RSA_PUB":
                    envelope = pack_message("RSA_PUB_KEY", payload_bytes=my_pub_key_bytes)
                    await self.network.send(envelope)
                    self.state = "WAIT_RSA_PUB"

                elif self.state == "WAIT_RSA_PUB":
                    raw_incoming_bytes = await self.message_queue.get()
                    msg_type, payload, nonce, hmac = unpack_message(raw_incoming_bytes)

                    if msg_type == "RSA_PUB_KEY":
                        self.peer_pub_key_bytes = payload
                        self.peer_public_key = self.crypto.load_remote_public_key(payload)
                        self.state = "GEN_AND_SEND_AES"
                    else:
                        logger.warning(f"Expected RSA key, but received {msg_type}. Dropping.")

                elif self.state == "GEN_AND_SEND_AES":
                    self.session_key = self.crypto.generate_session_key()
                    encrypted_aes_key = self.crypto.encrypt_session_key(
                        self.session_key, self.peer_public_key
                    )

                    envelope = pack_message("AES_KEY_EXCHANGE", payload_bytes=encrypted_aes_key)
                    await self.network.send(envelope)

                    self.state = "ESTABLISHED"

        # Receiver: Wait for RSA public key, send ours, then receive AES
        else:
            while self.state != "ESTABLISHED":
                if self.state == "WAIT_RSA_PUB":
                    raw_incoming_bytes = await self.message_queue.get()
                    msg_type, payload, nonce, hmac = unpack_message(raw_incoming_bytes)

                    if msg_type == "RSA_PUB_KEY":
                        self.peer_pub_key_bytes = payload
                        self.peer_public_key = self.crypto.load_remote_public_key(payload)
                        self.state = "SEND_RSA_PUB"
                    else:
                        logger.warning(f"Expected RSA key, but received {msg_type}. Dropping.")

                elif self.state == "SEND_RSA_PUB":
                    envelope = pack_message("RSA_PUB_KEY", payload_bytes=my_pub_key_bytes)
                    await self.network.send(envelope)
                    self.state = "WAIT_AES_KEY"

                elif self.state == "WAIT_AES_KEY":
                    raw_incoming_bytes = await self.message_queue.get()
                    msg_type, payload, nonce, hmac = unpack_message(raw_incoming_bytes)

                    if msg_type == "AES_KEY_EXCHANGE":
                        self.session_key = self.crypto.decrypt_session_key(payload)
                        self.state = "ESTABLISHED"
                    else:
                        logger.warning(f"Expected AES key, but received {msg_type}. Dropping.")

    async def send_message(self, plaintext: str) -> None:
        """
        Encrypt, sign, HMAC, and send a chat message.

        Args:
            plaintext: The message to send
        """
        if not self.session_key:
            raise RuntimeError("Session not established. Run handshake first.")

        # 1. Encrypt with AES-GCM
        nonce, ciphertext = self.crypto.encrypt_message(self.session_key, plaintext)

        # 2. Sign the ciphertext
        signature = self.crypto.sign_message(ciphertext)

        # 3. Generate HMAC of the ciphertext
        hmac_tag = self.crypto.generate_hmac(self.session_key, ciphertext)

        # 4. Pack into protobuf and send
        envelope = pack_message("CHAT_MESSAGE", payload_bytes=ciphertext, nonce_bytes=nonce, hmac_bytes=hmac_tag)

        await self.network.send(envelope)

        # 5. Log to storage
        entry = message_pb2.ChatLogEntry()
        entry.timestamp = int(time.time() * 1000)
        entry.direction = message_pb2.ChatLogEntry.Direction.SENT
        entry.message_type = message_pb2.P2PMessage.MessageType.CHAT_MESSAGE
        entry.plaintext_content = plaintext
        entry.hmac_verified = True
        entry.signature_verified = True
        self.logger.log_entry(entry)

        logger.debug(f"Message sent: {plaintext[:50]}...")

    async def receive_message(self, timeout: int = 30) -> Optional[str]:
        """
        Receive, verify, and decrypt a chat message.

        Args:
            timeout: Maximum time to wait for a message (seconds)

        Returns:
            Decrypted plaintext or None if timeout
        """
        if not self.session_key:
            raise RuntimeError("Session not established. Run handshake first.")

        try:
            raw_incoming_bytes = await asyncio.wait_for(
                self.message_queue.get(), timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.debug("No message received within timeout")
            return None

        msg_type, payload, nonce, hmac_tag = unpack_message(raw_incoming_bytes)

        if msg_type != "CHAT_MESSAGE":
            logger.warning(f"Expected CHAT_MESSAGE but got {msg_type}")
            return None

        # 1. Verify HMAC
        hmac_valid = self.crypto.verify_hmac(self.session_key, payload, hmac_tag)

        # 2. Decrypt the ciphertext
        try:
            plaintext = self.crypto.decrypt_message(self.session_key, nonce, payload)
        except ValueError as e:
            logger.error(f"Decryption failed: {e}")
            return None

        # 3. Log to storage
        entry = message_pb2.ChatLogEntry()
        entry.timestamp = int(time.time() * 1000)
        entry.direction = message_pb2.ChatLogEntry.Direction.RECEIVED
        entry.message_type = message_pb2.P2PMessage.MessageType.CHAT_MESSAGE
        entry.plaintext_content = plaintext
        entry.hmac_verified = hmac_valid
        entry.signature_verified = False  # We don't verify signatures in receive for now
        self.logger.log_entry(entry)

        logger.debug(f"Message received: {plaintext[:50]}...")

        return plaintext

    async def stop(self) -> None:
        """Clean shutdown of the session."""
        await self.network.stop()
        logger.info(f"Session stopped. Chat log: {self.storage_file}")

    def get_chat_history(self) -> list:
        """
        Retrieve the encrypted chat history.

        Returns:
            List of ChatLogEntry messages
        """
        return self.logger.read_history()

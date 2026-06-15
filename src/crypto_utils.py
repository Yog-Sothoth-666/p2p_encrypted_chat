import logging
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

class CryptoCore:
    def __init__(self):
        # Initializing the cryptographic state.
        # Keys are generated on-demand to avoid unnecessary overhead on startup.
        self._private_key = None
        self.public_key = None

    # BLOCK 1: IDENTITY (RSA)
    
    def generate_rsa_keys(self):
        """
        Generates a new 2048-bit RSA key pair for the local instance.
        """
        logger.info("Generating a new RSA-2048 key pair...")
        
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self._private_key.public_key()
        
        logger.info("RSA keys successfully generated and loaded.")
        return self.public_key

    def serialize_public_key(self) -> bytes:
        """
        Serializes the public key into PEM format (bytes) for network transmission.
        """
        if not self.public_key:
            raise RuntimeError("Error: Attempted to serialize a public key before generation.")
            
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
    def load_remote_public_key(self, pem_bytes: bytes):
        """
        Reconstructs the public key object from PEM bytes received from the remote peer.
        """
        try:
            remote_key = serialization.load_pem_public_key(pem_bytes)
            logger.info("Remote public key successfully loaded.")
            return remote_key
        except ValueError as e:
            logger.error("Failed to parse the remote public key. Data may be corrupted.")
            raise e


    # BLOCK 2: HYBRID ENCRYPTION (The Handshake)

    def generate_session_key(self) -> bytes:
        """
        Generates a 256-bit AES key. This is the fast, single-use key 
        we will use to encrypt the actual chat messages.
        """
        logger.debug("Generating a fresh AES-256 session key...")
        # AES-256 requires a 32-byte (256-bit) key
        return AESGCM.generate_key(bit_length=256)

    def encrypt_session_key(self, aes_key: bytes, peer_public_key) -> bytes:
        """
        Locks the fast AES session key inside the peer's RSA public padlock.
        Once encrypted, only the peer's private key can unlock it.
        """
        logger.debug("Encrypting the AES session key using the peer's RSA public key...")
        
        # We use OAEP padding with SHA-256. This is the modern standard 
        # required to prevent padding oracle attacks against RSA.
        encrypted_key = peer_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    def decrypt_session_key(self, encrypted_aes_key: bytes) -> bytes:
        """
        Unlocks a received AES session key using our local RSA private key.
        """
        if not self._private_key:
            raise RuntimeError("Critical: Cannot decrypt session key. Local RSA keys are missing.")
            
        logger.debug("Decrypting the received AES session key...")
        
        aes_key = self._private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key

    # BLOCK 3: COMMUNICATION (AES-GCM)

    def encrypt_message(self, aes_key: bytes, plaintext: str):
        """
        Encrypts a standard string message using AES-GCM.
        Returns the (nonce, ciphertext) tuple needed by Person 3 to send over the network.
        """
        logger.debug("Encrypting outgoing text message...")
        
        # Initialize the AES-GCM cipher with the shared session key
        aesgcm = AESGCM(aes_key)
        
        # CRITICAL: GCM mode absolutely requires a unique 'nonce' (Number Used Once) for EVERY message.
        # If we reuse a nonce with the same key, the encryption completely breaks.
        # We use os.urandom to generate 12 bytes, which is the NIST standard for GCM.
        nonce = os.urandom(12)
        
        # Sockets only send bytes, so we encode the string first.
        # Note: GCM automatically appends an authentication tag to the end of the ciphertext.
        encoded_message = plaintext.encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, encoded_message, None)
        
        return nonce, ciphertext

    def decrypt_message(self, aes_key: bytes, nonce: bytes, ciphertext: bytes) -> str:
        """
        Decrypts an incoming message and validates its built-in GCM authentication tag.
        Throws an error if the message was altered in transit.
        """
        logger.debug("Decrypting incoming text message...")
        aesgcm = AESGCM(aes_key)
        
        try:
            # If the ciphertext was altered even slightly by a hacker on the network, 
            # this decrypt method will immediately throw an InvalidTag exception.
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted_bytes.decode('utf-8')
            
        except InvalidTag as e:
            # We catch it, log a massive warning, and crash the function so Person 3 
            # knows to drop the message and warn the user.
            logger.error("SECURITY ALERT: The message authentication tag is invalid. The message was altered!")
            raise ValueError("Message integrity check failed during AES decryption.") from e


    # BLOCK 4: AUTHENTICATION & INTEGRITY (HMAC & Signatures)

    def sign_message(self, data: bytes) -> bytes:
        """
        Creates a digital signature of the data using our local RSA private key.
        This proves to the receiver that WE sent it, because only we have the private key.
        """
        if not self._private_key:
            raise RuntimeError("Cannot sign message: Local RSA keys are missing.")
            
        logger.debug("Signing outgoing data with RSA private key...")
        
        # PSS (Probabilistic Signature Scheme) is the modern standard for RSA signatures
        signature = self._private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, peer_public_key, signature: bytes, data: bytes) -> bool:
        """
        Verifies that the signature matches the data and was created by the peer.
        """
        logger.debug("Verifying sender's RSA signature...")
        try:
            peer_public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logger.debug("Signature is valid. Sender authenticated.")
            return True
        except InvalidSignature:
            logger.error("SECURITY ALERT: Invalid RSA signature. Someone is spoofing the sender!")
            return False

    def generate_hmac(self, aes_key: bytes, data: bytes) -> bytes:
        """
        Generates an HMAC-SHA256 tag for the given data using the shared AES key.
        Fulfills the specific project requirement for explicit integrity checks.
        """
        logger.debug("Generating HMAC-SHA256 tag for data integrity...")
        
        h = hmac.HMAC(aes_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def verify_hmac(self, aes_key: bytes, data: bytes, expected_hmac: bytes) -> bool:
        """
        Recalculates the HMAC locally and checks if it matches what was sent over the network.
        """
        logger.debug("Verifying HMAC-SHA256 integrity tag...")
        
        h = hmac.HMAC(aes_key, hashes.SHA256())
        h.update(data)
        try:
            h.verify(expected_hmac)
            logger.debug("HMAC verified. Data is intact.")
            return True
        except InvalidSignature:
            logger.error("SECURITY ALERT: HMAC verification failed. Data was tampered with!")
            return False

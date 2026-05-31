from message_utils import pack_message, unpack_message
import time

# ==========================================
# PHASE 1: THE INTERFACE CONTRACTS (MOCKS)
# ==========================================

# -- Cryptography Mocks (Person 1's future job) --
def generate_rsa_keypair_mock():
    return b"INITIATOR_PRIVATE_KEY", b"INITIATOR_PUBLIC_KEY"

def generate_aes_key_mock():
    return b"SESSION_AES_256_KEY"

def encrypt_asymmetric_mock(public_key, plaintext_bytes):
    # Simulates encrypting the AES key with the receiver's RSA public key
    return b"ENC[" + plaintext_bytes + b"]_WITH_" + public_key

# -- Network Mocks (Person 2's future job) --
def connect_mock(ip, port):
    print(f"[*] Mock: Connecting to {ip}:{port}...")
    return True

def send_data_mock(data):
    print(f"[->] Mock: Sending {len(data)} bytes: {data}")

def receive_data_mock(expected_type):
    # Simulates receiving data over the socket based on where we are in the handshake
    if expected_type == "rsa_key":
        # Simulate the receiver properly packing their key into an envelope
        data = pack_message("RSA_PUB_KEY", payload_bytes=b"RECEIVER_PUBLIC_KEY")
    else:
        data = pack_message("UNKNOWN", payload_bytes=b"DUMMY_DATA")
        
    print(f"[<-] Mock: Received data: {data}")
    return data

# ==========================================
# PHASE 2: THE FINITE STATE MACHINE (YOUR JOB)
# ==========================================

def run_initiator_handshake():
    state = "INIT"
    session_key = None
    receiver_pub_key = None
    
    # 1. Generate our keys before connecting
    my_priv_key, my_pub_key = generate_rsa_keypair_mock()

    print("\n=== Starting P2P Handshake (Initiator Node) ===")

    # 2. The Core FSM Loop
    while state != "ESTABLISHED":
        if state == "INIT":
            connected = connect_mock("127.0.0.1", 9999)
            if connected:
                state = "SEND_RSA_PUB"
            time.sleep(1) # Sleep added just so you can read the terminal output

        elif state == "SEND_RSA_PUB":
            print("\n[*] State Transition: SEND_RSA_PUB")
            # NEW: Pack the key into the Protobuf envelope before sending
            envelope = pack_message("RSA_PUB_KEY", payload_bytes=my_pub_key)
            send_data_mock(envelope) 
            state = "WAIT_RSA_PUB"
            time.sleep(1)

        elif state == "WAIT_RSA_PUB":
            print("\n[*] State Transition: WAIT_RSA_PUB")
            raw_incoming_bytes = receive_data_mock(expected_type="rsa_key")
            
            # NEW: Unpack the envelope to see what we received
            msg_type, payload, nonce, hmac = unpack_message(raw_incoming_bytes)
            
            if msg_type == "RSA_PUB_KEY":
                receiver_pub_key = payload
                state = "GEN_AND_SEND_AES"
            else:
                print(f"[!] Expected RSA key, but received {msg_type}. Dropping.")
            time.sleep(1)

        elif state == "GEN_AND_SEND_AES":
            print("\n[*] State Transition: GEN_AND_SEND_AES")
            session_key = generate_aes_key_mock()
            encrypted_aes_key = encrypt_asymmetric_mock(receiver_pub_key, session_key)
            send_data_mock(encrypted_aes_key)
            state = "ESTABLISHED"
            time.sleep(1)

        else:
            print("\n[!] Error: Unknown state. Aborting handshake.")
            break

    print("\n=== Handshake Complete ===")
    print(f"[*] Secure Session Key established: {session_key}")
    print("[*] Ready to pass AES key to the chat loop.\n")

if __name__ == "__main__":
    run_initiator_handshake()
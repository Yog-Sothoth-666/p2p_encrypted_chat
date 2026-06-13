import asyncio
from crypto_utils import CryptoCore
from network import P2PNetwork
from message_utils import pack_message, unpack_message

async def run_initiator_handshake():
    crypto = CryptoCore()
    state = "INIT"
    session_key = None
    receiver_pub_key_bytes = None
    
    # 1. Generate our keys before connecting
    crypto.generate_rsa_keys()
    my_pub_key_bytes = crypto.serialize_public_key()
    print("\n=== Starting P2P Handshake (Initiator Node) ===")

    # 2. Network Integration: The Callback Queue
    # This queue bridges the asynchronous WebSocket callbacks with the sequential FSM
    message_queue = asyncio.Queue()

    async def handle_incoming_message(message: bytes, conn_type: str):
        # When the network layer receives data, push it into the queue for the FSM
        await message_queue.put(message)

    # Initialize the networking node
    # Note: We assign port 9998 to the Initiator, connecting to the Receiver on 9999
    net = P2PNetwork(
        my_port=9998, 
        peer_address="127.0.0.1", 
        peer_port=9999, 
        on_message_callback=handle_incoming_message
    )

    # 3. The Core FSM Loop
    while state != "ESTABLISHED":
        if state == "INIT":
            await net.start()
            # Allow the WebSocket handshake to establish
            await asyncio.sleep(1)
            
            if net.outgoing_ws or net.incoming_ws:
                state = "SEND_RSA_PUB"
            else:
                print("Waiting for peer to connect...")
                await asyncio.sleep(2)

        elif state == "SEND_RSA_PUB":
            print("\n[*] State Transition: SEND_RSA_PUB")
            
            envelope = pack_message("RSA_PUB_KEY", payload_bytes=my_pub_key_bytes)
            await net.send(envelope)
            
            state = "WAIT_RSA_PUB"
            await asyncio.sleep(1)

        elif state == "WAIT_RSA_PUB":
            print("\n[*] State Transition: WAIT_RSA_PUB")
            
            # Block and wait for the network callback to push a message into the queue
            raw_incoming_bytes = await message_queue.get()
            
            msg_type, payload, nonce, hmac = unpack_message(raw_incoming_bytes)
            
            if msg_type == "RSA_PUB_KEY":
                receiver_pub_key_bytes = payload
                state = "GEN_AND_SEND_AES"
            else:
                print(f"[!] Expected RSA key, but received {msg_type}. Dropping.")
            await asyncio.sleep(1)

        elif state == "GEN_AND_SEND_AES":
            print("\n[*] State Transition: GEN_AND_SEND_AES")
            
            session_key = crypto.generate_session_key()
            remote_pub_key_obj = crypto.load_remote_public_key(receiver_pub_key_bytes)
            encrypted_aes_key = crypto.encrypt_session_key(session_key, remote_pub_key_obj)
            
            # Pack the encrypted AES key into the required Protobuf frame before sending
            envelope = pack_message("AES_KEY_EXCHANGE", payload_bytes=encrypted_aes_key)
            await net.send(envelope)
            
            state = "ESTABLISHED"
            await asyncio.sleep(1)

        else:
            print("\n[!] Error: Unknown state. Aborting handshake.")
            break

    print("\n=== Handshake Complete ===")
    print(f"[*] Secure Session Key established: {session_key}")
    print("[*] Ready to pass AES key to the chat loop.\n")

    # Keep the event loop running if you plan to implement the chat phase next
    # await asyncio.sleep(3600) 

if __name__ == "__main__":
    # Execute the asynchronous event loop
    asyncio.run(run_initiator_handshake())
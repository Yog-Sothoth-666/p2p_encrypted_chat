import asyncio
from crypto_utils import CryptoCore
from network import P2PNetwork
from message_utils import pack_message, unpack_message

async def run_receiver_handshake():
    crypto = CryptoCore()
    state = "INIT"
    session_key = None
    initiator_pub_key_bytes = None

    # 1. Generate our keys before listening
    crypto.generate_rsa_keys()
    my_pub_key_bytes = crypto.serialize_public_key()
    print("\n=== Starting P2P Handshake (Receiver Node) ===")

    message_queue = asyncio.Queue()

    async def handle_incoming_message(message: bytes, conn_type: str):
        await message_queue.put(message)

    # Initialize the networking node
    # Receiver binds to port 9999 and connects back to 9998
    net = P2PNetwork(
        my_port=9999, 
        peer_address="127.0.0.1", 
        peer_port=9998, 
        on_message_callback=handle_incoming_message
    )

    # 3. The Core FSM Loop
    while state != "ESTABLISHED":
        if state == "INIT":
            if not net._is_running:
             await net.start()
             
            await asyncio.sleep(1)
            
            if net.outgoing_ws or net.incoming_ws:
                state = "WAIT_RSA_PUB"
            else:
                print("Waiting for peer to connect...")
                await asyncio.sleep(2)

        elif state == "WAIT_RSA_PUB":
            print("\n[*] State Transition: WAIT_RSA_PUB")
            
            raw_incoming_bytes = await message_queue.get()
            msg_type, payload, nonce, hmac = unpack_message(raw_incoming_bytes)
            
            if msg_type == "RSA_PUB_KEY":
                initiator_pub_key_bytes = payload
                state = "SEND_RSA_PUB"
            else:
                print(f"[!] Expected RSA key, but received {msg_type}. Dropping.")
            await asyncio.sleep(1)

        elif state == "SEND_RSA_PUB":
            print("\n[*] State Transition: SEND_RSA_PUB")
            
            envelope = pack_message("RSA_PUB_KEY", payload_bytes=my_pub_key_bytes)
            await net.send(envelope)
            
            state = "WAIT_AES_KEY"
            await asyncio.sleep(1)

        elif state == "WAIT_AES_KEY":
            print("\n[*] State Transition: WAIT_AES_KEY")
            
            raw_incoming_bytes = await message_queue.get()
            msg_type, payload, nonce, hmac = unpack_message(raw_incoming_bytes)
            
            if msg_type == "AES_KEY_EXCHANGE":
                # Payload is the encrypted AES key. Decrypt it using our local RSA private key.
                session_key = crypto.decrypt_session_key(payload)
                state = "ESTABLISHED"
            else:
                print(f"[!] Expected AES key, but received {msg_type}. Dropping.")
            await asyncio.sleep(1)

        else:
            print("\n[!] Error: Unknown state. Aborting handshake.")
            break

    print("\n=== Handshake Complete ===")
    print(f"[*] Secure Session Key established: {session_key}")
    print("[*] Ready to pass AES key to the chat loop.\n")

if __name__ == "__main__":
    asyncio.run(run_receiver_handshake())
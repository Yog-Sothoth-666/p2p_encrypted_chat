import message_pb2

def pack_message(msg_type_str, payload_bytes=b"", nonce_bytes=b"", hmac_bytes=b""):
    """
    Takes raw data and packages it securely into a Protobuf byte stream.
    """
    # Create an empty message envelope
    msg = message_pb2.P2PMessage()
    
    # Map the string input to the Protobuf Enum
    if msg_type_str == "RSA_PUB_KEY":
        msg.type = message_pb2.P2PMessage.RSA_PUB_KEY
    elif msg_type_str == "AES_KEY_EXCHANGE":
        msg.type = message_pb2.P2PMessage.AES_KEY_EXCHANGE
    elif msg_type_str == "CHAT_MESSAGE":
        msg.type = message_pb2.P2PMessage.CHAT_MESSAGE
    else:
        msg.type = message_pb2.P2PMessage.UNKNOWN

    # Fill the envelope
    msg.payload = payload_bytes
    msg.nonce = nonce_bytes
    msg.hmac_tag = hmac_bytes

    # Serialize the whole envelope into a single raw byte string for the TCP socket
    return msg.SerializeToString()

def unpack_message(raw_bytes):
    """
    Takes a raw byte stream from the socket and reconstructs the message envelope.
    """
    msg = message_pb2.P2PMessage()
    try:
        # Rebuild the object from the raw TCP bytes
        msg.ParseFromString(raw_bytes)
        
        # Determine the string representation of the message type
        type_str = "UNKNOWN"
        if msg.type == message_pb2.P2PMessage.RSA_PUB_KEY:
            type_str = "RSA_PUB_KEY"
        elif msg.type == message_pb2.P2PMessage.AES_KEY_EXCHANGE:
            type_str = "AES_KEY_EXCHANGE"
        elif msg.type == message_pb2.P2PMessage.CHAT_MESSAGE:
            type_str = "CHAT_MESSAGE"
            
        return type_str, msg.payload, msg.nonce, msg.hmac_tag
        
    except Exception as e:
        print(f"[!] Error unpacking message: {e}")
        return None, None, None, None
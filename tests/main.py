import asyncio
import sys
from src.network import P2PNetwork

async def main():
    print("🔐 P2P Chat - Network Test")
    
    my_port = int(input("📡 My port (I listen on): ") or "8765")
    peer_address = input("🌍 Peer address (IP or domain): ") or "localhost"  # ✅ New input
    peer_port = int(input("🔌 Peer port (they listen on): ") or "8766")
    
    network = P2PNetwork(
        my_port=my_port,
        peer_address=peer_address,  # ✅ Pass peer_address
        peer_port=peer_port
    )
    
    await network.start()
    # ... rest of code
    
    # Interactive message loop
    try:
        while True:
            message = await asyncio.get_event_loop().run_in_executor(
                None, input, "You: "
            )
            
            if message.lower() == "quit":
                break
            
            if message.strip():
                # Convert text to bytes (later: Person 1 encrypts this)
                await network.send(message.encode("utf-8"))
    finally:
        await network.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Main] 👋 Shutting down...")
        sys.exit(0)
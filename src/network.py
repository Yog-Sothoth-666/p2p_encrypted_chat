import asyncio
import websockets
from typing import Optional, Callable

class P2PNetwork:
    """
    Pure P2P Network Manager.
    Each peer runs both a Server (listens) and a Client (connects).
    """
    
    def __init__(self, my_port: int, peer_address: str, peer_port: int, on_message_callback: Callable = None):
        """
        peer_address: Can be "localhost", "192.168.1.45", or "203.0.113.10"
        """
        self.my_port = my_port  #port i listen on
        self.peer_address = peer_address # IP/hostname (i think need dns) of the other
        self.peer_port = peer_port # port the other peer 
        # Store the callback function (Person 3 will use this later)
        self.on_message_callback = on_message_callback or self._default_handler
        # My server : I listen on this 
        self.server = None 
        self.outgoing_ws : Optional[websockets.WebsocketClientProtocol] = None # I → Peer
        self.incoming_ws: Optional[websockets.WebSocketServerProtocol] = None  # Peer → I
        self._is_running = False 

    
    
    async def start(self):
        print(f"[Network] 🚀 Starting P2P Node...")
        print(f"[Network] 📡 I will listen on: ws://0.0.0.0:{self.my_port}")  # Listen on ALL interfaces
        print(f"[Network] 🔌 I will connect to: ws://{self.peer_address}:{self.peer_port}")  # ✅ Use peer_address

        # Start server on 0.0.0.0 (all interfaces)
        self.server = await websockets.serve(self._handle_incoming, "0.0.0.0", self.my_port)
        print("[Network] ✅ Server started")

        # Connect to peer
        await asyncio.sleep(0.5)
        try:
            # ✅ Use peer_address here too
            self.outgoing_ws = await websockets.connect(f"ws://{self.peer_address}:{self.peer_port}")
            print("[Network] ✅ Connected to peer")
        except Exception as e:
            print(f"[Network] ⚠️ Could not connect yet: {e}")
            print("[Network]    Will keep trying when peer starts...")

        self._is_running = True
        asyncio.create_task(self._receive_loop(self.outgoing_ws, "outgoing"))
        print("[Network] 🟢 P2P network ready!\n")
    
    
    
    async def _handle_incoming(self, websocket):  # ✅ Removed 'path'
        """Called automatically when peer connects to my server"""
        self.incoming_ws = websocket
        print("[Network] 🤝 Peer connected to my server!")
        
        asyncio.create_task(self._receive_loop(websocket, "incoming"))
        
        try:
            await websocket.wait_closed()
        finally:
            print("[Network] 🔌 Peer disconnected from my server")
            self.incoming_ws = None

    
    
    async def _receive_loop(self, websocket, connection_type: str):
        """Background task that constantly listens for messages"""
        if not websocket:
            return
            
        try:
            async for message in websocket:
                # Handle both sync and async callbacks safely
                callback = self.on_message_callback(message, connection_type)
                if asyncio.iscoroutine(callback):
                    await callback
                # If it's not a coroutine, it's a sync function - already executed
        except websockets.exceptions.ConnectionClosed:
            print(f"[Network] 🔌 {connection_type} connection closed")
        except Exception as e:
            print(f"[Network] ⚠️ Error in {connection_type} receive: {e}")
        
    
    async def send(self, data: bytes):
        """Send encrypted bytes to the peer"""
        if not self.outgoing_ws and not self.incoming_ws:
            print("[Network]  Cannot send: No active connections")
            return
        
        # Try outgoing first, fallback to incoming
        if self.outgoing_ws:
            await self.outgoing_ws.send(data)
        elif self.incoming_ws:
            await self.incoming_ws.send(data)

    
    
    
    async def _default_handler(self, message: bytes, conn_type: str):
        """Default callback if Person 3 hasn't connected yet"""
        print(f"[Network] 📥 Received {len(message)} bytes via {conn_type}")

    
    
    
    async def stop(self):
        """Clean shutdown"""
        self._is_running = False
        if self.outgoing_ws:
            await self.outgoing_ws.close()
        if self.incoming_ws:
            await self.incoming_ws.close()
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        print("[Network] 🔴 Network stopped")
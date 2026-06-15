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
        self._background_tasks = set()

    async def start(self):
        """Start the server and attempt to connect to the peer."""
        if self.server is None:
            # Start server on 0.0.0.0 (all interfaces)
            self.server = await websockets.serve(self._handle_incoming, "0.0.0.0", self.my_port)
            self._is_running = True

        if not self.outgoing_ws:
            # Connect to peer
            try:
                # ✅ Use peer_address here too
                self.outgoing_ws = await websockets.connect(f"ws://{self.peer_address}:{self.peer_port}")
                task = asyncio.create_task(self._receive_loop(self.outgoing_ws, "outgoing"))
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)
            except Exception:
                pass

        if self._is_running:
            pass

    async def _handle_incoming(self, websocket):  # ✅ Removed 'path'
        """Called automatically when peer connects to my server"""
        self.incoming_ws = websocket
        
        task = asyncio.create_task(self._receive_loop(websocket, "incoming"))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        
        try:
            await websocket.wait_closed()
        finally:
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
        except (websockets.exceptions.ConnectionClosed, asyncio.CancelledError):
            pass
        except Exception:
            pass
        
    async def send(self, data: bytes):
        """Send encrypted bytes to the peer"""
        if not self.outgoing_ws and not self.incoming_ws:
            return
        
        # Try outgoing first, fallback to incoming
        try:
            if self.outgoing_ws:
                await self.outgoing_ws.send(data)
            elif self.incoming_ws:
                await self.incoming_ws.send(data)
        except Exception:
            pass

    async def _default_handler(self, message: bytes, conn_type: str):
        """Default callback if Person 3 hasn't connected yet"""
        pass

    async def stop(self):
        """Clean shutdown"""
        self._is_running = False
        
        # Cancel all background tasks
        for task in list(self._background_tasks):
            task.cancel()
        
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)

        if self.outgoing_ws:
            await self.outgoing_ws.close()
        if self.incoming_ws:
            await self.incoming_ws.close()
        if self.server:
            self.server.close()
            await self.server.wait_closed()

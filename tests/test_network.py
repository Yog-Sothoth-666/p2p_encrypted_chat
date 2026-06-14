"""
Test P2P Network Layer: Two nodes connect over localhost sockets and exchange bytes.
"""

import asyncio
import pytest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

from network import P2PNetwork


class TestP2PNetwork:
    """Test the P2P networking layer with real socket connections."""

    @pytest.mark.asyncio
    async def test_two_nodes_exchange_bytes(self):
        """
        Two P2PNetwork nodes connect over localhost sockets and exchange
        bytes in both directions.
        """
        # Node A listens on 5001, connects to B on 5002
        # Node B listens on 5002, connects to A on 5001

        messages_received_a = []
        messages_received_b = []

        async def callback_a(msg, conn_type):
            messages_received_a.append((msg, conn_type))

        async def callback_b(msg, conn_type):
            messages_received_b.append((msg, conn_type))

        # Create two P2P nodes
        node_a = P2PNetwork(5001, "localhost", 5002, on_message_callback=callback_a)
        node_b = P2PNetwork(5002, "localhost", 5001, on_message_callback=callback_b)

        try:
            # Start both nodes
            await node_a.start()
            await node_b.start()

            # Give them time to connect
            await asyncio.sleep(1)

            # Node A sends to Node B
            test_message_1 = b"Hello from Node A"
            await node_a.send(test_message_1)

            # Give time for message to arrive
            await asyncio.sleep(0.5)

            # Node B sends to Node A
            test_message_2 = b"Response from Node B"
            await node_b.send(test_message_2)

            # Give time for message to arrive
            await asyncio.sleep(0.5)

            # Verify messages were received
            assert len(messages_received_b) > 0, "Node B should have received message from A"
            assert len(messages_received_a) > 0, "Node A should have received message from B"

            # Find the actual messages in the received data
            received_at_b = [msg for msg, _ in messages_received_b]
            received_at_a = [msg for msg, _ in messages_received_a]

            assert test_message_1 in received_at_b, f"Node B should receive message from A"
            assert test_message_2 in received_at_a, f"Node A should receive message from B"

            print(f"✅ Node A sent and received: {len(messages_received_a)} messages")
            print(f"✅ Node B sent and received: {len(messages_received_b)} messages")

        finally:
            # Clean shutdown
            await node_a.stop()
            await node_b.stop()
            await asyncio.sleep(0.2)

    @pytest.mark.asyncio
    async def test_multiple_exchanges(self):
        """Test multiple back-and-forth message exchanges."""
        received_a = []
        received_b = []

        async def callback_a(msg, conn_type):
            received_a.append(msg)

        async def callback_b(msg, conn_type):
            received_b.append(msg)

        node_a = P2PNetwork(5003, "localhost", 5004, on_message_callback=callback_a)
        node_b = P2PNetwork(5004, "localhost", 5003, on_message_callback=callback_b)

        try:
            await node_a.start()
            await node_b.start()
            await asyncio.sleep(1)

            # Send multiple messages
            for i in range(3):
                msg_a = f"Message {i} from A".encode()
                msg_b = f"Message {i} from B".encode()

                await node_a.send(msg_a)
                await node_b.send(msg_b)
                await asyncio.sleep(0.3)

            # Verify all messages received
            assert len(received_a) >= 3, f"Node A should receive at least 3 messages, got {len(received_a)}"
            assert len(received_b) >= 3, f"Node B should receive at least 3 messages, got {len(received_b)}"

            print(f"✅ Multiple exchanges successful: {len(received_a)}, {len(received_b)}")

        finally:
            await node_a.stop()
            await node_b.stop()
            await asyncio.sleep(0.2)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

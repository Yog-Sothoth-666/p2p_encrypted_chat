#!/usr/bin/env python3
"""
P2P Encrypted Chat Application

A secure peer-to-peer chat application with hybrid encryption (RSA + AES),
message integrity (HMAC), and sender authentication (digital signatures).

Usage:
    python main.py --role initiator --my-port 9998 --peer-address localhost --peer-port 9999
    python main.py --role receiver --my-port 9999 --peer-address localhost --peer-port 9998
"""

import asyncio
import sys
import os
import argparse
import logging

# Add current directory to path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.session_manager import SessionManager

logging.basicConfig(level=logging.INFO, format='[%(name)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


async def run_chat_session(args):
    """
    Run the encrypted chat session.

    Args:
        args: Parsed command line arguments
    """
    # Create the session manager
    session = SessionManager(
        role=args.role,
        my_port=args.my_port,
        peer_address=args.peer_address,
        peer_port=args.peer_port,
        storage_file=args.log_file,
    )

    try:
        # Run the handshake
        print(f"\n🔐 Starting P2P Encrypted Chat ({args.role.upper()})")
        print(f"   Listening on: ws://0.0.0.0:{args.my_port}")
        print(f"   Connecting to: ws://{args.peer_address}:{args.peer_port}")

        await session.run_handshake()

        # Chat loop
        print("\n📝 Chat ready! Type 'quit' to exit.")
        print("   Type your message and press Enter to send\n")

        # Create a task for receiving messages in the background
        receive_task = None
        pending_message = None

        while True:
            # Get user input in a non-blocking way
            try:
                user_input = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(None, input, "You: "),
                    timeout=0.5,
                )

                if user_input.lower() == "quit":
                    print("\n👋 Goodbye!")
                    break

                if user_input.strip():
                    # Send message
                    await session.send_message(user_input)

            except asyncio.TimeoutError:
                # No input available, check for received messages
                if receive_task is None or receive_task.done():
                    receive_task = asyncio.create_task(session.receive_message(timeout=1))

                # Check if we have a received message
                if receive_task and receive_task.done():
                    try:
                        pending_message = receive_task.result()
                        if pending_message:
                            print(f"\n🤖 Peer: {pending_message}")
                            print("You: ", end="", flush=True)
                        receive_task = None
                    except Exception as e:
                        logger.error(f"Error receiving message: {e}")
                        receive_task = None

    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user")

    except Exception as e:
        logger.error(f"Error during chat: {e}", exc_info=True)

    finally:
        # Clean shutdown
        await session.stop()

        # Display chat history
        print("\n📋 Chat History (from local encrypted log):")
        print("=" * 50)
        try:
            history = session.get_chat_history()
            if history:
                for entry in history:
                    direction = "→ Sent" if entry.direction == 0 else "← Received"
                    print(f"{direction}: {entry.plaintext_content}")
            else:
                print("(No messages in history)")
        except Exception as e:
            logger.error(f"Error reading history: {e}")

        print("=" * 50)
        print(f"Log file: {session.storage_file}\n")


def create_parser():
    """Create and return the argument parser."""
    parser = argparse.ArgumentParser(
        description="P2P Encrypted Chat Application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start as initiator (connect to receiver)
  python main.py --role initiator --my-port 9998 --peer-address localhost --peer-port 9999

  # Start as receiver (wait for initiator)
  python main.py --role receiver --my-port 9999 --peer-address localhost --peer-port 9998

  # With custom log file
  python main.py --role initiator --my-port 9998 --peer-address 192.168.1.100 --peer-port 9999 --log-file my_chat.bin
        """,
    )

    parser.add_argument(
        "--role",
        choices=["initiator", "receiver"],
        required=True,
        help="Your role in the handshake (initiator connects, receiver listens)",
    )

    parser.add_argument(
        "--my-port",
        type=int,
        required=True,
        help="Port this peer listens on (e.g., 9998)",
    )

    parser.add_argument(
        "--peer-address",
        type=str,
        required=True,
        help="IP address or hostname of the peer (e.g., localhost, 192.168.1.100)",
    )

    parser.add_argument(
        "--peer-port",
        type=int,
        required=True,
        help="Port the peer listens on (e.g., 9999)",
    )

    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Path to encrypted chat log file (optional, auto-generated if not specified)",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    return parser


async def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        await run_chat_session(args)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Main] 👋 Shutting down...")
        sys.exit(0)

# P2P Encrypted Messaging System

## Description
This project is a secure, peer-to-peer (P2P) command-line chat application. It implements a custom cryptographic protocol featuring a hybrid encryption handshake (RSA + AES) to ensure end-to-end confidentiality, message integrity via HMAC, and sender authentication through digital signatures. 

## Core Features
* **Hybrid Handshake:** Secure exchange of session keys using RSA-2048 and OAEP padding.
* **Encrypted Transport:** All chat messages are encrypted in transit using AES-256-GCM.
* **Integrity & Authentication:** Every message includes an HMAC-SHA256 tag and an RSA digital signature to prevent tampering and spoofing.
* **Forward Secrecy:** Automated session key rotation during active conversations.
* **Secure Logging:** Local chat history is encrypted before being written to the disk.

## Team Structure & Roles
This project is divided into four distinct development domains:
1. **Cryptography Core:** Mathematical primitives, key generation, and raw encryption/decryption logic.
2. **Network Protocol:** Socket/WebSocket management and raw byte transmission.
3. **Session Management:** Orchestrating the handshake, key rotation, and the flow of messages between the crypto and network layers.
4. **Storage & QA:** Protobuf data serialization, encrypted local logging, and comprehensive end-to-end testing.

## Installation Instructions

**1. Clone the repository**
Ensure you have Git installed, then clone the project to your local machine:
`git clone [YOUR_REPOSITORY_URL_HERE]`

**2. Create a virtual environment**
It is highly recommended to use a virtual environment to isolate the project dependencies.
`python -m venv venv`

**3. Activate the environment**
* On Linux: `source venv/bin/activate`
* On Windows: `venv\Scripts\activate`

**4. Install dependencies**
Run the following command to install the required cryptographic and networking libraries:
`pip install -r requirements.txt`

## Running the Application
*(Instructions to be added once `main.py` is implemented)*

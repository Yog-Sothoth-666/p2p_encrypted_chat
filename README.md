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

# 1. Clone the repository
Ensure you have Git installed, then clone the project to your local machine:
```bash
git clone https://github.com/Yog-Sothoth-666/p2p_encrypted_chat.git
cd p2p_encrypted_chat
```
# 2. Create a virtual environment
It is highly recommended to use a virtual environment to isolate the project dependencies.
```bash
python -m venv venv
```
# 3. Activate the environment
## macOS / Linux
```bash
source venv/bin/activate
```
## Windows (Command Prompt)
```cmd
venv\Scripts\activate.bat
```
## Windows (PowerShell)
```powershell
.\venv\Scripts\Activate.ps1
``` 
# 4. Install dependencies
Run the following command to install the required cryptographic and networking libraries:
```bash
pip install -r requirements.txt
```

## Running the Application
*(Instructions to be added once `main.py` is implemented)*

## 📂 File Ownership & Work Boundaries
To completely avoid Git merge conflicts, team members must only edit the files assigned to their role unless agreed upon in a meeting.

* **Person 1 (Crypto Core):** Owns `src/crypto_utils.py` and `tests/test_crypto.py`.
* **Person 2 (Network):** Owns `src/network.py` and assists with `protos/message.proto`.
* **Person 3 (Protocol):** Owns `src/session_manager.py` and `main.py`.
* **Person 4 (Storage & QA):** Owns `src/storage.py`, `protos/message.proto`, and all End-to-End tests in the `tests/` directory.

## 🔄 Team Git Workflow
We are using a feature-branch workflow. Do not push directly to `master`.

1. **Pull the latest code:** `git pull origin master`
2. **Create a branch for your task:** `git checkout -b feature/your-name-task` (e.g., `feature/yahya-rsa-keys`)
3. **Commit your work:** `git commit -m "feat: added RSA generation"`
4. **Push your branch:** `git push -u origin feature/your-name-task`
5. **Review:** Let the team know your branch is ready to be merged into `master`.

## 🧪 Quality Assurance & Testing
This project uses `pytest` to ensure cryptographic integrity and network reliability.

To run the entire test suite:
`pytest tests/ -v`

To test a specific module (e.g., cryptography):
`pytest tests/test_crypto.py -v`



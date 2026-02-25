<p align="center">
  
</p>
<p align="center"><h1 align="center">n0cryp2</h1></p>
<p align="center">
	<em><code>❯ An end-to-end encrypted multi-client chat application over TCP/IP using C, built with TLS 1.3 and X25519/AES-256-GCM.
  n0cryp2 enables secure communication where even the server cannot read messages. It is an experimental project for exploring modern cryptographic protocols on UNIX systems.</code></em>
</p>
<p align="center">
	<!-- Shields.io badges disabled, using skill icons. --></p>
<p align="center">Built with the tools and technologies:</p>
<p align="center">
	<a href="https://skillicons.dev">
		<img src="https://skillicons.dev/icons?i=vscode,c,md,linux&theme=dark">
	</a></p>
<br>

## 🔗 Table of Contents

- [📍 Overview](#-overview)
- [🔐 Security Architecture](#-security-architecture)
- [👾 Features](#-features)
- [🚀 Getting Started](#-getting-started)
  - [☑️ Prerequisites](#-prerequisites)
  - [⚙️ Installation](#-installation)
  - [🤖 Usage](#🤖-usage)
  - [🧪 Testing](#🧪-testing)
- [📌 Project Roadmap](#-project-roadmap)
- [🎗 License](#-license)
- [🙌 Acknowledgments](#-acknowledgments)

---

## 📍 Overview

<code>❯ n0cryp2 is a multi-client chat application with two layers of encryption. TLS 1.3 secures the transport between clients and the server, while X25519 key exchange combined with AES-256-GCM provides true end-to-end encryption between clients. The server acts as a relay only — it cannot read any messages. Network traffic is fully encrypted; no readable data was observed when packets were examined with Wireshark.</code>

---

## 🔐 Security Architecture

```
Layer 1 — TLS 1.3 (Transport Security)
  Client ←──TLS 1.3──→ Server ←──TLS 1.3──→ Client
  • Protects against network eavesdropping
  • Server authenticated via certificate

Layer 2 — X25519 + AES-256-GCM (End-to-End)
  Client A ←─────── E2E Encrypted ────────→ Client B
  • Server is RELAY-ONLY, cannot read messages
  • Each client generates X25519 keypair at login
  • Pairwise shared secrets via ECDH + HKDF-SHA256
  • Messages encrypted with AES-256-GCM (authenticated)
```

**Protocol Messages (binary, length-prefixed):**
| Type | Direction | Purpose |
|------|-----------|---------|
| `0x01` LOGIN_REQ | C→S | Credentials (plaintext over TLS) |
| `0x02` LOGIN_RES | S→C | Login result + assigned client ID |
| `0x03` PUB_KEY | Both | X25519 public key announcement |
| `0x04` KEY_LIST | S→C | All connected peers' public keys |
| `0x05` E2E_MSG | Both | End-to-end encrypted message |
| `0x06` CLIENT_LEFT | S→C | Peer disconnection notice |

---

## 👾 Features
<code>❯ True end-to-end encryption — server cannot read messages</code><br>
<code>❯ TLS 1.3 transport security with certificate authentication</code><br>
<code>❯ X25519 ECDH key exchange + HKDF-SHA256 key derivation</code><br>
<code>❯ AES-256-GCM authenticated encryption for messages</code><br>
<code>❯ Multi-client support (up to 10 simultaneous clients)</code><br>
<code>❯ Thread-safe connection and peer key management</code><br>
<code>❯ Detailed logging on server (stdout) and client (log file)</code><br>
<code>❯ Cross-platform build (Linux & macOS)</code><br>
<code>❯ Pure C implementation (C11)</code><br>

---
## 🚀 Getting Started

### ☑️ Prerequisites

- **C Compiler:** `gcc` with C11 support
- **OpenSSL 3.x:** Required for TLS 1.3, X25519, AES-GCM, HKDF
  - Debian/Ubuntu: `sudo apt install libssl-dev`
  - macOS: `brew install openssl`
- **Operating System:** Linux (Ubuntu/Debian tested) or macOS


### ⚙️ Installation

1. Clone the repository:
```sh
❯ git clone https://github.com/n0connect/n0cryp2
❯ cd n0cryp2
```

2. Install dependencies:
```sh
# Debian/Ubuntu
❯ ./requirements_debian.sh

# macOS
❯ brew install openssl
```

3. Generate TLS certificates:
```sh
❯ make certs
```

4. Build:
```sh
❯ make all
```

### 🤖 Usage
Start server:
```sh
❯ ./server
```
Start client (in separate terminal):
```sh
❯ ./client
```
Log in with predefined credentials (`database.c`):
```sh
❯ Username: n0n0
❯ Password: n0n0
```

### 🧪 Testing
1. Start the server and connect 2+ clients
2. Send messages between clients
3. Verify in server logs: messages show as **"ENCRYPTED"** — server cannot read content
4. Check `client_log.log` for client-side transaction details

---
## 📌 Project Roadmap

- [x] **`Task 1`**: ~~Multi-client connection support~~
- [x] **`Task 2`**: ~~User authentication system~~
- [x] **`Task 3`**: ~~TLS 1.3 transport encryption~~
- [x] **`Task 4`**: ~~X25519 + AES-256-GCM end-to-end encryption~~
- [x] **`Task 5`**: ~~Comprehensive bug fix & code quality pass (69 fixes)~~
- [ ] **`Task 6`**: Password hashing and real database support
- [ ] **`Task 7`**: Qt cross-platform GUI client
- [ ] **`Task 8`**: Forward secrecy with ephemeral key rotation

      
---

## 🎗 License

This project is protected under the MIT licence. See the LICENSE file for more information.

---

## 🙌 Acknowledgments

- [OpenSSL](https://www.openssl.org/) for TLS 1.3, X25519, AES-256-GCM, and HKDF
- Inspired by modern E2E protocols (Signal, Noise Framework)

---

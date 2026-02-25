<p align="center">
  
</p>
<p align="center"><h1 align="center">n0cryp2</h1></p>
<p align="center">
	<em><code>❯ It is a communication/messaging programme over Local Network on UNIX systems using C/C++, it is an experimental project.
  n0cryp2 is a multi-client chat application that enables secure communication over TCP/IP protocol. The project allows users to send encrypted messages to each other and perform connection management through a central server.</code></em>
</p>
<p align="center">
	<!-- Shields.io badges disabled, using skill icons. --></p>
<p align="center">Built with the tools and technologies:</p>
<p align="center">
	<a href="https://skillicons.dev">
		<img src="https://skillicons.dev/icons?i=vscode,c,cpp,md,linux&theme=dark">
	</a></p>
<br>

## 🔗 Table of Contents

- [📍 Overview](#-overview)
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

<code>❯ n0cryp2 provides encrypted messaging by enabling clients to connect to the server. While user authentication and logging are performed on the server side, each transaction on the client side is recorded in a detailed log file. Messages are protected with RSA encryption (OAEP padding). Network traffic is fully encrypted — no readable data was observed when packets were examined over the local network with Wireshark.</code>

---

## 👾 Features
<code>❯ Multi-client support (up to 10 simultaneous clients)</code><br>
<code>❯ Secure messaging with RSA 2048-bit encryption (PKCS1 OAEP)</code><br>
<code>❯ Detailed logging on server (stdout) and client side (log file)</code><br>
<code>❯ User authentication (predefined username and password)</code><br>
<code>❯ Thread-safe connection management with pthreads</code><br>
<code>❯ Cross-platform build support (Linux & macOS)</code><br>

---
## 🚀 Getting Started

### ☑️ Prerequisites

Before getting started with n0cryp2, ensure your runtime environment meets the following requirements:

- **C/C++ Compiler:** `gcc` (C11) and `g++` (C++20) — GCC or Clang
- **OpenSSL Library:** Required for RSA encryption (`libssl-dev` on Debian, `openssl` on Homebrew)
- **GMP Library:** Required for large number operations (`libgmp-dev` on Debian, `gmp` on Homebrew)
- **Operating System:** Linux (Ubuntu/Debian tested) or macOS


### ⚙️ Installation

Install n0cryp2 using one of the following methods:

**Build from source:**

1. Clone the n0cryp2 repository:
```sh
❯ git clone https://github.com/n0connect/n0cryp2
```

2. Navigate to the project directory:
```sh
❯ cd n0cryp2
```

3. Install dependencies and generate RSA keys:
```sh
# Debian/Ubuntu
❯ ./requirements_debian.sh

# macOS (manual)
❯ brew install openssl gmp
❯ mkdir -p server-key
❯ openssl genpkey -algorithm RSA -out server-key/private_key.pem -pkeyopt rsa_keygen_bits:2048
❯ openssl pkey -in server-key/private_key.pem -pubout -out server-key/public_key.pem
```

4. Compile:
```sh
❯ make all
```

### 🤖 Usage
Start server with terminal:
```sh
❯ ./server
```
Start client with terminal:
```sh
❯ ./client
```
Log in: User names and passwords are predefined (`database.c`):
```sh
❯ Username : n0n0
❯ Password : n0n0
```

### 🧪 Testing
To test RSA encryption and connectivity, examine the `client_log.log` file. This file holds transaction details for each client.

---
## 📌 Project Roadmap

- [x] **`Task 1`**: ~~Multi-client connection support.~~
- [x] **`Task 2`**: ~~User authentication system.~~
- [x] **`Task 3`**: ~~RSA encryption integration.~~
- [x] **`Task 4`**: ~~Comprehensive bug fix & code quality pass (69 fixes).~~
- [ ] **`Task 5`**: Hybrid RSA+AES encryption (RSA for key exchange, AES for messages).
- [ ] **`Task 6`**: OpenSSL EVP API migration (replace deprecated RSA functions).
- [ ] **`Task 7`**: Password hashing and real database support.
- [ ] **`Task 8`**: Qt cross-platform GUI based client application.
- [ ] **`Task 9`**: Separate client/server key pairs for true end-to-end encryption.

      
---

## 🎗 License

This project is protected under the MIT licence. See the LICENSE file for more information.

---

## 🙌 Acknowledgments

- OpenSSL for RSA encryption.

---

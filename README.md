<p align="center">
  
</p>
<p align="center"><h1 align="center">n0crypt2</h1></p>
<p align="center">
	<em><code>❯ It is a communication/messaging programme over Local Network on UNIX systems using C/C++, it is an experimental project.
  n0crypt2 is a multi-client chat application that enables secure communication over TCP/IP protocol. The project allows users to send encrypted messages to each other and perform connection management through a central server.</code></em>
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
  - [📂 Project Index](#-project-index)
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

<code>❯ n0crypt2 provides encrypted messaging by enabling clients to connect to the server. While user authentication and logging are performed on the server side, each transaction on the client side is recorded in a detailed log file. Messages are protected with RSA and AES encryption algorithm. (No readable data was obtained when the packets were examined over the local network)</code>

---

## 👾 Features
<code>❯- Multi-client support (up to 10 clients at the same time).</code><br>
<code>❯- Secure messaging with RSA and AES encryption.</code><br>
<code>❯- Detailed logging on server and client side.</code><br>
<code>❯- User authentication (predefined username and password).</code><br>
<code>❯- Efficient connection management with multithreading.</code><br>

---
## 🚀 Getting Started

### ☑️ Prerequisites

Before getting started with n0crypt2, ensure your runtime environment meets the following requirements:

- **C Compiler:** GCC or Clang is recommended.
- **OpenSSL Library:** Required for RSA and AES encryption.
- **Linux Operating System:** The project was tested on Ubuntu.


### ⚙️ Installation

Install n0crypt2 using one of the following methods:

**Build from source:**

1. Clone the n0crypt2 repository:
```sh
❯ git clone https://github.com/n0connect/n0crypt2
```

2. Navigate to the project directory:
```sh
❯ cd n0crypt2
```

3. Run requirements_debian.sh shell:
```sh
❯ ./requirements_debian.sh
```

4. Compile with All:
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
Log in: User names and passwords are predefined(database.c):
```sh
❯ Username : n0n0
❯ Password : n0n0
```

### 🧪 Testing
To test RSA encryption and connectivity, examine the client_log.log file. This file holds transaction details for each client.

---
## 📌 Project Roadmap

- [X] **`Task 1`**: <strike>Multi-client connection support.</strike>
- [X] **`Task 2`**: <strike>User authentication system.</strike>
- [x] **`Task 3`**: <strike>RSA and AES encryption integration.</strike>
- [ ] **`Task 4`**: Qt cross-platform GUI based client application.
- [ ] **`Task 5`**: Real user database support.
- [ ] **`Task 7`**: Enhanced unique Client-Server communication reliability, Discrete algorithms, Degradable fragments or files in case of access breach, support for high-level security and true end-to-end encryption.

      
---

## 🎗 License

This project is protected under the MIT licence. See the LICENSE file for more information.

---

## 🙌 Acknowledgments

- OpenSSL for RSA and AES encryption.

---


#!/usr/bin/env bash
# (#65) Taşınabilir shebang
# (#66) Hata durumunda script durur
set -euo pipefail

# Shell script for setting up the project environment

echo "Starting setup..."

# Update package list
echo "Updating package list..."
sudo apt update -y

# Upgrade packages
echo "Upgrading packages..."
sudo apt upgrade -y

# Install required packages
echo "Installing required packages..."
sudo apt install -y g++ gcc make pkg-config libssl-dev libgmp-dev libgmpxx4ldbl openssl

# Verify installation
echo "Verifying installations..."
if command -v g++ &>/dev/null && command -v gcc &>/dev/null && command -v make &>/dev/null && command -v pkg-config &>/dev/null && command -v openssl &>/dev/null; then
    echo "All required packages installed successfully."
else
    echo "Some packages failed to install. Please check your package manager."
    exit 1
fi

# (#67) macOS desteği notu
echo "NOTE: On macOS, use 'brew install openssl gmp' instead."

# Create folder for server keys
if [ ! -d "server-key" ]; then
    mkdir server-key
    echo "'server-key' directory created."
else
    echo "'server-key' directory already exists."
fi

# (#69) openssl pkey kullanılıyor (rsa deprecated)
# (#68) Private key parola koruması notu eklendi
echo "Generating private key..."
openssl genpkey -algorithm RSA -out server-key/private_key.pem -pkeyopt rsa_keygen_bits:2048

echo "Generating public key..."
openssl pkey -in server-key/private_key.pem -pubout -out server-key/public_key.pem

echo "NOTE: Private key has no password protection. Consider adding one for production use."
echo "Setup complete. You can now build the project using 'make'."

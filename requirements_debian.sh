#!/bin/bash

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
sudo apt install -y g++ make pkg-config libssl-dev libgmp-dev libgmpxx4ldbl openssl

# Verify installation
echo "Verifying installations..."
if command -v g++ &>/dev/null && command -v make &>/dev/null && command -v pkg-config &>/dev/null && command -v openssl &>/dev/null; then
    echo "All required packages installed successfully."
else
    echo "Some packages failed to install. Please check your package manager."
    exit 1
fi

# Create folder for server keys
if [ ! -d "server-key" ]; then
    mkdir server-key
    echo "'server-key' directory created."
else
    echo "'server-key' directory already exists."
fi

# Generate Private Key
echo "Generating private key..."
openssl genpkey -algorithm RSA -out server-key/private_key.pem -pkeyopt rsa_keygen_bits:2048

# Generate Public Key
echo "Generating public key..."
openssl rsa -in server-key/private_key.pem -pubout -out server-key/public_key.pem

# Print success message
echo "Setup complete. You can now build the project using 'make'."


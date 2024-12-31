# 🔐 SecureWallet

A secure crypto wallet with local encryption.

## 🛡️ Security Features

- Private key encryption with Fernet (symmetric cryptography)
- Secure key derivation with PBKDF2
- Encrypted local storage
- No network connection by default
- Protection against brute force attacks

## 📋 Prerequisites

- Python 3.8+
- pip

## 🚀 Installation

```bash
# Create virtual environment
python -m venv venv

# Activate environment
source venv/bin/activate  # Unix
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## 💼 Usage

```python
from src.wallet import SecureWallet

# Create a new wallet
wallet = SecureWallet("strong_password")

# Generate a new address
btc_wallet = wallet.create_wallet("my_bitcoin")
print(f"New address: {btc_wallet['address']}")

# List wallets
wallets = wallet.list_wallets()
print("My wallets:", wallets)

# Save securely
wallet.save_to_file("my_wallets.enc")

# Load from file
wallet = SecureWallet.load_from_file("my_wallets.enc", "strong_password")
```

## ⚠️ Warnings

- Keep your password safe - it cannot be recovered
- Make regular backups of the encrypted file
- Never expose your private keys
- Use a strong password

## 🔒 Best Practices

1. Use a strong password (>12 characters)
2. Store the encrypted file securely
3. Create backups on different media
4. Never share your private keys
5. Verify addresses before transactions
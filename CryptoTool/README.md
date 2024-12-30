# CryptoTool

A comprehensive cryptography tool integrating classic and modern algorithms, with password analysis and management features.

## Features

### Classic Ciphers
- **Caesar Cipher**: Shift cipher
- **Vigenère Cipher**: Polyalphabetic cipher
- **ROT13**: Caesar cipher variant with fixed shift of 13
- **Atbash**: Reverse alphabet substitution cipher

### Modern Ciphers
- **AES**: Advanced Encryption Standard (via Fernet)
- **RSA**: Asymmetric encryption
- **Base64**: Base64 encoding

### File Management
- File encryption/decryption with password
- Automatic file management (secure deletion)
- Error handling and recovery

### Password Tools
- Secure password generator
- Password strength analysis
- Security policy verification

### Analysis Tools
- Character frequency analysis
- Automatic Caesar key detection
- Index of Coincidence calculation

## Installation

1. Clone the repository:
```bash
git clone [repo-url]
cd CryptoTool
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Launch the tool:
```bash
python crypto.py
```

### Usage Examples

1. Encrypt a message with Caesar:
   - Choose option 1
   - Enter text to encrypt
   - Specify key (number)

2. Encrypt a file:
   - Choose option 14
   - Enter file path
   - Set a password

3. Analyze encrypted text:
   - Choose option 18 for frequency analysis
   - Enter encrypted text

4. Generate a secure password:
   - Choose option 16
   - Specify desired length

## Project Structure

```
CryptoTool/
├── src/
│   ├── classic_ciphers.py    # Classic algorithms
│   ├── modern_ciphers.py     # Modern algorithms
│   ├── file_handler.py       # File management
│   ├── password_tools.py     # Password tools
│   └── analysis.py           # Analysis tools
├── crypto.py                 # Main interface
├── requirements.txt          # Dependencies
└── README.md                # Documentation
```

## Security

⚠️ Important note: This tool is designed for educational and demonstration purposes. For production applications, use established cryptographic libraries and follow security best practices.

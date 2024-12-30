# Basic Password Cracker Plus

An educational tool to understand different password cracking methods and hash analysis.

## Description

This tool allows you to:
- Crack passwords using different methods
- Analyze and identify hash types
- Use professional tools (Hashcat and John the Ripper)
- Learn different cracking techniques interactively

## Prerequisites

- Python 3.6+
- pip (Python package manager)
- Hashcat (recommended)
- John the Ripper (optional)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/BasicPasswordCracker.git
   cd BasicPasswordCracker
   ```

2. Install Python dependencies:
   ```bash
   pip install requests
   ```

3. Install Hashcat (recommended):
   ```bash
   # On Ubuntu/Debian
   sudo apt-get install hashcat
   
   # On macOS
   brew install hashcat
   ```

4. (Optional) Install John the Ripper:
   ```bash
   # On Ubuntu/Debian
   sudo apt-get install john
   
   # On macOS
   brew install john
   ```

## Features

1. **Password Cracking**
   - Dictionary attack
   - Brute force attack
   - Using Hashcat
   - Using John the Ripper

2. **Supported Hash Types**
   - MD5
   - SHA1
   - SHA256
   - SHA512
   - NTLM
   - MySQL
   - bcrypt

3. **Hash Analysis**
   - Automatic type identification
   - Composition analysis
   - Common usage information

4. **Configuration**
   - Preferred tool selection
   - Attack duration customization
   - Wordlist management

## Usage

1. Launch the program:
   ```bash
   python passwordCracker.py
   ```

2. Main menu:
   ```
   1. Crack a password    : Crack a plaintext password
   2. Crack a hash        : Crack a hash directly
   3. Configure settings  : Modify settings
   4. Check external tools: Check available tools
   5. Analyze a hash      : Analyze a hash without cracking
   6. Exit               : Exit program
   ```

3. Usage examples:
   ```bash
   # Analyze an MD5 hash
   > Choose 5
   > Enter hash: 5f4dcc3b5aa765d61d8327deb882cf99

   # Crack a password
   > Choose 1
   > Enter password: mypassword

   # Crack a hash directly
   > Choose 2
   > Enter hash: 5f4dcc3b5aa765d61d8327deb882cf99
   ```

## Wordlists

- The program automatically downloads rockyou.txt on first launch
- A basic wordlist is included by default
- You can add your own wordlists through configuration

## Advanced Configuration

- Modify maximum brute force times
- Change maximum password length
- Enable/disable external tools
- Choose between Hashcat and John the Ripper
- Configure verbosity level

## Security and Ethics

This tool is created for educational purposes only. Its use must be:
- Within legal boundaries
- On your own systems
- To understand password security

Malicious use of this tool is strictly prohibited.

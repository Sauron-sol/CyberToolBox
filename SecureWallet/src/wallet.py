from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
import os
from typing import Dict, Optional
import secrets
from eth_account import Account
import binascii
import hashlib

class SecureWallet:
    ITERATIONS = 480000
    
    def __init__(self, password: str):
        """Initialize wallet with password"""
        self.salt = os.urandom(16)
        self.password = password  # Store password temporarily for reinitialization
        self.key = self._generate_key()
        self.fernet = Fernet(self.key)
        self.wallets: Dict[str, dict] = {}
        
    def _generate_key(self) -> bytes:
        """Generate encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=self.ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.password.encode()))

    def create_wallet(self, name: str) -> dict:
        """Create a new cryptocurrency wallet"""
        private_key = secrets.token_hex(32)
        account = Account.from_key('0x' + private_key)
        
        wallet = {
            'address': account.address,
            'private_key': self.fernet.encrypt(private_key.encode()).decode(),
            'name': name,
            'balance': 0.0
        }
        
        self.wallets[name] = wallet
        return {'address': wallet['address'], 'name': name}

    def get_private_key(self, name: str) -> Optional[str]:
        """Get decrypted private key for a wallet"""
        if name not in self.wallets:
            return None
            
        encrypted_key = self.wallets[name]['private_key']
        try:
            decrypted_key = self.fernet.decrypt(encrypted_key.encode()).decode()
            return decrypted_key
        except:
            return None

    def list_wallets(self) -> list:
        """List all wallets without sensitive data"""
        return [
            {'name': name, 'address': w['address'], 'balance': w['balance']}
            for name, w in self.wallets.items()
        ]

    def save_to_file(self, filename: str):
        """Save encrypted wallet data to file"""
        with open(filename, 'wb') as f:
            # Write salt size (16 bytes) and salt
            f.write(self.salt)
            
            # Encrypt and write wallet data
            data = {'wallets': self.wallets}
            encrypted_data = self.fernet.encrypt(json.dumps(data).encode())
            f.write(encrypted_data)

    @classmethod
    def load_from_file(cls, filename: str, password: str) -> 'SecureWallet':
        """Load wallet from encrypted file"""
        with open(filename, 'rb') as f:
            # Read salt (first 16 bytes)
            salt = f.read(16)
            # Read rest of encrypted data
            encrypted_data = f.read()

        try:
            # Create new wallet instance with same password
            wallet = cls(password)
            # Replace generated salt with stored salt
            wallet.salt = salt
            # Regenerate key with stored salt
            wallet.key = wallet._generate_key()
            wallet.fernet = Fernet(wallet.key)
            
            # Decrypt data
            decrypted_data = wallet.fernet.decrypt(encrypted_data)
            data = json.loads(decrypted_data.decode())
            
            # Load wallets
            wallet.wallets = data['wallets']
            return wallet
            
        except Exception as e:
            print(f"Debug - Decryption error: {str(e)}")
            raise ValueError("Invalid password or corrupted file")

    def export_wallet(self, name: str, export_private_key: bool = False) -> dict:
        """Export wallet data (optionally with private key)"""
        if name not in self.wallets:
            return {}
            
        wallet = self.wallets[name].copy()
        if not export_private_key:
            wallet.pop('private_key')
        return wallet

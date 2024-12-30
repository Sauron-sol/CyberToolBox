from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

def generate_key_from_password(password):
    """Generate a Fernet key from a password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt_',  # In production, use a random salt
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def aes_encrypt(text, key):
    """Encrypt text using AES (via Fernet)"""
    f = Fernet(generate_key_from_password(key))
    return f.encrypt(text.encode()).decode()

def aes_decrypt(text, key):
    """Decrypt text using AES (via Fernet)"""
    f = Fernet(generate_key_from_password(key))
    return f.decrypt(text.encode()).decode()

def generate_rsa_keys():
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(text, public_key):
    """Encrypt text using RSA"""
    encrypted = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(encrypted_text, private_key):
    """Decrypt text using RSA"""
    encrypted = base64.b64decode(encrypted_text.encode())
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def base64_encode(text):
    """Encode text to Base64"""
    return base64.b64encode(text.encode()).decode()

def base64_decode(encoded_text):
    """Decode Base64 text"""
    return base64.b64decode(encoded_text.encode()).decode()

def process(algorithm, mode, input, key):
    """Process the input with the selected algorithm"""
    if algorithm == 'aes':
        if mode == 'encrypt':
            return aes_encrypt(input, key)
        else:
            return aes_decrypt(input, key)

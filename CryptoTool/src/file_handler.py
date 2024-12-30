import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_key_from_password(password):
    """Generate a valid Fernet key from a password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt_',  # In production, use a random salt
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(filepath, password):
    """Encrypt a file using Fernet with password"""
    try:
        if not os.path.exists(filepath):
            return "Error: File does not exist"
            
        key = generate_key_from_password(password)
        f = Fernet(key)
        
        with open(filepath, 'rb') as file:
            file_data = file.read()
        
        encrypted_data = f.encrypt(file_data)
        output_path = filepath + '.encrypted'
        
        # Write encrypted file
        with open(output_path, 'wb') as file:
            file.write(encrypted_data)
        
        # Delete original file after successful encryption
        os.remove(filepath)
        
        return output_path
    except Exception as e:
        # If error occurs, delete encrypted file if it was created
        if os.path.exists(filepath + '.encrypted'):
            os.remove(filepath + '.encrypted')
        return f"Error during encryption: {str(e)}"

def decrypt_file(filepath, password):
    """Decrypt a file using Fernet with password"""
    try:
        if not os.path.exists(filepath):
            return "Error: File does not exist"
            
        if not filepath.endswith('.encrypted'):
            return "Error: File does not appear to be encrypted (.encrypted)"
            
        key = generate_key_from_password(password)
        f = Fernet(key)
        
        with open(filepath, 'rb') as file:
            encrypted_data = file.read()
        
        try:
            decrypted_data = f.decrypt(encrypted_data)
        except InvalidToken:
            return "Error: Incorrect password or corrupted file"
        
        # Get original filename by removing .encrypted
        output_file = filepath[:-10]  
        
        # Write decrypted data to original file
        with open(output_file, 'wb') as file:
            file.write(decrypted_data)
        
        # Delete encrypted file after successful decryption
        os.remove(filepath)
        
        return output_file
    except Exception as e:
        # If error occurs, delete decrypted file if it was created
        output_file = filepath[:-10]
        if os.path.exists(output_file):
            os.remove(output_file)
        return f"Error during decryption: {str(e)}"

def save_to_file(data, filename):
    """Save data to a file"""
    try:
        with open(filename, 'w') as f:
            f.write(data)
        return True
    except Exception as e:
        return f"Error while saving: {str(e)}"

def read_from_file(filename):
    """Read data from a file"""
    try:
        if not os.path.exists(filename):
            return "Error: File does not exist"
            
        with open(filename, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error while reading: {str(e)}"

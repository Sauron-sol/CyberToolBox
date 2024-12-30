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
            return "Erreur: Le fichier n'existe pas"
            
        key = generate_key_from_password(password)
        f = Fernet(key)
        
        with open(filepath, 'rb') as file:
            file_data = file.read()
        
        encrypted_data = f.encrypt(file_data)
        output_path = filepath + '.encrypted'
        
        # Écriture du fichier chiffré
        with open(output_path, 'wb') as file:
            file.write(encrypted_data)
        
        # Suppression du fichier original après chiffrement réussi
        os.remove(filepath)
        
        return output_path
    except Exception as e:
        # En cas d'erreur, on supprime le fichier chiffré s'il a été créé
        if os.path.exists(filepath + '.encrypted'):
            os.remove(filepath + '.encrypted')
        return f"Erreur lors du chiffrement: {str(e)}"

def decrypt_file(filepath, password):
    """Decrypt a file using Fernet with password"""
    try:
        if not os.path.exists(filepath):
            return "Erreur: Le fichier n'existe pas"
            
        if not filepath.endswith('.encrypted'):
            return "Erreur: Le fichier ne semble pas être un fichier chiffré (.encrypted)"
            
        key = generate_key_from_password(password)
        f = Fernet(key)
        
        with open(filepath, 'rb') as file:
            encrypted_data = file.read()
        
        try:
            decrypted_data = f.decrypt(encrypted_data)
        except InvalidToken:
            return "Erreur: Mot de passe incorrect ou fichier corrompu"
        
        # Récupère le nom du fichier original en retirant .encrypted
        output_file = filepath[:-10]  # retire '.encrypted'
        
        # Écrit les données déchiffrées dans le fichier original
        with open(output_file, 'wb') as file:
            file.write(decrypted_data)
        
        # Supprime le fichier chiffré après déchiffrement réussi
        os.remove(filepath)
        
        return output_file
    except Exception as e:
        # En cas d'erreur, on supprime le fichier déchiffré s'il a été créé
        output_file = filepath[:-10]
        if os.path.exists(output_file):
            os.remove(output_file)
        return f"Erreur lors du déchiffrement: {str(e)}"

def save_to_file(data, filename):
    """Save data to a file"""
    try:
        with open(filename, 'w') as f:
            f.write(data)
        return True
    except Exception as e:
        return f"Erreur lors de la sauvegarde: {str(e)}"

def read_from_file(filename):
    """Read data from a file"""
    try:
        if not os.path.exists(filename):
            return "Erreur: Le fichier n'existe pas"
            
        with open(filename, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Erreur lors de la lecture: {str(e)}"

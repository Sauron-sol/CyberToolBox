from cryptography.fernet import Fernet
from src.classic_ciphers import caesar_cipher, vigenere_cipher, rot13_cipher, atbash_cipher
from src.modern_ciphers import (aes_encrypt, aes_decrypt, base64_encode, base64_decode,
                               generate_rsa_keys, rsa_encrypt, rsa_decrypt)
from src.analysis import frequency_analysis, detect_caesar_key, calculate_ic
from src.password_tools import generate_password, check_password_strength, validate_password_policy
from src.file_handler import encrypt_file, decrypt_file, save_to_file, read_from_file

def show_menu():
    print("\n=== CryptoTool ===")
    print("-- Chiffrement Classique --")
    print("1. Caesar Cipher - Encrypt")
    print("2. Caesar Cipher - Decrypt")
    print("3. Vigenere Cipher - Encrypt")
    print("4. Vigenere Cipher - Decrypt")
    print("5. ROT13")
    print("6. Atbash")
    print("\n-- Chiffrement Moderne --")
    print("7. AES - Encrypt")
    print("8. AES - Decrypt")
    print("9. RSA - Generate Keys")
    print("10. RSA - Encrypt")
    print("11. RSA - Decrypt")
    print("12. Base64 - Encode")
    print("13. Base64 - Decode")
    print("\n-- Gestion de Fichiers --")
    print("14. Chiffrer un fichier")
    print("15. Déchiffrer un fichier")
    print("\n-- Outils Mot de passe --")
    print("16. Générer un mot de passe")
    print("17. Vérifier la force d'un mot de passe")
    print("\n-- Analyse --")
    print("18. Analyse de fréquence")
    print("19. Détection clé Caesar")
    print("20. Calcul Index de Coïncidence")
    print("0. Exit")
    return input("\nChoisissez une option (0-20): ")

def main():
    rsa_keys = None
    while True:
        try:
            choice = show_menu()
            
            if choice == "0":
                break
            
            # Demande le texte seulement si ce n'est pas une opération sur fichier
            if choice not in ["14", "15"]:
                text = input("Entrez le texte: ")
            
            if choice in ["1", "2"]:
                key = input("Entrez la clé (nombre): ")
                result = caesar_cipher(text, key, decrypt=(choice=="2"))
            elif choice in ["3", "4"]:
                key = input("Entrez le mot clé: ")
                result = vigenere_cipher(text, key, decrypt=(choice=="4"))
            elif choice == "5":
                result = rot13_cipher(text)
            elif choice == "6":
                result = atbash_cipher(text)
            elif choice in ["7", "8"]:
                key = input("Entrez la clé de chiffrement: ")
                result = aes_encrypt(text, key) if choice == "7" else aes_decrypt(text, key)
            elif choice == "9":
                private_key, public_key = generate_rsa_keys()
                rsa_keys = (private_key, public_key)
                result = "Clés RSA générées avec succès"
                
            elif choice == "10":
                if not rsa_keys:
                    result = "Générez d'abord des clés RSA"
                else:
                    text = input("Entrez le texte: ")
                    result = rsa_encrypt(text, rsa_keys[1])
                    
            elif choice == "11":
                if not rsa_keys:
                    result = "Générez d'abord des clés RSA"
                else:
                    text = input("Entrez le texte chiffré: ")
                    result = rsa_decrypt(text, rsa_keys[0])
                    
            elif choice == "12":
                text = input("Entrez le texte: ")
                result = base64_encode(text)
                
            elif choice == "13":
                text = input("Entrez le texte encodé: ")
                result = base64_decode(text)
                
            elif choice == "14":
                filepath = input("Chemin du fichier à chiffrer: ")
                password = input("Entrez un mot de passe pour le chiffrement: ")
                result = encrypt_file(filepath, password)
                if isinstance(result, str) and result.startswith("Erreur"):
                    print(f"\n{result}")
                    continue
                result = f"Fichier chiffré: {result}"
                
            elif choice == "15":
                filepath = input("Chemin du fichier à déchiffrer: ")
                password = input("Entrez le mot de passe de déchiffrement: ")
                result = decrypt_file(filepath, password)
                if isinstance(result, str) and result.startswith("Erreur"):
                    print(f"\n{result}")
                    continue
                result = f"Fichier déchiffré: {result}"
                
            elif choice == "16":
                length = int(input("Longueur du mot de passe (default=12): ") or "12")
                result = generate_password(length)
                
            elif choice == "17":
                password = input("Entrez le mot de passe: ")
                strength = check_password_strength(password)
                policy = validate_password_policy(password)
                result = f"Force: {strength['score']}\nTemps de craquage estimé: {strength['crack_time']}\n"
                result += f"Politique de mot de passe:\n" + "\n".join(f"- {k}: {'✓' if v else '✗'}" for k, v in policy.items())
            elif choice == "18":
                freq = frequency_analysis(text)
                result = "\n".join([f"{char}: {freq:.2f}%" for char, freq in sorted(freq.items())])
            elif choice == "19":
                key = detect_caesar_key(text)
                result = f"Clé Caesar probable: {key}" if key is not None else "Impossible de détecter la clé"
            elif choice == "20":
                ic = calculate_ic(text)
                result = f"Index de Coïncidence: {ic:.4f}"
            
            print(f"\nRésultat: {result}")
            
        except Exception as e:
            print(f"\nErreur inattendue: {str(e)}")
        
        input("\nAppuyez sur Entrée pour continuer...")

if __name__ == "__main__":
    main()

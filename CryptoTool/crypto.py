from cryptography.fernet import Fernet
from src.classic_ciphers import caesar_cipher, vigenere_cipher, rot13_cipher, atbash_cipher
from src.modern_ciphers import (aes_encrypt, aes_decrypt, base64_encode, base64_decode,
                               generate_rsa_keys, rsa_encrypt, rsa_decrypt)
from src.analysis import frequency_analysis, detect_caesar_key, calculate_ic
from src.password_tools import generate_password, check_password_strength, validate_password_policy
from src.file_handler import encrypt_file, decrypt_file, save_to_file, read_from_file

def show_menu():
    print("\n=== CryptoTool ===")
    print("-- Classic Encryption --")
    print("1. Caesar Cipher - Encrypt")
    print("2. Caesar Cipher - Decrypt")
    print("3. Vigenere Cipher - Encrypt")
    print("4. Vigenere Cipher - Decrypt")
    print("5. ROT13")
    print("6. Atbash")
    print("\n-- Modern Encryption --")
    print("7. AES - Encrypt")
    print("8. AES - Decrypt")
    print("9. RSA - Generate Keys")
    print("10. RSA - Encrypt")
    print("11. RSA - Decrypt")
    print("12. Base64 - Encode")
    print("13. Base64 - Decode")
    print("\n-- File Management --")
    print("14. Encrypt file")
    print("15. Decrypt file")
    print("\n-- Password Tools --")
    print("16. Generate password")
    print("17. Check password strength")
    print("\n-- Analysis --")
    print("18. Frequency analysis")
    print("19. Caesar key detection")
    print("20. Calculate Index of Coincidence")
    print("0. Exit")
    return input("\nChoose an option (0-20): ")

def main():
    rsa_keys = None
    while True:
        try:
            choice = show_menu()
            
            if choice == "0":
                break
            
            # Request text only if it's not a file operation
            if choice not in ["14", "15"]:
                text = input("Enter text: ")
            
            if choice in ["1", "2"]:
                key = input("Enter key (number): ")
                result = caesar_cipher(text, key, decrypt=(choice=="2"))
            elif choice in ["3", "4"]:
                key = input("Enter keyword: ")
                result = vigenere_cipher(text, key, decrypt=(choice=="4"))
            elif choice == "5":
                result = rot13_cipher(text)
            elif choice == "6":
                result = atbash_cipher(text)
            elif choice in ["7", "8"]:
                key = input("Enter encryption key: ")
                result = aes_encrypt(text, key) if choice == "7" else aes_decrypt(text, key)
            elif choice == "9":
                private_key, public_key = generate_rsa_keys()
                rsa_keys = (private_key, public_key)
                result = "RSA keys generated successfully"
                
            elif choice == "10":
                if not rsa_keys:
                    result = "Generate RSA keys first"
                else:
                    text = input("Enter text: ")
                    result = rsa_encrypt(text, rsa_keys[1])
                    
            elif choice == "11":
                if not rsa_keys:
                    result = "Generate RSA keys first"
                else:
                    text = input("Enter encrypted text: ")
                    result = rsa_decrypt(text, rsa_keys[0])
                    
            elif choice == "12":
                text = input("Enter text: ")
                result = base64_encode(text)
                
            elif choice == "13":
                text = input("Enter encoded text: ")
                result = base64_decode(text)
                
            elif choice == "14":
                filepath = input("Path to file to encrypt: ")
                password = input("Enter encryption password: ")
                result = encrypt_file(filepath, password)
                if isinstance(result, str) and result.startswith("Error"):
                    print(f"\n{result}")
                    continue
                result = f"Encrypted file: {result}"
                
            elif choice == "15":
                filepath = input("Path to file to decrypt: ")
                password = input("Enter decryption password: ")
                result = decrypt_file(filepath, password)
                if isinstance(result, str) and result.startswith("Error"):
                    print(f"\n{result}")
                    continue
                result = f"Decrypted file: {result}"
                
            elif choice == "16":
                length = int(input("Password length (default=12): ") or "12")
                result = generate_password(length)
                
            elif choice == "17":
                password = input("Enter password: ")
                strength = check_password_strength(password)
                policy = validate_password_policy(password)
                result = f"Strength: {strength['score']}\nEstimated crack time: {strength['crack_time']}\n"
                result += f"Password policy:\n" + "\n".join(f"- {k}: {'✓' if v else '✗'}" for k, v in policy.items())
            elif choice == "18":
                freq = frequency_analysis(text)
                result = "\n".join([f"{char}: {freq:.2f}%" for char, freq in sorted(freq.items())])
            elif choice == "19":
                key = detect_caesar_key(text)
                result = f"Probable Caesar key: {key}" if key is not None else "Unable to detect key"
            elif choice == "20":
                ic = calculate_ic(text)
                result = f"Index of Coincidence: {ic:.4f}"
            
            print(f"\nResult: {result}")
            
        except Exception as e:
            print(f"\nUnexpected error: {str(e)}")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()

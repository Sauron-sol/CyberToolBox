import hashlib
import itertools
import string
import time
import subprocess
import os
import sys
import argparse
import requests
import re

class ExternalTools:
    def __init__(self):
        self.hashcat_path = self.find_tool("hashcat")
        self.john_path = self.find_tool("john")

    def find_tool(self, tool_name):
        try:
            result = subprocess.run(['which', tool_name], capture_output=True, text=True)
            return result.stdout.strip() if result.returncode == 0 else None
        except:
            return None

    def check_tools_availability(self):
        tools = {
            'hashcat': self.hashcat_path,
            'john': self.john_path
        }
        return {tool: path is not None for tool, path in tools.items()}

class HashIdentifier:
    HASH_PATTERNS = {
        'MD5': (r'^[a-fA-F0-9]{32}$', 0),
        'SHA1': (r'^[a-fA-F0-9]{40}$', 100),
        'SHA256': (r'^[a-fA-F0-9]{64}$', 1400),
        'SHA512': (r'^[a-fA-F0-9]{128}$', 1700),
        'NTLM': (r'^[a-fA-F0-9]{32}$', 1000),
        'MySQL': (r'^[a-fA-F0-9]{16}$', 300),
        'bcrypt': (r'^\$2[ayb]\$.{56}$', 3200)
    }

    @staticmethod
    def identify_hash(hash_string):
        """Identify hash type based on pattern and length"""
        possible_types = []
        for hash_type, (pattern, mode) in HashIdentifier.HASH_PATTERNS.items():
            if re.match(pattern, hash_string):
                # Additional checks for specific hash types
                if hash_type == 'bcrypt' and '$2' in hash_string:
                    return [(hash_type, mode)]
                possible_types.append((hash_type, mode))
        return possible_types

class PasswordCracker:
    def __init__(self):
        self.common_passwords = self.load_dictionary()
        self.external_tools = ExternalTools()
        self.config = {
            'max_brute_force_time': 30,  # seconds
            'max_length': 8,
            'use_external_tools': True,
            'preferred_tool': 'hashcat',  # Changed back to hashcat
            'verbose': True,
            'wordlist_path': 'rockyou.txt'
        }
        self.ensure_wordlist()
        self.hash_identifier = HashIdentifier()

    def ensure_wordlist(self):
        """Download rockyou.txt if not present"""
        if not os.path.exists(self.config['wordlist_path']):
            print("[*] Downloading rockyou.txt...")
            url = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
            try:
                response = requests.get(url)
                with open(self.config['wordlist_path'], 'wb') as f:
                    f.write(response.content)
                print("[+] Downloaded successfully")
            except Exception as e:
                print(f"[!] Error downloading wordlist: {e}")
                print("[*] Using default small wordlist")
                self.config['wordlist_path'] = 'common_passwords.txt'

    def load_dictionary(self):
        try:
            with open('common_passwords.txt', 'r') as file:
                return [line.strip() for line in file]
        except FileNotFoundError:
            return ['password', '123456', 'admin', 'welcome', 'qwerty']

    def hash_password(self, password):
        return hashlib.md5(password.encode()).hexdigest()

    def dictionary_attack(self, hash_to_crack):
        print("Starting dictionary attack...")
        for password in self.common_passwords:
            if self.hash_password(password) == hash_to_crack:
                return password
        return None

    def brute_force_attack(self, hash_to_crack, max_length=8):
        print("\n[+] Starting brute force attack...")
        print("[*] This may take a while depending on password complexity")
        start_time = time.time()
        chars = string.ascii_letters + string.digits
        
        for length in range(1, max_length + 1):
            for guess in itertools.product(chars, repeat=length):
                current_time = time.time() - start_time
                if (current_time > self.config['max_brute_force_time']):
                    print("\n[!] Brute force taking too long, switching to external tools...")
                    return self.try_external_tools(hash_to_crack)
                
                password = ''.join(guess)
                if self.hash_password(password) == hash_to_crack:
                    return password
        return None

    def try_external_tools(self, hash_to_crack):
        if not self.config['use_external_tools']:
            return None

        # Identify hash type
        possible_hash_types = HashIdentifier.identify_hash(hash_to_crack)
        if not possible_hash_types:
            print("[!] Unable to identify hash type")
            return None

        print("\n[+] Detected possible hash types:")
        for hash_type, mode in possible_hash_types:
            print(f"    - {hash_type} (Mode: {mode})")

        available_tools = self.external_tools.check_tools_availability()
        preferred_tool = self.config['preferred_tool']
        
        if preferred_tool == 'hashcat' and available_tools['hashcat']:
            print("\n[+] Attempting to crack with Hashcat...")
            
            # Try each possible hash type
            for hash_type, mode in possible_hash_types:
                print(f"\n[*] Trying {hash_type} mode...")
                
                # Cleanup previous attempts
                for file in ['hash.txt', 'hash.txt.pot', 'hashcat.potfile']:
                    if os.path.exists(file):
                        os.remove(file)
                
                with open('hash.txt', 'w') as f:
                    f.write(hash_to_crack)
                
                try:
                    # Try wordlist attack with current hash mode
                    print("[*] Using wordlist attack mode...")
                    with open(os.devnull, 'w') as devnull:
                        subprocess.run([
                            self.external_tools.hashcat_path,
                            '-m', str(mode),  # Use detected hash mode
                            '-a', '0',
                            '-w', '4',
                            '--force',
                            '--quiet',
                            '--potfile-path=hashcat.potfile',
                            '--outfile-format=2',
                            '--status',
                            'hash.txt',
                            self.config['wordlist_path']
                        ], stdout=devnull, stderr=devnull)

                    # Check result
                    if os.path.exists('hashcat.potfile'):
                        with open('hashcat.potfile', 'r') as f:
                            for line in f:
                                if hash_to_crack in line:
                                    password = line.strip().split(':')[1]
                                    print(f"[+] Password found by Hashcat ({hash_type}): {password}")
                                    return password

                except Exception as e:
                    if self.config['verbose']:
                        print(f"[!] Hashcat error: {e}")

            print("[!] Password not found with any hash type")

        if preferred_tool == 'john' and available_tools['john']:
            print("\n[+] Attempting to crack with John the Ripper...")
            
            # Create hash file in John format (user:hash)
            with open('hash.txt', 'w') as f:
                f.write(f"target:{hash_to_crack}")
            
            try:
                # First attempt: Incremental mode (brute force)
                print("[*] Trying incremental mode...")
                subprocess.run([
                    self.external_tools.john_path,
                    '--format=Raw-MD5',  # Note the capital R and M
                    '--incremental:Alnum',  # Using Alnum instead of alpha-numeric
                    'hash.txt'
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Second attempt: Dictionary mode with mutations
                print("[*] Trying dictionary mode...")
                subprocess.run([
                    self.external_tools.john_path,
                    '--format=Raw-MD5',
                    '--wordlist=common_passwords.txt',
                    '--rules:All',  # Using built-in rule set
                    'hash.txt'
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Check if password was found
                result = subprocess.run([
                    self.external_tools.john_path,
                    '--format=Raw-MD5',
                    '--show',
                    'hash.txt'
                ], capture_output=True, text=True)
                
                if result.stdout and ':' in result.stdout:
                    try:
                        password = result.stdout.split(':')[1].split()[0]
                        print(f"[+] Password found by John: {password}")
                        return password
                    except:
                        print("[!] Error parsing John output")
                else:
                    print("[!] No password found by John")
                
            except Exception as e:
                print(f"[!] John the Ripper error: {e}")
                print("[*] Full error:", str(e))

        return None

    def validate_hash(self, hash_string):
        """Validate if the string is a valid hash"""
        possible_types = HashIdentifier.identify_hash(hash_string)
        return len(possible_types) > 0

    def crack_password(self, password_to_crack):
        start_time = time.time()
        hash_to_crack = self.hash_password(password_to_crack)
        print(f"Trying to crack hash: {hash_to_crack}")

        # Try dictionary attack first
        result = self.dictionary_attack(hash_to_crack)
        if result:
            print(f"\nPassword found (dictionary): {result}")
            print(f"Time taken: {time.time() - start_time:.2f} seconds")
            return result

        # Try brute force if dictionary attack fails
        result = self.brute_force_attack(hash_to_crack)
        if result:
            print(f"\nPassword found (brute force): {result}")
            print(f"Time taken: {time.time() - start_time:.2f} seconds")
            return result

        print("\nPassword not found")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")
        return None

    def analyze_hash(self, hash_string):
        """Analyze a hash and provide detailed information"""
        print("\n[+] Hash Analysis Results:")
        print(f"Hash: {hash_string}")
        print(f"Length: {len(hash_string)} characters")
        print("Character composition:")
        lowercase = sum(c.islower() for c in hash_string)
        uppercase = sum(c.isupper() for c in hash_string)
        digits = sum(c.isdigit() for c in hash_string)
        print(f"- Lowercase: {lowercase}")
        print(f"- Uppercase: {uppercase}")
        print(f"- Digits: {digits}")
        
        possible_types = HashIdentifier.identify_hash(hash_string)
        if possible_types:
            print("\nPossible hash types:")
            for hash_type, mode in possible_types:
                print(f"- {hash_type} (Hashcat mode: {mode})")
                if hash_type == 'MD5':
                    print("  Common uses: Database passwords, legacy applications")
                elif hash_type == 'SHA1':
                    print("  Common uses: Git commits, legacy SSL certificates")
                elif hash_type == 'SHA256':
                    print("  Common uses: Modern password storage, blockchain")
                elif hash_type == 'SHA512':
                    print("  Common uses: Linux shadow passwords, high-security applications")
                elif hash_type == 'NTLM':
                    print("  Common uses: Windows authentication")
                elif hash_type == 'MySQL':
                    print("  Common uses: MySQL databases (pre-4.1)")
                elif hash_type == 'bcrypt':
                    print("  Common uses: Modern web applications, secure password storage")
        else:
            print("\n[!] No matching hash patterns found")
            print("This might be:")
            print("- An encrypted string rather than a hash")
            print("- A custom or uncommon hash algorithm")
            print("- Not a hash at all")

    def show_banner(self):
        print("""
╔══════════════════════════════════════════╗
║        Basic Password Cracker Plus        ║
║      Educational Purpose Only - v1.1      ║
╚══════════════════════════════════════════╝
        """)
        print("Available features:")
        print("1. Dictionary attack")
        print("2. Brute force attack")
        print("3. Integration with Hashcat and John the Ripper")
        print("4. Customizable settings\n")

    def configure(self):
        print("\nCurrent configuration:")
        for key, value in self.config.items():
            print(f"{key}: {value}")
        
        print("\nWould you like to modify any settings? (yes/no)")
        if input().lower() == 'yes':
            self.config['max_brute_force_time'] = int(input("Max brute force time (seconds): "))
            self.config['max_length'] = int(input("Max password length for brute force: "))
            self.config['use_external_tools'] = input("Use external tools (true/false): ").lower() == 'true'
            
            if self.config['use_external_tools']:
                print("\nSelect preferred external tool:")
                print("1. Hashcat")
                print("2. John the Ripper")
                tool_choice = input("Choose (1-2): ")
                self.config['preferred_tool'] = 'hashcat' if tool_choice == '1' else 'john'
            
            self.config['verbose'] = input("Verbose output (true/false): ").lower() == 'true'

def main():
    cracker = PasswordCracker()
    cracker.show_banner()
    
    print("Would you like to configure the tool first? (yes/no)")
    if input().lower() == 'yes':
        cracker.configure()

    while True:
        print("\nOptions:")
        print("1. Crack a password")
        print("2. Crack a hash")
        print("3. Configure settings")
        print("4. Check external tools")
        print("5. Analyze a hash")
        print("6. Exit")
        
        choice = input("\nSelect an option (1-6): ")
        
        if choice == '1':
            password = input("\nEnter a password to crack: ")
            cracker.crack_password(password)
        elif choice == '2':
            hash_input = input("\nEnter MD5 hash to crack: ")
            if not cracker.validate_hash(hash_input):
                print("[!] Error: Invalid MD5 hash format")
                print("[*] Hash should be 32 characters long and contain only hex digits")
                continue
            
            print(f"\n[+] Attempting to crack hash: {hash_input}")
            result = cracker.try_external_tools(hash_input)
            if not result:
                print("\n[!] Failed to crack the hash")
        elif choice == '3':
            cracker.configure()
        elif choice == '4':
            tools = cracker.external_tools.check_tools_availability()
            print("\nExternal tools status:")
            for tool, available in tools.items():
                print(f"{tool}: {'Available' if available else 'Not found'}")
        elif choice == '5':
            hash_input = input("\nEnter hash to analyze: ")
            cracker.analyze_hash(hash_input)
        elif choice == '6':
            print("\nGoodbye!")
            break

if __name__ == "__main__":
    main()

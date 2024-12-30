def caesar_cipher(text, key, decrypt=False):
    """Implementation of Caesar cipher"""
    result = ""
    key = int(key)
    if decrypt:
        key = -key
    
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - ascii_offset + key) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result

def vigenere_cipher(text, key, decrypt=False):
    """Implementation of Vigenere cipher"""
    result = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(i) - ord('A') for i in key]
    
    for i, char in enumerate(text):
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            key_idx = i % key_length
            key_shift = key_as_int[key_idx]
            if decrypt:
                key_shift = -key_shift
            shifted = (ord(char) - ascii_offset + key_shift) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result

def rot13_cipher(text):
    """Implementation of ROT13 cipher"""
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - ascii_offset + 13) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result

def atbash_cipher(text):
    """Implementation of Atbash substitution cipher"""
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr(90 - (ord(char) - 65))  # Z=90, A=65
            else:
                result += chr(122 - (ord(char) - 97))  # z=122, a=97
        else:
            result += char
    return result

def process(algorithm, mode, input, key):
    """Process the input with the selected algorithm"""
    is_decrypt = mode == 'decrypt'
    
    if algorithm == 'caesar':
        return caesar_cipher(input, key, is_decrypt)
    elif algorithm == 'vigenere':
        return vigenere_cipher(input, key, is_decrypt)
    elif algorithm == 'rot13':
        return rot13_cipher(input)  # ROT13 est son propre inverse
    elif algorithm == 'atbash':
        return atbash_cipher(input)  # Atbash est son propre inverse

from collections import Counter
import string

def frequency_analysis(text):
    """Analyze character frequency in text"""
    # Compte uniquement les lettres
    letters = [c.lower() for c in text if c.isalpha()]
    total = len(letters)
    
    if total == 0:
        return {}
        
    freq = Counter(letters)
    # Convertit en pourcentages
    return {char: (count/total)*100 for char, count in freq.items()}

def detect_caesar_key(text):
    """Try to detect Caesar cipher key based on 'E' frequency"""
    freq = frequency_analysis(text)
    if not freq:
        return None
        
    # Trouve la lettre la plus fréquente (probablement 'E')
    most_common = max(freq.items(), key=lambda x: x[1])[0]
    # Calcule la différence avec 'E'
    possible_key = (ord(most_common) - ord('e')) % 26
    return possible_key

def calculate_ic(text):
    """Calculate Index of Coincidence"""
    n = len([c for c in text if c.isalpha()])
    if n <= 1:
        return 0.0
        
    freq = Counter(c.lower() for c in text if c.isalpha())
    sum_fi_2 = sum(count * (count - 1) for count in freq.values())
    ic = sum_fi_2 / (n * (n - 1))
    return ic

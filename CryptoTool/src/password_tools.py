import random
import string
import re

def generate_password(length=12, use_upper=True, use_lower=True, 
                     use_digits=True, use_special=True):
    """Generate a secure password"""
    chars = ''
    if use_lower:
        chars += string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_special:
        chars += string.punctuation

    if not chars:
        return None

    password = ''.join(random.choice(chars) for _ in range(length))
    return password

def check_password_strength(password):
    """Check password strength"""
    score = 0
    feedback = []
    
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Le mot de passe devrait faire au moins 12 caractères")
        
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des majuscules")
        
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des minuscules")
        
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des chiffres")
        
    if any(c in string.punctuation for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des caractères spéciaux")
    
    strength = {
        0: "Très faible",
        1: "Faible",
        2: "Moyen",
        3: "Fort",
        4: "Très fort",
        5: "Excellent"
    }
    
    return {
        'score': strength[score],
        'crack_time': "Variable selon la complexité",
        'suggestions': feedback
    }

def validate_password_policy(password):
    """Validate password against common policy requirements"""
    checks = {
        'length': len(password) >= 8,
        'upper': any(c.isupper() for c in password),
        'lower': any(c.islower() for c in password),
        'digit': any(c.isdigit() for c in password),
        'special': any(c in string.punctuation for c in password)
    }
    
    return checks

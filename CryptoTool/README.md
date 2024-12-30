# CryptoTool

Un outil complet de cryptographie intégrant des algorithmes classiques et modernes, avec des fonctionnalités d'analyse et de gestion des mots de passe.

## Fonctionnalités

### Chiffrements Classiques
- **Caesar Cipher** : Chiffrement par décalage
- **Vigenère Cipher** : Chiffrement polyalphabétique
- **ROT13** : Variante du chiffrement César avec un décalage fixe de 13
- **Atbash** : Chiffrement par substitution inverse de l'alphabet

### Chiffrements Modernes
- **AES** : Advanced Encryption Standard (via Fernet)
- **RSA** : Chiffrement asymétrique
- **Base64** : Encodage en base 64

### Gestion de Fichiers
- Chiffrement/déchiffrement de fichiers avec mot de passe
- Gestion automatique des fichiers (suppression sécurisée)
- Support des erreurs et récupération

### Outils de Mot de passe
- Générateur de mots de passe sécurisés
- Analyse de la force des mots de passe
- Vérification des politiques de sécurité

### Outils d'Analyse
- Analyse de fréquence des caractères
- Détection automatique des clés Caesar
- Calcul de l'Index de Coïncidence

## Installation

1. Clonez le dépôt :
```bash
git clone [url-du-repo]
cd CryptoTool
```

2. Installez les dépendances :
```bash
pip install -r requirements.txt
```

## Utilisation

Lancez l'outil :
```bash
python crypto.py
```

### Exemples d'utilisation

1. Chiffrer un message avec Caesar :
   - Choisissez l'option 1
   - Entrez le texte à chiffrer
   - Spécifiez la clé (nombre)

2. Chiffrer un fichier :
   - Choisissez l'option 14
   - Entrez le chemin du fichier
   - Définissez un mot de passe

3. Analyser un texte chiffré :
   - Choisissez l'option 18 pour l'analyse de fréquence
   - Entrez le texte chiffré

4. Générer un mot de passe sécurisé :
   - Choisissez l'option 16
   - Spécifiez la longueur souhaitée

## Structure du Projet

```
CryptoTool/
├── src/
│   ├── classic_ciphers.py    # Algorithmes classiques
│   ├── modern_ciphers.py     # Algorithmes modernes
│   ├── file_handler.py       # Gestion des fichiers
│   ├── password_tools.py     # Outils de mot de passe
│   └── analysis.py          # Outils d'analyse
├── crypto.py                # Interface principale
├── requirements.txt         # Dépendances
└── README.md               # Documentation
```

## Sécurité

⚠️ Note importante : Cet outil est conçu à des fins éducatives et de démonstration. Pour des applications en production, utilisez des bibliothèques cryptographiques établies et suivez les meilleures pratiques de sécurité.

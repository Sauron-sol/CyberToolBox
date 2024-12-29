# Basic Password Cracker Plus

Un outil éducatif pour comprendre les différentes méthodes de cracking de mots de passe et d'analyse de hashs.

## Description

Cet outil permet de :
- Cracker des mots de passe en utilisant différentes méthodes
- Analyser et identifier les types de hashs
- Utiliser des outils professionnels (Hashcat et John the Ripper)
- Apprendre les différentes techniques de cracking de manière interactive

## Prérequis

- Python 3.6+
- pip (gestionnaire de paquets Python)
- Hashcat (recommandé)
- John the Ripper (optionnel)

## Installation

1. Clonez le repository :
   ```bash
   git clone https://github.com/votre-username/BasicPasswordCracker.git
   cd BasicPasswordCracker
   ```

2. Installez les dépendances Python :
   ```bash
   pip install requests
   ```

3. Installez Hashcat (recommandé) :
   ```bash
   # Sur Ubuntu/Debian
   sudo apt-get install hashcat
   
   # Sur macOS
   brew install hashcat
   ```

4. (Optionnel) Installez John the Ripper :
   ```bash
   # Sur Ubuntu/Debian
   sudo apt-get install john
   
   # Sur macOS
   brew install john
   ```

## Fonctionnalités

1. **Cracking de mots de passe**
   - Attaque par dictionnaire
   - Attaque par force brute
   - Utilisation de Hashcat
   - Utilisation de John the Ripper

2. **Types de hashs supportés**
   - MD5
   - SHA1
   - SHA256
   - SHA512
   - NTLM
   - MySQL
   - bcrypt

3. **Analyse de hashs**
   - Identification automatique du type
   - Analyse de la composition
   - Informations sur les usages courants

4. **Configuration**
   - Choix de l'outil préféré
   - Personnalisation des temps d'attaque
   - Gestion des wordlists

## Utilisation

1. Lancez le programme :
   ```bash
   python passwordCracker.py
   ```

2. Menu principal :
   ```
   1. Crack a password    : Cracker un mot de passe en clair
   2. Crack a hash        : Cracker un hash directement
   3. Configure settings  : Modifier les paramètres
   4. Check external tools: Vérifier les outils disponibles
   5. Analyze a hash      : Analyser un hash sans le cracker
   6. Exit               : Quitter le programme
   ```

3. Exemples d'utilisation :
   ```bash
   # Analyser un hash MD5
   > Choisissez 5
   > Entrez le hash : 5f4dcc3b5aa765d61d8327deb882cf99

   # Cracker un mot de passe
   > Choisissez 1
   > Entrez le mot de passe : monmotdepasse

   # Cracker un hash directement
   > Choisissez 2
   > Entrez le hash : 5f4dcc3b5aa765d61d8327deb882cf99
   ```

## Wordlists

- Le programme télécharge automatiquement rockyou.txt au premier lancement
- Une wordlist basique est incluse par défaut
- Vous pouvez ajouter vos propres wordlists via la configuration

## Configuration avancée

- Modifiez les temps maximum de force brute
- Changez la longueur maximum des mots de passe
- Activez/désactivez les outils externes
- Choisissez entre Hashcat et John the Ripper
- Configurez le niveau de verbosité

## Sécurité et éthique

Cet outil est créé à des fins éducatives uniquement. Son utilisation doit se faire :
- Dans un cadre légal
- Sur vos propres systèmes
- Pour comprendre la sécurité des mots de passe

L'utilisation malveillante de cet outil est strictement interdite.

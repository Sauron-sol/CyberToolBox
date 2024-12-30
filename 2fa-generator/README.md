# 2FA Generator 🔐

Un gestionnaire de codes 2FA moderne et sécurisé avec interface web. Cette application permet de gérer vos authentifications à double facteur de manière centralisée.

## Fonctionnalités

- 📱 Génération de codes TOTP (Time-based One-Time Password)
- 🎥 Scan de QR codes via webcam
- 📂 Import de QR codes via fichiers images
- 💾 Stockage sécurisé des secrets dans une base SQLite
- ⏱️ Barre de progression visuelle pour le timing
- 🔄 Actualisation automatique des codes
- 🎨 Interface utilisateur moderne et responsive

## Prérequis

- Node.js (v14 ou supérieur)
- npm ou yarn
- Une webcam pour le scan de QR codes (optionnel)

## Installation

1. Clonez le dépôt :
```bash
git clone <url-du-repo>
cd 2fa-generator
```

2. Installez les dépendances :
```bash
npm install
```

3. Lancez l'application :
```bash
npm start
```

4. Ouvrez votre navigateur à l'adresse : `http://localhost:3001`

## Utilisation

### Ajout d'un compte 2FA

Deux méthodes sont disponibles :

1. **Scan via caméra** :
   - Cliquez sur "Scan with Camera"
   - Autorisez l'accès à la caméra
   - Présentez le QR code à scanner

2. **Import d'image** :
   - Cliquez sur "Upload Image"
   - Glissez-déposez votre image ou cliquez pour sélectionner

### Gestion des comptes

- Les codes sont automatiquement mis à jour
- Une barre de progression indique le temps restant
- Le bouton "Delete" permet de supprimer un compte

## Sécurité

- Les secrets sont stockés de manière sécurisée dans une base SQLite
- Aucune donnée n'est envoyée à des serveurs externes
- L'application fonctionne entièrement en local

## Développement

Structure du projet :
```
2fa-generator/
├── index.js         # Serveur Express
├── public/          # Frontend
│   └── index.html   # Interface utilisateur
├── accounts.db      # Base de données SQLite
└── package.json     # Dépendances
```

## Technologies utilisées

- Frontend : HTML5, CSS3, JavaScript (Vanilla)
- Backend : Node.js, Express
- Base de données : SQLite
- Librairies : otplib, html5-qrcode, QRCode.js


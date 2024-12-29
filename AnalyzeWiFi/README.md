# Analyze WiFi 📡

Un outil multiplateforme pour analyser la sécurité des réseaux WiFi environnants.

## Fonctionnalités principales

- 🔍 Scan des réseaux WiFi disponibles
- 🛡️ Analyse de la sécurité des réseaux
- 📊 Génération de rapports détaillés
- 🔄 Support multiplateforme (Windows/Linux/MacOS)
- 📡 Analyse des canaux et des signaux
- 🚨 Détection des réseaux vulnérables

## Prérequis

- Python 3.6+
- Privilèges administrateur/root pour le scan WiFi
- Interface WiFi compatible
- Dépendances Python (voir requirements.txt)

## Installation

1. Clonez le repository :
   ```bash
   git clone <repository-url>
   cd AnalyzeWiFi
   ```

2. Installez les dépendances :
   ```bash
   pip install -r requirements.txt
   ```

3. Vérifiez les permissions système :
   - **Linux** : Exécutez avec sudo
   - **MacOS** : Autorisez l'accès à l'interface réseau
   - **Windows** : Exécutez en tant qu'administrateur

## Utilisation

1. Lancez l'analyseur :
   ```bash
   # Linux/MacOS
   sudo python wifi_analyzer.py

   # Windows (cmd en admin)
   python wifi_analyzer.py
   ```

2. Le programme va :
   - Scanner les réseaux disponibles
   - Analyser leur sécurité
   - Générer un rapport détaillé

## Informations analysées

- 📶 Force du signal
- 🔐 Type de sécurité (WEP/WPA/WPA2/WPA3)
- 📻 Canal et fréquence
- 🌐 Informations réseau (SSID, BSSID)
- 🔍 Vulnérabilités potentielles
- 📊 Statistiques de performance

## Format du rapport

Le rapport généré inclut :
- Informations système
- Liste des réseaux détectés
- Analyse de sécurité par réseau
- Alertes et recommandations
- Statistiques détaillées

## Compatibilité OS

| OS      | Status | Notes |
|---------|--------|-------|
| MacOS   | ✅     | Nécessite autorisation système |
| Linux   | ✅     | Nécessite sudo |
| Windows | ✅     | Nécessite droits admin |

## Limitations connues

- Certaines cartes WiFi peuvent ne pas supporter toutes les fonctionnalités
- L'analyse approfondie nécessite des privilèges élevés
- Les réseaux masqués peuvent ne pas être détectés
- Certaines fonctionnalités dépendent du système d'exploitation

## Sécurité

⚠️ Cet outil est destiné à des fins éducatives et de test uniquement. 
L'utilisation doit être conforme aux lois locales et avec autorisation appropriée.


import os
import sys
import time

# Ajouter le chemin parent au PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wallet import SecureWallet

def main():
    WALLET_FILE = "mon_wallet.enc"
    PASSWORD = "Mon_Mot_De_Passe_Fort_123!"

    # Supprimer l'ancien fichier s'il existe
    if os.path.exists(WALLET_FILE):
        os.remove(WALLET_FILE)

    # 1. Créer un nouveau wallet avec un mot de passe fort
    print("🔐 Création d'un nouveau wallet...")
    wallet = SecureWallet(PASSWORD)

    # 2. Créer plusieurs wallets crypto
    print("\n📝 Création de wallets...")
    eth_wallet = wallet.create_wallet("ethereum_principal")
    btc_wallet = wallet.create_wallet("bitcoin_principal")
    
    print(f"ETH Address: {eth_wallet['address']}")
    print(f"BTC Address: {btc_wallet['address']}")

    # 3. Lister tous les wallets
    print("\n📋 Liste des wallets:")
    for w in wallet.list_wallets():
        print(f"Nom: {w['name']}")
        print(f"Adresse: {w['address']}")
        print(f"Balance: {w['balance']}")
        print("---")

    # 4. Sauvegarder le wallet de façon sécurisée
    print("\n💾 Sauvegarde du wallet...")
    wallet.save_to_file(WALLET_FILE)
    
    print(f"Fichier créé: {os.path.exists(WALLET_FILE)}")
    print(f"Taille du fichier: {os.path.getsize(WALLET_FILE)} bytes")

    # Attendre que le fichier soit complètement écrit
    time.sleep(1)

    # Vérifier que le fichier existe
    if not os.path.exists(WALLET_FILE):
        raise Exception("Le fichier de wallet n'a pas été créé")

    # 5. Charger le wallet depuis le fichier
    print("\n📂 Chargement du wallet...")
    try:
        loaded_wallet = SecureWallet.load_from_file(WALLET_FILE, PASSWORD)
        print("✅ Wallet chargé avec succès")
    except Exception as e:
        print(f"Erreur lors du chargement: {str(e)}")
        with open(WALLET_FILE, 'rb') as f:
            data = f.read()
            print(f"Contenu du fichier (premiers 50 caractères): {data[:50]}")
        raise

    # 6. Vérifier les clés privées
    print("\n🔑 Vérification des clés privées...")
    eth_private_key = loaded_wallet.get_private_key("ethereum_principal")
    if eth_private_key:
        print("✅ Clé privée ETH récupérée avec succès")

    # 7. Exporter un wallet (sans la clé privée)
    print("\n📤 Export du wallet ETH...")
    exported_wallet = loaded_wallet.export_wallet("ethereum_principal")
    print(f"Wallet exporté: {exported_wallet}")

if __name__ == "__main__":
    try:
        main()
        print("\n✅ Opérations terminées avec succès!")
    except Exception as e:
        print(f"\n❌ Erreur: {str(e)}")

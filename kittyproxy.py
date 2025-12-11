#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KittySploit Proxy Interface
Lance l'interface du proxy web avec intégration au framework
"""

import sys
import os
import argparse

# Ajouter le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ajouter le répertoire kittyproxy au PYTHONPATH pour les imports relatifs
kittyproxy_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'interfaces', 'kittyproxy')
if kittyproxy_dir not in sys.path:
    sys.path.insert(0, kittyproxy_dir)

# Importer depuis le module kittyproxy (imports relatifs comme dans main.py)
from proxy_core import MitmProxyWrapper
from api import app, set_framework
from core.output_handler import print_info, print_success, print_error, print_warning
from core.framework.framework import Framework

try:
    import uvicorn
except ImportError:
    print_error("uvicorn n'est pas installé!")
    print_info("Installez-le avec: pip install uvicorn")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='KittySploit Proxy Interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Démarrer le proxy avec les paramètres par défaut
  python kittyproxy.py

  # Démarrer sur des ports personnalisés
  python kittyproxy.py --proxy-port 8080 --api-port 8000

  # Démarrer avec une adresse IP spécifique
  python kittyproxy.py --api-host 0.0.0.0

  # Démarrer avec un chemin de framework personnalisé
  python kittyproxy.py --framework-path /chemin/vers/framework
        """
    )
    
    parser.add_argument(
        '--framework-path',
        type=str,
        default=None,
        help='Chemin vers le répertoire racine du framework (défaut: répertoire courant)'
    )
    parser.add_argument(
        '--proxy-port',
        type=int,
        default=8080,
        help='Port du proxy (défaut: 8080)'
    )
    parser.add_argument(
        '--api-port',
        type=int,
        default=8000,
        help='Port du serveur API (défaut: 8000)'
    )
    parser.add_argument(
        '--api-host',
        type=str,
        default='127.0.0.1',
        help='Adresse IP du serveur API (défaut: 127.0.0.1)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Mode verbeux'
    )
    
    args = parser.parse_args()
    
    # Vérifier que mitmproxy est disponible
    try:
        from mitmproxy import http  # noqa: F401 - vérification de présence
    except ImportError:
        print_error("mitmproxy n'est pas installé!")
        print_info("Installez-le avec: pip install mitmproxy")
        sys.exit(1)
    
    print_success("=" * 60)
    print_success("KittySploit Proxy Interface")
    print_success("=" * 60)
    
    # Initialiser le framework
    try:
        if args.verbose:
            print_info("Initialisation du framework...")
        
        framework = Framework(clean_sessions=False)
        
        # Check charter acceptance
        if not framework.check_charter_acceptance():
            print_info("Premier démarrage de KittySploit")
            if not framework.prompt_charter_acceptance():
                print_error("Charte non acceptée. Arrêt du framework.")
                return 1
        
        # Handle encryption setup/loading for database unlock
        if not framework.is_encryption_initialized():
            print_info("Configuration du chiffrement pour la protection des données sensibles...")
            if not framework.initialize_encryption():
                print_error("Échec de l'initialisation du chiffrement. Arrêt du framework.")
                return 1
        else:
            # Load existing encryption with master key to unlock database
            if not framework.load_encryption():
                print_error("Échec du chargement du chiffrement. La base de données reste verrouillée. Arrêt du framework.")
                return 1
        
        # Définir le framework dans le module API
        set_framework(framework)
        
        if args.verbose:
            print_success("Framework initialisé avec succès")
    except Exception as e:
        print_error(f"Erreur lors de l'initialisation du framework: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    # Démarrer le proxy
    try:
        if args.verbose:
            print_info(f"Démarrage du proxy sur le port {args.proxy_port}...")
        
        proxy = MitmProxyWrapper(
            host="127.0.0.1", 
            port=args.proxy_port,
            api_host=args.api_host,
            api_port=args.api_port
        )
        proxy.start()
        
        print_success(f"Proxy démarré sur 127.0.0.1:{args.proxy_port}")
    except Exception as e:
        print_error(f"Erreur lors du démarrage du proxy: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    # Afficher les informations de connexion
    print_success("=" * 60)
    print_info(f"Interface web: http://{args.api_host}:{args.api_port}")
    print_info(f"Proxy: 127.0.0.1:{args.proxy_port}")
    print_info("Appuyez sur Ctrl+C pour arrêter le serveur")
    print_success("=" * 60)
    
    # Démarrer le serveur API
    try:
        if args.verbose:
            print_info(f"Démarrage du serveur API sur {args.api_host}:{args.api_port}...")
        
        uvicorn.run(
            app,
            host=args.api_host,
            port=args.api_port,
            log_level="info" if args.verbose else "warning"
        )
    except KeyboardInterrupt:
        print_info("\nArrêt du serveur...")
    except Exception as e:
        print_error(f"Erreur lors du démarrage du serveur API: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        # Arrêter le proxy
        try:
            proxy.stop()
            if args.verbose:
                print_info("Proxy arrêté")
        except:
            pass
    
    print_success("Serveur arrêté.")
    return 0


if __name__ == '__main__':
    sys.exit(main())


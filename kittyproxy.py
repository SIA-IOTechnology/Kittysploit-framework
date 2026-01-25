#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KittySploit Proxy Interface
This script starts the KittySploit Proxy Interface with integration to the framework.
"""

import sys
import os

# Add parent directory to PYTHONPATH (before importing venv_helper)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure we're using the project's venv if it exists
from core.utils.venv_helper import ensure_venv
ensure_venv(__file__)

import argparse

kittyproxy_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'interfaces', 'kittyproxy')
if kittyproxy_dir not in sys.path:
    sys.path.insert(0, kittyproxy_dir)

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
            print_info("First startup of KittySploit")
            if not framework.prompt_charter_acceptance():
                print_error("Charter not accepted. Stopping framework.")
                return 1
        
        # Handle encryption setup/loading for database unlock
        if not framework.is_encryption_initialized():
            print_info("Setting up encryption for sensitive data protection...")
            if not framework.initialize_encryption():
                print_error("Failed to initialize encryption. Stopping framework.")
                return 1
        else:
            # Load existing encryption with master key to unlock database
            if not framework.load_encryption():
                print_error("Failed to load encryption. Database remains locked. Stopping framework.")
                return 1
        
        # Set the framework in the API module
        set_framework(framework)
        
        if args.verbose:
            print_success("Framework initialized successfully")
    except Exception as e:
        print_error(f"Error initializing framework: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    # Start the proxy
    try:
        if args.verbose:
            print_info(f"Starting proxy on port {args.proxy_port}...")
        
        proxy = MitmProxyWrapper(
            host="127.0.0.1", 
            port=args.proxy_port,
            api_host=args.api_host,
            api_port=args.api_port
        )
        proxy.start()
        
        print_success(f"Proxy started on 127.0.0.1:{args.proxy_port}")
    except Exception as e:
        print_error(f"Error starting proxy: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    # Display connection information
    print_success("=" * 60)
    print_info(f"Web interface: http://{args.api_host}:{args.api_port}")
    print_info(f"Proxy: 127.0.0.1:{args.proxy_port}")
    print_info("Press Ctrl+C to stop the server")
    print_success("=" * 60)
    
    # Start the API server
    try:
        if args.verbose:
            print_info(f"Starting API server on {args.api_host}:{args.api_port}...")
        
        uvicorn.run(
            app,
            host=args.api_host,
            port=args.api_port,
            log_level="info" if args.verbose else "warning"
        )
    except KeyboardInterrupt:
        print_info("\nStopping server...")
    except Exception as e:
        print_error(f"Error starting API server: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        # Stop the proxy
        try:
            proxy.stop()
            if args.verbose:
                print_info("Proxy stopped")
        except:
            pass
    
    print_success("Server stopped.")
    return 0


if __name__ == '__main__':
    sys.exit(main())


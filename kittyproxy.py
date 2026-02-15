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
    print_error("uvicorn is not installed!")
    print_info("Install it with: pip install uvicorn")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='KittySploit Proxy Interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Start the proxy with default parameters
  python kittyproxy.py

  # Start on custom ports
  python kittyproxy.py --proxy-port 8080 --api-port 8443

  # Start with a specific IP address
  python kittyproxy.py --api-host 0.0.0.0

  # Start with a custom framework path
  python kittyproxy.py --framework-path /chemin/vers/framework
        """
    )
    
    parser.add_argument(
        '--framework-path',
        type=str,
        default=None,
        help='Path to the framework root directory (default: current directory)'
    )
    parser.add_argument(
        '--proxy-port',
        type=int,
        default=8080,
        help='Proxy port (default: 8080)'
    )
    parser.add_argument(
        '--api-port',
        type=int,
        default=8443,
        help='API server port (default: 8443)'
    )
    parser.add_argument(
        '--api-host',
        type=str,
        default='127.0.0.1',
        help='API server IP address (default: 127.0.0.1)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose mode'
    )
    
    args = parser.parse_args()
    
    # Check if mitmproxy is available
    try:
        from mitmproxy import http  # noqa: F401 - check for presence
    except ImportError:
        print_error("mitmproxy is not installed!")
        print_info("Install it with: pip install mitmproxy")
        sys.exit(1)
    
    print_success("=" * 60)
    print_success("KittySploit Proxy Interface")
    print_success("=" * 60)
    
    # Initialize the framework
    try:
        if args.verbose:
            print_info("Initializing framework...")
        
        framework = Framework(clean_sessions=False)
        
        # Check charter acceptance for first startup
        if not framework.check_charter_acceptance():
            print_info("First startup of KittySploit")
            if not framework.prompt_charter_acceptance():
                print_error("Charter not accepted. Stopping framework initialization.")
                return 1
        
        # Handle encryption setup/loading for database unlock (if not already initialized)
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


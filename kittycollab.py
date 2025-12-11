#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from interfaces.kittycollab.collab_server import CollabWebServer
from core.output_handler import print_info, print_success, print_error

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='KittySploit Collab - Collab Web Server')
    parser.add_argument('-H', '--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=5005, help='Port to bind to (default: 5005)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        server = CollabWebServer(
            host=args.host,
            port=args.port,
            verbose=args.verbose
        )
        server.start()
    except KeyboardInterrupt:
        print_info("Server stopped by user.")
    except Exception as e:
        print_error(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


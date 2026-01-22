#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example Web UI for KittySploit

Example web interface that demonstrates how to create an interface
compatible with the marketplace system.
"""

import os
import sys
from pathlib import Path

config = {
    'host': '127.0.0.1',
    'port': 5000,
    'debug': True
}

def get_extension_info():
    """Get extension information from global variables"""
    return {
        'id': globals().get('__extension_id__', 'unknown'),
        'base': globals().get('__extension_base__', Path.cwd()),
    }


def setup_paths():
    """Configure Python paths for the extension"""
    ext_info = get_extension_info()
    ext_base = Path(ext_info['base'])
    
    # Add folders to path
    for subdir in ['src', 'lib', 'vendor']:
        path_to_add = ext_base / subdir
        if path_to_add.exists():
            sys.path.insert(0, str(path_to_add))
    
    return ext_base


def main():
    """Main entry point for the interface"""
    print("=" * 60)
    print("Example Web UI for KittySploit")
    print("=" * 60)
    
    # Setup paths
    ext_base = setup_paths()
    ext_info = get_extension_info()
    
    print(f"Extension ID: {ext_info['id']}")
    print(f"Extension directory: {ext_base}")
    print()
    
    # Load configuration
    config_file = ext_base / "config.json"
    if config_file.exists():
        import json
        with open(config_file) as f:
            config = json.load(f)
            print(f"Configuration loaded from: {config_file}")
    else:
        config = {
            'host': '127.0.0.1',
            'port': 5000,
            'debug': True
        }
        print("Using default configuration")
    
    print()
    print(f"Starting web server on http://{config['host']}:{config['port']}")
    print("Press Ctrl+C to stop")
    print("-" * 60)
    
    # Simulate a web server (simple example)
    try:
        # In a real application, you would use Flask, FastAPI, etc.
        # from ui.server import create_app
        # app = create_app(config)
        # app.run(host=config['host'], port=config['port'], debug=config['debug'])
        
        # For this example, we just simulate
        print("\n[INFO] Web interface is running...")
        print(f"[INFO] Open your browser at: http://{config['host']}:{config['port']}")
        print("\n[EXAMPLE] This is a demonstration - no real server running")
        print("\nTo create a real web UI:")
        print("1. Install Flask: pip install flask")
        print("2. Create your UI in src/ui/")
        print("3. Import and run your Flask app here")
        
        # Wait for interruption
        import time
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        print("Goodbye!")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

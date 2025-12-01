#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Market command implementation
"""

import argparse
import requests
import json
import os
import sys
import getpass
import logging
from typing import Dict, List, Any, Optional
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_empty

class MarketCommand(BaseCommand):
    """Command to browse and install modules from the marketplace"""
    
    @property
    def name(self) -> str:
        return "market"
    
    @property
    def description(self) -> str:
        return "Browse and install modules from the KittySploit marketplace"
    
    @property
    def usage(self) -> str:
        return "market [browse|list|search|install|update|uninstall|info|categories|featured|popular|recent|installed|publish]"
    
    def get_subcommands(self) -> List[str]:
        """Get available subcommands for auto-completion"""
        return ['browse', 'list', 'search', 'install', 'update', 'uninstall', 'info', 'categories', 'featured', 'popular', 'recent', 'installed', 'publish']
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command allows you to browse, search, and install modules from the KittySploit marketplace.

Subcommands:
    browse        Browse available modules by category
    list          List all available extensions (alias for browse)
    search <term> Search for modules by name or description
    install [id]  Install a module by its ID (or use --all-free to install all free modules)
    info <id>     Show detailed information about a module
    categories    List available categories
    featured      Show featured modules
    popular       Show popular modules
    recent        Show recently added modules
    installed     List installed modules
    update [id]   Update installed modules (all or specific module)
    uninstall [id] Uninstall a module (all if --all flag, or specific module)
    publish <dir> Package and publish a module to the marketplace

Examples:
    market browse                    # Browse all modules
    market list                      # List all modules
    market search "proxy"            # Search for proxy-related modules
    market install test-module       # Install module with ID test-module
    market install --all-free       # Install all free modules from marketplace
    market info test-module          # Show info about module test-module
    market categories                # List all categories
    market featured                  # Show featured modules
    market installed                 # List installed modules
    market update                    # Update all installed modules
    market update test-module        # Update specific module
    market uninstall test-module    # Uninstall specific module
    market uninstall --all          # Uninstall all modules
    market publish examples/test_module  # Package and publish a module
        """
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
        # Use registry server
        self.registry_url = self._get_registry_url()
        self.timeout = 10
        self.api_key = None
        self._load_account_config()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command parser"""
        parser = argparse.ArgumentParser(
            description="Browse and install modules from the marketplace",
            add_help=True
        )
        
        subparsers = parser.add_subparsers(dest='action', help='Available actions')
        
        # Browse command
        browse_parser = subparsers.add_parser('browse', help='Browse modules by category')
        browse_parser.add_argument('--category', '-c', help='Filter by category')
        browse_parser.add_argument('--page', '-p', type=int, default=1, help='Page number')
        browse_parser.add_argument('--limit', '-l', type=int, default=20, help='Items per page')
        
        # List command (alias for browse)
        list_parser = subparsers.add_parser('list', help='List all available extensions')
        list_parser.add_argument('--category', '-c', help='Filter by category')
        list_parser.add_argument('--page', '-p', type=int, default=1, help='Page number')
        list_parser.add_argument('--limit', '-l', type=int, default=20, help='Items per page')
        
        # Search command
        search_parser = subparsers.add_parser('search', help='Search for modules')
        search_parser.add_argument('query', help='Search query')
        search_parser.add_argument('--category', '-c', help='Filter by category')
        search_parser.add_argument('--page', '-p', type=int, default=1, help='Page number')
        search_parser.add_argument('--limit', '-l', type=int, default=20, help='Items per page')
        
        # Install command
        install_parser = subparsers.add_parser('install', help='Install a module')
        install_parser.add_argument('module_id', nargs='?', help='Module ID to install (optional, use --all-free to install all free modules)')
        install_parser.add_argument('--force', '-f', action='store_true', help='Force installation')
        install_parser.add_argument('--all-free', '-a', action='store_true', help='Install all free modules from the marketplace')
        
        # Update command
        update_parser = subparsers.add_parser('update', help='Update installed modules')
        update_parser.add_argument('module_id', nargs='?', help='Module ID to update (optional, updates all if not specified)')
        
        # Uninstall command
        uninstall_parser = subparsers.add_parser('uninstall', help='Uninstall installed modules')
        uninstall_parser.add_argument('module_id', nargs='?', help='Module ID to uninstall (optional, use --all to uninstall all)')
        uninstall_parser.add_argument('--all', '-a', action='store_true', help='Uninstall all installed modules')
        
        # Info command
        info_parser = subparsers.add_parser('info', help='Show module information')
        info_parser.add_argument('module_id', help='Module ID')
        
        # Categories command
        subparsers.add_parser('categories', help='List available categories')
        
        # Featured command
        featured_parser = subparsers.add_parser('featured', help='Show featured modules')
        featured_parser.add_argument('--limit', '-l', type=int, default=10, help='Number of modules to show')
        
        # Popular command
        popular_parser = subparsers.add_parser('popular', help='Show popular modules')
        popular_parser.add_argument('--limit', '-l', type=int, default=10, help='Number of modules to show')
        
        # Recent command
        recent_parser = subparsers.add_parser('recent', help='Show recently added modules')
        recent_parser.add_argument('--limit', '-l', type=int, default=10, help='Number of modules to show')
        
        # Installed command
        subparsers.add_parser('installed', help='List installed extensions')
        
        # Publish command
        publish_parser = subparsers.add_parser('publish', help='Package and publish a module')
        publish_parser.add_argument('module_dir', help='Directory containing the module (with extension.toml)')
        publish_parser.add_argument('--package-only', action='store_true', help='Only package, do not upload')
        publish_parser.add_argument('--no-sign', action='store_true', help='Skip signing the bundle (not recommended)')
        
        return parser
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the market command"""
        try:
            if not args:
                # Si pas d'arguments et pas de compte, proposer l'inscription/connexion
                if not self.api_key:
                    self._prompt_account_setup()
                self.parser.print_help()
                return True
            
            parsed_args = self.parser.parse_args(args)
            
            if not parsed_args.action:
                self.parser.print_help()
                return True
            
            # Vérifier l'authentification pour les actions qui en nécessitent
            requires_auth = parsed_args.action in ['install', 'update', 'publish']
            if requires_auth and not self.api_key:
                print_warning("⚠️  This action requires an account")
                if self._prompt_account_setup():
                    self._load_account_config()
                else:
                    return False
            
            # Execute the appropriate action
            if parsed_args.action == 'browse' or parsed_args.action == 'list':
                return self._browse_modules(parsed_args)
            elif parsed_args.action == 'search':
                return self._search_modules(parsed_args)
            elif parsed_args.action == 'install':
                return self._install_module(parsed_args)
            elif parsed_args.action == 'update':
                return self._update_module(parsed_args)
            elif parsed_args.action == 'uninstall':
                return self._uninstall_module(parsed_args)
            elif parsed_args.action == 'info':
                return self._show_module_info(parsed_args)
            elif parsed_args.action == 'categories':
                return self._list_categories()
            elif parsed_args.action == 'featured':
                return self._show_featured_modules(parsed_args)
            elif parsed_args.action == 'popular':
                return self._show_popular_modules(parsed_args)
            elif parsed_args.action == 'recent':
                return self._show_recent_modules(parsed_args)
            elif parsed_args.action == 'installed':
                return self._list_installed_extensions()
            elif parsed_args.action == 'publish':
                return self._publish_module(parsed_args)
            else:
                print_error(f"Unknown action: {parsed_args.action}")
                return False
                
        except SystemExit:
            return True
        except Exception as e:
            print_error(f"Error executing market command: {str(e)}")
            return False
    
    def _get_registry_url(self) -> str:
        """Get registry URL from config or use default"""
        try:
            import toml
            config_path = os.path.join("config", "kittysploit.toml")
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = toml.load(f)
                    registry_url = config.get('registry', {}).get('url', 'http://localhost:5000')
                    if registry_url:
                        return registry_url.rstrip('/')
        except Exception as e:
            # Silently fall back to default
            pass
        return "http://localhost:5000"
    
    def _load_account_config(self):
        """Load account configuration from file"""
        try:
            config_file = os.path.join(os.path.expanduser("~"), ".kittysploit", "registry_config.json")
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    self.api_key = config.get('api_key')
        except Exception:
            pass
    
    def _prompt_account_setup(self) -> bool:
        """Prompt user to register or login"""
        print_warning("No account registered. You can browse extensions, but need an account to download/install.")
        choice = input("Would you like to create an account or login? (register/login/skip): ").strip().lower()
        
        if choice == 'register':
            return self._register_account()
        elif choice == 'login':
            return self._login_account()
        return False
    
    def _register_account(self) -> bool:
        """Register a new account"""
        try:
            print_info("\n=== Registry Account Registration ===")
            email = input("Email: ").strip()
            if not email:
                print_error("Email is required")
                return False
            
            username = input("Username (optional): ").strip() or None
            password = getpass.getpass("Password: ")
            if not password:
                print_error("Password is required")
                return False
            
            password_confirm = getpass.getpass("Confirm password: ")
            if password != password_confirm:
                print_error("Passwords do not match")
                return False
            
            response = requests.post(
                f"{self.registry_url}/api/auth/register",
                json={"email": email, "password": password, "username": username},
                timeout=self.timeout
            )
            
            if response.status_code == 201:
                result = response.json()
                self.api_key = result.get('api_key')
                self._save_account_config(self.api_key, email, username)
                print_success("Account created successfully!")
                return True
            else:
                error = response.json().get('error', response.text) if response.headers.get('content-type', '').startswith('application/json') else response.text
                print_error(f"Registration failed: {error}")
                return False
        except Exception as e:
            print_error(f"Error: {str(e)}")
            return False
    
    def _login_account(self) -> bool:
        """Login to account"""
        try:
            print_info("\n=== Registry Account Login ===")
            email = input("Email: ").strip()
            if not email:
                print_error("Email is required")
                return False
            
            password = getpass.getpass("Password: ")
            if not password:
                print_error("Password is required")
                return False
            
            response = requests.post(
                f"{self.registry_url}/api/auth/login",
                json={"email": email, "password": password},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                self.api_key = result.get('api_key')
                user = result.get('user', {})
                self._save_account_config(self.api_key, user.get('email'), user.get('username'))
                print_success("Login successful!")
                return True
            else:
                error = response.json().get('error', response.text) if response.headers.get('content-type', '').startswith('application/json') else response.text
                print_error(f"Login failed: {error}")
                return False
        except Exception as e:
            print_error(f"Error: {str(e)}")
            return False
    
    def _save_account_config(self, api_key: str, email: str, username: str = None):
        """Save account configuration"""
        try:
            config_dir = os.path.join(os.path.expanduser("~"), ".kittysploit")
            os.makedirs(config_dir, exist_ok=True)
            config_file = os.path.join(config_dir, "registry_config.json")
            
            config = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
            
            config['api_key'] = api_key
            config['registry_url'] = self.registry_url
            config['email'] = email
            if username:
                config['username'] = username
            
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass
    
    def _make_request(self, endpoint: str, params: Dict = None, method: str = 'GET', requires_auth: bool = False) -> Optional[Dict]:
        """Make a request to the registry API"""
        try:
            url = f"{self.registry_url}/api/registry/{endpoint}"
            headers = {}
            
            if requires_auth and self.api_key:
                headers['X-API-Key'] = self.api_key
            
            if method == 'GET':
                response = requests.get(url, params=params, headers=headers, timeout=self.timeout)
            else:
                response = requests.request(method, url, json=params, headers=headers, timeout=self.timeout)
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError as e:
            print_error("Failed to connect to registry server")
            print_info(f"Server URL: {self.registry_url}")
            print_info(f"Check if the server is accessible: curl {self.registry_url}/health")
            return None
        except requests.exceptions.Timeout as e:
            print_error("Connection timeout - registry server is not responding")
            print_info(f"Server URL: {self.registry_url}")
            return None
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 401:
                # Pour les routes qui ne nécessitent pas d'auth, un 401 est inattendu
                if not requires_auth:
                    print_error("Server returned 401 Unauthorized for a public endpoint")
                    print_warning("The server might have a global API key configured")
                    print_info("To allow public access, start the server without --api-key:")
                    print_info("python registry_server.py")
                    print_info("Or use a user account: market (then register/login)")
                else:
                    print_error("Unauthorized - please login or register")
                    print_info("Use: market (then register/login)")
            else:
                # Afficher plus de détails pour le débogage
                try:
                    error_body = e.response.json()
                    error_msg = error_body.get('error', 'Unknown error')
                    print_error(f"🌐 HTTP error {status_code}: {error_msg}")
                except:
                    error_text = e.response.text[:200] if hasattr(e.response, 'text') else str(e)
                    print_error(f"🌐 HTTP error {status_code}: {error_text}")
            return None
        except requests.exceptions.RequestException as e:
            print_error(f"🌐 Network error: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            print_error(f"📄 Invalid response from registry: {str(e)}")
            return None
    
    def _browse_modules(self, args) -> bool:
        """Browse modules by category"""
        # Test de connexion d'abord
        try:
            health_url = f"{self.registry_url}/health"
            health_response = requests.get(health_url, timeout=5)
            if health_response.status_code != 200:
                print_warning(f"Registry server health check failed (status {health_response.status_code})")
        except Exception as e:
            print_error(f"Error: {str(e)}")
        
        params = {
            'page': args.page,
            'per_page': args.limit
        }
        
        if args.category:
            params['type'] = args.category
        
        data = self._make_request('extensions', params, requires_auth=False)
        if not data:
            return False
        
        extensions = data.get('extensions', [])
        total = data.get('total', 0)
        self._display_extensions(extensions, f"Browse Results (Page {args.page}, Total: {total})")
        return True
    
    def _search_modules(self, args) -> bool:
        """Search for modules"""
        params = {
            'search': args.query,
            'page': args.page,
            'per_page': args.limit
        }
        
        if args.category:
            params['type'] = args.category
        
        data = self._make_request('extensions', params, requires_auth=False)
        if not data:
            return False
        
        extensions = data.get('extensions', [])
        self._display_extensions(extensions, f"Search Results for '{args.query}' (Page {args.page})")
        return True
    
    def _install_module(self, args) -> bool:
        """Install a module or all free modules"""
        if not self.api_key:
            print_error("Authentication required for installation")
            return False
        
        # If --all-free flag is set, install all free modules
        if args.all_free:
            return self._install_all_free_modules(args)
        
        # Otherwise, install a specific module
        if not args.module_id:
            print_error("Please specify a module ID or use --all-free to install all free modules")
            print_info("Usage: market install <module_id>")
            print_info("   or: market install --all-free")
            return False
        
        # First get extension info
        extension_data = self._make_request(f'extensions/{args.module_id}', requires_auth=False)
        if not extension_data:
            print_error(f"Extension {args.module_id} not found")
            return False
        
        # Check if extension is free
        if not extension_data.get('is_free', True):
            price = extension_data.get('price', 0)
            currency = extension_data.get('currency', 'USD')
            print_error(f"Extension '{extension_data.get('name', 'Unknown')}' is not free ({price} {currency})")
            print_info("Only free extensions can be installed via the market command")
            return False
        
        # Download and install
        return self._download_and_install_extension(args.module_id, extension_data)
    
    def _install_all_free_modules(self, args) -> bool:
        """Install all free modules from the marketplace"""
        try:
            print_info("=" * 70)
            print_info("📦 Installing All Free Modules")
            print_info("=" * 70)
            print_empty()
            
            # Get list of installed modules to skip already installed ones
            installed = self._get_installed_modules()
            installed_ids = {m['id'] for m in installed}
            
            # Fetch all free extensions from marketplace
            all_free_extensions = []
            page = 1
            per_page = 100  # Get as many as possible per page
            
            while True:
                params = {
                    'is_free': 'true',
                    'page': page,
                    'per_page': per_page
                }
                
                data = self._make_request('extensions', params, requires_auth=False)
                if not data:
                    break
                
                extensions = data.get('extensions', [])
                if not extensions:
                    break
                
                all_free_extensions.extend(extensions)
                
                # Check if there are more pages
                total_pages = data.get('total_pages', 1)
                if page >= total_pages:
                    break
                
                page += 1
            
            if not all_free_extensions:
                print_info("No free modules found in the marketplace")
                return True
            
            # Filter out already installed modules
            modules_to_install = [ext for ext in all_free_extensions if ext.get('id') not in installed_ids]
            
            if not modules_to_install:
                print_success("All free modules are already installed!")
                return True
            
            # Show what will be installed
            print_info(f"Found {len(all_free_extensions)} free module(s) in marketplace")
            if installed_ids:
                print_info(f"  - {len(installed_ids)} already installed")
                print_info(f"  - {len(modules_to_install)} to install")
            print_empty()
            
            # Ask for confirmation
            print_warning(f"This will install {len(modules_to_install)} module(s):")
            for ext in modules_to_install[:10]:  # Show first 10
                print_info(f"  - {ext.get('name', 'Unknown')} ({ext.get('id', 'N/A')})")
            if len(modules_to_install) > 10:
                print_info(f"  ... and {len(modules_to_install) - 10} more")
            print_empty()
            
            response = input("Do you want to continue? (yes/no): ").strip().lower()
            if response not in ['yes', 'y']:
                print_info("Installation cancelled")
                return True
            
            # Install each module
            print_empty()
            print_info("Starting installation...")
            print_empty()
            
            success_count = 0
            failed_count = 0
            
            for ext in modules_to_install:
                module_id = ext.get('id')
                module_name = ext.get('name', 'Unknown')
                
                print_info(f"📦 Installing {module_name} ({module_id})...")
                
                if self._download_and_install_extension(module_id, ext):
                    success_count += 1
                    print_success(f"✅ {module_name} installed successfully!")
                else:
                    failed_count += 1
                    print_error(f"❌ Failed to install {module_name}")
                
                print_empty()
            
            print_info("=" * 70)
            if failed_count == 0:
                print_success(f"✅ All installations completed successfully! ({success_count}/{len(modules_to_install)})")
            else:
                print_warning(f"⚠️  Installation completed with errors ({success_count}/{len(modules_to_install)} successful, {failed_count} failed)")
            print_info("=" * 70)
            
            return failed_count == 0
            
        except Exception as e:
            print_error(f"Failed to install all free modules: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _update_module(self, args) -> bool:
        """Update installed modules"""
        try:
            installed = self._get_installed_modules()
            
            if not installed:
                print_info("No modules installed")
                return True
            
            # If specific module_id provided, filter to that module
            if args.module_id:
                installed = [m for m in installed if m['id'] == args.module_id]
                if not installed:
                    print_error(f"Module '{args.module_id}' is not installed")
                    return False
            
            print_info("=" * 70)
            print_info("🔄 Checking for Updates")
            print_info("=" * 70)
            print_empty()
            
            updates_available = []
            
            for module in installed:
                module_id = module['id']
                installed_version = module['version']
                
                # Get latest version from marketplace
                extension_data = self._make_request(f'extensions/{module_id}', requires_auth=False)
                if not extension_data:
                    print_warning(f"⚠️  Could not check updates for {module_id} - not found in marketplace")
                    continue
                
                latest_version = extension_data.get('latest_version')
                if not latest_version:
                    # Try to get from versions array
                    versions = extension_data.get('versions', [])
                    for v in versions:
                        if v.get('is_latest', False):
                            latest_version = v.get('version')
                            break
                
                if not latest_version:
                    print_warning(f"⚠️  Could not determine latest version for {module_id}")
                    continue
                
                # Compare versions (simple string comparison for now)
                if installed_version != latest_version:
                    updates_available.append({
                        'module': module,
                        'installed_version': installed_version,
                        'latest_version': latest_version,
                        'extension_data': extension_data
                    })
                    print_info(f"📦 {module['name']}")
                    print_info(f"   Installed: v{installed_version} → Available: v{latest_version}")
                else:
                    print_info(f"✅ {module['name']} is up to date (v{installed_version})")
            
            print_empty()
            
            if not updates_available:
                print_success("All modules are up to date!")
                return True
            
            # Ask for confirmation
            print_info(f"Found {len(updates_available)} update(s) available")
            print_info("Updating modules...")
            print_empty()
            
            # Update each module
            success_count = 0
            for update in updates_available:
                module = update['module']
                module_id = module['id']
                print_info(f"🔄 Updating {module['name']} from v{update['installed_version']} to v{update['latest_version']}...")
                
                # Remove old installation
                try:
                    import shutil
                    if os.path.exists(module['path']):
                        # Remove the entire directory
                        shutil.rmtree(module['path'])
                        # Also clean up any .kext files in the parent directory
                        parent_dir = os.path.dirname(module['path'])
                        if os.path.exists(parent_dir):
                            for item in os.listdir(parent_dir):
                                if item.endswith('.kext'):
                                    kext_path = os.path.join(parent_dir, item)
                                    try:
                                        os.remove(kext_path)
                                    except Exception:
                                        pass
                except Exception as e:
                    print_warning(f"⚠️  Could not remove old version: {e}")
                
                # Install new version
                if self._download_and_install_extension(module_id, update['extension_data']):
                    success_count += 1
                    print_success(f"✅ {module['name']} updated successfully!")
                else:
                    print_error(f"❌ Failed to update {module['name']}")
                print_empty()
            
            print_info("=" * 70)
            if success_count == len(updates_available):
                print_success(f"✅ All updates completed successfully! ({success_count}/{len(updates_available)})")
            else:
                print_warning(f"⚠️  Updates completed with errors ({success_count}/{len(updates_available)} successful)")
            print_info("=" * 70)
            
            return success_count == len(updates_available)
            
        except Exception as e:
            print_error(f"Failed to update modules: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _uninstall_module(self, args) -> bool:
        """Uninstall installed modules"""
        try:
            installed = self._get_installed_modules()
            
            if not installed:
                print_info("No modules installed")
                return True
            
            # Determine which modules to uninstall
            modules_to_uninstall = []
            
            if args.all:
                # Uninstall all modules
                modules_to_uninstall = installed
                print_info("=" * 70)
                print_info("🗑️  Uninstalling All Modules")
                print_info("=" * 70)
                print_empty()
            elif args.module_id:
                # Uninstall specific module
                modules_to_uninstall = [m for m in installed if m['id'] == args.module_id]
                if not modules_to_uninstall:
                    print_error(f"Module '{args.module_id}' is not installed")
                    return False
                print_info("=" * 70)
                print_info("🗑️  Uninstalling Module")
                print_info("=" * 70)
                print_empty()
            else:
                print_error("Please specify a module ID or use --all to uninstall all modules")
                print_info("Usage: market uninstall <module_id>")
                print_info("   or: market uninstall --all")
                return False
            
            # Ask for confirmation if uninstalling all
            if args.all and len(modules_to_uninstall) > 1:
                print_warning(f"This will uninstall {len(modules_to_uninstall)} module(s):")
                for module in modules_to_uninstall:
                    print_info(f"  - {module['name']} (v{module['version']})")
                print_empty()
                response = input("Are you sure you want to uninstall all modules? (yes/no): ").strip().lower()
                if response not in ['yes', 'y']:
                    print_info("Uninstallation cancelled")
                    return True
            
            # Uninstall each module
            success_count = 0
            for module in modules_to_uninstall:
                module_id = module['id']
                module_name = module['name']
                module_path = module['path']
                
                print_info(f"🗑️  Uninstalling {module_name} (v{module['version']})...")
                
                try:
                    import shutil
                    # Remove the module directory
                    if os.path.exists(module_path):
                        shutil.rmtree(module_path)
                        print_success(f"✅ {module_name} uninstalled successfully")
                        success_count += 1
                        
                        # Also clean up parent directory if it's empty (for marketplace modules)
                        parent_dir = os.path.dirname(module_path)
                        if parent_dir and 'marketplace' in parent_dir:
                            # Check if parent directory is empty
                            try:
                                if os.path.exists(parent_dir) and not os.listdir(parent_dir):
                                    os.rmdir(parent_dir)
                                    # Also try to remove grandparent if empty
                                    grandparent_dir = os.path.dirname(parent_dir)
                                    if grandparent_dir and os.path.exists(grandparent_dir):
                                        try:
                                            if not os.listdir(grandparent_dir):
                                                os.rmdir(grandparent_dir)
                                        except Exception:
                                            pass
                            except Exception:
                                pass
                    else:
                        print_warning(f"⚠️  Module directory not found: {module_path}")
                        # Still count as success since it's already gone
                        success_count += 1
                        
                except Exception as e:
                    print_error(f"❌ Failed to uninstall {module_name}: {e}")
                
                print_empty()
            
            print_info("=" * 70)
            if success_count == len(modules_to_uninstall):
                print_success(f"✅ Uninstallation completed successfully! ({success_count}/{len(modules_to_uninstall)})")
            else:
                print_warning(f"⚠️  Uninstallation completed with errors ({success_count}/{len(modules_to_uninstall)} successful)")
            print_info("=" * 70)
            
            return success_count == len(modules_to_uninstall)
            
        except Exception as e:
            print_error(f"Failed to uninstall modules: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _show_module_info(self, args) -> bool:
        """Show detailed module information"""
        extension_data = self._make_request(f'extensions/{args.module_id}', requires_auth=False)
        if not extension_data:
            print_error(f"Extension {args.module_id} not found")
            return False
        
        self._display_extension_details(extension_data, args.module_id)
        return True
    
    def _list_categories(self) -> bool:
        """List available categories (extension types)"""
        # Les types d'extensions dans notre registry
        categories = [
            {'name': 'module', 'description': 'Framework modules'},
            {'name': 'plugin', 'description': 'Framework plugins'},
            {'name': 'UI', 'description': 'User interface components'},
            {'name': 'middleware', 'description': 'Middleware components'}
        ]
        
        print_info("Available Extension Types:")
        print_info("=" * 50)
        
        for category in categories:
            print_info(f"📁 {category['name']:<20}")
            print_info(f"   {category['description']}")
            print_empty()
        
        return True
    
    def _show_featured_modules(self, args) -> bool:
        """Show featured modules (top downloads)"""
        data = self._make_request('extensions', {'per_page': args.limit, 'is_free': 'true'}, requires_auth=False)
        if not data:
            return False
        
        extensions = sorted(data.get('extensions', []), key=lambda x: sum(v.get('download_count', 0) for v in x.get('versions', [])), reverse=True)
        self._display_extensions(extensions[:args.limit], "Featured Modules")
        return True
    
    def _show_popular_modules(self, args) -> bool:
        """Show popular modules (top downloads)"""
        data = self._make_request('extensions', {'per_page': args.limit, 'is_free': 'true'}, requires_auth=False)
        if not data:
            return False
        
        extensions = sorted(data.get('extensions', []), key=lambda x: sum(v.get('download_count', 0) for v in x.get('versions', [])), reverse=True)
        self._display_extensions(extensions[:args.limit], "Popular Modules")
        return True
    
    def _show_recent_modules(self, args) -> bool:
        """Show recently added modules"""
        data = self._make_request('extensions', {'per_page': args.limit}, requires_auth=False)
        if not data:
            return False
        
        extensions = sorted(data.get('extensions', []), key=lambda x: x.get('created_at', ''), reverse=True)
        self._display_extensions(extensions[:args.limit], "Recently Added Modules")
        return True
    
    def _get_installed_modules(self) -> List[Dict]:
        """Get list of installed modules from modules/marketplace/ and custom paths"""
        installed = []
        marketplace_dir = os.path.join("modules", "marketplace")
        
        # First, check modules/marketplace/ (default location)
        if os.path.exists(marketplace_dir):
            # Walk through modules/marketplace/<type>/<module_id>/latest/
            for module_type in os.listdir(marketplace_dir):
                type_path = os.path.join(marketplace_dir, module_type)
                if not os.path.isdir(type_path):
                    continue
                
                for module_id in os.listdir(type_path):
                    module_path = os.path.join(type_path, module_id)
                    if not os.path.isdir(module_path):
                        continue
                    
                    # Look for latest/ directory
                    latest_path = os.path.join(module_path, "latest")
                    if not os.path.exists(latest_path):
                        latest_path = module_path  # Fallback to module_path if no latest/
                    
                    # Look for extension.toml
                    manifest_path = os.path.join(latest_path, "extension.toml")
                    if os.path.exists(manifest_path):
                        try:
                            from core.registry.manifest import ManifestParser
                            manifest = ManifestParser.parse(manifest_path)
                            if manifest:
                                extension_type = manifest.extension_type.value if hasattr(manifest.extension_type, 'value') else str(manifest.extension_type)
                                installed.append({
                                    "id": manifest.id,
                                    "name": manifest.name,
                                    "version": manifest.version,
                                    "type": extension_type,
                                    "path": latest_path,
                                    "module_type": module_type
                                })
                        except Exception as e:
                            logging.debug(f"Could not parse manifest for {module_id}: {e}")
                            continue
        
        # Also check standard module directories (modules/auxiliary, modules/exploits, etc.)
        # for modules installed with custom install_path
        modules_dir = "modules"
        if os.path.exists(modules_dir):
            # Standard module type directories
            module_type_dirs = ["auxiliary", "exploits", "payloads", "listeners", "post", "encoders", "workflow", "backdoors", "remotescan"]
            
            for module_type in module_type_dirs:
                type_path = os.path.join(modules_dir, module_type)
                if not os.path.exists(type_path):
                    continue
                
                # Walk through each module directory
                for item in os.listdir(type_path):
                    item_path = os.path.join(type_path, item)
                    if not os.path.isdir(item_path):
                        continue
                    
                    # Look for extension.toml (indicates marketplace module)
                    manifest_path = os.path.join(item_path, "extension.toml")
                    if os.path.exists(manifest_path):
                        try:
                            from core.registry.manifest import ManifestParser
                            manifest = ManifestParser.parse(manifest_path)
                            if manifest:
                                # Check if this module is already in the list (by ID)
                                if any(m['id'] == manifest.id for m in installed):
                                    continue
                                
                                extension_type = manifest.extension_type.value if hasattr(manifest.extension_type, 'value') else str(manifest.extension_type)
                                installed.append({
                                    "id": manifest.id,
                                    "name": manifest.name,
                                    "version": manifest.version,
                                    "type": extension_type,
                                    "path": item_path,
                                    "module_type": module_type
                                })
                        except Exception as e:
                            logging.debug(f"Could not parse manifest for {item}: {e}")
                            continue
        
        return installed
    
    def _list_installed_extensions(self) -> bool:
        """List installed extensions"""
        try:
            installed = self._get_installed_modules()
            
            if not installed:
                print_info("No extensions installed")
                return True
            
            print_info("=" * 70)
            print_info(f"Installed Extensions ({len(installed)}):")
            print_info("=" * 70)
            print_empty()
            
            for ext in installed:
                print_info(f"📦 {ext['name']}")
                print_info(f"   ID: {ext['id']}")
                print_info(f"   Type: {ext['type']}")
                print_info(f"   Version: {ext['version']}")
                print_info(f"   Path: {ext['path']}")
                print_empty()
            
            return True
            
        except Exception as e:
            print_error(f"Failed to list installed extensions: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _publish_module(self, args) -> bool:
        """Package and publish a module to the marketplace"""
        import tempfile
        import zipfile
        import shutil
        from core.registry.packaging import ExtensionPackager
        from core.registry.manifest import ManifestParser
        from core.registry.signature import RegistrySignatureManager
        
        try:
            module_dir = os.path.abspath(args.module_dir)
            if not os.path.isdir(module_dir):
                print_error(f"❌ Module directory not found: {module_dir}")
                return False
            
            manifest_path = os.path.join(module_dir, "extension.toml")
            if not os.path.exists(manifest_path):
                print_error(f"❌ Manifest not found: {manifest_path}")
                print_info("💡 A module must have an extension.toml file")
                return False
            
            # Parse manifest to get module info
            manifest = ManifestParser.parse(manifest_path)
            if not manifest:
                print_error("❌ Failed to parse manifest")
                return False
            
            # Validate manifest
            is_valid, errors = ManifestParser.validate(manifest)
            if not is_valid:
                print_error(f"❌ Invalid manifest: {', '.join(errors)}")
                return False
            
            print_info("=" * 70)
            print_info("📦 Packaging Module")
            print_info("=" * 70)
            print_info(f"Module: {manifest.name}")
            print_info(f"ID: {manifest.id}")
            print_info(f"Version: {manifest.version}")
            print_empty()
            
            # Create bundle
            bundle_name = f"{manifest.id}_{manifest.version}.kext"
            bundle_path = os.path.join(module_dir, bundle_name)
            
            packager = ExtensionPackager()
            # Le serveur signera automatiquement avec la clé de l'utilisateur (basée sur l'API key)
            # On peut créer le bundle sans signature côté client, le serveur ajoutera la signature
            sign = not args.no_sign
            
            if sign:
                print_info("💡 Bundle will be signed automatically by the server using your API key")
            
            success = packager.create_bundle(
                source_dir=module_dir,
                manifest_path=manifest_path,
                output_path=bundle_path,
                publisher_name=None,  # Plus besoin - le serveur gère la signature
                sign=False  # Le serveur signera automatiquement
            )
            
            if not success:
                print_error("❌ Failed to create bundle")
                return False
            
            if args.package_only:
                print_success("✅ Module packaged successfully!")
                print_info(f"   Bundle: {bundle_path}")
                return True
            
            # Upload to registry
            print_info("=" * 70)
            print_info("📤 Publishing to Registry")
            print_info("=" * 70)
            
            # Upload bundle - le serveur utilisera votre API key pour identifier l'utilisateur
            # et signera automatiquement avec votre clé
            print_info(f"📤 Uploading bundle: {bundle_name}")
            print_info(f"   Your API key will be used for authentication and signing")
            
            success = self._upload_module(bundle_path)
            
            if success:
                print_success("=" * 70)
                print_success("✅ Module published successfully!")
                print_success("=" * 70)
                print_info(f"   Module ID: {manifest.id}")
                print_info(f"   Version: {manifest.version}")
                print_info(f"   Use 'market info {manifest.id}' to view details")
                print_info(f"   Use 'market install {manifest.id}' to install")
                return True
            else:
                return False
                
        except ImportError as e:
            print_error(f"❌ Registry packaging not available: {e}")
            return False
        except Exception as e:
            print_error(f"❌ Error publishing module: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _register_publisher(self, name: str, email: str) -> int:
        """Register a publisher and return its ID"""
        try:
            from core.registry.signature import RegistrySignatureManager
            
            # Generate key pair
            signature_manager = RegistrySignatureManager()
            success, public_key, private_key_path = signature_manager.generate_key_pair(name)
            
            if not success:
                print_error("❌ Failed to generate keys for publisher")
                return None
            
            print_info(f"🔑 Keys generated for {name}")
            print_info(f"   Private key: {private_key_path}")
            
            # Register publisher via API
            url = f"{self.registry_url}/api/registry/publishers"
            headers = {
                "X-API-Key": self.api_key,
                "Content-Type": "application/json"
            }
            
            data = {
                "name": name,
                "email": email,
                "public_key": public_key
            }
            
            response = requests.post(url, json=data, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                result = response.json()
                publisher_id = result.get("publisher_id")
                print_success(f"✅ Publisher registered with ID: {publisher_id}")
                return publisher_id
            elif response.status_code == 409:
                print_warning(f"⚠️  Publisher '{name}' already exists")
                print_info("💡 Use --publisher-id with the existing ID")
                return None
            else:
                error = response.json().get('error', response.text) if response.headers.get('content-type', '').startswith('application/json') else response.text
                print_error(f"❌ Failed to register publisher: {error}")
                return None
                
        except Exception as e:
            print_error(f"❌ Error registering publisher: {str(e)}")
            return None
    
    def _get_publisher_from_account(self) -> int:
        """Get publisher_id from user account (via API)"""
        try:
            # Récupérer les infos du compte depuis l'API
            url = f"{self.registry_url}/api/auth/me"
            headers = {
                "X-API-Key": self.api_key
            }
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                user_data = response.json()
                user_email = user_data.get('email')
                
                if user_email:
                    # Chercher le Publisher par email
                    # On pourrait ajouter une route API pour ça, mais pour l'instant on utilise l'email
                    # Le serveur le fera automatiquement
                    return None  # Le serveur le fera
            return None
        except:
            return None
    
    def _upload_module(self, bundle_path: str) -> bool:
        """Upload a module bundle to the registry (signed automatically by server using API key)"""
        try:
            url = f"{self.registry_url}/api/registry/extensions/upload"
            headers = {
                "X-API-Key": self.api_key
            }
            
            with open(bundle_path, 'rb') as f:
                files = {
                    'bundle': (os.path.basename(bundle_path), f, 'application/zip')
                }
                data = {}  # Plus besoin de publisher_id - le serveur utilise l'API key
                
                response = requests.post(url, files=files, data=data, headers=headers, timeout=60)
                response.raise_for_status()
                result = response.json()
                
                if result.get("success"):
                    # Server returns extension_id, name, version directly
                    extension_id = result.get('extension_id', 'N/A')
                    name = result.get('name', 'N/A')
                    version = result.get('version', 'N/A')
                    print_success(f"✅ Module uploaded successfully!")
                    print_info(f"   Extension ID: {extension_id}")
                    print_info(f"   Version: {version}")
                    return True
                else:
                    error = result.get('error', 'Unknown error')
                    print_error(f"❌ Upload failed: {error}")
                    return False
                    
        except requests.exceptions.HTTPError as e:
            print_error(f"❌ HTTP Error: {e.response.status_code}")
            try:
                error_data = e.response.json()
                error_msg = error_data.get('error', 'Unknown error')
                message = error_data.get('message', '')
                if message:
                    print_error(f"   {error_msg}")
                    print_error(f"   {message}")
                else:
                    print_error(f"   {error_msg}")
            except:
                print_error(f"   {e.response.text}")
            return False
        except Exception as e:
            print_error(f"❌ Error uploading module: {str(e)}")
            return False
    
    def _display_extensions(self, extensions: List[Dict], title: str):
        """Display a list of extensions"""
        if not extensions:
            print_info("No extensions found")
            return
        
        print_info(f"{title}")
        print_info("=" * 60)
        print_empty()
        
        for ext in extensions:
            ext_id = ext.get('id', 'N/A')
            name = ext.get('name', 'Unknown')
            description = ext.get('description', 'No description')
            publisher = ext.get('publisher', {})
            if isinstance(publisher, dict):
                publisher_name = publisher.get('name', 'Unknown')
            else:
                publisher_name = str(publisher) if publisher else 'Unknown'
            
            price = ext.get('price', 0)
            currency = ext.get('currency', 'USD')
            is_free = ext.get('is_free', True)
            ext_type = ext.get('type', 'Unknown')
            
            # Get latest version and total downloads
            latest_version = ext.get('latest_version')
            total_downloads = ext.get('total_downloads', 0)
            
            # Fallback: try to get from versions array if latest_version is not available
            if not latest_version:
                versions = ext.get('versions', [])
                for v in versions:
                    if v.get('is_latest', False):
                        latest_version = v.get('version')
                        break
                if not latest_version and versions:
                    latest_version = versions[0].get('version')
                # Recalculate total downloads if not provided
                if total_downloads == 0 and versions:
                    total_downloads = sum(v.get('download_count', 0) for v in versions)
            
            version_text = f"v{latest_version}" if latest_version else "vN/A"
            
            # Price display
            price_text = "FREE" if is_free else f"{price} {currency}"
            
            print_info(f"🆔 {ext_id:<30} | {name} {version_text}")
            print_info(f"   Publisher: {publisher_name:<20} | Type: {ext_type:<15} | Price: {price_text:<10}")
            print_info(f"   Downloads: {total_downloads}")
            print_info(f"   {description}")
            print_empty()
    
    def _display_extension_details(self, extension: Dict, extension_id: str = None):
        """Display detailed extension information"""
        print_info("=" * 70)
        print_info(f"📦 EXTENSION DETAILS")
        print_info("=" * 70)
        print_empty()
        
        # Basic info
        print_info(f"🆔 ID: {extension.get('id', 'N/A')}")
        print_info(f"📝 Name: {extension.get('name', 'Unknown')}")
        
        publisher = extension.get('publisher', {})
        if isinstance(publisher, dict):
            publisher_name = publisher.get('name', 'Unknown')
        else:
            publisher_name = str(publisher) if publisher else 'Unknown'
        print_info(f"👤 Publisher: {publisher_name}")
        
        price = extension.get('price', 0)
        currency = extension.get('currency', 'USD')
        is_free = extension.get('is_free', True)
        price_text = 'FREE' if is_free else f"{price} {currency}"
        print_info(f"💰 Price: {price_text}")
        print_info(f"📁 Type: {extension.get('type', 'Unknown')}")
        print_info(f"📄 License: {extension.get('license_type', 'N/A')}")
        
        # Calculate total downloads
        versions = extension.get('versions', [])
        total_downloads = sum(v.get('download_count', 0) for v in versions)
        print_info(f"📊 Total Downloads: {total_downloads}")
        print_empty()
        
        # Description
        print_info("📋 Description:")
        description = extension.get('description', 'No description available')
        # Wrap long descriptions
        words = description.split()
        lines = []
        current_line = ""
        for word in words:
            if len(current_line + word) > 60:
                lines.append(current_line.strip())
                current_line = word + " "
            else:
                current_line += word + " "
        if current_line:
            lines.append(current_line.strip())
        
        for line in lines:
            print_info(f"   {line}")
        print_empty()
        
        # Versions
        if versions:
            print_info("🔧 Available Versions:")
            for v in versions:
                latest = " (latest)" if v.get('is_latest') else ""
                print_info(f"   • {v.get('version')}{latest} - Downloads: {v.get('download_count', 0)}")
                print_info(f"     Compatible with KittySploit {v.get('kittysploit_min', '?')} - {v.get('kittysploit_max', '?')}")
            print_empty()
        
        # Installation instructions
        if is_free:
            print_info("💾 Installation:")
            print_info(f"   market install {extension.get('id', 'N/A')}")
        else:
            print_info("💳 Purchase Required:")
            print_info(f"   This extension costs {price} {currency} and cannot be installed via the market command")
        
        # Try to load and display doc.md if available
        if not extension_id:
            extension_id = extension.get('id', '')
        doc_content = self._load_extension_doc(extension_id)
        if doc_content:
            print_empty()
            print_info("=" * 70)
            print_info("Documentation:")
            print_info("=" * 70)
            print_info(doc_content)
        print_info("=" * 70)
    
    def _load_extension_doc(self, extension_id: str) -> Optional[str]:
        """Load doc.md for an extension"""
        try:
            # Get extensions directory from config
            try:
                import toml
                config_path = os.path.join("config", "kittysploit.toml")
                extensions_dir = "extensions"
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        config = toml.load(f)
                        extensions_dir = config.get('registry', {}).get('extensions_dir', 'extensions')
            except:
                extensions_dir = "extensions"
            
            ext_path = os.path.join(extensions_dir, extension_id)
            if not os.path.exists(ext_path):
                return None
            
            # Look for latest version or any version
            version_dirs = []
            for item in os.listdir(ext_path):
                item_path = os.path.join(ext_path, item)
                if os.path.isdir(item_path):
                    version_dirs.append((item, item_path))
            
            version_dirs.sort(key=lambda x: (x[0] != "latest", x[0]))
            
            if not version_dirs:
                version_dirs = [("", ext_path)]
            
            # Try each version directory
            for version_name, version_dir in version_dirs:
                doc_file = os.path.join(version_dir, "doc.md")
                if os.path.exists(doc_file):
                    with open(doc_file, 'r', encoding='utf-8') as f:
                        return f.read()
            
            return None
        except Exception as e:
            logging.debug(f"Could not load extension doc.md: {e}")
            return None
    
    def _download_and_install_extension(self, extension_id: str, extension_data: Dict) -> bool:
        """Download and install an extension"""
        import tempfile
        import zipfile
        import shutil
        
        try:
            module_name = extension_data.get('name', 'Unknown')
            
            print_info(f"📥 Downloading module '{module_name}'...")
            
            # Download extension bundle
            url = f"{self.registry_url}/api/registry/extensions/{extension_id}/download"
            headers = {'X-API-Key': self.api_key} if self.api_key else {}
            
            response = requests.get(url, headers=headers, stream=True, timeout=self.timeout)
            response.raise_for_status()
            
            # Get extensions directory from config
            try:
                import toml
                config_path = os.path.join("config", "kittysploit.toml")
                extensions_dir = "extensions"  # default
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        config = toml.load(f)
                        extensions_dir = config.get('registry', {}).get('extensions_dir', 'extensions')
            except:
                extensions_dir = "extensions"
            
            # Create temporary file for bundle
            with tempfile.NamedTemporaryFile(delete=False, suffix='.kext') as tmp_file:
                tmp_path = tmp_file.name
                for chunk in response.iter_content(chunk_size=8192):
                    tmp_file.write(chunk)
            
            print_info(f"📦 Extracting module bundle...")
            
            # Determine module type from manifest (will be read after extraction)
            # For now, extract to a temp location to read manifest first
            temp_extract_dir = tempfile.mkdtemp()
            
            # Extract the bundle temporarily to read manifest
            try:
                with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_extract_dir)
            except zipfile.BadZipFile:
                print_error("❌ Invalid bundle format (not a valid ZIP file)")
                os.remove(tmp_path)
                shutil.rmtree(temp_extract_dir, ignore_errors=True)
                return False
            
            # Read manifest to get install_path and module type
            manifest_path = os.path.join(temp_extract_dir, "extension.toml")
            module_type = "auxiliary"  # default
            install_path = None
            
            if os.path.exists(manifest_path):
                try:
                    from core.registry.manifest import ManifestParser
                    manifest_obj = ManifestParser.parse(manifest_path)
                    if manifest_obj:
                        # Use install_path from manifest if specified
                        install_path = manifest_obj.install_path
                    
                    # Also parse as TOML for backward compatibility
                    import toml
                    with open(manifest_path, 'r') as f:
                        manifest = toml.load(f)
                        # Get module type from manifest
                        # For modules from marketplace, we need to determine the actual module type
                        # by loading the main.py and checking the class
                        entry_point = manifest.get('metadata', {}).get('entry_point', 'main.py')
                        entry_file = os.path.join(temp_extract_dir, entry_point)
                        if os.path.exists(entry_file):
                            # Try to detect module type from code
                            with open(entry_file, 'r', encoding='utf-8') as f:
                                code = f.read()
                                if 'class Module(Auxiliary)' in code or 'class Module(BrowserAuxiliary)' in code:
                                    module_type = "auxiliary"
                                elif 'class Module(Exploit)' in code or 'class Module(BrowserExploit)' in code:
                                    module_type = "exploit"
                                elif 'class Module(Payload)' in code:
                                    module_type = "payload"
                                elif 'class Module(Listener)' in code:
                                    module_type = "listener"
                                elif 'class Module(Post)' in code:
                                    module_type = "post"
                except Exception as e:
                    logging.debug(f"Could not determine module type: {e}")
            
            # Determine extract directory
            if install_path:
                # Validate install_path security
                normalized_path = install_path.replace("\\", "/").strip()
                
                # Security checks
                if not (normalized_path.startswith("modules/") or normalized_path.startswith("plugins/")):
                    print_error(f"❌ Security: install_path must start with 'modules/' or 'plugins/'")
                    print_error(f"   Received: {install_path}")
                    shutil.rmtree(temp_extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                if ".." in normalized_path:
                    print_error(f"❌ Security: install_path cannot contain '..' (path traversal attempt)")
                    print_error(f"   Received: {install_path}")
                    shutil.rmtree(temp_extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                if os.path.isabs(normalized_path):
                    print_error(f"❌ Security: install_path must be a relative path")
                    print_error(f"   Received: {install_path}")
                    shutil.rmtree(temp_extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                # Use install_path from manifest (relative to framework root)
                extract_dir = normalized_path
                print_info(f"📁 Installing to: {extract_dir} (from manifest)")
            else:
                # Check for default_install_path in config
                try:
                    from core.config import Config
                    config = Config()
                    registry_config = config.config.get('registry', {})
                    default_install_path = registry_config.get('default_install_path', '')
                    
                    if default_install_path and default_install_path.strip():
                        # Use configured default path
                        if default_install_path.strip() == "marketplace":
                            # Use marketplace location
                            extract_dir = os.path.join("modules", "marketplace", module_type, extension_id, "latest")
                        else:
                            # Use custom path template (e.g., "modules/{type}/{id}")
                            extract_dir = default_install_path.replace("{type}", module_type).replace("{id}", extension_id)
                            # Ensure it starts with modules/ or plugins/
                            if not (extract_dir.startswith("modules/") or extract_dir.startswith("plugins/")):
                                extract_dir = os.path.join("modules", module_type, extension_id)
                    else:
                        # Default: install directly to modules/<type>/<module_id>
                        extract_dir = os.path.join("modules", module_type, extension_id)
                except Exception as e:
                    logging.debug(f"Could not read config for default_install_path: {e}")
                    # Fallback: install directly to modules/<type>/<module_id>
                    extract_dir = os.path.join("modules", module_type, extension_id)
                
                print_info(f"📁 Installing to: {extract_dir} (default location)")
            
            os.makedirs(extract_dir, exist_ok=True)
            
            # Clean up any existing .kext files in the extract directory
            if os.path.exists(extract_dir):
                for item in os.listdir(extract_dir):
                    if item.endswith('.kext'):
                        kext_path = os.path.join(extract_dir, item)
                        try:
                            os.remove(kext_path)
                        except Exception:
                            pass
            
            # Move files from temp location to final location
            for item in os.listdir(temp_extract_dir):
                src = os.path.join(temp_extract_dir, item)
                dst = os.path.join(extract_dir, item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(src, dst)
            
            # Clean up temp directory
            shutil.rmtree(temp_extract_dir, ignore_errors=True)
            
            # Check for manifest (already extracted to extract_dir)
            manifest_path = os.path.join(extract_dir, "extension.toml")
            if not os.path.exists(manifest_path):
                print_error("❌ Manifest extension.toml not found in bundle")
                shutil.rmtree(extract_dir, ignore_errors=True)
                os.remove(tmp_path)
                return False
            
            # Parse and validate manifest
            try:
                from core.registry.manifest import ManifestParser
                manifest = ManifestParser.parse(manifest_path)
                if not manifest:
                    print_error("❌ Failed to parse manifest")
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                # Validate manifest
                is_valid, errors = ManifestParser.validate(manifest)
                if not is_valid:
                    print_error(f"❌ Invalid manifest: {', '.join(errors)}")
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                # Validate extension type (category)
                valid_types = ['module', 'plugin', 'UI', 'middleware']
                extension_type = manifest.extension_type.value if hasattr(manifest.extension_type, 'value') else str(manifest.extension_type)
                if extension_type not in valid_types:
                    print_error(f"❌ Invalid extension type: {extension_type}")
                    print_error(f"   Valid types are: {', '.join(valid_types)}")
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                print_success(f"✅ Module '{module_name}' installed successfully!")
                print_info(f"   Installed to: {extract_dir}")
                print_info(f"   Type: {extension_type}")
                print_info(f"   Version: {manifest.version}")
                print_info(f"   Use 'market installed' to see installed modules")
                
                # Determine the correct use path
                if install_path:
                    # Use the install_path from manifest (convert to use path format)
                    use_path = install_path.replace("\\", "/")
                    if use_path.startswith("modules/"):
                        use_path = use_path[len("modules/"):]
                else:
                    # Generate use path based on actual installation location
                    # Remove "modules/" prefix if present
                    use_path = extract_dir.replace("\\", "/")
                    if use_path.startswith("modules/"):
                        use_path = use_path[len("modules/"):]
                    # Remove "/latest" suffix if present (for marketplace location)
                    if use_path.endswith("/latest"):
                        use_path = use_path[:-len("/latest")]
                
                print_info(f"   Use 'use {use_path}' to load the module")
                
            except ImportError:
                print_warning("⚠️  Could not validate manifest (registry module not available)")
                print_success(f"✅ Module '{module_name}' extracted to: {extract_dir}")
            except Exception as e:
                print_warning(f"⚠️  Could not fully validate module: {e}")
                print_success(f"✅ Module '{module_name}' extracted to: {extract_dir}")
            
            # Clean up temporary bundle file
            try:
                os.remove(tmp_path)
            except:
                pass
            
            return True
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print_error("❌ Unauthorized - please login or register")
            else:
                print_error(f"❌ Failed to download extension: {e.response.status_code}")
            return False
        except Exception as e:
            print_error(f"❌ Failed to install extension: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

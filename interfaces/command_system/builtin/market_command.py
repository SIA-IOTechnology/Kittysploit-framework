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
import time
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
        return "market [list|search|install|update|uninstall|info|installed|register|login|buy]"
    
    def get_subcommands(self) -> List[str]:
        """Get available subcommands for auto-completion"""
        return ['list', 'search', 'install', 'update', 'uninstall', 'info', 'installed', 'register', 'login', 'buy']
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command allows you to browse, search, and install modules from the KittySploit marketplace.

Subcommands:
    list          List all available modules
    search <term> Search for modules by name or description
    install [id]  Install a module by its ID (or use --all-free to install all free modules)
    info <id>     Show detailed information about a module
    installed     List installed modules
    update [id]   Update installed modules (all or specific module)
    uninstall [id] Uninstall a module (all if --all flag, or specific module)
    register      Register a new account
    login         Login to your account
    buy <id>      Purchase a module from the marketplace

Examples:
    market list                      # List all modules
    market search "proxy"            # Search for proxy-related modules
    market install test-module       # Install module with ID test-module
    market install --all-free       # Install all free modules from marketplace
    market info test-module          # Show info about module test-module
    market installed                 # List installed modules
    market update                    # Update all installed modules
    market update test-module        # Update specific module
    market uninstall test-module    # Uninstall specific module
    market uninstall --all          # Uninstall all modules
        """
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
        # Use registry server
        self.registry_url = self._get_registry_url()
        self.timeout = 10
        self.api_key = None  # Keep for backward compatibility
        self.token = None  # Bearer token for new API
        self._load_account_config()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command parser"""
        parser = argparse.ArgumentParser(
            description="Browse and install modules from the marketplace",
            add_help=True
        )
        
        subparsers = parser.add_subparsers(dest='action', help='Available actions')
        
        # List command
        list_parser = subparsers.add_parser('list', help='List all available modules')
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
        
        # Installed command
        subparsers.add_parser('installed', help='List installed extensions')
        
        # Register command
        subparsers.add_parser('register', help='Register a new account')
        
        # Login command
        subparsers.add_parser('login', help='Login to your account')
        
        # Buy command
        buy_parser = subparsers.add_parser('buy', help='Purchase a module from the marketplace')
        buy_parser.add_argument('module_id', help='Module ID to purchase')
        
        return parser
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the market command"""
        try:
            if not args:
                # If no arguments and no account, prompt for registration/login
                if not self.api_key:
                    self._prompt_account_setup()
                self.parser.print_help()
                return True
            
            parsed_args = self.parser.parse_args(args)
            
            if not parsed_args.action:
                self.parser.print_help()
                return True
            
            # Check authentication for actions that require it
            requires_auth = parsed_args.action in ['install', 'update', 'publish', 'buy']
            if requires_auth and not self.token and not self.api_key:
                print_warning("This action requires an account")
                if self._prompt_account_setup():
                    self._load_account_config()
                else:
                    return False
            
            # Execute the appropriate action
            if parsed_args.action == 'list':
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
            elif parsed_args.action == 'installed':
                return self._list_installed_extensions()
            elif parsed_args.action == 'register':
                return self._register_account()
            elif parsed_args.action == 'login':
                return self._login_account()
            elif parsed_args.action == 'buy':
                return self._buy_module(parsed_args)
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
                    registry_url = config.get('registry', {}).get('url', 'https://app.kittysploit.com')
                    if registry_url:
                        return registry_url.rstrip('/')
        except Exception as e:
            # Silently fall back to default
            pass
        # Try to get from config file
        try:
            config_file = os.path.join(os.path.expanduser("~"), ".kittysploit", "registry_config.json")
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    base_url = config.get('base_url')
                    if base_url:
                        return base_url.rstrip('/')
        except Exception:
            pass
        return "https://app.kittysploit.com"
    
    def _load_account_config(self):
        """Load account configuration from file"""
        try:
            config_file = os.path.join(os.path.expanduser("~"), ".kittysploit", "registry_config.json")
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    # Support both old api_key and new token
                    self.token = config.get('token')
                    self.api_key = config.get('api_key')  # Backward compatibility
                    # Update registry_url from config if available
                    base_url = config.get('base_url')
                    if base_url:
                        self.registry_url = base_url.rstrip('/')
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
            print_info("\n=== Marketplace Account Registration ===")
            email = input("Email: ").strip()
            if not email:
                print_error("Email is required")
                return False
            
            username = input("Username: ").strip()
            if not username:
                print_error("Username is required")
                return False
            
            password = getpass.getpass("Password: ")
            if not password:
                print_error("Password is required")
                return False
            
            password_confirm = getpass.getpass("Confirm password: ")
            if password != password_confirm:
                print_error("Passwords do not match")
                return False
            
            response = requests.post(
                f"{self.registry_url}/api/cli/register",
                json={"email": email, "username": username, "password": password},
                timeout=self.timeout
            )
            
            if response.status_code == 201:
                result = response.json()
                if result.get('success'):
                    user = result.get('user', {})
                    print_success("Account created successfully!")
                    print_info(f"Username: {user.get('username', 'N/A')}")
                    print_info(f"Email: {user.get('email', 'N/A')}")
                    print_info("You can now login with: market login")
                    return True
                else:
                    error = result.get('error', 'Unknown error')
                    print_error(f"Registration failed: {error}")
                    return False
            elif response.status_code == 409:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                error = error_data.get('error', 'Email or username already exists')
                print_error(f"Registration failed: {error}")
                print_info("Use 'market login' to connect to your existing account")
                return False
            elif response.status_code == 429:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                message = error_data.get('message', 'Too many requests')
                retry_after = error_data.get('retry_after', 3600)
                print_error(f"Rate limit exceeded: {message}")
                print_info(f"Please try again after {retry_after} seconds")
                return False
            else:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                error = error_data.get('error', response.text)
                message = error_data.get('message', '')
                if message:
                    print_error(f"Registration failed: {error}")
                    print_error(f"  {message}")
                else:
                    print_error(f"Registration failed: {error}")
                return False
        except requests.exceptions.ConnectionError:
            print_error("Failed to connect to marketplace server")
            print_info(f"Server URL: {self.registry_url}")
            return False
        except Exception as e:
            print_error(f"Error: {str(e)}")
            return False
    
    def _login_account(self) -> bool:
        """Login to account"""
        try:
            print_info("\n=== Marketplace Account Login ===")
            email = input("Email: ").strip()
            if not email:
                print_error("Email is required")
                return False
            
            password = getpass.getpass("Password: ")
            if not password:
                print_error("Password is required")
                return False
            
            response = requests.post(
                f"{self.registry_url}/api/cli/login",
                json={"email": email, "password": password},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    token = result.get('token')
                    expires_at = result.get('expires_at')
                    user = result.get('user', {})
                    
                    if token:
                        self.token = token
                        self._save_account_config(token, user.get('email'), user.get('username'), expires_at)
                        print_success("Login successful!")
                        print_info(f"Welcome, {user.get('username', 'N/A')}!")
                        if expires_at:
                            print_info(f"Token expires at: {expires_at}")
                        return True
                    else:
                        print_error("Login failed: No token received")
                        return False
                else:
                    error = result.get('error', 'Unknown error')
                    print_error(f"Login failed: {error}")
                    return False
            elif response.status_code == 401:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                error = error_data.get('error', 'Invalid credentials')
                print_error(f"Login failed: {error}")
                return False
            elif response.status_code == 403:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                error = error_data.get('error', 'Account disabled')
                print_error(f"Login failed: {error}")
                return False
            elif response.status_code == 429:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                message = error_data.get('message', 'Too many requests')
                retry_after = error_data.get('retry_after', 3600)
                print_error(f"Rate limit exceeded: {message}")
                print_info(f"Please try again after {retry_after} seconds")
                return False
            else:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                error = error_data.get('error', response.text)
                message = error_data.get('message', '')
                if message:
                    print_error(f"Login failed: {error}")
                    print_error(f"  {message}")
                else:
                    print_error(f"Login failed: {error}")
                return False
        except requests.exceptions.ConnectionError:
            print_error("Failed to connect to marketplace server")
            print_info(f"Server URL: {self.registry_url}")
            return False
        except Exception as e:
            print_error(f"Error: {str(e)}")
            return False
    
    def _save_account_config(self, token: str = None, email: str = None, username: str = None, expires_at: str = None, api_key: str = None):
        """Save account configuration"""
        try:
            config_dir = os.path.join(os.path.expanduser("~"), ".kittysploit")
            os.makedirs(config_dir, exist_ok=True)
            config_file = os.path.join(config_dir, "registry_config.json")
            
            config = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
            
            # Save token (new API) or api_key (old API for backward compatibility)
            if token:
                config['token'] = token
            if api_key:
                config['api_key'] = api_key  # Backward compatibility
            
            config['base_url'] = self.registry_url
            if email:
                config['email'] = email
            if username:
                config['username'] = username
            if expires_at:
                config['expires_at'] = expires_at
            
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass
    
    def _make_request(self, endpoint: str, params: Dict = None, method: str = 'GET', requires_auth: bool = False, use_new_api: bool = False) -> Optional[Dict]:
        """Make a request to the registry API"""
        try:
            # Use new API format if specified
            if use_new_api:
                url = f"{self.registry_url}/api/cli/{endpoint}"
            else:
                url = f"{self.registry_url}/api/registry/{endpoint}"
            
            headers = {}
            
            # Authentication headers
            if use_new_api:
                # Always send bearer token when available for new API (even for public endpoints)
                if self.token:
                    headers['Authorization'] = f'Bearer {self.token}'
                elif requires_auth and self.api_key:
                    # Some deployments may still accept API keys - send if token missing
                    headers['X-API-Key'] = self.api_key
            else:
                if requires_auth:
                    if self.api_key:
                        headers['X-API-Key'] = self.api_key
                    elif self.token:
                        headers['X-API-Key'] = self.token
            
            # Debug: log the URL being called (only in debug mode)
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.debug(f"Making {method} request to: {url}")
                if params:
                    logging.debug(f"Params: {params}")
            
            if method == 'GET':
                response = requests.get(url, params=params, headers=headers, timeout=self.timeout)
            else:
                response = requests.request(method, url, json=params, headers=headers, timeout=self.timeout)
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError as e:
            print_error("Failed to connect to marketplace server")
            print_info(f"Server URL: {self.registry_url}")
            return None
        except requests.exceptions.Timeout as e:
            print_error("Connection timeout - marketplace server is not responding")
            print_info(f"Server URL: {self.registry_url}")
            return None
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 401:
                if requires_auth:
                    # Clear invalid token silently
                    if self.token:
                        self.token = None
                        self._save_account_config()
                    # Don't print error here - let caller handle it
                else:
                    # Some public endpoints on the new API may require auth but we can fall back silently
                    if not use_new_api:
                        print_error("Server returned 401 Unauthorized for a public endpoint")
            elif status_code == 403:
                error_data = e.response.json() if e.response.headers.get('content-type', '').startswith('application/json') else {}
                error = error_data.get('error', 'Access forbidden')
                print_error(f"Forbidden: {error}")
            elif status_code == 404:
                # Silent 404 - endpoint may not exist, will be handled by caller
                pass
            elif status_code == 429:
                error_data = e.response.json() if e.response.headers.get('content-type', '').startswith('application/json') else {}
                message = error_data.get('message', 'Too many requests')
                retry_after = error_data.get('retry_after', 3600)
                print_error(f"Rate limit exceeded: {message}")
                print_info(f"Please try again after {retry_after} seconds")
            else:
                try:
                    error_body = e.response.json()
                    error_msg = error_body.get('error', 'Unknown error')
                    message = error_body.get('message', '')
                    if message:
                        print_error(f"HTTP error {status_code}: {error_msg}")
                        print_error(f"  {message}")
                    else:
                        print_error(f"HTTP error {status_code}: {error_msg}")
                except:
                    error_text = e.response.text[:200] if hasattr(e.response, 'text') else str(e)
                    print_error(f"HTTP error {status_code}: {error_text}")
            return None
        except requests.exceptions.RequestException as e:
            print_error(f"Network error: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            print_error(f"Invalid response from marketplace: {str(e)}")
            return None
    
    def _browse_modules(self, args) -> bool:
        """Browse modules by category"""
        params = {
            'page': args.page,
            'per_page': args.limit
        }
        
        if args.category:
            params['type'] = args.category
        
        # Try new API first, fallback to old API
        data = self._make_request('market/modules', params, requires_auth=False, use_new_api=True)
        
        if not data:
            # Fallback to old API
            data = self._make_request('extensions', params, requires_auth=False, use_new_api=False)
        
        if not data:
            return False
        
        # Handle both new and old API response formats
        if 'modules' in data:
            # New API format
            modules = data.get('modules', [])
            pagination = data.get('pagination', {})
            total = pagination.get('total', len(modules))
            self._display_modules_new_format(modules, f"Browse Results (Page {args.page}, Total: {total})", pagination)
        else:
            # Old API format
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
        
        # Try new API first, fallback to old API
        data = self._make_request('market/modules', params, requires_auth=False, use_new_api=True)
        
        if not data:
            # Fallback to old API
            data = self._make_request('extensions', params, requires_auth=False, use_new_api=False)
        
        if not data:
            return False
        
        # Handle both new and old API response formats
        if 'modules' in data:
            # New API format
            modules = data.get('modules', [])
            pagination = data.get('pagination', {})
            total = pagination.get('total', len(modules))
            self._display_modules_new_format(modules, f"Search Results for '{args.query}' (Page {args.page}, Total: {total})", pagination)
        else:
            # Old API format
            extensions = data.get('extensions', [])
            self._display_extensions(extensions, f"Search Results for '{args.query}' (Page {args.page})")
        
        return True
    
    def _install_module(self, args) -> bool:
        """Install a module or all free modules"""
        # Authentication is required for installation
        if not self.token and not self.api_key:
            print_error("Authentication required")
            print_info("Use 'market login' or 'market register'")
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
        
        # Get module info - search in the modules list
        params = {'per_page': 100, 'page': 1}
        data = self._make_request('market/modules', params=params, requires_auth=True, use_new_api=True)
        
        if not data:
            print_error("Authentication required")
            print_info("Use 'market login' or 'market register'")
            return False
        
        module_data = None
        if 'modules' in data:
            modules = data.get('modules', [])
            # Search through pages if needed
            found = False
            page = 1
            while not found and page <= 10:  # Limit to 10 pages
                for module in modules:
                    if str(module.get('id')) == str(args.module_id):
                        module_data = module
                        found = True
                        break
                
                if not found:
                    # Try next page
                    pagination = data.get('pagination', {})
                    if pagination.get('has_next'):
                        page += 1
                        params['page'] = page
                        data = self._make_request('market/modules', params=params, requires_auth=True, use_new_api=True)
                        if data and 'modules' in data:
                            modules = data.get('modules', [])
                        else:
                            break
                    else:
                        break
        
        if not module_data:
            print_error(f"Module {args.module_id} not found")
            return False
        
        # Check if module can be downloaded using the check endpoint (recommended)
        check_data = self._make_request(f'market/check/{args.module_id}', requires_auth=True, use_new_api=True)
        
        if check_data:
            # Use check endpoint response
            can_download = check_data.get('can_download', False)
            has_purchased = check_data.get('has_purchased', False)
            is_author = check_data.get('is_author', False)
            price = check_data.get('price', 0)
            requires_payment = check_data.get('requires_payment', False)
            module_name = check_data.get('module_name', module_data.get('name', 'Unknown'))
            
            if requires_payment or (price > 0 and not can_download and not has_purchased and not is_author):
                checkout_url = check_data.get('checkout_url') or check_data.get('purchase_url')
                print_error(f"Module '{module_name}' requires purchase ({price}€)")
                if checkout_url:
                    print_info(f"Checkout URL: {checkout_url}")
                else:
                    purchase_url = f"{self.registry_url}/market/modules/{args.module_id}/purchase"
                    print_info(f"Purchase URL: {purchase_url}")
                print_info(f"Or use: market buy {args.module_id}")
                return False
        else:
            # Fallback: use module_data from list
            can_download = module_data.get('can_download', False)
            has_purchased = module_data.get('has_purchased', False)
            is_author = module_data.get('is_author', False)
            price = module_data.get('price', 0)
            is_free = module_data.get('is_free', True)
            module_name = module_data.get('name', 'Unknown')
            
            # Strict check: if price > 0, must have can_download=True OR has_purchased=True OR is_author=True
            if price > 0:
                if not can_download and not has_purchased and not is_author:
                    print_error(f"Module '{module_name}' requires purchase ({price}€)")
                    purchase_url = f"{self.registry_url}/market/modules/{args.module_id}/purchase"
                    print_info(f"Purchase URL: {purchase_url}")
                    print_info(f"Or use: market buy {args.module_id}")
                    return False
            
            # Old API format fallback check
            if not is_free and price > 0 and not has_purchased and not is_author:
                currency = module_data.get('currency', 'EUR')
                print_error(f"Extension '{module_name}' is not free ({price} {currency})")
                purchase_url = f"{self.registry_url}/market/modules/{args.module_id}/purchase"
                print_info(f"Purchase URL: {purchase_url}")
                return False
        
        # Download and install
        return self._download_and_install_extension(args.module_id, module_data)
    
    def _install_all_free_modules(self, args) -> bool:
        """Install all free modules from the marketplace"""
        try:
            print_info("=" * 70)
            print_info("Installing All Free Modules")
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
                
                print_info(f"Installing {module_name} ({module_id})...")
                
                if self._download_and_install_extension(module_id, ext):
                    success_count += 1
                    print_success(f"{module_name} installed successfully!")
                else:
                    failed_count += 1
                    print_error(f"Failed to install {module_name}")
                
                print_empty()
            
            print_info("=" * 70)
            if failed_count == 0:
                print_success(f"All installations completed successfully! ({success_count}/{len(modules_to_install)})")
            else:
                print_warning(f"Installation completed with errors ({success_count}/{len(modules_to_install)} successful, {failed_count} failed)")
            print_info("=" * 70)
            
            return failed_count == 0
            
        except Exception as e:
            print_error(f"Failed to install all free modules: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two semver version strings
        Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        """
        try:
            # Remove any non-numeric prefixes/suffixes and split by '.'
            def parse_version(v):
                # Remove common prefixes/suffixes
                v_clean = v.strip().lstrip('vV')
                # Split by '.' and convert to integers
                parts = []
                for part in v_clean.split('.'):
                    # Take only the numeric part before any non-numeric suffix
                    numeric_part = ''
                    for char in part:
                        if char.isdigit():
                            numeric_part += char
                        else:
                            break
                    parts.append(int(numeric_part) if numeric_part else 0)
                return parts
            
            v1_parts = parse_version(v1)
            v2_parts = parse_version(v2)
            
            # Pad with zeros to make same length
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            return 0
        except Exception:
            # Fallback to string comparison
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            return 0
    
    def _find_local_versions(self, module: Dict) -> List[Dict]:
        """
        Find all versions of an extension installed locally
        Returns list of dicts with 'version', 'path', and 'manifest_path'
        """
        local_versions = []
        
        try:
            # Get the base path for this extension
            # Module path might be extensions/{marketplace_id}/{manifest_id}/latest/
            # or extensions/{manifest_id}/latest/
            module_path = module.get('path', '')
            if not module_path or not os.path.exists(module_path):
                return local_versions
            
            # Get the parent directory (extensions/{marketplace_id}/{manifest_id}/ or extensions/{manifest_id}/)
            if module_path.endswith('latest') or module_path.endswith('latest/'):
                parent_dir = os.path.dirname(module_path)
            else:
                parent_dir = module_path
            
            if not os.path.exists(parent_dir):
                return local_versions
            
            # Get extensions directory root
            extensions_root = None
            for part in parent_dir.split(os.sep):
                if part == 'extensions':
                    idx = parent_dir.find('extensions')
                    extensions_root = parent_dir[:idx + len('extensions')]
                    break
            
            if not extensions_root:
                return local_versions
            
            # Find all version directories
            # Structure: extensions/{marketplace_id}/{manifest_id}/{version}/
            # or: extensions/{manifest_id}/{version}/
            for marketplace_id in os.listdir(extensions_root):
                marketplace_path = os.path.join(extensions_root, marketplace_id)
                if not os.path.isdir(marketplace_path):
                    continue
                
                for item in os.listdir(marketplace_path):
                    item_path = os.path.join(marketplace_path, item)
                    if not os.path.isdir(item_path):
                        continue
                    
                    # Check if this is the same extension by looking for manifest
                    manifest_path = os.path.join(item_path, "extension.toml")
                    if not os.path.exists(manifest_path):
                        # Check in subdirectories (version directories)
                        for version_dir_name in os.listdir(item_path):
                            version_dir_path = os.path.join(item_path, version_dir_name)
                            if not os.path.isdir(version_dir_path):
                                continue
                            version_manifest = os.path.join(version_dir_path, "extension.toml")
                            if os.path.exists(version_manifest):
                                try:
                                    from core.registry.manifest import ManifestParser
                                    manifest = ManifestParser.parse(version_manifest)
                                    if manifest and manifest.id == module['id']:
                                        local_versions.append({
                                            'version': manifest.version,
                                            'path': version_dir_path,
                                            'manifest_path': version_manifest,
                                            'version_dir': version_dir_name
                                        })
                                except Exception:
                                    continue
                    else:
                        # Manifest in root, check if it's the same extension
                        try:
                            from core.registry.manifest import ManifestParser
                            manifest = ManifestParser.parse(manifest_path)
                            if manifest and manifest.id == module['id']:
                                local_versions.append({
                                    'version': manifest.version,
                                    'path': item_path,
                                    'manifest_path': manifest_path,
                                    'version_dir': item
                                })
                        except Exception:
                            continue
            
            # Remove duplicates and sort by version
            seen = set()
            unique_versions = []
            for v in local_versions:
                key = (v['version'], v['path'])
                if key not in seen:
                    seen.add(key)
                    unique_versions.append(v)
            
            # Sort by version using compare_versions (newest first)
            def version_sort_key(v):
                try:
                    # Parse version for proper sorting
                    parts = v['version'].split('.')
                    return tuple(int(p) if p.isdigit() else 0 for p in parts) + (v['version'],)
                except:
                    return (0, 0, 0, v['version'])
            
            unique_versions.sort(key=version_sort_key, reverse=True)
            
        except Exception as e:
            logging.debug(f"Error finding local versions: {e}")
        
        return local_versions
    
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
            print_info("Checking for Updates")
            print_info("=" * 70)
            print_empty()
            
            updates_available = []
            checked_modules = []  # Modules successfully checked
            unchecked_modules = []  # Modules that couldn't be checked
            
            for module in installed:
                module_id = module['id']
                installed_version = module['version']
                
                # Use marketplace_id if available (for new structure), otherwise use manifest id
                marketplace_id = module.get('marketplace_id') or module.get('directory_id')
                search_id = marketplace_id if marketplace_id else module_id
                
                # First, check for local versions that might be newer
                local_versions = self._find_local_versions(module)
                local_update_available = None
                
                if local_versions:
                    # Find the newest local version
                    for local_v in local_versions:
                        if self._compare_versions(local_v['version'], installed_version) > 0:
                            local_update_available = local_v
                            break
                
                # Get latest version from marketplace
                # Try marketplace ID first, then manifest ID as fallback
                extension_data = None
                module_lookup_id = marketplace_id or module_id

                # Try the new marketplace API first so numeric IDs work
                if module_lookup_id:
                    extension_data = self._make_request(
                        f'market/modules/{module_lookup_id}',
                        requires_auth=True,
                        use_new_api=True
                    )
                    if isinstance(extension_data, dict) and isinstance(extension_data.get('module'), dict):
                        extension_data = extension_data['module']

                # Fallback to old API using marketplace ID first, then manifest ID
                if not extension_data and marketplace_id:
                    extension_data = self._make_request(f'extensions/{marketplace_id}', requires_auth=False)
                if not extension_data:
                    extension_data = self._make_request(f'extensions/{module_id}', requires_auth=False)
                if not extension_data:
                    # If not in marketplace, check local versions
                    if local_update_available:
                        updates_available.append({
                            'module': module,
                            'installed_version': installed_version,
                            'latest_version': local_update_available['version'],
                            'extension_data': None,  # No marketplace data
                            'local_path': local_update_available['path'],
                            'is_local': True
                        })
                        print_info(f"{module['name']}")
                        print_info(f"   Installed: v{installed_version} -> Local: v{local_update_available['version']} (available locally)")
                    else:
                        print_warning(f"Could not check updates for {module['name']} ({module_id}) - not found in marketplace")
                        unchecked_modules.append(module)
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
                    detected_version = self._get_module_version(extension_data)
                    if detected_version and detected_version != "N/A":
                        latest_version = detected_version

                if not latest_version:
                    # Marketplace doesn't have version info, but check local versions
                    if local_update_available:
                        updates_available.append({
                            'module': module,
                            'installed_version': installed_version,
                            'latest_version': local_update_available['version'],
                            'extension_data': extension_data,
                            'local_path': local_update_available['path'],
                            'is_local': True
                        })
                        print_info(f"{module['name']}")
                        print_info(f"   Installed: v{installed_version} -> Local: v{local_update_available['version']} (available locally)")
                        checked_modules.append(module)
                    else:
                        print_warning(f"Could not determine latest version for {module['name']} ({module_id})")
                        unchecked_modules.append(module)
                    continue
                
                # Mark as successfully checked
                checked_modules.append(module)
                
                # Compare marketplace version with local version and choose the newest
                best_version = latest_version
                best_source = "marketplace"
                best_local_path = None
                
                if local_update_available:
                    # Compare local version with marketplace version
                    if self._compare_versions(local_update_available['version'], latest_version) > 0:
                        best_version = local_update_available['version']
                        best_source = "local"
                        best_local_path = local_update_available['path']
                
                # Check if update is needed
                if self._compare_versions(installed_version, best_version) < 0:
                    update_info = {
                        'module': module,
                        'installed_version': installed_version,
                        'latest_version': best_version,
                        'extension_data': extension_data if best_source == "marketplace" else None,
                        'is_local': best_source == "local"
                    }
                    if best_local_path:
                        update_info['local_path'] = best_local_path
                    
                    updates_available.append(update_info)
                    source_text = "locally" if best_source == "local" else "marketplace"
                    print_info(f"{module['name']}")
                    print_info(f"   Installed: v{installed_version} -> Available: v{best_version} (from {source_text})")
                else:
                    print_info(f"{module['name']} is up to date (v{installed_version})")
            
            print_empty()
            
            # Provide a better summary
            if unchecked_modules and not checked_modules:
                # All modules couldn't be checked
                print_warning(f"Could not check updates for {len(unchecked_modules)} module(s) - not found in marketplace")
                print_info("These modules may be locally installed and not published in the marketplace.")
                return True
            elif unchecked_modules and checked_modules:
                # Some checked, some couldn't be checked
                if not updates_available:
                    print_success(f"All checked modules are up to date! ({len(checked_modules)} checked)")
                    print_warning(f"Could not check {len(unchecked_modules)} module(s) - not found in marketplace")
                    return True
                else:
                    print_info(f"Found {len(updates_available)} update(s) available")
                    print_warning(f"Could not check {len(unchecked_modules)} module(s) - not found in marketplace")
            elif not updates_available:
                # All modules checked and up to date
                print_success("All modules are up to date!")
                return True
            
            # If we reach here, there are updates available (and we haven't printed the message yet)
            if updates_available and not (unchecked_modules and checked_modules):
                # Only print if we haven't already printed it in the elif block above
                print_info(f"Found {len(updates_available)} update(s) available")
            
            print_info("Updating modules...")
            print_empty()
            
            # Update each module
            success_count = 0
            for update in updates_available:
                module = update['module']
                module_id = module['id']
                # Use marketplace_id for download if available, otherwise use manifest id
                marketplace_id = module.get('marketplace_id') or module.get('directory_id')
                download_id = marketplace_id if marketplace_id else module_id
                
                print_info(f"Updating {module['name']} from v{update['installed_version']} to v{update['latest_version']}...")
                
                # Move the existing installation aside until the new version installs successfully
                backup_path = None
                parent_dir = os.path.dirname(module.get('path', '') or '')
                try:
                    import shutil
                    module_path = module.get('path')
                    if module_path and os.path.exists(module_path):
                        backup_path = f"{module_path}.backup"
                        if os.path.exists(backup_path):
                            shutil.rmtree(backup_path)
                        shutil.move(module_path, backup_path)
                except Exception as e:
                    print_warning(f"Could not create backup of existing installation: {e}")
                    backup_path = None

                # Install new version
                if update.get('is_local') and update.get('local_path'):
                    # Install from local path
                    if self._install_from_local_path(module, update['local_path'], update['latest_version']):
                        success_count += 1
                        print_success(f"{module['name']} updated successfully!")
                        if backup_path and os.path.exists(backup_path):
                            shutil.rmtree(backup_path, ignore_errors=True)
                        if parent_dir and os.path.exists(parent_dir):
                            for item in os.listdir(parent_dir):
                                if item.endswith('.kext'):
                                    kext_path = os.path.join(parent_dir, item)
                                    try:
                                        os.remove(kext_path)
                                    except Exception:
                                        pass
                    else:
                        print_error(f"Failed to update {module['name']}")
                        if backup_path:
                            try:
                                if not os.path.exists(module.get('path', '')):
                                    shutil.move(backup_path, module.get('path'))
                                    print_warning(f"Restored previous version of {module['name']} due to installation failure")
                                else:
                                    shutil.rmtree(backup_path, ignore_errors=True)
                            except Exception as e:
                                print_warning(f"Could not restore previous version of {module['name']}: {e}")
                elif update.get('extension_data'):
                    # Install from marketplace - use marketplace ID for download
                    if self._download_and_install_extension(download_id, update['extension_data']):
                        success_count += 1
                        print_success(f"{module['name']} updated successfully!")
                        if backup_path and os.path.exists(backup_path):
                            shutil.rmtree(backup_path, ignore_errors=True)
                        if parent_dir and os.path.exists(parent_dir):
                            for item in os.listdir(parent_dir):
                                if item.endswith('.kext'):
                                    kext_path = os.path.join(parent_dir, item)
                                    try:
                                        os.remove(kext_path)
                                    except Exception:
                                        pass
                    else:
                        print_error(f"Failed to update {module['name']}")
                        if backup_path:
                            try:
                                if not os.path.exists(module.get('path', '')):
                                    shutil.move(backup_path, module.get('path'))
                                    print_warning(f"Restored previous version of {module['name']} due to installation failure")
                                else:
                                    shutil.rmtree(backup_path, ignore_errors=True)
                            except Exception as e:
                                print_warning(f"Could not restore previous version of {module['name']}: {e}")
                else:
                    print_error(f"Unable to update {module['name']} - no source available")
                    if backup_path:
                        try:
                            if not os.path.exists(module.get('path', '')):
                                shutil.move(backup_path, module.get('path'))
                                print_warning(f"Restored previous version of {module['name']} due to missing update source")
                            else:
                                shutil.rmtree(backup_path, ignore_errors=True)
                        except Exception as e:
                            print_warning(f"Could not restore previous version of {module['name']}: {e}")
                print_empty()
            
            print_info("=" * 70)
            if success_count == len(updates_available):
                print_success(f"All updates completed successfully! ({success_count}/{len(updates_available)})")
            else:
                print_warning(f"Updates completed with errors ({success_count}/{len(updates_available)} successful)")
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
                print_info("Uninstalling All Modules")
                print_info("=" * 70)
                print_empty()
            elif args.module_id:
                # Uninstall specific module - can match by manifest ID or directory name
                modules_to_uninstall = []
                for m in installed:
                    # Match by manifest ID
                    if m['id'] == args.module_id:
                        modules_to_uninstall.append(m)
                    # Also match by directory name (marketplace ID might differ)
                    elif m.get('directory_id') == args.module_id or os.path.basename(m.get('path', '')) == args.module_id:
                        modules_to_uninstall.append(m)
                
                if not modules_to_uninstall:
                    print_error(f"Module '{args.module_id}' is not installed")
                    print_info("Tip: Use 'market installed' to see installed extension IDs")
                    return False
                print_info("=" * 70)
                print_info("Uninstalling Module")
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
            
            # Uninstall each module using ExtensionClient if available
            success_count = 0
            for module in modules_to_uninstall:
                module_id = module['id']
                module_name = module['name']
                module_path = module['path']
                
                print_info(f"Uninstalling {module_id} ({module_name}, v{module['version']})...")
                
                try:
                    # Try using ExtensionClient for proper cleanup (removes launchers, stubs, etc.)
                    try:
                        from core.registry.client import ExtensionClient
                        client = ExtensionClient(registry_url=self.registry_url)
                        if client.remove_extension(module_id):
                            print_success(f"{module_id} uninstalled successfully")
                            success_count += 1
                            print_empty()
                            continue
                    except ImportError:
                        pass  # Fallback to manual removal
                    except Exception as e:
                        print_warning(f"ExtensionClient removal failed: {e}, trying manual removal...")
                    
                    # Manual fallback
                    import shutil
                    # Remove the module directory
                    if os.path.exists(module_path):
                        shutil.rmtree(module_path)
                        print_success(f"{module_id} uninstalled successfully")
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
                        print_warning(f"Module directory not found: {module_path}")
                        # Still count as success since it's already gone
                        success_count += 1
                        
                except Exception as e:
                    print_error(f"Failed to uninstall {module_name}: {e}")
                
                print_empty()
            
            print_info("=" * 70)
            if success_count == len(modules_to_uninstall):
                print_success(f"Uninstallation completed successfully! ({success_count}/{len(modules_to_uninstall)})")
            else:
                print_warning(f"Uninstallation completed with errors ({success_count}/{len(modules_to_uninstall)} successful)")
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
    
    def _get_installed_modules(self) -> List[Dict]:
        """Get list of installed modules from extensions/ directory using ExtensionClient"""
        installed = []
        
        # First, try using ExtensionClient to get extensions from extensions/ directory
        try:
            from core.registry.client import ExtensionClient
            client = ExtensionClient(registry_url=self.registry_url)
            extensions = client.list_installed_extensions()
            
            for ext in extensions:
                installed.append({
                    "id": ext.get("id", ""),
                    "name": ext.get("name", ""),
                    "version": ext.get("version", ""),
                    "type": ext.get("type", ""),
                    "path": ext.get("path", ""),
                    "module_type": "",  # Will be determined from type
                    "directory_id": ext.get("directory_id") or os.path.basename(ext.get("path", "")),  # Store directory name
                    "marketplace_id": ext.get("marketplace_id")  # Store marketplace ID for API lookups
                })
            
            # If we found extensions via ExtensionClient, return them (prioritize extensions/)
            if installed:
                return installed
        except ImportError:
            pass  # Fallback to manual search
        except Exception as e:
            logging.debug(f"Could not use ExtensionClient to list extensions: {e}")
        
        # Fallback: manual search in modules/marketplace/ and custom paths
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
            
            # Try to get marketplace IDs by searching for extensions
            marketplace_ids = {}
            try:
                from core.registry.client import ExtensionClient
                client = ExtensionClient(registry_url=self.registry_url)
                # Search for each installed extension to find marketplace ID
                for ext in installed:
                    # Try searching by name first
                    results = client.list_extensions(search=ext['name'], per_page=50)
                    if results and results.get('extensions'):
                        for marketplace_ext in results['extensions']:
                            # Match by manifest ID (extension_id field in marketplace might be the manifest ID)
                            # or by name and version
                            if (marketplace_ext.get('extension_id') == ext['id'] or 
                                (marketplace_ext.get('name') == ext['name'] and 
                                 marketplace_ext.get('version') == ext['version'])):
                                # Get the marketplace ID (usually the 'id' field in the API response)
                                marketplace_id = marketplace_ext.get('id') or marketplace_ext.get('extension_id')
                                if marketplace_id and str(marketplace_id) != ext['id']:
                                    marketplace_ids[ext['id']] = str(marketplace_id)
                                    break
            except Exception:
                pass  # Silently fail if we can't get marketplace IDs
            
            for ext in installed:
                print_info(f"{ext['id']} - {ext['name']}")
                print_info(f"   Type: {ext['type']}")
                print_info(f"   Version: {ext['version']}")
                print_info(f"   Path: {ext['path']}")
                
                # Show IDs that can be used for uninstallation
                uninstall_ids = [ext['id']]  # Always include manifest ID
                
                # Add marketplace ID if found
                marketplace_id = marketplace_ids.get(ext['id'])
                if marketplace_id and marketplace_id not in uninstall_ids:
                    uninstall_ids.append(marketplace_id)
                
                # Add directory_id if different
                if ext.get('directory_id') and ext.get('directory_id') != ext['id'] and ext.get('directory_id') not in uninstall_ids:
                    uninstall_ids.append(ext['directory_id'])
                
                # Display uninstall command
                if len(uninstall_ids) > 1:
                    print_info(f"   Uninstall: market uninstall {' or '.join(uninstall_ids)}")
                else:
                    print_info(f"   Uninstall: market uninstall {ext['id']}")
                print_empty()
            
            return True
            
        except Exception as e:
            print_error(f"Failed to list installed extensions: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _buy_module(self, args) -> bool:
        """Purchase a module from the marketplace"""
        if not self.token:
            print_error("Authentication required for purchasing")
            print_info("Please login first with: market login")
            return False
        
        try:
            # First get module info
            module_data = None
            
            # Method 1: Try direct endpoint (if it exists)
            module_data = self._make_request(f'market/modules/{args.module_id}', requires_auth=True, use_new_api=True)
            
            # Method 2: If direct endpoint fails, search in the modules list
            if not module_data:
                params = {'per_page': 100, 'page': 1}
                data = self._make_request('market/modules', params=params, requires_auth=True, use_new_api=True)
                
                if data and 'modules' in data:
                    modules = data.get('modules', [])
                    found = False
                    page = 1
                    while not found and page <= 10:
                        for module in modules:
                            if str(module.get('id')) == str(args.module_id):
                                module_data = module
                                found = True
                                break
                        
                        if not found:
                            pagination = data.get('pagination', {})
                            if pagination.get('has_next'):
                                page += 1
                                params['page'] = page
                                data = self._make_request('market/modules', params=params, requires_auth=True, use_new_api=True)
                                if data and 'modules' in data:
                                    modules = data.get('modules', [])
                                else:
                                    break
                            else:
                                break
            
            if not module_data:
                print_error(f"Module {args.module_id} not found")
                return False
            
            # Prefer the check endpoint to determine pricing/entitlements.
            # Some deployments may return a 200 with an error payload for direct module endpoints,
            # which can make missing fields look like "free" (price defaults to 0).
            check_data = self._make_request(f'market/check/{args.module_id}', requires_auth=True, use_new_api=True)
            
            module_name = module_data.get('name', 'Unknown')
            currency = module_data.get('currency', 'EUR')
            has_purchased = bool(module_data.get('has_purchased', False))
            can_download = bool(module_data.get('can_download', False))
            is_author = bool(module_data.get('is_author', False))
            is_free_flag = module_data.get('is_free') if isinstance(module_data, dict) else None
            
            price_raw = module_data.get('price', None)
            price_value = self._normalize_price(price_raw) if price_raw is not None else None
            requires_payment = False
            
            if isinstance(check_data, dict):
                module_name = check_data.get('module_name') or module_name
                currency = check_data.get('currency', currency)
                has_purchased = bool(check_data.get('has_purchased', has_purchased))
                can_download = bool(check_data.get('can_download', can_download))
                is_author = bool(check_data.get('is_author', is_author))
                requires_payment = bool(check_data.get('requires_payment', False))
                
                check_price = check_data.get('price', None)
                if check_price is not None:
                    price_raw = check_price
                    price_value = self._normalize_price(check_price)
            
            if has_purchased or can_download or is_author:
                print_info(f"You already own this module: {module_name}")
                print_info("You can install it with: market install " + args.module_id)
                return True
            
            is_free_determined = (is_free_flag is True) or (price_value is not None and price_value <= 0)
            if is_free_determined:
                print_info(f"This module is free: {module_name}")
                print_info("You can install it directly with: market install " + args.module_id)
                return True
            
            # If we still can't determine price, avoid assuming "free".
            if price_value is None and not requires_payment:
                print_error("Unable to determine module price from the marketplace response")
                print_info(f"Try: market info {args.module_id}")
                return False
            
            # Show purchase confirmation
            print_info("=" * 70)
            print_info("PURCHASE MODULE")
            print_info("=" * 70)
            print_empty()
            print_info(f"Module: {module_name}")
            print_info(f"ID: {args.module_id}")
            price_display = price_raw if isinstance(price_raw, (int, float, str)) else (price_value if price_value is not None else "N/A")
            print_info(f"Price: {price_display} {currency}")
            print_empty()
            
            confirm = input(f"Do you want to purchase this module for {price_display} {currency}? (yes/no): ").strip().lower()
            if confirm not in ['yes', 'y']:
                print_info("Purchase cancelled")
                return True
            
            # Make purchase request
            print_info("Processing purchase...")
            purchase_data = self._make_request(
                f'market/modules/{args.module_id}/purchase',
                method='POST',
                requires_auth=True,
                use_new_api=True
            )
            
            if not purchase_data:
                print_error("Purchase failed")
                return False
            
            # Stripe/checkout flow: prefer redirect URL when provided.
            checkout_url = purchase_data.get('checkout_url') or purchase_data.get('payment_url') or purchase_data.get('stripe_url')
            if checkout_url:
                print_success("Checkout created")
                print_info("Open this URL in your browser to pay:")
                print_info(f"   {checkout_url}")
                
                if purchase_data.get('message'):
                    print_info(f"   {purchase_data['message']}")
                
                # Wait for the server to confirm payment (e.g. Stripe redirect to /purchase/success)
                print_info("Waiting for payment confirmation...")
                if self._wait_for_purchase_confirmation(str(args.module_id), timeout_seconds=15 * 60, poll_interval_seconds=3):
                    print_success("Payment confirmed!")
                    print_info(f"You can now install the module with: market install {args.module_id}")
                    return True
                
                print_warning("Payment not confirmed yet (timeout).")
                print_info("If you already paid, try again:")
                print_info(f"  market install {args.module_id}")
                print_info(f"  market buy {args.module_id}")
                return False
            
            # If server confirms immediately (e.g. demo/test registry), accept success=true.
            if purchase_data.get('success'):
                print_success("Purchase successful!")
                print_info(f"You can now install the module with: market install {args.module_id}")
                return True
            error = purchase_data.get('error', 'Unknown error')
            print_error(f"Purchase failed: {error}")
            return False
                
        except Exception as e:
            print_error(f"Error purchasing module: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def _wait_for_purchase_confirmation(self, module_id: str, timeout_seconds: int = 900, poll_interval_seconds: int = 3) -> bool:
        """
        Poll the marketplace until the module becomes owned/can_download.
        This is used for Stripe-like flows where payment happens in a browser and
        the backend confirms asynchronously (e.g. /purchase/success redirect).
        """
        start = time.time()
        last_status_line_at = 0.0
        initial_token = self.token
        
        while time.time() - start < timeout_seconds:
            # If the token got cleared (401), we can't keep polling meaningfully.
            if initial_token and not self.token:
                print_warning("Your marketplace session expired during purchase confirmation.")
                print_info("Please run: market login")
                return False
            
            # 1) Preferred: check endpoint (cheap JSON).
            check_data = self._make_request(f'market/check/{module_id}', requires_auth=True, use_new_api=True)
            if isinstance(check_data, dict):
                if check_data.get('has_purchased') or check_data.get('can_download') or check_data.get('is_author'):
                    return True
                # Some deployments may return a direct download URL once payment is complete.
                if check_data.get('download_url') or (check_data.get('success') is True):
                    return True
            
            # 2) Fallback: module detail endpoint can reflect ownership sooner.
            module_data = self._make_request(f'market/modules/{module_id}', requires_auth=True, use_new_api=True)
            if isinstance(module_data, dict):
                if module_data.get('has_purchased') or module_data.get('can_download') or module_data.get('is_author'):
                    return True
            
            # 3) Last resort: probe download endpoint headers.
            # If it returns a bundle (non-JSON), access is granted => purchase confirmed.
            try:
                url = f"{self.registry_url}/api/cli/market/download/{module_id}"
                headers = {}
                if self.token:
                    headers['Authorization'] = f'Bearer {self.token}'
                elif self.api_key:
                    headers['X-API-Key'] = self.api_key
                
                resp = requests.get(url, headers=headers, stream=True, timeout=self.timeout)
                content_type = (resp.headers.get('content-type') or '').lower()
                
                if resp.status_code == 200:
                    if 'application/json' in content_type:
                        # Might be an error payload or a success payload; parse safely.
                        try:
                            payload = resp.json()
                            if payload.get('download_url') or payload.get('success') is True:
                                resp.close()
                                return True
                        except Exception:
                            pass
                    elif 'text/html' not in content_type:
                        # Likely a zip/kext stream => download authorized.
                        resp.close()
                        return True
                
                resp.close()
            except Exception:
                # Ignore transient network/probe failures; keep polling.
                pass
            
            # Print a lightweight status line about once per ~15 seconds
            now = time.time()
            if now - last_status_line_at >= 15:
                last_status_line_at = now
                remaining = int(timeout_seconds - (now - start))
                print_info(f"   still waiting... ({remaining}s left)")
            
            time.sleep(max(1, int(poll_interval_seconds)))
        
        return False
    
    def _extract_version_value(self, value):
        """Extract a version string from different payload shapes"""
        if not value:
            return None
        if isinstance(value, str):
            value = value.strip()
            return value or None
        if isinstance(value, dict):
            for key in ('version', 'number', 'name', 'tag', 'label'):
                ver = value.get(key)
                if isinstance(ver, str) and ver.strip():
                    return ver.strip()
            nested = value.get('data') or value.get('info')
            if isinstance(nested, dict):
                for key in ('version', 'number'):
                    ver = nested.get(key)
                    if isinstance(ver, str) and ver.strip():
                        return ver.strip()
        return None

    def _get_module_version(self, module: Dict) -> str:
        """Return the best-known version for a marketplace module"""
        if not module:
            return "N/A"
        
        direct_sources = [
            module.get('version'),
            module.get('latest_version'),
            module.get('current_version'),
            module.get('release_version'),
            module.get('module_version'),
        ]
        
        for source in direct_sources:
            version = self._extract_version_value(source)
            if version:
                return version
        
        for key in ('latest_release', 'latest_release_info', 'latest'):
            version = self._extract_version_value(module.get(key))
            if version:
                return version
        
        metadata = module.get('metadata') or module.get('manifest') or {}
        version = self._extract_version_value(metadata)
        if version:
            return version
        
        for key in ('versions', 'releases', 'release_history'):
            entries = module.get(key)
            if not isinstance(entries, list) or not entries:
                continue
            for entry in entries:
                if isinstance(entry, dict) and (entry.get('is_latest') or entry.get('latest') or entry.get('is_current') or entry.get('current')):
                    version = self._extract_version_value(entry)
                    if version:
                        return version
            first_entry = entries[0]
            if isinstance(first_entry, dict):
                version = self._extract_version_value(first_entry)
            else:
                version = self._extract_version_value({'version': first_entry})
            if version:
                return version
        
        return "N/A"

    def _normalize_price(self, value) -> float:
        """Convert various price representations to a float"""
        if value is None:
            return 0.0
        if isinstance(value, (int, float)):
            try:
                return float(value)
            except Exception:
                return 0.0
        if isinstance(value, str):
            cleaned = value.strip()
            if not cleaned:
                return 0.0
            # Remove common currency suffixes/prefixes
            for token in ['EUR', 'USD', '€', '$']:
                cleaned = cleaned.replace(token, '')
            cleaned = cleaned.strip().replace(',', '.')
            try:
                return float(cleaned)
            except Exception:
                return 0.0
        return 0.0

    def _display_modules_new_format(self, modules: List[Dict], title: str, pagination: Dict = None):
        """Display a list of modules in the new API format"""
        if not modules:
            print_info("No modules found")
            return
        
        print_info(f"{title}")
        print_info("=" * 80)
        print_empty()
        
        for idx, module in enumerate(modules, 1):
            module_id = module.get('id', 'N/A')
            name = module.get('name', 'Unknown')
            description = module.get('description', 'No description')
            author = module.get('author', {})
            if isinstance(author, dict):
                author_name = author.get('username', 'Unknown')
            else:
                author_name = str(author) if author else 'Unknown'
            
            price_raw = module.get('price', 0)
            price_value = self._normalize_price(price_raw)
            rating = module.get('rating', 0)
            rating_count = module.get('rating_count', 0)
            downloads = module.get('downloads', 0)
            module_type = module.get('type', 'Unknown')
            version = self._get_module_version(module)
            can_download = module.get('can_download', False)
            has_purchased = module.get('has_purchased', False)
            
            # Price display
            if price_value <= 0:
                price_text = "FREE"
            else:
                display_price = price_raw if isinstance(price_raw, (int, float, str)) else price_value
                price_text = f"{display_price}€"
                if has_purchased:
                    price_text += " (OWNED)"
                elif not can_download:
                    price_text += " (PURCHASE REQUIRED)"
            
            # Rating display
            if rating_count > 0:
                rating_text = f"{rating:.1f}/5.0 ({rating_count} reviews)"
            else:
                rating_text = "No ratings"
            
            # Wrap description to fit terminal width (80 chars)
            desc_lines = []
            words = description.split()
            current_line = ""
            for word in words:
                if len(current_line + word) > 72:  # Leave margin for indentation
                    if current_line:
                        desc_lines.append(current_line.strip())
                    current_line = word + " "
                else:
                    current_line += word + " "
            if current_line:
                desc_lines.append(current_line.strip())
            if not desc_lines:
                desc_lines = ["No description available"]
            
            # Display module in a card-like format
            print_info(f"[{idx}] {name} v{version}")
            print_info("-" * 80)
            print_info(f"  ID:          {module_id}")
            print_info(f"  Author:      {author_name}")
            print_info(f"  Type:        {module_type}")
            print_info(f"  Price:       {price_text}")
            print_info(f"  Downloads:   {downloads:,}" if downloads > 0 else f"  Downloads:   {downloads}")
            print_info(f"  Rating:      {rating_text}")
            print_info(f"  Description: {desc_lines[0]}")
            for line in desc_lines[1:]:
                print_info(f"               {line}")
            print_empty()
        
        # Display pagination info if available
        if pagination:
            page = pagination.get('page', 1)
            per_page = pagination.get('per_page', 20)
            total = pagination.get('total', 0)
            pages = pagination.get('pages', 1)
            has_next = pagination.get('has_next', False)
            has_prev = pagination.get('has_prev', False)
            
            print_info("=" * 80)
            print_info(f"Page {page} of {pages} (Total: {total} modules)")
            if has_prev:
                print_info("Use --page to navigate to previous pages")
            if has_next:
                print_info("Use --page to navigate to next pages")
            print_empty()
    
    def _display_module_details_new_format(self, module: Dict):
        """Display detailed module information in the new API format"""
        print_info("=" * 70)
        print_info(f"MODULE DETAILS")
        print_info("=" * 70)
        print_empty()
        
        # Basic info
        print_info(f"ID: {module.get('id', 'N/A')}")
        print_info(f"Name: {module.get('name', 'Unknown')}")
        version = self._get_module_version(module)
        print_info(f"Version: {version}")
        
        author = module.get('author', {})
        if isinstance(author, dict):
            author_name = author.get('username', 'Unknown')
        else:
            author_name = str(author) if author else 'Unknown'
        print_info(f"Author: {author_name}")
        
        price = module.get('price', 0)
        can_download = module.get('can_download', False)
        has_purchased = module.get('has_purchased', False)
        is_author = module.get('is_author', False)
        
        if price == 0:
            price_text = 'FREE'
        else:
            if has_purchased:
                price_text = f"{price}€ (OWNED)"
            elif is_author:
                price_text = f"{price}€ (YOUR MODULE)"
            elif can_download:
                price_text = f"{price}€ (AVAILABLE)"
            else:
                price_text = f"{price}€ (PURCHASE REQUIRED)"
        
        print_info(f"Price: {price_text}")
        print_info(f"Type: {module.get('type', 'Unknown')}")
        print_info(f"Compatibility: {module.get('compatibility', 'N/A')}")
        
        # Ratings
        rating = module.get('rating', 0)
        rating_count = module.get('rating_count', 0)
        if rating_count > 0:
            print_info(f"Rating: {rating:.1f}/5.0 ({rating_count} reviews)")
        else:
            print_info(f"Rating: No ratings yet")
        
        print_info(f"Downloads: {module.get('downloads', 0)}")
        print_empty()
        
        # Description
        print_info("Description:")
        description = module.get('description', 'No description available')
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
        
        # Images if available
        images = module.get('images', [])
        if images:
            print_info("Images:")
            for img in images:
                img_url = img.get('url', '')
                if img_url:
                    print_info(f"   {self.registry_url}{img_url}")
            print_empty()
        
        # Installation/Purchase instructions
        if can_download or has_purchased or is_author or price == 0:
            print_info("Installation:")
            print_info(f"   market install {module.get('id', 'N/A')}")
        else:
            print_info("Purchase Required:")
            print_info(f"   This module costs {price}€")
            print_info(f"   Use 'market buy {module.get('id', 'N/A')}' to purchase")
        
        # Dates
        created_at = module.get('created_at', '')
        updated_at = module.get('updated_at', '')
        if created_at:
            print_info(f"Created: {created_at}")
        if updated_at:
            print_info(f"Updated: {updated_at}")
        
        print_info("=" * 70)
    
    def _display_extensions(self, extensions: List[Dict], title: str):
        """Display a list of extensions"""
        if not extensions:
            print_info("No extensions found")
            return
        
        print_info(f"{title}")
        print_info("=" * 80)
        print_empty()
        
        for idx, ext in enumerate(extensions, 1):
            ext_id = ext.get('id', 'N/A')
            name = ext.get('name', 'Unknown')
            description = ext.get('description', 'No description')
            publisher = ext.get('publisher', {})
            if isinstance(publisher, dict):
                publisher_name = publisher.get('name', 'Unknown')
            else:
                publisher_name = str(publisher) if publisher else 'Unknown'
            
            price = ext.get('price', 0)
            currency = ext.get('currency', 'EUR')  # Default to EUR for new API
            # Determine if free: check is_free first, then price
            is_free = ext.get('is_free')
            if is_free is None:
                # If is_free is not provided, determine from price
                is_free = (price == 0 or price is None)
            else:
                # If is_free is provided, use it but also check price as fallback
                if not is_free and (price == 0 or price is None):
                    is_free = True  # Override if price is 0
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
            
            # Price display - use price if available, otherwise check is_free
            if price and price > 0:
                price_text = f"{price} {currency}"
            elif is_free:
                price_text = "FREE"
            else:
                # Fallback: if neither price nor is_free is clear, show as FREE to be safe
                price_text = "FREE"
            
            # Wrap description to fit terminal width (80 chars)
            desc_lines = []
            words = description.split()
            current_line = ""
            for word in words:
                if len(current_line + word) > 72:  # Leave margin for indentation
                    if current_line:
                        desc_lines.append(current_line.strip())
                    current_line = word + " "
                else:
                    current_line += word + " "
            if current_line:
                desc_lines.append(current_line.strip())
            if not desc_lines:
                desc_lines = ["No description available"]
            
            # Display extension in a card-like format
            print_info(f"[{idx}] {name} {version_text}")
            print_info("-" * 80)
            print_info(f"  ID:          {ext_id}")
            print_info(f"  Publisher:   {publisher_name}")
            print_info(f"  Type:        {ext_type}")
            print_info(f"  Price:       {price_text}")
            print_info(f"  Downloads:   {total_downloads:,}" if total_downloads > 0 else f"  Downloads:   {total_downloads}")
            print_info(f"  Description: {desc_lines[0]}")
            for line in desc_lines[1:]:
                print_info(f"               {line}")
            print_empty()
    
    def _display_extension_details(self, extension: Dict, extension_id: str = None):
        """Display detailed extension information"""
        print_info("=" * 70)
        print_info(f"EXTENSION DETAILS")
        print_info("=" * 70)
        print_empty()
        
        # Basic info
        print_info(f"ID: {extension.get('id', 'N/A')}")
        print_info(f"Name: {extension.get('name', 'Unknown')}")
        
        publisher = extension.get('publisher', {})
        if isinstance(publisher, dict):
            publisher_name = publisher.get('name', 'Unknown')
        else:
            publisher_name = str(publisher) if publisher else 'Unknown'
        print_info(f"Publisher: {publisher_name}")
        
        price = extension.get('price', 0)
        currency = extension.get('currency', 'EUR')  # Default to EUR for new API
        # Determine if free: check is_free first, then price
        is_free = extension.get('is_free')
        if is_free is None:
            # If is_free is not provided, determine from price
            is_free = (price == 0 or price is None)
        else:
            # If is_free is provided, use it but also check price as fallback
            if not is_free and (price == 0 or price is None):
                is_free = True  # Override if price is 0
        
        # Price display - use price if available, otherwise check is_free
        if price and price > 0:
            price_text = f"{price} {currency}"
        elif is_free:
            price_text = 'FREE'
        else:
            # Fallback: if neither price nor is_free is clear, show as FREE to be safe
            price_text = 'FREE'
        print_info(f"Price: {price_text}")
        print_info(f"Type: {extension.get('type', 'Unknown')}")
        print_info(f"License: {extension.get('license_type', 'N/A')}")
        
        # Calculate total downloads
        versions = extension.get('versions', [])
        total_downloads = sum(v.get('download_count', 0) for v in versions)
        print_info(f"Total Downloads: {total_downloads}")
        print_empty()
        
        # Description
        print_info("Description:")
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
            print_info("Available Versions:")
            for v in versions:
                latest = " (latest)" if v.get('is_latest') else ""
                print_info(f"   • {v.get('version')}{latest} - Downloads: {v.get('download_count', 0)}")
                print_info(f"     Compatible with KittySploit {v.get('kittysploit_min', '?')} - {v.get('kittysploit_max', '?')}")
            print_empty()
        
        # Installation instructions
        if is_free:
            print_info("Installation:")
            print_info(f"   market install {extension.get('id', 'N/A')}")
        else:
            print_info("Purchase Required:")
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
    
    def _install_from_local_path(self, module: Dict, local_path: str, version: str) -> bool:
        """Install extension from a local path (for local updates)"""
        try:
            import shutil
            from core.registry.client import ExtensionClient
            from core.registry.manifest import ManifestParser
            
            # Read manifest from local path
            manifest_path = os.path.join(local_path, "extension.toml")
            if not os.path.exists(manifest_path):
                print_error(f"Manifest not found at {manifest_path}")
                return False
            
            manifest = ManifestParser.parse(manifest_path)
            if not manifest:
                print_error("Failed to parse manifest")
                return False
            
            # Get extensions directory
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
            
            # Determine target path structure
            # Try to preserve marketplace_id if available
            module_path = module.get('path', '')
            marketplace_id = None
            
            # Extract marketplace_id from current path if possible
            if module_path:
                parts = module_path.split(os.sep)
                if 'extensions' in parts:
                    ext_idx = parts.index('extensions')
                    if ext_idx + 1 < len(parts):
                        potential_marketplace_id = parts[ext_idx + 1]
                        # Check if it's numeric (marketplace ID) or the extension ID
                        if potential_marketplace_id.isdigit() or potential_marketplace_id != manifest.id:
                            marketplace_id = potential_marketplace_id
            
            # If no marketplace_id found, use a default or the extension ID
            if not marketplace_id:
                # Try to find existing marketplace_id by scanning extensions directory
                if os.path.exists(extensions_dir):
                    for item in os.listdir(extensions_dir):
                        item_path = os.path.join(extensions_dir, item)
                        if os.path.isdir(item_path):
                            # Check if this directory contains our extension
                            for subitem in os.listdir(item_path):
                                subitem_path = os.path.join(item_path, subitem)
                                if os.path.isdir(subitem_path):
                                    check_manifest = os.path.join(subitem_path, "extension.toml")
                                    if not os.path.exists(check_manifest):
                                        # Check in latest/ subdirectory
                                        check_manifest = os.path.join(subitem_path, "latest", "extension.toml")
                                    if os.path.exists(check_manifest):
                                        check_manifest_obj = ManifestParser.parse(check_manifest)
                                        if check_manifest_obj and check_manifest_obj.id == manifest.id:
                                            marketplace_id = item
                                            break
                            if marketplace_id:
                                break
            
            # If still no marketplace_id, use extension ID as fallback
            if not marketplace_id:
                marketplace_id = manifest.id
            
            # Create target directory: extensions/{marketplace_id}/{manifest_id}/latest/
            target_dir = os.path.join(extensions_dir, marketplace_id, manifest.id, "latest")
            os.makedirs(target_dir, exist_ok=True)
            
            # Copy all files from local_path to target_dir
            print_info(f"Copying extension files to {target_dir}...")
            for item in os.listdir(local_path):
                src = os.path.join(local_path, item)
                dst = os.path.join(target_dir, item)
                
                if os.path.isdir(src):
                    if os.path.exists(dst):
                        shutil.rmtree(dst)
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)
            
            # Use ExtensionClient to create stubs/launchers
            client = ExtensionClient(registry_url=self.registry_url)
            stub_created = client._create_stub_files(manifest, target_dir, "latest", marketplace_id=marketplace_id)
            
            if stub_created:
                print_success(f"Extension '{manifest.name}' v{version} installed from local path")
                return True
            else:
                print_warning("Stubs/launchers may not have been created correctly")
                return True  # Still consider it successful if files were copied
                
        except Exception as e:
            print_error(f"Failed to install from local path: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _download_and_install_extension(self, extension_id: str, extension_data: Dict) -> bool:
        """Download and install an extension using ExtensionClient"""
        try:
            from core.registry.client import ExtensionClient
            
            module_name = extension_data.get('name', 'Unknown')
            
            print_info(f"Installing extension '{module_name}' (ID: {extension_id})...")
            
            # Use ExtensionClient for proper installation (handles UI, modules, plugins correctly)
            client = ExtensionClient(registry_url=self.registry_url)
            
            # Install using ExtensionClient (handles extensions/ directory and launchers)
            success = client.install_extension(
                extension_id=extension_id,
                version=None,  # Use latest
                user_id=None,
                verify_signature=True
            )
            
            if success:
                print_success(f"Extension '{module_name}' (ID: {extension_id}) installed successfully!")
                return True
            else:
                print_error(f"Failed to install extension '{module_name}' (ID: {extension_id})")
                return False
                
        except ImportError:
            # Fallback to manual installation if ExtensionClient not available
            print_warning("ExtensionClient not available, using manual installation")
            return self._download_and_install_extension_manual(extension_id, extension_data)
        except Exception as e:
            print_error(f"Error installing extension: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _download_and_install_extension_manual(self, extension_id: str, extension_data: Dict) -> bool:
        """Manual installation fallback (old method)"""
        import tempfile
        import zipfile
        import shutil
        
        try:
            module_name = extension_data.get('name', 'Unknown')
            
            print_info(f"Downloading module '{module_name}'...")
            
            # Download extension bundle - use correct endpoint
            url = f"{self.registry_url}/api/cli/market/download/{extension_id}"
            headers = {}
            if self.token:
                headers['Authorization'] = f'Bearer {self.token}'
            elif self.api_key:
                headers['X-API-Key'] = self.api_key
            
            response = requests.get(url, headers=headers, stream=True, timeout=self.timeout)
            
            # Check if response is JSON (payment required or error)
            content_type = response.headers.get('content-type', '')
            if 'application/json' in content_type:
                try:
                    error_data = response.json()
                    # Check if it's a payment required response with Stripe checkout URL
                    if error_data.get('requires_payment') or error_data.get('checkout_url'):
                        checkout_url = error_data.get('checkout_url') or error_data.get('purchase_url')
                        price = error_data.get('price', extension_data.get('price', 0))
                        module_name = error_data.get('module_name', extension_data.get('name', 'Unknown'))
                        print_error(f"Module '{module_name}' requires purchase ({price}€)")
                        if checkout_url:
                            print_info(f"Checkout URL: {checkout_url}")
                        else:
                            purchase_url = f"{self.registry_url}/market/modules/{extension_id}/purchase"
                            print_info(f"Purchase URL: {purchase_url}")
                        print_info(f"Or use: market buy {extension_id}")
                        return False
                    else:
                        error_msg = error_data.get('error', 'Download failed')
                        print_error(f"Download failed: {error_msg}")
                        return False
                except:
                    print_error("Download failed: Invalid response from server")
                    return False
            
            # Check if response is HTML (error page)
            if 'text/html' in content_type:
                # Likely an error page, check if module is paid
                price = extension_data.get('price', 0)
                can_download = extension_data.get('can_download', False)
                has_purchased = extension_data.get('has_purchased', False)
                is_author = extension_data.get('is_author', False)
                
                if price > 0 and not can_download and not has_purchased and not is_author:
                    print_error(f"Module '{extension_data.get('name', 'Unknown')}' requires purchase ({price}€)")
                    purchase_url = f"{self.registry_url}/market/modules/{extension_id}/purchase"
                    print_info(f"Purchase URL: {purchase_url}")
                    print_info(f"Or use: market buy {extension_id}")
                    return False
                else:
                    print_error("Download failed: Invalid response from server")
                    return False
            
            # If 404, try alternative endpoint
            if response.status_code == 404:
                url = f"{self.registry_url}/market/download/{extension_id}"
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
            
            print_info(f"Extracting module bundle...")
            
            # Sanity-check the downloaded bundle before attempting extraction.
            # Some registry deployments may return an empty ZIP placeholder (e.g. 22-byte EOCD record)
            # when the module bundle is missing server-side.
            try:
                bundle_size = os.path.getsize(tmp_path)
            except Exception:
                bundle_size = None
            
            try:
                # Quick magic-byte check
                with open(tmp_path, 'rb') as f:
                    first_bytes = f.read(8)
            except Exception:
                first_bytes = b''
            
            if bundle_size is not None and bundle_size <= 32:
                print_error("Downloaded bundle is unexpectedly small.")
                print_info(f"   Size: {bundle_size} bytes")
                print_info("   This usually means the registry returned an empty placeholder instead of the real module bundle.")
                print_info("   Server-side action: verify the module has a valid uploaded .kext/.zip artifact and the download endpoint serves it.")
                os.remove(tmp_path)
                return False
            
            # If it's a ZIP, ensure it contains files (manifest + code) before continuing
            try:
                if zipfile.is_zipfile(tmp_path):
                    with zipfile.ZipFile(tmp_path, 'r') as zf:
                        names = zf.namelist()
                        if not names:
                            print_error("Downloaded bundle is an empty ZIP archive (no files).")
                            if bundle_size is not None:
                                print_info(f"   Size: {bundle_size} bytes")
                            print_info("   Server-side action: the registry must return the actual module bundle, not an empty ZIP placeholder.")
                            os.remove(tmp_path)
                            return False
            except Exception:
                # If this fails, extraction below will handle it.
                pass
            
            # Determine module type from manifest (will be read after extraction)
            # For now, extract to a temp location to read manifest first
            temp_extract_dir = tempfile.mkdtemp()
            
            # Extract the bundle temporarily to read manifest
            try:
                with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_extract_dir)
            except zipfile.BadZipFile:
                # Check if this might be a paid module issue
                price = extension_data.get('price', 0)
                can_download = extension_data.get('can_download', False)
                has_purchased = extension_data.get('has_purchased', False)
                is_author = extension_data.get('is_author', False)
                
                if price > 0 and not can_download and not has_purchased and not is_author:
                    print_error(f"Module '{extension_data.get('name', 'Unknown')}' requires purchase ({price}€)")
                    purchase_url = f"{self.registry_url}/market/modules/{extension_id}/purchase"
                    print_info(f"Purchase URL: {purchase_url}")
                    print_info(f"Or use: market buy {extension_id}")
                else:
                    # Provide better diagnostics (common: HTML/text error pages or empty placeholders)
                    size_hint = ""
                    try:
                        size_hint = f" (size: {os.path.getsize(tmp_path)} bytes)"
                    except Exception:
                        pass
                    print_error(f"Invalid bundle format (not a valid ZIP file){size_hint}")
                    if first_bytes:
                        try:
                            import binascii
                            print_info(f"   First bytes: {binascii.hexlify(first_bytes).decode()}")
                        except Exception:
                            pass
                
                os.remove(tmp_path)
                shutil.rmtree(temp_extract_dir, ignore_errors=True)
                return False
            
            # Read manifest to get install_path and module type
            manifest_path = os.path.join(temp_extract_dir, "extension.toml")
            module_type = "auxiliary"  # default
            install_path = None
            install_mode = None
            stub_specs = []
            stub_version_dir = "latest"
            on_conflict = "fail"
            
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
                        install_cfg = manifest.get('install', {}) if isinstance(manifest, dict) else {}
                        if isinstance(install_cfg, dict):
                            install_mode = install_cfg.get('mode')
                            stub_version_dir = install_cfg.get('version_dir', stub_version_dir) or stub_version_dir
                            on_conflict = install_cfg.get('on_conflict', on_conflict) or on_conflict
                            stub_specs = install_cfg.get('stubs', []) or []
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
            
            stubs_requested = isinstance(stub_specs, list) and len(stub_specs) > 0
            
            # Determine extract directory
            if stubs_requested or (isinstance(install_mode, str) and install_mode.strip().lower() == "isolated"):
                # Install into extensions directory (isolated), then generate stubs into modules/plugins.
                safe_ver = str(stub_version_dir or "latest").replace("\\", "/").strip().strip("/")
                if not safe_ver or ".." in safe_ver or os.path.isabs(safe_ver):
                    safe_ver = "latest"
                
                extract_dir = os.path.join(extensions_dir, extension_id, safe_ver)
                print_info(f"Installing to: {extract_dir} (isolated extension)")
            elif install_path:
                # Validate install_path security
                normalized_path = install_path.replace("\\", "/").strip()
                
                # Security checks
                if not (normalized_path.startswith("modules/") or normalized_path.startswith("plugins/")):
                    print_error(f"Security: install_path must start with 'modules/' or 'plugins/'")
                    print_error(f"   Received: {install_path}")
                    shutil.rmtree(temp_extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                if ".." in normalized_path:
                    print_error(f"Security: install_path cannot contain '..' (path traversal attempt)")
                    print_error(f"   Received: {install_path}")
                    shutil.rmtree(temp_extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                if os.path.isabs(normalized_path):
                    print_error(f"Security: install_path must be a relative path")
                    print_error(f"   Received: {install_path}")
                    shutil.rmtree(temp_extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                # Use install_path from manifest (relative to framework root)
                extract_dir = normalized_path
                print_info(f"Installing to: {extract_dir} (from manifest)")
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
                
                print_info(f"Installing to: {extract_dir} (default location)")
            
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
                print_error("Manifest extension.toml not found in bundle")
                shutil.rmtree(extract_dir, ignore_errors=True)
                os.remove(tmp_path)
                return False
            
            # Parse and validate manifest
            try:
                from core.registry.manifest import ManifestParser
                manifest = ManifestParser.parse(manifest_path)
                if not manifest:
                    print_error("Failed to parse manifest")
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                # Validate manifest
                is_valid, errors = ManifestParser.validate(manifest)
                if not is_valid:
                    print_error(f"Invalid manifest: {', '.join(errors)}")
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                # Validate extension type (category)
                valid_types = ['module', 'plugin', 'UI', 'middleware']
                extension_type = manifest.extension_type.value if hasattr(manifest.extension_type, 'value') else str(manifest.extension_type)
                if extension_type not in valid_types:
                    print_error(f"Invalid extension type: {extension_type}")
                    print_error(f"   Valid types are: {', '.join(valid_types)}")
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
                
                first_use_hint = None
                # Generate stub modules if requested
                if stubs_requested:
                    try:
                        from core.registry.packaging import generate_python_stub_module
                    except Exception as e:
                        print_error(f"Stub generation unavailable: {e}")
                        os.remove(tmp_path)
                        return False
                    
                    if on_conflict not in ("fail", "overwrite", "skip"):
                        on_conflict = "fail"
                    
                    created = 0
                    for spec in stub_specs:
                        if not isinstance(spec, dict):
                            continue
                        target = spec.get("to") or spec.get("target")
                        entry = spec.get("entry") or spec.get("from")
                        export_symbol = spec.get("export", "Module")
                        if not target or not entry:
                            continue
                        
                        # Security: only allow writing stubs into modules/ or plugins/
                        target_norm = str(target).replace("\\", "/").strip()
                        if ".." in target_norm or os.path.isabs(target_norm):
                            print_error(f"Security: invalid stub target path: {target}")
                            continue
                        if not (target_norm.startswith("modules/") or target_norm.startswith("plugins/")):
                            print_error(f"Security: stub target must be under modules/ or plugins/: {target}")
                            continue
                        
                        entry_rel = str(entry).replace("\\", "/").lstrip("/")
                        stub_code = generate_python_stub_module(
                            extension_id=str(extension_id),
                            entry_rel_path=entry_rel,
                            export_symbol=str(export_symbol or "Module"),
                            version_dir=str(stub_version_dir or "latest"),
                        )
                        
                        target_abs = os.path.join(target_norm)
                        os.makedirs(os.path.dirname(target_abs) or ".", exist_ok=True)
                        
                        if os.path.exists(target_abs):
                            if on_conflict == "skip":
                                continue
                            if on_conflict == "fail":
                                print_error(f"Stub target already exists: {target_norm}")
                                print_info("   Set install.on_conflict = \"overwrite\" or \"skip\" in extension.toml")
                                continue
                        
                        with open(target_abs, "w", encoding="utf-8") as f:
                            f.write(stub_code)
                        
                        created += 1
                        
                        if not first_use_hint and target_norm.startswith("modules/"):
                            rel = target_norm[len("modules/"):]
                            if rel.endswith(".py"):
                                rel = rel[:-3]
                            first_use_hint = rel
                    
                    if created > 0:
                        print_success(f"Generated {created} stub module(s)")
                    else:
                        print_warning("install.stubs was present but no stubs were generated (check your extension.toml).")
                
                print_success(f"Module '{module_name}' installed successfully!")
                print_info(f"   Installed to: {extract_dir}")
                print_info(f"   Type: {extension_type}")
                print_info(f"   Version: {manifest.version}")
                print_info(f"   Use 'market installed' to see installed modules")
                
                # Determine the correct use path
                if first_use_hint:
                    use_path = first_use_hint
                elif install_path:
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
                print_warning("Could not validate manifest (registry module not available)")
                print_success(f"Module '{module_name}' extracted to: {extract_dir}")
            except Exception as e:
                print_warning(f"Could not fully validate module: {e}")
                print_success(f"Module '{module_name}' extracted to: {extract_dir}")
            
            # Clean up temporary bundle file
            try:
                os.remove(tmp_path)
            except:
                pass
            
            return True
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print_error("Unauthorized - please login or register")
            else:
                print_error(f"Failed to download extension: {e.response.status_code}")
            return False
        except Exception as e:
            print_error(f"Failed to install extension: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

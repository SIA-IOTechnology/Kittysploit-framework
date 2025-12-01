#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Default Password Plugin for KittySploit
Search for default credentials in routers and devices
"""

from kittysploit import *
import shlex
import re
import os
import json
from typing import List, Dict, Optional

class DefaultPasswordPlugin(Plugin):
    """Plugin to search for default passwords in routers and devices"""

    __info__ = {
        "name": "default_password",
        "description": "Search for default credentials in routers and devices database",
        "version": "1.0.0",
        "author": "KittySploit Team",
        "dependencies": []
    }

    def __init__(self, framework=None):
        super().__init__(framework)
        self.json_path = os.path.join("data", "default_password.json")

    def _load_database(self) -> Dict[str, Dict]:
        """Load JSON database from file"""
        try:
            if not os.path.exists(self.json_path):
                print_error(f"Database file not found: {self.json_path}")
                return {}
            
            with open(self.json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Handle nested structure with "_default" key
                if "_default" in data and isinstance(data["_default"], dict):
                    return data["_default"]
                # If no "_default" key, assume flat structure
                return data
        except Exception as e:
            print_error(f"Failed to load database: {e}")
            return {}

    def _search_by_vendor(self, search_term: str) -> List[Dict]:
        """Search credentials by product/vendor name"""
        data = self._load_database()
        if not data:
            return []
        
        results = []
        # Normalize search term: remove hyphens and convert to lowercase for better matching
        search_normalized = search_term.lower().replace('-', '').replace('_', '').replace(' ', '')
        
        for key, entry in data.items():
            vendor = entry.get('productvendor', '')
            if not vendor:
                continue
            # Normalize vendor name for comparison
            vendor_normalized = vendor.lower().replace('-', '').replace('_', '').replace(' ', '')
            # Check both exact match and substring match
            if search_normalized in vendor_normalized or search_term.lower() in vendor.lower():
                results.append({
                    'productvendor': entry.get('productvendor', ''),
                    'username': entry.get('username', ''),
                    'password': entry.get('password', '')
                })
        
        return results

    def _search_by_username(self, search_term: str) -> List[Dict]:
        """Search credentials by username"""
        data = self._load_database()
        if not data:
            return []
        
        results = []
        search_lower = search_term.lower()
        
        for key, entry in data.items():
            username = entry.get('username', '').lower()
            if search_lower in username:
                results.append({
                    'productvendor': entry.get('productvendor', ''),
                    'username': entry.get('username', ''),
                    'password': entry.get('password', '')
                })
        
        return results

    def _search_by_password(self, search_term: str) -> List[Dict]:
        """Search credentials by password"""
        data = self._load_database()
        if not data:
            return []
        
        results = []
        search_lower = search_term.lower()
        
        for key, entry in data.items():
            password = entry.get('password', '').lower()
            if search_lower in password:
                results.append({
                    'productvendor': entry.get('productvendor', ''),
                    'username': entry.get('username', ''),
                    'password': entry.get('password', '')
                })
        
        return results

    def _search_all_fields(self, search_term: str) -> List[Dict]:
        """Search in all fields (vendor, username, password)"""
        data = self._load_database()
        if not data:
            return []
        
        results = []
        seen = set()
        search_lower = search_term.lower()
        # Normalize search term: remove hyphens for better matching
        search_normalized = search_lower.replace('-', '').replace('_', '').replace(' ', '')
        
        for key, entry in data.items():
            vendor = entry.get('productvendor', '')
            username = entry.get('username', '').lower()
            password = entry.get('password', '').lower()
            
            # Normalize vendor for comparison
            vendor_normalized = vendor.lower().replace('-', '').replace('_', '').replace(' ', '') if vendor else ''
            
            # Check in all fields with normalized comparison
            if (search_normalized in vendor_normalized or 
                search_lower in vendor.lower() or
                search_lower in username or 
                search_lower in password):
                
                # Deduplicate using a tuple key
                result_key = (
                    entry.get('productvendor', ''),
                    entry.get('username', ''),
                    entry.get('password', '')
                )
                
                if result_key not in seen:
                    seen.add(result_key)
                    results.append({
                        'productvendor': entry.get('productvendor', ''),
                        'username': entry.get('username', ''),
                        'password': entry.get('password', '')
                    })
        
        return results

    def _display_results(self, results: List[Dict], search_term: Optional[str] = None):
        """Display search results in a formatted table"""
        if not results:
            if search_term:
                print_warning(f"No credentials found for '{search_term}'")
            else:
                print_warning("No credentials found")
            return
        
        # Format results for table display
        creds_found = []
        for result in results:
            creds_found.append([
                result.get("productvendor", "N/A"),
                result.get("username", "N/A"),
                result.get("password", "N/A")
            ])
        
        headers = ["Product/Vendor", "Username", "Password"]
        print_info("")
        print_table(headers, creds_found)
        print_info("")
        print_success(f"Found {len(creds_found)} credential(s)")

    def _count_total(self) -> int:
        """Count total number of entries in database"""
        data = self._load_database()
        # Count actual entries, not the "_default" wrapper
        if isinstance(data, dict):
            return len(data)
        return 0

    def run(self, *args, **kwargs):
        """Main execution method for the plugin"""
        
        parser = ModuleArgumentParser(
            description="Search for default credentials in routers and devices database",
            prog="default_password"
        )
        parser.add_argument("-s", "--search", dest="search", help="Search term (searches in product/vendor, username, and password)", type=str)
        parser.add_argument("-v", "--vendor", dest="vendor", help="Search only in product/vendor name", type=str)
        parser.add_argument("-u", "--username", dest="username", help="Search only in username", type=str)
        parser.add_argument("-p", "--password", dest="password", help="Search only in password", type=str)
        parser.add_argument("-c", "--count", dest="count", action="store_true", help="Show total number of entries in database")
        
        if not args or not args[0]:
            parser.print_help()
            print_info("")
            print_info(f"Database location: {self.json_path}")
            print_info(f"Total entries: {self._count_total()}")
            return True
        
        try:
            pargs = parser.parse_args(shlex.split(args[0]))
            
            if hasattr(pargs, 'help') and pargs.help:
                parser.print_help()
                return True
            
            # Count option
            if pargs.count:
                total = self._count_total()
                print_success(f"Total entries in database: {total}")
                return True
            
            # Determine search type and term
            search_term = None
            search_type = None
            
            if pargs.vendor:
                search_term = pargs.vendor
                search_type = "vendor"
            elif pargs.username:
                search_term = pargs.username
                search_type = "username"
            elif pargs.password:
                search_term = pargs.password
                search_type = "password"
            elif pargs.search:
                search_term = pargs.search
                search_type = "all"
            else:
                parser.print_help()
                return True
            
            if not search_term:
                print_error("Please provide a search term")
                parser.print_help()
                return False
            
            # Perform search based on type
            results = []
            if search_type == "vendor":
                results = self._search_by_vendor(search_term)
            elif search_type == "username":
                results = self._search_by_username(search_term)
            elif search_type == "password":
                results = self._search_by_password(search_term)
            elif search_type == "all":
                results = self._search_all_fields(search_term)
            
            # Display results
            self._display_results(results, search_term)
            return True
            
        except Exception as e:
            print_error(f"Error executing plugin: {e}")
            import traceback
            if is_debug_mode():
                traceback.print_exc()
            return False

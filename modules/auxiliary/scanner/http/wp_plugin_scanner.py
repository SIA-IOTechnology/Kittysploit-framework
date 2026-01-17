#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'WordPress Plugin Scanner',
        'description': 'Scans for WordPress plugins, their versions, and known vulnerabilities',
        'author': 'KittySploit Team',
        'tags': ['web', 'wordpress', 'plugin', 'scanner', 'security', 'cms'],
        'references': [
            'https://wpscan.com/',
            'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=wordpress+plugin',
            'https://wordpress.org/plugins/',
        ]
    }

    # Common WordPress plugins to check
    COMMON_PLUGINS = [
        'akismet',
        'contact-form-7',
        'yoast-seo',
        'wordfence',
        'all-in-one-wp-migration',
        'elementor',
        'woocommerce',
        'jetpack',
        'wp-super-cache',
        'really-simple-captcha',
        'wp-file-manager',
        'advanced-custom-fields',
        'duplicate-post',
        'updraftplus',
        'wp-mail-smtp',
    ]

    # Plugin paths to check
    PLUGIN_PATHS = [
        '/wp-content/plugins/',
        '/wp-content/plugins/{plugin}/',
        '/wp-content/plugins/{plugin}/readme.txt',
        '/wp-content/plugins/{plugin}/changelog.txt',
        '/wp-content/plugins/{plugin}/{plugin}.php',
    ]

    def check(self):
        """
        Check if the target is accessible and running WordPress
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for WordPress indicators
                content = response.text.lower()
                if 'wordpress' in content or 'wp-content' in content or 'wp-includes' in content:
                    return True
                # Check for WordPress paths
                test_response = self.http_request(method="GET", path="/wp-login.php")
                if test_response and test_response.status_code in [200, 301, 302, 403]:
                    return True
                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_plugin(self, plugin_name):
        """
        Detect if a plugin is installed and get its version
        
        Args:
            plugin_name: Name of the plugin to check
            
        Returns:
            dict: Plugin information or None
        """
        try:
            # Check plugin directory
            plugin_path = f"/wp-content/plugins/{plugin_name}/"
            response = self.http_request(method="GET", path=plugin_path, allow_redirects=False)
            
            if response and response.status_code in [200, 301, 302, 403]:
                # Try to get version from readme.txt
                readme_path = f"/wp-content/plugins/{plugin_name}/readme.txt"
                readme_response = self.http_request(method="GET", path=readme_path, allow_redirects=False)
                
                version = None
                if readme_response and readme_response.status_code == 200:
                    # Extract version from readme.txt
                    version_match = re.search(r'Stable tag:\s*([\d\.]+)', readme_response.text, re.IGNORECASE)
                    if version_match:
                        version = version_match.group(1)
                
                # Try main plugin file
                plugin_file = f"/wp-content/plugins/{plugin_name}/{plugin_name}.php"
                plugin_response = self.http_request(method="GET", path=plugin_file, allow_redirects=False)
                
                if plugin_response and plugin_response.status_code == 200:
                    # Extract version from plugin file
                    if not version:
                        version_match = re.search(r'Version:\s*([\d\.]+)', plugin_response.text, re.IGNORECASE)
                        if version_match:
                            version = version_match.group(1)
                
                return {
                    'name': plugin_name,
                    'installed': True,
                    'version': version,
                    'path': plugin_path
                }
            
            return None
        except Exception as e:
            print_debug(f"Error detecting plugin {plugin_name}: {str(e)}")
            return None

    def discover_plugins_from_source(self):
        """
        Discover plugins from HTML source code
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return []
            
            discovered = []
            content = response.text
            
            # Look for plugin references in HTML
            plugin_patterns = [
                r'wp-content/plugins/([^/"]+)',
                r'plugins/([^/"]+)/',
                r'plugin["\']?\s*:\s*["\']([^"\']+)',
            ]
            
            for pattern in plugin_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    plugin_name = match.strip('/').lower()
                    if plugin_name and plugin_name not in [p['name'] for p in discovered]:
                        discovered.append({
                            'name': plugin_name,
                            'source': 'HTML source',
                            'installed': True
                        })
            
            return discovered
        except Exception as e:
            return []

    def run(self):
        """
        Execute the WordPress plugin scan
        """
        self.discovered_plugins = []
        self.plugin_info = []
        
        print_status("Starting WordPress plugin scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Discover plugins from source
        print_status("Discovering plugins from HTML source...")
        source_plugins = self.discover_plugins_from_source()
        if source_plugins:
            print_success(f"Found {len(source_plugins)} plugins in HTML source")
            for plugin in source_plugins:
                print_info(f"  - {plugin['name']}")
        print_info("")
        
        # Check common plugins
        print_status("Checking for common WordPress plugins...")
        print_info("")
        
        all_plugins = list(set([p['name'] for p in source_plugins] + self.COMMON_PLUGINS))
        
        for plugin_name in all_plugins[:20]:  # Check first 20 plugins
            print_info(f"Checking plugin: {plugin_name}")
            plugin_info = self.detect_plugin(plugin_name)
            
            if plugin_info:
                self.plugin_info.append(plugin_info)
                print_success(f"  [!] Plugin found: {plugin_name}")
                if plugin_info.get('version'):
                    print_info(f"      Version: {plugin_info['version']}")
                else:
                    print_warning("      Version: Not detected")
            else:
                print_debug(f"  Plugin not found: {plugin_name}")
        
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("WordPress Plugin Scan Summary")
        print_status("=" * 60)
        
        print_info(f"Plugins discovered from source: {len(source_plugins)}")
        print_info(f"Plugins confirmed installed: {len(self.plugin_info)}")
        print_status("=" * 60)
        print_info("")
        
        if self.plugin_info:
            print_success("Installed plugins:")
            print_info("")
            
            table_data = []
            for plugin in self.plugin_info:
                version = plugin.get('version', 'Unknown')
                table_data.append([
                    plugin['name'],
                    version,
                    plugin.get('path', 'N/A')
                ])
            
            print_table(['Plugin Name', 'Version', 'Path'], table_data)
            print_info("")
            print_info("Note: Check for known vulnerabilities in these plugins using tools like WPScan.")
        else:
            print_info("No WordPress plugins detected.")
            print_info("Note: Plugins may be hidden or not in the common list.")
        
        return True

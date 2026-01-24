#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner - Base class for simple remote vulnerability scanning modules
Similar to OpenVAS, these modules perform simple version checks and response tests
"""

from core.framework.base_module import BaseModule
from core.framework.failure import ProcedureError, FailureType
from core.output_handler import print_info, print_success, print_error, print_warning
from typing import Optional


class Scanner(BaseModule):
    """
    Base class for scanner modules.
    
    These modules are designed to be very simple and focused:
    - Version detection
    - Response pattern matching
    - Simple vulnerability checks
    - No exploitation, only detection
    
    Similar to OpenVAS plugins - lightweight and fast.
    """
    
    TYPE_MODULE = "scanner"

    def __init__(self, framework=None):
        super().__init__(framework)
        self.vulnerable = False
        self.vulnerability_info = {}  # Pour les infos dynamiques uniquement
    
    def extract_version(self, text: str, pattern: str) -> str:
        """Helper to extract version from text using regex pattern"""
        import re
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1) if match else ""
    
    def set_info(self, **details):
        """
        Set dynamic vulnerability information (optional).
        
        Use this only for dynamic data (detected version, etc.).
        Static info should be in __info__.
        
        Args:
            **details: Dynamic details to store (version, cves, etc.)
        """
        self.vulnerability_info.update(details)
    
    def _get_detector(self, name: str):
        """
        Charge dynamiquement un détecteur depuis les modules organisés.
        
        Découvre automatiquement les détecteurs disponibles dans:
        - lib.scanner.http.detectors
        - lib.scanner.ftp.detectors
        - lib.scanner.ssh.detectors
        - lib.scanner.router.detectors
        - etc.
        
        Pattern: if_<name> -> detect_<name> dans le bon module
        """
        # Cache des détecteurs chargés pour éviter les re-imports
        if not hasattr(self, '_detector_cache'):
            self._detector_cache = {}
        
        if name in self._detector_cache:
            return self._detector_cache[name]
        
        # Liste des protocoles à chercher (dans l'ordre de priorité)
        protocols = ['http', 'ftp', 'ssh', 'router', 'smtp', 'dns', 'ldap']  # Extensible
        
        # Extraire le nom du détecteur (enlever le préfixe "if_")
        if name.startswith('if_'):
            detector_name = name[3:]  # Enlever "if_"
            func_name = f"detect_{detector_name}"
        else:
            # Fonctions utilitaires (contains_pattern, has_header, etc.)
            detector_name = name
            func_name = name
        
        # Chercher dans chaque protocole
        for protocol in protocols:
            try:
                module_path = f"lib.scanner.{protocol}.detectors"
                module = __import__(module_path, fromlist=[func_name])
                
                if hasattr(module, func_name):
                    detector_func = getattr(module, func_name)
                    
                    # Créer un wrapper pour préserver la signature
                    def detector_wrapper(*args, **kwargs):
                        return detector_func(*args, **kwargs)
                    
                    # Mettre en cache
                    self._detector_cache[name] = detector_wrapper
                    return detector_wrapper
                    
            except (ImportError, AttributeError):
                continue
        
        # Si pas trouvé, retourner une fonction par défaut
        # Déterminer le type de retour selon le nom
        if name.startswith('if_'):
            # Les détecteurs de version retournent None, les booléens False
            # On peut deviner selon le nom (mais pas parfait)
            version_detectors = ['apache', 'nginx', 'php', 'vsftpd', 'proftpd', 'openssh', 'dlink', 'cisco']
            if any(vd in detector_name for vd in version_detectors):
                def default_none(*args, **kwargs):
                    return None
                self._detector_cache[name] = default_none
                return default_none
        
        def default_false(*args, **kwargs):
            return False
        self._detector_cache[name] = default_false
        return default_false
    
    def __getattr__(self, name: str):
        """
        Charge dynamiquement les détecteurs à la demande.
        
        Permet d'utiliser self.if_apache(), self.if_vsftpd(), etc.
        sans avoir à définir chaque méthode manuellement.
        
        Pattern:
        - if_<name> -> cherche detect_<name> dans lib.scanner.*.detectors
        - contains_pattern, has_header -> cherche directement dans http.detectors
        """
        # Seulement pour les helpers de détection
        if name.startswith('if_') or name in ['contains_pattern', 'has_header', 'detect_version']:
            return self._get_detector(name)
        
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")
    
    def run(self) -> bool:
        """
        Run the scanner module.
        
        This method must be implemented by scanner modules.
        It should perform the scan and return True if vulnerable, False otherwise.
        
        Returns:
            bool: True if vulnerable, False otherwise
        
        Note: Use set_info() to store dynamic details (version, cves, etc.)
        """
        raise NotImplementedError("Scanner modules must implement the run() method")
    
    def _exploit(self):
        """
        Execute the scan (scanner modules don't exploit, they only scan)
        """
        try:
            return self.run()
        except ProcedureError as e:
            return False
        except Exception as e:
            print_error(f"Scan error: {e}")
            return False

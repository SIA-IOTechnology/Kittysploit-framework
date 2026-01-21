#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ftp.ftp_client import FTPOptions, FTPClientMixin

class Module(Auxiliary, FTPClientMixin):
    """
    FTP Server Enumeration Scanner (Mode Direct - Sans Session)
    
    Ce module démontre comment FTPClientMixin fonctionne en mode DIRECT :
    - Se connecte directement à un serveur FTP (pas de session existante)
    - Utilise FTPOptions pour la configuration (rhost, rport, ftp_user, ftp_password)
    - Le mixin détecte automatiquement qu'il n'y a pas de session et crée une nouvelle connexion
    
    DIFFÉRENCE avec un module Post :
    - Module Post : utilise self.session (connexion déjà établie)
    - Module Auxiliary : utilise rhost/rport (nouvelle connexion)
    """
    
    __info__ = {
        "name": "FTP Server Enumeration Scanner",
        "description": "Connect to FTP server and enumerate files, directories and server information (Direct mode - no session required)",
        "author": "KittySploit Team",
        "tags": ["ftp", "scanner", "enumeration"],
    }
    
    # Configuration FTP (Mode Direct)
    rhost = OptString("", "Target FTP server IP or hostname", True)
    rport = OptPort(21, "Target FTP port", True)
    ftp_user = OptString("anonymous", "FTP username", True)
    ftp_password = OptString("anonymous@example.com", "FTP password", True)
    timeout = OptInteger(10, "Connection timeout in seconds", True)
    
    # Options de scan
    max_depth = OptInteger(3, "Maximum directory depth to recurse", False)
    show_hidden = OptBool(True, "Show hidden files (starting with .)", False)
    remote_path = OptString("/", "Starting directory path", False)
    
    def run(self):
        """Run FTP enumeration scan"""
        
        print_info("=" * 70)
        print_info("FTP SCANNER - MODE DIRECT (AUXILIARY)")
        print_info("=" * 70)
        print_info()
        
        # Afficher la configuration
        print_status("Configuration:")
        print_info(f"  Target:   {self.rhost.value}:{self.rport.value}")
        print_info(f"  Username: {self.ftp_user.value}")
        print_info(f"  Password: {'*' * len(str(self.ftp_password.value))}")
        print_info(f"  Timeout:  {self.timeout.value}s")
        print_info()
        
        try:
            # ===================================================================
            # ÉTAPE 1 : Connexion FTP
            # ===================================================================
            # Le mixin FTPClientMixin détecte automatiquement qu'on est en mode
            # "Direct" car il n'y a pas de self.session, donc il utilise rhost
            print_status("Step 1: Connecting to FTP server...")
            
            ftp = self.get_ftp_connection()
            print_success(f"✓ Connected to {self.rhost.value}")
            print_info()
            
            # ===================================================================
            # ÉTAPE 2 : Récupérer les informations du serveur
            # ===================================================================
            print_status("Step 2: Gathering server information...")
            
            try:
                welcome_msg = ftp.getwelcome()
                print_info(f"  Welcome Message: {welcome_msg}")
            except:
                print_warning("  No welcome message available")
            
            try:
                current_dir = ftp.pwd()
                print_info(f"  Current Directory: {current_dir}")
            except:
                print_warning("  Could not get current directory")
            
            # Tester la commande SYST
            try:
                system_type = ftp.sendcmd('SYST')
                print_info(f"  System Type: {system_type}")
            except Exception as e:
                print_warning(f"  SYST command failed: {e}")
            
            print_info()
            
            # ===================================================================
            # ÉTAPE 3 : Énumérer les fichiers et dossiers
            # ===================================================================
            print_status("Step 3: Enumerating files and directories...")
            print_info()
            
            # Utiliser la méthode list_files() du mixin
            # Cette méthode fonctionne aussi bien en mode Direct qu'en mode Session!
            files = self.list_files(self.remote_path.value)
            
            if not files:
                print_warning("No files found or access denied")
                return True
            
            # Séparer les dossiers et les fichiers
            directories = []
            regular_files = []
            
            for file_info in files:
                name = file_info.get('name', '')
                file_type = file_info.get('type', 'unknown')
                
                # Filtrer les fichiers cachés si demandé
                if not self.show_hidden.value and name.startswith('.'):
                    continue
                
                if file_type == 'directory':
                    directories.append(file_info)
                else:
                    regular_files.append(file_info)
            
            # Afficher les statistiques
            print_success(f"Found {len(directories)} directories and {len(regular_files)} files")
            print_info()
            
            # ===================================================================
            # ÉTAPE 4 : Afficher les résultats
            # ===================================================================
            
            # Afficher les dossiers
            if directories:
                print_status("Directories:")
                dir_table = []
                for d in directories:
                    dir_table.append([
                        "📁 " + d.get('name', ''),
                        d.get('date', ''),
                        d.get('size', '')
                    ])
                print_table(['Name', 'Date', 'Size'], dir_table)
                print_info()
            
            # Afficher les fichiers
            if regular_files:
                print_status("Files:")
                file_table = []
                for f in regular_files:
                    file_table.append([
                        "📄 " + f.get('name', ''),
                        f.get('date', ''),
                        f.get('size', '') + " bytes"
                    ])
                print_table(['Name', 'Date', 'Size'], file_table)
                print_info()
            
            # ===================================================================
            # ÉTAPE 5 : Tester d'autres commandes FTP
            # ===================================================================
            print_status("Step 4: Testing FTP capabilities...")
            
            # Test FEAT (FTP Features)
            try:
                features = ftp.sendcmd('FEAT')
                print_info("  Supported Features:")
                for line in features.split('\n')[1:-1]:  # Skip first and last line
                    print_info(f"    {line.strip()}")
            except Exception as e:
                print_warning(f"  FEAT command not supported: {e}")
            
            print_info()
            
            # ===================================================================
            # RÉSUMÉ : Comment ça fonctionne
            # ===================================================================
            print_info("=" * 70)
            print_success("SCAN COMPLETED")
            print_info("=" * 70)
            print_info()
            print_info("💡 HOW IT WORKS (Mode Direct):")
            print_info()
            print_info("1. Ce module hérite de 'Auxiliary' et 'FTPClientMixin'")
            print_info("2. Il définit des options FTP : rhost, rport, ftp_user, ftp_password")
            print_info("3. Quand on appelle get_ftp_connection():")
            print_info("   → Le mixin détecte qu'il n'y a PAS de self.session")
            print_info("   → Il utilise donc rhost pour créer une NOUVELLE connexion")
            print_info("   → Il appelle _get_direct_client() automatiquement")
            print_info()
            print_info("4. Toutes les méthodes du mixin fonctionnent ensuite:")
            print_info("   → list_files(), download_file(), change_directory(), etc.")
            print_info()
            print_info("=" * 70)
            print_info()
            print_info("🔄 COMPARAISON avec un module Post (Session):")
            print_info()
            print_info("Mode Post (avec session FTP existante):")
            print_info("  ✓ Hérite de 'Post' (pas 'Auxiliary')")
            print_info("  ✓ Utilise self.session (connexion déjà établie)")
            print_info("  ✓ get_ftp_connection() détecte self.session")
            print_info("  ✓ Utilise _get_session_client() automatiquement")
            print_info("  ✓ Pas besoin de rhost/rport (déjà connecté!)")
            print_info()
            print_info("Mode Auxiliary (sans session - comme ce module):")
            print_info("  ✓ Hérite de 'Auxiliary' (pas 'Post')")
            print_info("  ✓ Définit rhost, rport, ftp_user, ftp_password")
            print_info("  ✓ get_ftp_connection() détecte l'absence de session")
            print_info("  ✓ Crée une nouvelle connexion avec ces paramètres")
            print_info("  ✓ Utilise _get_direct_client() automatiquement")
            print_info()
            print_info("=" * 70)
            print_info()
            print_success("✓ Une seule bibliothèque FTPClientMixin pour les deux modes!")
            print_info()
            
            # Fermer la connexion proprement
            try:
                ftp.quit()
                print_status("Connection closed cleanly")
            except:
                ftp.close()
                print_status("Connection closed")
            
            return True
            
        except Exception as e:
            print_error(f"FTP scan failed: {e}")
            import traceback
            print_error(traceback.format_exc())
            return False

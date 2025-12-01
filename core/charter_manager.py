#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
from typing import Dict, Any, Optional
from core.output_handler import print_info, print_warning, print_error, print_success, print_status

class CharterManager:
    """Manager for the acceptance of the usage charter"""
    
    def __init__(self, config_dir: str = None):
        """
        Initialize the charter manager
        
        Args:
            config_dir: Configuration directory (default ~/.kittysploit)
        """
        if config_dir is None:
            self.config_dir = os.path.expanduser("~/.kittysploit")
        else:
            self.config_dir = config_dir
            
        self.config_file = os.path.join(self.config_dir, "charter.json")
        self.charter_file = os.path.join(os.path.dirname(__file__), "..", "charter.txt")
        
        # Create the configuration directory if it doesn't exist
        os.makedirs(self.config_dir, exist_ok=True)
    
    def get_charter_content(self) -> str:
        """
        Retrieve the charter content
        
        Returns:
            The charter content
        """
        try:
            with open(self.charter_file, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            return self._get_default_charter()
        except Exception as e:
            print_error(f"Error reading charter: {e}")
            return self._get_default_charter()
    
    def _get_default_charter(self) -> str:

        return """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           TERMS OF USE                                       ║
║                           KittySploit Framework                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  IMPORTANT WARNING:                                                          ║
║                                                                              ║
║  This framework is intended ONLY for educational purposes and authorized     ║
║  penetration testing. The use of this tool on systems without explicit       ║
║  authorization is ILLEGAL and may result in legal prosecution.               ║
║                                                                              ║
║  TERMS OF USE:                                                               ║
║                                                                              ║
║  1. You must have written authorization from the system owner before         ║
║     using this framework.                                                    ║
║                                                                              ║
║  2. This framework should only be used in the context of:                    ║
║     - Authorized penetration testing                                         ║
║     - Cybersecurity research                                                 ║
║     - Training and education                                                 ║
║     - Controlled test environments                                           ║
║                                                                              ║
║  3. You are solely responsible for the use of this tool and its              ║
║     consequences.                                                            ║
║                                                                              ║
║  4. The developers of this framework disclaim any responsibility for         ║
║     the misuse of this tool.                                                 ║
║                                                                              ║
║  5. By using this framework, you agree to comply with all applicable         ║
║     local, national and international laws.                                  ║
║                                                                              ║
║  LIABILITY:                                                                  ║
║                                                                              ║
║  The use of this framework is at your own risk. The developers cannot        ║
║  be held responsible for any direct or indirect damage resulting from        ║
║  the use of this software.                                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    def is_charter_accepted(self) -> bool:
        """
        Check if the charter has been accepted
        
        Returns:
            True if the charter has been accepted, False otherwise
        """
        if not os.path.exists(self.config_file):
            return False
            
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                return config.get('charter_accepted', False)
        except (json.JSONDecodeError, KeyError, FileNotFoundError):
            return False
    
    def accept_charter(self, user_name: str = None) -> bool:
        """
        Mark the charter as accepted
        
        Args:
            user_name: Name of the user accepting the charter
            
        Returns:
            True if the acceptance was recorded successfully
        """
        try:
            config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            
            config['charter_accepted'] = True
            config['charter_accepted_date'] = self._get_current_timestamp()
            if user_name:
                config['charter_accepted_by'] = user_name
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception as e:
            print_error(f"Error recording acceptance: {e}")
            return False
    
    def _get_current_timestamp(self) -> str:
        """
        Return the current timestamp
        
        Returns:
            Timestamp in ISO format
        """
        from datetime import datetime
        return datetime.now().isoformat()
    
    def display_charter(self) -> None:
        """
        Display the charter to the user
        """
        charter_content = self.get_charter_content()
        print(charter_content)
    
    def prompt_charter_acceptance(self) -> bool:
        """
        Ask the user to accept the charter
        
        Returns:
            True if the user accepts, False otherwise
        """
        self.display_charter()
        
        print_warning("You must accept this charter to use KittySploit.")
        print_status("Please read the terms of use above carefully.")
        
        while True:
            try:
                response = input("\nDo you accept this terms of use? (yes/no): ").strip().lower()
                
                if response in ['yes', 'y', 'oui', 'o']:
                    if self.accept_charter():
                        print_success("Charter accepted successfully!")
                        print_success("You can now use KittySploit.")
                        return True
                    else:
                        print_error("Error recording acceptance.")
                        return False
                        
                elif response in ['no', 'n', 'non']:
                    print_warning("Charter not accepted. KittySploit cannot be used.")
                    print_status("You can restart the framework later to accept the charter.")
                    return False
                    
                else:
                    print_error("Invalid response. Please answer 'yes' or 'no'.")
                    
            except KeyboardInterrupt:
                print_warning("Interruption detected. Charter not accepted.")
                return False
            except EOFError:
                print_warning("End of input detected. Charter not accepted.")
                return False
    
    def reset_charter_acceptance(self) -> bool:
        """
        Reset the charter acceptance (for testing)
        
        Returns:
            True if the reset was successful
        """
        try:
            if os.path.exists(self.config_file):
                config = {}
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                config['charter_accepted'] = False
                if 'charter_accepted_date' in config:
                    del config['charter_accepted_date']
                if 'charter_accepted_by' in config:
                    del config['charter_accepted_by']
                
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
            else:
                # Create a configuration file with charter_accepted = False
                config = {'charter_accepted': False}
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception as e:
            print_error(f"Error during reset: {e}")
            return False

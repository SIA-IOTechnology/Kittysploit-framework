#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.framework.base_module import BaseModule
from core.framework.enums import Handler, SessionType, Arch, Platform, Protocol
from core.framework.option.option_string import OptString
from core.framework.option.option_bool import OptBool
from core.output_handler import print_info, print_success, print_error, print_warning
from typing import Optional, Any
import struct
import socket
import importlib

class Payload(BaseModule):
    """Base class for payload modules"""

    TYPE_MODULE = "payload"

    # Language of the generated client code (e.g. "python", "powershell"). Used to check transform compatibility.
    # Payloads that support stream transforms set this; transform must support this language via generate_client_code(lang).
    CLIENT_LANGUAGE: Optional[str] = None

    # Optional C2 stream transform: must match the listener's transform (and options) so both sides encode/decode the same way
    transform = OptString("", "C2 stream transform - same as listener (e.g. transforms/python/stream/xor)", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.type = "payload"
        self._zig_compiler = None
        self._transform_instance = None
        self._transform_path = ""

    def _get_transform_path(self) -> str:
        from core.framework.transform import get_transform_path_from_instance
        return get_transform_path_from_instance(self)

    def _ensure_transform_loaded(self) -> None:
        """Load or reload transform instance when transform option is set."""
        path_str = self._get_transform_path()
        if not path_str:
            self._transform_instance = None
            self._transform_path = ""
            return
        if self._transform_instance is not None and self._transform_path == path_str:
            return
        try:
            mod_path = "modules." + path_str.replace("/", ".")
            mod = importlib.import_module(mod_path)
            xf_cls = getattr(mod, "Module", None)
            if not xf_cls:
                self._transform_instance = None
                self._transform_path = ""
                return
            self._transform_instance = xf_cls(framework=getattr(self, "framework", None))
            self._transform_path = path_str
        except Exception:
            self._transform_instance = None
            self._transform_path = ""

    def _get_transform_instance(self):
        """Return the loaded transform instance (loads it if needed)."""
        self._ensure_transform_loaded()
        return self._transform_instance

    def _get_client_language(self) -> Optional[str]:
        """Return the language of the generated client code (e.g. 'python', 'powershell')."""
        return getattr(self.__class__, "CLIENT_LANGUAGE", None)

    def _is_transform_compatible(self, xf) -> bool:
        """Return True if the transform supports this payload's client language."""
        if xf is None:
            return False
        lang = self._get_client_language()
        if not lang:
            return False
        supported = getattr(xf, "get_supported_client_languages", lambda: getattr(xf.__class__, "SUPPORTED_CLIENT_LANGUAGES", []))()
        return lang in supported

    def get_options(self) -> dict:
        """Return payload options merged with transform options when transform is set."""
        opts = super().get_options()
        path_str = self._get_transform_path()
        if not path_str:
            return opts
        self._ensure_transform_loaded()
        if self._transform_instance is None:
            return opts
        xf_opts = self._transform_instance.get_options()
        if xf_opts:
            merged = dict(opts)
            for name, data in xf_opts.items():
                merged[name] = data
            return merged
        return opts

    def set_option(self, name: str, value: Any) -> bool:
        """Set option on payload or on transform instance when applicable."""
        from core.framework.transform import LEGACY_OPTION
        if name == LEGACY_OPTION:
            name = "transform"
        own_opts = getattr(self, "exploit_attributes", {})
        if name in own_opts:
            return super().set_option(name, value)
        self._ensure_transform_loaded()
        if self._transform_instance is not None:
            xf_opts = self._transform_instance.get_options()
            if name in xf_opts:
                return self._transform_instance.set_option(name, value)
        return False

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to transform instance for transform option names."""
        if name.startswith("_"):
            raise AttributeError(name)
        if self._transform_instance is not None and name in self._transform_instance.get_options():
            return getattr(self._transform_instance, name)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    # Backward compatibility (deprecated).
    def _get_obfuscator_path(self) -> str:
        return self._get_transform_path()

    def _ensure_obfuscator_loaded(self) -> None:
        self._ensure_transform_loaded()

    def _get_obfuscator_instance(self):
        return self._get_transform_instance()

    def _is_obfuscator_compatible(self, xf) -> bool:
        return self._is_transform_compatible(xf)
    
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
                    static: bool = True,
                    windows_subsystem: Optional[str] = None) -> bool:
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
            windows_subsystem: On Windows, use 'windows' to hide console (no window)
            
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
            static=static,
            windows_subsystem=windows_subsystem
        )
    
    def shellcode_ip(self, ip: str) -> bytes:
        return socket.inet_aton(ip)
    
    def shellcode_port(self, port: int) -> bytes:
        return port.to_bytes(2, 'big')

    def get_python_script(self) -> Optional[str]:
        """
        Override in Python payloads to return the raw script for compilation to EXE.
        Default returns None (payload does not support Python compilation).
        """
        return None

    def compile_python_to_exe(self,
                              output_path: str,
                              script: Optional[str] = None,
                              target_platform: Optional[str] = None,
                              target_arch: str = 'x64',
                              python_binary: Optional[str] = None,
                              use_compression: bool = False,
                              standalone: bool = False,
                              embeddable_path: Optional[str] = None) -> bool:
        """
        Compile Python script to executable using Zig.

        Args:
            output_path: Output executable path
            script: Python script (if None, uses get_python_script())
            target_platform: windows, linux, macos (default from payload platform)
            target_arch: x64, x86, etc.
            python_binary: python, python3, py (default from payload option if available)
            use_compression: Use zlib for smaller payload (non-standalone only)
            standalone: If True, embed Python runtime (python3X.dll + stdlib). No Python install needed on target.
            embeddable_path: Path to pythonX.Y-embed-amd64.zip (standalone only)

        Returns:
            True if successful
        """
        script_code = script or self.get_python_script()
        if not script_code:
            print_error("No Python script: set script= or implement get_python_script()")
            return False

        if standalone:
            from core.lib.py_compiler import Py2ExeStandaloneCompiler
            platform_str = target_platform
            if platform_str is None:
                info = getattr(self.__class__, '__info__', {})
                platform = info.get('platform') if info else None
                platform_str = getattr(platform, 'value', None) or str(platform or 'windows').lower()
            if platform_str and platform_str.lower() != 'windows':
                print_error("Standalone mode is Windows-only for now")
                return False
            compiler = Py2ExeStandaloneCompiler(embeddable_path=embeddable_path)
            if not compiler.is_available():
                print_error("Zig and/or Python embeddable package not available")
                print_error("Download pythonX.Y-embed-amd64.zip from python.org and place in core/lib/embed_python/")
                return False
            return compiler.compile(
                script_code=script_code,
                output_path=output_path,
                embeddable_path=embeddable_path,
            )

        from core.lib.py_compiler import Py2ExeCompiler
        platform_str = target_platform
        if platform_str is None:
            info = getattr(self.__class__, '__info__', {})
            platform = info.get('platform') if info else None
            if hasattr(platform, 'value'):
                platform_str = platform.value if platform else 'windows'
            else:
                platform_str = str(platform).lower() if platform else 'windows'

        py_bin = python_binary
        if py_bin is None and hasattr(self, 'python_binary'):
            pb = getattr(self.python_binary, 'value', self.python_binary)
            py_bin = str(pb) if pb else 'python'

        compiler = Py2ExeCompiler()
        if not compiler.is_available():
            print_error("Zig compiler not available for Python-to-EXE")
            return False

        return compiler.compile(
            script_code=script_code,
            output_path=output_path,
            target_platform=platform_str,
            target_arch=target_arch,
            python_binary=py_bin or 'python',
            use_compression=use_compression,
        )

    # --- Implant identity (Ed25519, persistent per build) ---

    implant_identity = OptBool(
        True,
        "Generate persistent Ed25519 implant identity (implant_id + signed hello)",
        False,
        True,
    )
    implant_id = OptString("", "Implant ID (auto when implant_identity=true)", False, True)

    def _resolve_implant_identity(self):
        """Return ImplantIdentity, generating and saving when enabled."""
        from lib.implant.identity import (
            ImplantIdentity,
            generate_implant_identity,
            load_implant_identity,
            save_implant_identity,
        )

        use_identity = getattr(self, "implant_identity", None)
        enabled = use_identity.value if hasattr(use_identity, "value") else bool(use_identity)
        if not enabled:
            return None

        existing = str(getattr(getattr(self, "implant_id", None), "value", self.implant_id) or "").strip()
        keys_dir = "output/implant_keys"
        if existing:
            path = __import__("pathlib").Path(keys_dir) / f"{existing}.json"
            if path.is_file():
                return load_implant_identity(path)

        identity = generate_implant_identity()
        path = save_implant_identity(identity, keys_dir)
        print_success(f"Implant identity {identity.implant_id} saved to {path}")
        if hasattr(self, "implant_id") and hasattr(self.implant_id, "value"):
            self.implant_id.value = identity.implant_id
        return identity

    def _apply_implant_identity_options(self) -> None:
        """Set relay_token / client_id from implant_id when identity is enabled."""
        identity = self._resolve_implant_identity()
        if not identity:
            return
        for opt_name in ("relay_token", "client_id"):
            if hasattr(self, opt_name):
                opt = getattr(self, opt_name)
                if hasattr(opt, "value"):
                    if not str(opt.value or "").strip():
                        opt.value = identity.implant_id
                else:
                    setattr(self, opt_name, identity.implant_id)
        self._implant_identity_obj = identity
        self._implant_public_key_pem = identity.public_key_pem
        return identity

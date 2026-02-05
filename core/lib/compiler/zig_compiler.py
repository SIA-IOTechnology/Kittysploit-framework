#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zig Compiler for cross-compiling executables
"""

import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Dict, Any
from core.output_handler import print_info, print_success, print_error, print_warning


class ZigCompiler:
    """Zig compiler with cross-compilation support"""
    
    def __init__(self, zig_path: Optional[str] = None):
        """
        Initialize Zig compiler
        
        Args:
            zig_path: Path to zig executable (None for auto-detection)
        """
        self.zig_path = zig_path or self._find_zig()
        self.temp_dir = None
        
    def _find_zig(self) -> Optional[str]:
        """Find zig executable - check PATH first (for complete installation), then core/lib/compiler/zig_executable/"""
        import platform
        
        # First, check PATH (usually has complete Zig installation)
        zig_paths = ['zig', 'zig.exe']
        
        for zig_path in zig_paths:
            try:
                result = subprocess.run(
                    [zig_path, 'version'],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    print_info(f"Found Zig in PATH: {zig_path}")
                    return zig_path
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        # If not in PATH, check in core/lib/compiler/zig_executable/
        # Get the framework root directory (assuming we're in core/lib/compiler/)
        current_file = Path(__file__)
        framework_root = current_file.parent.parent.parent.parent
        
        zig_executable_dir = framework_root / "core" / "lib" / "compiler" / "zig_executable"
        
        # Check for zig.exe (Windows) or zig (Unix)
        if platform.system() == 'Windows':
            zig_exe = "zig.exe"
        else:
            zig_exe = "zig"
        
        zig_path = zig_executable_dir / zig_exe
        
        if zig_path.exists():
            # Check if we have a complete installation (with lib/ directory)
            # Zig needs its lib/ directory to be in the same directory as the executable
            zig_dir = zig_path.parent
            lib_dir = zig_dir / "lib"
            
            if lib_dir.exists() and lib_dir.is_dir():
                # Complete installation found
                print_info(f"Found Zig compiler (complete installation): {zig_path}")
                return str(zig_path)
            else:
                # Only executable found, but no lib/ directory
                # Zig won't work without its lib/ directory
                print_warning(f"Found Zig executable at {zig_path}, but missing lib/ directory.")
                print_warning("Zig requires its complete installation directory (with lib/ folder).")
                # Try to install automatically (with confirmation)
                try:
                    from core.lib.compiler.zig_installer import install_zig_if_needed
                    if install_zig_if_needed(ask_confirmation=True):
                        # Retry finding Zig after installation
                        if zig_path.exists():
                            lib_dir = zig_dir / "lib"
                            if lib_dir.exists() and lib_dir.is_dir():
                                print_info(f"Found Zig compiler (complete installation): {zig_path}")
                                return str(zig_path)
                except Exception as e:
                    print_warning(f"Installation failed: {e}")
                print_warning("Please either:")
                print_warning("  1. Install Zig and add it to PATH: https://ziglang.org/download/")
                print_warning("  2. Place the complete Zig installation in core/lib/compiler/zig_executable/")
                return None
        
        # Zig not found, try automatic installation (with confirmation)
        try:
            from core.lib.compiler.zig_installer import install_zig_if_needed
            if install_zig_if_needed(ask_confirmation=True):
                # Retry finding Zig after installation
                if zig_path.exists():
                    zig_dir = zig_path.parent
                    lib_dir = zig_dir / "lib"
                    if lib_dir.exists() and lib_dir.is_dir():
                        print_info(f"Found Zig compiler (complete installation): {zig_path}")
                        return str(zig_path)
        except Exception as e:
            print_warning(f"Automatic installation failed: {e}")
        
        print_warning("Zig not found in PATH or core/lib/compiler/zig_executable/")
        print_warning("Install Zig and add it to PATH: https://ziglang.org/download/")
        return None
    
    def is_available(self) -> bool:
        """Check if Zig is available"""
        return self.zig_path is not None
    
    def get_target_triple(self, platform: str, arch: str) -> str:
        """
        Convert platform and architecture to Zig target triple
        
        Args:
            platform: Target platform (linux, windows, macos, freebsd, etc.)
            arch: Target architecture (x86, x64, arm, arm64, mips, etc.)
            
        Returns:
            Zig target triple (e.g., 'x86_64-linux-gnu')
        """
        # Architecture mapping
        arch_map = {
            'x86': 'i386',
            'x64': 'x86_64',
            'x86_64': 'x86_64',
            'arm': 'arm',
            'arm64': 'aarch64',
            'aarch64': 'aarch64',
            'mips': 'mips',
            'mips64': 'mips64',
            'ppc': 'powerpc',
            'ppc64': 'powerpc64',
            'riscv64': 'riscv64'
        }
        
        # Platform mapping
        platform_map = {
            'linux': 'linux-gnu',
            'windows': 'windows',
            'macos': 'macos',
            'freebsd': 'freebsd',
            'openbsd': 'openbsd',
            'netbsd': 'netbsd',
            'dragonfly': 'dragonfly',
            'android': 'android'
        }
        
        zig_arch = arch_map.get(arch.lower(), arch.lower())
        zig_platform = platform_map.get(platform.lower(), platform.lower())
        
        # Windows uses different format
        if platform.lower() == 'windows':
            if zig_arch == 'i386':
                return 'i386-windows'
            else:
                return f'{zig_arch}-windows'
        
        # Linux and other Unix-like
        return f'{zig_arch}-{zig_platform}'
    
    def compile(self, 
                source_code: str,
                output_path: str,
                target_platform: str = 'linux',
                target_arch: str = 'x64',
                optimization: str = 'ReleaseSmall',
                strip: bool = True,
                static: bool = True,
                windows_subsystem: Optional[str] = None) -> bool:
        """
        Compile Zig source code to executable

        Args:
            source_code: Zig source code as string
            output_path: Path where to save the compiled binary
            target_platform: Target platform (linux, windows, macos, etc.)
            target_arch: Target architecture (x86, x64, arm, etc.)
            optimization: Optimization level (Debug, ReleaseFast, ReleaseSafe, ReleaseSmall)
            strip: Strip debug symbols
            static: Create static binary
            windows_subsystem: On Windows, use 'windows' to hide console (no window), 'console' for default
            
        Returns:
            True if compilation successful, False otherwise
        """
        if not self.is_available():
            print_error("Zig compiler not available")
            return False
        
        try:
            # Convert to absolute path first; handle bare filenames (no directory)
            output_path = os.path.abspath(output_path)
            output_dir = os.path.dirname(output_path)
            if not output_dir:
                output_dir = os.getcwd()
                output_path = os.path.join(output_dir, os.path.basename(output_path))
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Use output directory for compilation to avoid antivirus issues
            # This is safer than using temp directories that antivirus might block
            # Create a subdirectory for compilation to avoid deleting the output directory
            compile_dir = os.path.join(output_dir, '.zig_compile')
            os.makedirs(compile_dir, exist_ok=True)
            self.temp_dir = compile_dir
            source_file = os.path.join(self.temp_dir, 'main.zig')
            
            # Write source code to file
            with open(source_file, 'w', encoding='utf-8') as f:
                f.write(source_code)
            
            # Get target triple
            target_triple = self.get_target_triple(target_platform, target_arch)
            print_info(f"Compiling for target: {target_triple}")
            
            # Use -femit-bin to output directly to target path (avoids move + Windows file lock)
            binary_name = os.path.basename(output_path)
            binary_name_no_ext = os.path.splitext(binary_name)[0]

            # Set custom cache directory to avoid antivirus issues
            env = os.environ.copy()
            workspace_cache = os.path.join(os.path.dirname(output_dir), '.zig_cache')
            os.makedirs(workspace_cache, exist_ok=True)
            env['ZIG_LOCAL_CACHE_DIR'] = workspace_cache

            # Build zig command: -femit-bin=path outputs directly (must be single arg)
            # Use forward slashes on Windows to avoid backslash parsing issues
            emit_bin_path = output_path.replace('\\', '/')
            cmd = [
                self.zig_path,
                'build-exe',
                source_file,
                '-target', target_triple,
                '-O', optimization,
                '--name', binary_name_no_ext,
                '-femit-bin=' + emit_bin_path,
            ]
            
            # Note: Zig generates static binaries by default (since 0.4.0)
            # Use -dynamic if you want a dynamic binary instead
            if not static:
                cmd.append('-dynamic')
            
            if strip:
                cmd.append('-fstrip')  # Zig uses -fstrip (not --strip) to strip debug symbols
                # Additional size reduction flags
                cmd.append('-fno-stack-check')  # Disable stack overflow checking
                cmd.append('-fno-unwind-tables')  # Disable unwind tables for smaller binary
                cmd.append('-fsingle-threaded')  # Disable threading support for smaller binary
                # Note: Zig handles optimization through -O flag
                # Additional GCC/Clang-style flags are not supported by Zig

            # Windows: hide console window (no black window when exe runs)
            if target_platform.lower() == 'windows' and windows_subsystem == 'windows':
                cmd.extend(['--subsystem', 'windows'])

            # Remove existing output file - lld-link on Windows often fails with "Permission denied"
            # when trying to overwrite an existing .exe (e.g. from a previous run)
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except OSError:
                    print_warning("Cannot remove existing output file (close it if running)")

            # Execute compilation
            print_info(f"Compiling with Zig...")
            result = subprocess.run(
                cmd,
                cwd=self.temp_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                error_msg = result.stderr
                print_error(f"Compilation failed: {error_msg}")
                
                # Check for antivirus-related errors
                if 'virus' in error_msg.lower() or 'logiciel potentiellement indésirable' in error_msg.lower() or 'cannot open' in error_msg.lower():
                    print_warning("Antivirus detected! The compilation was blocked.")
                    print_info("Solutions:")
                    print_info("1. Add exclusion for: " + workspace_cache)
                    print_info("2. Add exclusion for: " + self.temp_dir)
                    print_info("3. Temporarily disable real-time protection")
                    print_info("4. Compile on a Linux system if available")
                
                return False
            
            # With -femit-bin, Zig outputs directly to output_path (avoids Windows file lock on move)
            if os.path.exists(output_path):
                if os.name != 'nt':
                    os.chmod(output_path, 0o755)
                print_success(f"Binary compiled successfully: {output_path}")
                return True
            # Fallback if -femit-bin wrote to cwd: copy instead of move (move can fail if file locked)
            compiled_binary = None
            for name in [binary_name, binary_name_no_ext + '.exe', binary_name_no_ext]:
                p = os.path.join(self.temp_dir, name)
                if os.path.exists(p):
                    compiled_binary = p
                    break
            if compiled_binary:
                try:
                    shutil.copy2(compiled_binary, output_path)
                    if os.name != 'nt':
                        os.chmod(output_path, 0o755)
                    print_success(f"Binary compiled successfully: {output_path}")
                    return True
                except Exception as e:
                    print_error(f"Failed to copy binary to output path: {e}")
                    return False
            if os.path.exists(self.temp_dir):
                print_error(f"Compiled binary not found. Files: {os.listdir(self.temp_dir)}")
            return False
                
        except subprocess.TimeoutExpired:
            print_error("Compilation timeout")
            return False
        except Exception as e:
            print_error(f"Compilation error: {e}")
            return False
        finally:
            # Cleanup temporary directory
            if self.temp_dir and os.path.exists(self.temp_dir):
                try:
                    shutil.rmtree(self.temp_dir)
                except Exception:
                    pass
    
    def compile_template(self,
                        template_name: str,
                        output_path: str,
                        target_platform: str = 'linux',
                        target_arch: str = 'x64',
                        template_vars: Optional[Dict[str, Any]] = None) -> bool:
        """
        Compile from a template
        
        Args:
            template_name: Name of the template
            template_vars: Variables to inject into template
            
        Returns:
            True if successful
        """
        from core.lib.compiler.zig_templates import get_template
        
        template = get_template(template_name)
        if not template:
            print_error(f"Template '{template_name}' not found")
            return False
        
        # Inject variables into template
        source_code = template
        if template_vars:
            for key, value in template_vars.items():
                source_code = source_code.replace(f'{{{{{key}}}}}', str(value))
        
        return self.compile(
            source_code=source_code,
            output_path=output_path,
            target_platform=target_platform,
            target_arch=target_arch
        )


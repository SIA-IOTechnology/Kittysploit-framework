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
from typing import List, Dict, Any, Optional
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
                print_success(f"Found Zig compiler")
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
        
        # Windows: prefer -gnu triple so zig cc finds MinGW headers (windows.h) when cross-compiling.
        if platform.lower() == 'windows':
            if zig_arch == 'i386':
                return 'i386-windows-gnu'
            return f'{zig_arch}-windows-gnu'
        
        # Linux and other Unix-like
        return f'{zig_arch}-{zig_platform}'
    
    @staticmethod
    def _c_opt_level(optimization: str) -> str:
        """Map Zig optimization names to clang -O flags for zig cc."""
        mapping = {
            'Debug': '-O0',
            'ReleaseFast': '-O3',
            'ReleaseSafe': '-O2',
            'ReleaseSmall': '-Os',
        }
        return mapping.get(optimization, '-Os')

    def _build_c_compile_cmd(self,
                               source_file: str,
                               output_path: str,
                               target_triple: str,
                               optimization: str,
                               strip: bool,
                               target_platform: str,
                               windows_subsystem: Optional[str],
                               extra_args: Optional[List[str]],
                               compile_dir: str) -> List[str]:
        cmd = [
            self.zig_path,
            'cc',
            '-target', target_triple,
            self._c_opt_level(optimization),
            '-I', compile_dir,
            source_file,
            '-o', output_path.replace('\\', '/'),
        ]
        if strip:
            cmd.append('-s')
        if optimization == 'Debug':
            cmd.append('-g')

        extra = list(extra_args or [])
        if target_platform.lower() == 'windows':
            if not any(arg == '-masm=intel' for arg in extra):
                cmd.append('-masm=intel')
            if not any(arg == '-lc' for arg in extra):
                cmd.append('-lc')
            if not any(arg in ('-lkernel32', '-luser32') for arg in extra):
                cmd.extend(['-lkernel32', '-luser32'])
            if windows_subsystem == 'windows' and not any('subsystem' in arg for arg in extra):
                cmd.append('-Wl,--subsystem,windows')
        elif not any(arg == '-lc' for arg in extra):
            cmd.append('-lc')

        cmd.extend(extra)
        return cmd

    def compile_c(self,
                  source_code: str,
                  output_path: str,
                  target_platform: str = 'windows',
                  target_arch: str = 'x64',
                  optimization: str = 'ReleaseSmall',
                  strip: bool = True,
                  static: bool = True,
                  windows_subsystem: Optional[str] = None,
                  include_dir: Optional[str] = None,
                  extra_args: Optional[List[str]] = None) -> bool:
        """Compile C source (e.g. inline asm syscall stubs) to executable via Zig/clang."""
        extra = list(extra_args or [])
        if include_dir:
            include_flag = '-I' + include_dir.replace('\\', '/')
            if include_flag not in extra:
                extra.append(include_flag)
        if target_platform.lower() == "windows" and not any(a == "-lc" for a in extra):
            extra.append("-lc")
        return self._compile_source(
            source_code=source_code,
            output_path=output_path,
            source_name='main.c',
            target_platform=target_platform,
            target_arch=target_arch,
            optimization=optimization,
            strip=strip,
            static=static,
            windows_subsystem=windows_subsystem,
            extra_args=extra,
            include_dir=include_dir,
        )

    def compile(self, 
                source_code: str,
                output_path: str,
                target_platform: str = 'linux',
                target_arch: str = 'x64',
                optimization: str = 'ReleaseSmall',
                strip: bool = True,
                static: bool = True,
                windows_subsystem: Optional[str] = None,
                extra_args: Optional[List[str]] = None) -> bool:
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

        extra_args = list(extra_args or [])
        if target_platform.lower() == "linux" and not any(a == "-lc" for a in extra_args):
            extra_args.append("-lc")

        return self._compile_source(
            source_code=source_code,
            output_path=output_path,
            source_name='main.zig',
            target_platform=target_platform,
            target_arch=target_arch,
            optimization=optimization,
            strip=strip,
            static=static,
            windows_subsystem=windows_subsystem,
            extra_args=extra_args,
        )

    def _compile_source(self,
                        source_code: str,
                        output_path: str,
                        source_name: str,
                        target_platform: str = 'linux',
                        target_arch: str = 'x64',
                        optimization: str = 'ReleaseSmall',
                        strip: bool = True,
                        static: bool = True,
                        windows_subsystem: Optional[str] = None,
                        extra_args: Optional[List[str]] = None,
                        include_dir: Optional[str] = None) -> bool:
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
            source_file = os.path.join(self.temp_dir, source_name)

            if include_dir and os.path.isdir(include_dir):
                for header_name in os.listdir(include_dir):
                    if header_name.endswith('.h'):
                        src_header = os.path.join(include_dir, header_name)
                        dst_header = os.path.join(self.temp_dir, header_name)
                        shutil.copy2(src_header, dst_header)
            
            # Write source code to file
            with open(source_file, 'w', encoding='utf-8') as f:
                f.write(source_code)
            
            # Get target triple
            target_triple = self.get_target_triple(target_platform, target_arch)
            print_info(f"Compiling for target: {target_triple}")
            
            binary_name = os.path.basename(output_path)
            binary_name_no_ext = os.path.splitext(binary_name)[0]

            # Set custom cache directory to avoid antivirus issues
            env = os.environ.copy()
            workspace_cache = os.path.join(os.path.dirname(output_dir), '.zig_cache')
            os.makedirs(workspace_cache, exist_ok=True)
            env['ZIG_LOCAL_CACHE_DIR'] = workspace_cache

            is_c_source = source_name.endswith('.c')
            if is_c_source:
                cmd = self._build_c_compile_cmd(
                    source_file=source_file,
                    output_path=output_path,
                    target_triple=target_triple,
                    optimization=optimization,
                    strip=strip,
                    target_platform=target_platform,
                    windows_subsystem=windows_subsystem,
                    extra_args=extra_args,
                    compile_dir=self.temp_dir,
                )
            else:
                # Use -femit-bin to output directly to target path (avoids move + Windows file lock)
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
                
                if not static:
                    cmd.append('-dynamic')
                
                if strip:
                    cmd.append('-fstrip')
                    cmd.append('-fno-stack-check')
                    cmd.append('-fno-unwind-tables')
                    cmd.append('-fsingle-threaded')

                if target_platform.lower() == 'windows' and windows_subsystem == 'windows':
                    cmd.extend(['--subsystem', 'windows'])

                if extra_args:
                    cmd.extend(extra_args)

                if target_platform.lower() == 'linux' and not any(a == '-lc' for a in extra_args or []):
                    cmd.append('-lc')

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
                timeout=180 if is_c_source else 60
            )
            
            if result.returncode != 0:
                error_msg = result.stderr
                print_error(f"Compilation failed: {error_msg}")
                
                # Check for antivirus-related errors
                if 'virus' in error_msg.lower() or 'software' in error_msg.lower() or 'cannot open' in error_msg.lower():
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


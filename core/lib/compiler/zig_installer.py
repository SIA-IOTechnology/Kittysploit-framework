#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zig Compiler Auto-Installer
Downloads and installs Zig compiler automatically on first installation
"""

import os
import sys
import platform
import subprocess
import shutil
import zipfile
import tarfile
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error
from core.output_handler import print_info, print_success, print_error, print_warning


class ZigInstaller:
    """Automatic Zig compiler installer"""
    
    # Zig version to download (stable version)
    ZIG_VERSION = "0.15.2"
    
    # Direct download URLs for each platform (stable version)
    ZIG_DOWNLOAD_URLS = {
        'linux': 'https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz',
        'macos': 'https://ziglang.org/download/0.15.2/zig-x86_64-macos-0.15.2.tar.xz',
        'windows': 'https://ziglang.org/download/0.15.2/zig-x86_64-windows-0.15.2.zip'
    }
    
    def __init__(self):
        """Initialize the installer"""
        self.framework_root = self._get_framework_root()
        self.zig_executable_dir = self.framework_root / "core" / "lib" / "compiler" / "zig_executable"
        self.platform_info = self._detect_platform()
        
    def _get_framework_root(self) -> Path:
        """Get the framework root directory"""
        current_file = Path(__file__)
        return current_file.parent.parent.parent.parent
    
    def _detect_platform(self) -> dict:
        """
        Detect the current platform and return download information
        
        Returns:
            dict with platform info: {
                'system': 'windows'|'linux'|'macos',
                'arch': 'x86_64'|'aarch64'|'arm',
                'ext': '.zip'|'.tar.xz',
                'zig_arch': 'x86_64'|'aarch64'|'arm',
                'zig_os': 'windows'|'linux'|'macos'
            }
        """
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        info = {
            'system': system,
            'arch': machine,
            'ext': '.zip' if system == 'windows' else '.tar.xz',
        }
        
        # Map architecture
        if machine in ('x86_64', 'amd64'):
            info['zig_arch'] = 'x86_64'
        elif machine in ('aarch64', 'arm64'):
            info['zig_arch'] = 'aarch64'
        elif machine.startswith('arm'):
            info['zig_arch'] = 'arm'
        else:
            info['zig_arch'] = machine
        
        # Map OS
        if system == 'windows':
            info['zig_os'] = 'windows'
        elif system == 'darwin':
            info['zig_os'] = 'macos'
        elif system == 'linux':
            info['zig_os'] = 'linux'
        else:
            info['zig_os'] = system
        
        return info
    
    def _get_download_url(self) -> Optional[str]:
        """
        Get the download URL for Zig based on platform
        
        Returns:
            URL to download Zig archive, or None if platform not supported
        """
        os_name = self.platform_info['zig_os']
        
        # Get URL from predefined URLs dictionary
        url = self.ZIG_DOWNLOAD_URLS.get(os_name)
        
        if not url:
            print_error(f"Unsupported platform: {os_name}")
            print_error(f"Supported platforms: {', '.join(self.ZIG_DOWNLOAD_URLS.keys())}")
            return None
        
        return url
    
    def _get_zig_executable_name(self) -> str:
        """Get the name of the Zig executable for the current platform"""
        if self.platform_info['system'] == 'windows':
            return 'zig.exe'
        return 'zig'
    
    def is_installed(self) -> bool:
        """
        Check if Zig is already installed in zig_executable directory
        
        Returns:
            True if Zig is installed, False otherwise
        """
        zig_exe = self.zig_executable_dir / self._get_zig_executable_name()
        
        if not zig_exe.exists():
            return False
        
        # Check if we have a complete installation (with lib/ directory)
        lib_dir = self.zig_executable_dir / "lib"
        if not lib_dir.exists() or not lib_dir.is_dir():
            return False
        
        # Verify that Zig actually works
        try:
            result = subprocess.run(
                [str(zig_exe), 'version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _download_file(self, url: str, dest_path: Path) -> bool:
        """
        Download a file from URL to destination
        
        Args:
            url: URL to download from
            dest_path: Path where to save the file
            
        Returns:
            True if download successful, False otherwise
        """
        try:
            print_info(f"Downloading Zig from {url}...")
            print_info(f"This may take a few minutes depending on your connection...")
            
            # Create parent directory if it doesn't exist
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Download with progress
            def show_progress(block_num, block_size, total_size):
                if total_size > 0:
                    percent = min(100, (block_num * block_size * 100) // total_size)
                    sys.stdout.write(f"\r[*] Progress: {percent}%")
                    sys.stdout.flush()
            
            urllib.request.urlretrieve(url, dest_path, show_progress)
            print()  # New line after progress
            print_success(f"Download completed: {dest_path}")
            return True
            
        except urllib.error.HTTPError as e:
            print_error(f"HTTP error while downloading: {e.code} {e.reason}")
            return False
        except urllib.error.URLError as e:
            print_error(f"URL error while downloading: {e.reason}")
            return False
        except Exception as e:
            print_error(f"Error downloading file: {e}")
            return False
    
    def _extract_archive(self, archive_path: Path, extract_to: Path) -> bool:
        """
        Extract archive (zip or tar.xz) to destination
        
        Args:
            archive_path: Path to archive file
            extract_to: Directory to extract to
            
        Returns:
            True if extraction successful, False otherwise
        """
        try:
            print_info(f"Extracting archive to {extract_to}...")
            
            # Create extraction directory
            extract_to.mkdir(parents=True, exist_ok=True)
            
            if archive_path.suffix == '.zip':
                # Extract ZIP file
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_to)
            elif archive_path.suffixes == ['.tar', '.xz']:
                # Extract tar.xz file
                with tarfile.open(archive_path, 'r:xz') as tar_ref:
                    tar_ref.extractall(extract_to)
            else:
                print_error(f"Unsupported archive format: {archive_path.suffix}")
                return False
            
            print_success("Extraction completed")
            return True
            
        except Exception as e:
            print_error(f"Error extracting archive: {e}")
            return False
    
    def _move_zig_files(self, extract_dir: Path) -> bool:
        """
        Move Zig files from extracted directory to zig_executable directory
        
        Args:
            extract_dir: Directory where archive was extracted
            
        Returns:
            True if move successful, False otherwise
        """
        try:
            # Find the zig directory in the extracted files
            # Zig archives typically extract to a directory like "zig-{os}-{arch}-{version}"
            zig_dirs = [d for d in extract_dir.iterdir() if d.is_dir() and d.name.startswith('zig-')]
            
            if not zig_dirs:
                print_error("Could not find Zig directory in extracted archive")
                return False
            
            if len(zig_dirs) > 1:
                print_warning(f"Multiple Zig directories found, using first: {zig_dirs[0]}")
            
            zig_source_dir = zig_dirs[0]
            
            print_info(f"Moving Zig files from {zig_source_dir} to {self.zig_executable_dir}...")
            
            # Remove existing directory if it exists
            if self.zig_executable_dir.exists():
                shutil.rmtree(self.zig_executable_dir)
            
            # Create target directory
            self.zig_executable_dir.mkdir(parents=True, exist_ok=True)
            
            # Move all files from source to target
            for item in zig_source_dir.iterdir():
                dest = self.zig_executable_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)
            
            print_success("Zig files moved successfully")
            return True
            
        except Exception as e:
            print_error(f"Error moving Zig files: {e}")
            return False
    
    def install(self) -> bool:
        """
        Download and install Zig compiler
        
        Returns:
            True if installation successful, False otherwise
        """
        # Check if already installed
        if self.is_installed():
            print_info("Zig compiler is already installed")
            return True
        
        print_info("Starting Zig compiler installation...")
        print_info(f"Platform: {self.platform_info['system']} ({self.platform_info['zig_arch']})")
        print_info(f"Installation directory: {self.zig_executable_dir}")
        
        # Get download URL
        download_url = self._get_download_url()
        if not download_url:
            print_error("Could not determine download URL for this platform")
            return False
        
        print_info(f"Download URL: {download_url}")
        
        # Create temporary directory for download
        temp_dir = self.framework_root / ".zig_install_temp"
        temp_dir.mkdir(exist_ok=True)
        
        archive_path = temp_dir / f"zig{self.platform_info['ext']}"
        
        try:
            # Download
            if not self._download_file(download_url, archive_path):
                return False
            
            # Extract
            extract_dir = temp_dir / "extracted"
            if not self._extract_archive(archive_path, extract_dir):
                return False
            
            # Move files to final location
            if not self._move_zig_files(extract_dir):
                return False
            
            # Verify installation
            if not self.is_installed():
                print_error("Installation completed but verification failed")
                return False
            
            print_success("Zig compiler installed successfully!")
            zig_exe = self.zig_executable_dir / self._get_zig_executable_name()
            
            # Test Zig version
            try:
                result = subprocess.run(
                    [str(zig_exe), 'version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    print_success(f"Zig version: {result.stdout.strip()}")
            except Exception:
                pass
            
            return True
            
        finally:
            # Cleanup temporary directory
            if temp_dir.exists():
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass


def install_zig_if_needed(ask_confirmation: bool = True) -> bool:
    """
    Install Zig compiler if it's not already installed
    
    Args:
        ask_confirmation: If True, ask user for confirmation before installing
    
    Returns:
        True if Zig is available (was already installed or successfully installed), False otherwise
    """
    installer = ZigInstaller()
    
    if installer.is_installed():
        return True
    
    # Ask for user confirmation
    if ask_confirmation:
        print_warning("Zig compiler not found.")
        print_info(f"Platform: {installer.platform_info['system']} ({installer.platform_info['zig_arch']})")
        print_info(f"Installation directory: {installer.zig_executable_dir}")
        print_info("Zig compiler is required for payload compilation.")
        print_info("Would you like to install it automatically? (y/n): ", end="")
        
        try:
            response = input().strip().lower()
            if response not in ['y', 'yes']:
                print_warning("Zig installation cancelled by user.")
                print_info("You can install Zig manually from: https://ziglang.org/download/")
                print_info("Or run this script again and answer 'y' to install automatically.")
                return False
        except (EOFError, KeyboardInterrupt):
            print_warning("\nZig installation cancelled by user.")
            return False
    
    return installer.install()


if __name__ == "__main__":
    # Test installation
    installer = ZigInstaller()
    if installer.install():
        print_success("Installation test successful!")
    else:
        print_error("Installation test failed!")
        sys.exit(1)


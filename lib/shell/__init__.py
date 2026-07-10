"""Interactive shell helpers (PTY / ConPTY)."""

from lib.shell.pty_runtime import (
    PTY_MAGIC,
    build_unix_pty_script,
    build_windows_conpty_script,
    relay_socket_terminal,
    terminal_raw_supported,
)

__all__ = [
    "PTY_MAGIC",
    "build_unix_pty_script",
    "build_windows_conpty_script",
    "relay_socket_terminal",
    "terminal_raw_supported",
]

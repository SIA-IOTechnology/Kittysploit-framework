"""Interactive shell helpers (PTY / ConPTY / adaptive upgrade)."""

from lib.shell.adaptive_upgrade import adapt_connection, probe_os, try_unix_pty_upgrade
from lib.shell.pty_runtime import (
    PTY_MAGIC,
    build_unix_pty_script,
    build_windows_conpty_script,
    relay_socket_terminal,
    terminal_raw_supported,
)

__all__ = [
    "PTY_MAGIC",
    "adapt_connection",
    "build_unix_pty_script",
    "build_windows_conpty_script",
    "probe_os",
    "relay_socket_terminal",
    "terminal_raw_supported",
    "try_unix_pty_upgrade",
]

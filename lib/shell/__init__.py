"""Interactive shell helpers (PTY / ConPTY / adaptive upgrade)."""

from lib.shell.adaptive_upgrade import adapt_connection, probe_os, try_unix_pty_upgrade
from lib.shell.pty_runtime import (
    PTY_MAGIC,
    build_unix_pty_script,
    build_windows_conpty_script,
    encode_winsize,
    local_terminal_winsize,
    probe_socket_liveliness,
    relay_socket_terminal,
    terminal_raw_supported,
)

__all__ = [
    "PTY_MAGIC",
    "adapt_connection",
    "build_unix_pty_script",
    "build_windows_conpty_script",
    "encode_winsize",
    "local_terminal_winsize",
    "probe_os",
    "probe_socket_liveliness",
    "relay_socket_terminal",
    "terminal_raw_supported",
    "try_unix_pty_upgrade",
]

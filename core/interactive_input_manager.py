#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interactive Input Manager - Routes web terminal input to plugins in interactive mode.

When a plugin (e.g. minicom) runs in interactive mode via the web terminal,
stdin is not connected to the web UI. This manager allows plugins to register
a queue to receive input from the web terminal instead.
"""

import threading
import queue


class InteractiveInputManager:
    """
    Manages interactive input routing for web-based terminals.
    
    Plugins that use input() in interactive mode can register a queue;
    when the web terminal sends input, it is put in the queue instead of
    being executed as a framework command.
    """
    
    def __init__(self):
        # session_id -> queue.Queue
        self._handlers = {}
        self._lock = threading.Lock()
    
    def register(self, session_id: str):
        """
        Register an interactive handler for a session.
        Returns a queue that will receive input strings.
        """
        with self._lock:
            q = queue.Queue()
            self._handlers[session_id] = q
            return q
    
    def unregister(self, session_id: str):
        """Unregister the interactive handler for a session."""
        with self._lock:
            if session_id in self._handlers:
                q = self._handlers[session_id]
                # Put sentinel to unblock any get() waiting
                try:
                    q.put(None)
                except Exception:
                    pass
                del self._handlers[session_id]
    
    def has_handler(self, session_id: str) -> bool:
        """Check if there is an active interactive handler for this session."""
        with self._lock:
            return session_id in self._handlers
    
    def put(self, session_id: str, text: str) -> bool:
        """
        Put input text into the session's queue.
        Returns True if delivered, False if no handler registered.
        """
        with self._lock:
            if session_id not in self._handlers:
                return False
            q = self._handlers[session_id]
        
        try:
            q.put(text)
            return True
        except Exception:
            return False
    
    def get_queue(self, session_id: str):
        """Get the queue for a session (for blocking get). Returns None if not registered."""
        with self._lock:
            return self._handlers.get(session_id)

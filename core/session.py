#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional

@dataclass
class SessionData:
    """Structure representing a session."""
    id: str
    host: str
    port: int
    session_type: str
    data: dict = field(default_factory=dict)


class Session:
    """Gère la session utilisateur et l'état actuel du framework"""
    
    def __init__(self):
        """Initialise une nouvelle session"""
        self.current_module = None
        self.options = {}
        self.history = []
        self.user_id = None
        self.authenticated = False
        self.privileges = None
        self.active_sessions: Dict[str, SessionData] = {}

    def create_session(self, host: str, port: int, session_type: str, data=None) -> str:
        """Creates a new session and returns its unique ID."""
        session_id = str(uuid.uuid4())  # Generate a unique session ID
        self.active_sessions[session_id] = SessionData(
            id=session_id, host=host, port=port, session_type=session_type, data=data or {}
        )
        return session_id

    def get_session(self, session_id: str) -> Optional[SessionData]:
        """Retrieves a session by its ID."""
        return self.active_sessions.get(session_id)

    def list_sessions(self) -> Dict[str, SessionData]:
        """Lists all active sessions (returns a copy to avoid unwanted modifications)."""
        return self.active_sessions.copy()

    def destroy_session(self, session_id: str) -> bool:
        """Destroys a session if it exists."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            return True
        return False

    def set_current_module(self, module):
        """Définit le module actuellement utilisé"""
        self.current_module = module
        if module and hasattr(module, 'name'):
            self.history.append(module.name)
        elif module:
            self.history.append(str(module))
    
    def get_current_module(self):
        """Retourne le module actuellement utilisé"""
        return self.current_module
    
    def set_option(self, key, value):
        """Définit une option globale pour la session"""
        self.options[key] = value
        return True
    
    def get_option(self, key, default=None):
        """Récupère une option globale de la session"""
        return self.options.get(key, default)
    
    def get_history(self):
        """Retourne l'historique des modules utilisés"""
        return self.history
    
    def set_user(self, user_id, authenticated=True, privileges=None):
        """Définit l'utilisateur actuel et son état d'authentification"""
        self.user_id = user_id
        self.authenticated = authenticated
        self.privileges = privileges
    
    def is_authenticated(self):
        """Vérifie si l'utilisateur est authentifié"""
        return self.authenticated
    
    def get_privileges(self):
        """Retourne les privilèges de l'utilisateur"""
        return self.privileges
    
    def clear(self):
        """Réinitialise la session"""
        self.current_module = None
        self.options = {}
        # Conserve l'historique et les informations utilisateur
"""
Client de collaboration pour se connecter au serveur SaaS externe
"""
import os
import requests
from typing import Dict, Optional, Callable
import json

class CollaborationClient:
    """Client pour se connecter au serveur SaaS de collaboration"""
    
    def __init__(self, server_url: Optional[str] = None, api_key: Optional[str] = None):

        self.server_url = "https://proxy.kittysploit.com"
        self.api_key = api_key or os.getenv("COLLABORATION_API_KEY")
        
        # S'assurer que l'URL n'a pas de slash final
        self.server_url = self.server_url.rstrip('/')
        
        if not self.api_key:
            print("[WARNING] No collaboration API key configured. Collaboration features will be disabled.")
            print("[INFO] Set COLLABORATION_API_KEY environment variable or configure in settings.")
    
    def is_configured(self) -> bool:
        """Vérifie si le client est configuré"""
        return self.api_key is not None and self.server_url is not None
    
    def get_headers(self) -> Dict[str, str]:
        """Retourne les headers avec l'API key"""
        if not self.api_key:
            return {}
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
    
    def create_session(self, name: str, owner_id: Optional[str] = None, target_url: str = "") -> Optional[Dict]:
        """Crée une nouvelle session sur le serveur SaaS"""
        if not self.is_configured():
            return None
        
        try:
            response = requests.post(
                f"{self.server_url}/api/v1/sessions",
                headers=self.get_headers(),
                json={
                    "name": name,
                    "owner_id": owner_id,
                    "target_url": target_url
                },
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[ERROR] Failed to create session: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"[ERROR] Error creating collaboration session: {e}")
            return None
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Récupère les détails d'une session"""
        if not self.is_configured():
            return None
        
        try:
            response = requests.get(
                f"{self.server_url}/api/v1/sessions/{session_id}",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception as e:
            print(f"[ERROR] Error getting session: {e}")
            return None
    
    def get_session_by_invite(self, invite_code: str) -> Optional[Dict]:
        """Récupère une session par code d'invitation"""
        if not self.is_configured():
            return None
        
        try:
            response = requests.get(
                f"{self.server_url}/api/v1/sessions/invite/{invite_code}",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception as e:
            print(f"[ERROR] Error getting session by invite: {e}")
            return None
    
    def get_websocket_url(self, session_id: str) -> str:
        """Retourne l'URL WebSocket pour une session"""
        ws_protocol = "ws" if self.server_url.startswith("http://") else "wss"
        ws_host = self.server_url.replace("http://", "").replace("https://", "")
        return f"{ws_protocol}://{ws_host}/ws/v1/sessions/{session_id}"
    
    def get_websocket_connection_data(self, username: str, color: str, user_id: Optional[str] = None) -> Dict:
        """Retourne les données à envoyer lors de la connexion WebSocket"""
        return {
            "api_key": self.api_key,
            "name": username,
            "username": username,
            "color": color,
            "user_id": user_id
        }

# Instance globale
collaboration_client = CollaborationClient()


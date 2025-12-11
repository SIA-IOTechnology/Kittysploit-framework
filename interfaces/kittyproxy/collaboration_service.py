"""
Service de collaboration en temps réel utilisant Ably (ou autre SaaS)
"""
import os
import json
import time
import uuid
from typing import Dict, List, Optional
from datetime import datetime
import threading

# Option 1: Ably (recommandé)
try:
    import ably
    ABLY_AVAILABLE = True
except ImportError:
    ABLY_AVAILABLE = False
    print("[WARNING] Ably not installed. Install with: pip install ably")

# Option 2: Fallback WebSocket natif
from fastapi import WebSocket

class CollaborationService:
    """Service de gestion de la collaboration en temps réel"""
    
    def __init__(self, saas_provider: str = "ably", api_key: Optional[str] = None):
        """
        Initialise le service de collaboration
        
        Args:
            saas_provider: "ably", "pusher", ou "native" (WebSocket natif)
            api_key: Clé API du SaaS (None pour mode natif)
        """
        self.provider = saas_provider
        self.api_key = api_key or os.getenv("COLLABORATION_API_KEY")
        self.sessions: Dict[str, Dict] = {}
        self.participants: Dict[str, Dict[str, Dict]] = {}  # session_id -> {user_id -> user_data}
        self._lock = threading.RLock()
        
        # Initialiser le provider
        if saas_provider == "ably" and ABLY_AVAILABLE and self.api_key:
            self._init_ably()
        elif saas_provider == "native":
            self._init_native()
        else:
            print(f"[WARNING] Collaboration provider '{saas_provider}' not available. Using native WebSocket.")
            self.provider = "native"
            self._init_native()
    
    def _init_ably(self):
        """Initialise Ably"""
        try:
            self.ably_client = ably.AblyRest(api_key=self.api_key)
            print("[INFO] Ably collaboration service initialized")
        except Exception as e:
            print(f"[ERROR] Failed to initialize Ably: {e}")
            self.provider = "native"
            self._init_native()
    
    def _init_native(self):
        """Initialise le mode natif (WebSocket FastAPI)"""
        self.websockets: Dict[str, List[WebSocket]] = {}  # session_id -> [websockets]
        print("[INFO] Native WebSocket collaboration service initialized")
    
    # === GESTION DES SESSIONS ===
    
    def create_session(self, name: str, owner_id: str, owner_username: str, 
                      max_participants: int = 10, public: bool = False) -> Dict:
        """Crée une nouvelle session collaborative"""
        session_id = f"session_{uuid.uuid4().hex[:12]}"
        invite_code = uuid.uuid4().hex[:8].upper()
        
        session = {
            "id": session_id,
            "name": name,
            "owner": owner_id,
            "created_at": datetime.utcnow().isoformat(),
            "invite_code": invite_code,
            "public": public,
            "settings": {
                "max_participants": max_participants,
                "auto_sync": True
            },
            "participants": {}
        }
        
        with self._lock:
            self.sessions[session_id] = session
            self.participants[session_id] = {}
        
        # Ajouter le propriétaire comme premier participant
        self.add_participant(session_id, owner_id, owner_username, "owner")
        
        return session
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Récupère une session par ID"""
        return self.sessions.get(session_id)
    
    def get_session_by_invite(self, invite_code: str) -> Optional[Dict]:
        """Récupère une session par code d'invitation"""
        for session in self.sessions.values():
            if session.get("invite_code") == invite_code.upper():
                return session
        return None
    
    def list_sessions(self, user_id: Optional[str] = None) -> List[Dict]:
        """Liste toutes les sessions (optionnellement filtrées par utilisateur)"""
        sessions = list(self.sessions.values())
        if user_id:
            sessions = [s for s in sessions if user_id in s.get("participants", {})]
        return sessions
    
    def delete_session(self, session_id: str, user_id: str) -> bool:
        """Supprime une session (seul le propriétaire peut)"""
        session = self.sessions.get(session_id)
        if not session or session["owner"] != user_id:
            return False
        
        with self._lock:
            del self.sessions[session_id]
            if session_id in self.participants:
                del self.participants[session_id]
        
        # Notifier tous les participants
        self._broadcast(session_id, {
            "type": "session_deleted",
            "session_id": session_id
        })
        
        return True
    
    # === GESTION DES PARTICIPANTS ===
    
    def add_participant(self, session_id: str, user_id: str, username: str, role: str = "viewer"):
        """Ajoute un participant à une session"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        # Vérifier la limite de participants
        if len(session.get("participants", {})) >= session["settings"]["max_participants"]:
            return False
        
        participant = {
            "user_id": user_id,
            "username": username,
            "role": role,
            "joined_at": datetime.utcnow().isoformat(),
            "status": "online"
        }
        
        with self._lock:
            session["participants"][user_id] = participant
            self.participants[session_id][user_id] = participant
        
        # Notifier les autres participants
        self._broadcast(session_id, {
            "type": "participant_joined",
            "participant": participant
        }, exclude_user_id=user_id)
        
        return True
    
    def remove_participant(self, session_id: str, user_id: str):
        """Retire un participant d'une session"""
        if session_id not in self.sessions:
            return
        
        with self._lock:
            if session_id in self.sessions:
                self.sessions[session_id]["participants"].pop(user_id, None)
            if session_id in self.participants:
                self.participants[session_id].pop(user_id, None)
        
        # Notifier les autres participants
        self._broadcast(session_id, {
            "type": "participant_left",
            "user_id": user_id
        })
    
    def update_participant_status(self, session_id: str, user_id: str, status: str):
        """Met à jour le statut d'un participant (online/offline)"""
        if session_id in self.sessions:
            participant = self.sessions[session_id]["participants"].get(user_id)
            if participant:
                participant["status"] = status
                
                self._broadcast(session_id, {
                    "type": "participant_status",
                    "user_id": user_id,
                    "status": status
                })
    
    def get_participants(self, session_id: str) -> List[Dict]:
        """Récupère la liste des participants d'une session"""
        if session_id not in self.sessions:
            return []
        return list(self.sessions[session_id]["participants"].values())
    
    # === MESSAGES & COMMUNICATION ===
    
    def send_chat_message(self, session_id: str, user_id: str, username: str, 
                          content: str, flow_id: Optional[str] = None) -> Dict:
        """Envoie un message de chat dans une session"""
        message = {
            "id": f"msg_{uuid.uuid4().hex[:12]}",
            "session_id": session_id,
            "user_id": user_id,
            "username": username,
            "content": content,
            "flow_id": flow_id,
            "type": "chat_message",
            "created_at": datetime.utcnow().isoformat()
        }
        
        self._broadcast(session_id, {
            "type": "chat_message",
            "message": message
        })
        
        return message
    
    def send_flow_added(self, session_id: str, flow_data: Dict, user_id: str):
        """Notifie qu'un nouveau flow a été ajouté"""
        self._broadcast(session_id, {
            "type": "flow_added",
            "flow": flow_data,
            "user_id": user_id,
            "timestamp": time.time()
        })
    
    def send_flow_selected(self, session_id: str, flow_id: str, user_id: str, username: str):
        """Notifie qu'un flow a été sélectionné par un utilisateur"""
        self._broadcast(session_id, {
            "type": "flow_selected",
            "flow_id": flow_id,
            "user_id": user_id,
            "username": username
        })
    
    def send_annotation(self, session_id: str, flow_id: str, user_id: str, 
                       username: str, content: str, annotation_type: str = "comment"):
        """Envoie une annotation sur un flow"""
        annotation = {
            "id": f"annot_{uuid.uuid4().hex[:12]}",
            "session_id": session_id,
            "flow_id": flow_id,
            "user_id": user_id,
            "username": username,
            "content": content,
            "type": annotation_type,
            "created_at": datetime.utcnow().isoformat()
        }
        
        self._broadcast(session_id, {
            "type": "annotation",
            "annotation": annotation
        })
        
        return annotation
    
    # === BROADCAST (Provider-agnostic) ===
    
    def _broadcast(self, session_id: str, message: Dict, exclude_user_id: Optional[str] = None):
        """Diffuse un message à tous les participants d'une session"""
        if self.provider == "ably":
            self._broadcast_ably(session_id, message)
        else:
            self._broadcast_native(session_id, message, exclude_user_id)
    
    def _broadcast_ably(self, session_id: str, message: Dict):
        """Diffuse via Ably"""
        if not ABLY_AVAILABLE:
            return
        
        try:
            channel = self.ably_client.channels.get(f"session:{session_id}")
            event_type = message.get("type", "message")
            channel.publish(event_type, message)
        except Exception as e:
            print(f"[ERROR] Failed to broadcast via Ably: {e}")
    
    def _broadcast_native(self, session_id: str, message: Dict, exclude_user_id: Optional[str] = None):
        """Diffuse via WebSocket natif"""
        if session_id not in self.websockets:
            return
        
        import asyncio
        import json
        
        message_json = json.dumps(message)
        to_remove = []
        
        for ws in self.websockets[session_id]:
            try:
                # Vérifier si on doit exclure cet utilisateur
                # (nécessite de stocker user_id avec le websocket)
                asyncio.create_task(ws.send_text(message_json))
            except Exception as e:
                print(f"[ERROR] Failed to send WebSocket message: {e}")
                to_remove.append(ws)
        
        # Nettoyer les connexions fermées
        for ws in to_remove:
            if session_id in self.websockets:
                self.websockets[session_id].remove(ws)
    
    def register_websocket(self, session_id: str, websocket: WebSocket):
        """Enregistre un WebSocket pour une session (mode natif)"""
        if session_id not in self.websockets:
            self.websockets[session_id] = []
        self.websockets[session_id].append(websocket)
    
    def unregister_websocket(self, session_id: str, websocket: WebSocket):
        """Désenregistre un WebSocket"""
        if session_id in self.websockets:
            if websocket in self.websockets[session_id]:
                self.websockets[session_id].remove(websocket)

# Instance globale
collaboration_service = CollaborationService(
    saas_provider=os.getenv("COLLABORATION_PROVIDER", "ably"),
    api_key=os.getenv("COLLABORATION_API_KEY")
)


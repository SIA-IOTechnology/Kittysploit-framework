#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Système d'événements (Pub/Sub) - Couche N+1
Système de publication/souscription pour découpler les composants du framework.
"""

from typing import Dict, List, Callable, Any, Optional
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
import threading
import uuid


class EventType(Enum):
    """Types d'événements du framework"""
    # Module events
    MODULE_LOADING = "module.loading"
    MODULE_LOADED = "module.loaded"
    MODULE_UNLOADED = "module.unloaded"
    MODULE_EXECUTING = "module.executing"
    MODULE_EXECUTED = "module.executed"
    MODULE_FAILED = "module.failed"
    MODULE_RELOADED = "module.reloaded"
    
    # Pipeline events
    PIPELINE_STARTED = "pipeline.started"
    PIPELINE_COMPLETED = "pipeline.completed"
    PIPELINE_FAILED = "pipeline.failed"
    PIPELINE_STEP_STARTED = "pipeline.step.started"
    PIPELINE_STEP_COMPLETED = "pipeline.step.completed"
    PIPELINE_STEP_FAILED = "pipeline.step.failed"
    
    # Workflow events
    WORKFLOW_STARTED = "workflow.started"
    WORKFLOW_COMPLETED = "workflow.completed"
    WORKFLOW_FAILED = "workflow.failed"
    
    # Resource events
    RESOURCE_LIMIT_EXCEEDED = "resource.limit_exceeded"
    RESOURCE_MONITORING_STARTED = "resource.monitoring_started"
    RESOURCE_MONITORING_STOPPED = "resource.monitoring_stopped"
    
    # Session events
    SESSION_CREATED = "session.created"
    SESSION_CLOSED = "session.closed"
    SESSION_UPDATED = "session.updated"
    
    # Workspace events
    WORKSPACE_CHANGED = "workspace.changed"
    WORKSPACE_CREATED = "workspace.created"
    WORKSPACE_DELETED = "workspace.deleted"
    
    # Extension events
    EXTENSION_LOADED = "extension.loaded"
    EXTENSION_UNLOADED = "extension.unloaded"
    EXTENSION_ERROR = "extension.error"
    
    # Sandbox events
    SANDBOX_CREATED = "sandbox.created"
    SANDBOX_DESTROYED = "sandbox.destroyed"
    SANDBOX_VIOLATION = "sandbox.violation"


@dataclass
class Event:
    """Représente un événement"""
    event_type: EventType
    data: Dict[str, Any]
    timestamp: datetime = None
    event_id: str = None
    source: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.event_id is None:
            self.event_id = str(uuid.uuid4())


class EventBus:
    """
    Bus d'événements - Système de publication/souscription
    
    Permet aux composants de publier et s'abonner aux événements
    de manière découplée.
    """
    
    def __init__(self):
        self.subscribers: Dict[EventType, List[Callable]] = {}
        self.event_history: List[Event] = []
        self.max_history: int = 1000
        self.lock = threading.Lock()
        self.enabled = True
    
    def subscribe(self, event_type: EventType, callback: Callable[[Event], None], priority: int = 0):
        """
        S'abonne à un type d'événement
        
        Args:
            event_type: Type d'événement
            callback: Fonction appelée lors de l'événement (reçoit un Event)
            priority: Priorité (plus élevé = exécuté en premier)
        """
        with self.lock:
            if event_type not in self.subscribers:
                self.subscribers[event_type] = []
            
            self.subscribers[event_type].append({
                "callback": callback,
                "priority": priority
            })
            # Trier par priorité décroissante
            self.subscribers[event_type].sort(key=lambda x: x["priority"], reverse=True)
    
    def unsubscribe(self, event_type: EventType, callback: Callable):
        """Se désabonne d'un type d'événement"""
        with self.lock:
            if event_type in self.subscribers:
                self.subscribers[event_type] = [
                    sub for sub in self.subscribers[event_type]
                    if sub["callback"] != callback
                ]
    
    def publish(self, event_type: EventType, data: Dict[str, Any] = None, source: Optional[str] = None) -> Event:
        """
        Publie un événement
        
        Args:
            event_type: Type d'événement
            data: Données de l'événement
            source: Source de l'événement (optionnel)
            
        Returns:
            Event: L'événement publié
        """
        if not self.enabled:
            return None
        
        event = Event(
            event_type=event_type,
            data=data or {},
            source=source
        )
        
        # Ajouter à l'historique
        with self.lock:
            self.event_history.append(event)
            if len(self.event_history) > self.max_history:
                self.event_history.pop(0)
        
        # Notifier les abonnés
        # IMPORTANT: "Publier" ne signifie PAS envoyer quelque part à l'extérieur.
        # C'est un système INTERNE : on appelle directement les fonctions qui se sont abonnées.
        # Les callbacks sont exécutés SYNCHRONEMENT dans le même thread.
        with self.lock:
            subscribers = self.subscribers.get(event_type, [])
        
        # Appeler chaque fonction abonnée immédiatement
        for subscriber in subscribers:
            try:
                subscriber["callback"](event)  # ← Appel direct de la fonction, pas d'envoi réseau/fichier
            except Exception as e:
                print(f"Error in event subscriber for {event_type.value}: {e}")
        
        return event
    
    def get_history(self, event_type: Optional[EventType] = None, limit: int = 100) -> List[Event]:
        """
        Récupère l'historique des événements
        
        Args:
            event_type: Filtrer par type (optionnel)
            limit: Nombre maximum d'événements à retourner
            
        Returns:
            Liste des événements
        """
        with self.lock:
            if event_type:
                filtered = [e for e in self.event_history if e.event_type == event_type]
            else:
                filtered = self.event_history
            
            return filtered[-limit:]
    
    def clear_history(self):
        """Efface l'historique des événements"""
        with self.lock:
            self.event_history.clear()
    
    def disable(self):
        """Désactive le bus d'événements"""
        self.enabled = False
    
    def enable(self):
        """Active le bus d'événements"""
        self.enabled = True


class EventFilter:
    """Filtre pour les événements"""
    
    @staticmethod
    def by_source(events: List[Event], source: str) -> List[Event]:
        """Filtre les événements par source"""
        return [e for e in events if e.source == source]
    
    @staticmethod
    def by_time_range(events: List[Event], start_time: datetime, end_time: datetime) -> List[Event]:
        """Filtre les événements par plage de temps"""
        return [e for e in events if start_time <= e.timestamp <= end_time]
    
    @staticmethod
    def by_data_key(events: List[Event], key: str, value: Any) -> List[Event]:
        """Filtre les événements par clé de données"""
        return [e for e in events if e.data.get(key) == value]


#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Callable
from enum import Enum
from dataclasses import dataclass

from .events import Event, EventType
from core.framework.utils.hooks import HookPoint


class ExtensionType(Enum):
    """Types d'extensions"""
    HOOK = "hook"
    EVENT_LISTENER = "event_listener"
    MIDDLEWARE = "middleware"
    POLICY = "policy"
    PLUGIN = "plugin"


@dataclass
class ExtensionMetadata:
    """Métadonnées d'une extension"""
    name: str
    version: str
    author: str
    description: str
    extension_type: ExtensionType
    dependencies: List[str] = None
    config_schema: Dict[str, Any] = None


class Extension(ABC):
    
    def __init__(self, metadata: ExtensionMetadata):
        self.metadata = metadata
        self.enabled = True
        self.config: Dict[str, Any] = {}
    
    @abstractmethod
    def initialize(self, context: Dict[str, Any]) -> bool:
        pass
    
    @abstractmethod
    def cleanup(self):
        pass
    
    def configure(self, config: Dict[str, Any]):
        self.config.update(config)
    
    def is_enabled(self) -> bool:
        return self.enabled
    
    def enable(self):
        self.enabled = True
    
    def disable(self):
        self.enabled = False


class HookExtension(Extension):
    """Extension basée sur les hooks"""
    
    def __init__(self, metadata: ExtensionMetadata, hook_point: HookPoint, callback: Callable):
        super().__init__(metadata)
        self.hook_point = hook_point
        self.callback = callback
        self.priority = 0
    
    def initialize(self, context: Dict[str, Any]) -> bool:
        hook_manager = context.get("hook_manager")
        if hook_manager:
            hook_manager.register(self.hook_point, self.callback, self.priority)
            return True
        return False
    
    def cleanup(self):
        # Le hook manager devrait gérer le nettoyage
        pass


class EventListenerExtension(Extension):
    """Extension basée sur les événements"""
    
    def __init__(self, metadata: ExtensionMetadata, event_types: List[EventType], callback: Callable):
        super().__init__(metadata)
        self.event_types = event_types
        self.callback = callback
        self.priority = 0
    
    def initialize(self, context: Dict[str, Any]) -> bool:
        event_bus = context.get("event_bus")
        if event_bus:
            for event_type in self.event_types:
                event_bus.subscribe(event_type, self.callback, self.priority)
            return True
        return False
    
    def cleanup(self):
        event_bus = self.config.get("event_bus")
        if event_bus:
            for event_type in self.event_types:
                event_bus.unsubscribe(event_type, self.callback)


class MiddlewareExtension(Extension):
    def __init__(self, metadata: ExtensionMetadata):
        super().__init__(metadata)
        self.order = 0  # Ordre d'exécution dans le pipeline
    
    @abstractmethod
    def process(self, request: Dict[str, Any], next_handler: Callable) -> Any:
        """
        Traite une requête dans le pipeline
        
        Args:
            request: Données de la requête
            next_handler: Handler suivant dans le pipeline
            
        Returns:
            Résultat du traitement
        """
        pass
    
    def initialize(self, context: Dict[str, Any]) -> bool:
        return True
    
    def cleanup(self):
        pass


class PolicyExtension(Extension):
    def __init__(self, metadata: ExtensionMetadata):
        super().__init__(metadata)
        self.policy_level = "standard"
    
    @abstractmethod
    def evaluate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Évalue une politique
        
        Args:
            context: Contexte d'évaluation
            
        Returns:
            Résultat de l'évaluation avec 'allowed' (bool) et 'reason' (str)
        """
        pass
    
    def initialize(self, context: Dict[str, Any]) -> bool:
        return True
    
    def cleanup(self):
        pass


class ExtensionRegistry:
    
    def __init__(self):
        import threading
        self.extensions: Dict[str, Extension] = {}
        self.extensions_by_type: Dict[ExtensionType, List[Extension]] = {}
        self.lock = threading.Lock()
    
    def register(self, extension: Extension):
        with self.lock:
            self.extensions[extension.metadata.name] = extension
            ext_type = extension.metadata.extension_type
            if ext_type not in self.extensions_by_type:
                self.extensions_by_type[ext_type] = []
            self.extensions_by_type[ext_type].append(extension)
    
    def unregister(self, extension_name: str):
        with self.lock:
            extension = self.extensions.pop(extension_name, None)
            if extension:
                ext_type = extension.metadata.extension_type
                if ext_type in self.extensions_by_type:
                    self.extensions_by_type[ext_type].remove(extension)
                extension.cleanup()
    
    def get(self, extension_name: str) -> Optional[Extension]:
        with self.lock:
            return self.extensions.get(extension_name)
    
    def get_by_type(self, extension_type: ExtensionType) -> List[Extension]:
        with self.lock:
            return self.extensions_by_type.get(extension_type, []).copy()
    
    def get_all(self) -> List[Extension]:
        with self.lock:
            return list(self.extensions.values())
    
    def initialize_all(self, context: Dict[str, Any]):
        for extension in self.get_all():
            if extension.is_enabled():
                try:
                    extension.initialize(context)
                except Exception as e:
                    print(f"Error initializing extension {extension.metadata.name}: {e}")
    
    def cleanup_all(self):
        for extension in self.get_all():
            try:
                extension.cleanup()
            except Exception as e:
                print(f"Error cleaning up extension {extension.metadata.name}: {e}")


#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Système de Hot Reload - Couche N+1
Permet de recharger dynamiquement les modules et extensions sans redémarrer le framework.
"""

import os
import sys
import time
import importlib
import importlib.util
import threading
from typing import Dict, Set, Optional, Callable, List, Any
from pathlib import Path

# Optionnel: watchdog pour le monitoring de fichiers
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None
    FileSystemEventHandler = object
    FileModifiedEvent = object

from .events import EventBus, EventType


class ModuleReloader:
    """Gère le rechargement des modules"""
    
    def __init__(self, event_bus: Optional[EventBus] = None):
        self.module_paths: Dict[str, str] = {}  # module_id -> file_path
        self.module_specs: Dict[str, Any] = {}  # module_id -> module_spec
        self.file_times: Dict[str, float] = {}  # file_path -> mtime
        self.reload_callbacks: Dict[str, List[Callable]] = {}  # module_id -> callbacks
        self.event_bus = event_bus
        self.lock = threading.Lock()
    
    def register_module(self, module_id: str, file_path: str, module_spec: Any = None):
        """Enregistre un module pour le hot reload"""
        with self.lock:
            self.module_paths[module_id] = file_path
            if module_spec:
                self.module_specs[module_id] = module_spec
            self.file_times[file_path] = os.path.getmtime(file_path)
    
    def unregister_module(self, module_id: str):
        """Désenregistre un module"""
        with self.lock:
            self.module_paths.pop(module_id, None)
            self.module_specs.pop(module_id, None)
            self.reload_callbacks.pop(module_id, None)
    
    def add_reload_callback(self, module_id: str, callback: Callable):
        """Ajoute un callback appelé lors du rechargement"""
        with self.lock:
            if module_id not in self.reload_callbacks:
                self.reload_callbacks[module_id] = []
            self.reload_callbacks[module_id].append(callback)
    
    def check_and_reload(self, module_id: str) -> bool:
        """
        Vérifie si un module a changé et le recharge si nécessaire
        
        Returns:
            True si le module a été rechargé
        """
        with self.lock:
            file_path = self.module_paths.get(module_id)
            if not file_path or not os.path.exists(file_path):
                return False
            
            current_mtime = os.path.getmtime(file_path)
            if current_mtime <= self.file_times.get(file_path, 0):
                return False  # Pas de changement
        
        # Recharger le module
        try:
            if module_id in self.module_specs:
                # Recharger via le spec
                module_spec = self.module_specs[module_id]
                if module_spec and hasattr(module_spec, 'loader'):
                    module = importlib.reload(sys.modules.get(module_spec.name))
                else:
                    # Recharger via le chemin
                    module = self._reload_by_path(file_path)
            else:
                module = self._reload_by_path(file_path)
            
            # Mettre à jour le timestamp
            with self.lock:
                self.file_times[file_path] = os.path.getmtime(file_path)
            
            # Appeler les callbacks
            with self.lock:
                callbacks = self.reload_callbacks.get(module_id, [])
            
            for callback in callbacks:
                try:
                    callback(module)
                except Exception as e:
                    print(f"Error in reload callback for {module_id}: {e}")
            
            # Publier l'événement
            if self.event_bus:
                self.event_bus.publish(
                    EventType.MODULE_RELOADED,
                    {"module_id": module_id, "file_path": file_path},
                    source="hot_reload"
                )
            
            return True
            
        except Exception as e:
            print(f"Error reloading module {module_id}: {e}")
            if self.event_bus:
                self.event_bus.publish(
                    EventType.EXTENSION_ERROR,
                    {"module_id": module_id, "error": str(e)},
                    source="hot_reload"
                )
            return False
    
    def _reload_by_path(self, file_path: str):
        """Recharge un module par son chemin de fichier"""
        # Trouver le module dans sys.modules
        module_name = None
        for name, module in sys.modules.items():
            if hasattr(module, '__file__') and module.__file__ == file_path:
                module_name = name
                break
        
        if module_name:
            return importlib.reload(sys.modules[module_name])
        else:
            # Charger le module
            spec = importlib.util.spec_from_file_location(
                os.path.basename(file_path).replace('.py', ''),
                file_path
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module
        
        raise ValueError(f"Could not reload module at {file_path}")
    
    def check_all(self) -> List[str]:
        """Vérifie tous les modules enregistrés et retourne ceux qui ont été rechargés"""
        reloaded = []
        with self.lock:
            module_ids = list(self.module_paths.keys())
        
        for module_id in module_ids:
            if self.check_and_reload(module_id):
                reloaded.append(module_id)
        
        return reloaded


class HotReloadWatcher(FileSystemEventHandler):
    """Watcher de fichiers pour le hot reload"""
    
    def __init__(self, reloader: ModuleReloader, watch_paths: List[str]):
        self.reloader = reloader
        self.watch_paths = watch_paths
        self.ignored_patterns = {'.pyc', '__pycache__', '.pyc'}
    
    def on_modified(self, event):
        """Appelé lorsqu'un fichier est modifié"""
        if isinstance(event, FileModifiedEvent):
            file_path = event.src_path
            
            # Ignorer les fichiers temporaires
            if any(pattern in file_path for pattern in self.ignored_patterns):
                return
            
            # Vérifier si c'est un module enregistré
            with self.reloader.lock:
                for module_id, registered_path in self.reloader.module_paths.items():
                    if os.path.abspath(registered_path) == os.path.abspath(file_path):
                        # Recharger le module
                        self.reloader.check_and_reload(module_id)
                        break


class HotReloadManager:
    """Gestionnaire de hot reload"""
    
    def __init__(self, event_bus: Optional[EventBus] = None, watch_paths: List[str] = None):
        self.reloader = ModuleReloader(event_bus)
        self.observer: Optional[Observer] = None
        self.watch_paths = watch_paths or []
        self.watching = False
        self.event_bus = event_bus
    
    def start_watching(self, watch_paths: List[str] = None):
        """Démarre le monitoring des fichiers"""
        if not WATCHDOG_AVAILABLE:
            print("Warning: watchdog not available, file watching disabled")
            return
        
        if self.watching:
            return
        
        paths = watch_paths or self.watch_paths
        if not paths:
            return
        
        self.observer = Observer()
        handler = HotReloadWatcher(self.reloader, paths)
        
        for path in paths:
            if os.path.exists(path):
                self.observer.schedule(handler, path, recursive=True)
        
        self.observer.start()
        self.watching = True
    
    def stop_watching(self):
        """Arrête le monitoring des fichiers"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.watching = False
    
    def register_module(self, module_id: str, file_path: str, module_spec: Any = None):
        """Enregistre un module pour le hot reload"""
        self.reloader.register_module(module_id, file_path, module_spec)
    
    def unregister_module(self, module_id: str):
        """Désenregistre un module"""
        self.reloader.unregister_module(module_id)
    
    def add_reload_callback(self, module_id: str, callback: Callable):
        """Ajoute un callback pour le rechargement"""
        self.reloader.add_reload_callback(module_id, callback)
    
    def check_all(self) -> List[str]:
        """Vérifie tous les modules"""
        return self.reloader.check_all()
    
    def cleanup(self):
        """Nettoie les ressources"""
        self.stop_watching()


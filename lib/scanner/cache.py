#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner Cache - Système de cache pour éviter les requêtes HTTP redondantes
"""

import hashlib
import threading
import time
from typing import Optional, Dict, Any, Tuple
from copy import deepcopy


class CachedResponse:
    """
    Wrapper pour une réponse HTTP mise en cache.
    Simule l'interface de requests.Response pour compatibilité.
    """
    
    def __init__(self, response):
        """Crée un wrapper autour d'une réponse requests.Response"""
        # Copier les attributs importants
        self.status_code = response.status_code
        self.headers = dict(response.headers)  # Copie du dict
        self.text = response.text
        self.content = response.content
        self.url = response.url
        self.reason = getattr(response, 'reason', '')
        self.encoding = response.encoding
        self.cookies = dict(response.cookies) if hasattr(response, 'cookies') else {}
        
        # Préserver l'objet original pour les attributs non copiés
        self._original = response
    
    def __getattr__(self, name):
        """Délègue les attributs non copiés à l'objet original"""
        if hasattr(self._original, name):
            return getattr(self._original, name)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")
    
    def json(self):
        """Parse JSON si disponible"""
        try:
            import json
            return json.loads(self.text)
        except:
            return None


class ScannerCache:
    """
    Cache thread-safe pour les requêtes HTTP des modules scanner.
    
    Évite de faire plusieurs fois la même requête HTTP lors de l'exécution
    de nombreux modules en parallèle.
    """
    
    def __init__(self, ttl: int = 300):
        """
        Args:
            ttl: Time To Live en secondes (par défaut 5 minutes)
        """
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()  # Reentrant lock pour thread-safety
        self._ttl = ttl
        self._hits = 0
        self._misses = 0
    
    def _make_key(self, method: str, url: str, headers: Optional[Dict] = None, 
                  data: Optional[Any] = None) -> str:
        """
        Crée une clé unique pour une requête.
        
        Args:
            method: Méthode HTTP (GET, POST, etc.)
            url: URL complète
            headers: Headers optionnels
            data: Données optionnelles (POST, etc.)
        
        Returns:
            str: Clé de cache (hash)
        """
        # Normaliser l'URL (enlever trailing slash, etc.)
        url_normalized = url.rstrip('/') or '/'
        
        # Créer une chaîne représentant la requête
        parts = [method.upper(), url_normalized]
        
        # Ajouter headers si présents (trier pour avoir une clé stable)
        if headers:
            sorted_headers = sorted(headers.items())
            parts.append(f"headers:{sorted_headers}")
        
        # Ajouter data si présent
        if data:
            if isinstance(data, dict):
                sorted_data = sorted(data.items())
                parts.append(f"data:{sorted_data}")
            else:
                parts.append(f"data:{str(data)}")
        
        # Créer un hash de la clé
        key_string = "|".join(str(p) for p in parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def get(self, method: str, url: str, headers: Optional[Dict] = None,
            data: Optional[Any] = None) -> Optional[Any]:
        """
        Récupère une réponse depuis le cache.
        
        Args:
            method: Méthode HTTP
            url: URL complète
            headers: Headers optionnels
            data: Données optionnelles
        
        Returns:
            CachedResponse si trouvé et valide, None sinon
        """
        key = self._make_key(method, url, headers, data)
        
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                
                # Vérifier si l'entrée est encore valide (TTL)
                if time.time() - entry['timestamp'] < self._ttl:
                    self._hits += 1
                    # Retourner une nouvelle instance de CachedResponse
                    return CachedResponse(entry['response'])
                else:
                    # Expiré, supprimer
                    del self._cache[key]
            
            self._misses += 1
            return None
    
    def set(self, method: str, url: str, response: Any,
            headers: Optional[Dict] = None, data: Optional[Any] = None):
        """
        Stocke une réponse dans le cache.
        
        Args:
            method: Méthode HTTP
            url: URL complète
            response: Objet response à mettre en cache
            headers: Headers optionnels (pour la clé)
            data: Données optionnelles (pour la clé)
        """
        key = self._make_key(method, url, headers, data)
        
        with self._lock:
            # Stocker la réponse originale (elle sera wrappée dans get())
            self._cache[key] = {
                'response': response,  # Stocker l'original, pas de deepcopy
                'timestamp': time.time(),
                'method': method,
                'url': url
            }
    
    def clear(self):
        """Vide le cache"""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
    
    def stats(self) -> Dict[str, Any]:
        """
        Retourne les statistiques du cache.
        
        Returns:
            dict: Statistiques (hits, misses, hit_rate, size)
        """
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0
            
            return {
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': f"{hit_rate:.1f}%",
                'size': len(self._cache),
                'ttl': self._ttl
            }
    
    def cleanup_expired(self):
        """Supprime les entrées expirées du cache"""
        current_time = time.time()
        
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if current_time - entry['timestamp'] >= self._ttl
            ]
            
            for key in expired_keys:
                del self._cache[key]
            
            return len(expired_keys)


# Instance globale du cache (partagée entre tous les modules)
_global_cache: Optional[ScannerCache] = None
_cache_lock = threading.Lock()
_cache_enabled = True  # Flag global pour activer/désactiver le cache


def get_cache() -> ScannerCache:
    """
    Récupère l'instance globale du cache (singleton thread-safe).
    
    Returns:
        ScannerCache: Instance du cache
    """
    global _global_cache
    
    if _global_cache is None:
        with _cache_lock:
            if _global_cache is None:
                _global_cache = ScannerCache()
    
    return _global_cache


def reset_cache():
    """Réinitialise le cache global (utile entre deux scans)"""
    global _global_cache
    with _cache_lock:
        if _global_cache:
            _global_cache.clear()
        _global_cache = None


def disable_cache():
    """Désactive le cache global"""
    global _cache_enabled
    _cache_enabled = False


def enable_cache():
    """Active le cache global"""
    global _cache_enabled
    _cache_enabled = True


def is_cache_enabled() -> bool:
    """Vérifie si le cache est activé"""
    return _cache_enabled

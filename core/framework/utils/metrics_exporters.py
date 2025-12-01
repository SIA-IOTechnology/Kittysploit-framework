#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Système d'export de métriques pour télémétrie temps réel
Supporte stdout structuré, fichiers JSONL, et sockets
"""

import json
import socket
import threading
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
import sys


class MetricsExporter(ABC):
    """Interface abstraite pour les exporteurs de métriques"""
    
    @abstractmethod
    def export(self, metric_type: str, metric_name: str, value: Any, 
               metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Exporte une métrique
        
        Args:
            metric_type: Type de métrique ('counter', 'timing', 'value')
            metric_name: Nom de la métrique
            value: Valeur de la métrique
            metadata: Métadonnées supplémentaires (timestamp, module, etc.)
            
        Returns:
            bool: True si l'export a réussi, False sinon
        """
        pass
    
    @abstractmethod
    def flush(self) -> bool:
        """
        Force l'écriture des données en attente
        
        Returns:
            bool: True si le flush a réussi
        """
        pass
    
    @abstractmethod
    def close(self) -> bool:
        """
        Ferme l'exporteur et libère les ressources
        
        Returns:
            bool: True si la fermeture a réussi
        """
        pass


class StdoutExporter(MetricsExporter):
    """Exporteur vers stdout avec format JSON structuré"""
    
    def __init__(self, pretty: bool = False):
        """
        Args:
            pretty: Si True, formate le JSON de manière lisible
        """
        self.pretty = pretty
        self.enabled = True
    
    def export(self, metric_type: str, metric_name: str, value: Any,
               metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Exporte vers stdout en JSON"""
        if not self.enabled:
            return False
        
        try:
            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "type": "metric",
                "metric_type": metric_type,
                "metric_name": metric_name,
                "value": value
            }
            
            if metadata:
                event["metadata"] = metadata
            
            if self.pretty:
                output = json.dumps(event, indent=2, ensure_ascii=False)
            else:
                output = json.dumps(event, ensure_ascii=False)
            
            print(output, file=sys.stdout, flush=True)
            return True
        except Exception as e:
            print(f"Error exporting metric to stdout: {e}", file=sys.stderr)
            return False
    
    def flush(self) -> bool:
        """Flush stdout"""
        try:
            sys.stdout.flush()
            return True
        except Exception:
            return False
    
    def close(self) -> bool:
        """Fermeture (stdout reste ouvert)"""
        self.enabled = False
        return True


class JSONLFileExporter(MetricsExporter):
    """Exporteur vers fichier JSONL (JSON Lines)"""
    
    def __init__(self, file_path: str, append: bool = True):
        """
        Args:
            file_path: Chemin vers le fichier de sortie
            append: Si True, ajoute au fichier existant, sinon écrase
        """
        self.file_path = Path(file_path)
        self.append = append
        self.file_handle = None
        self.lock = threading.Lock()
        self._open_file()
    
    def _open_file(self):
        """Ouvre le fichier pour écriture"""
        try:
            # Créer le répertoire parent si nécessaire
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            
            mode = 'a' if self.append else 'w'
            self.file_handle = open(self.file_path, mode, encoding='utf-8')
        except Exception as e:
            print(f"Error opening metrics file {self.file_path}: {e}", file=sys.stderr)
            self.file_handle = None
    
    def export(self, metric_type: str, metric_name: str, value: Any,
               metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Exporte vers fichier JSONL"""
        if not self.file_handle:
            return False
        
        try:
            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "type": "metric",
                "metric_type": metric_type,
                "metric_name": metric_name,
                "value": value
            }
            
            if metadata:
                event["metadata"] = metadata
            
            with self.lock:
                json_line = json.dumps(event, ensure_ascii=False)
                self.file_handle.write(json_line + '\n')
                self.file_handle.flush()
            
            return True
        except Exception as e:
            print(f"Error writing metric to file: {e}", file=sys.stderr)
            return False
    
    def flush(self) -> bool:
        """Force l'écriture sur disque"""
        if not self.file_handle:
            return False
        
        try:
            with self.lock:
                self.file_handle.flush()
            return True
        except Exception:
            return False
    
    def close(self) -> bool:
        """Ferme le fichier"""
        if self.file_handle:
            try:
                with self.lock:
                    self.file_handle.close()
                self.file_handle = None
                return True
            except Exception:
                return False
        return True


class SocketExporter(MetricsExporter):
    """Exporteur vers socket pour télémétrie temps réel"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 8125, 
                 protocol: str = 'tcp', reconnect: bool = True):
        """
        Args:
            host: Adresse du serveur
            port: Port du serveur
            protocol: 'tcp' ou 'udp'
            reconnect: Si True, tente de reconnecter en cas d'échec
        """
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.reconnect = reconnect
        self.socket = None
        self.lock = threading.Lock()
        self.connected = False
        self._connect()
    
    def _connect(self):
        """Établit la connexion socket"""
        try:
            if self.protocol == 'tcp':
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(5.0)
                self.socket.connect((self.host, self.port))
            else:  # UDP
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            self.connected = True
        except Exception as e:
            print(f"Error connecting to socket {self.host}:{self.port}: {e}", file=sys.stderr)
            self.connected = False
            self.socket = None
    
    def export(self, metric_type: str, metric_name: str, value: Any,
               metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Exporte vers socket"""
        if not self.connected or not self.socket:
            if self.reconnect:
                self._connect()
            if not self.connected:
                return False
        
        try:
            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "type": "metric",
                "metric_type": metric_type,
                "metric_name": metric_name,
                "value": value
            }
            
            if metadata:
                event["metadata"] = metadata
            
            data = json.dumps(event, ensure_ascii=False).encode('utf-8')
            
            with self.lock:
                if self.protocol == 'tcp':
                    # Pour TCP, envoyer la taille puis les données
                    size = len(data).to_bytes(4, byteorder='big')
                    self.socket.sendall(size + data)
                else:  # UDP
                    self.socket.sendto(data, (self.host, self.port))
            
            return True
        except Exception as e:
            print(f"Error sending metric to socket: {e}", file=sys.stderr)
            self.connected = False
            if self.reconnect:
                self._connect()
            return False
    
    def flush(self) -> bool:
        """Flush socket (NOP pour UDP, peut être utile pour TCP)"""
        return self.connected
    
    def close(self) -> bool:
        """Ferme la connexion socket"""
        if self.socket:
            try:
                with self.lock:
                    self.socket.close()
                self.socket = None
                self.connected = False
                return True
            except Exception:
                return False
        return True


class MetricsAggregator:
    """Agrégateur de métriques pour tableaux de bord"""
    
    def __init__(self):
        self.aggregations: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
    
    def update(self, metric_name: str, value: float, metadata: Optional[Dict[str, Any]] = None):
        """Met à jour les agrégations pour une métrique"""
        with self.lock:
            if metric_name not in self.aggregations:
                self.aggregations[metric_name] = {
                    "count": 0,
                    "sum": 0.0,
                    "min": float('inf'),
                    "max": float('-inf'),
                    "values": [],
                    "last_update": None,
                    "metadata": {}
                }
            
            agg = self.aggregations[metric_name]
            agg["count"] += 1
            agg["sum"] += value
            agg["min"] = min(agg["min"], value)
            agg["max"] = max(agg["max"], value)
            agg["values"].append(value)
            agg["last_update"] = datetime.utcnow().isoformat() + "Z"
            
            # Garder seulement les N dernières valeurs pour éviter la croissance infinie
            if len(agg["values"]) > 1000:
                agg["values"] = agg["values"][-1000:]
            
            if metadata:
                # Fusionner les métadonnées (ex: module name, workspace)
                for key, val in metadata.items():
                    if key not in agg["metadata"]:
                        agg["metadata"][key] = []
                    agg["metadata"][key].append(val)
                    # Garder seulement les 100 dernières valeurs par clé
                    if len(agg["metadata"][key]) > 100:
                        agg["metadata"][key] = agg["metadata"][key][-100:]
    
    def get_stats(self, metric_name: str) -> Optional[Dict[str, Any]]:
        """Récupère les statistiques agrégées pour une métrique"""
        with self.lock:
            if metric_name not in self.aggregations:
                return None
            
            agg = self.aggregations[metric_name]
            values = agg["values"]
            
            if not values:
                return None
            
            stats = {
                "count": agg["count"],
                "sum": agg["sum"],
                "min": agg["min"] if agg["min"] != float('inf') else 0,
                "max": agg["max"] if agg["max"] != float('-inf') else 0,
                "avg": agg["sum"] / agg["count"],
                "last_update": agg["last_update"],
                "metadata": agg["metadata"]
            }
            
            # Calculer la médiane si on a des valeurs
            if values:
                sorted_values = sorted(values)
                n = len(sorted_values)
                if n % 2 == 0:
                    stats["median"] = (sorted_values[n//2 - 1] + sorted_values[n//2]) / 2
                else:
                    stats["median"] = sorted_values[n//2]
            
            return stats
    
    def get_module_stats(self, module_name: str) -> Dict[str, Any]:
        """Récupère les statistiques pour un module spécifique"""
        with self.lock:
            module_metrics = {}
            for metric_name, agg in self.aggregations.items():
                if 'module' in agg.get("metadata", {}):
                    modules = agg["metadata"]["module"]
                    if module_name in modules:
                        stats = self.get_stats(metric_name)
                        if stats:
                            module_metrics[metric_name] = stats
            
            return module_metrics
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Récupère toutes les statistiques agrégées"""
        with self.lock:
            return {
                name: self.get_stats(name)
                for name in self.aggregations.keys()
            }
    
    def reset(self, metric_name: Optional[str] = None):
        """Réinitialise les agrégations"""
        with self.lock:
            if metric_name:
                if metric_name in self.aggregations:
                    del self.aggregations[metric_name]
            else:
                self.aggregations.clear()


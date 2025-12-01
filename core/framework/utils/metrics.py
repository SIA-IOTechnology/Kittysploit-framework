#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, List, Any, Optional
from collections import defaultdict
from datetime import datetime
import time
import threading

# Import exporters (lazy import to avoid circular dependencies)
_exporters_module = None
_aggregator_class = None

def _get_exporters_module():
    """Lazy import des exporteurs"""
    global _exporters_module
    if _exporters_module is None:
        from core.framework.utils.metrics_exporters import (
            MetricsExporter, MetricsAggregator
        )
        _exporters_module = {
            'MetricsExporter': MetricsExporter,
            'MetricsAggregator': MetricsAggregator
        }
    return _exporters_module

class MetricsCollector:
    """Collect and store metrics with real-time export capability"""
    
    def __init__(self, enable_export: bool = False):
        """
        Args:
            enable_export: Si True, active l'export automatique des métriques
        """
        self.metrics: Dict[str, List[float]] = defaultdict(list)
        self.counters: Dict[str, int] = defaultdict(int)
        self.timers: Dict[str, List[float]] = defaultdict(list)
        
        # Système d'export
        self.exporters: List[Any] = []
        self.aggregator = None
        self.enable_export = enable_export
        self.export_lock = threading.Lock()
        self.metadata_context: Dict[str, Any] = {}
        
        if enable_export:
            exporters_module = _get_exporters_module()
            MetricsAggregator = exporters_module['MetricsAggregator']
            self.aggregator = MetricsAggregator()
    
    def add_exporter(self, exporter: Any) -> bool:
        """
        Ajoute un exporteur de métriques
        
        Args:
            exporter: Instance d'un exporteur (StdoutExporter, JSONLFileExporter, etc.)
            
        Returns:
            bool: True si l'exporteur a été ajouté
        """
        exporters_module = _get_exporters_module()
        MetricsExporter = exporters_module['MetricsExporter']
        
        if not isinstance(exporter, MetricsExporter):
            return False
        
        with self.export_lock:
            self.exporters.append(exporter)
            self.enable_export = True
            if not self.aggregator:
                MetricsAggregator = exporters_module['MetricsAggregator']
                self.aggregator = MetricsAggregator()
        
        return True
    
    def remove_exporter(self, exporter: Any) -> bool:
        """Retire un exporteur"""
        with self.export_lock:
            if exporter in self.exporters:
                exporter.close()
                self.exporters.remove(exporter)
                if not self.exporters:
                    self.enable_export = False
                return True
        return False
    
    def set_metadata_context(self, **kwargs):
        """Définit le contexte de métadonnées pour les prochaines métriques"""
        self.metadata_context.update(kwargs)
    
    def clear_metadata_context(self):
        """Efface le contexte de métadonnées"""
        self.metadata_context.clear()
    
    def _export_metric(self, metric_type: str, metric_name: str, value: Any):
        """Exporte une métrique vers tous les exporteurs enregistrés"""
        if not self.enable_export or not self.exporters:
            return
        
        metadata = self.metadata_context.copy() if self.metadata_context else None
        
        with self.export_lock:
            for exporter in self.exporters:
                try:
                    exporter.export(metric_type, metric_name, value, metadata)
                except Exception:
                    # Ignorer les erreurs d'export pour ne pas interrompre l'exécution
                    pass
        
        # Mettre à jour l'agrégateur si disponible
        if self.aggregator and metric_type in ('timing', 'value'):
            try:
                float_value = float(value)
                self.aggregator.update(metric_name, float_value, metadata)
            except (ValueError, TypeError):
                pass
    
    def increment(self, metric_name: str, value: int = 1, metadata: Optional[Dict[str, Any]] = None):
        """Increment a counter"""
        self.counters[metric_name] += value
        
        # Export si activé
        if metadata:
            self.set_metadata_context(**metadata)
        self._export_metric('counter', metric_name, value)
        if metadata:
            self.clear_metadata_context()
    
    def record_timing(self, metric_name: str, duration: float, metadata: Optional[Dict[str, Any]] = None):
        """Record a timing metric"""
        self.timers[metric_name].append(duration)
        
        # Export si activé
        if metadata:
            self.set_metadata_context(**metadata)
        self._export_metric('timing', metric_name, duration)
        if metadata:
            self.clear_metadata_context()
    
    def record_value(self, metric_name: str, value: float, metadata: Optional[Dict[str, Any]] = None):
        """Record a value"""
        self.metrics[metric_name].append(value)
        
        # Export si activé
        if metadata:
            self.set_metadata_context(**metadata)
        self._export_metric('value', metric_name, value)
        if metadata:
            self.clear_metadata_context()
    
    def get_stats(self, metric_name: str) -> Dict[str, float]:
        """Get statistics for a metric"""
        values = self.metrics[metric_name] + self.timers[metric_name]
        if not values:
            return {}
        
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
            "sum": sum(values)
        }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all metrics"""
        return {
            "counters": dict(self.counters),
            "timings": {k: self.get_stats(k) for k in self.timers},
            "values": {k: self.get_stats(k) for k in self.metrics}
        }
    
    def get_aggregated_stats(self, metric_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Récupère les statistiques agrégées pour les tableaux de bord
        
        Args:
            metric_name: Nom de la métrique (None pour toutes)
            
        Returns:
            Dict contenant les statistiques agrégées
        """
        if not self.aggregator:
            return {}
        
        if metric_name:
            stats = self.aggregator.get_stats(metric_name)
            return {metric_name: stats} if stats else {}
        else:
            return self.aggregator.get_all_stats()
    
    def get_module_stats(self, module_name: str) -> Dict[str, Any]:
        """
        Récupère les statistiques pour un module spécifique
        
        Args:
            module_name: Nom du module
            
        Returns:
            Dict contenant les statistiques du module
        """
        if not self.aggregator:
            return {}
        return self.aggregator.get_module_stats(module_name)
    
    def flush_exporters(self):
        """Force l'écriture de toutes les données en attente dans les exporteurs"""
        with self.export_lock:
            for exporter in self.exporters:
                try:
                    exporter.flush()
                except Exception:
                    pass
    
    def close_exporters(self):
        """Ferme tous les exporteurs"""
        with self.export_lock:
            for exporter in self.exporters:
                try:
                    exporter.close()
                except Exception:
                    pass
            self.exporters.clear()
            self.enable_export = False
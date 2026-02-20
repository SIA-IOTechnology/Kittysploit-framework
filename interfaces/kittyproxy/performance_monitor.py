#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Performance Monitor - Surveille les performances et la bande passante
"""

import time
from typing import Dict, List, Tuple
from collections import deque

class PerformanceMonitor:
    """Monitore les performances des requêtes HTTP"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.response_times = deque(maxlen=window_size)
        self.timeouts = deque(maxlen=window_size)
        self.bandwidth_usage = deque(maxlen=window_size)
        self.error_rates = deque(maxlen=window_size)
        self.slow_requests = []
        self.start_time = time.time()
        
    def record_request(self, flow):
        """Enregistre les métriques d'une requête"""
        if not flow.response:
            return
        
        # Calculer le temps de réponse
        if flow.response.timestamp_end and flow.request.timestamp_start:
            response_time = flow.response.timestamp_end - flow.request.timestamp_start
            self.response_times.append(response_time)
            
            # Détecter les requêtes lentes (> 1 seconde)
            if response_time > 1.0:
                self.slow_requests.append({
                    'url': flow.request.url,
                    'method': flow.request.method,
                    'response_time': response_time,
                    'status_code': flow.response.status_code,
                    'timestamp': flow.request.timestamp_start
                })
                # Garder seulement les 50 dernières
                if len(self.slow_requests) > 50:
                    self.slow_requests = self.slow_requests[-50:]
        
        # Détecter les timeouts (pas de réponse après 30 secondes)
        if not flow.response and (time.time() - flow.request.timestamp_start) > 30:
            self.timeouts.append({
                'url': flow.request.url,
                'method': flow.request.method,
                'timestamp': flow.request.timestamp_start
            })
        
        # Calculer la bande passante (safe: évite BadGzipFile si Content-Encoding gzip mais corps brut)
        request_size = len(flow.request.content) if flow.request.content else 0
        from .flow_utils import safe_response_size
        response_size = safe_response_size(flow.response) if flow.response else 0
        if response_size is None:
            response_size = 0
        total_size = request_size + response_size
        
        self.bandwidth_usage.append({
            'timestamp': flow.request.timestamp_start,
            'request_size': request_size,
            'response_size': response_size,
            'total_size': total_size,
            'url': flow.request.url
        })
        
        # Calculer le taux d'erreur
        if flow.response:
            is_error = flow.response.status_code >= 400
            self.error_rates.append({
                'timestamp': flow.request.timestamp_start,
                'is_error': is_error,
                'status_code': flow.response.status_code
            })
    
    def get_stats(self) -> Dict:
        """Retourne les statistiques de performance"""
        current_time = time.time()
        uptime = current_time - self.start_time
        
        # Statistiques de temps de réponse
        avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        max_response_time = max(self.response_times) if self.response_times else 0
        min_response_time = min(self.response_times) if self.response_times else 0
        
        # Statistiques de bande passante
        total_bandwidth = sum(bw['total_size'] for bw in self.bandwidth_usage)
        avg_request_size = sum(bw['request_size'] for bw in self.bandwidth_usage) / len(self.bandwidth_usage) if self.bandwidth_usage else 0
        avg_response_size = sum(bw['response_size'] for bw in self.bandwidth_usage) / len(self.bandwidth_usage) if self.bandwidth_usage else 0
        
        # Taux d'erreur
        error_count = sum(1 for er in self.error_rates if er['is_error'])
        error_rate = (error_count / len(self.error_rates) * 100) if self.error_rates else 0
        
        # Requêtes par seconde
        requests_per_second = len(self.response_times) / uptime if uptime > 0 else 0
        
        # Bande passante par seconde
        bandwidth_per_second = total_bandwidth / uptime if uptime > 0 else 0
        
        return {
            'uptime': uptime,
            'total_requests': len(self.response_times),
            'requests_per_second': requests_per_second,
            'response_times': {
                'avg': avg_response_time,
                'max': max_response_time,
                'min': min_response_time,
                'current': list(self.response_times)[-10:] if self.response_times else []  # Dernières 10
            },
            'bandwidth': {
                'total': total_bandwidth,
                'avg_request_size': avg_request_size,
                'avg_response_size': avg_response_size,
                'per_second': bandwidth_per_second,
                'history': list(self.bandwidth_usage)[-20:] if self.bandwidth_usage else []  # Dernières 20
            },
            'errors': {
                'count': error_count,
                'rate': error_rate,
                'recent': list(self.error_rates)[-10:] if self.error_rates else []
            },
            'timeouts': len(self.timeouts),
            'slow_requests': self.slow_requests[-10:] if self.slow_requests else [],
            'alerts': self._generate_alerts()
        }
    
    def _generate_alerts(self) -> List[Dict]:
        """Génère des alertes basées sur les métriques"""
        alerts = []
        
        # Alerte si temps de réponse moyen > 2 secondes
        if self.response_times:
            avg_time = sum(self.response_times) / len(self.response_times)
            if avg_time > 2.0:
                alerts.append({
                    'type': 'performance',
                    'severity': 'warning',
                    'message': f'High average response time: {avg_time:.2f}s',
                    'timestamp': time.time()
                })
        
        # Alerte si taux d'erreur > 10%
        if self.error_rates:
            error_count = sum(1 for er in self.error_rates if er['is_error'])
            error_rate = (error_count / len(self.error_rates) * 100)
            if error_rate > 10:
                alerts.append({
                    'type': 'error_rate',
                    'severity': 'error',
                    'message': f'High error rate: {error_rate:.1f}%',
                    'timestamp': time.time()
                })
        
        # Alerte si timeouts détectés
        if len(self.timeouts) > 0:
            alerts.append({
                'type': 'timeout',
                'severity': 'error',
                'message': f'{len(self.timeouts)} timeout(s) detected',
                'timestamp': time.time()
            })
        
        # Alerte si requêtes lentes
        if len(self.slow_requests) > 5:
            alerts.append({
                'type': 'slow_requests',
                'severity': 'warning',
                'message': f'{len(self.slow_requests)} slow request(s) detected',
                'timestamp': time.time()
            })
        
        return alerts

# Instance globale
performance_monitor = PerformanceMonitor()


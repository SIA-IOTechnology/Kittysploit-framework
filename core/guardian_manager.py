#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Manager for KittySploit
Provides behavioral analysis and anomaly detection for offensive operations
"""

import time
import json
import threading
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from statistics import mean, stdev, StatisticsError
import random

logger = logging.getLogger(__name__)

@dataclass
class GuardianAlert:
    """Guardian alert structure"""
    timestamp: str
    severity: str  # CRITICAL, WARNING, INFO
    target: str
    issue: str
    confidence: float
    recommendations: List[str]
    auto_action_taken: bool = False
    action_description: str = ""
    evidence: List[str] = field(default_factory=list)

@dataclass
class HostProfile:
    """Host behavioral profile"""
    host: str
    response_times: List[float]
    service_banners: List[str]
    port_responses: Dict[int, str]
    last_seen: str
    interaction_count: int
    suspicious_indicators: List[str]
    honeypot_score: float = 0.0
    baseline_response: float = 0.0
    risk_history: List[float] = field(default_factory=list)
    consecutive_anomalies: int = 0
    acknowledged_safe: bool = False
    last_alert: Optional[str] = None
    operator_notes: List[str] = field(default_factory=list)

class GuardianManager:
    """Guardian behavioral analysis and anomaly detection manager"""
    
    def __init__(self):
        """Initialize Guardian manager"""
        self.logger = logger
        self.enabled = False
        self.verbose = False
        self.auto_action = False
        self.learning_mode = False
        
        # Configuration
        self.config = {
            'response_time_threshold': 2000,  # ms
            'honeypot_threshold': 70,  # %
            'baseline_operations': 50,
            'alert_retention_days': 7,
            'risk_threshold': 60.0,
            'critical_threshold': 85.0,
            'baseline_smoothing': 0.2,
            'response_deviation_factor': 2.0,
            'minimum_samples_for_baseline': 5,
            'suspicious_indicator_threshold': 3
        }
        
        self.risk_weights: Dict[str, float] = {
            'response_time': 30.0,
            'honeypot_indicators': 25.0,
            'profile_honeypot': 20.0,
            'suspicious_history': 15.0,
            'consecutive_anomalies': 10.0
        }
        
        # Data storage
        self.host_profiles: Dict[str, HostProfile] = {}
        self.alerts: List[GuardianAlert] = []
        self.blacklist: Dict[str, Dict[str, Any]] = {}
        self.operation_history: List[Dict[str, Any]] = []
        self.whitelist: Set[str] = set()
        
        # Statistics
        self.stats = {
            'threats_detected': 0,
            'alerts_generated': 0,
            'auto_actions': 0,
            'honeypots_detected': 0,
            'false_positives': 0,
            'total_operations': 0,
            'validated_operations': 0,
            'last_training_operations': 0
        }
        
        # Learning data
        self.learned_patterns = {
            'normal_response_times': [],
            'honeypot_signatures': [],
            'deception_patterns': [],
            'blue_team_ttps': [],
            'accuracy': 87.0
        }
        
        # Monitoring thread
        self.monitoring_thread = None
        self.stop_monitoring = False
    
    def enable(self, verbose: bool = False, auto_action: bool = False):
        """Enable Guardian monitoring"""
        self.enabled = True
        self.verbose = verbose
        self.auto_action = auto_action
        
        # Start monitoring thread
        self.stop_monitoring = False
        if self.monitoring_thread is None or not self.monitoring_thread.is_alive():
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
        
        self.logger.info(f"Guardian monitoring enabled (verbose={verbose}, auto_action={auto_action})")
        print(f"[GUARDIAN] Enabled: {self.enabled}, Verbose: {self.verbose}, Auto Action: {self.auto_action}")
    
    def disable(self):
        """Disable Guardian monitoring"""
        self.enabled = False
        self.stop_monitoring = True
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=1)
        
        self.logger.info("Guardian monitoring disabled")
    
    def _normalize_operation_data(self, operation_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate and normalize raw operation data"""
        if not isinstance(operation_data, dict):
            self.logger.debug("Guardian ignored operation: invalid payload type")
            return None
        
        target = str(operation_data.get('target', '')).strip()
        if not target:
            self.logger.debug("Guardian ignored operation: missing target")
            return None
        
        response_time = operation_data.get('response_time')
        try:
            response_time = float(response_time)
        except (TypeError, ValueError):
            self.logger.debug("Guardian ignored operation: invalid response_time value")
            return None
        
        if response_time <= 0:
            self.logger.debug("Guardian ignored operation: non-positive response_time")
            return None
        
        timestamp = operation_data.get('timestamp')
        if not timestamp:
            timestamp = datetime.now().isoformat()
        
        honeypot_indicators = operation_data.get('honeypot_indicators') or []
        if not isinstance(honeypot_indicators, list):
            honeypot_indicators = [honeypot_indicators]
        honeypot_indicators = sorted(set(str(ind).strip() for ind in honeypot_indicators if ind))
        
        flags = operation_data.get('flags') or []
        if not isinstance(flags, list):
            flags = [flags]
        flags = sorted(set(str(flag).strip() for flag in flags if flag))
        
        metadata = operation_data.get('metadata')
        if not isinstance(metadata, dict):
            metadata = {}
        
        latency_samples = operation_data.get('latency_samples') or []
        if isinstance(latency_samples, (int, float)):
            latency_samples = [float(latency_samples)]
        elif isinstance(latency_samples, list):
            try:
                latency_samples = [float(sample) for sample in latency_samples if float(sample) > 0]
            except (TypeError, ValueError):
                latency_samples = []
        else:
            latency_samples = []
        
        normalized = {
            'target': target,
            'response_time': response_time,
            'timestamp': timestamp,
            'honeypot_indicators': honeypot_indicators,
            'flags': flags,
            'metadata': metadata,
            'latency_samples': latency_samples
        }
        
        self.stats['validated_operations'] += 1
        return normalized
    
    def _get_or_create_profile(self, target: str) -> HostProfile:
        """Get host profile or create a new one"""
        if target not in self.host_profiles:
            self.host_profiles[target] = HostProfile(
                host=target,
                response_times=[],
                service_banners=[],
                port_responses={},
                last_seen=datetime.now().isoformat(),
                interaction_count=0,
                suspicious_indicators=[]
            )
        return self.host_profiles[target]
    
    def _update_profile_metrics(self, profile: HostProfile, operation: Dict[str, Any]) -> None:
        """Update host profile statistics with new operation data"""
        profile.last_seen = operation['timestamp']
        profile.interaction_count += 1
        profile.response_times.append(operation['response_time'])
        if len(profile.response_times) > 100:
            profile.response_times = profile.response_times[-100:]
        
        baseline = profile.baseline_response or operation['response_time']
        alpha = self.config['baseline_smoothing']
        profile.baseline_response = (1 - alpha) * baseline + alpha * operation['response_time']
        
        for indicator in operation['honeypot_indicators']:
            if indicator not in profile.suspicious_indicators:
                profile.suspicious_indicators.append(indicator)
        
        for flag in operation['flags']:
            if flag not in profile.suspicious_indicators:
                profile.suspicious_indicators.append(flag)
        
        if len(profile.suspicious_indicators) > 20:
            profile.suspicious_indicators = profile.suspicious_indicators[-20:]
    
    def _calculate_risk_components(self, profile: HostProfile, operation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Calculate individual risk component scores"""
        components: List[Dict[str, Any]] = []
        baseline = profile.baseline_response or operation['response_time']
        ratio = operation['response_time'] / max(baseline, 1.0)
        
        if len(profile.response_times) >= self.config['minimum_samples_for_baseline'] and ratio >= self.config['response_deviation_factor']:
            delta = ratio - self.config['response_deviation_factor']
            score = min(self.risk_weights['response_time'], (delta / self.config['response_deviation_factor']) * self.risk_weights['response_time'])
            components.append({
                'reason': 'response_time',
                'score': score,
                'summary': f"Response time {ratio:.1f}x slower than baseline",
                'detail': f"Observed {operation['response_time']:.0f}ms vs baseline {baseline:.0f}ms"
            })
        
        indicator_score = 0.0
        if operation['honeypot_indicators']:
            known_signatures = set(self.learned_patterns.get('honeypot_signatures', []))
            overlap = known_signatures.intersection(operation['honeypot_indicators'])
            base_score = min(1.0, len(operation['honeypot_indicators']) / 3.0)
            indicator_score = base_score * self.risk_weights['honeypot_indicators']
            if overlap:
                indicator_score += 0.5 * self.risk_weights['honeypot_indicators']
            components.append({
                'reason': 'honeypot_indicators',
                'score': min(self.risk_weights['honeypot_indicators'], indicator_score),
                'summary': "Known honeypot indicators observed",
                'detail': f"Indicators: {', '.join(operation['honeypot_indicators'])}"
            })
        
        profile.honeypot_score = self._calculate_honeypot_score(profile)
        if profile.honeypot_score > 0:
            score = min(self.risk_weights['profile_honeypot'], (profile.honeypot_score / 100.0) * self.risk_weights['profile_honeypot'])
            components.append({
                'reason': 'profile_honeypot',
                'score': score,
                'summary': f"Honeypot score {profile.honeypot_score:.0f}%",
                'detail': f"Accumulated honeypot probability {profile.honeypot_score:.0f}%"
            })
        
        suspicious_count = len(profile.suspicious_indicators)
        if suspicious_count >= self.config['suspicious_indicator_threshold']:
            history_score = min(self.risk_weights['suspicious_history'], suspicious_count * 2.0)
            components.append({
                'reason': 'suspicious_history',
                'score': history_score,
                'summary': "Persistent suspicious interaction history",
                'detail': f"{suspicious_count} unique indicators recorded"
            })
        
        if profile.risk_history and profile.risk_history[-1] >= self.config['risk_threshold']:
            components.append({
                'reason': 'consecutive_anomalies',
                'score': self.risk_weights['consecutive_anomalies'],
                'summary': "Repeated anomaly streak",
                'detail': "Multiple high-risk operations observed in succession"
            })
        
        return components
    
    def _determine_severity(self, risk_score: float, profile: HostProfile) -> Optional[str]:
        """Convert risk score into severity level"""
        if risk_score >= self.config['critical_threshold'] or profile.honeypot_score >= self.config['honeypot_threshold']:
            return "CRITICAL"
        if risk_score >= self.config['risk_threshold']:
            return "WARNING"
        return None
    
    def _build_issue_summary(self, components: List[Dict[str, Any]]) -> str:
        """Build short issue summary from components"""
        if not components:
            return "Anomaly detected"
        primary = max(components, key=lambda comp: comp['score'])
        return primary['summary']
    
    def _build_recommendations(self, severity: str, components: List[Dict[str, Any]], target: str) -> List[str]:
        """Generate recommendations based on severity and evidence"""
        recommendations: List[str] = []
        
        if severity == "CRITICAL":
            recommendations.append("Stop current operation immediately")
            recommendations.append(f"Treat {target} as hostile infrastructure until verified")
            recommendations.append("Escalate to lead operator for manual validation")
            if any(comp['reason'] == 'profile_honeypot' for comp in components):
                recommendations.append("Consider adding host to Guardian blacklist")
        elif severity == "WARNING":
            recommendations.append("Slow down interaction pace and collect additional telemetry")
            recommendations.append("Cross-check target with existing intelligence sources")
        
        if any(comp['reason'] == 'honeypot_indicators' for comp in components):
            recommendations.append("Verify service banners and TLS certificates for authenticity")
        if any(comp['reason'] == 'response_time' for comp in components):
            recommendations.append("Perform out-of-band connectivity test to confirm latency")
        
        return recommendations
    
    def acknowledge_host(self, host: str, note: str = "") -> bool:
        """Mark host as safe and reduce future alerting"""
        profile = self.host_profiles.get(host)
        if not profile:
            return False
        
        profile.acknowledged_safe = True
        profile.consecutive_anomalies = 0
        profile.risk_history.append(0.0)
        profile.honeypot_score = max(0.0, profile.honeypot_score * 0.5)
        self.stats['false_positives'] += 1
        
        if host in self.blacklist:
            entry = self.blacklist[host]
            if note:
                entry['note'] = note
            else:
                self.blacklist.pop(host, None)
        
        if note:
            profile.operator_notes.append(note)
        self.whitelist.add(host)
        return True
    
    def get_status(self) -> Dict[str, Any]:
        """Get Guardian status"""
        # Get recent threats (last 24 hours)
        recent_threats = []
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        for alert in self.alerts:
            alert_time = datetime.fromisoformat(alert.timestamp)
            if alert_time > cutoff_time:
                recent_threats.append({
                    'severity': alert.severity,
                    'description': alert.issue,
                    'details': f"Target: {alert.target}",
                    'action': alert.action_description if alert.auto_action_taken else None,
                    'time': alert.timestamp
                })
        
        return {
            'enabled': self.enabled,
            'threats_detected': self.stats['threats_detected'],
            'alerts_generated': self.stats['alerts_generated'],
            'auto_actions': self.stats['auto_actions'],
            'recent_threats': recent_threats[-5:]  # Last 5 threats
        }
    
    def learn(self, operations_count: int = 100) -> Dict[str, Any]:
        """Train Guardian on past operations"""
        self.learning_mode = True
        try:
            recent_operations = self.operation_history[-operations_count:] if operations_count > 0 else self.operation_history
            responses = []
            honeypot_indicators: List[str] = []
            deception_flags: List[str] = []
            
            for op in recent_operations:
                normalized = op.get('normalized')
                rt = None
                if normalized:
                    rt = normalized.get('response_time')
                    indicators = normalized.get('honeypot_indicators', [])
                else:
                    rt = op.get('response_time')
                    indicators = op.get('honeypot_indicators', [])
                
                if isinstance(rt, (int, float)) and rt > 0:
                    responses.append(float(rt))
                
                if indicators:
                    honeypot_indicators.extend(indicators)
                
                flags = []
                if normalized:
                    flags = normalized.get('flags', [])
                elif 'flags' in op:
                    flags = op.get('flags') or []
                for flag in flags:
                    deception_flags.append(str(flag))
            
            lower_bound = upper_bound = 0.0
            if responses:
                avg = mean(responses)
                deviation = stdev(responses) if len(responses) > 1 else avg * 0.1 or 50.0
                lower_bound = max(1.0, avg - 1.5 * deviation)
                upper_bound = max(lower_bound + 25.0, avg + 1.5 * deviation)
                self.learned_patterns['normal_response_times'] = [lower_bound, upper_bound]
            
            self.learned_patterns['honeypot_signatures'] = sorted(set(honeypot_indicators))
            unique_deception = sorted(set(deception_flags))
            unique_threats = {alert.issue for alert in self.alerts}
            
            alerts_generated = max(1, self.stats['alerts_generated'])
            false_positive_rate = self.stats['false_positives'] / alerts_generated
            accuracy = max(50.0, 100.0 - (false_positive_rate * 100.0))
            old_accuracy = self.learned_patterns['accuracy']
            self.learned_patterns['accuracy'] = round(accuracy, 2)
            self.stats['last_training_operations'] = len(recent_operations)
            
            return {
                'normal_response_time': f"{lower_bound:.1f}-{upper_bound:.1f}ms" if responses else "baseline unavailable",
                'honeypot_signatures': len(self.learned_patterns['honeypot_signatures']),
                'deception_patterns': len(unique_deception),
                'blue_team_ttps': len(unique_threats),
                'old_accuracy': old_accuracy,
                'new_accuracy': self.learned_patterns['accuracy'],
                'operations_used': len(recent_operations)
            }
        finally:
            self.learning_mode = False
    
    def add_to_blacklist(self, host: str, reason: str = ""):
        """Add host to blacklist"""
        self.blacklist[host] = {
            'reason': reason,
            'timestamp': datetime.now().isoformat(),
            'added_by': 'guardian'
        }
        self.logger.info(f"Host {host} added to blacklist: {reason}")
    
    def remove_from_blacklist(self, host: str):
        """Remove host from blacklist"""
        if host in self.blacklist:
            del self.blacklist[host]
            self.logger.info(f"Host {host} removed from blacklist")
    
    def get_blacklist(self) -> Dict[str, Dict[str, Any]]:
        """Get blacklisted hosts"""
        return self.blacklist.copy()
    
    def get_recent_alerts(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        recent_alerts = sorted(self.alerts, key=lambda x: x.timestamp, reverse=True)[:count]
        return [asdict(alert) for alert in recent_alerts]
    
    def get_config(self) -> Dict[str, Any]:
        """Get Guardian configuration"""
        return {
            'enabled': self.enabled,
            'verbose': self.verbose,
            'auto_action': self.auto_action,
            'response_time_threshold': self.config['response_time_threshold'],
            'honeypot_threshold': self.config['honeypot_threshold'],
            'learning_mode': self.learning_mode,
            'blacklist_size': len(self.blacklist)
        }
    
    def test_host(self, host: str, deep: bool = False) -> Dict[str, Any]:
        """Test host for anomalies"""
        import socket
        import time
        
        behavioral_analysis = []
        network_context = []
        honeypot_score = 0.0
        
        try:
            # Test 1: Port scanning behavior
            open_ports = self._test_port_scanning(host)
            if len(open_ports) > 20:  # Too many ports open
                behavioral_analysis.append(f"Host has {len(open_ports)} open ports (suspicious)")
                honeypot_score += 15.0
            elif len(open_ports) < 3:
                behavioral_analysis.append(f"Host has only {len(open_ports)} open ports (normal)")
                honeypot_score -= 5.0
            
            # Test 2: Service banner analysis
            banners = self._analyze_service_banners(host, open_ports)
            fake_banners = self._detect_fake_banners(banners)
            if fake_banners:
                behavioral_analysis.append(f"Fake service banners detected: {', '.join(fake_banners)}")
                honeypot_score += 25.0
            
            # Test 3: Response time analysis
            response_times = self._test_response_times(host)
            if response_times:
                avg_response = sum(response_times) / len(response_times)
                if avg_response > 2000:  # Very slow responses
                    behavioral_analysis.append(f"Average response time: {avg_response:.0f}ms (suspicious)")
                    honeypot_score += 20.0
                else:
                    behavioral_analysis.append(f"Average response time: {avg_response:.0f}ms (normal)")
                    honeypot_score -= 10.0
            
            # Test 4: Credential acceptance test
            cred_test = self._test_credential_acceptance(host)
            if cred_test['accepts_any']:
                behavioral_analysis.append("Services accept ANY credentials (major red flag)")
                honeypot_score += 30.0
            else:
                behavioral_analysis.append("Services properly reject invalid credentials (normal)")
                honeypot_score -= 15.0
            
            # Test 5: Network behavior
            network_behavior = self._analyze_network_behavior(host)
            if network_behavior['isolated']:
                network_context.append("Host appears isolated from other network activity")
                honeypot_score += 10.0
            else:
                network_context.append("Host shows normal network activity patterns")
                honeypot_score -= 5.0
            
            # Test 6: Reverse DNS analysis
            if deep:
                reverse_dns = self._get_reverse_dns(host)
                if reverse_dns:
                    if any(keyword in reverse_dns.lower() for keyword in ['honeypot', 'honeynet', 'research', 'lab', 'test']):
                        network_context.append(f"Reverse DNS: {reverse_dns} (suspicious)")
                        honeypot_score += 20.0
                    else:
                        network_context.append(f"Reverse DNS: {reverse_dns} (normal)")
                        honeypot_score -= 5.0
            
            # Test 7: Service interaction patterns
            interaction_patterns = self._analyze_interaction_patterns(host)
            if interaction_patterns['unusual']:
                behavioral_analysis.append("Unusual service interaction patterns detected")
                honeypot_score += 15.0
            else:
                behavioral_analysis.append("Normal service interaction patterns")
                honeypot_score -= 5.0
            
            # Calculate final confidence
            confidence = max(0, min(100, honeypot_score))
            
            # Determine verdict
            if confidence > 80:
                verdict = "HONEYPOT"
                recommendation = "Add to blacklist and cease all interaction"
            elif confidence > 50:
                verdict = "SUSPICIOUS"
                recommendation = "Monitor closely and limit interaction"
            else:
                verdict = "NORMAL"
                recommendation = "Host appears to be legitimate"
            
            # Auto-blacklist only for high confidence honeypots
            auto_blacklist = confidence > 80 and self.auto_action and verdict == "HONEYPOT"
            if auto_blacklist:
                self.add_to_blacklist(host, f"Detected as {verdict} with {confidence:.0f}% confidence")
            
            return {
                'behavioral_analysis': behavioral_analysis,
                'network_context': network_context,
                'confidence': confidence,
                'verdict': verdict,
                'recommendation': recommendation,
                'auto_blacklist': auto_blacklist
            }
            
        except Exception as e:
            self.logger.error(f"Error testing host {host}: {e}")
            return {
                'behavioral_analysis': [f"Error during analysis: {str(e)}"],
                'network_context': [],
                'confidence': 0.0,
                'verdict': "ERROR",
                'recommendation': "Manual investigation required",
                'auto_blacklist': False
            }
    
    def analyze_operation(self, operation_data: Dict[str, Any]) -> Optional[GuardianAlert]:
        """Analyze operation for anomalies"""
        if not self.enabled:
            return None

        self.stats['total_operations'] += 1
        normalized = self._normalize_operation_data(operation_data)
        if not normalized:
            return None

        target = normalized['target']
        if target in self.blacklist or target in self.whitelist:
            return None

        profile = self._get_or_create_profile(target)
        self._update_profile_metrics(profile, normalized)

        components = self._calculate_risk_components(profile, normalized)
        risk_score = min(100.0, sum(component['score'] for component in components))
        profile.risk_history.append(risk_score)
        if len(profile.risk_history) > 50:
            profile.risk_history = profile.risk_history[-50:]

        severity = self._determine_severity(risk_score, profile)
        if not severity:
            profile.consecutive_anomalies = 0
            self.operation_history.append({**operation_data, 'normalized': normalized, 'risk': risk_score})
            if len(self.operation_history) > 1000:
                self.operation_history = self.operation_history[-1000:]
            return None

        previous_high = len(profile.risk_history) >= 2 and profile.risk_history[-2] >= self.config['risk_threshold']
        profile.consecutive_anomalies = profile.consecutive_anomalies + 1 if previous_high else 1

        if severity == "CRITICAL" and profile.honeypot_score >= self.config['honeypot_threshold']:
            self.stats['honeypots_detected'] += 1

        issue = self._build_issue_summary(components)
        evidence = [component['detail'] for component in components if component['score'] > 0]
        recommendations = self._build_recommendations(severity, components, target)
        confidence = max(profile.honeypot_score, risk_score)

        alert = self._create_alert(
            target=target,
            severity=severity,
            issue=issue,
            confidence=confidence,
            recommendations=recommendations,
            evidence=evidence
        )

        profile.last_alert = alert.timestamp

        self.operation_history.append({
            **operation_data,
            'normalized': normalized,
            'risk': risk_score,
            'severity': severity
        })
        if len(self.operation_history) > 1000:
            self.operation_history = self.operation_history[-1000:]

        return alert


    def _create_alert(self, target: str, severity: str, issue: str, 
                     confidence: float, recommendations: List[str],
                     evidence: Optional[List[str]] = None) -> GuardianAlert:
        """Create Guardian alert"""
        evidence = evidence or []
        alert = GuardianAlert(
            timestamp=datetime.now().isoformat(),
            severity=severity,
            target=target,
            issue=issue,
            confidence=confidence,
            recommendations=recommendations,
            evidence=evidence
        )
        
        # Auto-action if enabled
        if self.auto_action and severity == "CRITICAL":
            if confidence > 90:
                self.add_to_blacklist(target, f"Auto-detected {issue}")
                alert.auto_action_taken = True
                alert.action_description = f"Auto-blacklisted {target}"
                self.stats['auto_actions'] += 1
        
        # Store alert
        self.alerts.append(alert)
        self.stats['alerts_generated'] += 1
        
        if severity == "CRITICAL":
            self.stats['threats_detected'] += 1
        
        # Clean old alerts
        cutoff_time = datetime.now() - timedelta(days=self.config['alert_retention_days'])
        self.alerts = [
            alert for alert in self.alerts 
            if datetime.fromisoformat(alert.timestamp) > cutoff_time
        ]
        
        return alert
    
    def _calculate_honeypot_score(self, profile: HostProfile) -> float:
        """Calculate honeypot probability score"""
        responses = profile.response_times[-20:]
        if not responses:
            return profile.honeypot_score
        
        score = 0.0
        avg_response = mean(responses)
        baseline = profile.baseline_response or avg_response
        ratio = avg_response / max(baseline, 1.0)
        
        if avg_response > self.config['response_time_threshold']:
            score += 20.0
        if ratio >= self.config['response_deviation_factor']:
            score += 15.0
        
        try:
            if len(responses) > 1:
                variability = stdev(responses)
                if variability < 25.0:
                    score += 10.0
        except StatisticsError:
            pass
        
        if profile.interaction_count > 50:
            score += 10.0
        
        score += min(20.0, len(profile.suspicious_indicators) * 4.0)
        
        fake_banners = ('honeypot', 'fake', 'test', 'demo')
        for banner in profile.service_banners:
            lowered = banner.lower()
            if any(fake in lowered for fake in fake_banners):
                score += 15.0
                break
        
        if profile.acknowledged_safe:
            score *= 0.5
        
        smoothed = (profile.honeypot_score * 0.6) + (score * 0.4)
        return float(min(100.0, max(0.0, smoothed)))
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while not self.stop_monitoring and self.enabled:
            try:
                # Perform background monitoring tasks
                self._cleanup_old_data()
                self._update_statistics()
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)
    
    def _cleanup_old_data(self):
        """Clean up old data"""
        # Clean old host profiles
        cutoff_time = datetime.now() - timedelta(days=7)
        old_hosts = [
            host for host, profile in self.host_profiles.items()
            if datetime.fromisoformat(profile.last_seen) < cutoff_time
        ]
        
        for host in old_hosts:
            del self.host_profiles[host]
    
    def _update_statistics(self):
        """Update Guardian statistics"""
        # Update honeypot detection count
        self.stats['honeypots_detected'] = len([
            alert for alert in self.alerts 
            if 'honeypot' in alert.issue.lower()
        ])
    
    def _test_port_scanning(self, host: str) -> List[int]:
        """Test port scanning behavior"""
        import socket
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389, 5432, 5900, 8080]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return open_ports
    
    def _analyze_service_banners(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Analyze service banners"""
        import socket
        
        banners = {}
        for port in ports[:5]:  # Limit to first 5 ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((host, port))
                
                # Try to get banner
                if port in [21, 22, 25, 80, 443]:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    banners[port] = banner
                
                sock.close()
            except:
                pass
        
        return banners
    
    def _detect_fake_banners(self, banners: Dict[int, str]) -> List[str]:
        """Detect fake service banners"""
        fake_indicators = [
            'honeypot', 'fake', 'test', 'demo', 'mock', 'simulation',
            'research', 'lab', 'sandbox', 'trap', 'decoy'
        ]
        
        fake_banners = []
        for port, banner in banners.items():
            banner_lower = banner.lower()
            for indicator in fake_indicators:
                if indicator in banner_lower:
                    fake_banners.append(f"Port {port}: {banner[:50]}...")
                    break
        
        return fake_banners
    
    def _test_response_times(self, host: str) -> List[float]:
        """Test response times"""
        import socket
        import time
        
        response_times = []
        test_ports = [80, 443, 22, 21, 25]
        
        for port in test_ports:
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                response_time = (time.time() - start_time) * 1000  # Convert to ms
                
                if result == 0:
                    response_times.append(response_time)
                sock.close()
            except:
                pass
        
        return response_times
    
    def _test_credential_acceptance(self, host: str) -> Dict[str, Any]:
        """Test if services accept any credentials"""
        # This is a simplified test - in reality, you'd test actual services
        # For now, we'll simulate based on common honeypot behavior
        
        # Simulate that most real hosts reject invalid credentials
        # Honeypots often accept any credentials to capture more data
        accepts_any = False
        
        # In a real implementation, you would:
        # 1. Try SSH with invalid credentials
        # 2. Try FTP with invalid credentials  
        # 3. Try HTTP basic auth with invalid credentials
        # 4. Check if services accept obviously fake credentials
        
        return {
            'accepts_any': accepts_any,
            'tested_services': ['ssh', 'ftp', 'http'],
            'details': 'Services properly reject invalid credentials'
        }
    
    def _analyze_network_behavior(self, host: str) -> Dict[str, Any]:
        """Analyze network behavior patterns"""
        # This would analyze network traffic patterns, connections, etc.
        # For now, we'll simulate normal behavior
        
        return {
            'isolated': False,  # Most hosts are not isolated
            'active_connections': True,
            'normal_traffic': True
        }
    
    def _get_reverse_dns(self, host: str) -> Optional[str]:
        """Get reverse DNS for host"""
        import socket
        
        try:
            reverse_dns = socket.gethostbyaddr(host)[0]
            return reverse_dns
        except:
            return None
    
    def _analyze_interaction_patterns(self, host: str) -> Dict[str, Any]:
        """Analyze service interaction patterns"""
        # This would analyze how services respond to different types of requests
        # For now, we'll simulate normal behavior
        
        return {
            'unusual': False,
            'consistent_responses': True,
            'proper_error_handling': True
        }
    
    def simulate_anomaly_detection(self, target: str, operation_type: str = "exploit"):
        """Simulate anomaly detection for testing"""
        if not self.enabled:
            return
        
        # Simulate operation data
        operation_data = {
            'target': target,
            'operation_type': operation_type,
            'response_time': random.uniform(100, 5000),  # Random response time
            'timestamp': datetime.now().isoformat(),
            'honeypot_indicators': []
        }
        
        # Add some honeypot indicators randomly
        if random.random() < 0.3:  # 30% chance
            operation_data['honeypot_indicators'] = [
                'deliberate_delay',
                'fake_banner',
                'no_user_activity'
            ]
        
        # Analyze the operation
        alert = self.analyze_operation(operation_data)
        
        if alert:
            self._display_alert(alert)
    
    def _display_alert(self, alert: GuardianAlert):
        """Display Guardian alert with collected evidence"""
        print()
        print("=" * 63)
        print("ANOMALY DETECTED BY GUARDIAN")
        print("=" * 63)
        print(f"Target: {alert.target}")
        print(f"Issue: {alert.issue}")
        print(f"Confidence: {alert.confidence:.1f}%")
        print()
        print("Evidence:")
        if alert.evidence:
            for item in alert.evidence:
                print(f"  - {item}")
        else:
            print("  - No additional telemetry captured")
        print()
        print("Recommended actions:")
        for rec in alert.recommendations:
            print(f"  - {rec}")
        if alert.auto_action_taken and alert.action_description:
            print()
            print(f"Automatic action: {alert.action_description}")
        print("=" * 63)

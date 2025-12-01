#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CANBUS Message Analyzer - Analyzes CAN messages from a CANBUS session
Author: KittySploit Team
Version: 1.0.0
"""

from kittysploit import *
from core.output_handler import print_info, print_success, print_error, print_warning
import json
import time
from collections import defaultdict

class Module(Post):
    """Analyze CAN messages from a CANBUS session"""
    
    __info__ = {
        "name": "Analyze CAN Messages",
        "description": "Analyzes CAN messages from a CANBUS session, detecting patterns and anomalies",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.CANBUS,
    }
    
    analyze_duration = OptInteger(60, "Duration to analyze messages in seconds", required=True)
    detect_patterns = OptBool(True, "Detect message patterns and frequencies", required=True)
    detect_anomalies = OptBool(True, "Detect anomalies in message timing and data", required=True)
    output_file = OptString("", "Output file to save analysis results (JSON format)", required=False)
    
    def check(self):
        """Check if session is a CANBUS session"""
        try:
            session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
            if not session_id_value:
                print_error("Session ID not set")
                return False
            
            if self.framework and hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(session_id_value)
                if session:
                    if session.session_type == 'canbus':
                        return True
                    else:
                        print_error(f"Session is not a CANBUS session (type: {session.session_type})")
                        return False
                else:
                    print_error("Session not found")
                    return False
            else:
                print_warning("Session manager not available - assuming valid session")
                return True
        except Exception as e:
            print_error(f"Error checking session: {e}")
            return False
    
    def run(self):
        """Run the CAN message analysis"""
        try:
            session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
            
            if not self.framework or not hasattr(self.framework, 'session_manager'):
                print_error("Framework or session manager not available")
                return False
            
            session = self.framework.session_manager.get_session(session_id_value)
            if not session:
                print_error("Session not found")
                return False
            
            print_info("Starting CAN message analysis...")
            print_info("=" * 80)
            
            # Get session data
            can_id = session.data.get('can_id') if session.data else None
            can_id_hex = session.data.get('can_id_hex') if session.data else None
            messages = session.data.get('messages', []) if session.data else []
            
            if not can_id:
                print_error("CAN ID not found in session data")
                return False
            
            print_info(f"Analyzing CAN ID: {can_id_hex or f'0x{can_id:03X}'}")
            print_info(f"Messages in session: {len(messages)}")
            print_info("")
            
            # Analyze messages
            analysis_results = {
                'can_id': can_id,
                'can_id_hex': can_id_hex or f"0x{can_id:03X}",
                'total_messages': len(messages),
                'analysis_timestamp': time.time()
            }
            
            if messages:
                # Pattern detection
                if self.detect_patterns.value:
                    print_info("[1] Detecting message patterns...")
                    patterns = self._detect_patterns(messages)
                    analysis_results['patterns'] = patterns
                    self._display_patterns(patterns)
                
                # Anomaly detection
                if self.detect_anomalies.value:
                    print_info("\n[2] Detecting anomalies...")
                    anomalies = self._detect_anomalies(messages)
                    analysis_results['anomalies'] = anomalies
                    self._display_anomalies(anomalies)
                
                # Data analysis
                print_info("\n[3] Analyzing message data...")
                data_analysis = self._analyze_data(messages)
                analysis_results['data_analysis'] = data_analysis
                self._display_data_analysis(data_analysis)
                
                # Timing analysis
                print_info("\n[4] Analyzing message timing...")
                timing_analysis = self._analyze_timing(messages)
                analysis_results['timing_analysis'] = timing_analysis
                self._display_timing_analysis(timing_analysis)
            
            # Save results
            if self.output_file.value:
                try:
                    with open(self.output_file.value, 'w') as f:
                        json.dump(analysis_results, f, indent=2)
                    print_success(f"\nAnalysis results saved to: {self.output_file.value}")
                except Exception as e:
                    print_error(f"Error saving results: {e}")
            
            print_success("\nCAN message analysis completed")
            return True
            
        except Exception as e:
            print_error(f"Error analyzing CAN messages: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _detect_patterns(self, messages):
        """Detect patterns in CAN messages"""
        patterns = {
            'unique_data_patterns': set(),
            'data_frequency': defaultdict(int),
            'data_lengths': [],
            'repeating_data': []
        }
        
        for msg in messages:
            data_hex = msg.get('data', '')
            patterns['unique_data_patterns'].add(data_hex)
            patterns['data_frequency'][data_hex] += 1
            patterns['data_lengths'].append(len(data_hex) // 2)  # Hex to bytes
        
        # Find repeating data
        for data_hex, count in patterns['data_frequency'].items():
            if count > 1:
                patterns['repeating_data'].append({
                    'data': data_hex,
                    'count': count
                })
        
        patterns['unique_data_patterns'] = list(patterns['unique_data_patterns'])
        patterns['repeating_data'].sort(key=lambda x: x['count'], reverse=True)
        
        return patterns
    
    def _detect_anomalies(self, messages):
        """Detect anomalies in CAN messages"""
        anomalies = {
            'timing_anomalies': [],
            'data_anomalies': [],
            'length_anomalies': []
        }
        
        if len(messages) < 2:
            return anomalies
        
        # Analyze timing
        timestamps = [msg.get('timestamp', 0) for msg in messages]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            for i, interval in enumerate(intervals):
                if abs(interval - avg_interval) > avg_interval * 0.5:  # 50% deviation
                    anomalies['timing_anomalies'].append({
                        'index': i,
                        'interval': interval,
                        'expected': avg_interval,
                        'deviation': abs(interval - avg_interval) / avg_interval * 100
                    })
        
        # Analyze data changes
        data_samples = [msg.get('data', '') for msg in messages]
        for i in range(1, len(data_samples)):
            if data_samples[i] != data_samples[i-1]:
                # Check if change is significant
                if len(data_samples[i]) != len(data_samples[i-1]):
                    anomalies['length_anomalies'].append({
                        'index': i,
                        'previous_length': len(data_samples[i-1]) // 2,
                        'current_length': len(data_samples[i]) // 2
                    })
        
        return anomalies
    
    def _analyze_data(self, messages):
        """Analyze message data"""
        analysis = {
            'unique_messages': len(set(msg.get('data', '') for msg in messages)),
            'data_lengths': {},
            'byte_frequency': defaultdict(int),
            'common_bytes': []
        }
        
        for msg in messages:
            data_hex = msg.get('data', '')
            length = len(data_hex) // 2
            analysis['data_lengths'][length] = analysis['data_lengths'].get(length, 0) + 1
            
            # Analyze byte frequency
            for i in range(0, len(data_hex), 2):
                byte_hex = data_hex[i:i+2]
                if len(byte_hex) == 2:
                    analysis['byte_frequency'][byte_hex] += 1
        
        # Find common bytes
        sorted_bytes = sorted(analysis['byte_frequency'].items(), key=lambda x: x[1], reverse=True)
        analysis['common_bytes'] = [{'byte': b, 'count': c} for b, c in sorted_bytes[:10]]
        
        return analysis
    
    def _analyze_timing(self, messages):
        """Analyze message timing"""
        if len(messages) < 2:
            return {'average_interval': 0, 'min_interval': 0, 'max_interval': 0}
        
        timestamps = [msg.get('timestamp', 0) for msg in messages]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        return {
            'average_interval': sum(intervals) / len(intervals) if intervals else 0,
            'min_interval': min(intervals) if intervals else 0,
            'max_interval': max(intervals) if intervals else 0,
            'message_rate': len(messages) / (timestamps[-1] - timestamps[0]) if len(timestamps) > 1 and timestamps[-1] > timestamps[0] else 0
        }
    
    def _display_patterns(self, patterns):
        """Display detected patterns"""
        print_info(f"  Unique data patterns: {len(patterns['unique_data_patterns'])}")
        print_info(f"  Repeating patterns: {len(patterns['repeating_data'])}")
        if patterns['repeating_data']:
            print_info("  Top repeating patterns:")
            for pattern in patterns['repeating_data'][:5]:
                print_info(f"    {pattern['data']}: {pattern['count']} occurrences")
    
    def _display_anomalies(self, anomalies):
        """Display detected anomalies"""
        total_anomalies = len(anomalies['timing_anomalies']) + len(anomalies['data_anomalies']) + len(anomalies['length_anomalies'])
        print_info(f"  Total anomalies detected: {total_anomalies}")
        if anomalies['timing_anomalies']:
            print_warning(f"  Timing anomalies: {len(anomalies['timing_anomalies'])}")
        if anomalies['length_anomalies']:
            print_warning(f"  Length anomalies: {len(anomalies['length_anomalies'])}")
    
    def _display_data_analysis(self, analysis):
        """Display data analysis results"""
        print_info(f"  Unique messages: {analysis['unique_messages']}")
        print_info(f"  Data lengths: {dict(analysis['data_lengths'])}")
        if analysis['common_bytes']:
            print_info("  Most common bytes:")
            for byte_info in analysis['common_bytes'][:5]:
                print_info(f"    0x{byte_info['byte']}: {byte_info['count']} occurrences")
    
    def _display_timing_analysis(self, timing):
        """Display timing analysis results"""
        print_info(f"  Average interval: {timing['average_interval']:.4f} seconds")
        print_info(f"  Min interval: {timing['min_interval']:.4f} seconds")
        print_info(f"  Max interval: {timing['max_interval']:.4f} seconds")
        print_info(f"  Message rate: {timing['message_rate']:.2f} messages/second")


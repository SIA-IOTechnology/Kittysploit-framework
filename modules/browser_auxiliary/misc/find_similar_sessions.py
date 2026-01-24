from kittysploit import *
import json
from difflib import SequenceMatcher

class Module(BrowserAuxiliary):

    __info__ = {
        "name": "Find Similar Sessions",
        "description": "Find browser sessions with similar fingerprints (90% match)",
        "author": "KittySploit Team",
        "browser": Browser.ALL,
        "platform": Platform.ALL,
        "session_type": SessionType.BROWSER,
    }

    threshold = OptInteger(90, "Similarity threshold (0-100, default: 90 = 90%)", True)
    min_match = OptInteger(1, "Minimum number of matching sessions to display", True)

    def run(self):
        """Find sessions with similar fingerprints"""
        if not self.browser_server:
            print_error("Browser server not available")
            return False
        
        if not self.session_id:
            print_error("Session ID not set. Please set the session_id option.")
            return False
        
        # Get current session
        current_session = self.browser_server.get_session(self.session_id)
        if not current_session:
            print_error(f"Session {self.session_id[:8]}... not found")
            return False
        
        # Check if current session has a fingerprint
        if not current_session.fingerprint:
            print_warning("Current session has no fingerprint. Run 'detect properties' first.")
            return False
        
        current_fingerprint = current_session.fingerprint
        current_props = current_fingerprint.get('properties', {})
        
        print_info("="*80)
        print_success(f"Finding sessions similar to {self.session_id[:8]}...")
        # Convert threshold from 0-100 to 0.0-1.0
        threshold_float = self.threshold / 100.0
        print_info(f"Similarity threshold: {self.threshold}%")
        print_info("="*80)
        
        # Compare with all other sessions
        similar_sessions = []
        all_sessions = self.browser_server.get_sessions()
        
        for session_id, session in all_sessions.items():
            if session_id == self.session_id:
                continue  # Skip current session
            
            if not session.fingerprint:
                continue  # Skip sessions without fingerprint
            
            other_fingerprint = session.fingerprint
            other_props = other_fingerprint.get('properties', {})
            
            # Calculate similarity
            similarity = self._calculate_similarity(current_props, other_props)
            
            if similarity >= threshold_float:
                similar_sessions.append({
                    'session_id': session_id,
                    'similarity': similarity,
                    'fingerprint': other_fingerprint.get('hash', 'N/A'),
                    'timestamp': other_fingerprint.get('timestamp', 'N/A'),
                    'session': session
                })
        
        # Sort by similarity (highest first)
        similar_sessions.sort(key=lambda x: x['similarity'], reverse=True)
        
        # Display results
        if len(similar_sessions) >= self.min_match:
            print_success(f"Found {len(similar_sessions)} similar session(s):\n")
            
            for idx, match in enumerate(similar_sessions, 1):
                similarity_pct = match['similarity'] * 100
                session = match['session']
                
                print_info(f"{idx}. Session: {match['session_id'][:8]}...")
                print_info(f"   Similarity: {similarity_pct:.1f}%")
                print_info(f"   Fingerprint: {match['fingerprint'][:16]}...")
                print_info(f"   Timestamp: {match['timestamp']}")
                print_info(f"   User Agent: {session.user_agent[:60]}...")
                print_info(f"   IP: {session.ip_address}")
                print_info("")
        else:
            print_warning(f"No sessions found with similarity >= {self.threshold}%")
            if similar_sessions:
                print_info(f"\nFound {len(similar_sessions)} session(s) below threshold:")
                for match in similar_sessions:
                    similarity_pct = match['similarity'] * 100
                    print_info(f"  - {match['session_id'][:8]}... ({similarity_pct:.1f}%)")
        
        print_info("="*80)
        return True
    
    def _calculate_similarity(self, props1: dict, props2: dict) -> float:
        """
        Calculate similarity between two browser property sets
        
        Returns:
            float: Similarity score between 0.0 and 1.0
        """
        if not props1 or not props2:
            return 0.0
        
        scores = []
        weights = []
        
        # 1. User Agent similarity (weight: 0.15)
        ua1 = props1.get('userAgent', '')
        ua2 = props2.get('userAgent', '')
        if ua1 and ua2:
            ua_sim = SequenceMatcher(None, ua1, ua2).ratio()
            scores.append(ua_sim)
            weights.append(0.15)
        
        # 2. Platform match (weight: 0.10)
        platform1 = props1.get('platform', '')
        platform2 = props2.get('platform', '')
        platform_match = 1.0 if platform1 == platform2 else 0.0
        scores.append(platform_match)
        weights.append(0.10)
        
        # 3. Screen properties (weight: 0.15)
        screen1 = props1.get('screen', {})
        screen2 = props2.get('screen', {})
        if screen1 and screen2:
            screen_scores = []
            for key in ['width', 'height', 'colorDepth', 'pixelDepth']:
                val1 = screen1.get(key, 0)
                val2 = screen2.get(key, 0)
                if val1 == val2 and val1 != 0:
                    screen_scores.append(1.0)
                elif val1 != 0 and val2 != 0:
                    # Partial match for similar resolutions
                    diff = abs(val1 - val2) / max(val1, val2)
                    screen_scores.append(max(0.0, 1.0 - diff))
            screen_sim = sum(screen_scores) / len(screen_scores) if screen_scores else 0.0
            scores.append(screen_sim)
            weights.append(0.15)
        
        # 4. Hardware similarity (weight: 0.10)
        hw1 = props1.get('hardware', {})
        hw2 = props2.get('hardware', {})
        if hw1 and hw2:
            hw_scores = []
            for key in ['hardwareConcurrency', 'deviceMemory', 'maxTouchPoints']:
                val1 = hw1.get(key, 0)
                val2 = hw2.get(key, 0)
                if val1 == val2 and val1 != 0:
                    hw_scores.append(1.0)
                elif val1 != 0 and val2 != 0:
                    diff = abs(val1 - val2) / max(val1, val2)
                    hw_scores.append(max(0.0, 1.0 - diff))
            hw_sim = sum(hw_scores) / len(hw_scores) if hw_scores else 0.0
            scores.append(hw_sim)
            weights.append(0.10)
        
        # 5. Timezone match (weight: 0.10)
        tz1 = props1.get('timezone', '')
        tz2 = props2.get('timezone', '')
        tz_match = 1.0 if tz1 == tz2 else 0.0
        scores.append(tz_match)
        weights.append(0.10)
        
        # 6. Language match (weight: 0.05)
        lang1 = props1.get('language', '')
        lang2 = props2.get('language', '')
        lang_match = 1.0 if lang1 == lang2 else 0.0
        scores.append(lang_match)
        weights.append(0.05)
        
        # 7. Features similarity (weight: 0.15)
        features1 = props1.get('features', {})
        features2 = props2.get('features', {})
        if features1 and features2:
            all_features = set(list(features1.keys()) + list(features2.keys()))
            if all_features:
                matches = sum(1 for f in all_features if features1.get(f) == features2.get(f))
                features_sim = matches / len(all_features)
                scores.append(features_sim)
                weights.append(0.15)
        
        # 8. WebGL similarity (weight: 0.10)
        webgl1 = props1.get('webgl')
        webgl2 = props2.get('webgl')
        if webgl1 and webgl2 and isinstance(webgl1, dict) and isinstance(webgl2, dict):
            webgl_scores = []
            for key in ['vendor', 'renderer']:
                val1 = webgl1.get(key, '')
                val2 = webgl2.get(key, '')
                if val1 == val2:
                    webgl_scores.append(1.0)
                elif val1 and val2:
                    webgl_scores.append(SequenceMatcher(None, val1, val2).ratio())
            webgl_sim = sum(webgl_scores) / len(webgl_scores) if webgl_scores else 0.0
            scores.append(webgl_sim)
            weights.append(0.10)
        
        # Calculate weighted average
        if scores and weights:
            total_weight = sum(weights)
            if total_weight > 0:
                weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
                return weighted_sum / total_weight
        
        return 0.0


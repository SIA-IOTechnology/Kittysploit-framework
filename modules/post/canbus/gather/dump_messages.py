#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CANBUS Message Dumper - Dumps CAN messages from a session to file
Author: KittySploit Team
Version: 1.0.0
"""

from kittysploit import *
from core.output_handler import print_info, print_success, print_error, print_warning
import json
import csv
from datetime import datetime

class Module(Post):
    """Dump CAN messages from a CANBUS session to file"""
    
    __info__ = {
        "name": "Dump CAN Messages",
        "description": "Dumps CAN messages from one CANBUS session or sibling sessions to file",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.CANBUS,
    'agent': {
        'risk': 'passive',
        'effects': ['recon'],
        'expected_requests': 0,
        'reversible': True,
        'approval_required': False,
        'produces': ['canbus_capture'],
        'cost': 0.3,
        'noise': 0.0,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }
    
    output_file = OptString("canbus_dump.json", "Output file path", required=True)
    format = OptChoice("json", "Output format", required=True, choices=["json", "csv", "raw", "candump"])
    filter_id = OptString("", "Filter by CAN ID (hex format, e.g., 0x123). Empty = all IDs", required=False)
    filter_ids = OptString("", "Comma-separated CAN IDs or ranges (e.g., 0x123,0x7E8-0x7EF)", required=False)
    include_siblings = OptBool(False, "Include sibling CANBUS sessions on the same interface:channel", required=True)
    start_time = OptFloat(0.0, "Only dump messages at or after this timestamp (0 = no lower bound)", required=False)
    end_time = OptFloat(0.0, "Only dump messages at or before this timestamp (0 = no upper bound)", required=False)
    min_dlc = OptInteger(0, "Minimum DLC/data length in bytes", required=False)
    max_dlc = OptInteger(64, "Maximum DLC/data length in bytes", required=False)
    extended = OptChoice("any", "Extended-ID filter", required=True, choices=["any", "true", "false"])
    remote = OptChoice("any", "Remote-frame filter", required=True, choices=["any", "true", "false"])
    limit = OptInteger(0, "Limit number of messages to dump (0 = all)", required=True)
    
    def check(self):
        """Check if session is a CANBUS session"""
        try:
            session_id_value = str(self.session_id)
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
        """Dump CAN messages to file"""
        try:
            session_id_value = str(self.session_id)
            
            if not self.framework or not hasattr(self.framework, 'session_manager'):
                print_error("Framework or session manager not available")
                return False
            
            session = self.framework.session_manager.get_session(session_id_value)
            if not session:
                print_error("Session not found")
                return False
            
            messages = self._collect_messages(session)
            
            if not messages:
                print_warning("No messages found in session")
                return False
            
            print_info("Dumping CAN messages...")
            print_info("=" * 80)
            print_info(f"Total normalized messages: {len(messages)}")
            
            filter_ids = self._parse_filter_ids()
            if filter_ids:
                pretty = ", ".join(self._fmt_can_id(cid) for cid in sorted(filter_ids))
                print_info(f"Filtering by CAN ID(s): {pretty}")

            filtered_messages = self._apply_filters(messages, filter_ids)
            
            # Apply limit
            limit = int(self.limit)
            if limit > 0:
                filtered_messages = filtered_messages[:limit]
            
            print_info(f"Messages to dump: {len(filtered_messages)}")
            
            # Get output format
            format_type = str(self.format)
            output_file = str(self.output_file)
            
            # Dump based on format
            if format_type == "json":
                self._dump_json(filtered_messages, output_file)
            elif format_type == "csv":
                self._dump_csv(filtered_messages, output_file)
            elif format_type == "raw":
                self._dump_raw(filtered_messages, output_file)
            elif format_type == "candump":
                self._dump_candump(filtered_messages, output_file)
            else:
                print_error(f"Unknown format: {format_type}")
                return False
            
            print_success(f"Messages dumped to: {output_file}")
            return True
            
        except Exception as e:
            print_error(f"Error dumping CAN messages: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _collect_messages(self, session):
        """Normalize messages from the current session and optional sibling sessions."""
        sessions = [session]
        data = session.data or {}
        interface = data.get("interface")
        channel = data.get("channel")

        if self.include_siblings and self.framework and hasattr(self.framework, "session_manager"):
            for other in self.framework.session_manager.get_sessions():
                if other.id == session.id or other.session_type != "canbus":
                    continue
                odata = other.data or {}
                if odata.get("interface") == interface and odata.get("channel") == channel:
                    sessions.append(other)

        normalized = []
        for sess in sessions:
            sdata = sess.data or {}
            session_can_id = self._coerce_can_id(sdata.get("can_id"))
            session_can_id_hex = sdata.get("can_id_hex")
            for msg in sdata.get("messages", []) or []:
                can_id = self._coerce_can_id(
                    msg.get("can_id", msg.get("arbitration_id", session_can_id))
                )
                if can_id is None:
                    continue
                payload = self._normalize_hex(msg.get("data", ""))
                normalized.append({
                    "session_id": sess.id,
                    "interface": sdata.get("interface"),
                    "channel": sdata.get("channel"),
                    "timestamp": msg.get("timestamp", 0),
                    "can_id": can_id,
                    "can_id_hex": msg.get("can_id_hex") or session_can_id_hex or self._fmt_can_id(can_id),
                    "data": payload,
                    "dlc": msg.get("dlc", len(payload) // 2),
                    "is_extended": bool(msg.get("is_extended", sdata.get("is_extended", False))),
                    "is_remote": bool(msg.get("is_remote", sdata.get("is_remote", False))),
                })

        normalized.sort(key=lambda m: (float(m.get("timestamp") or 0), int(m.get("can_id") or 0)))
        return normalized

    def _apply_filters(self, messages, filter_ids):
        start_time = float(self.start_time or 0)
        end_time = float(self.end_time or 0)
        min_dlc = max(0, int(self.min_dlc or 0))
        max_dlc = max(min_dlc, int(self.max_dlc or 64))
        extended = str(self.extended or "any").lower()
        remote = str(self.remote or "any").lower()

        filtered = []
        for msg in messages:
            can_id = msg.get("can_id")
            timestamp = float(msg.get("timestamp") or 0)
            dlc = int(msg.get("dlc") or 0)
            if filter_ids and can_id not in filter_ids:
                continue
            if start_time and timestamp < start_time:
                continue
            if end_time and timestamp > end_time:
                continue
            if dlc < min_dlc or dlc > max_dlc:
                continue
            if extended != "any" and bool(msg.get("is_extended")) != (extended == "true"):
                continue
            if remote != "any" and bool(msg.get("is_remote")) != (remote == "true"):
                continue
            filtered.append(msg)
        return filtered

    def _parse_filter_ids(self):
        specs = []
        if self.filter_id:
            specs.append(str(self.filter_id))
        if self.filter_ids:
            specs.extend(part.strip() for part in str(self.filter_ids).split(",") if part.strip())

        ids = set()
        for spec in specs:
            if "-" in spec:
                left, right = spec.split("-", 1)
                start = self._coerce_can_id(left)
                end = self._coerce_can_id(right)
                if start is None or end is None or start > end:
                    print_warning(f"Ignoring invalid CAN ID range: {spec}")
                    continue
                if end - start > 4096:
                    print_warning(f"Ignoring oversized CAN ID range: {spec}")
                    continue
                ids.update(range(start, end + 1))
            else:
                can_id = self._coerce_can_id(spec)
                if can_id is None:
                    print_warning(f"Ignoring invalid CAN ID: {spec}")
                    continue
                ids.add(can_id)
        return ids

    def _coerce_can_id(self, value):
        if value is None or value == "":
            return None
        try:
            if isinstance(value, int):
                return value
            text = str(value).strip()
            if text.lower().startswith("0x"):
                return int(text, 16)
            if all(c in "0123456789ABCDEFabcdef" for c in text):
                return int(text, 16)
            return int(text)
        except Exception:
            return None

    def _normalize_hex(self, value):
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).hex().upper()
        return str(value or "").replace(" ", "").replace(":", "").upper()

    def _fmt_can_id(self, can_id):
        return f"0x{can_id:03X}" if int(can_id) <= 0x7FF else f"0x{can_id:08X}"

    def _dump_json(self, messages, filename):
        """Dump messages in JSON format"""
        data = {
            'total_messages': len(messages),
            'dump_timestamp': datetime.now().isoformat(),
            'messages': messages
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _dump_csv(self, messages, filename):
        """Dump messages in CSV format"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Session_ID', 'Interface', 'Channel', 'CAN_ID', 'DLC', 'Data', 'Extended', 'Remote'])
            
            for msg in messages:
                writer.writerow([
                    msg.get('timestamp', ''),
                    msg.get('session_id', ''),
                    msg.get('interface', ''),
                    msg.get('channel', ''),
                    msg.get('can_id_hex') or self._fmt_can_id(msg.get('can_id', 0)),
                    msg.get('dlc', ''),
                    msg.get('data', ''),
                    msg.get('is_extended', False),
                    msg.get('is_remote', False)
                ])
    
    def _dump_raw(self, messages, filename):
        """Dump messages in raw hex format"""
        with open(filename, 'w') as f:
            for msg in messages:
                data = msg.get('data', '')
                f.write(f"{data}\n")
    
    def _dump_candump(self, messages, filename):
        """Dump messages in candump format (compatible with can-utils)"""
        with open(filename, 'w') as f:
            for msg in messages:
                timestamp = msg.get('timestamp', 0)
                data = msg.get('data', '')
                is_extended = msg.get('is_extended', False)
                can_id = int(msg.get('can_id') or 0)
                channel = msg.get("channel") or "can0"
                
                # Format: (timestamp) interface can_id#data
                can_id_str = f"{can_id:08X}" if is_extended else f"{can_id:03X}"
                f.write(f"({float(timestamp):.6f}) {channel} {can_id_str}#{data}\n")

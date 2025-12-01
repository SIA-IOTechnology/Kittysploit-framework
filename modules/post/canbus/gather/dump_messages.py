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
        "description": "Dumps CAN messages from a CANBUS session to file (JSON, CSV, or raw)",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.CANBUS,
    }
    
    output_file = OptString("canbus_dump.json", "Output file path", required=True)
    format = OptChoice("json", "Output format", required=True, choices=["json", "csv", "raw", "candump"])
    filter_id = OptString("", "Filter by CAN ID (hex format, e.g., 0x123). Empty = all IDs", required=False)
    limit = OptInteger(0, "Limit number of messages to dump (0 = all)", required=True)
    
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
        """Dump CAN messages to file"""
        try:
            session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
            
            if not self.framework or not hasattr(self.framework, 'session_manager'):
                print_error("Framework or session manager not available")
                return False
            
            session = self.framework.session_manager.get_session(session_id_value)
            if not session:
                print_error("Session not found")
                return False
            
            # Get messages from session
            messages = session.data.get('messages', []) if session.data else []
            can_id = session.data.get('can_id') if session.data else None
            
            if not messages:
                print_warning("No messages found in session")
                return False
            
            print_info("Dumping CAN messages...")
            print_info("=" * 80)
            print_info(f"Total messages in session: {len(messages)}")
            
            # Filter by CAN ID if specified
            filter_id = None
            if self.filter_id.value:
                filter_id_str = str(self.filter_id.value) if hasattr(self.filter_id, 'value') else str(self.filter_id)
                if filter_id_str.startswith('0x') or filter_id_str.startswith('0X'):
                    filter_id = int(filter_id_str, 16)
                else:
                    filter_id = int(filter_id_str, 16) if all(c in '0123456789ABCDEFabcdef' for c in filter_id_str) else int(filter_id_str)
                print_info(f"Filtering by CAN ID: 0x{filter_id:03X}")
            
            # Apply filters
            filtered_messages = messages
            if filter_id and can_id != filter_id:
                print_warning(f"Session CAN ID ({can_id}) doesn't match filter ({filter_id})")
                filtered_messages = []
            else:
                filtered_messages = messages
            
            # Apply limit
            limit = int(self.limit.value) if hasattr(self.limit, 'value') else int(self.limit)
            if limit > 0:
                filtered_messages = filtered_messages[:limit]
            
            print_info(f"Messages to dump: {len(filtered_messages)}")
            
            # Get output format
            format_type = str(self.format.value) if hasattr(self.format, 'value') else str(self.format)
            output_file = str(self.output_file.value) if hasattr(self.output_file, 'value') else str(self.output_file)
            
            # Dump based on format
            if format_type == "json":
                self._dump_json(filtered_messages, output_file, can_id)
            elif format_type == "csv":
                self._dump_csv(filtered_messages, output_file, can_id)
            elif format_type == "raw":
                self._dump_raw(filtered_messages, output_file, can_id)
            elif format_type == "candump":
                self._dump_candump(filtered_messages, output_file, can_id)
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
    
    def _dump_json(self, messages, filename, can_id):
        """Dump messages in JSON format"""
        data = {
            'can_id': can_id,
            'can_id_hex': f"0x{can_id:03X}" if can_id else None,
            'total_messages': len(messages),
            'dump_timestamp': datetime.now().isoformat(),
            'messages': messages
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _dump_csv(self, messages, filename, can_id):
        """Dump messages in CSV format"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'CAN_ID', 'Data', 'Extended', 'Remote'])
            
            for msg in messages:
                writer.writerow([
                    msg.get('timestamp', ''),
                    f"0x{can_id:03X}" if can_id else '',
                    msg.get('data', ''),
                    msg.get('is_extended', False),
                    msg.get('is_remote', False)
                ])
    
    def _dump_raw(self, messages, filename, can_id):
        """Dump messages in raw hex format"""
        with open(filename, 'w') as f:
            for msg in messages:
                data = msg.get('data', '')
                f.write(f"{data}\n")
    
    def _dump_candump(self, messages, filename, can_id):
        """Dump messages in candump format (compatible with can-utils)"""
        with open(filename, 'w') as f:
            for msg in messages:
                timestamp = msg.get('timestamp', 0)
                data = msg.get('data', '')
                is_extended = msg.get('is_extended', False)
                is_remote = msg.get('is_remote', False)
                
                # Format: (timestamp) interface can_id#data
                can_id_str = f"{can_id:08X}" if is_extended else f"{can_id:03X}"
                data_str = ' '.join([data[i:i+2] for i in range(0, len(data), 2)])
                
                f.write(f"({timestamp:.6f}) can0 {can_id_str}#{data_str}\n")


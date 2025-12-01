#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import threading
import time
import json

class Module(Listener):
    """CANBUS Listener - Listens to CAN bus messages and creates sessions"""
    
    __info__ = {
        'name': 'CANBUS Listener',
        'description': 'Listens to CAN bus messages and creates sessions for each detected CAN ID',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,  # CANBUS is a bind listener (we connect to the bus)
        'session_type': SessionType.CANBUS,
        'references': [
            'https://en.wikipedia.org/wiki/CAN_bus',
            'https://python-can.readthedocs.io/'
        ],
        'dependencies': ['can']
    }
    
    interface = OptString("socketcan", "CAN interface type (socketcan, virtual, pcan, slcan, usb2can)", required=True)
    channel = OptString("can0", "CAN channel/device (e.g., can0, vcan0, COM3)", required=True)
    bitrate = OptInteger(500000, "CAN bus bitrate in bps (e.g., 500000 for 500 kbps)", required=True)
    
    def __init__(self, framework=None):
        super().__init__(framework)
        self.bus = None
        self.running = False
        self.listener_thread = None
        self.can_interface = None
        self.can_channel = None
        self.bitrate = 500000  # Default 500 kbps
        self.detected_ids = {}  # Store detected CAN IDs
        self.message_count = 0
        self.sessions_by_id = {}  # Map CAN ID to session ID
    
    def _check_dependencies(self):
        """Check if python-can is available"""
        try:
            import can
            return True
        except ImportError:
            print_error("python-can is required but not installed")
            print_info("Install it with: pip install python-can")
            return False
    
    def run(self, background=False):
        """Run the CANBUS listener"""
        if not self._check_dependencies():
            return False
        
        try:
            # Get CAN interface configuration
            interface = str(self.interface.value) if hasattr(self.interface, 'value') else str(self.interface) if self.interface else "socketcan"
            channel = str(self.channel.value) if hasattr(self.channel, 'value') else str(self.channel) if self.channel else "can0"
            bitrate = int(self.bitrate.value) if hasattr(self.bitrate, 'value') else int(self.bitrate) if self.bitrate else 500000
            
            self.can_interface = interface
            self.can_channel = channel
            self.bitrate = bitrate
            
            print_success(f"Starting CANBUS listener on {interface}:{channel} at {bitrate} bps")
            print_info("Listening for CAN messages...")
            print_info("Press Ctrl+C to stop the listener")
            
            # Start listener in a separate thread
            self.running = True
            self.listener_thread = threading.Thread(target=self._start_canbus_listener, daemon=True)
            self.listener_thread.start()
            
            if background:
                return True
            
            # Wait for user to stop (foreground mode)
            try:
                while self.running:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                print_info("\n[!] Interrupted by user")
                self.running = False
            
            self._shutdown()
            return True
            
        except Exception as e:
            print_error(f"CANBUS listener error: {e}")
            return False
    
    def _start_canbus_listener(self):
        """Start the CANBUS listener in a separate thread"""
        try:
            import can
            
            # Create CAN bus interface
            try:
                if self.can_interface == "socketcan":
                    # Linux SocketCAN
                    self.bus = can.interface.Bus(channel=self.can_channel, bustype='socketcan')
                elif self.can_interface == "virtual":
                    # Virtual bus for testing
                    self.bus = can.interface.Bus(channel=self.can_channel, bustype='virtual')
                elif self.can_interface == "pcan":
                    # PCAN interface
                    self.bus = can.interface.Bus(channel=self.can_channel, bustype='pcan', bitrate=self.bitrate)
                elif self.can_interface == "slcan":
                    # Serial Line CAN
                    self.bus = can.interface.Bus(channel=self.can_channel, bustype='slcan', bitrate=self.bitrate)
                elif self.can_interface == "usb2can":
                    # USB2CAN interface
                    self.bus = can.interface.Bus(channel=self.can_channel, bustype='usb2can', bitrate=self.bitrate)
                else:
                    # Try generic interface
                    self.bus = can.interface.Bus(channel=self.can_channel, bustype=self.can_interface, bitrate=self.bitrate)
            except Exception as e:
                print_error(f"Failed to initialize CAN bus: {e}")
                print_info("Available interfaces: socketcan, virtual, pcan, slcan, usb2can")
                self.running = False
                return
            
            print_success(f"CAN bus initialized: {self.can_interface}:{self.can_channel}")
            
            # Listen for messages
            while self.running:
                try:
                    # Receive message with timeout
                    message = self.bus.recv(timeout=0.1)
                    
                    if message:
                        self.message_count += 1
                        self._handle_can_message(message)
                        
                except can.CanError as e:
                    if self.running:
                        print_warning(f"CAN error: {e}")
                    time.sleep(0.1)
                except Exception as e:
                    if self.running:
                        print_error(f"Error receiving CAN message: {e}")
                    time.sleep(0.1)
                    
        except Exception as e:
            if self.running:
                print_error(f"Error in CANBUS listener thread: {e}")
        finally:
            self._shutdown()
    
    def _handle_can_message(self, message):
        """Handle a received CAN message"""
        try:
            can_id = message.arbitration_id
            data = message.data
            timestamp = message.timestamp
            is_extended = message.is_extended_id
            is_remote = message.is_remote_frame
            
            # Store message info
            if can_id not in self.detected_ids:
                self.detected_ids[can_id] = {
                    'first_seen': timestamp,
                    'last_seen': timestamp,
                    'count': 0,
                    'is_extended': is_extended,
                    'is_remote': is_remote,
                    'data_samples': []
                }
                
                # Create a session for this CAN ID
                session_id = self._create_can_session(can_id, message)
                if session_id:
                    self.sessions_by_id[can_id] = session_id
                    print_success(f"New CAN ID detected: 0x{can_id:03X} - Session: {session_id}")
            
            # Update statistics
            self.detected_ids[can_id]['last_seen'] = timestamp
            self.detected_ids[can_id]['count'] += 1
            
            # Store data sample (keep last 10)
            if len(self.detected_ids[can_id]['data_samples']) < 10:
                self.detected_ids[can_id]['data_samples'].append({
                    'data': data.hex(),
                    'timestamp': timestamp
                })
            
            # Update session data
            if can_id in self.sessions_by_id:
                session_id = self.sessions_by_id[can_id]
                self._update_session_data(session_id, message)
            
            # Update stats
            self.stats['bytes_received'] += len(data)
            self.stats['connections_received'] = self.message_count
            
        except Exception as e:
            print_error(f"Error handling CAN message: {e}")
    
    def _create_can_session(self, can_id, message):
        """Create a session for a CAN ID"""
        try:
            session_data = {
                'can_id': can_id,
                'can_id_hex': f"0x{can_id:03X}",
                'is_extended': message.is_extended_id,
                'is_remote': message.is_remote_frame,
                'interface': self.can_interface,
                'channel': self.can_channel,
                'bitrate': self.bitrate,
                'messages': [],
                'first_seen': message.timestamp,
                'last_seen': message.timestamp
            }
            
            # Create session using framework's session manager
            if self.framework and hasattr(self.framework, 'session_manager'):
                session_id = self.framework.session_manager.create_session(
                    host=f"{self.can_interface}:{self.can_channel}",
                    port=can_id,  # Use CAN ID as port
                    session_type='canbus',
                    data=session_data
                )
                return session_id
            else:
                # Fallback: generate session ID manually
                import uuid
                return str(uuid.uuid4())
                
        except Exception as e:
            print_error(f"Error creating CAN session: {e}")
            return None
    
    def _update_session_data(self, session_id, message):
        """Update session data with new message"""
        try:
            if self.framework and hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(session_id)
                if session and session.data:
                    # Add message to session data
                    if 'messages' not in session.data:
                        session.data['messages'] = []
                    
                    # Keep last 100 messages
                    session.data['messages'].append({
                        'data': message.data.hex(),
                        'timestamp': message.timestamp,
                        'is_extended': message.is_extended_id,
                        'is_remote': message.is_remote_frame
                    })
                    
                    if len(session.data['messages']) > 100:
                        session.data['messages'] = session.data['messages'][-100:]
                    
                    session.data['last_seen'] = message.timestamp
                    session.data['message_count'] = len(session.data['messages'])
                    
        except Exception as e:
            # Silently fail - session update is not critical
            pass
    
    def _shutdown(self):
        """Shutdown the listener"""
        self.running = False
        if self.bus:
            try:
                self.bus.shutdown()
            except:
                pass
            self.bus = None
        
        if self.listener_thread and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=2)
        
        print_info("CANBUS listener stopped")
    
    def get_detected_ids(self):
        """Get all detected CAN IDs"""
        return self.detected_ids.copy()
    
    def get_session_for_id(self, can_id):
        """Get session ID for a CAN ID"""
        return self.sessions_by_id.get(can_id)


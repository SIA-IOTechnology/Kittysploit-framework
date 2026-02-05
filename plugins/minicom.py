#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Minicom Plugin - Serial Communication Program
Connects to serial devices (COM ports, /dev/tty*, etc.) for interactive communication
Similar to the minicom serial communication program
"""

from kittysploit import *
import shlex
import sys
import threading
import time
import select
import platform

class MinicomPlugin(Plugin):
    """Minicom-like serial communication plugin"""
    
    __info__ = {
        "name": "minicom",
        "description": "Serial communication program for connecting to devices via serial ports (COM ports, /dev/tty*, etc.)",
        "version": "1.0.0",
        "author": "KittySploit Team",
        "dependencies": ["serial"]  # pyserial package provides 'serial' module
    }
    
    def __init__(self, framework=None):
        super().__init__(framework)
        self.serial_port = None
        self.connected = False
        self.read_thread = None
        self.stop_reading = False
        self.port_name = None
        self.baudrate = 9600
        self.bytesize = 8
        self.parity = 'N'
        self.stopbits = 1
        self.timeout = 1
        self.xonxoff = False
        self.rtscts = False
        self.dsrdtr = False
        
        # Advanced features
        self.logging_enabled = False
        self.log_file = None
        self.session_log = []  # Store session for replay
        self.protocol_analyzer = None
        self.auto_respond = False
        self.auto_respond_patterns = {}  # Pattern -> response mapping
    
    def _check_pyserial(self):
        """Check if pyserial is available"""
        try:
            import serial
            import serial.tools.list_ports
            return True
        except ImportError:
            print_error("pyserial is required but not installed")
            print_info("Install it with: pip install pyserial")
            return False
    
    def _list_serial_ports(self):
        """List all available serial ports"""
        if not self._check_pyserial():
            return []
        
        try:
            import serial.tools.list_ports
            ports = serial.tools.list_ports.comports()
            return ports
        except Exception as e:
            print_error(f"Error listing serial ports: {e}")
            return []
    
    def _check_port_availability(self, port_name: str) -> tuple:
        """Check if a port is available and can be opened"""
        try:
            import serial
            # Try to open the port briefly to check availability
            test_port = serial.Serial(port_name, timeout=0.1)
            test_port.close()
            return (True, "Available")
        except serial.SerialException as e:
            error_msg = str(e)
            if "Access is denied" in error_msg or "Permission denied" in error_msg:
                return (False, "In use / Permission denied")
            elif "could not open port" in error_msg.lower():
                return (False, "Cannot open")
            else:
                return (False, f"Error: {error_msg[:30]}")
        except Exception as e:
            return (False, f"Unknown error: {str(e)[:30]}")
    
    def _parse_bluetooth_info(self, hwid: str) -> dict:
        """Parse Bluetooth Hardware ID to extract useful information"""
        info = {}
        try:
            # Extract VID (Vendor ID) and PID (Product ID) if present
            if 'VID&' in hwid:
                vid_start = hwid.find('VID&') + 4
                vid_end = hwid.find('_', vid_start)
                if vid_end == -1:
                    vid_end = len(hwid)
                info['VID'] = hwid[vid_start:vid_end]
            
            if 'PID&' in hwid:
                pid_start = hwid.find('PID&') + 4
                pid_end = hwid.find('_', pid_start)
                if pid_end == -1:
                    pid_end = len(hwid)
                info['PID'] = hwid[pid_start:pid_end]
            
            # Extract Bluetooth address if present
            if 'BTHENUM' in hwid:
                info['Type'] = 'Bluetooth Serial'
                # Try to extract MAC address pattern
                mac_pattern = r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})'
                import re
                mac_match = re.search(mac_pattern, hwid.upper())
                if mac_match:
                    info['MAC'] = mac_match.group(0)
        except:
            pass
        
        return info
    
    def _display_serial_ports(self):
        """Display all available serial ports with detailed information"""
        ports = self._list_serial_ports()
        
        if not ports:
            print_warning("No serial ports found")
            return
        
        # Calculate column widths dynamically
        max_device_len = max(len(port.device) for port in ports) if ports else 10
        max_device_len = max(max_device_len, 10)  # Minimum 10
        
        max_desc_len = max(len(port.description) for port in ports) if ports else 20
        max_desc_len = max(max_desc_len, 20)  # Minimum 20
        
        # Adjust to terminal width if available (default to 120)
        try:
            import shutil
            terminal_width = shutil.get_terminal_size().columns
        except:
            terminal_width = 120
        
        print_info("=" * terminal_width)
        print_info("Available Serial Ports")
        print_info("=" * terminal_width)
        print_info(f"{'Device':<{max_device_len}} {'Description':<{max_desc_len}} {'Status':<15}")
        print_info("-" * terminal_width)
        
        for port in ports:
            device = port.device
            description = port.description
            hwid = port.hwid
            
            # Check port availability
            is_available, status_msg = self._check_port_availability(device)
            status = "✓ Available" if is_available else f"✗ {status_msg}"
            
            # Parse Bluetooth info if applicable
            bt_info = self._parse_bluetooth_info(hwid)
            
            # Truncate description if necessary
            if len(description) > max_desc_len:
                desc_display = description[:max_desc_len-3] + "..."
            else:
                desc_display = description
            
            print_info(f"{device:<{max_device_len}} {desc_display:<{max_desc_len}} {status:<15}")
            
            # Show additional information
            indent = " " * (max_device_len + 2)
            
            # Show full description if truncated
            if len(description) > max_desc_len:
                print_info(f"{indent}Full Description: {description}")
            
            # Show Bluetooth information if applicable
            if bt_info:
                bt_details = []
                if 'Type' in bt_info:
                    bt_details.append(f"Type: {bt_info['Type']}")
                if 'VID' in bt_info:
                    bt_details.append(f"VID: {bt_info['VID']}")
                if 'PID' in bt_info:
                    bt_details.append(f"PID: {bt_info['PID']}")
                if 'MAC' in bt_info:
                    bt_details.append(f"MAC: {bt_info['MAC']}")
                if bt_details:
                    print_info(f"{indent}Bluetooth Info: {', '.join(bt_details)}")
            
            # Show full Hardware ID if it's long
            if len(hwid) > 80:
                print_info(f"{indent}Hardware ID: {hwid}")
            
            # Connection instructions
            if is_available:
                print_info(f"{indent}→ Connect with: connect {device}")
            else:
                print_info(f"{indent}→ Port may be in use by another application")
        
        print_info("=" * terminal_width)
        print_info("")
        print_info("Connection Examples:")
        print_info("  minicom> connect COM3")
        print_info("  minicom> connect COM4")
        print_info("")
        print_info("From main prompt (if 'connect' shows unknown command):")
        print_info("  minicom connect COM3")
        print_info("  plugin run minicom -p COM3")
        print_info("")
        print_info("Note: Bluetooth serial ports require the device to be paired and connected.")
    
    def _connect_serial(self, port_name: str) -> bool:
        """Connect to a serial port"""
        if not self._check_pyserial():
            return False
        
        try:
            import serial
            
            # Close existing connection if any
            if self.serial_port and self.serial_port.is_open:
                self._disconnect_serial()
            
            # Create serial connection
            self.serial_port = serial.Serial(
                port=port_name,
                baudrate=self.baudrate,
                bytesize=self.bytesize,
                parity=self.parity,
                stopbits=self.stopbits,
                timeout=self.timeout,
                xonxoff=self.xonxoff,
                rtscts=self.rtscts,
                dsrdtr=self.dsrdtr
            )
            
            if self.serial_port.is_open:
                self.port_name = port_name
                self.connected = True
                print_success(f"Connected to {port_name}")
                print_info(f"Configuration: {self.baudrate} {self.bytesize}{self.parity}{int(self.stopbits)}")
                print_info(f"  Baudrate: {self.baudrate}")
                print_info(f"  Data bits: {self.bytesize}")
                print_info(f"  Parity: {self.parity}")
                print_info(f"  Stop bits: {self.stopbits}")
                print_info("")
                print_info("=" * 80)
                print_info("Connection Active - Command Guide")
                print_info("=" * 80)
                print_info("Minicom Commands (prefixed, NOT sent to device):")
                print_info("  exit, quit              - Disconnect and quit")
                print_info("  disconnect              - Disconnect (stay in minicom)")
                print_info("  help                    - Show help")
                print_info("  config                   - Show configuration")
                print_info("  log start <file>         - Start logging")
                print_info("  log stop                 - Stop logging")
                print_info("  script <file>            - Execute script")
                print_info("  analyze protocol         - Enable protocol analysis")
                print_info("  fuzz <pattern>           - Fuzz test")
                print_info("  session save             - Save session to framework")
                print_info("")
                print_info("Raw Data (everything else is sent directly to the device):")
                print_info("  Any text you type will be sent to the serial port")
                print_info("  Examples:")
                print_info("    ATZ                     - AT command (modems)")
                print_info("    help                    - Device help command")
                print_info("    ls                      - List files (if shell)")
                print_info("    ?                       - Device menu")
                print_info("")
                print_info("=" * 80)
                print_info("Type 'help' for full command list")
                print_info("Type 'exit' to disconnect and quit")
                return True
            else:
                print_error(f"Failed to open serial port {port_name}")
                return False
                
        except serial.SerialException as e:
            print_error(f"Serial port error: {e}")
            if "Permission denied" in str(e) or "Access is denied" in str(e):
                print_info("You may need administrator/root privileges to access this port")
            elif "could not open port" in str(e).lower():
                print_info("Port may be in use by another application")
            return False
        except Exception as e:
            print_error(f"Error connecting to serial port: {e}")
            return False
    
    def _disconnect_serial(self):
        """Disconnect from serial port"""
        self.stop_reading = True
        
        if self.read_thread and self.read_thread.is_alive():
            # Wait for read thread to finish
            self.read_thread.join(timeout=2)
        
        if self.serial_port and self.serial_port.is_open:
            try:
                self.serial_port.close()
                print_success("Disconnected from serial port")
            except Exception as e:
                print_error(f"Error closing serial port: {e}")
        
        self.connected = False
        self.port_name = None
        self.serial_port = None
    
    def _read_serial_thread(self):
        """Thread function to read data from serial port"""
        while not self.stop_reading and self.connected:
            try:
                if self.serial_port and self.serial_port.is_open:
                    # Check if data is available
                    if self.serial_port.in_waiting > 0:
                        data = self.serial_port.read(self.serial_port.in_waiting)
                        if data:
                            # Log data if logging is enabled
                            if self.logging_enabled:
                                self._log_data('RX', data)
                            
                            # Store in session log for replay
                            self.session_log.append({
                                'type': 'RX',
                                'data': data,
                                'timestamp': time.time()
                            })
                            
                            # Analyze protocol if enabled
                            if self.protocol_analyzer:
                                self._analyze_protocol(data)
                            
                            # Auto-respond if pattern matches
                            if self.auto_respond:
                                self._check_auto_respond(data)
                            
                            # Print received data
                            try:
                                decoded = data.decode('utf-8', errors='replace')
                                # Print without newline to allow real-time display
                                sys.stdout.write(decoded)
                                sys.stdout.flush()
                            except:
                                # If decode fails, print hex representation
                                hex_str = ' '.join([f'{b:02x}' for b in data])
                                sys.stdout.write(f"[HEX: {hex_str}]")
                                sys.stdout.flush()
                    else:
                        time.sleep(0.01)  # Small delay when no data
                else:
                    time.sleep(0.1)
            except Exception as e:
                if not self.stop_reading:
                    print_error(f"\nError reading from serial port: {e}")
                    self.connected = False
                break
    
    def _start_read_thread(self):
        """Start the read thread"""
        if self.read_thread and self.read_thread.is_alive():
            return
        
        self.stop_reading = False
        self.read_thread = threading.Thread(target=self._read_serial_thread, daemon=True)
        self.read_thread.start()
    
    def _send_data(self, data: str):
        """Send data to serial port"""
        if not self.connected or not self.serial_port or not self.serial_port.is_open:
            print_error("Not connected to serial port")
            return False
        
        try:
            # Add newline if not present
            if not data.endswith('\n') and not data.endswith('\r'):
                data = data + '\n'
            
            data_bytes = data.encode('utf-8')
            self.serial_port.write(data_bytes)
            
            # Log data if logging is enabled
            if self.logging_enabled:
                self._log_data('TX', data_bytes)
            
            # Store in session log for replay
            self.session_log.append({
                'type': 'TX',
                'data': data_bytes,
                'timestamp': time.time()
            })
            
            return True
        except Exception as e:
            print_error(f"Error sending data: {e}")
            return False
    
    def _log_data(self, direction: str, data: bytes):
        """Log data to file"""
        if self.log_file:
            try:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                if direction == 'TX':
                    self.log_file.write(f"[{timestamp}] TX: {data}\n")
                else:
                    try:
                        decoded = data.decode('utf-8', errors='replace')
                        self.log_file.write(f"[{timestamp}] RX: {decoded}\n")
                    except:
                        hex_str = ' '.join([f'{b:02x}' for b in data])
                        self.log_file.write(f"[{timestamp}] RX: [HEX: {hex_str}]\n")
                self.log_file.flush()
            except Exception as e:
                print_error(f"Error writing to log file: {e}")
    
    def _analyze_protocol(self, data: bytes):
        """Analyze protocol patterns in received data"""
        # Basic protocol detection
        try:
            decoded = data.decode('utf-8', errors='ignore')
            
            # Detect common protocols
            if decoded.startswith('AT'):
                print_info(f"[Protocol] Detected: AT Commands (Modem)")
            elif b'\x00\x01' in data[:2] or b'\x01\x00' in data[:2]:
                print_info(f"[Protocol] Detected: Possible Modbus")
            elif decoded.startswith('$'):
                print_info(f"[Protocol] Detected: NMEA (GPS)")
            elif b'\x7e' in data[:1]:  # 0x7E is common in serial protocols
                print_info(f"[Protocol] Detected: Possible HDLC/PPP")
        except:
            pass
    
    def _check_auto_respond(self, data: bytes):
        """Check if received data matches auto-respond patterns"""
        try:
            decoded = data.decode('utf-8', errors='ignore')
            for pattern, response in self.auto_respond_patterns.items():
                if pattern in decoded:
                    print_info(f"[Auto-Respond] Pattern '{pattern}' matched, sending: {response}")
                    time.sleep(0.1)  # Small delay
                    self._send_data(response)
                    break
        except:
            pass
    
    def _execute_script(self, script_file: str):
        """Execute a script file for automation"""
        try:
            with open(script_file, 'r') as f:
                lines = f.readlines()
            
            print_info(f"Executing script: {script_file} ({len(lines)} lines)")
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Handle script commands
                if line.startswith('sleep '):
                    sleep_time = float(line.split(' ', 1)[1])
                    time.sleep(sleep_time)
                elif line.startswith('send '):
                    data = line.split(' ', 1)[1]
                    self._send_data(data)
                    time.sleep(0.5)  # Wait for response
                elif line.startswith('expect '):
                    # Wait for expected pattern (simplified)
                    pattern = line.split(' ', 1)[1]
                    print_info(f"Waiting for pattern: {pattern}")
                    # This would need more sophisticated implementation
                else:
                    # Treat as raw command
                    self._send_data(line)
                    time.sleep(0.5)
            
            print_success("Script execution completed")
            return True
        except FileNotFoundError:
            print_error(f"Script file not found: {script_file}")
            return False
        except Exception as e:
            print_error(f"Error executing script: {e}")
            return False
    
    def _replay_session(self, log_file: str):
        """Replay a logged session"""
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
            
            print_info(f"Replaying session from: {log_file}")
            
            for line in lines:
                if 'TX:' in line:
                    # Extract TX data
                    data = line.split('TX:', 1)[1].strip()
                    self._send_data(data)
                    time.sleep(0.1)
            
            print_success("Session replay completed")
            return True
        except FileNotFoundError:
            print_error(f"Log file not found: {log_file}")
            return False
        except Exception as e:
            print_error(f"Error replaying session: {e}")
            return False
    
    def _save_session_to_framework(self):
        """Save session to framework database"""
        if not self.framework:
            print_warning("Framework not available - cannot save session")
            return False
        
        try:
            session_manager = getattr(self.framework, 'session_manager', None)
            if session_manager:
                session_data = {
                    'port': self.port_name,
                    'baudrate': self.baudrate,
                    'config': {
                        'bytesize': self.bytesize,
                        'parity': self.parity,
                        'stopbits': self.stopbits
                    },
                    'session_log': self.session_log
                }
                # Create a serial session in the framework
                session_id = session_manager.create_session(
                    session_type='serial',
                    target_host=self.port_name,
                    target_port=0,
                    session_data=session_data
                )
                print_success(f"Session saved to framework: {session_id}")
                return session_id
            else:
                print_warning("Session manager not available")
                return False
        except Exception as e:
            print_error(f"Error saving session: {e}")
            return False
    
    def _show_help(self):
        """Show help for minicom commands"""
        help_text = """
Minicom Commands:
  exit, quit              - Exit minicom and disconnect
  disconnect              - Disconnect from serial port (but stay in minicom)
  connect <port>          - Connect to a serial port
  list, ls                - List all available serial ports
  send <data>             - Send raw data to serial port
  config                  - Show current serial port configuration
  set baudrate <rate>     - Set baudrate (e.g., 9600, 115200)
  set bytesize <size>     - Set data bits (5, 6, 7, 8)
  set parity <P|E|O|N>    - Set parity (None, Even, Odd)
  set stopbits <1|2>      - Set stop bits (1 or 2)
  set timeout <seconds>   - Set read timeout in seconds
  help                    - Show this help message
  clear                   - Clear the screen
  
Advanced Features (Framework Integration):
  log start <file>        - Start logging session to file
  log stop                - Stop logging
  log replay <file>       - Replay a logged session
  script <file>           - Execute a script file (automation)
  analyze protocol        - Analyze protocol patterns in received data
  fuzz <pattern>          - Fuzz test with pattern
  payload <type>          - Inject framework payload (if available)
  session save            - Save session to framework database
  session load <id>       - Load session from framework database
  
Serial Port Configuration:
  Default: 9600 8N1 (9600 baud, 8 data bits, No parity, 1 stop bit)
  
Examples:
  list
  connect COM3
  connect /dev/ttyUSB0
  set baudrate 115200
  send ATZ
  log start session.log
  script router_config.txt
  exit
        """
        print_info(help_text)

    def _show_connected_help(self):
        """Show help when connected to a serial port (minicom commands vs raw data)"""
        help_text = """
Minicom Commands (prefixed, NOT sent to device):
  exit, quit              - Disconnect and quit
  disconnect              - Disconnect (stay in minicom)
  help                    - Show this help
  config                  - Show configuration
  send <data>             - Send raw data to serial port
  log start <file>        - Start logging
  log stop                - Stop logging
  script <file>           - Execute script
  session save            - Save session to framework

Raw Data (everything else is sent directly to the device):
  Any text you type will be sent to the serial port
  Examples: ATZ, help, ls, ?
        """
        print_info(help_text)

    def _show_config(self):
        """Show current serial port configuration"""
        print_info("=" * 80)
        print_info("Serial Port Configuration")
        print_info("=" * 80)
        print_info(f"Port: {self.port_name or 'Not connected'}")
        print_info(f"Baudrate: {self.baudrate}")
        print_info(f"Data bits: {self.bytesize}")
        print_info(f"Parity: {self.parity}")
        print_info(f"Stop bits: {self.stopbits}")
        print_info(f"Timeout: {self.timeout} seconds")
        print_info(f"XON/XOFF: {self.xonxoff}")
        print_info(f"RTS/CTS: {self.rtscts}")
        print_info(f"DSR/DTR: {self.dsrdtr}")
        print_info("=" * 80)
    
    def _get_interactive_input(self, prompt: str, input_queue) -> str:
        """Get input from queue (web terminal) or stdin (CLI). Returns None on EOF/sentinel."""
        if input_queue is not None:
            # Always display prompt so user knows minicom is ready (otherwise appears to hang)
            print_info(prompt.rstrip())
            try:
                result = input_queue.get()
                if result is None:
                    raise EOFError("Interactive session ended")
                return result
            except EOFError:
                raise
        return input(prompt)

    def _interactive_loop(self):
        """Main interactive loop"""
        # Register for web terminal input if we have a session context
        input_queue = None
        session_id = None
        if self.framework:
            output_handler = getattr(self.framework, 'output_handler', None)
            if output_handler and hasattr(output_handler, 'get_current_session_id'):
                session_id = output_handler.get_current_session_id()
            if session_id and hasattr(self.framework, 'interactive_input_manager'):
                input_queue = self.framework.interactive_input_manager.register(session_id)

        try:
            while True:
                try:
                    # Get user input
                    if self.connected:
                        prompt = f"minicom[{self.port_name}]> "
                    else:
                        prompt = "minicom> "

                    try:
                        command = self._get_interactive_input(prompt, input_queue)
                    except (EOFError, KeyboardInterrupt):
                        print_info("\nExiting minicom...")
                        if self.connected:
                            self._disconnect_serial()
                        break

                    if not command.strip():
                        continue

                    command = command.strip()
                    cmd_lower = command.lower()

                    # Handle minicom commands
                    if cmd_lower in ['exit', 'quit']:
                        if self.connected:
                            self._disconnect_serial()
                        print_info("Exiting minicom...")
                        break

                    elif cmd_lower == 'disconnect':
                        if self.connected:
                            self._disconnect_serial()
                        else:
                            print_warning("Not connected to any serial port")

                    elif cmd_lower == 'help':
                        if self.connected:
                            self._show_connected_help()
                        else:
                            self._show_help()

                    elif cmd_lower == 'clear':
                        # Clear screen (simple version)
                        print("\n" * 50)

                    elif cmd_lower in ['list', 'ls']:
                        self._display_serial_ports()

                    elif cmd_lower.startswith('connect '):
                        parts = command.split(' ', 1)
                        if len(parts) > 1:
                            port_name = parts[1].strip()
                            if self._connect_serial(port_name):
                                self._start_read_thread()
                        else:
                            print_error("Usage: connect <port>")
                            print_info("Example: connect COM3 or connect /dev/ttyUSB0")

                    elif cmd_lower.startswith('send '):
                        if not self.connected:
                            print_error("Not connected to serial port")
                            continue

                        parts = command.split(' ', 1)
                        if len(parts) > 1:
                            data = parts[1]
                            self._send_data(data)
                        else:
                            print_error("Usage: send <data>")

                    elif cmd_lower == 'config':
                        self._show_config()

                    elif cmd_lower == 'analyze protocol':
                        self.protocol_analyzer = True if not self.protocol_analyzer else None
                        status = "enabled" if self.protocol_analyzer else "disabled"
                        print_success(f"Protocol analysis {status}")

                    elif cmd_lower.startswith('log start '):
                        if not self.connected:
                            print_error("Not connected to serial port")
                            continue
                        parts = command.split(' ', 2)
                        if len(parts) >= 3:
                            log_file = parts[2].strip()
                            try:
                                self.log_file = open(log_file, 'a', encoding='utf-8')
                                self.logging_enabled = True
                                print_success(f"Logging to {log_file}")
                            except Exception as e:
                                print_error(f"Cannot open log file: {e}")
                        else:
                            print_error("Usage: log start <file>")

                    elif cmd_lower == 'log stop':
                        self.logging_enabled = False
                        if self.log_file:
                            try:
                                self.log_file.close()
                            except Exception:
                                pass
                            self.log_file = None
                            print_success("Logging stopped")
                        else:
                            print_info("Logging was not active")

                    elif cmd_lower.startswith('script '):
                        if not self.connected:
                            print_error("Not connected to serial port")
                            continue
                        parts = command.split(' ', 1)
                        if len(parts) > 1:
                            self._execute_script(parts[1].strip())
                        else:
                            print_error("Usage: script <file>")

                    elif cmd_lower == 'session save':
                        self._save_session_to_framework()

                    elif cmd_lower.startswith('set '):
                        # Handle configuration commands
                        parts = command.split(' ', 2)
                        if len(parts) < 3:
                            print_error("Usage: set <parameter> <value>")
                            print_info("Parameters: baudrate, bytesize, parity, stopbits, timeout")
                            continue

                        param = parts[1].lower()
                        value = parts[2]

                        try:
                            if param == 'baudrate':
                                self.baudrate = int(value)
                                print_success(f"Baudrate set to {self.baudrate}")
                                if self.connected:
                                    print_warning("Reconnect to apply new baudrate")
                            elif param == 'bytesize':
                                self.bytesize = int(value)
                                if self.bytesize not in [5, 6, 7, 8]:
                                    print_error("Bytesize must be 5, 6, 7, or 8")
                                    self.bytesize = 8
                                else:
                                    print_success(f"Data bits set to {self.bytesize}")
                                    if self.connected:
                                        print_warning("Reconnect to apply new bytesize")
                            elif param == 'parity':
                                value_upper = value.upper()
                                if value_upper in ['N', 'E', 'O']:
                                    self.parity = value_upper
                                    print_success(f"Parity set to {self.parity}")
                                    if self.connected:
                                        print_warning("Reconnect to apply new parity")
                                else:
                                    print_error("Parity must be N (None), E (Even), or O (Odd)")
                            elif param == 'stopbits':
                                stopbits = float(value)
                                if stopbits in [1, 1.5, 2]:
                                    self.stopbits = stopbits
                                    print_success(f"Stop bits set to {self.stopbits}")
                                    if self.connected:
                                        print_warning("Reconnect to apply new stopbits")
                                else:
                                    print_error("Stop bits must be 1, 1.5, or 2")
                            elif param == 'timeout':
                                self.timeout = float(value)
                                print_success(f"Timeout set to {self.timeout} seconds")
                                if self.connected:
                                    try:
                                        self.serial_port.timeout = self.timeout
                                    except Exception:
                                        pass
                            else:
                                print_error(f"Unknown parameter: {param}")
                        except ValueError:
                            print_error(f"Invalid value for {param}: {value}")

                    elif self.connected:
                        # If connected and not a minicom command, send to serial port
                        self._send_data(command)

                    else:
                        # Not connected and not a minicom command
                        print_warning(f"Unknown command: {command}")
                        print_info("Type 'help' for available commands or 'list' to see available ports")

                except KeyboardInterrupt:
                    print_info("\nInterrupted. Type 'exit' to quit or 'disconnect' to disconnect.")
                    continue
                except Exception as e:
                    print_error(f"Error: {e}")
                    continue
        finally:
            # Unregister from web terminal input when exiting
            if session_id and self.framework and hasattr(self.framework, 'interactive_input_manager'):
                self.framework.interactive_input_manager.unregister(session_id)

    def run(self, *args, **kwargs):
        """Main execution method for the plugin"""
        # Check dependencies
        if not self.check_dependencies():
            return False
        
        parser = ModuleArgumentParser(
            description="Serial communication program for connecting to devices via serial ports",
            prog="minicom"
        )
        parser.add_argument(
            "-p", "--port",
            dest="port",
            help="Serial port to connect to (e.g., COM3, /dev/ttyUSB0)",
            metavar="<port>",
            type=str
        )
        parser.add_argument(
            "-b", "--baudrate",
            dest="baudrate",
            help="Baudrate (default: 9600)",
            metavar="<rate>",
            type=int,
            default=9600
        )
        parser.add_argument(
            "-l", "--list",
            dest="list_only",
            help="List all available serial ports and exit",
            action="store_true"
        )
        parser.add_argument(
            "-c", "--config",
            dest="show_config",
            help="Show serial port configuration and exit",
            action="store_true"
        )
        
        if not args or not args[0]:
            # No arguments - start interactive mode
            print_success("Minicom - Serial Communication Program")
            print_info("Type 'help' for available commands")
            print_info("Type 'list' to see available serial ports")
            print_info("-" * 80)
            
            # Show ports on startup
            self._display_serial_ports()
            
            # Start interactive loop
            self._interactive_loop()
            return True
        
        try:
            pargs = parser.parse_args(shlex.split(args[0]))
            
            if hasattr(pargs, 'help') and pargs.help:
                parser.print_help()
                print_info("\nMinicom is a serial communication program.")
                print_info("When started without arguments, it enters interactive mode.")
                print_info("Use 'list' to see available ports and 'connect <port>' to connect.")
                return True
            
            # Set configuration
            if pargs.baudrate:
                self.baudrate = pargs.baudrate
            
            # List only mode
            if pargs.list_only:
                self._display_serial_ports()
                return True
            
            # Show config
            if pargs.show_config:
                self._show_config()
                return True
            
            # Connect to specific port
            if pargs.port:
                print_success("Minicom - Serial Communication Program")
                if self._connect_serial(pargs.port):
                    self._start_read_thread()
                    print_info("Connected! Type 'exit' to disconnect and quit")
                    print_info("All input will be sent to the serial port")
                    print_info("-" * 80)
                    self._interactive_loop()
                else:
                    print_error(f"Failed to connect to serial port {pargs.port}")
                    return False
                return True
            
            # Default: start interactive mode
            print_success("Minicom - Serial Communication Program")
            print_info("Type 'help' for available commands")
            print_info("Type 'list' to see available serial ports")
            print_info("-" * 80)
            
            self._display_serial_ports()
            self._interactive_loop()
            return True
            
        except Exception as e:
            print_error(f"Error: {e}")
            parser.print_help()
            return False
        finally:
            # Cleanup
            if self.connected:
                self._disconnect_serial()


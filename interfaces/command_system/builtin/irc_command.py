#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IRC command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_status
import argparse
import socket
import ssl
import threading
import time
import sys
import shutil
import re
from datetime import datetime
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style
from prompt_toolkit.application import get_app

class IRCCommand(BaseCommand):
    """Command to connect to IRC server"""
    
    @property
    def name(self) -> str:
        return "irc"
    
    @property
    def description(self) -> str:
        return "Connect to irc.libera.chat and join #KittySploit channel"
    
    @property
    def usage(self) -> str:
        return "irc -u <nickname>"
    
    @property
    def help_text(self) -> str:
        return """
Connect to IRC server (irc.libera.chat) and join #KittySploit channel.

Arguments:
    -u, --username  Your IRC nickname (required)

Examples:
    irc -u mynickname
    irc --username mynickname
        """
    
    def _create_parser(self):
        """Create argument parser for irc command"""
        parser = argparse.ArgumentParser(
            prog='irc',
            description='Connect to IRC server (irc.libera.chat) and join #KittySploit channel',
            add_help=True
        )
        
        parser.add_argument('-u', '--username',
                          dest='nickname',
                          help='Your IRC nickname (required)')
        
        return parser
    
    def execute(self, args, **kwargs):
        """Execute the irc command"""
        # Check for help requests before parsing
        if args and args[0].lower() in ['help', '--help', '-h']:
            parser = self._create_parser()
            parser.print_help()
            return True
        
        try:
            parsed_args = self._create_parser().parse_args(args)
            if not parsed_args.nickname:
                # Show help instead of error when nickname is missing
                parser = self._create_parser()
                parser.print_help()
                return True  # Return True since help was displayed successfully
            return self._connect_irc(parsed_args)
        except SystemExit:
            # argparse raises SystemExit on --help, which is normal
            return True
        except Exception as e:
            print_error(f"Error connecting to IRC: {e}")
            return False
    
    def _connect_irc(self, args):
        """Connect to IRC server and start chat interface"""
        nickname = args.nickname
        server = 'irc.libera.chat'
        port = 6697
        channel = '#KittySploit'
        
        print_success(f"Connecting to {server}:{port} as {nickname}...")
        
        # Create IRC client
        irc_client = IRCClient(nickname, server, port, channel)
        
        try:
            # Connect to server
            if not irc_client.connect():
                print_error("Failed to connect to IRC server")
                return False
            
            print_success("Connected to IRC server")
            
            # Start receiving thread
            receive_thread = threading.Thread(target=irc_client.receive_messages, daemon=True)
            receive_thread.start()
            
            # Wait for registration (001 message)
            print_status("Waiting for IRC registration...")
            max_wait = 10  # Wait up to 10 seconds
            waited = 0
            while not irc_client.registered and waited < max_wait:
                time.sleep(0.5)
                waited += 0.5
            
            if not irc_client.registered:
                print_error("Failed to register with IRC server")
                irc_client.disconnect()
                return False
            
            # Join channel automatically
            print_status(f"Joining channel {channel}...")
            irc_client.join_channel(channel)
            time.sleep(0.5)
            
            # Start interactive chat interface
            return self._open_irc_chat(irc_client, irc_client.nickname)
            
        except KeyboardInterrupt:
            print_info("\nDisconnecting from IRC...")
            irc_client.disconnect()
            return True
        except Exception as e:
            print_error(f"Error in IRC connection: {e}")
            irc_client.disconnect()
            return False
    
    def _open_irc_chat(self, irc_client, nickname):
        """Open interactive IRC chat interface"""
        print_success("=== IRC Chat ===")
        print_info("Type your messages and press Enter to send")
        print_info("Type '/exit' to disconnect")
        print_info("Type '/users' or '/who' to list users in the channel")
        print_info("Type '/msg <nickname> <message>' to send a private message")
        print_info("Type '/help' for more commands")
        print_info("=" * 30)
        
        # Create prompt session with prompt_toolkit
        chat_style = Style.from_dict({
            'prompt': 'ansicyan bold',
        })
        
        prompt_text = f"[{nickname}]> "
        
        def get_chat_prompt():
            return HTML(f'<prompt>{prompt_text}</prompt>')
        
        prompt_session = PromptSession(
            style=chat_style,
            message=get_chat_prompt
        )
        
        # Store reference to prompt session in IRC client for message display
        irc_client._prompt_session = prompt_session
        
        try:
            while irc_client.connected:
                # Get user input using prompt_toolkit
                try:
                    raw_message = prompt_session.prompt()
                except (EOFError, KeyboardInterrupt):
                    break
                
                message = raw_message.strip()
                
                if not message:
                    continue
                
                # Remove the previous prompt/input so chat log stays clean
                # Do this AFTER we have the message but BEFORE we display it
                self._clear_prompt_input_line(prompt_text, raw_message)
                
                # Handle special commands
                if message == '/exit':
                    break
                elif message == '/help':
                    self._show_irc_help()
                    continue
                elif message == '/users' or message == '/who':
                    irc_client.list_users()
                    continue
                elif message.startswith('/nick '):
                    new_nick = message[6:].strip()
                    if new_nick:
                        irc_client.change_nick(new_nick)
                    else:
                        print_error("Usage: /nick <newnickname>")
                    continue
                elif message.startswith('/msg '):
                    # Private message: /msg nickname message
                    parts = message[5:].strip().split(' ', 1)
                    if len(parts) == 2:
                        target, msg = parts
                        irc_client.send_private_message(target, msg)
                        # send_private_message already displays the message
                    else:
                        print_error("Usage: /msg <nickname> <message>")
                    continue
                elif message.startswith('/'):
                    print_error(f"Unknown command: {message}")
                    print_info("Type '/help' for available commands")
                    continue
                
                # Send message to current channel or as general message
                if irc_client.send_message(message):
                    # Display our own message immediately (after clearing the input line)
                    irc_client._display_own_message(message)
                else:
                    print_error("Failed to send message")
            
            print_info("Disconnecting from IRC...")
            irc_client.disconnect()
            return True
            
        except KeyboardInterrupt:
            print_info("\nDisconnecting from IRC...")
            irc_client.disconnect()
            return True
        except Exception as e:
            print_error(f"Error in IRC chat interface: {e}")
            irc_client.disconnect()
            return False
        finally:
            # Clean up prompt session reference
            if hasattr(irc_client, '_prompt_session'):
                del irc_client._prompt_session
    
    def _show_irc_help(self):
        """Show IRC help"""
        print_info("=== IRC Commands ===")
        print_info("/exit          - Disconnect from IRC")
        print_info("/help          - Show this help")
        print_info("/users or /who - List users in the channel")
        print_info("/nick <nick>   - Change nickname")
        print_info("/msg <nick> <msg> - Send private message")
        print_info("=" * 20)
    
    def _clear_prompt_input_line(self, prompt_text: str, raw_message: str) -> None:
        """
        Remove the user's previously entered text so only formatted chat messages remain.
        This keeps the prompt at the bottom with a clean chat history.
        """
        if not raw_message:
            return
        if not sys.stdout or not sys.stdout.isatty():
            return
        
        try:
            columns = max(shutil.get_terminal_size(fallback=(80, 24)).columns, 1)
        except Exception:
            columns = 80
        
        # Account for long lines that wrap by estimating how many terminal rows were used
        message_lines = raw_message.splitlines() or ['']
        total_lines = 0
        for idx, line in enumerate(message_lines):
            visible_length = len(line)
            if idx == 0:
                visible_length += len(prompt_text)
            total_lines += max(1, (visible_length // columns) + 1)
        
        try:
            for _ in range(total_lines):
                sys.stdout.write('\x1b[1A')  # Move cursor up
                sys.stdout.write('\x1b[2K')  # Clear the entire line
            sys.stdout.write('\r')
            sys.stdout.flush()
        except Exception:
            pass


class IRCClient:
    """Simple IRC client for connecting to IRC servers"""
    
    def __init__(self, nickname, server, port, channel=None):
        self.nickname = nickname
        self.original_nickname = nickname
        self.server = server
        self.port = port
        self.channel = channel
        self.socket = None
        self.connected = False
        self.registered = False
        self._prompt_session = None
        self._nick_attempts = 0
        self._users_list = []  # Store users list
        self._waiting_for_names = False  # Flag to know when we're waiting for NAMES response
    
    def connect(self):
        """Connect to IRC server"""
        try:
            # Create socket
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(5)
            raw_socket.connect((self.server, self.port))
            
            # Wrap socket with SSL/TLS
            context = ssl.create_default_context()
            self.socket = context.wrap_socket(raw_socket, server_hostname=self.server)
            self.connected = True
            
            # Send initial IRC commands
            self._send(f"NICK {self.nickname}")
            self._send(f"USER {self.nickname} 0 * :{self.nickname}")
            
            return True
        except Exception as e:
            print_error(f"Connection error: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from IRC server"""
        self.connected = False
        if self.socket:
            try:
                self._send("QUIT :Goodbye")
            except:
                pass
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def _send(self, message):
        """Send a raw IRC message"""
        if self.socket and self.connected:
            try:
                self.socket.send(f"{message}\r\n".encode('utf-8', errors='ignore'))
                return True
            except Exception as e:
                print_error(f"Error sending message: {e}")
                return False
        return False
    
    def send_message(self, message):
        """Send a PRIVMSG to current channel"""
        if self.channel:
            return self._send(f"PRIVMSG {self.channel} :{message}")
        else:
            print_warning("Not in any channel. Use '/msg <nickname> <message>' for private messages")
            return False
    
    def send_private_message(self, target, message):
        """Send a private message to a user"""
        result = self._send(f"PRIVMSG {target} :{message}")
        if result:
            # Display our own private message immediately
            self._display_own_message(f"-> {target}: {message}", is_private=True)
        return result
    
    def join_channel(self, channel):
        """Join an IRC channel (internal use only)"""
        if not channel.startswith('#'):
            channel = '#' + channel
        self.channel = channel
        return self._send(f"JOIN {channel}")
    
    def list_users(self):
        """Request list of users in the current channel"""
        if self.channel:
            self._users_list = []  # Clear previous list
            self._waiting_for_names = True  # Set flag to collect names
            return self._send(f"NAMES {self.channel}")
        else:
            print_warning("Not in any channel")
            return False
    
    def change_nick(self, new_nick):
        """Change nickname"""
        self.nickname = new_nick
        return self._send(f"NICK {new_nick}")
    
    def receive_messages(self):
        """Receive messages from IRC server in a separate thread"""
        buffer = ""
        
        while self.connected:
            try:
                if not self.socket:
                    break
                
                self.socket.settimeout(1)
                data = self.socket.recv(4096)
                
                if not data:
                    break
                
                buffer += data.decode('utf-8', errors='ignore')
                
                # Process complete messages (IRCs messages end with \r\n)
                while '\r\n' in buffer:
                    line, buffer = buffer.split('\r\n', 1)
                    if line:
                        self._handle_message(line)
            
            except socket.timeout:
                # Timeout is normal, continue listening
                continue
            except Exception as e:
                if self.connected:
                    print_error(f"Error receiving message: {e}")
                break
        
        self.connected = False
    
    def _handle_message(self, line):
        """Handle incoming IRC message"""
        # Parse IRC message format: :prefix COMMAND params :trailing
        # Example: :nickname!user@host PRIVMSG #channel :message
        
        # Filter out system messages that start with "***"
        # These are usually server status messages we don't need to display
        if line.strip().startswith('***'):
            # These are likely server notices, skip them
            return
        
        # Handle PING (must respond with PONG)
        if line.startswith('PING'):
            pong_msg = line.replace('PING', 'PONG', 1)
            self._send(pong_msg)
            return
        
        # Parse message - handle both :prefix COMMAND and COMMAND formats
        # For numeric replies, format is: :server 353 nickname params :trailing
        # For regular commands, format is: :prefix COMMAND params :trailing
        
        # Check if line starts with colon (has prefix)
        if line.startswith(':'):
            # Has prefix, split differently
            # Format: :prefix COMMAND rest
            # Find first space after colon
            first_space = line.find(' ', 1)
            if first_space == -1:
                return
            
            prefix = line[1:first_space]
            rest = line[first_space + 1:]
            
            # Now parse rest: COMMAND params :trailing
            parts = rest.split(' ', 2)
            if len(parts) < 1:
                return
            
            command = parts[0]
            if len(parts) >= 2:
                params = parts[1]
                # For trailing, we need to check the entire rest of the line
                # Trailing starts with : and can contain spaces
                if len(parts) >= 3:
                    # Check if the third part starts with : (trailing)
                    if parts[2].startswith(':'):
                        # Trailing starts here, take everything after the colon
                        trailing = parts[2][1:]
                    else:
                        # No trailing yet, but there might be more parts
                        # For numeric replies, params can be multiple words
                        # Trailing is the part that starts with :
                        # So we need to look for : in the remaining parts
                        remaining = ' '.join(parts[2:])
                        if ' :' in remaining:
                            # Split on ' :' and take everything after
                            trailing = remaining.split(' :', 1)[1]
                        else:
                            trailing = None
                else:
                    trailing = None
            else:
                params = None
                trailing = None
        else:
            # No prefix, simpler format
            parts = line.split(' ', 3)
            if len(parts) < 2:
                return
            
            prefix = None
            command = parts[0]
            params = parts[1] if len(parts) > 1 else None
            trailing = parts[2][1:] if len(parts) > 2 and parts[2].startswith(':') else (parts[2] if len(parts) > 2 else None)
        
        # Extract nickname from prefix (format: nickname!user@host)
        nickname = None
        if prefix:
            nickname_match = re.match(r'^([^!]+)', prefix)
            if nickname_match:
                nickname = nickname_match.group(1)
        
        # Handle different IRC commands
        if command == '001':  # Welcome message - registration complete
            self.registered = True
            print_success(f"Registered with IRC server as {self.nickname}")
        elif command == '433':  # Nickname already in use
            self._nick_attempts += 1
            if self._nick_attempts < 5:  # Try up to 5 times
                # Try with underscore and number
                new_nick = f"{self.original_nickname}_{self._nick_attempts}"
                print_warning(f"Nickname {self.nickname} is already in use, trying {new_nick}...")
                self.nickname = new_nick
                self._send(f"NICK {new_nick}")
            else:
                print_error(f"Failed to register nickname after {self._nick_attempts} attempts")
                self.connected = False
        elif command == 'JOIN':
            if nickname:
                self._display_system_message(f"*** {nickname} joined {params}")
        elif command == 'PART':
            if nickname:
                self._display_system_message(f"*** {nickname} left {params}")
        elif command == 'QUIT':
            if nickname:
                self._display_system_message(f"*** {nickname} quit ({trailing or ''})")
        elif command == 'NICK':
            if nickname:
                self._display_system_message(f"*** {nickname} is now known as {trailing}")
        elif command == 'PRIVMSG':
            # Display private message or channel message
            target = params
            message = trailing or ''
            
            # Skip our own messages (they're already displayed when we send them)
            if nickname and nickname.lower() == self.nickname.lower():
                return  # Don't display our own messages again
            
            if target == self.nickname:
                # Private message
                if nickname:
                    self._display_message(f"<{nickname}> {message}", is_private=True)
            else:
                # Channel message
                if nickname:
                    self._display_message(f"<{nickname}> {message}")
        elif command == 'NOTICE':
            # Server notices - only show important ones, filter out Ident/hostname checks
            if trailing and not any(x in trailing.lower() for x in ['ident', 'hostname', 'looking up']):
                self._display_system_message(f"*** {trailing}")
        elif command.startswith('4') or command.startswith('5'):  # Error messages
            # Filter out "You have not registered" if we're still registering
            if trailing:
                if command == '451' and 'not registered' in trailing.lower() and not self.registered:
                    # This is expected during registration, ignore it
                    pass
                else:
                    print_error(f"IRC Error: {trailing}")
        else:
            # Other messages (numeric replies, etc.)
            if trailing and command.isdigit():
                # Handle NAMES response (353 = RPL_NAMREPLY, 366 = RPL_ENDOFNAMES)
                if command == '353':  # RPL_NAMREPLY - list of users
                    # Format: :server 353 nickname = #channel :user1 user2 user3
                    # Or: :server 353 nickname @ #channel :user1 user2 user3 (with @ for ops)
                    # Note: trailing already has the ':' removed by the parser
                    # So trailing is: "= #channel user1 user2 user3" or "@ #channel user1 user2 user3"
                    if self._waiting_for_names and trailing:
                        # Extract user list from trailing
                        # The format is: "= #channel user1 user2" or "@ #channel user1 user2"
                        # Users are after the channel name
                        parts = trailing.split()
                        if len(parts) >= 2:
                            # Skip the first part (= or @) and channel name, rest are users
                            users = parts[2:]
                            # Filter out empty strings and remove IRC prefixes like @ (op), + (voice), etc.
                            cleaned_users = []
                            for u in users:
                                if u:
                                    # Remove IRC mode prefixes
                                    clean_user = u.lstrip('@%+&~')
                                    if clean_user:
                                        cleaned_users.append(clean_user)
                            self._users_list.extend(cleaned_users)
                elif command == '366':  # RPL_ENDOFNAMES - end of user list
                    if self._waiting_for_names:
                        self._waiting_for_names = False
                        if self._users_list:
                            print_info(f"Users in {self.channel} ({len(self._users_list)}):")
                            # Format users nicely
                            users_str = ", ".join(self._users_list)
                            print_info(f"  {users_str}")
                            self._users_list = []
                        else:
                            print_info(f"No users found in {self.channel}")
                elif command in ['332', '333']:  # Channel topic info
                    if trailing:
                        self._display_system_message(f"*** {trailing}")
                # Ignore other numeric replies during registration (like 002, 003, 004, 005)
                elif command in ['002', '003', '004', '005'] and not self.registered:
                    # These are server info messages during registration, ignore them
                    pass
    
    def _display_message(self, message, is_private=False):
        """Display a message using prompt_toolkit for non-intrusive display"""
        try:
            from prompt_toolkit import print_formatted_text
            from prompt_toolkit.formatted_text import FormattedText
            
            # Format message with timestamp
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if is_private:
                formatted = FormattedText([
                    ('#ff6b6b', f'[{timestamp}] '),
                    ('#ff6b6b', message)
                ])
            else:
                formatted = FormattedText([
                    ('#4ecdc4', f'[{timestamp}] '),
                    ('', message)
                ])
            
            # Print message above the prompt
            print_formatted_text(formatted)
            
            # Invalidate the prompt to redraw it below the new message
            if self._prompt_session:
                app = get_app()
                if app:
                    app.invalidate()
        except Exception:
            # Fallback to simple print if prompt_toolkit fails
            timestamp = datetime.now().strftime("%H:%M:%S")
            if is_private:
                print_info(f"[{timestamp}] {message}")
            else:
                print_info(f"[{timestamp}] {message}")
    
    def _display_own_message(self, message, is_private=False):
        """Display a message sent by ourselves"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Use prompt_toolkit for better integration with the prompt
        try:
            from prompt_toolkit import print_formatted_text
            from prompt_toolkit.formatted_text import FormattedText
            
            if is_private:
                formatted = FormattedText([
                    ('#ff6b6b', f'[{timestamp}] '),
                    ('#ff6b6b', message)
                ])
            else:
                formatted = FormattedText([
                    ('#4ecdc4', f'[{timestamp}] '),
                    ('', f'<{self.nickname}> {message}')
                ])
            
            # Print message above the prompt
            print_formatted_text(formatted)
            
            # Invalidate the prompt to redraw it below the new message
            if self._prompt_session:
                app = get_app()
                if app:
                    app.invalidate()
        except Exception:
            # Fallback to print_info if prompt_toolkit fails
            if is_private:
                print_info(f"[{timestamp}] {message}")
            else:
                print_info(f"[{timestamp}] <{self.nickname}> {message}")
    
    def _display_system_message(self, message):
        """Display a system message (JOIN, PART, QUIT, NICK, etc.) using prompt_toolkit"""
        try:
            from prompt_toolkit import print_formatted_text
            from prompt_toolkit.formatted_text import FormattedText
            
            # Format system message (no timestamp for system messages)
            formatted = FormattedText([
                ('#888888', message)  # Gray color for system messages
            ])
            
            # Print message above the prompt
            print_formatted_text(formatted)
            
            # Invalidate the prompt to redraw it below the new message
            if self._prompt_session:
                app = get_app()
                if app:
                    app.invalidate()
        except Exception:
            # Fallback to simple print if prompt_toolkit fails
            print_info(message)


#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sound command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import os

class SoundCommand(BaseCommand):
    """Command to enable/disable sound notifications"""
    
    @property
    def name(self) -> str:
        return "sound"
    
    @property
    def description(self) -> str:
        return "Enable or disable sound notifications for new sessions"
    
    @property
    def usage(self) -> str:
        return "sound [on|off|status|test]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Options:
    on      - Enable sound notifications
    off     - Disable sound notifications
    status  - Show current sound status
    test    - Test sound notification

Examples:
    sound on     # Enable sound
    sound off    # Disable sound
    sound status # Check current status
    sound test   # Test sound notification
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the sound command"""
        # Initialize sound_enabled if not exists
        if not hasattr(self.framework, 'sound_enabled'):
            self.framework.sound_enabled = False
        
        if len(args) == 0:
            # Show current status
            status = "enabled" if self.framework.sound_enabled else "disabled"
            print_info(f"Sound notifications: {status}")
            return True
        
        action = args[0].lower()
        
        # Handle help flags
        if action in ['--help', '-h', 'help']:
            print_info(self.help_text)
            return True
        
        if action == "on" or action == "enable" or action == "true" or action == "1":
            self.framework.sound_enabled = True
            print_success("Sound notifications enabled")
            return True
        elif action == "off" or action == "disable" or action == "false" or action == "0":
            self.framework.sound_enabled = False
            print_success("Sound notifications disabled")
            return True
        elif action == "status" or action == "show":
            status = "enabled" if self.framework.sound_enabled else "disabled"
            print_info(f"Sound notifications: {status}")
            return True
        elif action == "test":
            print_info("Testing sound notification...")
            # Use the same method as session_manager to play sound
            self._test_sound()
            return True
        else:
            print_error(f"Unknown action: {action}")
            print_info(f"Usage: {self.usage}")
            print_info("Use 'sound --help' for more information")
            return False
    
    def _test_sound(self):
        """Test sound notification"""
        try:
            sound_played = False
            
            # Try nava first (cross-platform)
            try:
                from nava import play
                # Play notification sound
                try:
                    # Try to find the sound file
                    sound_file = None
                    # Get the framework root directory (parent of interfaces directory)
                    # os is already imported at the top of the file
                    framework_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
                    
                    # Try multiple possible paths
                    possible_paths = [
                        os.path.join(framework_root, 'data/sound/notify.wav'),
                        os.path.join(os.getcwd(), 'data/sound/notify.wav'),
                        'data/sound/notify.wav',
                    ]
                    
                    for path in possible_paths:
                        abs_path = os.path.abspath(path)
                        if os.path.exists(abs_path):
                            sound_file = abs_path
                            break
                    
                    if sound_file:
                        # Play the sound file
                        play(sound_file)
                        sound_played = True
                        print_success(f"Sound played successfully using nava (file: {sound_file})")
                    else:
                        # If file doesn't exist, we can't use nava without a file
                        print_warning("Sound file not found, cannot use nava")
                except Exception as e:
                    # Error with nava, show error
                    print_warning(f"nava error: {str(e)}")
                    pass
            except ImportError as e:
                # nava not installed, try Windows fallback
                print_warning(f"nava not available: {str(e)}")
                pass
            except Exception as e:
                # Error with nava, try Windows fallback
                print_warning(f"nava error: {str(e)}")
                pass
            
            # Windows fallback using winsound
            if not sound_played:
                try:
                    import sys
                    if sys.platform == 'win32':
                        import winsound
                        # Play system beep sound
                        winsound.Beep(1000, 200)  # 1000 Hz for 200 ms
                        sound_played = True
                        print_success("Sound played successfully using winsound (Windows)")
                except ImportError:
                    pass
                except Exception as e:
                    pass
            
            # Linux/Unix fallback using system beep
            if not sound_played:
                try:
                    import sys
                    # os is already imported at the top of the file
                    if sys.platform != 'win32':
                        # Try to use system beep command
                        os.system('echo -e "\a"')  # ASCII bell character
                        sound_played = True
                        print_success("Sound played successfully using system beep")
                except Exception:
                    pass
            
                    
        except Exception as e:
            print_error(f"Error testing sound: {str(e)}")


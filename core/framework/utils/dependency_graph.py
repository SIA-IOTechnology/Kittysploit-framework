#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dependency Graph - Graphe de dépendances pour les modules
"""

from typing import Dict, List, Set, Optional, Any
from collections import defaultdict, deque
import sys
import importlib.util
from core.framework.utils.policy_engine import DependencyNode


class DependencyGraph:
    """Graphe de dépendances pour tracker les relations entre modules"""
    
    def __init__(self):
        """Initialise le graphe de dépendances"""
        self.nodes: Dict[str, DependencyNode] = {}
        self.adjacency_list: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_adjacency: Dict[str, Set[str]] = defaultdict(set)
    
    def add_module(
        self,
        module_path: str,
        dependencies: List[str],
        version: Optional[str] = None
    ):
        """
        Ajoute un module au graphe
        
        Args:
            module_path: Chemin du module
            dependencies: Liste des dépendances
            version: Version du module
        """
        # Créer ou mettre à jour le nœud
        if module_path not in self.nodes:
            self.nodes[module_path] = DependencyNode(
                module_path=module_path,
                dependencies=set(),
                dependents=set(),
                version=version
            )
        
        node = self.nodes[module_path]
        node.dependencies = set(dependencies)
        node.version = version
        
        # Mettre à jour les adjacences
        self.adjacency_list[module_path] = set(dependencies)
        
        # Mettre à jour les dépendants inverses
        for dep in dependencies:
            if dep not in self.reverse_adjacency:
                self.reverse_adjacency[dep] = set()
            self.reverse_adjacency[dep].add(module_path)
            
            # Créer un nœud pour la dépendance si elle n'existe pas
            if dep not in self.nodes:
                self.nodes[dep] = DependencyNode(
                    module_path=dep,
                    dependencies=set(),
                    dependents=set()
                )
            
            self.nodes[dep].dependents.add(module_path)
    
    def validate_dependencies(
        self,
        module_path: str,
        dependencies: List[str]
    ) -> List[str]:
        """
        Valide les dépendances d'un module
        
        Args:
            module_path: Chemin du module
            dependencies: Liste des dépendances
            
        Returns:
            Liste des problèmes détectés (warnings/errors)
        """
        issues = []
        
        for dep in dependencies:
            # Ignorer les dépendances valides (bibliothèque standard, modules internes, wildcards)
            if self._is_valid_dependency(dep):
                continue
            
            # Vérifier si la dépendance existe dans le graphe
            if dep not in self.nodes:
                issues.append(f"Dépendance '{dep}' non trouvée dans le graphe")
            
            # Détecter les cycles
            if self._has_cycle(module_path, dep):
                issues.append(f"Cycle de dépendance détecté avec '{dep}'")
        
        return issues
    
    def _is_valid_dependency(self, dep: str) -> bool:
        """
        Vérifie si une dépendance est valide (bibliothèque standard, module interne, wildcard)
        
        Args:
            dep: Nom de la dépendance
            
        Returns:
            True si la dépendance est valide et ne nécessite pas de vérification
        """
        # Gérer les patterns wildcard (ex: kittysploit.*)
        if dep.endswith('.*'):
            return True
        
        # Normaliser "module as alias" -> "module" (l'alias n'affecte pas la dépendance réelle)
        if ' as ' in dep:
            dep = dep.split(' as ', 1)[0].strip()
        
        # Extraire le nom du module de base (sans les attributs)
        # Ex: datetime.datetime -> datetime, core.output_handler.print_success -> core
        base_module = dep.split('.')[0]
        
        # Vérifier si c'est un module de la bibliothèque standard
        # Cela fonctionne aussi pour les sous-modules comme datetime.datetime
        if self._is_stdlib_module(base_module):
            return True
        
        # Vérifier si c'est un module interne du framework
        if dep.startswith('core.') or dep.startswith('kittysploit'):
            return True
        
        # Vérifier si le module peut être importé (module tiers installé)
        if self._can_import_module(base_module):
            return True
        
        return False
    
    def _is_stdlib_module(self, module_name: str) -> bool:
        """
        Vérifie si un module fait partie de la bibliothèque standard Python
        
        Args:
            module_name: Nom du module
            
        Returns:
            True si c'est un module de la bibliothèque standard
        """
        # Liste des modules de la bibliothèque standard couramment utilisés
        stdlib_modules = {
            'json', 'datetime', 'time', 'os', 'sys', 're', 'collections',
            'itertools', 'functools', 'operator', 'copy', 'pickle', 'hashlib',
            'base64', 'urllib', 'http', 'socket', 'ssl', 'email', 'csv',
            'xml', 'html', 'sqlite3', 'threading', 'multiprocessing', 'queue',
            'asyncio', 'logging', 'pathlib', 'shutil', 'tempfile', 'glob',
            'fnmatch', 'linecache', 'codecs', 'io', 'struct', 'array',
            'decimal', 'fractions', 'statistics', 'random', 'secrets',
            'string', 'textwrap', 'unicodedata', 'readline', 'rlcompleter',
            'types', 'copyreg', 'pprint', 'reprlib', 'enum', 'numbers',
            'math', 'cmath', 'decimal', 'fractions', 'statistics', 'random',
            'secrets', 'bisect', 'heapq', 'weakref', 'gc', 'inspect',
            'site', 'fpectl', 'atexit', 'traceback', 'warnings', 'contextlib',
            'abc', 'atexit', 'traceback', 'gc', 'inspect', 'site', 'fpectl',
            'argparse', 'getopt', 'shlex', 'configparser', 'netrc', 'xdrlib',
            'plistlib', 'subprocess', 'sched', 'queue', 'select', 'selectors',
            'asyncio', 'asyncore', 'asynchat', 'signal', 'mmap', 'readline',
            'rlcompleter', 'cmd', 'shlex', 'configparser', 'netrc', 'xdrlib',
            'plistlib', 'code', 'codeop', 'py_compile', 'compileall', 'dis',
            'pickletools', 'pickle', 'copyreg', 'shelve', 'marshal', 'dbm',
            'sqlite3', 'zlib', 'gzip', 'bz2', 'lzma', 'zipfile', 'tarfile',
            'csv', 'configparser', 'netrc', 'xdrlib', 'plistlib', 'calendar',
            'collections', 'heapq', 'bisect', 'array', 'weakref', 'types',
            'copy', 'pprint', 'reprlib', 'enum', 'numbers', 'math', 'cmath',
            'decimal', 'fractions', 'statistics', 'random', 'secrets', 'string',
            're', 'difflib', 'textwrap', 'unicodedata', 'stringprep', 'readline',
            'rlcompleter', 'codecs', 'io', 'locale', 'gettext', 'argparse',
            'getopt', 'shlex', 'logging', 'logging.handlers', 'logging.config',
            'getpass', 'curses', 'platform', 'errno', 'ctypes', 'ctypes.util',
            'ctypes.wintypes', 'msilib', 'msvcrt', 'winreg', 'winsound',
            'posix', 'pwd', 'spwd', 'grp', 'crypt', 'termios', 'tty', 'pty',
            'fcntl', 'pipes', 'resource', 'nis', 'syslog', 'sys', 'sysconfig',
            'builtins', '__builtin__', '__builtins__'
        }
        
        if module_name in stdlib_modules:
            return True
        
        # Vérifier via sys.builtin_module_names pour les modules compilés
        if module_name in sys.builtin_module_names:
            return True
        
        # Vérifier si le module est dans le chemin standard de Python
        try:
            spec = importlib.util.find_spec(module_name)
            if spec is None:
                return False
            # Si le module est dans la bibliothèque standard, son origin sera None ou dans site-packages
            # Les modules stdlib ont généralement origin dans le répertoire de Python
            if spec.origin:
                # Vérifier si c'est dans le répertoire de la bibliothèque standard
                stdlib_paths = [sys.prefix, sys.exec_prefix]
                for stdlib_path in stdlib_paths:
                    if stdlib_path and stdlib_path in spec.origin:
                        # Mais pas dans site-packages
                        if 'site-packages' not in spec.origin:
                            return True
        except (ImportError, ValueError, AttributeError):
            pass
        
        return False
    
    def _can_import_module(self, module_name: str) -> bool:
        """
        Vérifie si un module peut être importé (module tiers installé)
        
        Args:
            module_name: Nom du module
            
        Returns:
            True si le module peut être importé
        """
        try:
            __import__(module_name)
            return True
        except (ImportError, ModuleNotFoundError):
            return False
    
    def _has_cycle(self, start: str, target: str) -> bool:
        """
        Vérifie s'il y a un cycle entre deux modules
        
        Args:
            start: Module de départ
            target: Module cible
            
        Returns:
            True si un cycle est détecté
        """
        visited = set()
        queue = deque([target])
        
        while queue:
            current = queue.popleft()
            if current == start:
                return True
            
            if current in visited:
                continue
            
            visited.add(current)
            
            # Ajouter les dépendances au queue
            for dep in self.adjacency_list.get(current, set()):
                if dep not in visited:
                    queue.append(dep)
        
        return False
    
    def get_dependencies(self, module_path: str, recursive: bool = False) -> Set[str]:
        """
        Récupère les dépendances d'un module
        
        Args:
            module_path: Chemin du module
            recursive: Si True, inclut les dépendances transitives
            
        Returns:
            Ensemble des dépendances
        """
        if module_path not in self.nodes:
            return set()
        
        if not recursive:
            return self.nodes[module_path].dependencies.copy()
        
        # Récursif: collecter toutes les dépendances transitives
        dependencies = set()
        visited = set()
        queue = deque([module_path])
        
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            
            visited.add(current)
            
            if current in self.nodes:
                deps = self.nodes[current].dependencies
                dependencies.update(deps)
                for dep in deps:
                    if dep not in visited:
                        queue.append(dep)
        
        return dependencies
    
    def get_dependents(self, module_path: str, recursive: bool = False) -> Set[str]:
        """
        Récupère les modules qui dépendent d'un module
        
        Args:
            module_path: Chemin du module
            recursive: Si True, inclut les dépendants transitifs
            
        Returns:
            Ensemble des modules dépendants
        """
        if module_path not in self.nodes:
            return set()
        
        if not recursive:
            return self.nodes[module_path].dependents.copy()
        
        # Récursif: collecter tous les dépendants transitifs
        dependents = set()
        visited = set()
        queue = deque([module_path])
        
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            
            visited.add(current)
            
            if current in self.reverse_adjacency:
                deps = self.reverse_adjacency[current]
                dependents.update(deps)
                for dep in deps:
                    if dep not in visited:
                        queue.append(dep)
        
        return dependents
    
    def get_graph(self) -> Dict[str, Any]:
        """
        Retourne une représentation complète du graphe
        
        Returns:
            Dictionnaire représentant le graphe
        """
        return {
            "nodes": {
                path: {
                    "dependencies": list(node.dependencies),
                    "dependents": list(node.dependents),
                    "version": node.version
                }
                for path, node in self.nodes.items()
            },
            "edges": [
                {"from": module, "to": dep}
                for module, deps in self.adjacency_list.items()
                for dep in deps
            ]
        }
    
    def topological_sort(self) -> List[str]:
        """
        Effectue un tri topologique du graphe
        
        Returns:
            Liste des modules dans l'ordre topologique
        """
        # Calculer les degrés entrants
        in_degree = defaultdict(int)
        for module in self.nodes:
            in_degree[module] = len(self.nodes[module].dependencies)
        
        # Trouver les modules sans dépendances
        queue = deque([m for m in self.nodes if in_degree[m] == 0])
        result = []
        
        while queue:
            current = queue.popleft()
            result.append(current)
            
            # Réduire le degré des dépendants
            for dependent in self.nodes[current].dependents:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)
        
        # Vérifier les cycles
        if len(result) != len(self.nodes):
            # Il y a un cycle
            remaining = set(self.nodes.keys()) - set(result)
            result.extend(remaining)
        
        return result


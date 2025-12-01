#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RPC Server - Service XML-RPC pour le framework
Fournit une interface RPC pour contrôler le framework sans interface CLI.
"""

import os
import threading
import logging
import base64
import time
import socket
import uuid
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import io
import sys

# Imports optionnels pour les fonctionnalités avancées
try:
    from core.interpreter import KittyInterpreter
    INTERPRETER_AVAILABLE = True
except ImportError:
    INTERPRETER_AVAILABLE = False

try:
    from core.framework.runtime import EventBus, EventType
    from core.framework.runtime.pipeline import Pipeline, PipelineStepType
    RUNTIME_KERNEL_AVAILABLE = True
except ImportError:
    RUNTIME_KERNEL_AVAILABLE = False

class AuthHandler(SimpleXMLRPCRequestHandler):
    """Handler personnalisé pour l'authentification"""

    def do_POST(self):
        if self.server.api_key:
            auth_header = self.headers.get('Authorization')
            if not auth_header or auth_header != f"Bearer {self.server.api_key}":
                self.send_response(401)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Unauthorized")
                return
        try:
            super().do_POST()
        except Exception as e:
            logging.exception("Error in POST request")
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Internal Server Error")

class RpcServer:
    """
    Serveur RPC XML-RPC pour le framework
    
    Fournit une interface RPC pour contrôler le framework sans interface CLI.
    Compatible avec les fonctionnalités du runtime kernel (pipelines, events, resources).
    """
    
    def __init__(self, framework, host='127.0.0.1', port=8888, api_key=None):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.framework = framework
        self.clients = {}
        self.server = None
        self.running = False
        self.output_callbacks = {
            'stdout': [],
            'stderr': [],
            'result': [],
            'error': [],
        }
        self.interpreters = {}  # Stocke les interpréteurs par session
        
        # Initialize registry service if available (mode serveur uniquement)
        # Note: Le registry est normalement un service distant géré par KittySploit
        # Ce service local est optionnel pour les déploiements self-hosted
        self.registry_service = None
        self.registry_mode = os.getenv('KITTYSPLOIT_REGISTRY_MODE', 'client')  # 'client' ou 'server'
        
        if self.registry_mode == 'server':
            # Mode serveur : ce framework peut servir de registry pour d'autres clients
            try:
                import core.registry  # noqa: F401
                from core.registry.signature import RegistrySignatureManager
                from core.registry.service import RegistryService
                
                if hasattr(self.framework, 'db_manager') and hasattr(self.framework, 'current_workspace'):
                    db_session = self.framework.db_manager.get_session(self.framework.current_workspace)
                    if db_session:
                        signature_manager = RegistrySignatureManager(
                            encryption_manager=self.framework.encryption_manager
                        )
                        self.registry_service = RegistryService(
                            db_session=db_session,
                            signature_manager=signature_manager
                        )
                        logging.info("Registry service initialized (server mode)")
            except ImportError:
                logging.warning("Registry marketplace not available (missing dependencies)")
            except Exception as e:
                logging.warning(f"Failed to initialize registry service: {e}")
        else:
            # Mode client : se connecte au registry distant
            logging.info("Registry client mode (connecting to remote registry)")

    def is_port_available(self):
        """Vérifie si le port est disponible"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            return sock.connect_ex((self.host, self.port)) != 0

    def start(self):
        """Démarre le serveur RPC"""
        if not self.is_port_available():
            logging.error(f"Port {self.port} already in use.")
            return

        try:
            self.server = SimpleXMLRPCServer(
                (self.host, self.port),
                requestHandler=AuthHandler,
                allow_none=True,
                logRequests=True
            )
            self.server.api_key = self.api_key
            
            # Register existing functions
            self.server.register_introspection_functions()
            
            # Routes de base
            self.server.register_function(self.health, 'health')
            self.server.register_function(self.get_modules, 'get_modules')
            self.server.register_function(self.get_module_info, 'get_module_info')
            self.server.register_function(self.get_module_options, 'get_module_options')
            self.server.register_function(self.set_module_option, 'set_module_option')
            self.server.register_function(self.run_module, 'run_module')
            self.server.register_function(self.get_module_logs, 'get_module_logs')
            self.server.register_function(self.get_sessions, 'get_sessions')
            
            # Interpréteur (si disponible)
            if INTERPRETER_AVAILABLE:
                self.server.register_function(self.execute_interpreter, 'execute_interpreter')
            
            # Runtime Kernel (si disponible)
            if RUNTIME_KERNEL_AVAILABLE:
                self.server.register_function(self.create_pipeline, 'create_pipeline')
                self.server.register_function(self.get_events, 'get_events')
                self.server.register_function(self.get_resource_usage, 'get_resource_usage')
            
            # Workspaces
            self.server.register_function(self.list_workspaces, 'list_workspaces')
            self.server.register_function(self.switch_workspace, 'switch_workspace')
            
            # Registry Marketplace (si disponible)
            if self.registry_service:
                self.server.register_function(self.list_registry_extensions, 'list_registry_extensions')
                self.server.register_function(self.get_registry_extension, 'get_registry_extension')
                self.server.register_function(self.register_publisher, 'register_publisher')
                self.server.register_function(self.purchase_extension, 'purchase_extension')
            
            self.running = True
            logging.info(f"RPC server started on {self.host}:{self.port}")

            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()

        except Exception as e:
            logging.exception("Error starting RPC server")

    def stop(self):
        """Arrête le serveur RPC"""
        if not self.running:
            return
        
        self.running = False
        if self.server:
            try:
                self.server.shutdown()  # Arrête proprement le serveur
                # Wait for server thread to finish (max 2 seconds)
                if hasattr(self, 'server_thread') and self.server_thread.is_alive():
                    self.server_thread.join(timeout=2.0)
                    if self.server_thread.is_alive():
                        logging.warning("Server thread did not stop gracefully within timeout")
                self.server.server_close()
                logging.info("RPC server stopped")
            except Exception as e:
                logging.error(f"Error stopping RPC server: {e}")

    def get_modules(self):
        """Renvoie les modules disponibles"""
        modules = self.framework.module_loader.discover_modules()
        result = {}
        
        # Convertir la liste des modules en dictionnaire avec leurs informations
        for module_name in modules:
            try:
                module = self.framework.module_loader.load_module(module_name)
                if module:
                    result[module_name] = {
                        'name': module.name,
                        'description': module.description,
                        'author': getattr(module, 'author', 'Unknown'),
                        'references': getattr(module, 'references', [])
                    }
                else:
                    result[module_name] = {
                        'name': module_name,
                        'description': 'No description available',
                        'author': 'Unknown',
                        'references': []
                    }
            except Exception as e:
                logging.error(f"Error loading module {module_name}: {str(e)}")
                result[module_name] = {
                    'name': module_name,
                    'description': 'Error loading module',
                    'author': 'Unknown',
                    'references': []
                }
        
        return result

    def run_module(self, module_name, params):
        """Exécute un module"""
        module = self.framework.module_loader.load_module(module_name)
        if not module:
            return {'error': 'Module not found'}

        client_id = str(uuid.uuid4())

        self.setup_output_redirect(client_id)

        # Exécution du module dans un thread
        execution_thread = threading.Thread(target=self._run_module, args=(client_id, module, params))
        execution_thread.start()

        return {'status': 'success', 'message': 'Module launched', 'client_id': client_id}

    def _run_module(self, client_id, module, params):
        """Exécute un module et gère les erreurs"""
        try:
            # Définir les options du module à partir des paramètres
            if params:
                for key, value in params.items():
                    module.set_option(key, value)
            
            # Exécuter le module
            result = module.run()
            
            # Stocker le résultat
            self._store_output(client_id, 'result', f"Module execution {'succeeded' if result else 'failed'}")
        except Exception as e:
            logging.exception(f"Error executing module {client_id}")
            self._store_output(client_id, 'error', str(e))
        finally:
            self.clients[client_id]['active'] = False

    def add_output_callback(self, output_type, callback):
        """Ajoute un callback pour un type de sortie"""
        if output_type in self.output_callbacks and callback not in self.output_callbacks[output_type]:
            self.output_callbacks[output_type].append(callback)

    def add_stdout_callback(self, callback):
        """Ajoute un callback pour la sortie standard"""
        if callback not in self.output_callbacks['stdout']:
            self.output_callbacks['stdout'].append(callback)

    def add_stderr_callback(self, callback):
        """Ajoute un callback pour la sortie d'erreur"""
        if callback not in self.output_callbacks['stderr']:
            self.output_callbacks['stderr'].append(callback)

    def remove_output_callback(self, output_type, callback):
        """Supprime un callback pour un type de sortie"""
        if output_type in self.output_callbacks:
            self.output_callbacks[output_type].remove(callback)

    def setup_output_redirect(self, client_id):
        """Redirige la sortie d'un module vers le serveur RPC"""
        self.clients[client_id] = {'active': True, 'outputs': [], 'result': None}

        def stdout_callback(text):
            self._store_output(client_id, 'stdout', text)

        def stderr_callback(text):
            self._store_output(client_id, 'stderr', text)

        self.framework.output_handler.add_stdout_callback(stdout_callback)
        self.framework.output_handler.add_stderr_callback(stderr_callback)

        self.clients[client_id]['callbacks'] = {'stdout': stdout_callback, 'stderr': stderr_callback}

        self.framework.output_handler.start_redirection()

    def _store_output(self, client_id, output_type, text):
        """Stocke la sortie du module"""
        if client_id in self.clients:
            self.clients[client_id]['outputs'].append({
                'type': output_type,
                'text': base64.b64encode(text.encode()).decode(),
                'timestamp': time.time()
            })

    def get_module_logs(self, client_id):
        """Récupère les logs d'un module"""
        client_data = self.clients.get(client_id, {})
        outputs = client_data.get('outputs', [])
        active = client_data.get('active', False)
        
        return {
            "outputs": outputs,
            "active": active,
            "completed": not active and len(outputs) > 0
        }

    def execute_interpreter(self, code, session_id='default'):
        """Exécute du code dans l'interpréteur Python
        
        Args:
            code (str): Code Python à exécuter
            session_id (str): ID de session pour maintenir l'état
            
        Returns:
            dict: Résultat de l'exécution avec stdout, stderr et résultat
        """
        if not INTERPRETER_AVAILABLE:
            return {'error': 'Interpreter not available'}
        
        # Obtenir ou créer l'interpréteur pour cette session
        if session_id not in self.interpreters:
            self.interpreters[session_id] = KittyInterpreter(self.framework)
        
        interpreter = self.interpreters[session_id]
        
        # Rediriger stdout et stderr
        stdout = io.StringIO()
        stderr = io.StringIO()
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = stdout
        sys.stderr = stderr
        
        try:
            # Exécuter le code avec runsource (méthode recommandée)
            exec_result = interpreter.runsource(code)
            
            # Récupérer les sorties
            output = stdout.getvalue()
            error = stderr.getvalue()
            
            return {
                'output': output if output else None,
                'error': error if error else None,
                'result': str(exec_result) if exec_result is not None else None
            }
            
        except Exception as e:
            logging.exception("Error executing interpreter code")
            return {'error': str(e)}
        finally:
            # Restaurer stdout et stderr
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            
    def get_module_info(self, module_name):
        """Récupère les informations d'un module"""
        module = self.framework.module_loader.load_module(module_name)
        if not module:
            return {'error': 'Module not found'}
        return {
            'name': module.name,
            'description': module.description,
            'options': module.options
        }

    def get_module_options(self, module_name):
        """Récupère les options d'un module"""
        module = self.framework.module_loader.load_module(module_name)
        if not module:
            return {'error': 'Module introuvable'}
        return {
            'name': module.name,
            'options': module.options
        }

    def set_module_option(self, module_name, option_name, value):
        """Définit une option pour un module"""
        module = self.framework.module_loader.load_module(module_name)
        if not module:
            return {'error': 'Module introuvable'}
        module.set_option(option_name, value)
        return {'status': 'success', 'message': 'Module option defined'}

    def get_sessions(self):
        """Récupère les sessions disponibles"""
        return list(self.interpreters.keys())
    
    def health(self):
        """Health check - Retourne l'état du serveur"""
        return {
            'status': 'healthy',
            'version': getattr(self.framework, 'version', 'unknown'),
            'runtime_kernel': 'active' if (RUNTIME_KERNEL_AVAILABLE and hasattr(self.framework, 'runtime_kernel')) else 'inactive',
            'interpreter': 'available' if INTERPRETER_AVAILABLE else 'unavailable'
        }
    
    def run_module(self, module_name, params, use_runtime_kernel=False):
        """Exécute un module
        
        Args:
            module_name (str): Nom du module à exécuter
            params (dict): Paramètres/options du module
            use_runtime_kernel (bool): Utiliser le runtime kernel si disponible (défaut: False)
        
        Returns:
            dict: Statut de l'exécution avec client_id
        """
        # Charger le module
        if hasattr(self.framework, 'module_loader'):
            module = self.framework.module_loader.load_module(module_name)
        else:
            module = self.framework.load_module(module_name)
        
        if not module:
            return {'error': 'Module not found'}

        client_id = str(uuid.uuid4())

        # Si runtime kernel est demandé et disponible, utiliser execute_module
        if use_runtime_kernel and RUNTIME_KERNEL_AVAILABLE and hasattr(self.framework, 'execute_module'):
            self.setup_output_redirect(client_id)
            execution_thread = threading.Thread(
                target=self._run_module_with_kernel, 
                args=(client_id, module, params)
            )
            execution_thread.start()
        else:
            # Méthode classique
            self.setup_output_redirect(client_id)
            execution_thread = threading.Thread(
                target=self._run_module, 
                args=(client_id, module, params)
            )
            execution_thread.start()

        return {'status': 'success', 'message': 'Module launched', 'client_id': client_id}
    
    def _run_module_with_kernel(self, client_id, module, params):
        """Exécute un module avec le runtime kernel"""
        try:
            # Définir les options du module
            if params:
                for key, value in params.items():
                    module.set_option(key, value)
            
            # Exécuter avec le runtime kernel
            result = self.framework.execute_module(use_runtime_kernel=True)
            
            # Stocker le résultat
            self._store_output(client_id, 'result', f"Module execution completed: {result}")
        except Exception as e:
            logging.exception(f"Error executing module {client_id} with kernel")
            self._store_output(client_id, 'error', str(e))
        finally:
            self.clients[client_id]['active'] = False
    
    # ===== Méthodes Runtime Kernel (si disponible) =====
    
    def create_pipeline(self, name, steps, initial_data=None, description=''):
        """Crée et exécute un pipeline
        
        Args:
            name (str): Nom du pipeline
            steps (list): Liste des étapes du pipeline
            initial_data (dict): Données initiales (optionnel)
            description (str): Description du pipeline (optionnel)
        
        Returns:
            dict: Résultat de l'exécution du pipeline
        """
        if not RUNTIME_KERNEL_AVAILABLE:
            return {'error': 'Runtime kernel not available'}
        
        if not hasattr(self.framework, 'event_bus'):
            return {'error': 'Event bus not available'}
        
        try:
            initial_data = initial_data or {}
            
            # Créer le pipeline
            pipeline = Pipeline(
                name=name,
                description=description,
                event_bus=self.framework.event_bus
            )
            
            # Ajouter les étapes
            for step_data in steps:
                step_type = PipelineStepType(step_data.get('type', 'module'))
                pipeline.add_step(
                    step_id=step_data['id'],
                    step_type=step_type,
                    name=step_data.get('name', step_data['id']),
                    config=step_data.get('config', {}),
                    on_success=step_data.get('on_success'),
                    on_failure=step_data.get('on_failure')
                )
            
            # Exécuter le pipeline
            start_time = time.time()
            context = pipeline.execute(
                initial_data=initial_data,
                module_loader=lambda path: self.framework.load_module(path),
                workflow_loader=lambda path: self.framework.load_module(path)
            )
            
            return {
                'status': context.status,
                'pipeline_id': context.pipeline_id,
                'results': {k: str(v) for k, v in context.results.items()},
                'errors': context.errors,
                'duration': time.time() - start_time
            }
        except Exception as e:
            logging.exception("Error creating pipeline")
            return {'error': str(e)}
    
    def get_events(self, event_type=None, limit=100):
        """Récupère l'historique des événements
        
        Args:
            event_type (str): Type d'événement à filtrer (optionnel)
            limit (int): Nombre maximum d'événements à retourner (défaut: 100)
        
        Returns:
            list: Liste des événements
        """
        if not RUNTIME_KERNEL_AVAILABLE:
            return {'error': 'Runtime kernel not available'}
        
        if not hasattr(self.framework, 'event_bus'):
            return {'error': 'Event bus not available'}
        
        try:
            if event_type:
                event_type_enum = EventType[event_type]
                events = self.framework.event_bus.get_history(event_type_enum, limit)
            else:
                events = self.framework.event_bus.get_history(limit=limit)
            
            return [{
                'event_type': e.event_type.value,
                'data': e.data,
                'timestamp': e.timestamp.isoformat(),
                'source': e.source
            } for e in events]
        except KeyError:
            return {'error': f'Invalid event type: {event_type}'}
        except Exception as e:
            logging.exception("Error getting events")
            return {'error': str(e)}
    
    def get_resource_usage(self, module_id):
        """Récupère l'utilisation des ressources d'un module
        
        Args:
            module_id (str): ID du module
        
        Returns:
            dict: Informations sur l'utilisation des ressources
        """
        if not RUNTIME_KERNEL_AVAILABLE:
            return {'error': 'Runtime kernel not available'}
        
        if not hasattr(self.framework, 'runtime_kernel'):
            return {'error': 'Runtime kernel not available'}
        
        try:
            usage = self.framework.runtime_kernel.get_resource_usage(module_id)
            if not usage:
                return {'error': 'Module not found or not monitored'}
            
            return {
                'module_id': usage.module_id,
                'cpu_percent': usage.cpu_percent,
                'memory_mb': usage.memory_mb,
                'thread_count': usage.thread_count,
                'start_time': usage.start_time,
                'last_update': usage.last_update
            }
        except Exception as e:
            logging.exception("Error getting resource usage")
            return {'error': str(e)}
    
    # ===== Méthodes Workspaces =====
    
    def list_workspaces(self):
        """Liste les workspaces disponibles
        
        Returns:
            list: Liste des workspaces
        """
        if hasattr(self.framework, 'get_workspaces'):
            return self.framework.get_workspaces()
        else:
            return {'error': 'Workspaces not available'}
    
    def switch_workspace(self, name):
        """Change de workspace
        
        Args:
            name (str): Nom du workspace
        
        Returns:
            dict: Statut de l'opération
        """
        if hasattr(self.framework, 'set_workspace'):
            success = self.framework.set_workspace(name)
            return {'success': success}
        else:
            return {'error': 'Workspaces not available'}
    
    # ===== Méthodes Registry Marketplace =====
    
    def list_registry_extensions(self, extension_type=None, is_free=None, search=None, page=1, per_page=20):
        """Liste les extensions du registry
        
        Args:
            extension_type (str, optional): Type d'extension (module, plugin, UI, middleware)
            is_free (bool, optional): Filtrer les extensions gratuites
            search (str, optional): Terme de recherche
            page (int): Numéro de page (défaut: 1)
            per_page (int): Nombre d'éléments par page (défaut: 20)
        
        Returns:
            dict: Liste des extensions avec pagination
        """
        if not self.registry_service:
            return {'error': 'Registry service not available'}
        
        try:
            result = self.registry_service.list_extensions(
                extension_type=extension_type,
                is_free=is_free,
                search=search,
                page=page,
                per_page=per_page
            )
            return result
        except Exception as e:
            logging.exception("Error listing registry extensions")
            return {'error': str(e)}
    
    def get_registry_extension(self, extension_id):
        """Récupère les détails d'une extension
        
        Args:
            extension_id (str): ID de l'extension
        
        Returns:
            dict: Détails de l'extension
        """
        if not self.registry_service:
            return {'error': 'Registry service not available'}
        
        try:
            extension = self.registry_service.get_extension(extension_id)
            if not extension:
                return {'error': 'Extension not found'}
            return extension
        except Exception as e:
            logging.exception(f"Error getting registry extension {extension_id}")
            return {'error': str(e)}
    
    def register_publisher(self, name, email, public_key, kyc_data=None):
        """Enregistre un nouvel éditeur
        
        Args:
            name (str): Nom de l'éditeur
            email (str): Email de l'éditeur
            public_key (str): Clé publique en PEM
            kyc_data (dict, optional): Données KYC
        
        Returns:
            dict: Résultat de l'enregistrement
        """
        if not self.registry_service:
            return {'error': 'Registry service not available'}
        
        try:
            publisher = self.registry_service.register_publisher(
                name=name,
                email=email,
                public_key=public_key,
                kyc_data=kyc_data or {}
            )
            if not publisher:
                return {'error': 'Registration failed'}
            return {
                'success': True,
                'publisher_id': publisher.id,
                'name': publisher.name
            }
        except Exception as e:
            logging.exception("Error registering publisher")
            return {'error': str(e)}
    
    def purchase_extension(self, extension_id, user_id, version=None):
        """Achète une extension payante
        
        Args:
            extension_id (str): ID de l'extension
            user_id (str): ID de l'utilisateur
            version (str, optional): Version spécifique
        
        Returns:
            dict: Résultat de l'achat
        """
        if not self.registry_service:
            return {'error': 'Registry service not available'}
        
        try:
            license_obj = self.registry_service.purchase_extension(
                extension_id=extension_id,
                user_id=user_id,
                version=version
            )
            if not license_obj:
                return {'error': 'Purchase failed'}
            return {
                'success': True,
                'license_id': license_obj.id,
                'extension_id': extension_id,
                'version': license_obj.version
            }
        except Exception as e:
            logging.exception(f"Error purchasing extension {extension_id}")
            return {'error': str(e)}

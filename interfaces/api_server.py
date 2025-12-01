#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API Server unifié - Service REST pour le framework
Combine les fonctionnalités de api_server et headless_service
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import uuid
import logging
import json
import time
import io
import sys
import os
from typing import Optional

# Ajouter le répertoire parent au PYTHONPATH pour les imports relatifs
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

class ApiServer:
    """
    Serveur API unifié pour le framework
    
    Fournit une API REST complète pour contrôler le framework sans interface CLI.
    Combine les fonctionnalités d'api_server (sessions, streaming, interpréteur) 
    et headless_service (pipelines, events, resources, workspaces).
    """
    
    def __init__(self, framework, host='127.0.0.1', port=5000, api_key=None):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.app = Flask(__name__)
        CORS(self.app)  # Permettre les requêtes cross-origin
        self.framework = framework
        self.clients = {}  # Stocke les clients connectés
        self.interpreters = {}  # Stocke les interpréteurs par session
        self.server_thread: Optional[threading.Thread] = None
        self.running = False
        
        # Logger
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Initialize registry service if available (mode serveur registry uniquement)
        # Note: Le registry est normalement un service distant géré par KittySploit
        # Ce service local est optionnel pour les déploiements self-hosted
        self.registry_service = None
        self.registry_signature_manager = None
        self.registry_mode = os.getenv('KITTYSPLOIT_REGISTRY_MODE', 'client')  # 'client' ou 'server'
        
        if self.registry_mode == 'server':
            # Mode serveur : ce framework peut servir de registry pour d'autres clients
            try:
                # Import registry module to ensure models are registered
                import core.registry  # noqa: F401
                from core.registry.signature import RegistrySignatureManager
                from core.registry.service import RegistryService
                
                # Get database session from framework
                if hasattr(self.framework, 'db_manager') and hasattr(self.framework, 'current_workspace'):
                    db_session = self.framework.db_manager.get_session(self.framework.current_workspace)
                    if db_session:
                        self.registry_signature_manager = RegistrySignatureManager(
                            encryption_manager=self.framework.encryption_manager
                        )
                        self.registry_service = RegistryService(
                            db_session=db_session,
                            signature_manager=self.registry_signature_manager
                        )
                        self.logger.info("Registry service initialized (server mode)")
            except ImportError:
                self.logger.warning("Registry marketplace not available (missing dependencies)")
            except Exception as e:
                self.logger.warning(f"Failed to initialize registry service: {e}")
        else:
            # Mode client : se connecte au registry distant
            self.logger.info("Registry client mode (connecting to remote registry)")
        
        self.setup_routes()
    
    def setup_routes(self):
        """Configure les routes de l'API"""
        
        # ===== Routes de base =====
        
        @self.app.route('/api/health', methods=['GET'])
        def health():
            """Health check"""
            return jsonify({
                "status": "healthy",
                "version": getattr(self.framework, 'version', 'unknown'),
                "runtime_kernel": "active" if (RUNTIME_KERNEL_AVAILABLE and hasattr(self.framework, 'runtime_kernel')) else "inactive",
                "interpreter": "available" if INTERPRETER_AVAILABLE else "unavailable"
            })
        
        @self.app.route('/api/metrics', methods=['GET'])
        def get_metrics():
            """Récupère les métriques du framework"""
            if not self.check_auth(request):
                return jsonify({"error": "Unauthorized"}), 401
            
            if not hasattr(self.framework, 'metrics_collector'):
                return jsonify({"error": "Metrics collector not available"}), 503
            
            try:
                metrics = self.framework.metrics_collector.get_all_metrics()
                return jsonify(metrics)
            except Exception as e:
                self.logger.error(f"Error getting metrics: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/data/generate-mock', methods=['POST'])
        def generate_mock_data():
            """Génère des données simulées et les injecte dans le framework"""
            if not self.check_auth(request):
                return jsonify({"error": "Unauthorized"}), 401
            
            import random
            
            try:
                # Générer des métriques simulées
                if hasattr(self.framework, 'metrics_collector'):
                    collector = self.framework.metrics_collector
                    
                    # Générer des compteurs
                    for _ in range(random.randint(5, 15)):
                        collector.increment(
                            f"module.execution.success",
                            value=random.randint(1, 5),
                            metadata={"module": f"test_module_{random.randint(1, 10)}"}
                        )
                    
                    for _ in range(random.randint(0, 3)):
                        collector.increment(
                            f"module.execution.failed",
                            value=1,
                            metadata={"module": f"test_module_{random.randint(1, 10)}"}
                        )
                    
                    # Générer des timings
                    for _ in range(random.randint(10, 30)):
                        collector.record_timing(
                            "module.execution.duration",
                            duration=random.uniform(1.0, 30.0),
                            metadata={"module": f"test_module_{random.randint(1, 10)}"}
                        )
                    
                    # Générer des valeurs
                    for _ in range(random.randint(5, 15)):
                        collector.record_value(
                            "telemetry.bandwidth",
                            value=random.uniform(50.0, 500.0),
                            metadata={"source": "simulated"}
                        )
                
                return jsonify({
                    "success": True,
                    "message": "Données simulées générées avec succès"
                })
            except Exception as e:
                self.logger.error(f"Error generating mock data: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/modules', methods=['GET'])
        def get_modules():
            """Liste tous les modules disponibles"""
            if not self.check_auth(request):
                return jsonify({'error': 'Non autorise'}), 401
            
            full_view = request.args.get('full', '').lower() in ('1', 'true', 'yes')
            
            module_type = request.args.get('type')
            if module_type and hasattr(self.framework, 'get_modules_by_type'):
                try:
                    modules = self.framework.get_modules_by_type(module_type)
                    return jsonify([m.to_dict() if hasattr(m, 'to_dict') else str(m) for m in modules])
                except Exception as e:
                    self.logger.warning(f"Error filtering by type: {e}")
            
            if not full_view and not module_type and hasattr(self.framework, 'get_module_counts_by_type'):
                try:
                    counts = self.framework.get_module_counts_by_type()
                    return jsonify(counts)
                except Exception as e:
                    self.logger.warning(f"Error getting counts: {e}")
            
            modules = self.framework.get_available_modules()
            if isinstance(modules, dict):
                result = {}
                for module_path, module_file in modules.items():
                    module_info = self.framework.get_module_info(module_path)
                    if module_info:
                        result[module_path] = module_info
                    else:
                        result[module_path] = {
                            'name': module_path,
                            'description': 'No description available',
                            'author': 'Unknown',
                            'references': []
                        }
                return jsonify(result)
            return jsonify(modules)

        @self.app.route('/api/modules/<path:module_path>', methods=['GET'])
        def get_module_info(module_path):
            """Récupère les informations d'un module"""
            if not self.check_auth(request):
                return jsonify({'error': 'Non autorisé'}), 401
            
            # Charger le module pour obtenir ses options
            module = self.framework.load_module(module_path, load_only=True)
            if not module:
                return jsonify({'error': 'Module non trouvé'}), 404
            
            # Format unifié (compatible avec les deux versions)
            if hasattr(module, 'get_info'):
                info = module.get_info()
                options = module.get_options()
                return jsonify({
                    'info': info,
                    'options': options,
                    'name': getattr(module, 'name', ''),
                    'description': getattr(module, 'description', ''),
                    'author': getattr(module, 'author', '')
                })
            else:
                return jsonify({
                    'name': getattr(module, 'name', ''),
                    'description': getattr(module, 'description', ''),
                    'author': getattr(module, 'author', ''),
                    'options': module.get_options() if hasattr(module, 'get_options') else {}
                })
        
        @self.app.route('/api/modules/<path:module_path>/run', methods=['POST'])
        def run_module(module_path):
            """Exécute un module (méthode originale avec streaming)"""
            if not self.check_auth(request):
                return jsonify({'error': 'Non autorisé'}), 401
            
            # Récupérer les options du module
            data = request.json or {}
            options = data.get('options', {})
            
            # Charger le module
            if hasattr(self.framework, 'module_loader'):
                module = self.framework.module_loader.load_module(module_path)
            else:
                module = self.framework.load_module(module_path)
            
            if not module:
                return jsonify({'error': 'Module non trouvé'}), 404
            
            # Configurer les options
            for option_name, option_value in options.items():
                module.set_option(option_name, option_value)
            
            # Créer un ID client pour cette exécution
            client_id = str(uuid.uuid4())
            
            # Configurer la redirection des sorties
            self.setup_output_redirection(client_id)
            
            # Exécuter le module dans un thread séparé
            thread = threading.Thread(target=self.run_module_thread, args=(module, client_id))
            thread.daemon = True
            thread.start()
            
            return jsonify({
                'status': 'success',
                'message': 'Module en cours d\'exécution',
                'client_id': client_id
            })
        
        @self.app.route('/api/modules/<path:module_path>/execute', methods=['POST'])
        def execute_module(module_path):
            """Exécute un module (méthode headless avec runtime kernel)"""
            if not self.check_auth(request):
                return jsonify({"error": "Unauthorized"}), 401
            
            data = request.json or {}
            options = data.get('options', {})
            use_runtime_kernel = data.get('use_runtime_kernel', True)
            
            # Charger le module
            module = self.framework.load_module(module_path)
            if not module:
                return jsonify({"error": "Module not found"}), 404
            
            # Configurer les options
            for key, value in options.items():
                if hasattr(module, key):
                    module.set_option(key, value)
            
            # Exécuter le module
            try:
                if use_runtime_kernel and hasattr(self.framework, 'execute_module'):
                    result = self.framework.execute_module(use_runtime_kernel=use_runtime_kernel)
                else:
                    result = module.run()
                
                return jsonify({
                    "status": "success",
                    "result": str(result) if result else None
                })
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "error": str(e)
                }), 500
        
        @self.app.route('/api/sessions', methods=['GET'])
        def get_sessions():
            if not self.check_auth(request):
                return jsonify({'error': 'Non autorisé'}), 401
            
            sessions = self.framework.session.list_sessions()
            return jsonify(sessions)
        
        @self.app.route('/api/sessions/<int:session_id>', methods=['GET'])
        def get_session(session_id):
            if not self.check_auth(request):
                return jsonify({'error': 'Non autorisé'}), 401
            
            session = self.framework.session.get_session(session_id)
            if not session:
                return jsonify({'error': 'Session non trouvée'}), 404
            
            return jsonify(session)
        
        @self.app.route('/api/sessions/<int:session_id>', methods=['DELETE'])
        def delete_session(session_id):
            if not self.check_auth(request):
                return jsonify({'error': 'Non autorisé'}), 401
            
            result = self.framework.session.destroy_session(session_id)
            if not result:
                return jsonify({'error': 'Session non trouvée'}), 404
            
            return jsonify({'status': 'success', 'message': f'Session {session_id} supprimée'})
        
        @self.app.route('/api/output/<client_id>', methods=['GET'])
        def get_output(client_id):
            if not self.check_auth(request):
                return jsonify({'error': 'Non autorisé'}), 401
            
            if client_id not in self.clients:
                return jsonify({'error': 'Client non trouvé'}), 404
            
            # Récupérer les sorties du client
            outputs = self.clients[client_id]['outputs']
            
            # Vider la liste des sorties
            self.clients[client_id]['outputs'] = []
            
            return jsonify(outputs)
        
        @self.app.route('/api/output/<client_id>/stream', methods=['GET'])
        def stream_output(client_id):
            if not self.check_auth(request):
                return jsonify({'error': 'Non autorisé'}), 401
            
            if client_id not in self.clients:
                return jsonify({'error': 'Client non trouvé'}), 404
            
            def generate():
                while client_id in self.clients and self.clients[client_id]['active']:
                    outputs = self.clients[client_id]['outputs']
                    if outputs:
                        # Récupérer les sorties et vider la liste
                        current_outputs = outputs.copy()
                        self.clients[client_id]['outputs'] = []
                        
                        # Envoyer les sorties au format SSE
                        yield f"data: {json.dumps(current_outputs)}\n\n"
                    
                    time.sleep(0.1)
            
            return self.app.response_class(
                generate(),
                mimetype='text/event-stream'
            )
        
        # ===== Routes Interpréteur (si disponible) =====
        
        if INTERPRETER_AVAILABLE:
            @self.app.route('/api/interpreter/execute', methods=['POST'])
            def execute_interpreter():
                if not self.check_auth(request):
                    return jsonify({'error': 'Non autorisé'}), 401
                
                try:
                    data = request.get_json()
                    if not data or 'code' not in data:
                        return jsonify({'error': 'Code manquant'}), 400
                    
                    code = data['code'].strip()
                    if not code:
                        return jsonify({'error': 'Code vide'}), 400
                    
                    # Obtenir ou créer l'interpréteur pour cette session
                    session_id = request.headers.get('X-Session-ID', 'default')
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
                        # Exécuter le code directement avec runsource
                        exec_result = interpreter.runsource(code)
                        
                        # Récupérer les sorties
                        output = stdout.getvalue()
                        error = stderr.getvalue()
                        
                        response = {
                            'output': output if output else None,
                            'error': error if error else None,
                            'result': str(exec_result) if exec_result is not None else None
                        }
                        
                        return jsonify(response)
                        
                    finally:
                        # Restaurer stdout et stderr
                        sys.stdout = old_stdout
                        sys.stderr = old_stderr
                        
                except Exception as e:
                    logging.exception("Erreur lors de l'exécution du code")
                    return jsonify({'error': str(e)}), 500
        
        # ===== Routes Runtime Kernel (si disponible) =====
        
        if RUNTIME_KERNEL_AVAILABLE:
            @self.app.route('/api/pipelines', methods=['POST'])
            def create_pipeline():
                """Crée et exécute un pipeline"""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                
                if not hasattr(self.framework, 'event_bus'):
                    return jsonify({"error": "Event bus not available"}), 503
                
                data = request.json or {}
                pipeline_name = data.get('name', 'pipeline')
                steps = data.get('steps', [])
                initial_data = data.get('initial_data', {})
                
                # Créer le pipeline
                pipeline = Pipeline(
                    name=pipeline_name,
                    description=data.get('description', ''),
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
                try:
                    context = pipeline.execute(
                        initial_data=initial_data,
                        module_loader=lambda path: self.framework.load_module(path),
                        workflow_loader=lambda path: self.framework.load_module(path)
                    )
                    
                    return jsonify({
                        "status": context.status,
                        "pipeline_id": context.pipeline_id,
                        "results": {k: str(v) for k, v in context.results.items()},
                        "errors": context.errors,
                        "duration": time.time() - context.start_time
                    })
                except Exception as e:
                    return jsonify({
                        "status": "error",
                        "error": str(e)
                    }), 500
            
            @self.app.route('/api/events', methods=['GET'])
            def get_events():
                """Récupère l'historique des événements"""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                
                if not hasattr(self.framework, 'event_bus'):
                    return jsonify({"error": "Event bus not available"}), 503
                
                event_type = request.args.get('type')
                limit = int(request.args.get('limit', 100))
                
                if event_type:
                    try:
                        event_type_enum = EventType[event_type]
                        events = self.framework.event_bus.get_history(event_type_enum, limit)
                    except KeyError:
                        return jsonify({"error": "Invalid event type"}), 400
                else:
                    events = self.framework.event_bus.get_history(limit=limit)
                
                return jsonify([{
                    "event_type": e.event_type.value,
                    "data": e.data,
                    "timestamp": e.timestamp.isoformat(),
                    "source": e.source
                } for e in events])
            
            @self.app.route('/api/resources/<module_id>', methods=['GET'])
            def get_resource_usage(module_id):
                """Récupère l'utilisation des ressources d'un module"""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                
                if not hasattr(self.framework, 'runtime_kernel'):
                    return jsonify({"error": "Runtime kernel not available"}), 503
                
                usage = self.framework.runtime_kernel.get_resource_usage(module_id)
                if not usage:
                    return jsonify({"error": "Module not found or not monitored"}), 404
                
                return jsonify({
                    "module_id": usage.module_id,
                    "cpu_percent": usage.cpu_percent,
                    "memory_mb": usage.memory_mb,
                    "thread_count": usage.thread_count,
                    "start_time": usage.start_time,
                    "last_update": usage.last_update
                })
        
        # ===== Routes Workspaces =====
        
        @self.app.route('/api/workspaces', methods=['GET'])
        def list_workspaces():
            """Liste les workspaces"""
            if not self.check_auth(request):
                return jsonify({"error": "Unauthorized"}), 401
            
            if hasattr(self.framework, 'get_workspaces'):
                workspaces = self.framework.get_workspaces()
                return jsonify(workspaces)
            else:
                return jsonify({"error": "Workspaces not available"}), 503
        
        @self.app.route('/api/workspaces/<name>', methods=['POST'])
        def switch_workspace(name):
            """Change de workspace"""
            if not self.check_auth(request):
                return jsonify({"error": "Unauthorized"}), 401
            
            if hasattr(self.framework, 'set_workspace'):
                success = self.framework.set_workspace(name)
                return jsonify({"success": success})
            else:
                return jsonify({"error": "Workspaces not available"}), 503
        
        # ===== Routes Registry Marketplace =====
        
        if self.registry_service:
            @self.app.route('/api/registry/extensions', methods=['GET'])
            def list_registry_extensions():
                """Liste les extensions du registry"""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                
                extension_type = request.args.get('type')
                is_free = request.args.get('is_free')
                search = request.args.get('search')
                page = int(request.args.get('page', 1))
                per_page = int(request.args.get('per_page', 20))
                
                if is_free is not None:
                    is_free = is_free.lower() == 'true'
                
                result = self.registry_service.list_extensions(
                    extension_type=extension_type,
                    is_free=is_free,
                    search=search,
                    page=page,
                    per_page=per_page
                )
                return jsonify(result)
            
            @self.app.route('/api/registry/extensions/<extension_id>', methods=['GET'])
            def get_registry_extension(extension_id):
                """Récupère les détails d'une extension"""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                
                extension = self.registry_service.get_extension(extension_id)
                if not extension:
                    return jsonify({"error": "Extension not found"}), 404
                
                return jsonify(extension)
            
            @self.app.route('/api/registry/extensions/<extension_id>/download', methods=['GET'])
            def download_registry_extension(extension_id):
                """Télécharge le bundle d'une extension"""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                
                version = request.args.get('version')
                bundle_path = self.registry_service.get_extension_bundle(extension_id, version)
                
                if not bundle_path or not os.path.exists(bundle_path):
                    return jsonify({"error": "Bundle not found"}), 404
                
                from flask import send_file
                return send_file(
                    bundle_path,
                    as_attachment=True,
                    download_name=os.path.basename(bundle_path)
                )
            
            @self.app.route('/api/registry/extensions/<extension_id>/purchase', methods=['POST'])
            def purchase_registry_extension(extension_id):
                """Achète une extension payante"""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                
                data = request.json or {}
                user_id = data.get('user_id')
                version = data.get('version')
                
                if not user_id:
                    return jsonify({"error": "user_id required"}), 400
                
                license_obj = self.registry_service.purchase_extension(extension_id, user_id, version)
                if not license_obj:
                    return jsonify({"error": "Purchase failed"}), 400
                
                return jsonify({
                    "success": True,
                    "license_id": license_obj.id,
                    "extension_id": extension_id,
                    "version": license_obj.version
                })
            
            @self.app.route('/api/registry/publishers', methods=['POST'])
            def register_publisher():
                """Enregistre un nouvel éditeur"""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                
                data = request.json or {}
                name = data.get('name')
                email = data.get('email')
                public_key = data.get('public_key')
                kyc_data = data.get('kyc_data')
                
                if not all([name, email, public_key]):
                    return jsonify({"error": "name, email, and public_key required"}), 400
                
                publisher = self.registry_service.register_publisher(name, email, public_key, kyc_data)
                if not publisher:
                    return jsonify({"error": "Registration failed"}), 400
                
                return jsonify({
                    "success": True,
                    "publisher_id": publisher.id,
                    "name": publisher.name
                })
            
            @self.app.route('/api/registry/extensions', methods=['POST'])
            def publish_extension():
                """Publie une nouvelle extension"""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                
                # Cette route nécessiterait un upload de fichier
                # Pour l'instant, on retourne une erreur
                return jsonify({"error": "Use /api/registry/extensions/upload for publishing"}), 501
            
            @self.app.route('/api/registry/extensions/<extension_id>/revoke', methods=['POST'])
            def revoke_extension(extension_id):
                """Révoque une extension"""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                
                data = request.json or {}
                reason = data.get('reason', 'No reason provided')
                actor_id = data.get('actor_id', 'admin')
                
                success = self.registry_service.revoke_extension(extension_id, reason, actor_id)
                if not success:
                    return jsonify({"error": "Revocation failed"}), 400
                
                return jsonify({"success": True})
    
    def check_auth(self, request):
        """Vérifie l'authentification de la requête (supporte X-API-Key et Authorization Bearer)"""
        if not self.api_key:
            return True
        
        # Support de X-API-Key (méthode originale)
        api_key = request.headers.get('X-API-Key')
        if api_key == self.api_key:
            return True
        
        # Support de Authorization Bearer (méthode headless_service)
        auth_header = request.headers.get('Authorization')
        if auth_header:
            # Format: "Bearer <api_key>" ou juste "<api_key>"
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
            else:
                token = auth_header
            
            if token == self.api_key:
                return True
        
        return False
    
    def setup_output_redirection(self, client_id):
        """Configure la redirection des sorties pour un client"""
        # Créer un client
        self.clients[client_id] = {
            'active': True,
            'outputs': [],
            'result': None
        }
        
        # Configurer les callbacks
        def stdout_callback(text):
            if client_id in self.clients:
                self.clients[client_id]['outputs'].append({
                    'type': 'stdout',
                    'text': text,
                    'timestamp': time.time()
                })
        
        def stderr_callback(text):
            if client_id in self.clients:
                self.clients[client_id]['outputs'].append({
                    'type': 'stderr',
                    'text': text,
                    'timestamp': time.time()
                })
        
        # Ajouter les callbacks
        self.framework.output_handler.add_stdout_callback(stdout_callback)
        self.framework.output_handler.add_stderr_callback(stderr_callback)
        
        # Stocker les callbacks pour pouvoir les supprimer plus tard
        self.clients[client_id]['callbacks'] = {
            'stdout': stdout_callback,
            'stderr': stderr_callback
        }
        
        # Démarrer la redirection
        self.framework.output_handler.start_redirection()
    
    def run_module_thread(self, module, client_id):
        """Exécute un module dans un thread séparé"""
        try:
            # Exécuter le module
            result = module.run()
            
            # Stocker le résultat
            if client_id in self.clients:
                self.clients[client_id]['result'] = result
                self.clients[client_id]['outputs'].append({
                    'type': 'result',
                    'result': result,
                    'timestamp': time.time()
                })
        except Exception as e:
            logging.error(f"Erreur lors de l'exécution du module: {e}")
            if client_id in self.clients:
                self.clients[client_id]['outputs'].append({
                    'type': 'error',
                    'error': str(e),
                    'timestamp': time.time()
                })
        finally:
            # Nettoyer les ressources
            if client_id in self.clients:
                # Supprimer les callbacks
                callbacks = self.clients[client_id]['callbacks']
                self.framework.output_handler.remove_stdout_callback(callbacks['stdout'])
                self.framework.output_handler.remove_stderr_callback(callbacks['stderr'])
                
                # Marquer le client comme inactif
                self.clients[client_id]['active'] = False
                
                # Arrêter la redirection si plus aucun client n'est actif
                active_clients = [c for c in self.clients.values() if c['active']]
                if not active_clients:
                    self.framework.output_handler.stop_redirection()
    
    def run_interpreter_thread(self, interpreter, code, client_id):
        """Exécute du code dans l'interpréteur"""
        try:
            # Exécuter le code
            result = interpreter.runsource(code)
            
            # Stocker le résultat
            if client_id in self.clients:
                self.clients[client_id]['result'] = result
                self.clients[client_id]['outputs'].append({
                    'type': 'result',
                    'result': result,
                    'timestamp': time.time()
                })
        except Exception as e:
            if client_id in self.clients:
                self.clients[client_id]['outputs'].append({
                    'type': 'error',
                    'error': str(e),
                    'timestamp': time.time()
                })
        finally:
            if client_id in self.clients:
                self.clients[client_id]['active'] = False
    
    def start(self):
        """Démarre le serveur API"""
        if self.running:
            return
        
        def run_server():
            self.app.run(host=self.host, port=self.port, debug=False, use_reloader=False, threaded=True)
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        self.running = True
        
        self.logger.info(f"API server started on {self.host}:{self.port}")
    
    def stop(self):
        """Arrête le serveur API"""
        # Flask ne supporte pas l'arrêt propre, on marque juste comme arrêté
        self.running = False
        self.logger.info("API server stopped") 
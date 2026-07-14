#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API Server unifié - Service REST pour le framework
Combine les fonctionnalités de api_server et headless_service
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import threading
import uuid
import logging
import json
import time
import io
import sys
import os
from typing import Any, Dict, Optional

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

from interfaces.api_security import (
    ROLE_PERMISSIONS,
    ApiRateLimiter,
    RequestAuthenticator,
    RotatingTokenManager,
    iso_timestamp,
    mask_token,
    normalize_roles,
    parse_cors_origins,
    secrets_equal,
)
from interfaces.node_command_service import NodeCommandService, RelayRemoteClientError, RelayService

class ApiServer:
    """
    Serveur API unifié pour le framework
    
    Fournit une API REST complète pour contrôler le framework sans interface CLI.
    Combine les fonctionnalités d'api_server (sessions, streaming, interpréteur) 
    et headless_service (pipelines, events, resources, workspaces).
    """
    
    def __init__(self, framework, host='127.0.0.1', port=5000, api_key=None, ssl_context=None):
        self.host = host
        self.port = port
        self.api_key = (api_key or "").strip() or None
        self.ssl_context = ssl_context
        self.started_at = time.time()
        self.app = Flask(__name__)
        self.framework = framework
        self.clients = {}  # Stocke les clients connectés
        self.interpreters = {}  # Stocke les interpréteurs par session
        self.server_thread: Optional[threading.Thread] = None
        self.running = False
        self.token_manager = RotatingTokenManager(self.api_key, issuer="kittysploit-api")
        self.authenticator = RequestAuthenticator(self.token_manager)
        self.rate_limiter = ApiRateLimiter()
        self.route_permissions: Dict[str, str] = {}
        self.route_rate_tiers: Dict[str, str] = {}
        self._last_auth_error: Dict[str, Any] = {
            "status_code": 401,
            "error": "Unauthorized",
            "message": "A valid API key or Bearer access token is required.",
        }
        
        # Logger
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._configure_cors()
        
        # Initialize registry service if available (mode serveur registry uniquement)
        # Note: Le registry est normalement un service distant géré par KittySploit
        # Ce service local est optionnel pour les déploiements self-hosted
        self.registry_service = None
        self.registry_signature_manager = None
        self.registry_mode = os.getenv('KITTYSPLOIT_REGISTRY_MODE', 'client')  # 'client' ou 'server'
        
        if self.registry_mode == 'server':
            # Mode serveur : ce framework peut servir de registry pour d'autres clients
            try:
                # Import registry models to ensure they're registered with Base
                import core.registry.models  # noqa: F401
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
        
        self.node_command_service = NodeCommandService(self.framework, enabled=True)
        self.relay_service = RelayService()
        
        self.setup_routes()
    
    def setup_routes(self):
        """Configure les routes de l'API"""

        @self.app.before_request
        def enforce_rbac():
            return self.enforce_rbac()
        
        @self.app.route('/api/node/status', methods=['GET'])
        def node_status():
            """Cluster-compatible node health (kittyCluster / kittyconsole --api)."""
            if not self.check_auth(request):
                return jsonify({'error': 'Unauthorized'}), 401
            return jsonify(self.node_command_service.status())

        @self.app.route('/api/node/command', methods=['POST'])
        def node_command():
            """Cluster-compatible remote CLI dispatch (kittyCluster / kittyconsole --api)."""
            if not self.check_auth(request):
                return jsonify({'error': 'Unauthorized'}), 401
            data = request.json or {}
            result = self.node_command_service.execute(str(data.get('command') or ''))
            result['state'] = self.node_command_service.status()
            return jsonify(result)

        @self.app.route('/api/relay/status', methods=['POST'])
        def relay_status():
            """Forward a status request from this relay to an explicit target node."""
            if not self.check_auth(request):
                return jsonify({'error': 'Unauthorized'}), 401
            try:
                return jsonify(self.relay_service.relay_status(request.json or {}))
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            except RelayRemoteClientError as exc:
                return jsonify({"error": str(exc)}), 502

        @self.app.route('/api/relay/command', methods=['POST'])
        def relay_command():
            """Forward a command request from this relay to an explicit target node."""
            if not self.check_auth(request):
                return jsonify({'error': 'Unauthorized'}), 401
            try:
                return jsonify(self.relay_service.relay_command(request.json or {}))
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            except RelayRemoteClientError as exc:
                return jsonify({"error": str(exc)}), 502

        # ===== Routes de base =====
        
        @self.app.route('/api/health', methods=['GET'])
        def health():
            """Health check public (résumé non sensible)."""
            return jsonify(self.health_payload(detailed=False))

        @self.app.route('/api/health/live', methods=['GET'])
        def health_live():
            """Liveness check public."""
            return jsonify({
                "status": "alive",
                "service": "kittysploit-api",
                "timestamp": iso_timestamp(),
                "uptime_seconds": round(time.time() - self.started_at, 3),
            })

        @self.app.route('/api/health/ready', methods=['GET'])
        def health_ready():
            """Readiness check avec statut HTTP adapté."""
            payload = self.health_payload(detailed=True)
            status_code = 200 if payload.get("status") in ("healthy", "degraded") else 503
            return jsonify(payload), status_code

        @self.app.route('/api/health/detailed', methods=['GET'])
        def health_detailed():
            """Health détaillé pour opérateurs authentifiés."""
            return jsonify(self.health_payload(detailed=True))

        @self.app.route('/api/openapi.json', methods=['GET'])
        def openapi_json():
            """Specification OpenAPI 3.0 de l'API REST."""
            return jsonify(self.build_openapi_spec())

        @self.app.route('/api/docs', methods=['GET'])
        def api_docs():
            """Documentation Swagger UI minimale."""
            return (
                """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>KittySploit API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => SwaggerUIBundle({ url: "/api/openapi.json", dom_id: "#swagger-ui" });
  </script>
</body>
</html>""",
                200,
                {"Content-Type": "text/html; charset=utf-8"},
            )

        @self.app.route('/api/auth/token', methods=['POST'])
        def auth_token():
            """Émet un access token court terme et un refresh token rotatif."""
            data = request.json or {}
            roles = normalize_roles(data.get("roles") or ("operator",))
            token_data = self.token_manager.issue_pair(
                subject=str(data.get("subject") or "operator"),
                roles=roles,
                permissions=data.get("permissions") or None,
                access_ttl_seconds=data.get("ttl_seconds"),
                refresh_ttl_seconds=data.get("refresh_ttl_seconds"),
                metadata={"issuer": "api"},
            )
            return jsonify(token_data), 201

        @self.app.route('/api/auth/refresh', methods=['POST'])
        @self.app.route('/api/auth/rotate', methods=['POST'])
        def auth_refresh():
            """Rotation du refresh token: révoque l'ancienne famille et émet une nouvelle paire."""
            data = request.json or {}
            refresh_token = data.get("refresh_token")
            if not refresh_token:
                auth_header = request.headers.get("Authorization", "")
                if auth_header.lower().startswith("bearer "):
                    refresh_token = auth_header[7:].strip()
            token_data = self.token_manager.rotate_refresh(refresh_token)
            if not token_data:
                return jsonify({
                    "error": "Unauthorized",
                    "message": "A valid refresh token is required.",
                }), 401
            return jsonify(token_data)

        @self.app.route('/api/auth/revoke', methods=['POST'])
        def auth_revoke():
            """Révoque un access/refresh token rotatif."""
            data = request.json or {}
            body_token = data.get("token") or data.get("refresh_token")
            current_token = request.headers.get("X-API-Key")
            auth_header = request.headers.get("Authorization", "")
            if auth_header.lower().startswith("bearer "):
                current_token = auth_header[7:].strip()

            token = body_token
            if not token:
                token = current_token
            ctx = getattr(g, "auth_context", None)
            if body_token and token != current_token and ctx and not ctx.has_permission("auth:token"):
                return jsonify({
                    "error": "Forbidden",
                    "message": "Only an admin token can revoke another token.",
                }), 403
            if token and self.api_key and secrets_equal(token, self.api_key):
                with self.token_manager._lock:
                    if self.token_manager._bootstrap_enabled:
                        self.token_manager._bootstrap_enabled = False
                return jsonify({
                    "success": True,
                    "message": "Bootstrap API key has been disabled. Use rotating tokens for future access.",
                })
            revoked = self.token_manager.revoke(token)
            return jsonify({"revoked": revoked, "token": mask_token(token)})

        @self.app.route('/api/auth/me', methods=['GET'])
        def auth_me():
            """Retourne le principal authentifié et les stats RBAC."""
            ctx = getattr(g, "auth_context", None)
            return jsonify({
                "principal": ctx.to_dict() if ctx else None,
                "token_manager": self.token_manager.stats(),
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
                # Full metadata for every module is expensive; return a compact catalog
                # and only hydrate info when ?details=1 is set.
                details = request.args.get('details', '').lower() in ('1', 'true', 'yes')
                for module_path, module_file in modules.items():
                    if details:
                        module_info = self.framework.get_module_info(module_path)
                        if module_info:
                            result[module_path] = module_info
                            continue
                    result[module_path] = {
                        'name': str(module_path).rsplit('/', 1)[-1],
                        'path': module_path,
                        'file': module_file if isinstance(module_file, str) else None,
                        'description': 'No description available',
                        'author': 'Unknown',
                        'references': [],
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

            @self.app.route('/api/workflows', methods=['GET'])
            def list_workflows():
                """List declarative workflow library definitions."""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                try:
                    from core.workflows import list_workflow_ids, load_workflow_definition

                    items = []
                    for workflow_id in list_workflow_ids():
                        definition = load_workflow_definition(workflow_id)
                        items.append({
                            "id": definition.workflow_id,
                            "name": definition.name,
                            "description": definition.description,
                            "tags": definition.tags,
                            "steps": len(definition.steps),
                            "quick_win": definition.quick_win,
                        })
                    return jsonify({"workflows": items, "count": len(items)})
                except Exception as e:
                    return jsonify({"error": str(e)}), 500

            @self.app.route('/api/workflows/<workflow_id>/run', methods=['POST'])
            def run_workflow(workflow_id):
                """Execute a library workflow by id."""
                if not self.check_auth(request):
                    return jsonify({"error": "Unauthorized"}), 401
                try:
                    from core.workflows import WorkflowEngine, load_workflow_definition

                    data = request.json or {}
                    variables = dict(data.get("variables") or {})
                    if data.get("target"):
                        variables["target"] = data["target"]
                    variables["workflow_id"] = workflow_id
                    dry_run = bool(data.get("dry_run", False))

                    definition = load_workflow_definition(workflow_id)
                    engine = WorkflowEngine(self.framework)
                    result = engine.run(definition, variables, dry_run=dry_run)
                    return jsonify({
                        "workflow_id": result.workflow_id,
                        "success": result.success,
                        "dry_run": result.dry_run,
                        "duration_seconds": result.duration_seconds,
                        "steps_executed": result.steps_executed,
                        "step_results": result.step_results,
                        "errors": result.errors,
                        "plan": result.plan,
                    })
                except FileNotFoundError:
                    return jsonify({"error": f"Workflow not found: {workflow_id}"}), 404
                except Exception as e:
                    return jsonify({"error": str(e)}), 500
            
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

        self.configure_route_permissions()

    def _configure_cors(self) -> None:
        """Enable CORS only when KITTYSPLOIT_API_CORS_ORIGINS is explicitly set."""
        origins = parse_cors_origins(os.environ.get("KITTYSPLOIT_API_CORS_ORIGINS"))
        if not origins:
            self.logger.info(
                "CORS disabled by default; set KITTYSPLOIT_API_CORS_ORIGINS to allow cross-origin access"
            )
            return
        if origins == ["*"]:
            self.logger.warning("CORS allows all origins (KITTYSPLOIT_API_CORS_ORIGINS=*)")
            CORS(self.app, resources={r"/api/*": {"origins": "*"}})
            return
        CORS(
            self.app,
            resources={r"/api/*": {"origins": origins}},
            supports_credentials=True,
        )
        self.logger.info("CORS enabled for origins: %s", ", ".join(origins))

    def configure_route_permissions(self):
        """Map Flask endpoints to RBAC permissions."""
        self.route_permissions = {
            # Public, low-sensitivity discovery/status endpoints.
            "health": "public",
            "health_live": "public",
            "openapi_json": "public",
            "api_docs": "public",
            "auth_refresh": "public",

            # Auth/token lifecycle.
            "auth_token": "auth:token",
            "auth_revoke": "authenticated",
            "auth_me": "authenticated",

            # Health/details and framework read paths.
            "health_ready": "health:read",
            "health_detailed": "health:read",
            "get_metrics": "metrics:read",
            "get_modules": "modules:read",
            "get_module_info": "modules:read",
            "get_sessions": "sessions:read",
            "get_session": "sessions:read",
            "get_output": "output:read",
            "stream_output": "output:read",
            "get_events": "events:read",
            "get_resource_usage": "resources:read",
            "list_workspaces": "workspaces:read",
            "list_registry_extensions": "registry:read",
            "get_registry_extension": "registry:read",
            "download_registry_extension": "registry:read",
            "node_status": "authenticated",
            "node_command": "authenticated",
            "relay_status": "authenticated",
            "relay_command": "authenticated",

            # Mutating/high-risk operations.
            "generate_mock_data": "mock:generate",
            "run_module": "modules:run",
            "execute_module": "modules:run",
            "delete_session": "sessions:delete",
            "execute_interpreter": "interpreter:execute",
            "create_pipeline": "pipelines:write",
            "switch_workspace": "workspaces:switch",
            "purchase_registry_extension": "registry:write",
            "register_publisher": "registry:write",
            "publish_extension": "registry:write",
            "revoke_extension": "registry:write",
        }
        self.route_rate_tiers = {
            "health": "public",
            "health_live": "public",
            "openapi_json": "public",
            "api_docs": "public",
            "auth_token": "auth",
            "auth_refresh": "auth",
            "auth_revoke": "auth",
            "generate_mock_data": "admin",
            "run_module": "mutate",
            "execute_module": "mutate",
            "delete_session": "mutate",
            "execute_interpreter": "admin",
            "create_pipeline": "mutate",
            "switch_workspace": "mutate",
            "purchase_registry_extension": "admin",
            "register_publisher": "admin",
            "publish_extension": "admin",
            "revoke_extension": "admin",
            "node_status": "read",
            "node_command": "mutate",
            "relay_status": "read",
            "relay_command": "mutate",
        }

    def enforce_rbac(self):
        """Authenticate and authorize every /api route before reaching handlers."""
        if not request.path.startswith("/api"):
            return None

        permission = self.route_permissions.get(request.endpoint)
        if permission == "public":
            rate_tier = self.route_rate_tiers.get(request.endpoint, "public")
            allowed, rate_info = self.rate_limiter.allow(
                rate_tier,
                request.remote_addr or "unknown",
            )
            if not allowed:
                return self.rate_limit_response(rate_info)
            return None

        rate_tier = self.route_rate_tiers.get(request.endpoint, "read")
        allowed, rate_info = self.rate_limiter.allow(
            rate_tier,
            request.remote_addr or "unknown",
        )
        if not allowed:
            return self.rate_limit_response(rate_info)

        if permission is None:
            permission = "admin:all"

        required_permission = None if permission == "authenticated" else permission
        ctx, error = self.authenticator.authenticate_request(request, required_permission)
        if error:
            self._last_auth_error = error
            return self.auth_error_response()

        g.auth_context = ctx
        return None
    
    def check_auth(self, request, permission=None):
        """Vérifie l'authentification de la requête (supporte X-API-Key et Authorization Bearer).

        Sans clé serveur configurée, l'accès est refusé (plus d'« open bar » par défaut).
        """
        ctx = getattr(g, "auth_context", None)
        if ctx and ctx.has_permission(permission):
            return True

        ctx, error = self.authenticator.authenticate_request(request, permission)
        if error:
            self._last_auth_error = error
            return False
        g.auth_context = ctx
        return True

    def rate_limit_response(self, rate_info: Optional[Dict[str, int]]):
        """Return a 429 response when a client exceeds route rate limits."""
        info = rate_info or {}
        response = jsonify({
            "error": "Too Many Requests",
            "message": "API rate limit exceeded for this endpoint.",
            "retry_after": info.get("retry_after"),
            "limit": info.get("limit"),
            "window_seconds": info.get("window_seconds"),
        })
        response.status_code = 429
        retry_after = info.get("retry_after")
        if retry_after:
            response.headers["Retry-After"] = str(retry_after)
        return response

    def auth_error_response(self):
        """Return the last authentication/authorization error as JSON."""
        error = dict(self._last_auth_error)
        status_code = int(error.pop("status_code", 401))
        return jsonify(error), status_code

    def health_payload(self, detailed=False):
        """Build API health details without leaking internals on the public summary."""
        auth_ready = bool(self.api_key)
        framework_ready = self.framework is not None
        status = "healthy" if auth_ready and framework_ready else "unhealthy"
        runtime_status = (
            "active"
            if (RUNTIME_KERNEL_AVAILABLE and hasattr(self.framework, 'runtime_kernel'))
            else "inactive"
        )

        payload = {
            "status": status,
            "service": "kittysploit-api",
            "version": getattr(self.framework, 'version', 'unknown'),
            "timestamp": iso_timestamp(),
            "uptime_seconds": round(time.time() - self.started_at, 3),
            "runtime_kernel": runtime_status,
            "interpreter": "available" if INTERPRETER_AVAILABLE else "unavailable",
        }

        if not detailed:
            return payload

        components = {
            "framework": {
                "status": "ok" if framework_ready else "error",
                "workspace": getattr(self.framework, "current_workspace", None),
            },
            "auth": {
                "status": "ok" if auth_ready else "error",
                **self.token_manager.stats(),
            },
            "runtime_kernel": {
                "status": runtime_status,
                "package_available": RUNTIME_KERNEL_AVAILABLE,
            },
            "interpreter": {
                "status": "available" if INTERPRETER_AVAILABLE else "unavailable",
            },
            "registry": {
                "mode": self.registry_mode,
                "status": "available" if self.registry_service else "client",
            },
            "clients": {
                "total": len(self.clients),
                "active": sum(1 for c in self.clients.values() if c.get("active")),
            },
        }

        try:
            if hasattr(self.framework, "get_module_counts_by_type"):
                components["modules"] = {
                    "status": "ok",
                    "counts": self.framework.get_module_counts_by_type(),
                }
            elif hasattr(self.framework, "get_available_modules"):
                modules = self.framework.get_available_modules()
                components["modules"] = {
                    "status": "ok",
                    "count": len(modules) if hasattr(modules, "__len__") else None,
                }
        except Exception as e:
            components["modules"] = {"status": "degraded", "error": str(e)}
            status = "degraded"

        try:
            if hasattr(self.framework, "get_workspaces"):
                workspaces = self.framework.get_workspaces()
                components["workspaces"] = {
                    "status": "ok",
                    "count": len(workspaces) if hasattr(workspaces, "__len__") else None,
                }
        except Exception as e:
            components["workspaces"] = {"status": "degraded", "error": str(e)}
            status = "degraded"

        payload["status"] = status
        payload["components"] = components
        payload["rbac"] = {
            role: sorted(perms)
            for role, perms in ROLE_PERMISSIONS.items()
        }
        return payload

    def build_openapi_spec(self):
        """Return a compact OpenAPI 3 document for the Flask REST surface."""
        security = [{"ApiKeyAuth": []}, {"BearerAuth": []}]

        def response(description, schema_type="object"):
            return {
                "description": description,
                "content": {
                    "application/json": {
                        "schema": {"type": schema_type},
                    },
                },
            }

        def operation(
            method,
            summary,
            permission="authenticated",
            *,
            request_body=False,
            parameters=None,
            public=False,
        ):
            op = {
                "summary": summary,
                "operationId": method,
                "responses": {
                    "200": response("OK"),
                    "401": response("Unauthorized"),
                    "403": response("Forbidden"),
                },
                "x-rbac-permission": "public" if public else permission,
            }
            if public:
                op["security"] = []
                op["responses"].pop("401", None)
                op["responses"].pop("403", None)
            else:
                op["security"] = security
            if parameters:
                op["parameters"] = parameters
            if request_body:
                op["requestBody"] = {
                    "required": False,
                    "content": {
                        "application/json": {
                            "schema": {"type": "object", "additionalProperties": True},
                        },
                    },
                }
            return op

        path_param = lambda name, typ="string": {
            "name": name,
            "in": "path",
            "required": True,
            "schema": {"type": typ},
        }

        paths = {
            "/api/health": {
                "get": operation("getHealth", "Public health summary", public=True),
            },
            "/api/health/live": {
                "get": operation("getLiveness", "Public liveness check", public=True),
            },
            "/api/health/ready": {
                "get": operation("getReadiness", "Detailed readiness check", "health:read"),
            },
            "/api/health/detailed": {
                "get": operation("getDetailedHealth", "Detailed health report", "health:read"),
            },
            "/api/openapi.json": {
                "get": operation("getOpenApiSpec", "OpenAPI document", public=True),
            },
            "/api/auth/token": {
                "post": operation("issueToken", "Issue rotating access/refresh tokens", "auth:token", request_body=True),
            },
            "/api/auth/refresh": {
                "post": operation("refreshToken", "Rotate a refresh token", public=True, request_body=True),
            },
            "/api/auth/rotate": {
                "post": operation("rotateToken", "Alias for refresh-token rotation", public=True, request_body=True),
            },
            "/api/auth/revoke": {
                "post": operation("revokeToken", "Revoke a rotating token", "authenticated", request_body=True),
            },
            "/api/auth/me": {
                "get": operation("getAuthContext", "Current authenticated principal", "authenticated"),
            },
            "/api/metrics": {
                "get": operation("getMetrics", "Framework metrics", "metrics:read"),
            },
            "/api/data/generate-mock": {
                "post": operation("generateMockData", "Generate mock framework data", "mock:generate", request_body=True),
            },
            "/api/modules": {
                "get": operation("listModules", "List modules", "modules:read"),
            },
            "/api/modules/{module_path}": {
                "get": operation(
                    "getModuleInfo",
                    "Get module metadata and options",
                    "modules:read",
                    parameters=[path_param("module_path")],
                ),
            },
            "/api/modules/{module_path}/run": {
                "post": operation(
                    "runModule",
                    "Run a module with output streaming",
                    "modules:run",
                    request_body=True,
                    parameters=[path_param("module_path")],
                ),
            },
            "/api/modules/{module_path}/execute": {
                "post": operation(
                    "executeModule",
                    "Run a module via classic or runtime-kernel execution",
                    "modules:run",
                    request_body=True,
                    parameters=[path_param("module_path")],
                ),
            },
            "/api/sessions": {
                "get": operation("listSessions", "List sessions", "sessions:read"),
            },
            "/api/sessions/{session_id}": {
                "get": operation(
                    "getSession",
                    "Get session details",
                    "sessions:read",
                    parameters=[path_param("session_id", "integer")],
                ),
                "delete": operation(
                    "deleteSession",
                    "Delete a session",
                    "sessions:delete",
                    parameters=[path_param("session_id", "integer")],
                ),
            },
            "/api/output/{client_id}": {
                "get": operation(
                    "getOutput",
                    "Poll module output",
                    "output:read",
                    parameters=[path_param("client_id")],
                ),
            },
            "/api/output/{client_id}/stream": {
                "get": operation(
                    "streamOutput",
                    "Stream module output via SSE",
                    "output:read",
                    parameters=[path_param("client_id")],
                ),
            },
            "/api/interpreter/execute": {
                "post": operation(
                    "executeInterpreter",
                    "Execute Python in the framework interpreter",
                    "interpreter:execute",
                    request_body=True,
                ),
            },
            "/api/pipelines": {
                "post": operation("createPipeline", "Create and execute a pipeline", "pipelines:write", request_body=True),
            },
            "/api/events": {
                "get": operation("listEvents", "List runtime events", "events:read"),
            },
            "/api/resources/{module_id}": {
                "get": operation(
                    "getResourceUsage",
                    "Get module resource usage",
                    "resources:read",
                    parameters=[path_param("module_id")],
                ),
            },
            "/api/workspaces": {
                "get": operation("listWorkspaces", "List workspaces", "workspaces:read"),
            },
            "/api/workspaces/{name}": {
                "post": operation(
                    "switchWorkspace",
                    "Switch workspace",
                    "workspaces:switch",
                    parameters=[path_param("name")],
                ),
            },
            "/api/registry/extensions": {
                "get": operation("listRegistryExtensions", "List registry extensions", "registry:read"),
                "post": operation("publishExtension", "Publish a registry extension", "registry:write", request_body=True),
            },
            "/api/registry/extensions/{extension_id}": {
                "get": operation(
                    "getRegistryExtension",
                    "Get registry extension details",
                    "registry:read",
                    parameters=[path_param("extension_id")],
                ),
            },
            "/api/registry/extensions/{extension_id}/download": {
                "get": operation(
                    "downloadRegistryExtension",
                    "Download registry extension bundle",
                    "registry:read",
                    parameters=[path_param("extension_id")],
                ),
            },
            "/api/registry/extensions/{extension_id}/purchase": {
                "post": operation(
                    "purchaseRegistryExtension",
                    "Purchase a registry extension",
                    "registry:write",
                    request_body=True,
                    parameters=[path_param("extension_id")],
                ),
            },
            "/api/registry/publishers": {
                "post": operation("registerPublisher", "Register a publisher", "registry:write", request_body=True),
            },
            "/api/registry/extensions/{extension_id}/revoke": {
                "post": operation(
                    "revokeRegistryExtension",
                    "Revoke a registry extension",
                    "registry:write",
                    request_body=True,
                    parameters=[path_param("extension_id")],
                ),
            },
        }

        return {
            "openapi": "3.0.3",
            "info": {
                "title": "KittySploit REST API",
                "version": getattr(self.framework, 'version', 'unknown'),
                "description": "REST control surface for KittySploit with rotating tokens and RBAC.",
            },
            "servers": [{"url": f"http://{self.host}:{self.port}"}],
            "paths": paths,
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key",
                        "description": "Bootstrap admin key, normally used to mint rotating tokens.",
                    },
                    "BearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "description": "Rotating access token returned by /api/auth/token or /api/auth/refresh.",
                    },
                },
                "schemas": {
                    "Error": {
                        "type": "object",
                        "properties": {
                            "error": {"type": "string"},
                            "message": {"type": "string"},
                            "required_permission": {"type": "string"},
                        },
                    }
                },
            },
            "x-rbac-roles": {
                role: sorted(perms)
                for role, perms in ROLE_PERMISSIONS.items()
            },
        }
    
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

        if not self.api_key:
            self.logger.error(
                "API server refused to start: set a non-empty api_key "
                "(CLI --api-key / -k or environment KITTYSPLOIT_API_KEY)."
            )
            raise ValueError("ApiServer requires a non-empty api_key")

        def run_server():
            self.app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
                threaded=True,
                ssl_context=self.ssl_context,
            )
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        self.running = True
        
        scheme = "https" if self.ssl_context is not None else "http"
        self.logger.info(f"API server started on {scheme}://{self.host}:{self.port}")
    
    def stop(self):
        """Arrête le serveur API"""
        # Flask ne supporte pas l'arrêt propre, on marque juste comme arrêté
        self.running = False
        self.logger.info("API server stopped")

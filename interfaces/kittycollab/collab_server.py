#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Serveur Flask simple pour afficher les pages web du kittycollab
"""

import os
import sys
import requests
import json
from threading import Lock

# Ajouter le répertoire parent au PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    from flask import Flask, render_template, send_from_directory, jsonify, request
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("ERROR: Flask is required. Install with: pip install flask flask-cors")
    sys.exit(1)

from core.config import Config
from core.output_handler import print_info, print_success, print_error, print_warning


class CollabWebServer:
    """Serveur web simple qui sert uniquement les pages HTML"""
    
    def __init__(self, host="127.0.0.1", port=5001, verbose=False):
        if not FLASK_AVAILABLE:
            raise ImportError("Flask is required")
        
        self.host = host
        self.port = port
        self.saas_url = "https://collab.kittysploit.com"
        self.verbose = verbose
        self.api_key = self._load_api_key()
        self.api_key_valid = False
        self.api_key_error = None
        self.api_session_token = None
        self.sessions_lock = Lock()
        self.saved_sessions_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_sessions.json")
        
        # Chemins vers les templates et static
        base_dir = os.path.dirname(os.path.abspath(__file__))
        template_dir = os.path.join(base_dir, 'templates')
        static_dir = os.path.join(base_dir, 'static')
        
        # Si les dossiers n'existent pas, utiliser ceux de collab
        if not os.path.exists(template_dir):
            template_dir = os.path.join(os.path.dirname(base_dir), 'collab', 'templates')
        if not os.path.exists(static_dir):
            static_dir = os.path.join(os.path.dirname(base_dir), 'collab', 'static')
        
        if self.verbose:
            print_info(f"Template folder: {template_dir}")
            print_info(f"Static folder: {static_dir}")
            print_info(f"Template folder exists: {os.path.exists(template_dir)}")
            print_info(f"Static folder exists: {os.path.exists(static_dir)}")
        
        # Créer l'app Flask
        self.app = Flask(__name__,
                        template_folder=template_dir,
                        static_folder=static_dir)
        CORS(self.app)

        # Validate API key once at startup
        self._validate_api_key()

        self._setup_routes()

    def _load_api_key(self) -> str:
        """Récupère l'API key depuis la configuration ou les variables d'environnement"""
        try:
            config = Config.get_instance().config
            framework_cfg = config.get('FRAMEWORK') or config.get('framework') or {}
            api_key = os.environ.get('KITTYSPLOIT_API_KEY') or framework_cfg.get('api_key') or ''
            return api_key.strip()
        except Exception as e:
            if self.verbose:
                print_warning(f"Unable to load API key from config: {e}")
            return ''

    def _validate_api_key(self) -> bool:
        """Valide l'API key en interrogeant le serveur SaaS"""
        if not self.api_key:
            self.api_key_error = "No API key configured. Add a valid key in config.toml (section [FRAMEWORK])."
            if self.verbose:
                print_warning(self.api_key_error)
            return False

        validation_url = f"{self.saas_url}/api/auth/validate-api-key"

        try:
            response = requests.get(
                validation_url,
                params={'api_key': self.api_key},
                timeout=10
            )

            if response.status_code == 200:
                # Exiger une réponse JSON explicite avec un champ "valid" et récupérer le token
                if response.headers.get('Content-Type', '').startswith('application/json'):
                    data = response.json()
                    if data.get('valid') is True:
                        self.api_session_token = data.get('token') or data.get('access_token')
                        self.api_key_valid = True
                        if self.verbose:
                            print_success("API key validated successfully.")
                            if self.api_session_token:
                                print_success("Session token retrieved from the API key.")
                        return True
                    self.api_key_error = data.get('message', "API key invalide.")
                else:
                    self.api_key_error = "Unexpected response from the server when validating the API key."
            else:
                self.api_key_error = f"Failed to validate the API key (HTTP {response.status_code})."

        except requests.RequestException as e:
            self.api_key_error = f"Unable to validate the API key: {e}"

        if self.verbose:
            print_error(self.api_key_error)
        return False

    def _render_invalid_api_key(self):
        """Affiche une page dédiée si l'API key est absente ou invalide"""
        return render_template(
            'invalid_api_key.html',
            server_url=self.saas_url or '',
            error_message=self.api_key_error
        ), 403
    
    def _setup_routes(self):
        """Configure les routes pour servir les pages HTML"""
        
        @self.app.route('/')
        def index():
            """Page de login"""
            if not self.api_key_valid:
                return self._render_invalid_api_key()
            if self.verbose:
                print_info(f"[GET /] Serving login page")
            try:
                return render_template(
                    'login.html',
                    server_url=self.saas_url or '',
                    api_token=self.api_session_token
                )
            except Exception as e:
                print_error(f"Error rendering login.html: {e}")
                return f"<h1>Error</h1><p>Could not load login page: {str(e)}</p>", 500
        
        @self.app.route('/rooms')
        def rooms():
            """Page des salons"""
            if not self.api_key_valid:
                return self._render_invalid_api_key()
            if self.verbose:
                print_info(f"[GET /rooms] Serving rooms page")
            try:
                return render_template(
                    'rooms.html',
                    server_url=self.saas_url or '',
                    api_token=self.api_session_token
                )
            except Exception as e:
                print_error(f"Error rendering rooms.html: {e}")
                return f"<h1>Error</h1><p>Could not load rooms page: {str(e)}</p>", 500
        
        @self.app.route('/editor')
        def editor():
            """Page de l'éditeur"""
            if not self.api_key_valid:
                return self._render_invalid_api_key()
            if self.verbose:
                print_info(f"[GET /editor] Serving editor page")
            try:
                return render_template(
                    'index.html',
                    server_url=self.saas_url or '',
                    api_token=self.api_session_token
                )
            except Exception as e:
                print_error(f"Error rendering index.html: {e}")
                return f"<h1>Error</h1><p>Could not load editor page: {str(e)}</p>", 500

        @self.app.route('/api/saved-sessions', methods=['GET'])
        def list_saved_sessions():
            """Retourne la liste des sessions enregistrées (persistées en JSON)"""
            try:
                sessions = self._load_saved_sessions()
                return jsonify({'status': 'success', 'sessions': sessions})
            except Exception as e:
                print_error(f"Error reading saved sessions: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/api/saved-sessions', methods=['POST'])
        def save_session():
            """Enregistre ou met à jour une session"""
            try:
                payload = request.get_json(force=True) or {}
                room_id = (payload.get('id') or '').strip()
                description = payload.get('description') or 'No description'

                if not room_id:
                    return jsonify({'status': 'error', 'message': 'Missing room id'}), 400

                with self.sessions_lock:
                    sessions = self._load_saved_sessions()
                    existing_idx = next((i for i, s in enumerate(sessions) if s.get('id') == room_id), -1)
                    session_data = {
                        'id': room_id,
                        'description': description,
                        'savedAt': self._now_iso()
                    }
                    if existing_idx >= 0:
                        sessions[existing_idx] = session_data
                    else:
                        sessions.append(session_data)
                    self._write_saved_sessions(sessions)

                return jsonify({'status': 'success'})
            except Exception as e:
                print_error(f"Error saving session: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/api/saved-sessions/<room_id>', methods=['DELETE'])
        def delete_session(room_id):
            """Supprime une session enregistrée"""
            try:
                room_id = (room_id or '').strip()
                if not room_id:
                    return jsonify({'status': 'error', 'message': 'Missing room id'}), 400

                with self.sessions_lock:
                    sessions = self._load_saved_sessions()
                    filtered = [s for s in sessions if s.get('id') != room_id]
                    self._write_saved_sessions(filtered)

                return jsonify({'status': 'success'})
            except Exception as e:
                print_error(f"Error deleting session: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        # Route de test
        @self.app.route('/test')
        def test():
            """Route de test"""
            if not self.api_key_valid:
                return self._render_invalid_api_key()
            if self.verbose:
                print_info(f"[GET /test] Test route called")
            return "<h1>Server is working!</h1><p>If you see this, the server is running correctly.</p>", 200
        
        # Route spécifique pour le favicon
        @self.app.route('/favicon.ico')
        def serve_favicon():
            """Serve favicon from interfaces/static/img"""
            if self.verbose:
                print_info(f"[GET /favicon.ico] Serving favicon")
            
            current_file_dir = os.path.dirname(os.path.abspath(__file__))  # interfaces/collab_client
            interfaces_dir = os.path.dirname(current_file_dir)  # interfaces
            favicon_path = os.path.join(interfaces_dir, 'static', 'img', 'favicon.ico')
            
            if not os.path.exists(favicon_path):
                if self.verbose:
                    print_warning(f"Favicon not found at: {favicon_path}")
                return jsonify({'status': 'error', 'message': 'Favicon not found'}), 404
            
            try:
                return send_from_directory(os.path.join(interfaces_dir, 'static', 'img'), 'favicon.ico', mimetype='image/x-icon')
            except Exception as e:
                print_error(f"Error serving favicon: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        # Route pour servir les images depuis interfaces/static/img
        @self.app.route('/static/img/<path:filename>')
        def serve_static_img(filename):
            """Serve static images from interfaces/static/img"""
            if self.verbose:
                print_info(f"[GET /static/img/{filename}] Serving image")
            
            # Chemin vers interfaces/static/img
            # __file__ est dans interfaces/collab_client/simple_server.py
            # On remonte jusqu'à interfaces/ puis on va dans static/img
            current_file_dir = os.path.dirname(os.path.abspath(__file__))  # interfaces/collab_client
            interfaces_dir = os.path.dirname(current_file_dir)  # interfaces
            static_img_dir = os.path.join(interfaces_dir, 'static', 'img')
            
            if not os.path.exists(static_img_dir):
                if self.verbose:
                    print_warning(f"Static img directory not found at: {static_img_dir}")
                return jsonify({'status': 'error', 'message': 'Directory not found'}), 404
            
            file_path = os.path.join(static_img_dir, filename)
            if not os.path.exists(file_path):
                if self.verbose:
                    print_warning(f"Image not found: {file_path}")
                return jsonify({'status': 'error', 'message': 'File not found'}), 404
            
            try:
                # Déterminer le type MIME pour le favicon
                mimetype = None
                if filename.lower().endswith('.ico'):
                    mimetype = 'image/x-icon'
                elif filename.lower().endswith('.png'):
                    mimetype = 'image/png'
                elif filename.lower().endswith('.jpg') or filename.lower().endswith('.jpeg'):
                    mimetype = 'image/jpeg'
                elif filename.lower().endswith('.gif'):
                    mimetype = 'image/gif'
                elif filename.lower().endswith('.svg'):
                    mimetype = 'image/svg+xml'
                
                return send_from_directory(static_img_dir, filename, mimetype=mimetype)
            except Exception as e:
                print_error(f"Error serving image: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        # Routes API locales pour les modules
        @self.app.route('/api/modules', methods=['GET'])
        def get_modules():
            """Liste les modules locaux"""
            if self.verbose:
                print_info(f"[GET /api/modules] Listing local modules")
            
            modules = []
            # Chemin vers le répertoire modules (à la racine du projet)
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            root_dir = os.path.join(base_dir, 'modules')
            
            if not os.path.exists(root_dir):
                if self.verbose:
                    print_warning(f"Modules directory not found at: {root_dir}")
                return jsonify({'status': 'success', 'modules': []})
            
            try:
                for root, dirs, files in os.walk(root_dir):
                    # Ignorer les dossiers cachés et spéciaux
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'venv' and d != '__pycache__']
                    
                    for file in files:
                        if file.endswith('.py') and not file.startswith('__'):
                            full_path = os.path.join(root, file)
                            rel_path = os.path.relpath(full_path, root_dir)
                            rel_path = rel_path.replace('\\', '/')
                            modules.append({'name': file, 'path': rel_path})
                
                modules.sort(key=lambda x: x['path'])
                if self.verbose:
                    print_info(f"Found {len(modules)} local modules")
                return jsonify({'status': 'success', 'modules': modules})
            except Exception as e:
                print_error(f"Error listing modules: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/modules/<path:module_path>', methods=['GET'])
        def get_module_content(module_path):
            """Récupère le contenu d'un module local"""
            if self.verbose:
                print_info(f"[GET /api/modules/{module_path}] Getting module content")
            
            # Chemin vers le répertoire modules
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            root_dir = os.path.join(base_dir, 'modules')
            full_path = os.path.join(root_dir, module_path)
            
            # Sécurité : s'assurer que le chemin est dans le répertoire modules
            if not os.path.abspath(full_path).startswith(os.path.abspath(root_dir)):
                return jsonify({'status': 'error', 'message': 'Access denied'}), 403
            
            if not os.path.exists(full_path):
                return jsonify({'status': 'error', 'message': 'Module not found'}), 404
            
            try:
                # Essayer d'abord avec UTF-8, puis avec latin-1 si ça échoue
                try:
                    with open(full_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except UnicodeDecodeError:
                    # Si UTF-8 échoue, essayer latin-1 (qui peut lire n'importe quel byte)
                    with open(full_path, 'r', encoding='latin-1') as f:
                        content = f.read()
                
                return jsonify({'status': 'success', 'content': content})
            except Exception as e:
                print_error(f"Error reading module: {e}")
                import traceback
                traceback.print_exc()
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/modules/<path:module_path>', methods=['POST'])
        def save_module_content(module_path):
            """Sauvegarde le contenu d'un module local"""
            if self.verbose:
                print_info(f"[POST /api/modules/{module_path}] Saving module content")
            
            from flask import request
            
            # Chemin vers le répertoire modules
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            root_dir = os.path.join(base_dir, 'modules')
            full_path = os.path.join(root_dir, module_path)
            
            # Sécurité : s'assurer que le chemin est dans le répertoire modules
            if not os.path.abspath(full_path).startswith(os.path.abspath(root_dir)):
                return jsonify({'status': 'error', 'message': 'Access denied'}), 403
            
            data = request.json
            content = data.get('content', '')
            
            try:
                # Créer les répertoires si nécessaire
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                if self.verbose:
                    print_info(f"Module saved: {module_path}")
                return jsonify({'status': 'success'})
            except Exception as e:
                print_error(f"Error saving module: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500
    
    def start(self):
        """Démarre le serveur"""
        print_success("=" * 60)
        print_success("KittySploit Collab Web Server")
        print_success("=" * 60)
        print_success(f"Server running on: http://{self.host}:{self.port}")
        print_info("Press Ctrl+C to stop the server")
        
        try:
            self.app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False
            )
        except OSError as e:
            print_error(f"Error starting server: {e}")
            raise
        except KeyboardInterrupt:
            print_info("Server stopped.")
        except Exception as e:
            print_error(f"Error starting server: {e}")
            import traceback
            traceback.print_exc()
            raise

    def _load_saved_sessions(self):
        """Charge les sessions sauvegardées depuis le fichier JSON"""
        if not os.path.exists(self.saved_sessions_file):
            return []
        try:
            with open(self.saved_sessions_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    # Sanitize legacy entries (remove token if present)
                    for item in data:
                        if isinstance(item, dict) and 'token' in item:
                            item.pop('token', None)
                    return data
                return []
        except Exception as e:
            print_warning(f"Could not read saved sessions file: {e}")
            return []

    def _write_saved_sessions(self, sessions):
        """Écrit les sessions sauvegardées dans le fichier JSON"""
        try:
            with open(self.saved_sessions_file, 'w', encoding='utf-8') as f:
                json.dump(sessions, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print_error(f"Could not write saved sessions file: {e}")
            raise

    @staticmethod
    def _now_iso():
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

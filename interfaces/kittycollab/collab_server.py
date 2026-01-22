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
        # Cache pour les fichiers des rooms (évite les incohérences du load balancer)
        self.room_files_cache = {}  # {room_id: {'data': {...}, 'timestamp': float}}
        self.cache_ttl = 1.0  # Cache valide pendant 1 seconde (réduit pour plus de réactivité)
        
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
        # Configurer CORS pour permettre toutes les origines (nécessaire pour Socket.IO)
        CORS(self.app, resources={
            r"/*": {
                "origins": "*",
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization", "X-API-Key"]
            }
        })

        # Validate API key once at startup
        if self.verbose:
            print_info(f"Validating API key against {self.saas_url}...")
        self._validate_api_key()
        if self.verbose:
            if self.api_key_valid:
                print_success("API key validation successful")
            else:
                print_error(f"API key validation failed: {self.api_key_error}")

        self._setup_routes()
    
    def _invalidate_room_files_cache(self, room_id: str = None):
        """Invalide le cache des fichiers d'une room (ou toutes si room_id est None)"""
        if room_id:
            if room_id in self.room_files_cache:
                del self.room_files_cache[room_id]
        else:
            self.room_files_cache.clear()

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
                headers={
                    'X-API-Key': self.api_key,
                    'User-Agent': 'Kittysploit-Framework/2.0'
                },
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
                    self.api_key_error = f"Unexpected response from the server when validating the API key. Content-Type: {response.headers.get('Content-Type', 'unknown')}"
            else:
                # Essayer de récupérer plus d'informations sur l'erreur
                try:
                    error_body = response.text[:200]
                    self.api_key_error = f"Failed to validate the API key (HTTP {response.status_code}): {error_body}"
                except:
                    self.api_key_error = f"Failed to validate the API key (HTTP {response.status_code})."

        except requests.exceptions.Timeout:
            self.api_key_error = f"Timeout while connecting to {self.saas_url}. The server may be unreachable or slow."
        except requests.exceptions.SSLError as e:
            self.api_key_error = f"SSL error when connecting to {self.saas_url}: {e}. Check your SSL certificates."
        except requests.exceptions.ConnectionError as e:
            self.api_key_error = f"Connection error: Unable to reach {self.saas_url}. Check your internet connection. Error: {e}"
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
        
        # Route proxy pour /api/rooms vers le serveur SaaS
        @self.app.route('/api/rooms', methods=['GET'])
        def proxy_rooms():
            """Proxy pour récupérer la liste des rooms depuis le serveur SaaS"""
            if not self.api_key_valid:
                return jsonify({'status': 'error', 'message': 'API key not valid'}), 401
            
            try:
                token = request.args.get('token', '')
                url = f"{self.saas_url}/api/rooms"
                headers = {
                    'X-API-Key': self.api_key,  # Utiliser l'API key originale pour l'authentification
                    'User-Agent': 'Kittysploit-Framework/2.0'
                }
                # Ajouter le token de session si disponible (pour les rooms privées)
                if self.api_session_token:
                    headers['Authorization'] = f'Bearer {self.api_session_token}'
                # Ajouter le token passé en paramètre si fourni
                if token:
                    url += f'?token={token}'
                
                resp = requests.get(url, headers=headers, timeout=10)
                resp.raise_for_status()
                return jsonify(resp.json()), resp.status_code
            except requests.RequestException as e:
                print_error(f"Error proxying rooms request: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 502
        
        # Route proxy pour /api/rooms/{room_id}/files vers le serveur SaaS
        # IMPORTANT: Cette route doit être définie AVANT les routes catch-all pour les fichiers individuels
        @self.app.route('/api/rooms/<room_id>/files', methods=['GET'], strict_slashes=False)
        def proxy_room_files(room_id):
            """Proxy pour récupérer la liste des fichiers d'une room depuis le serveur SaaS avec cache"""
            if self.verbose:
                print_info(f"[GET /api/rooms/{room_id}/files] Proxy request received")
            if not self.api_key_valid:
                if self.verbose:
                    print_error(f"[GET /api/rooms/{room_id}/files] API key not valid")
                return jsonify({'status': 'error', 'message': 'API key not valid'}), 401
            
            import time
            current_time = time.time()
            
            # Vérifier le cache
            if room_id in self.room_files_cache:
                cached = self.room_files_cache[room_id]
                if current_time - cached['timestamp'] < self.cache_ttl:
                    # Retourner les données en cache
                    if self.verbose:
                        file_count = len(cached['data'].get('files', [])) if isinstance(cached['data'], dict) and cached['data'].get('status') == 'success' else 0
                        print_info(f"[PROXY] /api/rooms/{room_id}/files returned {file_count} files (from cache)")
                    return jsonify(cached['data']), 200
            
            try:
                url = f"{self.saas_url}/api/rooms/{room_id}/files"
                headers = {
                    'X-API-Key': self.api_key,
                    'User-Agent': 'Kittysploit-Framework/2.0'
                }
                if self.api_session_token:
                    headers['Authorization'] = f'Bearer {self.api_session_token}'
                
                resp = requests.get(url, headers=headers, timeout=10)
                resp.raise_for_status()
                data = resp.json()
                
                # Mettre en cache
                self.room_files_cache[room_id] = {
                    'data': data,
                    'timestamp': current_time
                }
                
                # Nettoyer le cache ancien (garder seulement les 10 dernières rooms)
                if len(self.room_files_cache) > 10:
                    oldest_room = min(self.room_files_cache.keys(), 
                                    key=lambda k: self.room_files_cache[k]['timestamp'])
                    del self.room_files_cache[oldest_room]
                
                # Log pour debug
                if self.verbose:
                    file_count = len(data.get('files', [])) if isinstance(data, dict) and data.get('status') == 'success' else 0
                    print_info(f"[PROXY] /api/rooms/{room_id}/files returned {file_count} files (fresh)")
                
                return jsonify(data), resp.status_code
            except requests.RequestException as e:
                print_error(f"Error proxying room files request: {e}")
                # En cas d'erreur, retourner le cache si disponible
                if room_id in self.room_files_cache:
                    cached = self.room_files_cache[room_id]
                    if self.verbose:
                        print_warning(f"[PROXY] Using cached data due to error")
                    return jsonify(cached['data']), 200
                return jsonify({'status': 'error', 'message': str(e)}), 502
        
        # Route proxy catch-all pour les autres endpoints de fichiers (upload, delete, content, etc.)
        # Cette route doit être définie APRÈS la route /api/rooms/<room_id>/files pour éviter les conflits
        @self.app.route('/api/rooms/<room_id>/files/<path:file_path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def proxy_room_file_operations(room_id, file_path):
            """Proxy catch-all pour les opérations sur les fichiers (upload, delete, content, etc.)"""
            if self.verbose:
                print_info(f"[{request.method} /api/rooms/{room_id}/files/{file_path}] Proxy request received")
            if not self.api_key_valid:
                return jsonify({'status': 'error', 'message': 'API key not valid'}), 401
            
            try:
                # Construire l'URL complète vers le SaaS
                url = f"{self.saas_url}/api/rooms/{room_id}/files/{file_path}"
                # Ajouter les query parameters si présents
                if request.query_string:
                    url += '?' + request.query_string.decode('utf-8')
                
                headers = {
                    'X-API-Key': self.api_key,
                    'User-Agent': 'Kittysploit-Framework/2.0'
                }
                if self.api_session_token:
                    headers['Authorization'] = f'Bearer {self.api_session_token}'
                
                # Copier les headers Content-Type si présents
                if request.content_type:
                    headers['Content-Type'] = request.content_type
                
                # Préparer les données selon la méthode
                if request.method in ['POST', 'PUT']:
                    if request.is_json:
                        data = request.get_json()
                        resp = requests.request(request.method, url, json=data, headers=headers, timeout=10)
                    elif request.content_type and 'multipart/form-data' in request.content_type:
                        # Pour les uploads de fichiers
                        files = {}
                        data = {}
                        for key, value in request.form.items():
                            data[key] = value
                        for key, file in request.files.items():
                            files[key] = (file.filename, file.stream, file.content_type)
                        resp = requests.request(request.method, url, files=files, data=data, headers=headers, timeout=30)
                    else:
                        resp = requests.request(request.method, url, data=request.data, headers=headers, timeout=10)
                else:
                    resp = requests.request(request.method, url, headers=headers, timeout=10)
                
                resp.raise_for_status()
                
                # Pour les téléchargements de fichiers, retourner le contenu binaire
                if 'download' in request.args or resp.headers.get('Content-Type', '').startswith('image/'):
                    from flask import Response
                    return Response(resp.content, mimetype=resp.headers.get('Content-Type', 'application/octet-stream'))
                
                # Sinon, retourner le JSON
                try:
                    return jsonify(resp.json()), resp.status_code
                except:
                    from flask import Response
                    return Response(resp.content, mimetype=resp.headers.get('Content-Type', 'text/plain')), resp.status_code
                    
            except requests.RequestException as e:
                print_error(f"Error proxying file operation: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 502
        
        # Route proxy pour /api/rooms/{room_id}/upload
        @self.app.route('/api/rooms/<room_id>/upload', methods=['POST'])
        def proxy_room_upload(room_id):
            """Proxy pour l'upload de fichiers vers le serveur SaaS"""
            if self.verbose:
                print_info(f"[POST /api/rooms/{room_id}/upload] Proxy upload request received")
            if not self.api_key_valid:
                return jsonify({'status': 'error', 'message': 'API key not valid'}), 401
            
            try:
                url = f"{self.saas_url}/api/rooms/{room_id}/upload"
                headers = {
                    'X-API-Key': self.api_key,
                    'User-Agent': 'Kittysploit-Framework/2.0'
                }
                if self.api_session_token:
                    headers['Authorization'] = f'Bearer {self.api_session_token}'
                
                # Préparer les fichiers pour l'upload
                files = {}
                data = {}
                for key, value in request.form.items():
                    data[key] = value
                for key, file in request.files.items():
                    files[key] = (file.filename, file.stream, file.content_type)
                
                resp = requests.post(url, files=files, data=data, headers=headers, timeout=30)
                resp.raise_for_status()
                
                # Invalider le cache après un upload
                self._invalidate_room_files_cache(room_id)
                
                return jsonify(resp.json()), resp.status_code
            except requests.RequestException as e:
                print_error(f"Error proxying upload request: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 502
        
        # Route proxy pour créer un salon via HTTP (alternative à Socket.IO)
        @self.app.route('/api/rooms/create', methods=['POST'])
        def proxy_create_room():
            """Proxy pour créer un salon via HTTP vers le serveur SaaS"""
            if not self.api_key_valid:
                return jsonify({'status': 'error', 'message': 'API key not valid'}), 401
            
            try:
                payload = request.get_json(force=True) or {}
                url = f"{self.saas_url}/api/rooms/create"
                headers = {
                    'Content-Type': 'application/json',
                    'X-API-Key': self.api_key,  # Utiliser l'API key originale pour l'authentification
                    'User-Agent': 'Kittysploit-Framework/2.0'
                }
                if self.api_session_token:
                    headers['Authorization'] = f'Bearer {self.api_session_token}'
                
                # Ajouter le token d'accès si fourni
                if payload.get('access_token'):
                    headers['X-Access-Token'] = payload.get('access_token')
                
                resp = requests.post(url, json=payload, headers=headers, timeout=10)
                resp.raise_for_status()
                return jsonify(resp.json()), resp.status_code
            except requests.RequestException as e:
                print_error(f"Error proxying create room request: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 502
        
        # Route proxy pour /api/rooms/{room_id}/notes
        @self.app.route('/api/rooms/<room_id>/notes', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def proxy_room_notes(room_id):
            """Proxy pour les notes d'une room vers le serveur SaaS"""
            if self.verbose:
                print_info(f"[{request.method} /api/rooms/{room_id}/notes] Proxy request received")
            if not self.api_key_valid:
                return jsonify({'status': 'error', 'message': 'API key not valid'}), 401
            
            try:
                url = f"{self.saas_url}/api/rooms/{room_id}/notes"
                headers = {
                    'X-API-Key': self.api_key,
                    'User-Agent': 'Kittysploit-Framework/2.0'
                }
                if self.api_session_token:
                    headers['Authorization'] = f'Bearer {self.api_session_token}'
                
                if request.method == 'GET':
                    resp = requests.get(url, headers=headers, timeout=10)
                elif request.method in ['POST', 'PUT']:
                    if request.is_json:
                        headers['Content-Type'] = 'application/json'
                        resp = requests.request(request.method, url, json=request.get_json(), headers=headers, timeout=10)
                    else:
                        resp = requests.request(request.method, url, data=request.data, headers=headers, timeout=10)
                elif request.method == 'DELETE':
                    resp = requests.delete(url, headers=headers, timeout=10)
                else:
                    return jsonify({'status': 'error', 'message': 'Method not allowed'}), 405
                
                resp.raise_for_status()
                return jsonify(resp.json()), resp.status_code
            except requests.RequestException as e:
                print_error(f"Error proxying room notes request: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 502
        
        # Route proxy pour /api/rooms/{room_id}/description
        @self.app.route('/api/rooms/<room_id>/description', methods=['GET', 'POST', 'PUT'])
        def proxy_room_description(room_id):
            """Proxy pour la description d'une room vers le serveur SaaS"""
            if self.verbose:
                print_info(f"[{request.method} /api/rooms/{room_id}/description] Proxy request received")
            if not self.api_key_valid:
                return jsonify({'status': 'error', 'message': 'API key not valid'}), 401
            
            try:
                url = f"{self.saas_url}/api/rooms/{room_id}/description"
                headers = {
                    'X-API-Key': self.api_key,
                    'User-Agent': 'Kittysploit-Framework/2.0'
                }
                if self.api_session_token:
                    headers['Authorization'] = f'Bearer {self.api_session_token}'
                
                if request.method == 'GET':
                    resp = requests.get(url, headers=headers, timeout=10)
                elif request.method in ['POST', 'PUT']:
                    if request.is_json:
                        headers['Content-Type'] = 'application/json'
                        resp = requests.request(request.method, url, json=request.get_json(), headers=headers, timeout=10)
                    else:
                        resp = requests.request(request.method, url, data=request.data, headers=headers, timeout=10)
                else:
                    return jsonify({'status': 'error', 'message': 'Method not allowed'}), 405
                
                resp.raise_for_status()
                return jsonify(resp.json()), resp.status_code
            except requests.RequestException as e:
                print_error(f"Error proxying room description request: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 502
        
        # Route proxy pour /api/rooms/{room_id}/join
        @self.app.route('/api/rooms/<room_id>/join', methods=['POST'])
        def proxy_room_join(room_id):
            """Proxy pour rejoindre une room vers le serveur SaaS"""
            if self.verbose:
                print_info(f"[POST /api/rooms/{room_id}/join] Proxy request received")
            if not self.api_key_valid:
                return jsonify({'status': 'error', 'message': 'API key not valid'}), 401
            
            try:
                url = f"{self.saas_url}/api/rooms/{room_id}/join"
                headers = {
                    'X-API-Key': self.api_key,
                    'User-Agent': 'Kittysploit-Framework/2.0'
                }
                if self.api_session_token:
                    headers['Authorization'] = f'Bearer {self.api_session_token}'
                
                if request.is_json:
                    headers['Content-Type'] = 'application/json'
                    resp = requests.post(url, json=request.get_json(), headers=headers, timeout=10)
                else:
                    resp = requests.post(url, data=request.data, headers=headers, timeout=10)
                
                resp.raise_for_status()
                return jsonify(resp.json()), resp.status_code
            except requests.RequestException as e:
                print_error(f"Error proxying room join request: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 502
        
        # Route proxy pour /api/rooms/{room_id}/leave
        @self.app.route('/api/rooms/<room_id>/leave', methods=['POST'])
        def proxy_room_leave(room_id):
            """Proxy pour quitter une room vers le serveur SaaS"""
            if self.verbose:
                print_info(f"[POST /api/rooms/{room_id}/leave] Proxy request received")
            if not self.api_key_valid:
                return jsonify({'status': 'error', 'message': 'API key not valid'}), 401
            
            try:
                url = f"{self.saas_url}/api/rooms/{room_id}/leave"
                headers = {
                    'X-API-Key': self.api_key,
                    'User-Agent': 'Kittysploit-Framework/2.0'
                }
                if self.api_session_token:
                    headers['Authorization'] = f'Bearer {self.api_session_token}'
                
                if request.is_json:
                    headers['Content-Type'] = 'application/json'
                    resp = requests.post(url, json=request.get_json(), headers=headers, timeout=10)
                else:
                    resp = requests.post(url, data=request.data, headers=headers, timeout=10)
                
                resp.raise_for_status()
                return jsonify(resp.json()), resp.status_code
            except requests.RequestException as e:
                print_error(f"Error proxying room leave request: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 502
        
        # Route proxy pour supprimer une room.
        # Note: le SaaS expose la suppression via DELETE /api/rooms/<room_id>
        @self.app.route('/api/rooms/<room_id>/delete', methods=['DELETE', 'POST'])
        def proxy_room_delete(room_id):
            """Proxy pour supprimer une room vers le serveur SaaS"""
            if self.verbose:
                print_info(f"[{request.method} /api/rooms/{room_id}/delete] Proxy request received")
            if not self.api_key_valid:
                return jsonify({'status': 'error', 'message': 'API key not valid'}), 401
            
            try:
                # SaaS endpoint (REST): DELETE /api/rooms/<room_id>
                url = f"{self.saas_url}/api/rooms/{room_id}"
                # Forward query params (e.g. ?username=...) if provided by the client
                if request.query_string:
                    url += '?' + request.query_string.decode('utf-8')
                headers = {
                    'X-API-Key': self.api_key,
                    'User-Agent': 'Kittysploit-Framework/2.0'
                }
                if self.api_session_token:
                    headers['Authorization'] = f'Bearer {self.api_session_token}'
                
                if request.method == 'DELETE':
                    resp = requests.delete(url, headers=headers, timeout=10)
                else:  # POST
                    if request.is_json:
                        headers['Content-Type'] = 'application/json'
                        resp = requests.post(url, json=request.get_json(), headers=headers, timeout=10)
                    else:
                        resp = requests.post(url, data=request.data, headers=headers, timeout=10)
                
                resp.raise_for_status()
                return jsonify(resp.json()), resp.status_code
            except requests.RequestException as e:
                print_error(f"Error proxying room delete request: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 502

        # Backward-compatible route: some clients call DELETE /api/rooms/<room_id>
        @self.app.route('/api/rooms/<room_id>', methods=['DELETE'])
        def proxy_room_delete_legacy(room_id):
            """Compat: redirect deletion to /api/rooms/<room_id>/delete"""
            return proxy_room_delete(room_id)
        
        # Route proxy pour /api/rooms/{room_id}/share_module
        @self.app.route('/api/rooms/<room_id>/share_module', methods=['POST'])
        def proxy_room_share_module(room_id):
            """Proxy pour partager un module dans une room vers le serveur SaaS"""
            if self.verbose:
                print_info(f"[POST /api/rooms/{room_id}/share_module] Proxy request received")
            if not self.api_key_valid:
                return jsonify({'status': 'error', 'message': 'API key not valid'}), 401
            
            try:
                url = f"{self.saas_url}/api/rooms/{room_id}/share_module"
                headers = {
                    'X-API-Key': self.api_key,
                    'User-Agent': 'Kittysploit-Framework/2.0'
                }
                if self.api_session_token:
                    headers['Authorization'] = f'Bearer {self.api_session_token}'
                
                if request.is_json:
                    headers['Content-Type'] = 'application/json'
                    resp = requests.post(url, json=request.get_json(), headers=headers, timeout=10)
                else:
                    resp = requests.post(url, data=request.data, headers=headers, timeout=10)
                
                resp.raise_for_status()
                return jsonify(resp.json()), resp.status_code
            except requests.RequestException as e:
                print_error(f"Error proxying room share_module request: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 502
        
        # Route de test
        @self.app.route('/test')
        def test():
            """Route de test"""
            if not self.api_key_valid:
                return self._render_invalid_api_key()
            if self.verbose:
                print_info(f"[GET /test] Test route called")
            return "<h1>Server is working!</h1><p>If you see this, the server is running correctly.</p>", 200
        
        # Route de test pour vérifier les routes proxy
        @self.app.route('/test-proxy')
        def test_proxy():
            """Route de test pour vérifier que les routes proxy sont bien enregistrées"""
            routes = []
            for rule in self.app.url_map.iter_rules():
                routes.append(f"{rule.rule} [{', '.join(rule.methods)}]")
            return jsonify({
                'status': 'success',
                'routes': sorted(routes),
                'api_key_valid': self.api_key_valid
            }), 200
        
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

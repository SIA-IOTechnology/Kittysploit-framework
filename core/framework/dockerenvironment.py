#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import subprocess
import socket
import docker
from core.framework.base_module import BaseModule
from core.output_handler import print_info, print_error, print_success, print_warning, print_status
from core.framework.option import OptBool, OptInteger, OptPort, OptString

class DockerEnvironment(BaseModule):
    """Docker Environment Module"""

    host_port = OptPort(80, "Local port to expose the service", True)
    image_name = OptString("", "Docker image name to use (or image ID/tag)", True)
    container_name = OptString("", "Container name", True)
    auto_cleanup = OptBool(True, "Automatically remove the container at stop", False)
    ready_timeout = OptInteger(120, "Timeout in seconds for the service to be ready", True)
    dockerfile_path = OptString("", "Path to Dockerfile to build image from (optional)", False)
    image_tar_path = OptString("", "Path to .tar file to load image from (optional)", False)
    keep_stdin_open = OptBool(True, "Keep STDIN open for the container (docker -i)", False)
    allocate_tty = OptBool(True, "Allocate a pseudo-TTY for the container (docker -t)", False)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._type = "docker_environment"
        self.container = None
        self.client = None
        self.exposed_ports = {}
        self.environment_vars = {}
        self.volumes = {}
        self.network_mode = "bridge"
        
    def check_docker(self):
        """Check if Docker is installed and accessible"""
        try:
            # First, try to use docker.from_env() which works on both Windows and Linux
            # if Docker is properly configured
            try:
                self.client = docker.from_env()
                self.client.ping()
                print_status("Docker client initialized successfully")
                return True
            except (docker.errors.DockerException, Exception) as e:
                # On Windows, fall back to named pipe if from_env() fails
                if os.name == 'nt':
                    try:
                        self.client = docker.DockerClient(base_url='npipe:////./pipe/docker_engine')
                        self.client.ping()
                        print_status("Docker client initialized successfully")
                        return True
                    except Exception as pipe_error:
                        # Check if Docker Desktop might not be running
                        error_str = str(pipe_error).lower()
                        if 'fichier' in error_str or 'file' in error_str or 'not found' in error_str:
                            print_error("Cannot connect to Docker daemon.")
                            print_error("Docker Desktop is not running or not accessible.")
                            print_warning("Please ensure Docker Desktop is installed and running.")
                            print_info("On Windows, you can start Docker Desktop from the Start menu.")

                            return False
                        raise pipe_error
                else:
                    print_info("On Linux, you may need to start Docker with: sudo systemctl start docker")
                    raise e
        except docker.errors.DockerException as e:
            print_error(f"Docker error: {str(e)}")
            if os.name == 'nt':
                print_error("Ensure Docker Desktop is installed and running.")
                print_info("You can download Docker Desktop from: https://www.docker.com/products/docker-desktop")
            else:
                print_error("Ensure Docker is installed and the Docker daemon is running.")
                print_info("On Linux, you may need to start Docker with: sudo systemctl start docker")
            return False
        except Exception as e:
            print_error(f"Unexpected error connecting to Docker: {str(e)}")
            if os.name == 'nt':
                print_warning("Make sure Docker Desktop is running and try again.")
            return False
    
    def pull_image(self):
        """Pull, build, or load the Docker image"""
        # Priority: 1) Load from tar, 2) Build from Dockerfile, 3) Use existing/pull from registry
        
        # Option 1: Load from tar file
        if self.image_tar_path and os.path.exists(self.image_tar_path):
            try:
                print_status(f"Loading image from tar file: {self.image_tar_path}...")
                with open(self.image_tar_path, 'rb') as tar_file:
                    tar_data = tar_file.read()
                loaded_images = self.client.images.load(tar_data)
                print_success(f"Image loaded successfully from {self.image_tar_path}")
                
                # If image_name is set, verify it exists or use the loaded image
                if self.image_name:
                    try:
                        self.client.images.get(self.image_name)
                        print_status(f"Image {self.image_name} verified")
                    except docker.errors.ImageNotFound:
                        # Try to find the loaded image by ID or use the first one
                        if loaded_images:
                            loaded_img = loaded_images[0]
                            if loaded_img.tags:
                                self.image_name = loaded_img.tags[0]
                                print_status(f"Using loaded image: {self.image_name}")
                            else:
                                print_warning(f"Loaded image has no tags. Using image ID: {loaded_img.id[:12]}")
                                # Try to use the image by ID
                                try:
                                    self.client.images.get(loaded_img.id)
                                    self.image_name = loaded_img.id
                                except:
                                    pass
                        else:
                            print_warning(f"Image {self.image_name} not found after loading. Check available images.")
                return True
            except Exception as e:
                print_error(f"Error loading image from tar: {str(e)}")
                return False
        
        # Option 2: Build from Dockerfile
        if self.dockerfile_path and os.path.exists(self.dockerfile_path):
            try:
                dockerfile_dir = os.path.dirname(os.path.abspath(self.dockerfile_path))
                dockerfile_name = os.path.basename(self.dockerfile_path)
                
                if not self.image_name:
                    print_error("image_name must be specified when building from Dockerfile")
                    return False
                
                print_status(f"Building image {self.image_name} from Dockerfile: {self.dockerfile_path}...")
                image, build_logs = self.client.images.build(
                    path=dockerfile_dir,
                    dockerfile=dockerfile_name,
                    tag=self.image_name,
                    rm=True
                )
                print_success(f"Image {self.image_name} built successfully")
                return True
            except Exception as e:
                print_error(f"Error building image from Dockerfile: {str(e)}")
                return False
        
        # Option 3: Use existing image or pull from registry
        if not self.image_name:
            print_error("Image name not specified")
            return False
            
        try:
            print_status(f"Searching for image {self.image_name}...")
            try:
                self.client.images.get(self.image_name)
                print_status(f"Image {self.image_name} already present locally")
                return True
            except docker.errors.ImageNotFound:
                # Try to find by image ID (short or full)
                try:
                    # Check if it's an image ID (hexadecimal string)
                    if len(self.image_name) >= 12 and all(c in '0123456789abcdefABCDEF' for c in self.image_name):
                        # Try to get by ID
                        images = self.client.images.list()
                        for img in images:
                            if img.id.startswith(self.image_name) or self.image_name in img.id:
                                self.image_name = img.tags[0] if img.tags else img.id
                                print_status(f"Found image by ID: {self.image_name}")
                                return True
                except:
                    pass
                
                # If not found locally, try to pull from registry
                print_status(f"Pulling image {self.image_name} from registry...")
                self.client.images.pull(self.image_name)
                print_success(f"Image {self.image_name} pulled successfully")
                return True
        except Exception as e:
            print_error(f"Error with image {self.image_name}: {str(e)}")
            return False
    
    def wait_for_service(self, host, port, timeout=60):
        """Wait for the service to be available on the specified port"""
        print_status(f"Waiting for the service to be available on {host}:{port}...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((host, port))
                s.close()
                print_success(f"Service available on {host}:{port}")
                return True
            except (socket.timeout, ConnectionRefusedError):
                time.sleep(1)
            except Exception as e:
                print_error(f"Error checking service: {str(e)}")
                return False    
        
        print_error(f"Timeout: The service is not available on {host}:{port} after {timeout} seconds")
        return False
    
    def start_container(self):
        """Start the Docker container"""
        if not self.container_name:
            self.container_name = f"kittysploit_{self._type}_{int(time.time())}"
            
        try:
            # Check if a container with this name already exists
            try:
                existing_container = self.client.containers.get(self.container_name)
                existing_container.reload()
                
                if existing_container.status == "running":
                    # Container is already running, reuse it
                    print_success(f"Container {self.container_name} is already running (ID: {existing_container.id[:12]})")
                    print_info("Reusing existing container instead of creating a new one")
                    self.container = existing_container
                    return True
                else:
                    # Container exists but is stopped, restart it
                    print_status(f"Container {self.container_name} exists but is stopped. Restarting...")
                    existing_container.start()
                    existing_container.reload()
                    self.container = existing_container
                    print_success(f"Container {self.container_name} restarted successfully (ID: {existing_container.id[:12]})")
                    return True
            except docker.errors.NotFound:
                # The container doesn't exist, that's normal - we'll create it
                pass
            
            # Check if ports are already in use by other containers
            docker_ports = {}
            for container_port, host_binding in self.exposed_ports.items():
                # Extract host port from binding
                if isinstance(host_binding, (tuple, list)):
                    host_port = host_binding[-1]
                else:
                    host_port = int(host_binding)
                
                # Check if port is already in use
                try:
                    all_containers = self.client.containers.list(all=True)
                    for container in all_containers:
                        if container.name == self.container_name:
                            continue  # Skip the container we're about to create
                        container.reload()
                        ports = container.attrs.get('NetworkSettings', {}).get('Ports', {})
                        for cp, bindings in ports.items():
                            if bindings:
                                for binding in bindings:
                                    if binding.get('HostPort') == str(host_port):
                                        print_warning(f"Port {host_port} is already in use by container '{container.name}'")
                                        print_info(f"Use 'environments stop {container.name}' to stop it, or change the port in this module")
                                        return False
                except Exception:
                    pass  # If we can't check, continue anyway
                
                # Format: "22/tcp" -> {"22/tcp": (127.0.0.1, 2222)}
                if isinstance(host_binding, (tuple, list)):
                    docker_ports[container_port] = host_binding
                else:
                    docker_ports[container_port] = ('127.0.0.1', int(host_binding))
            
            print_status(f"Starting container {self.container_name}...")
            print_status(f"Ports configuration: {docker_ports}")
            
            # Create and start the container
            try:
                self.container = self.client.containers.run(
                    self.image_name,
                    name=self.container_name,
                    detach=True,
                    ports=docker_ports,
                    environment=self.environment_vars,
                    volumes=self.volumes,
                    network_mode=self.network_mode,
                    auto_remove=self.auto_cleanup,
                    stdin_open=bool(self.keep_stdin_open),
                    tty=bool(self.allocate_tty)
                )
                
                if self.container:
                    print_success(f"Container {self.container_name} started successfully (ID: {self.container.id})")
                else:
                    print_error("Container.run() returned None")
                    return False
            except docker.errors.APIError as e:
                print_error(f"Docker API error: {str(e)}")
                if "port is already allocated" in str(e).lower():
                    print_error("One or more ports are already in use. Try changing the port numbers.")
                return False
            except docker.errors.ImageNotFound as e:
                print_error(f"Image not found: {str(e)}")
                return False
            except Exception as e:
                print_error(f"Unexpected error starting container: {str(e)}")
                import traceback
                print_error(traceback.format_exc())
                return False
            
            # Register the environment in the Docker manager
            if hasattr(self, 'framework') and self.framework and hasattr(self.framework, 'docker_manager'):
                module_name = self.name if hasattr(self, 'name') else self.__class__.__name__
                self.framework.docker_manager.register_environment(
                    self.container.id,
                    self.container_name,
                    self.image_name,
                    self.exposed_ports,
                    module_name
                )
            
            return True
            
        except Exception as e:
            print_error(f"Error starting container: {str(e)}")
            return False
    
    def stop_container(self):
        """Stop the Docker container"""
        if not self.container:
            return True
            
        try:
            print_status(f"Stopping container {self.container_name}...")
            self.container.stop()
            print_success(f"Container {self.container_name} stopped successfully")
            
            # Remove the container if necessary
            if not self.auto_cleanup:
                print_info(f"Removing container {self.container_name}...")
                self.container.remove()
                print_success(f"Container {self.container_name} removed successfully")
            
            return True
        except Exception as e:
            print_error(f"Error stopping container: {str(e)}")
            return False
    
    def _resolve_container_image(self):
        """Return the most useful identifier for the current container image"""
        if not self.container:
            return self.image_name
        try:
            image = getattr(self.container, "image", None)
            if not image:
                return self.image_name
            tags = getattr(image, "tags", None) or []
            if tags:
                return tags[0]
            return getattr(image, "id", self.image_name)
        except Exception:
            return self.image_name

    def _collect_port_bindings(self):
        """Return normalized port bindings for the running container"""
        if not self.container:
            return {}

        try:
            attrs = getattr(self.container, "attrs", {}) or {}
            network_settings = attrs.get("NetworkSettings", {})
            ports = network_settings.get("Ports", {}) or {}
            normalized = {}

            for container_port, bindings in ports.items():
                normalized_bindings = []
                if bindings:
                    for binding in bindings:
                        if not binding:
                            continue
                        host_port = binding.get("HostPort")
                        if host_port is None:
                            continue
                        normalized_bindings.append({
                            "host_ip": binding.get("HostIp") or "127.0.0.1",
                            "host_port": int(host_port)
                        })
                normalized[container_port] = normalized_bindings

            if normalized:
                return normalized
        except Exception:
            pass

        # Fallback to the configured exposures if Docker didn't return bindings
        fallback = {}
        for container_port, host_binding in self.exposed_ports.items():
            bindings = []
            try:
                if isinstance(host_binding, dict):
                    bindings.append({
                        "host_ip": host_binding.get("host_ip", "127.0.0.1"),
                        "host_port": int(host_binding.get("host_port"))
                    })
                elif isinstance(host_binding, (list, tuple)) and len(host_binding) > 0:
                    # Extract IP and port from tuple/list: (ip, port) or (port,)
                    if len(host_binding) >= 2:
                        host_ip = host_binding[0] if host_binding[0] else "127.0.0.1"
                        host_port = host_binding[1]
                    else:
                        host_ip = "127.0.0.1"
                        host_port = host_binding[0]
                    bindings.append({
                        "host_ip": str(host_ip) or "127.0.0.1",
                        "host_port": int(host_port)
                    })
                elif host_binding is not None:
                    # Single integer port value (legacy format)
                    bindings.append({
                        "host_ip": "127.0.0.1",
                        "host_port": int(host_binding)
                    })
            except (ValueError, TypeError, IndexError) as e:
                # Skip invalid port bindings
                continue
            if bindings:
                fallback[container_port] = bindings

        return fallback

    def _build_container_info_stub(self):
        """Return a base info dict used by get_container_info"""
        return {
            "id": getattr(self.container, "id", None) if self.container else None,
            "name": getattr(self.container, "name", self.container_name) if self.container_name else None,
            "status": "not_running" if not self.container else getattr(self.container, "status", None),
            "image": self._resolve_container_image(),
            "ports": {},  # Will be populated by _collect_port_bindings() or get_container_info()
            "created": None,
            "ip_address": None
        }

    def get_container_info(self):
        """Get normalized container information for downstream modules"""
        info = self._build_container_info_stub()

        if not self.container:
            # If container doesn't exist, still normalize ports from exposed_ports
            info["ports"] = self._collect_port_bindings()
            return info
            
        try:
            self.container.reload()  # Update the information
            attrs = getattr(self.container, "attrs", {}) or {}
            state = attrs.get("State", {})

            info.update({
                "status": state.get("Status", getattr(self.container, "status", info["status"])),
                "image": self._resolve_container_image(),
                "ports": self._collect_port_bindings(),
                "created": attrs.get("Created"),
                "ip_address": self.get_container_ip()
            })
            
            return info
        except Exception as e:
            info.update({
                "status": "error",
                "error": str(e)
            })
            return info

    def print_container_overview(self, container_info=None):
        """Print a concise summary of the currently running container"""
        container_info = container_info or self.get_container_info()
        status = container_info.get("status")

        if status == "not_running":
            print_error("Container is not running. Check the logs above for errors.")
            return False

        if status == "error":
            print_error("Unable to retrieve container information.")
            if container_info.get("error"):
                print_error(container_info["error"])
            return False

        container_id = container_info.get("id")
        if container_id:
            print_success(f"Container ID: {container_id[:12]}")
        if status:
            print_success(f"Container status: {status}")

        image_ref = container_info.get("image")
        if image_ref:
            print_status(f"Image: {image_ref}")

        ports = container_info.get("ports") or {}
        if ports:
            print_status("Exposed ports:")
            for container_port, host_bindings in ports.items():
                if not host_bindings:
                    continue
                # Ensure host_bindings is a list
                if not isinstance(host_bindings, list):
                    host_bindings = [host_bindings]
                for binding in host_bindings:
                    # Handle both dict and tuple formats
                    if isinstance(binding, dict):
                        host_ip = binding.get("host_ip", "127.0.0.1")
                        host_port = binding.get("host_port")
                    elif isinstance(binding, (tuple, list)) and len(binding) >= 2:
                        host_ip = binding[0] or "127.0.0.1"
                        host_port = binding[1]
                    else:
                        continue
                    print_info(f"  {host_ip}:{host_port} -> {container_port}")

        return True
    
    def get_container_ip(self):
        """Get the container IP address"""
        if not self.container:
            return None
            
        try:
            self.container.reload()
            networks = self.container.attrs['NetworkSettings']['Networks']
            
            if self.network_mode == 'host':
                return '127.0.0.1'
            elif self.network_mode in networks:
                return networks[self.network_mode]['IPAddress']
            elif 'bridge' in networks:
                return networks['bridge']['IPAddress']
            else:
                for network_name, network_config in networks.items():
                    if 'IPAddress' in network_config and network_config['IPAddress']:
                        return network_config['IPAddress']
            
            return None
        except Exception as e:
            print_error(f"Error getting container IP: {str(e)}")
            return None
    
    def expose_ports(self):
        """Configure exposed ports - override this method in subclasses to define custom ports"""
        # Default: single port from host_port, bound to 127.0.0.1 for security
        if hasattr(self, 'host_port') and self.host_port:
            port_key = f"{self.host_port}/tcp"
            self.exposed_ports = {port_key: ('127.0.0.1', int(self.host_port))}
        else:
            # If no host_port, use default port 80 on 127.0.0.1
            self.exposed_ports = {"80/tcp": ('127.0.0.1', 80)}

    def run_docker(self):
        """Execute the module - handles Docker connection, image pull, and container start"""
        # Vérifier Docker
        if not self.check_docker():
            print_error("Docker check failed")
            return False
            
        # Pull the image if necessary
        if not self.pull_image():
            print_error("Image pull failed")
            return False
            
        # Configure the exposed ports (calls expose_ports() which can be overridden)
        self.expose_ports()
        
        if not self.exposed_ports:
            print_error("No ports configured. Make sure expose_ports() sets self.exposed_ports")
            return False
            
        # Start the container
        if not self.start_container():
            print_error("Container start failed")
            return False
        
        # Verify container was created
        if not self.container:
            print_error("Container object is None after start_container()")
            return False
            
        # Wait for the services to be available (check first port if multiple)
        if self.exposed_ports:
            first_binding = list(self.exposed_ports.values())[0]
            # Extract port from tuple (host_ip, port) or use directly if it's just a port
            if isinstance(first_binding, (tuple, list)):
                first_host_ip = first_binding[0] if len(first_binding) > 1 else '127.0.0.1'
                first_port = first_binding[-1]
            else:
                first_host_ip = '127.0.0.1'
                first_port = first_binding
            
            if not self.wait_for_service(first_host_ip, int(first_port), int(self.ready_timeout)):
                print_warning(f"Service on {first_host_ip}:{first_port} may not be available yet, but the container is started")
        
        return True

    def on_environment_ready(self):
        """
        Hook executed once the container is up.
        Subclasses can override this to display custom instructions.
        """
        return self.print_container_overview()

    def run(self, *args, **kwargs):
        """Framework entry point - start Docker then delegate to the hook."""
        if not self.run_docker():
            return False
        return self.on_environment_ready()

    def _exploit(self):
        """Execute the module and return the result"""
        try:
            return self.run()
        except Exception as e:
            print_error(f"Error executing the module: {str(e)}")
            return False
    
    def cleanup(self):
        """Clean up the resources used by the module"""
        return self.stop_container()

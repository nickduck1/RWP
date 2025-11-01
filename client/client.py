import socket
import hashlib
import json
import os
import time
import threading
import base64
import requests
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import mimetypes
import io

class RWPClient:
    def __init__(self, rwp_host='127.0.0.1', http_port=8080):
        self.rwp_host = rwp_host
        self.http_port = http_port
        self.config_file = "client_config.json"
        self.private_key_file = "client_private_key.pem"
        self.server_info_file = "server_info.json"
        self.ports_file = "ports.json"
        
        # HTX Tunnel Configuration
        self.target_domain = "www.google.com"  # Domain to mimic
        self.use_htx_tunnel = True  # Enable HTX tunneling
        
        # Track active connections and their status
        self.active_connections = {}  # {port: (socket, last_active_time)}
        self.connection_lock = threading.Lock()
        
        # Streaming configuration
        self.chunk_size = 1024 * 1024  # 1MB chunks for streaming
        self.stream_cache = {}  # Cache for ongoing streams
        self.cache_lock = threading.Lock()
        
        # Load or generate client identity
        self.load_or_generate_identity()
        
        # Initialize server connection info
        self.server_node_id = None
        self.server_public_key_pem = None
        self.server_ports = []
        self.knock_ports = []
        
        # Load or create ports configuration
        self.load_or_create_ports_config()
        
        # Fetch server configuration
        self.fetch_server_config()
        
        # Initialize connections with improved logic
        self.initialize_connections()
        
        # Start HTTP proxy server
        self.start_http_proxy()
        
        # Start connection health monitor
        self.start_connection_monitor()
    
    def load_or_create_ports_config(self):
        """Load existing ports config or create new one by asking user"""
        if os.path.exists(self.ports_file):
            try:
                with open(self.ports_file, 'r') as f:
                    ports_config = json.load(f)
                    self.user_ports = ports_config.get("ports", [])
                    print(f"Loaded {len(self.user_ports)} ports from {self.ports_file}")
                    return
            except Exception as e:
                print(f"Error loading ports config: {e}")
        
        # Ask user for ports
        print("Please enter at least 5 ports you would like to use for connecting to servers:")
        self.user_ports = []
        
        while len(self.user_ports) < 5:
            try:
                port = int(input(f"Enter port #{len(self.user_ports) + 1}: "))
                if 1 <= port <= 65535:
                    if port not in self.user_ports:
                        self.user_ports.append(port)
                    else:
                        print("Port already added, please enter a different port.")
                else:
                    print("Port must be between 1 and 65535")
            except ValueError:
                print("Invalid port number, please enter a number.")
        
        # Save to file
        try:
            with open(self.ports_file, 'w') as f:
                json.dump({"ports": self.user_ports}, f, indent=2)
            print(f"Saved {len(self.user_ports)} ports to {self.ports_file}")
        except Exception as e:
            print(f"Error saving ports config: {e}")

    def save_server_info(self, node_id, title, contents):
        """Save or update server information in sv_searchdb.json"""
        db_file = "sv_searchdb.json"
        servers = {}

        # Load existing database if it exists
        if os.path.exists(db_file):
            try:
                with open(db_file, 'r') as f:
                    servers = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error loading server database: {e}")
                servers = {}
    
        # Update server information
        servers[node_id] = {
            "node_id": node_id,
            "title": title,
            "contents": contents,
            "last_updated": time.time()
        }

        # Save updated database
        try:
            with open(db_file, 'w') as f:
                json.dump(servers, f, indent=2)
            print(f"Saved server info for {node_id} to {db_file}")
        except IOError as e:
            print(f"Error saving server database: {e}")

    def fetch_server_config(self):
        """Fetch server configuration from port 80 via HTTP"""
        try:
            print(f"Fetching server configuration from http://{self.rwp_host}/")
            response = requests.get(
                f"http://{self.rwp_host}/",
                headers={"Accept": "application/json"},
                timeout=10
            )

            if response.status_code == 200:
                try:
                    server_config = response.json()
                    print("Successfully fetched server configuration")

                    # Extract server information
                    self.server_node_id = server_config.get("node_id")
                    self.server_ports = server_config.get("ports", [])
                    self.knock_ports = server_config.get("knock_ports", [])

                    # Get title and contents for saving
                    title = server_config.get("title", "")
                    contents = server_config.get("contents", "")

                    # Save server information to database
                    if self.server_node_id:
                        self.save_server_info(self.server_node_id, title, contents)

                    print(f"Server provided {len(self.server_ports)} ports: {self.server_ports}")
                    print(f"Server provided {len(self.knock_ports)} knock ports: {self.knock_ports}")

                    with open(self.server_info_file, 'w') as f:
                        json.dump(server_config, f, indent=2)

                    return True
                except json.JSONDecodeError as e:
                    print(f"Error parsing server configuration JSON: {e}")
                    return False
            else:
                print(f"Failed to fetch server configuration: HTTP {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"Error fetching server configuration: {e}")
            return False

    def get_content_type(self, path):
        """Get MIME type for a path"""
        content_type, _ = mimetypes.guess_type(path)
        if content_type is None:
            content_type = 'application/octet-stream'
        return content_type

    def is_streamable_content(self, content_type):
        """Check if content should be streamed"""
        streamable_types = [
            'video/', 'audio/', 'application/octet-stream'
        ]
        return any(content_type.startswith(t) for t in streamable_types)

    def send_rwp_stream_request(self, resource, range_header=None):
        """Send a streaming request to RWP server"""
        if not self.active_connections:
            print("No active connections available")
            return None
        
        # Try each connection until one succeeds
        for port, (sock, last_active) in list(self.active_connections.items()):
            try:
                # Update last active time
                with self.connection_lock:
                    if port in self.active_connections:
                        self.active_connections[port] = (sock, time.time())
                
                # Test if socket is still connected
                try:
                    sock.settimeout(5.0)
                    sock.send(b'')
                except socket.error:
                    print(f"Connection to port {port} is dead, removing...")
                    with self.connection_lock:
                        if port in self.active_connections:
                            del self.active_connections[port]
                    continue
                
                try:
                    shared_secret = self.derive_shared_secret(self.server_public_key_pem)
                except Exception as e:
                    print(f"Error deriving shared secret: {e}")
                    continue
                
                request_payload = {
                    "type": "STREAM_REQUEST",
                    "resource": resource,
                    "timestamp": time.time()
                }
                
                if range_header:
                    request_payload['range'] = range_header
                
                payload_json = json.dumps(request_payload).encode('utf-8')
                encrypted_payload = self.encrypt_payload(payload_json, shared_secret)
                
                public_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                request_headers = [
                    f"STREAM_REQUEST /{resource} RWP/1.0",
                    f"X-Node-ID: {self.node_id}",
                    f"X-Public-Key: {base64.b64encode(public_pem.encode()).decode('utf-8')}",
                    f"X-Encrypted-Payload: {base64.b64encode(encrypted_payload).decode('utf-8')}"
                ]
                
                request = '\r\n'.join(request_headers) + '\r\n\r\n'
                
                sock.sendall(request.encode('utf-8'))
                print(f"Sent RWP STREAM_REQUEST for: {resource} via port {port}")
                
                # Receive response
                response_data = b""
                sock.settimeout(10.0)
                
                while True:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            break
                        response_data += data
                        if b'\r\n\r\n' in response_data:
                            break
                    except socket.timeout:
                        print(f"Timeout waiting for stream info from port {port}")
                        break
                    except socket.error as e:
                        print(f"Socket error receiving stream info from port {port}: {e}")
                        break
                
                if not response_data:
                    print(f"No stream info received from port {port}")
                    continue
                
                response_lines = response_data.decode('utf-8').split('\r\n')
                
                if len(response_lines) < 2:
                    print("Invalid response format")
                    continue
                
                headers = {}
                for line in response_lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key] = value
                
                if 'X-Encrypted-Payload' not in headers:
                    print("Missing encrypted payload in response")
                    continue
                
                encrypted_response = base64.b64decode(headers['X-Encrypted-Payload'])
                
                try:
                    decrypted = self.decrypt_payload(encrypted_response, shared_secret)
                    response_payload = json.loads(decrypted.decode('utf-8'))
                except Exception as e:
                    print(f"Error decrypting response: {e}")
                    continue
                
                print(f"Received RWP stream info with status: {response_payload.get('status')} via port {port}")
                return response_payload
                
            except Exception as e:
                print(f"Error processing RWP stream request via port {port}: {e}")
                with self.connection_lock:
                    if port in self.active_connections:
                        try:
                            sock.close()
                        except:
                            pass
                        del self.active_connections[port]
                continue
        
        print("All connections failed for stream request. Attempting to re-establish...")
        self.initialize_connections()
        return None

    def request_stream_chunk(self, resource, chunk_start, chunk_size=None):
        """Request a specific chunk of a stream"""
        if chunk_size is None:
            chunk_size = self.chunk_size
            
        if not self.active_connections:
            print("No active connections available")
            return None
        
        for port, (sock, last_active) in list(self.active_connections.items()):
            try:
                with self.connection_lock:
                    if port in self.active_connections:
                        self.active_connections[port] = (sock, time.time())
                
                try:
                    shared_secret = self.derive_shared_secret(self.server_public_key_pem)
                except Exception as e:
                    print(f"Error deriving shared secret: {e}")
                    continue
                
                request_payload = {
                    "type": "STREAM_CHUNK",
                    "resource": resource,
                    "chunk_start": chunk_start,
                    "chunk_size": chunk_size,
                    "timestamp": time.time()
                }
                
                payload_json = json.dumps(request_payload).encode('utf-8')
                encrypted_payload = self.encrypt_payload(payload_json, shared_secret)
                
                public_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                request_headers = [
                    f"STREAM_CHUNK /{resource} RWP/1.0",
                    f"X-Node-ID: {self.node_id}",
                    f"X-Public-Key: {base64.b64encode(public_pem.encode()).decode('utf-8')}",
                    f"X-Encrypted-Payload: {base64.b64encode(encrypted_payload).decode('utf-8')}"
                ]
                
                request = '\r\n'.join(request_headers) + '\r\n\r\n'
                
                sock.sendall(request.encode('utf-8'))
                
                # Receive response
                response_data = b""
                sock.settimeout(15.0)
                
                while True:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            break
                        response_data += data
                        if b'\r\n\r\n' in response_data:
                            break
                    except socket.timeout:
                        print(f"Timeout waiting for chunk from port {port}")
                        break
                    except socket.error as e:
                        print(f"Socket error receiving chunk from port {port}: {e}")
                        break
                
                if not response_data:
                    continue
                
                response_lines = response_data.decode('utf-8').split('\r\n')
                headers = {}
                for line in response_lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key] = value
                
                if 'X-Encrypted-Payload' not in headers:
                    continue
                
                encrypted_response = base64.b64decode(headers['X-Encrypted-Payload'])
                
                try:
                    decrypted = self.decrypt_payload(encrypted_response, shared_secret)
                    response_payload = json.loads(decrypted.decode('utf-8'))
                    
                    if response_payload.get('status') == 200:
                        chunk_data = base64.b64decode(response_payload['data'])
                        return {
                            'data': chunk_data,
                            'chunk_start': response_payload.get('chunk_start'),
                            'chunk_end': response_payload.get('chunk_end'),
                            'total_size': response_payload.get('total_size')
                        }
                except Exception as e:
                    print(f"Error decrypting chunk response: {e}")
                    continue
                    
            except Exception as e:
                print(f"Error requesting chunk via port {port}: {e}")
                continue
        
        return None
    
    def get_active_connection_count(self):
        """Get the number of active connections"""
        with self.connection_lock:
            return len(self.active_connections)

    def is_port_running_rwp(self, port):
        """Check if a port is running RWP by attempting a test connection"""
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2)
            result = test_sock.connect_ex((self.rwp_host, port))
            
            if result == 0:
                test_request = "GET_SERVER_INFO RWP/1.0\r\nX-Node-ID: test\r\n\r\n"
                test_sock.sendall(test_request.encode('utf-8'))
                
                response = test_sock.recv(1024).decode('utf-8')
                test_sock.close()
                
                if 'RWP/1.0' in response:
                    return "RWP_READY"
                else:
                    return "PORT_USED"
            else:
                return "PORT_CLOSED"
        except:
            test_sock.close()
            return "PORT_CLOSED"
    
    def establish_connection(self, port):
        """Establish a connection to a specific port"""
        with self.connection_lock:
            if port in self.active_connections:
                return True

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)

                print(f"Attempting to connect to {self.rwp_host}:{port}...")
                sock.connect((self.rwp_host, port))
                print(f"Successfully connected to {self.rwp_host}:{port}")

                # Wrap in HTX tunnel if enabled
                if self.use_htx_tunnel:
                    print(f"Wrapping connection in HTX tunnel to mimic {self.target_domain}")
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    # Set ALPN to HTTP/1.1 to mimic normal HTTPS
                    context.set_alpn_protocols(['http/1.1'])
                    
                    # Set SNI to target domain
                    sock = context.wrap_socket(sock, server_hostname=self.target_domain)
                    print(f"HTX tunnel established for connection to {self.rwp_host}:{port}")

                if not self.server_node_id or not self.server_public_key_pem:
                    if not self.fetch_server_info_on_connection(sock):
                        sock.close()
                        return False

                self.active_connections[port] = (sock, time.time())
                return True

            except Exception as e:
                print(f"Failed to connect to port {port}: {e}")
                return False

    def request_port_open(self, requested_port):
        """Request server to open a port using existing connection"""
        if not self.active_connections:
            print("No active connections to request port opening")
            return False
        
        # Use the first available connection to send the request
        for port, (sock, last_active) in list(self.active_connections.items()):
            try:
                # Update last active time
                with self.connection_lock:
                    if port in self.active_connections:
                        self.active_connections[port] = (sock, time.time())
                
                # Prepare the port open request
                if not self.server_public_key_pem:
                    print("Missing server public key")
                    continue
                
                shared_secret = self.derive_shared_secret(self.server_public_key_pem)
                
                request_payload = {
                    "type": "OPEN_PORT",
                    "port": requested_port,
                    "timestamp": time.time()
                }
                
                payload_json = json.dumps(request_payload).encode('utf-8')
                encrypted_payload = self.encrypt_payload(payload_json, shared_secret)
                
                public_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                request_headers = [
                    f"OPEN_PORT /{requested_port} RWP/1.0",
                    f"X-Node-ID: {self.node_id}",
                    f"X-Public-Key: {base64.b64encode(public_pem.encode()).decode('utf-8')}",
                    f"X-Encrypted-Payload: {base64.b64encode(encrypted_payload).decode('utf-8')}"
                ]
                
                request = '\r\n'.join(request_headers) + '\r\n\r\n'
                
                sock.sendall(request.encode('utf-8'))
                print(f"Sent port open request for port {requested_port} via connection on port {port}")
                
                # Receive response
                response_data = b""
                sock.settimeout(10.0)
                
                while True:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            print(f"No response data received from port {port}")
                            break
                        response_data += data
                        if b'\r\n\r\n' in response_data:
                            break
                    except socket.timeout:
                        print(f"Timeout waiting for port open response from port {port}")
                        break
                    except socket.error as e:
                        print(f"Socket error receiving port open response from port {port}: {e}")
                        break
                
                if not response_data:
                    print(f"No response received for port open request from port {port}")
                    continue
                
                response_lines = response_data.decode('utf-8').split('\r\n')
                
                if len(response_lines) < 2:
                    print("Invalid response format for port open request")
                    continue
                
                headers = {}
                for line in response_lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key] = value
                
                if 'X-Encrypted-Payload' not in headers:
                    print("Missing encrypted payload in port open response")
                    continue
                
                encrypted_response = base64.b64decode(headers['X-Encrypted-Payload'])
                
                try:
                    decrypted = self.decrypt_payload(encrypted_response, shared_secret)
                    response_payload = json.loads(decrypted.decode('utf-8'))
                except Exception as e:
                    print(f"Error decrypting port open response: {e}")
                    continue
                
                print(f"Port open response: {response_payload}")
                
                if response_payload.get('status') == 200:
                    result = response_payload.get('result')
                    if result in ['PORT_OPENED', 'RWP_READY']:
                        print(f"Successfully opened port {requested_port}: {result}")
                        return True
                    else:
                        print(f"Failed to open port {requested_port}: {result}")
                        return False
                else:
                    message = response_payload.get('message', 'Unknown error')
                    print(f"Server rejected port open request: {message}")
                    return False
                
            except Exception as e:
                print(f"Error requesting port open via port {port}: {e}")
                # Remove failed connection
                with self.connection_lock:
                    if port in self.active_connections:
                        try:
                            sock.close()
                        except:
                            pass
                        del self.active_connections[port]
                continue
        
        print("All connections failed for port open request")
        return False
    
    def initialize_connections(self):
        """Initialize connections with improved logic for maintaining 3 connections"""
        print("Initializing connections to server...")
        
        current_count = self.get_active_connection_count()
        needed_connections = 3 - current_count
        
        if needed_connections <= 0:
            print(f"Already have {current_count} connections")
            return
        
        print(f"Need {needed_connections} more connections (currently have {current_count})")
        
        # First, try server-provided ports
        for port in self.server_ports:
            if port not in self.active_connections:
                if self.establish_connection(port):
                    needed_connections -= 1
                    if needed_connections == 0:
                        break
        
        # If we still need more connections, try user-provided ports
        if needed_connections > 0:
            print(f"Trying user-provided ports to establish {needed_connections} more connections...")
            for port in self.user_ports:
                if port not in self.active_connections and port not in self.server_ports:
                    port_status = self.is_port_running_rwp(port)
                    
                    if port_status == "RWP_READY":
                        print(f"Port {port} is already running RWP, connecting...")
                        if self.establish_connection(port):
                            needed_connections -= 1
                            if needed_connections == 0:
                                break
                    elif port_status == "PORT_USED":
                        print(f"Port {port} is used by another service, skipping...")
                        continue
                    elif port_status == "PORT_CLOSED":
                        print(f"Port {port} is closed. Attempting port knocking...")
                        knock_result = self.port_knock_for_connection(port)
                        if knock_result:
                            needed_connections -= 1
                            if needed_connections == 0:
                                break
                        else:
                            print("Port knocking failed. Trying server request method...")
                            if self.request_port_open(port):
                                time.sleep(2)
                                if self.establish_connection(port):
                                    needed_connections -= 1
                                    if needed_connections == 0:
                                        break
                            print("Server request method also failed.")
                            continue
    
    def fetch_server_info_on_connection(self, sock):
        """Fetch server info using an existing connection"""
        try:
            request_headers = [
                f"GET_SERVER_INFO RWP/1.0",
                f"X-Node-ID: {self.node_id}"
            ]
            request = '\r\n'.join(request_headers) + '\r\n\r\n'
            sock.sendall(request.encode('utf-8'))
            
            response_data = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response_data += data
                if b'\r\n\r\n' in response_data:
                    break
                    
            response_text = response_data.decode('utf-8')
            body_start = response_text.find('\r\n\r\n')
            if body_start == -1:
                print("Invalid response format")
                return False
                
            body = response_text[body_start + 4:]
            try:
                server_info = json.loads(body)
            except json.JSONDecodeError:
                print(f"Invalid JSON in response: {body}")
                return False
                
            if server_info.get('type') == 'SERVER_INFO':
                self.server_node_id = server_info.get('node_id')
                self.server_public_key_pem = server_info.get('public_key')
                
                with open(self.server_info_file, 'w') as f:
                    json.dump(server_info, f, indent=2)
                
                print(f"Fetched server info for Node ID: {self.server_node_id}")
                return True
            else:
                print(f"Unexpected server response type: {server_info.get('type')}")
                return False
        except Exception as e:
            print(f"Error fetching server info: {e}")
            return False
    
    def send_rwp_request(self, method, resource, data=None, content_type=None, range_header=None):
        """Send an RWP request using available connections with failover"""
        if not self.active_connections:
            print("No active connections available")
            return None
        
        # Check if this should be a streaming request
        content_mime_type = self.get_content_type(resource)
        if method == 'GET' and self.is_streamable_content(content_mime_type):
            # First, try to get stream info
            stream_info = self.send_rwp_stream_request(resource, range_header)
            if stream_info and stream_info.get('status') == 200:
                return stream_info
        
        # Regular request handling
        for port, (sock, last_active) in list(self.active_connections.items()):
            try:
                # Update last active time
                with self.connection_lock:
                    if port in self.active_connections:
                        self.active_connections[port] = (sock, time.time())
                
                # Test if socket is still connected
                try:
                    sock.settimeout(5.0)
                    sock.send(b'')
                except socket.error:
                    print(f"Connection to port {port} is dead, removing...")
                    with self.connection_lock:
                        if port in self.active_connections:
                            del self.active_connections[port]
                    continue
                
                try:
                    shared_secret = self.derive_shared_secret(self.server_public_key_pem)
                except Exception as e:
                    print(f"Error deriving shared secret: {e}")
                    continue
                
                request_payload = {
                    "type": method,
                    "resource": resource,
                    "timestamp": time.time()
                }
                
                if range_header:
                    request_payload['range'] = range_header
                
                if method == 'POST' and data:
                    request_payload['data'] = data
                    if content_type:
                        request_payload['content_type'] = content_type
                    else:
                        request_payload['content_type'] = 'application/x-www-form-urlencoded'
                
                payload_json = json.dumps(request_payload).encode('utf-8')
                encrypted_payload = self.encrypt_payload(payload_json, shared_secret)
                
                public_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                request_headers = [
                    f"{method} /{resource} RWP/1.0",
                    f"X-Node-ID: {self.node_id}",
                    f"X-Public-Key: {base64.b64encode(public_pem.encode()).decode('utf-8')}",
                    f"X-Encrypted-Payload: {base64.b64encode(encrypted_payload).decode('utf-8')}"
                ]
                
                request = '\r\n'.join(request_headers) + '\r\n\r\n'
                
                sock.sendall(request.encode('utf-8'))
                print(f"Sent RWP {method} request for: {resource} via port {port}")
                
                # Receive response
                response_data = b""
                sock.settimeout(10.0)
                
                while True:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            print(f"No response data received from port {port}")
                            break
                        response_data += data
                        if b'\r\n\r\n' in response_data:
                            break
                    except socket.timeout:
                        print(f"Timeout waiting for response from port {port}")
                        break
                    except socket.error as e:
                        print(f"Socket error receiving response from port {port}: {e}")
                        break
                
                if not response_data:
                    print(f"No response received from port {port}")
                    continue
                
                response_lines = response_data.decode('utf-8').split('\r\n')
                
                if len(response_lines) < 2:
                    print("Invalid response format")
                    continue
                
                headers = {}
                for line in response_lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key] = value
                
                if 'X-Encrypted-Payload' not in headers:
                    print("Missing encrypted payload in response")
                    continue
                
                encrypted_response = base64.b64decode(headers['X-Encrypted-Payload'])
                
                try:
                    decrypted = self.decrypt_payload(encrypted_response, shared_secret)
                    response_payload = json.loads(decrypted.decode('utf-8'))
                except Exception as e:
                    print(f"Error decrypting response: {e}")
                    continue
                
                if 'content' in response_payload and isinstance(response_payload['content'], str):
                    response_payload['content'] = base64.b64decode(response_payload['content'])
                
                print(f"Received RWP response with status: {response_payload.get('status')} via port {port}")
                return response_payload
                
            except Exception as e:
                print(f"Error processing RWP request via port {port}: {e}")
                with self.connection_lock:
                    if port in self.active_connections:
                        try:
                            sock.close()
                        except:
                            pass
                        del self.active_connections[port]
                continue
        
        print("All connections failed. Attempting to re-establish...")
        self.initialize_connections()
        return None
    
    def start_connection_monitor(self):
        """Monitor connection health and re-establish as needed"""
        def monitor():
            while True:
                time.sleep(60)
                current_time = time.time()
                
                with self.connection_lock:
                    for port, (sock, last_active) in list(self.active_connections.items()):
                        if current_time - last_active > 300:
                            print(f"Connection to port {port} has been idle for 5+ minutes, testing...")
                            
                            try:
                                sock.settimeout(1.0)
                                sock.setblocking(False)
                                try:
                                    data = sock.recv(1, socket.MSG_PEEK)
                                    print(f"Connection to port {port} appears to be alive, keeping it")
                                    continue
                                except socket.error as e:
                                    if e.errno in (socket.EAGAIN, socket.EWOULDBLOCK):
                                        print(f"Connection to port {port} is alive (no pending data)")
                                        continue
                                    else:
                                        print(f"Connection to port {port} is dead: {e}")
                                        raise e
                                finally:
                                    sock.setblocking(True)
                            except:
                                print(f"Connection to port {port} is dead, removing...")
                                try:
                                    sock.close()
                                except:
                                    pass
                                del self.active_connections[port]
                    
                    connection_count = len(self.active_connections)
                
                if connection_count < 3:
                    print(f"Only {connection_count} active connections, attempting to establish more...")
                    ports_to_try = list(self.active_connections.keys()) + self.server_ports + self.user_ports
                    for port in ports_to_try:
                        if port not in self.active_connections and connection_count < 3:
                            if self.establish_connection(port):
                                connection_count += 1
        
        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
    
    def port_knock_for_connection(self, requested_port):
        """Use port knocking to request a connection"""
        if not self.knock_ports:
            print("No knock ports available from server")
            return False

        print(f"Attempting port knock sequence to open port {requested_port}...")

        for port in self.knock_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect((self.rwp_host, port))

                if port == self.knock_ports[-1]:
                    sock.sendall(str(requested_port).encode('utf-8'))

                sock.close()
                print(f"Knocked on port {port}")
            except Exception as e:
                print(f"Failed to knock on port {port}: {e}")
                return False

        print("Waiting for server to open the port...")

        max_attempts = 5
        for attempt in range(1, max_attempts + 1):
            print(f"Connection attempt {attempt}/{max_attempts}...")
            time.sleep(3)

            if self.establish_connection(requested_port):
                print(f"Successfully connected via port knocking on port {requested_port}")
                return True

        print(f"Failed to connect after {max_attempts} attempts")
        return False
    
    def load_or_generate_identity(self):
        """Load existing client identity or generate new one"""
        if os.path.exists(self.config_file) and os.path.exists(self.private_key_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.node_id = config.get("node_id")
                
                with open(self.private_key_file, "rb") as f:
                    private_key_data = f.read()
                    self.private_key = serialization.load_pem_private_key(
                        private_key_data,
                        password=None,
                        backend=default_backend()
                    )
                    self.public_key = self.private_key.public_key()
                
                print(f"Loaded existing client identity with Node ID: {self.node_id}")
                return
            except Exception as e:
                print(f"Error loading client identity: {e}")
        
        print("Generating new client identity...")
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.node_id = hashlib.sha256(public_pem).hexdigest()
        
        try:
            with open(self.private_key_file, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            config = {
                "node_id": self.node_id,
                "server_host": self.rwp_host
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"Saved new client identity with Node ID: {self.node_id}")
        except Exception as e:
            print(f"Error saving client identity: {e}")
    
    def derive_shared_secret(self, peer_public_key_pem):
        """Derive shared secret using ECDH"""
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_pem.encode(),
            backend=default_backend()
        )
        
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'rwp-key-derivation',
            backend=default_backend()
        ).derive(shared_secret)
        
        return derived_key
    
    def encrypt_payload(self, payload, key):
        """Encrypt payload using AES-256-GCM"""
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        encrypted = encryptor.update(payload) + encryptor.finalize()
        
        return iv + encryptor.tag + encrypted
    
    def decrypt_payload(self, encrypted_data, key):
        """Decrypt payload using AES-256-GCM"""
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def start_http_proxy(self):
        """Start HTTP proxy server with streaming support"""
        class RWPProxyHandler(BaseHTTPRequestHandler):
            def __init__(self, *args, client=None, **kwargs):
                self.client = client
                super().__init__(*args, **kwargs)
            
            def do_GET(self):
                parsed_path = urlparse(self.path)
                resource = parsed_path.path.lstrip('/')

                if not resource:
                    resource = "index.html"

                print(f"HTTP GET Request for: {resource}")

                # Parse Range header if present
                range_header = self.headers.get('Range')
                if range_header:
                    print(f"Range request: {range_header}")

                # Get content type to determine if streaming is needed
                content_type = self.client.get_content_type(resource)

                # For video/audio content, always handle as streamable
                if self.client.is_streamable_content(content_type):
                    if range_header:
                        # Handle range request for streaming
                        self.handle_range_request(resource, range_header, content_type)
                    else:
                        # No range header - start streaming from beginning
                        self.handle_full_download(resource, content_type)
                else:
                    # Regular request for non-streamable content
                    rwp_response = self.client.send_rwp_request('GET', resource, range_header=range_header)
                    self.handle_regular_response(resource, rwp_response, content_type)
            
            def handle_range_request(self, resource, range_header, content_type):
                """Handle HTTP Range requests with RWP streaming"""
                # First get file info
                stream_info = self.client.send_rwp_stream_request(resource, range_header)
                
                if not stream_info or stream_info.get('status') != 200:
                    self.send_error(404, "Resource not found")
                    return
                
                file_size = stream_info.get('file_size', 0)
                start_byte = stream_info.get('start_byte', 0)
                end_byte = stream_info.get('end_byte', file_size - 1)
                content_length = end_byte - start_byte + 1
                
                # Send HTTP headers
                self.send_response(206, 'Partial Content')
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(content_length))
                self.send_header('Content-Range', f'bytes {start_byte}-{end_byte}/{file_size}')
                self.send_header('Accept-Ranges', 'bytes')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                
                # Stream the content in chunks
                current_pos = start_byte
                chunk_size = 256 * 1024  # 256KB chunks for HTTP streaming
                
                while current_pos <= end_byte:
                    remaining = end_byte - current_pos + 1
                    request_size = min(chunk_size, remaining)
                    
                    chunk_response = self.client.request_stream_chunk(resource, current_pos, request_size)
                    
                    if not chunk_response or 'data' not in chunk_response:
                        print(f"Failed to get chunk at position {current_pos}")
                        break
                    
                    chunk_data = chunk_response['data']
                    actual_size = len(chunk_data)
                    
                    if actual_size == 0:
                        break
                    
                    try:
                        self.wfile.write(chunk_data)
                        self.wfile.flush()
                        current_pos += actual_size
                        print(f"Streamed {actual_size} bytes ({current_pos}/{end_byte})")
                    except (BrokenPipeError, ConnectionAbortedError):
                        print("Client disconnected during streaming")
                        break
                
                print(f"Finished streaming {resource}")
            
            def handle_full_download(self, resource, content_type):
                """Handle full file download for streamable content without range header"""
                # First get file info
                stream_info = self.client.send_rwp_stream_request(resource)

                if not stream_info or stream_info.get('status') != 200:
                    self.send_error(404, "Resource not found")
                    return

                file_size = stream_info.get('file_size', 0)

                # Send HTTP headers for full download
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(file_size))
                self.send_header('Accept-Ranges', 'bytes')
                self.end_headers()

                # Stream the entire content in chunks
                current_pos = 0
                chunk_size = 1024 * 1024  # 1MB chunks for full download

                while current_pos < file_size:
                    remaining = file_size - current_pos
                    request_size = min(chunk_size, remaining)

                    chunk_response = self.client.request_stream_chunk(resource, current_pos, request_size)

                    if not chunk_response or 'data' not in chunk_response:
                        print(f"Failed to get chunk at position {current_pos}")
                        break
                        
                    chunk_data = chunk_response['data']
                    actual_size = len(chunk_data)

                    if actual_size == 0:
                        break
                        
                    try:
                        self.wfile.write(chunk_data)
                        self.wfile.flush()
                        current_pos += actual_size
                        print(f"Downloaded {actual_size} bytes ({current_pos}/{file_size})")
                    except (BrokenPipeError, ConnectionAbortedError):
                        print("Client disconnected during download")
                        break
                        
                print(f"Finished downloading {resource}")

            def handle_regular_response(self, resource, rwp_response, content_type):
                """Handle regular non-streaming responses"""
                if rwp_response:
                    if rwp_response.get('status') == 200:
                        content = rwp_response.get('content', b'')
                        
                        if isinstance(content, str):
                            content = content.encode('utf-8')
                        elif content is None:
                            content = b''
                        
                        # Check if this is a stream info response for large files
                        if rwp_response.get('supports_streaming'):
                            # Large file detected, suggest streaming
                            file_size = rwp_response.get('file_size', 0)
                            self.send_response(200)
                            self.send_header('Content-Type', content_type)
                            self.send_header('Content-Length', str(file_size))
                            self.send_header('Accept-Ranges', 'bytes')
                            self.end_headers()
                            
                            # For large files without range request, start streaming from beginning
                            self.handle_range_request(resource, f'bytes=0-{file_size-1}', content_type)
                        else:
                            # Regular small file response
                            self.send_response(200)
                            self.send_header('Content-Type', content_type)
                            self.send_header('Content-Length', str(len(content)))
                            if self.client.is_streamable_content(content_type):
                                self.send_header('Accept-Ranges', 'bytes')
                            self.end_headers()
                            self.wfile.write(content)
                    else:
                        self.send_error(404, rwp_response.get('message', 'Resource not found'))
                else:
                    self.send_error(500, "Failed to communicate with RWP server --- Try refreshing after 5s")
            
            def do_POST(self):
                parsed_path = urlparse(self.path)
                resource = parsed_path.path.lstrip('/')
                
                print(f"HTTP POST Request for: {resource}")
                
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                
                content_type = self.headers.get('Content-Type', 'application/x-www-form-urlencoded')
                
                if content_type == 'application/x-www-form-urlencoded':
                    try:
                        post_data = parse_qs(post_data.decode('utf-8'))
                        post_data_str = '&'.join([f"{k}={v[0] if v else ''}" for k, v in post_data.items()])
                    except:
                        post_data_str = post_data.decode('utf-8', errors='ignore')
                else:
                    post_data_str = post_data.decode('utf-8', errors='ignore')
                
                rwp_response = self.client.send_rwp_request('POST', resource, post_data_str, content_type)
                
                if rwp_response:
                    if rwp_response.get('status') == 200:
                        content = rwp_response.get('content', b'')
                        
                        if isinstance(content, str):
                            content = content.encode('utf-8')
                        elif content is None:
                            content = b''
                        
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(content)
                    else:
                        self.send_error(500, rwp_response.get('message', 'POST request failed'))
                else:
                    self.send_error(500, "Failed to communicate with RWP server --- Try refreshing after 5s")
        
        def handler(*args):
            RWPProxyHandler(*args, client=self)
        
        server = HTTPServer(('0.0.0.0', self.http_port), handler)
        print(f"HTTP Proxy with streaming support started on port {self.http_port}")
        print(f"Access RWP content at: http://localhost:{self.http_port}")
        
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        return server

if __name__ == "__main__":
    client = RWPClient()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Client shutting down...")

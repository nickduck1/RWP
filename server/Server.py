import socket
import hashlib
import json
import select
import os
import time
import threading
import ssl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import ipaddress
import base64
import mimetypes
from datetime import datetime, timezone

class RWPServer:
    def __init__(self, ports=[7070, 7071, 7072], host='0.0.0.0'):
        self.ports = ports
        self.host = host
        self.running = False
        self.sockets = []
        self.content_dir = "content"
        self.config_file = "server_config.json"
        self.private_key_file = "server_private_key.pem"

        # HTX (HTTPS Tunnel) Configuration
        self.ssl_cert_file = "server_cert.pem"
        self.ssl_key_file = "server_ssl_key.pem"
        self.enable_htx = True  # Enable HTX tunneling support

        # Port knocking configuration
        self.knock_ports = [10000, 10001, 10002]
        self.knock_sequences = {}
        self.open_ports = {}  # {port: (socket, creation_time)}
        self.open_port_sockets = []
        
        # Track client connections per port
        self.port_client_counts = {}  # {port: count}
        self.port_client_lock = threading.Lock()

        # HTTP server info
        self.title = "testing123"
        self.contents = "long test 1234"

        # Streaming configuration
        self.chunk_size = 1024 * 1024  # 1MB chunks for streaming

        # Load or generate server identity
        self.load_or_generate_identity()

        # Generate SSL certificate for HTX support
        if self.enable_htx:
            self.generate_ssl_certificate()

        # Ensure content directory exists
        os.makedirs(self.content_dir, exist_ok=True)
        self.create_default_html()

    def generate_ssl_certificate(self):
        """Generate a self-signed SSL certificate for HTX support"""
        if os.path.exists(self.ssl_cert_file) and os.path.exists(self.ssl_key_file):
            print("SSL certificate already exists for HTX support")
            return

        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            import datetime

            print("Generating self-signed SSL certificate for HTX support...")

            # Generate SSL key pair (separate from RWP identity)
            ssl_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RWP Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, "www.google.com"),  # Mimic target domain
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                ssl_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)  # ✅ Full path
            ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)  # ✅ Full path
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("www.google.com"),
                    x509.DNSName("google.com"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            ).sign(ssl_private_key, hashes.SHA256(), default_backend())

            # Save certificate and key
            with open(self.ssl_cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            with open(self.ssl_key_file, "wb") as f:
                f.write(ssl_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            print("SSL certificate generated successfully for HTX support")

        except ImportError:
            print("Warning: cryptography library missing x509 support. HTX will be disabled.")
            self.enable_htx = False
        except Exception as e:
            print(f"Error generating SSL certificate: {e}. HTX will be disabled.")
            self.enable_htx = False

    def create_ssl_context(self):
        """Create SSL context for HTX connections"""
        if not self.enable_htx:
            return None

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.ssl_cert_file, self.ssl_key_file)
            
            # Configure for mimicking HTTPS
            context.set_alpn_protocols(['http/1.1', 'h2'])
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            return context
        except Exception as e:
            print(f"Error creating SSL context: {e}")
            return None

    def detect_ssl_connection(self, client_socket):
        """Detect if incoming connection is SSL/TLS"""
        try:
            # Peek at the first byte to detect SSL handshake
            client_socket.settimeout(1.0)
            first_byte = client_socket.recv(1, socket.MSG_PEEK)
            
            if len(first_byte) == 1:
                # SSL/TLS handshake starts with 0x16 (22 decimal)
                return first_byte[0] == 0x16
            return False
        except (socket.timeout, socket.error):
            return False
        finally:
            client_socket.settimeout(None)

    def wrap_ssl_connection(self, client_socket):
        """Wrap a connection with SSL for HTX support"""
        if not self.enable_htx:
            return None

        try:
            ssl_context = self.create_ssl_context()
            if not ssl_context:
                return None

            ssl_socket = ssl_context.wrap_socket(
                client_socket,
                server_side=True,
                do_handshake_on_connect=False
            )
            
            # Perform handshake with timeout
            ssl_socket.settimeout(10.0)
            ssl_socket.do_handshake()
            ssl_socket.settimeout(None)
            
            print(f"HTX SSL connection established successfully")
            return ssl_socket

        except ssl.SSLError as e:
            print(f"SSL handshake failed: {e}")
            return None
        except Exception as e:
            print(f"Error wrapping SSL connection: {e}")
            return None

    def load_or_generate_identity(self):
        """Load existing identity or generate new one"""
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
                
                print(f"Loaded existing server identity with Node ID: {self.node_id}")
                return
            except Exception as e:
                print(f"Error loading server identity: {e}")
        
        # Generate new identity
        print("Generating new server identity...")
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
                "host": self.host,
                "ports": self.ports,
                "htx_enabled": self.enable_htx
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"Saved new server identity with Node ID: {self.node_id}")
        except Exception as e:
            print(f"Error saving server identity: {e}")
    
    def create_default_html(self):
        """Create a default HTML file to serve with video player"""
        html_path = os.path.join(self.content_dir, "index.html")
        if not os.path.exists(html_path):
            html_content = """<!DOCTYPE html>
<html>
<head>
    <title>RWP Streaming Test</title>
    <style>
        body {{ font-family: monospace; background-color: #000; color: #0f0; padding: 20px; }}
        h1 {{ color: #0ff; }}
        .box {{ border: 1px solid #0f0; padding: 10px; margin: 10px 0; }}
        video {{ max-width: 100%; height: auto; border: 1px solid #0f0; }}
    </style>
</head>
<body>
    <h1>RWP Streaming Protocol Test</h1>
    <div class="box">
        <p>Welcome to the decentralized streaming web!</p>
        <p>This page is served via RWP with streaming support and HTX tunneling.</p>
        <p>Node ID: {node_id}</p>
        <p>HTX Support: {htx_status}</p>
        
        <!-- Example video player - put your video files in the content directory -->
        <h2>Video Test:</h2>
        <video controls preload="none">
            <source src="test.mp4" type="video/mp4">
            <source src="test.webm" type="video/webm">
            Your browser does not support the video tag.
        </video>
    </div>
</body>
</html>""".format(node_id=self.node_id, htx_status="Enabled" if self.enable_htx else "Disabled")
        
            with open(html_path, 'w') as f:
                f.write(html_content)
    
    def derive_shared_secret(self, peer_public_key_bytes):
        """Derive shared secret using ECDH"""
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_bytes,
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

    def get_content_type(self, resource_path):
        """Get MIME type for a resource"""
        content_type, _ = mimetypes.guess_type(resource_path)
        if content_type is None:
            content_type = 'application/octet-stream'
        return content_type

    def parse_range_header(self, range_header, file_size):
        """Parse HTTP Range header and return start and end bytes"""
        if not range_header or not range_header.startswith('bytes='):
            return 0, file_size - 1
        
        try:
            ranges = range_header[6:].split(',')[0]  # Take first range only
            if '-' not in ranges:
                return 0, file_size - 1
                
            start, end = ranges.split('-', 1)
            
            if start == '':
                # Suffix range: -500 means last 500 bytes
                start = max(0, file_size - int(end))
                end = file_size - 1
            elif end == '':
                # Prefix range: 500- means from byte 500 to end
                start = int(start)
                end = file_size - 1
            else:
                # Full range: 0-1023
                start = int(start)
                end = min(int(end), file_size - 1)
                
            # Ensure valid range
            if start < 0:
                start = 0
            if end >= file_size:
                end = file_size - 1
            if start > end:
                start = 0
                end = file_size - 1
                
            return start, end
        except (ValueError, IndexError):
            return 0, file_size - 1

    def serve_resource_stream(self, resource, range_header=None):
        """Serve a resource with streaming support"""
        if resource.startswith('/'):
            resource = resource[1:]
        
        if not resource or resource.endswith('/'):
            resource += "index.html"
        
        resource = os.path.normpath(resource)
        if resource.startswith('..'):
            return None
        
        resource_path = os.path.join(self.content_dir, resource)
        
        if not os.path.exists(resource_path) or not os.path.isfile(resource_path):
            return None
            
        file_size = os.path.getsize(resource_path)
        content_type = self.get_content_type(resource_path)
        
        # Parse range if provided
        start_byte, end_byte = self.parse_range_header(range_header, file_size)
        content_length = end_byte - start_byte + 1
        
        return {
            'path': resource_path,
            'file_size': file_size,
            'content_type': content_type,
            'start_byte': start_byte,
            'end_byte': end_byte,
            'content_length': content_length,
            'is_range': range_header is not None
        }

    def send_stream_chunk(self, client_socket, shared_secret, file_info, chunk_start, chunk_end):
        """Send a chunk of file data"""
        try:
            with open(file_info['path'], 'rb') as f:
                f.seek(chunk_start)
                chunk_size = chunk_end - chunk_start + 1
                chunk_data = f.read(chunk_size)
                
                response_payload = {
                    'type': 'STREAM_CHUNK',
                    'status': 200,
                    'chunk_start': chunk_start,
                    'chunk_end': chunk_end,
                    'total_size': file_info['file_size'],
                    'content_type': file_info['content_type'],
                    'data': base64.b64encode(chunk_data).decode('utf-8'),
                    'timestamp': time.time()
                }
                
                response_json = json.dumps(response_payload).encode('utf-8')
                encrypted_response = self.encrypt_payload(response_json, shared_secret)
                
                response_headers = [
                    f"RWP/1.0 206 Partial Content" if file_info['is_range'] else f"RWP/1.0 200 OK",
                    f"X-Node-ID: {self.node_id}",
                    f"X-Encrypted-Payload: {base64.b64encode(encrypted_response).decode('utf-8')}"
                ]
                
                response = '\r\n'.join(response_headers) + '\r\n\r\n'
                client_socket.sendall(response.encode('utf-8'))
                
                return True
        except Exception as e:
            print(f"Error sending stream chunk: {e}")
            return False

    def increment_port_client_count(self, port):
        """Increment client count for a port"""
        with self.port_client_lock:
            self.port_client_counts[port] = self.port_client_counts.get(port, 0) + 1
            print(f"Port {port} client count: {self.port_client_counts[port]}")

    def decrement_port_client_count(self, port):
        """Decrement client count for a port"""
        with self.port_client_lock:
            if port in self.port_client_counts:
                self.port_client_counts[port] = max(0, self.port_client_counts[port] - 1)
                print(f"Port {port} client count: {self.port_client_counts[port]}")

    def get_port_from_socket(self, client_socket):
        """Get the port number that the client connected to"""
        try:
            return client_socket.getsockname()[1]
        except:
            return None

    def handle_port_open_request(self, payload, shared_secret, client_socket):
        """Handle client request to open a port"""
        try:
            requested_port = payload.get('port')
            if not requested_port:
                return self.create_error_response(shared_secret, 400, "Missing port number")
            
            # Validate port number
            if not isinstance(requested_port, int) or requested_port < 1024 or requested_port > 65535:
                return self.create_error_response(shared_secret, 400, "Invalid port number")
            
            # Check if port is already running RWP
            if self.is_port_running_rwp(requested_port):
                response_payload = {
                    'type': 'PORT_OPEN_RESPONSE',
                    'status': 200,
                    'message': 'Port is already running RWP',
                    'port': requested_port,
                    'result': 'RWP_READY',
                    'timestamp': time.time()
                }
                return self.encrypt_response(response_payload, shared_secret)
            
            # Check if port is in use by something else
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(1)
            result = test_sock.connect_ex((self.host, requested_port))
            test_sock.close()
            
            if result == 0:
                return self.create_error_response(shared_secret, 409, f"Port {requested_port} is in use by another service")
            
            # Try to open the port
            success = self.open_port(requested_port)
            
            if success:
                response_payload = {
                    'type': 'PORT_OPEN_RESPONSE',
                    'status': 200,
                    'message': f'Port {requested_port} opened successfully',
                    'port': requested_port,
                    'result': 'PORT_OPENED',
                    'timestamp': time.time()
                }
                return self.encrypt_response(response_payload, shared_secret)
            else:
                return self.create_error_response(shared_secret, 500, f"Failed to open port {requested_port}")
        
        except Exception as e:
            print(f"Error handling port open request: {e}")
            return self.create_error_response(shared_secret, 500, "Internal server error")

    def create_error_response(self, shared_secret, status_code, message):
        """Create an encrypted error response"""
        response_payload = {
            'type': 'PORT_OPEN_RESPONSE',
            'status': status_code,
            'message': message,
            'result': 'ERROR',
            'timestamp': time.time()
        }
        return self.encrypt_response(response_payload, shared_secret)

    def encrypt_response(self, response_payload, shared_secret):
        """Encrypt response payload"""
        response_json = json.dumps(response_payload).encode('utf-8')
        return self.encrypt_payload(response_json, shared_secret)
    
    def handle_client(self, client_socket, addr):
        """Handle incoming client connection with HTX support and persistent connections"""
        port = self.get_port_from_socket(client_socket)
        if port:
            self.increment_port_client_count(port)
        
        # Check if this is an SSL connection and wrap it if needed
        is_htx_connection = False
        if self.enable_htx and self.detect_ssl_connection(client_socket):
            print(f"HTX SSL connection detected from {addr}")
            ssl_socket = self.wrap_ssl_connection(client_socket)
            if ssl_socket:
                client_socket = ssl_socket
                is_htx_connection = True
                print(f"HTX connection established with {addr}")
            else:
                print(f"Failed to establish HTX connection with {addr}")
                try:
                    client_socket.close()
                except:
                    pass
                if port:
                    self.decrement_port_client_count(port)
                return
        
        try:
            client_socket.settimeout(300)  # 5 minute timeout for idle connections
            
            while True:  # Keep connection alive for multiple requests
                try:
                    request_data = b""
                    while True:
                        data = client_socket.recv(4096)
                        if not data:
                            print(f"Client {addr} disconnected (HTX: {is_htx_connection})")
                            return  # Client disconnected
                        request_data += data
                        
                        if b'\r\n\r\n' in request_data:
                            break
                    
                    if not request_data:
                        continue
                    
                    request_text = request_data.decode('utf-8')
                    
                    if 'RWP/1.0' not in request_text:
                        print(f"Ignoring non-RWP request from {addr} (HTX: {is_htx_connection})")
                        continue
                    
                    request_lines = request_text.split('\r\n')
                    if len(request_lines) < 1:
                        continue
                    
                    request_line = request_lines[0]
                    print(f"Received request: {request_line} (HTX: {is_htx_connection})")
                    
                    headers = {}
                    for line in request_lines[1:]:
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            headers[key] = value
                    
                    # Handle server info request
                    if "GET_SERVER_INFO" in request_line:
                        public_pem = self.public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ).decode('utf-8')
                        
                        response_payload = {
                            'type': 'SERVER_INFO',
                            'node_id': self.node_id,
                            'public_key': public_pem,
                            'htx_enabled': self.enable_htx,
                            'timestamp': time.time()
                        }
                        
                        response_json = json.dumps(response_payload)
                        
                        response_headers = [
                            f"RWP/1.0 200 OK",
                            f"X-Node-ID: {self.node_id}",
                            f"Content-Length: {len(response_json)}"
                        ]
                        
                        response = '\r\n'.join(response_headers) + '\r\n\r\n' + response_json
                        
                        client_socket.sendall(response.encode('utf-8'))
                        print(f"Sent server info to {addr} (HTX: {is_htx_connection})")
                        continue
                    
                    # Handle encrypted requests
                    if 'X-Encrypted-Payload' not in headers:
                        print("Missing encrypted payload in request")
                        continue
                    
                    encrypted_payload = base64.b64decode(headers['X-Encrypted-Payload'])
                    peer_public_key = base64.b64decode(headers['X-Public-Key'])
                    
                    shared_secret = self.derive_shared_secret(peer_public_key)
                    decrypted = self.decrypt_payload(encrypted_payload, shared_secret)
                    payload = json.loads(decrypted.decode('utf-8'))
                    
                    request_type = payload.get('type')
                    
                    # Handle port open requests
                    if request_type == 'OPEN_PORT':
                        encrypted_response = self.handle_port_open_request(payload, shared_secret, client_socket)
                        
                        response_headers = [
                            f"RWP/1.0 200 OK",
                            f"X-Node-ID: {self.node_id}",
                            f"X-Encrypted-Payload: {base64.b64encode(encrypted_response).decode('utf-8')}"
                        ]
                        
                        response = '\r\n'.join(response_headers) + '\r\n\r\n'
                        client_socket.sendall(response.encode('utf-8'))
                        print(f"Sent port open response to {addr} (HTX: {is_htx_connection})")
                        continue
                    
                    resource = payload.get('resource', '/')
                    range_header = payload.get('range')
                    
                    if request_type == 'GET' or request_type == 'STREAM_REQUEST':
                        file_info = self.serve_resource_stream(resource, range_header)
                        
                        if file_info:
                            # For streaming requests, send file info first
                            if request_type == 'STREAM_REQUEST':
                                response_payload = {
                                    'type': 'STREAM_INFO',
                                    'status': 200,
                                    'file_size': file_info['file_size'],
                                    'content_type': file_info['content_type'],
                                    'start_byte': file_info['start_byte'],
                                    'end_byte': file_info['end_byte'],
                                    'content_length': file_info['content_length'],
                                    'supports_range': True,
                                    'htx_connection': is_htx_connection,
                                    'timestamp': time.time()
                                }
                                
                                response_json = json.dumps(response_payload).encode('utf-8')
                                encrypted_response = self.encrypt_payload(response_json, shared_secret)
                                
                                response_headers = [
                                    f"RWP/1.0 200 OK",
                                    f"X-Node-ID: {self.node_id}",
                                    f"X-Encrypted-Payload: {base64.b64encode(encrypted_response).decode('utf-8')}"
                                ]
                                
                                response = '\r\n'.join(response_headers) + '\r\n\r\n'
                                client_socket.sendall(response.encode('utf-8'))
                                print(f"Sent stream info for resource: {resource} (HTX: {is_htx_connection})")
                            
                            # For regular GET or small files, send content normally
                            elif file_info['content_length'] < 5 * 1024 * 1024:  # 5MB threshold
                                with open(file_info['path'], 'rb') as f:
                                    f.seek(file_info['start_byte'])
                                    content = f.read(file_info['content_length'])
                                
                                response_payload = {
                                    'type': 'RESPONSE',
                                    'status': 206 if file_info['is_range'] else 200,
                                    'content': base64.b64encode(content).decode('utf-8'),
                                    'content_type': file_info['content_type'],
                                    'content_length': file_info['content_length'],
                                    'file_size': file_info['file_size'],
                                    'start_byte': file_info['start_byte'],
                                    'end_byte': file_info['end_byte'],
                                    'htx_connection': is_htx_connection,
                                    'timestamp': time.time()
                                }
                                
                                response_json = json.dumps(response_payload).encode('utf-8')
                                encrypted_response = self.encrypt_payload(response_json, shared_secret)
                                
                                status_code = 206 if file_info['is_range'] else 200
                                status_text = "Partial Content" if file_info['is_range'] else "OK"
                                response_headers = [
                                    f"RWP/1.0 {status_code} {status_text}",
                                    f"X-Node-ID: {self.node_id}",
                                    f"X-Encrypted-Payload: {base64.b64encode(encrypted_response).decode('utf-8')}"
                                ]
                                
                                response = '\r\n'.join(response_headers) + '\r\n\r\n'
                                client_socket.sendall(response.encode('utf-8'))
                                print(f"Sent response for resource: {resource} (HTX: {is_htx_connection})")
                            else:
                                # File is large, suggest streaming
                                response_payload = {
                                    'type': 'RESPONSE',
                                    'status': 200,
                                    'message': 'File too large, use STREAM_REQUEST',
                                    'file_size': file_info['file_size'],
                                    'content_type': file_info['content_type'],
                                    'supports_streaming': True,
                                    'htx_connection': is_htx_connection,
                                    'timestamp': time.time()
                                }
                                
                                response_json = json.dumps(response_payload).encode('utf-8')
                                encrypted_response = self.encrypt_payload(response_json, shared_secret)
                                
                                response_headers = [
                                    f"RWP/1.0 200 OK",
                                    f"X-Node-ID: {self.node_id}",
                                    f"X-Encrypted-Payload: {base64.b64encode(encrypted_response).decode('utf-8')}"
                                ]
                                
                                response = '\r\n'.join(response_headers) + '\r\n\r\n'
                                client_socket.sendall(response.encode('utf-8'))
                                print(f"Sent large file info for resource: {resource} (HTX: {is_htx_connection})")
                        else:
                            self.send_error_response(client_socket, shared_secret, 404, 'Resource not found')
                    
                    elif request_type == 'STREAM_CHUNK':
                        # Handle chunk requests for streaming
                        chunk_start = payload.get('chunk_start', 0)
                        chunk_size = payload.get('chunk_size', self.chunk_size)
                        
                        file_info = self.serve_resource_stream(resource)
                        if file_info:
                            chunk_end = min(chunk_start + chunk_size - 1, file_info['file_size'] - 1)
                            self.send_stream_chunk(client_socket, shared_secret, file_info, chunk_start, chunk_end)
                        else:
                            self.send_error_response(client_socket, shared_secret, 404, 'Resource not found')
                    
                    elif request_type == 'POST':
                        post_data = payload.get('data', '')
                        response_content = f"{post_data}"
                        
                        response_payload = {
                            'type': 'RESPONSE',
                            'status': 200,
                            'content': base64.b64encode(response_content.encode('utf-8')).decode('utf-8'),
                            'htx_connection': is_htx_connection,
                            'timestamp': time.time()
                        }
                        
                        response_json = json.dumps(response_payload).encode('utf-8')
                        encrypted_response = self.encrypt_payload(response_json, shared_secret)
                        
                        response_headers = [
                            f"RWP/1.0 200 OK",
                            f"X-Node-ID: {self.node_id}",
                            f"X-Encrypted-Payload: {base64.b64encode(encrypted_response).decode('utf-8')}"
                        ]
                        
                        response = '\r\n'.join(response_headers) + '\r\n\r\n'
                        client_socket.sendall(response.encode('utf-8'))
                        print(f"Sent POST response for resource: {resource} (HTX: {is_htx_connection})")
                    
                    else:
                        self.send_error_response(client_socket, shared_secret, 501, f'Unsupported method: {request_type}')
                
                except socket.timeout:
                    print(f"Client {addr} connection timed out (HTX: {is_htx_connection})")
                    break
                except Exception as e:
                    print(f"Error in client communication loop: {e} (HTX: {is_htx_connection})")
                    break
        
        except Exception as e:
            print(f"Error handling request from {addr}: {e} (HTX: {is_htx_connection})")
        finally:
            if port:
                self.decrement_port_client_count(port)
                print(f"Client {addr} disconnected from port {port} (HTX: {is_htx_connection})")
            try:
                client_socket.close()
            except:
                pass

    def send_error_response(self, client_socket, shared_secret, status_code, message):
        """Send an encrypted error response"""
        response_payload = {
            'type': 'RESPONSE',
            'status': status_code,
            'message': message,
            'timestamp': time.time()
        }
        
        response_json = json.dumps(response_payload).encode('utf-8')
        encrypted_response = self.encrypt_payload(response_json, shared_secret)
        
        status_text = "Not Found" if status_code == 404 else "Not Implemented"
        response_headers = [
            f"RWP/1.0 {status_code} {status_text}",
            f"X-Node-ID: {self.node_id}",
            f"X-Encrypted-Payload: {base64.b64encode(encrypted_response).decode('utf-8')}"
        ]
        
        response = '\r\n'.join(response_headers) + '\r\n\r\n'
        client_socket.sendall(response.encode('utf-8'))

    def is_port_running_rwp(self, port):
        """Check if a port is running RWP by attempting a test connection"""
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2)
            result = test_sock.connect_ex((self.host, port))
            test_sock.close()
            
            if result == 0:
                # Port is open, now check if it's RWP by sending a test request
                try:
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(2)
                    test_sock.connect((self.host, port))
                    
                    test_request = "GET_SERVER_INFO RWP/1.0\r\nX-Node-ID: test\r\n\r\n"
                    test_sock.sendall(test_request.encode('utf-8'))
                    
                    response = test_sock.recv(1024).decode('utf-8')
                    test_sock.close()
                    
                    return 'RWP/1.0' in response
                except:
                    return False
            return False
        except:
            return False

    def start_http_server(self):
        """Start HTTP server on port 80"""
        import json

        def handle_http_request(client_socket, addr):
            try:
                request_data = client_socket.recv(4096).decode('utf-8')
                request_lines = request_data.splitlines()
                if not request_lines:
                    client_socket.close()
                    return

                # Parse request line
                request_line = request_lines[0]
                method, path, _ = request_line.split(" ", 2)

                # Check headers
                headers = {}
                for line in request_lines[1:]:
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        headers[key.lower()] = value.lower()

                # Decide if API/JSON or HTML
                is_json_request = (
                    "/api" in path.lower()
                    or "application/json" in headers.get("accept", "")
                )

                if is_json_request:
                    response_body = json.dumps({
                        "title": self.title,
                        "contents": self.contents,
                        "node_id": self.node_id,
                        "ports": self.ports,
                        "knock_ports": self.knock_ports,
                        "htx_enabled": self.enable_htx
                    }, indent=2)

                    http_response = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(response_body)}\r\n"
                        "Connection: close\r\n\r\n"
                        f"{response_body}"
                    )
                else:
                    response_body = f"""<!DOCTYPE html>
<html>
<head>
    <title>RWP Server Info</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f0f0f0; }}
        .container {{ background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; }}
        .info-section {{ margin: 20px 0; padding: 15px; background-color: #f9f9f9; border-left: 4px solid #007acc; }}
        .port-list {{ background-color: #e7f3ff; padding: 10px; border-radius: 5px; }}
        ul {{ list-style-type: none; padding: 0; }}
        li {{ margin: 5px 0; padding: 5px; background-color: white; border-radius: 3px; }}
        .htx-status {{ color: {'#28a745' if self.enable_htx else '#dc3545'}; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>I AM RWP SV with Streaming & HTX</h1>
        
        <div class="info-section">
            <h2>HTX Tunneling:</h2>
            <p class="htx-status">{'ENABLED' if self.enable_htx else 'DISABLED'}</p>
            <p>HTX allows RWP traffic to be disguised as regular HTTPS connections.</p>
        </div>
        
        <div class="info-section">
            <h2>Default Ports:</h2>
            <div class="port-list">
                <ul>
                    {''.join(f'<li>Port {port}</li>' for port in self.ports)}
                </ul>
            </div>
        </div>
        
        <div class="info-section">
            <h2>Knock Ports:</h2>
            <div class="port-list">
                <ul>
                    {''.join(f'<li>Port {port}</li>' for port in self.knock_ports)}
                </ul>
            </div>
        </div>
        
        <div class="info-section">
            <h2>Server Info:</h2>
            <p><strong>Title:</strong> {self.title}</p>
            <p><strong>Contents:</strong> {self.contents}</p>
            <p><strong>Node ID:</strong> {self.node_id}</p>
            <p><strong>Features:</strong> Streaming Support, Range Requests, HTX Tunneling</p>
        </div>
    </div>
</body>
</html>"""
                    http_response = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html\r\n"
                        f"Content-Length: {len(response_body)}\r\n"
                        "Connection: close\r\n\r\n"
                        f"{response_body}"
                    )

                client_socket.sendall(http_response.encode('utf-8'))
                client_socket.close()

            except Exception as e:
                print(f"HTTP server error: {e}")
                try:
                    client_socket.close()
                except:
                    pass

        def http_server_loop():
            try:
                http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                http_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                http_sock.bind((self.host, 80))
                http_sock.listen(5)
                print(f"HTTP Server listening on {self.host}:80")

                while self.running:
                    try:
                        client_socket, addr = http_sock.accept()
                        http_thread = threading.Thread(
                            target=handle_http_request,
                            args=(client_socket, addr)
                        )
                        http_thread.daemon = True
                        http_thread.start()
                    except Exception as e:
                        if self.running:
                            print(f"HTTP server accept error: {e}")

                http_sock.close()
            except Exception as e:
                print(f"HTTP server startup error: {e}")

        http_thread = threading.Thread(target=http_server_loop)
        http_thread.daemon = True
        http_thread.start()

    def start(self):
        """Start the RWP server on multiple ports"""
        self.running = True

        # Initialize client counts for all ports
        with self.port_client_lock:
            for port in self.ports:
                self.port_client_counts[port] = 0

        # Start HTTP server on port 80
        self.start_http_server()

        # Create server sockets for each port
        for port in self.ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, port))
            sock.listen(5)
            self.sockets.append(sock)
            print(f"RWP Server listening on {self.host}:{port} (HTX: {self.enable_htx})")

        # Start port knocking listener
        knock_thread = threading.Thread(target=self.port_knocking_listener)
        knock_thread.daemon = True
        knock_thread.start()

        # Start port expiration monitor
        expiration_thread = threading.Thread(target=self.monitor_port_expiration)
        expiration_thread.daemon = True
        expiration_thread.start()
    
        # Main server loop
        while self.running:
            all_sockets = self.sockets + self.open_port_sockets
            readable, _, _ = select.select(all_sockets, [], [], 1.0)

            for sock in readable:
                try:
                    client_socket, addr = sock.accept()
                    print(f"New connection from {addr}")

                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                except KeyboardInterrupt:
                    self.stop()
                except Exception as e:
                    print(f"Error: {e}")

    def port_knocking_listener(self):
        """Listen for port knocks and open requested ports"""
        knock_sockets = []
        socket_to_port = {}

        for port in self.knock_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, port))
            sock.listen(5)
            knock_sockets.append((port, sock))
            socket_to_port[sock] = port

        print(f"Port knocking listener started on ports {self.knock_ports}")

        while self.running:
            readable, _, _ = select.select(socket_to_port.keys(), [], [], 1.0)

            for sock in readable:
                try:
                    port = socket_to_port[sock]
                    client_socket, addr = sock.accept()
                    ip = addr[0]

                    data = b""
                    try:
                        data = client_socket.recv(1024)
                    except:
                        pass
                        
                    client_socket.close()
                    self.process_knock(ip, port, data)

                except Exception as e:
                    print(f"Error processing knock on port {port}: {e}")
    
    def process_knock(self, ip, port, data):
        """Process a single knock in a sequence"""
        current_time = time.time()

        if ip not in self.knock_sequences:
            self.knock_sequences[ip] = {"ports": [], "last_time": current_time}

        sequence = self.knock_sequences[ip]

        if current_time - sequence["last_time"] > 10:
            sequence["ports"] = []

        sequence["ports"].append(port)
        sequence["last_time"] = current_time

        if sequence["ports"] == self.knock_ports:
            try:
                requested_port = int(data.decode('utf-8'))
                print(f"Valid knock sequence from {ip}, requesting port {requested_port}")

                # Check if port is already running RWP
                if self.is_port_running_rwp(requested_port):
                    print(f"Port {requested_port} is already running RWP")
                    return "RWP_READY"
                
                # Check if port is in use by something else
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.settimeout(1)
                result = test_sock.connect_ex((self.host, requested_port))
                test_sock.close()
                
                if result == 0:
                    print(f"Port {requested_port} is in use by another service")
                    return "PORT_USED"

                self.open_port(requested_port)
                sequence["ports"] = []
                return "PORT_OPENED"

            except (ValueError, UnicodeDecodeError):
                print(f"Invalid port request in knock sequence from {ip}")
                sequence["ports"] = []
                return "INVALID_REQUEST"

    def open_port(self, port):
        """Open a specific port for RWP service"""
        try:
            if port in self.ports or port in self.open_ports:
                return True

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, port))
            sock.listen(5)

            creation_time = time.time()
            self.open_ports[port] = (sock, creation_time)
            self.open_port_sockets.append(sock)

            # Initialize client count for this port
            with self.port_client_lock:
                self.port_client_counts[port] = 0

            print(f"Opened RWP port {port} (HTX: {self.enable_htx})")
            return True

        except Exception as e:
            print(f"Failed to open port {port}: {e}")
            return False

    def monitor_port_expiration(self):
        """Monitor and close expired dynamically opened ports"""
        while self.running:
            current_time = time.time()

            for port, (sock, creation_time) in list(self.open_ports.items()):
                with self.port_client_lock:
                    client_count = self.port_client_counts.get(port, 0)
                
                # If no clients for 5 minutes, close the port
                if client_count == 0 and (current_time - creation_time) > 300:
                    print(f"Port {port} has no clients for 5 minutes, closing...")
                    try:
                        sock.close()
                        if sock in self.open_port_sockets:
                            self.open_port_sockets.remove(sock)
                    except:
                        pass
                    
                    del self.open_ports[port]
                    
                    with self.port_client_lock:
                        if port in self.port_client_counts:
                            del self.port_client_counts[port]

            time.sleep(30)  # Check every 30 seconds

    def stop(self):
        """Stop the RWP server"""
        self.running = False

        for sock in self.sockets:
            sock.close()

        for port, (sock, _) in self.open_ports.items():
            sock.close()

        print("RWP Server stopped")

if __name__ == "__main__":
    server = RWPServer(ports=[7070, 7071, 2213])
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()

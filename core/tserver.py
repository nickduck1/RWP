#!/usr/bin/env python3
"""
RRKDHT Server with Web-RWP Protocol Support
Production server for Rotating Rendezvous Kademlia DHT with custom Web-RWP protocol.
"""

import asyncio
import json
import logging
import socket
import ssl
import threading
import time
import traceback
import signal
import sys
import os
import base64
import hashlib
import secrets
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import websockets
from websockets import WebSocketServerProtocol
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

# Import the RRKDHT implementation
from RRKDHT import RRKDHT, create_ed25519_key_pair, generate_peer_id, digest

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('rrkdht_server.log')
    ]
)
log = logging.getLogger(__name__)

class WebRWPMessageType(Enum):
    """Web-RWP specific message types."""
    HANDSHAKE = "handshake"
    HANDSHAKE_RESPONSE = "handshake_response"
    ENCRYPTED_PAYLOAD = "encrypted_payload"
    DHT_GET = "dht_get"
    DHT_SET = "dht_set"
    DHT_RESPONSE = "dht_response"
    NODE_INFO = "node_info"
    NETWORK_STATUS = "network_status"
    ERROR = "error"
    HEARTBEAT = "heartbeat"
    PONG = "pong"

@dataclass
class WebRWPMessage:
    """Web-RWP message structure."""
    type: WebRWPMessageType
    payload: Dict[str, Any]
    message_id: str
    timestamp: float
    encrypted: bool = False
    signature: Optional[str] = None

class WebRWPSession:
    """Represents an authenticated Web-RWP session."""
    
    def __init__(self, session_id: str, client_public_key: x25519.X25519PublicKey):
        self.session_id = session_id
        self.client_public_key = client_public_key
        self.created_at = time.time()
        self.last_activity = time.time()
        self.authenticated = False
        self.shared_secret = None
        self.encryption_key = None
    
    def is_expired(self, timeout: int = 3600) -> bool:
        """Check if session is expired."""
        return time.time() - self.last_activity > timeout
    
    def touch(self):
        """Update last activity timestamp."""
        self.last_activity = time.time()

class WebRWPServer:
    """Custom Web-RWP server for RRKDHT clients."""
    
    def __init__(self, dht_node: RRKDHT, port: int = 7070):
        self.dht_node = dht_node
        self.port = port
        self.server = None
        self.running = False
        self.sessions: Dict[str, WebRWPSession] = {}
        self.sessions_lock = threading.RLock()
        self.cleanup_thread = None
        
        # Generate server key pair for Web-RWP
        self.server_private_key = x25519.X25519PrivateKey.generate()
        self.server_public_key = self.server_private_key.public_key()
        
        # Server identification
        self.server_id = secrets.token_hex(16)
        self.protocol_version = "1.0"
        
        log.info(f"Web-RWP server initialized with ID: {self.server_id}")
    
    async def start(self):
        """Start the Web-RWP server."""
        if self.running:
            return
            
        self.running = True
        
        # Start session cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_sessions, daemon=True)
        self.cleanup_thread.start()
        
        # Start WebSocket server
        self.server = await websockets.serve(
            self.handle_client,
            "0.0.0.0",
            self.port,
            ping_interval=30,
            ping_timeout=10,
            max_size=1024 * 1024,  # 1MB max message size
            max_queue=100
        )
        
        log.info(f"Web-RWP server started on port {self.port}")
    
    async def stop(self):
        """Stop the Web-RWP server."""
        self.running = False
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        self.dht_node.stop()

        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        
        log.info("Web-RWP server stopped")
    
    def _cleanup_sessions(self):
        """Cleanup expired sessions periodically."""
        while self.running:
            try:
                with self.sessions_lock:
                    expired_sessions = [
                        sid for sid, session in self.sessions.items()
                        if session.is_expired()
                    ]
                    
                    for sid in expired_sessions:
                        del self.sessions[sid]
                    
                    if expired_sessions:
                        log.info(f"Cleaned up {len(expired_sessions)} expired sessions")
                
                time.sleep(300)  # Cleanup every 5 minutes
                
            except Exception as e:
                log.error(f"Error in session cleanup: {e}")
                time.sleep(60)
    
    async def handle_client(self, websocket: WebSocketServerProtocol, path: str):
        """Handle incoming Web-RWP client connections."""
        client_addr = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        session_id = None
        
        try:
            log.info(f"New Web-RWP client connected: {client_addr}")
            
            async for message_raw in websocket:
                try:
                    message_data = json.loads(message_raw)
                    message = WebRWPMessage(
                        type=WebRWPMessageType(message_data['type']),
                        payload=message_data['payload'],
                        message_id=message_data['message_id'],
                        timestamp=message_data['timestamp'],
                        encrypted=message_data.get('encrypted', False),
                        signature=message_data.get('signature')
                    )
                    
                    response = await self.process_message(message, session_id)
                    
                    if message.type == WebRWPMessageType.HANDSHAKE and response:
                        session_id = response.payload.get('session_id')
                    
                    if response:
                        response_json = json.dumps({
                            'type': response.type.value,
                            'payload': response.payload,
                            'message_id': response.message_id,
                            'timestamp': response.timestamp,
                            'encrypted': response.encrypted,
                            'signature': response.signature
                        })
                        await websocket.send(response_json)
                
                except json.JSONDecodeError:
                    error_response = self.create_error_response(
                        "Invalid JSON message", "INVALID_JSON"
                    )
                    await websocket.send(json.dumps(error_response))
                
                except ValueError as e:
                    error_response = self.create_error_response(
                        f"Invalid message type: {e}", "INVALID_MESSAGE_TYPE"
                    )
                    await websocket.send(json.dumps(error_response))
                
                except Exception as e:
                    log.error(f"Error processing message from {client_addr}: {e}")
                    error_response = self.create_error_response(
                        "Internal server error", "INTERNAL_ERROR"
                    )
                    await websocket.send(json.dumps(error_response))
        
        except websockets.exceptions.ConnectionClosed:
            log.info(f"Web-RWP client disconnected: {client_addr}")
        except Exception as e:
            log.error(f"Error handling Web-RWP client {client_addr}: {e}")
        finally:
            if session_id:
                with self.sessions_lock:
                    self.sessions.pop(session_id, None)
                log.info(f"Session {session_id} cleaned up")
    
    async def process_message(self, message: WebRWPMessage, session_id: Optional[str]) -> Optional[WebRWPMessage]:
        """Process incoming Web-RWP messages."""
        if message.type == WebRWPMessageType.HANDSHAKE:
            return await self.handle_handshake(message)
        
        # All other messages require authentication
        if not session_id:
            return self.create_error_response("No session", "NO_SESSION")
        
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if not session:
                return self.create_error_response("Invalid session", "INVALID_SESSION")
            
            session.touch()
        
        if message.encrypted and session.encryption_key:
            # Decrypt message
            try:
                decrypted_payload = self.decrypt_payload(
                    message.payload, session.encryption_key
                )
                message.payload = decrypted_payload
            except Exception as e:
                log.error(f"Failed to decrypt message: {e}")
                return self.create_error_response("Decryption failed", "DECRYPTION_ERROR")
        
        if message.type == WebRWPMessageType.DHT_GET:
            return await self.handle_dht_get(message, session)
        elif message.type == WebRWPMessageType.DHT_SET:
            return await self.handle_dht_set(message, session)
        elif message.type == WebRWPMessageType.NODE_INFO:
            return await self.handle_node_info(message, session)
        elif message.type == WebRWPMessageType.NETWORK_STATUS:
            return await self.handle_network_status(message, session)
        elif message.type == WebRWPMessageType.HEARTBEAT:
            return await self.handle_heartbeat(message, session)
        else:
            return self.create_error_response("Unknown message type", "UNKNOWN_MESSAGE")
    
    async def handle_handshake(self, message: WebRWPMessage) -> WebRWPMessage:
        """Handle Web-RWP handshake."""
        try:
            # Extract client public key
            client_public_key_bytes = base64.b64decode(
                message.payload['client_public_key']
            )
            client_public_key = x25519.X25519PublicKey.from_public_bytes(
                client_public_key_bytes
            )
            
            # Generate session ID
            session_id = secrets.token_hex(32)
            
            # Perform key exchange
            shared_secret = self.server_private_key.exchange(client_public_key)
            
            # Derive encryption key
            encryption_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'web-rwp-encryption',
                backend=default_backend()
            ).derive(shared_secret)
            
            # Create session
            session = WebRWPSession(session_id, client_public_key)
            session.shared_secret = shared_secret
            session.encryption_key = encryption_key
            session.authenticated = True
            
            with self.sessions_lock:
                self.sessions[session_id] = session
            
            # Send handshake response
            server_public_key_bytes = self.server_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            response_payload = {
                'session_id': session_id,
                'server_public_key': base64.b64encode(server_public_key_bytes).decode(),
                'server_id': self.server_id,
                'protocol_version': self.protocol_version,
                'node_id': self.dht_node.node.id.hex(),
                'rendezvous_key': self.dht_node.get_rendezvous_key(),
                'capabilities': [
                    'dht_get', 'dht_set', 'node_info', 
                    'network_status', 'encrypted_messaging'
                ]
            }
            
            return WebRWPMessage(
                type=WebRWPMessageType.HANDSHAKE_RESPONSE,
                payload=response_payload,
                message_id=secrets.token_hex(16),
                timestamp=time.time()
            )
            
        except Exception as e:
            log.error(f"Handshake failed: {e}")
            return self.create_error_response("Handshake failed", "HANDSHAKE_ERROR")
    
    async def handle_dht_get(self, message: WebRWPMessage, session: WebRWPSession) -> WebRWPMessage:
        """Handle DHT GET request."""
        try:
            key = message.payload['key']
            value = await self.dht_node.get(key)
            
            response_payload = {
                'key': key,
                'value': value,
                'found': value is not None,
                'timestamp': time.time()
            }
            
            # Encrypt response if requested
            if message.payload.get('encrypt_response', False):
                encrypted_payload = self.encrypt_payload(
                    response_payload, session.encryption_key
                )
                return WebRWPMessage(
                    type=WebRWPMessageType.DHT_RESPONSE,
                    payload=encrypted_payload,
                    message_id=secrets.token_hex(16),
                    timestamp=time.time(),
                    encrypted=True
                )
            
            return WebRWPMessage(
                type=WebRWPMessageType.DHT_RESPONSE,
                payload=response_payload,
                message_id=secrets.token_hex(16),
                timestamp=time.time()
            )
            
        except Exception as e:
            log.error(f"DHT GET failed: {e}")
            return self.create_error_response("DHT GET failed", "DHT_GET_ERROR")
    
    async def handle_dht_set(self, message: WebRWPMessage, session: WebRWPSession) -> WebRWPMessage:
        """Handle DHT SET request."""
        try:
            key = message.payload['key']
            value = message.payload['value']
            ttl = message.payload.get('ttl', 86400)  # 24 hours default
            
            success = await self.dht_node.set(key, value)
            
            response_payload = {
                'key': key,
                'success': success,
                'timestamp': time.time()
            }
            
            # Encrypt response if requested
            if message.payload.get('encrypt_response', False):
                encrypted_payload = self.encrypt_payload(
                    response_payload, session.encryption_key
                )
                return WebRWPMessage(
                    type=WebRWPMessageType.DHT_RESPONSE,
                    payload=encrypted_payload,
                    message_id=secrets.token_hex(16),
                    timestamp=time.time(),
                    encrypted=True
                )
            
            return WebRWPMessage(
                type=WebRWPMessageType.DHT_RESPONSE,
                payload=response_payload,
                message_id=secrets.token_hex(16),
                timestamp=time.time()
            )
            
        except Exception as e:
            log.error(f"DHT SET failed: {e}")
            return self.create_error_response("DHT SET failed", "DHT_SET_ERROR")
    
    async def handle_node_info(self, message: WebRWPMessage, session: WebRWPSession) -> WebRWPMessage:
        """Handle node info request."""
        try:
            debug_info = self.dht_node.get_debug_info()
            
            response_payload = {
                'node_info': debug_info['node_info'],
                'epoch_info': debug_info['epoch_info'],
                'routing_info': debug_info['routing_info'],
                'server_info': {
                    'server_id': self.server_id,
                    'protocol_version': self.protocol_version,
                    'uptime': time.time() - session.created_at,
                    'active_sessions': len(self.sessions)
                }
            }
            
            return WebRWPMessage(
                type=WebRWPMessageType.DHT_RESPONSE,
                payload=response_payload,
                message_id=secrets.token_hex(16),
                timestamp=time.time()
            )
            
        except Exception as e:
            log.error(f"Node info request failed: {e}")
            return self.create_error_response("Node info failed", "NODE_INFO_ERROR")
    
    async def handle_network_status(self, message: WebRWPMessage, session: WebRWPSession) -> WebRWPMessage:
        """Handle network status request."""
        try:
            debug_info = self.dht_node.get_debug_info()
            
            # Get additional network metrics
            neighbors = self.dht_node.bootstrappable_neighbors()
            
            response_payload = {
                'network_id': self.dht_node.node.id.hex(),
                'total_neighbors': len(neighbors),
                'routing_table_size': debug_info['routing_info']['total_nodes'],
                'bucket_count': debug_info['routing_info']['total_buckets'],
                'lonely_buckets': debug_info['routing_info']['lonely_buckets'],
                'current_epoch': debug_info['epoch_info']['current_epoch'],
                'storage_epochs': debug_info['epoch_info']['storage_epochs'],
                'retrieval_epochs': debug_info['epoch_info']['retrieval_epochs'],
                'rendezvous_key': debug_info['node_info']['rendezvous_key'],
                'neighbors': [
                    {'ip': n[0], 'port': n[1], 'rwp_port': n[2] if len(n) > 2 else None}
                    for n in neighbors[:10]  # Limit to first 10 neighbors
                ]
            }
            
            return WebRWPMessage(
                type=WebRWPMessageType.DHT_RESPONSE,
                payload=response_payload,
                message_id=secrets.token_hex(16),
                timestamp=time.time()
            )
            
        except Exception as e:
            log.error(f"Network status request failed: {e}")
            return self.create_error_response("Network status failed", "NETWORK_STATUS_ERROR")
    
    async def handle_heartbeat(self, message: WebRWPMessage, session: WebRWPSession) -> WebRWPMessage:
        """Handle heartbeat message."""
        return WebRWPMessage(
            type=WebRWPMessageType.PONG,
            payload={'timestamp': time.time()},
            message_id=secrets.token_hex(16),
            timestamp=time.time()
        )
    
    def encrypt_payload(self, payload: Dict, encryption_key: bytes) -> Dict:
        """Encrypt payload using ChaCha20Poly1305."""
        try:
            chacha = ChaCha20Poly1305(encryption_key)
            nonce = os.urandom(12)
            
            payload_bytes = json.dumps(payload).encode()
            ciphertext = chacha.encrypt(nonce, payload_bytes, None)
            
            return {
                'encrypted_data': base64.b64encode(ciphertext).decode(),
                'nonce': base64.b64encode(nonce).decode()
            }
            
        except Exception as e:
            log.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_payload(self, encrypted_payload: Dict, encryption_key: bytes) -> Dict:
        """Decrypt payload using ChaCha20Poly1305."""
        try:
            chacha = ChaCha20Poly1305(encryption_key)
            
            ciphertext = base64.b64decode(encrypted_payload['encrypted_data'])
            nonce = base64.b64decode(encrypted_payload['nonce'])
            
            decrypted = chacha.decrypt(nonce, ciphertext, None)
            return json.loads(decrypted.decode())
            
        except Exception as e:
            log.error(f"Decryption failed: {e}")
            raise
    
    def create_error_response(self, message: str, error_code: str) -> Dict:
        """Create error response message."""
        return {
            'type': WebRWPMessageType.ERROR.value,
            'payload': {
                'error': message,
                'error_code': error_code,
                'timestamp': time.time()
            },
            'message_id': secrets.token_hex(16),
            'timestamp': time.time(),
            'encrypted': False
        }

class RRKDHTServerManager:
    """Main server manager for RRKDHT with Web-RWP support."""
    
    def __init__(self):
        self.dht_node: Optional[RRKDHT] = None
        self.web_rwp_server: Optional[WebRWPServer] = None
        self.running = False
        self.loop = None

    async def start_server(self):
        """Start the RRKDHT server with all components."""
        try:
            self.loop = asyncio.get_running_loop()  # Store loop reference
            
            print("=" * 60)
            print("RRKDHT Server with Web-RWP Protocol")
            print("=" * 60)
            print()
            
            # Ask user for network choice
            choice = input("Choose option:\n1. Create new network\n2. Join existing network\nEnter choice (1 or 2): ").strip()
            
            bootstrap_addresses = []
            if choice == "2":
                print("\nEnter bootstrap node addresses (format: ip:port:rwp_port)")
                print("Press Enter with empty line to finish.")
                
                while True:
                    addr_input = input("Bootstrap address: ").strip()
                    if not addr_input:
                        break
                    
                    try:
                        parts = addr_input.split(':')
                        if len(parts) == 2:
                            ip, port = parts
                            bootstrap_addresses.append((ip, int(port), int(port) + 1000))
                        elif len(parts) == 3:
                            ip, port, rwp_port = parts
                            bootstrap_addresses.append((ip, int(port), int(rwp_port)))
                        else:
                            print("Invalid format. Use ip:port or ip:port:rwp_port")
                            continue
                            
                        print(f"Added bootstrap node: {bootstrap_addresses[-1]}")
                        
                    except ValueError:
                        print("Invalid port numbers. Please try again.")
            
            elif choice != "1":
                print("Invalid choice. Creating new network.")
            
            # Generate keys for this node
            signing_private_key, signing_public_key = create_ed25519_key_pair()
            
            # Create DHT node
            print(f"\nCreating RRKDHT node...")
            self.dht_node = RRKDHT(
                ksize=3,
                alpha=3,
                signing_keys=(signing_private_key, signing_public_key),
                rwp_port=8443
            )
            
            # Start DHT node
            print(f"Starting DHT node on port 8080 (RWP: 8443)...")
            await self.dht_node.listen(8080, "0.0.0.0", 8443)
            
            # Bootstrap if addresses provided
            if bootstrap_addresses:
                print(f"Bootstrapping with {len(bootstrap_addresses)} nodes...")
                try:
                    result = await self.dht_node.bootstrap(bootstrap_addresses)
                    if result:
                        print(f"Successfully bootstrapped with {len(result)} nodes")
                    else:
                        print("Bootstrap completed, but no nodes found")
                except Exception as e:
                    traceback.print_exc()
                    print(f"Bootstrap failed: {e}")
                    print("Continuing as isolated node...")
            
            # Start Web-RWP server
            print(f"Starting Web-RWP server on port 7070...")
            self.web_rwp_server = WebRWPServer(self.dht_node, 7070)
            await self.web_rwp_server.start()
            
            # Display node information
            self.display_node_info()
            
            # Start console handler
            console_thread = self.start_console_handler()
            
            self.running = True
            print(f"\n✅ RRKDHT Server is running!")
            print(f"  - DHT Protocol: UDP port 8080")
            print(f"  - RWP Protocol: TCP port 8443") 
            print(f"  - Web-RWP Protocol: WebSocket port 7070")
            print(f"  - Node ID: {self.dht_node.node.id.hex()}")
            print(f"  - Rendezvous Key: {self.dht_node.get_rendezvous_key()}")
            print(f"\nPress Ctrl+C to stop the server or type commands at the prompt.")
            
            # Keep server running
            while self.running:
                await asyncio.sleep(1) 
                
        except KeyboardInterrupt:
            print(f"\n\nShutting down server...")
        except Exception as e:
            log.error(f"Server error: {e}")
            print(f"Server error: {e}")
            traceback.print_exc()
        finally:
            await self.stop_server()
    
    def start_console_handler(self):
        """Start console command handler in a separate thread."""
        def console_loop():
            print(f"\nConsole commands available:")
            print(f"  rt, routing         - Show routing table")
            print(f"  rt-full             - Show routing table with empty buckets")
            print(f"  rt-repl             - Show routing table with replacement nodes") 
            print(f"  neighbors           - Show all neighbors")
            print(f"  health              - Show routing health analysis")
            print(f"  status              - Show node status")
            print(f"  debug               - Show comprehensive debug info")
            print(f"  ping <ip> <port>    - Ping a specific node")
            print(f"  search <node_id>    - Search for a node by Node ID")
            print(f"  search-rk <key>     - Search for a node by Rendezvous Key")
            print(f"  help                - Show this help message")
            print(f"  quit, exit          - Shutdown server")
            print(f"Enter commands below:")
            
            while self.running:
                try:
                    command = input("> ").strip()
                    
                    if not command:
                        continue
                        
                    if command in ['quit', 'exit']:
                        print("Shutting down server...")
                        self.running = False
                        if self.loop and self.loop.is_running():
                            asyncio.run_coroutine_threadsafe(self.stop_server(), self.loop)
                        break
                    
                    elif command in ['rt', 'routing']:
                        self.display_routing_table()
                    
                    elif command == 'rt-full':
                        self.display_routing_table(show_empty_buckets=True)
                    
                    elif command == 'rt-repl':
                        self.display_routing_table(show_replacement_nodes=True)
                    
                    elif command.startswith('search-rk '):
                        parts = command.split(maxsplit=1)
                        if len(parts) >= 2:
                            rendezvous_key = parts[1].strip()
                            asyncio.run_coroutine_threadsafe(
                                self.search_by_rendezvous_command(rendezvous_key),
                                self.loop
                            )
                        else:
                            print("Usage: search-rk <rendezvous_key>")

                    elif command == 'neighbors':
                        self.display_neighbors()
                    
                    elif command == 'health':
                        self.display_routing_health()
                    
                    elif command == 'status':
                        self.display_node_status()
                    
                    elif command == 'debug':
                        self.display_comprehensive_debug()
                    
                    elif command.startswith('ping '):
                        parts = command.split()
                        if len(parts) >= 3:
                            try:
                                ip = parts[1]
                                port = int(parts[2])
                                rwp_port = int(parts[3]) if len(parts) > 3 else port + 1000
                                asyncio.run_coroutine_threadsafe(
                                    self.ping_node_command(ip, port, rwp_port), 
                                    self.loop
                                )
                            except ValueError:
                                print("Invalid port number")
                        else:
                            print("Usage: ping <ip> <port> [rwp_port]")
                    
                    elif command.startswith('search '):
                        parts = command.split()
                        if len(parts) >= 2:
                            node_id = parts[1].strip()
                            asyncio.run_coroutine_threadsafe(
                                self.search_node_command(node_id),
                                self.loop
                            )
                        else:
                            print("Usage: search <node_id>")
                    
                    elif command == 'help':
                        print(f"\nAvailable commands:")
                        print(f"  rt, routing         - Show routing table")
                        print(f"  rt-full             - Show routing table with empty buckets")
                        print(f"  rt-repl             - Show routing table with replacement nodes")
                        print(f"  search-rk <key>     - Search for node by Rendezvous Key")
                        print(f"  neighbors           - Show all neighbors by distance") 
                        print(f"  health              - Show routing health analysis")
                        print(f"  status              - Show current node status")
                        print(f"  debug               - Show comprehensive debug info")
                        print(f"  ping <ip> <port>    - Ping a specific node")
                        print(f"  search <node_id>    - Search for node by Node ID (hex)")
                        print(f"  help                - Show this help message")
                        print(f"  quit, exit          - Shutdown server")
                    
                    else:
                        print(f"Unknown command: {command}. Type 'help' for available commands.")
                        
                except EOFError:
                    print("\nShutting down server...")
                    self.running = False
                    if self.loop and self.loop.is_running():
                        asyncio.run_coroutine_threadsafe(self.stop_server(), self.loop)
                    break
                except Exception as e:
                    print(f"Console error: {e}")
        
        console_thread = threading.Thread(target=console_loop, daemon=True)
        console_thread.start()
        return console_thread

    async def search_node_command(self, node_id: str):
        """Execute node search and display results."""
        print(f"\nSearching for node: {node_id}")
        print(f"{'='*60}")
        
        try:
            result = await self.dht_node.search_node(node_id)
            
            if result.found:
                print(f"✅ NODE FOUND!")
                print(f"\nTarget Node Information:")
                print(f"  Node ID: {result.target_node.id.hex()}")
                print(f"  Address: {result.target_node.ip}:{result.target_node.port}")
                print(f"  RWP Port: {result.target_node.rwp_port}")
                if result.target_node.rendezvous_key:
                    print(f"  Rendezvous Key: {result.target_node.rendezvous_key}")
                
                print(f"\nSearch Statistics:")
                print(f"  Hops: {result.hops}")
                print(f"  Nodes Queried: {result.nodes_queried}")
                print(f"  Search Time: {result.search_time:.3f} seconds")
                
                if result.path:
                    print(f"\nSearch Path (Node IDs):")
                    for i, path_node_id in enumerate(result.path, 1):
                        print(f"    {i}. {path_node_id}")
            else:
                print(f"❌ NODE NOT FOUND")
                print(f"\nSearch Statistics:")
                print(f"  Hops: {result.hops}")
                print(f"  Nodes Queried: {result.nodes_queried}")
                print(f"  Search Time: {result.search_time:.3f} seconds")
                
                if result.path:
                    print(f"\nNodes Queried (in order):")
                    for i, path_node_id in enumerate(result.path, 1):
                        print(f"    {i}. {path_node_id}")
                
                print(f"\nThe target node may be:")
                print(f"  • Offline or unreachable")
                print(f"  • Not part of this network")
                print(f"  • Behind a firewall or NAT")
            
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"❌ Search error: {e}")
            import traceback
            traceback.print_exc()

    def display_routing_table(self, show_empty_buckets=False, show_replacement_nodes=False):
        """Display detailed routing table information."""
        if not self.dht_node or not self.dht_node.protocol:
            print("DHT node not initialized or no protocol available")
            return
            
        # Print routing table
        self.dht_node.protocol.router.print_routing_table(
            show_empty_buckets=show_empty_buckets, 
            show_replacement_nodes=show_replacement_nodes
        )

    async def search_by_rendezvous_command(self, rendezvous_key: str):
        """Execute rendezvous key search and display results."""
        print(f"\nSearching for node by rendezvous key: {rendezvous_key}")
        print(f"{'='*60}")
        
        try:
            result = await self.dht_node.search_by_rendezvous_key(rendezvous_key)
            
            if result.found:
                print(f"✅ NODE FOUND!")
                print(f"\nTarget Node Information:")
                print(f"  Node ID: {result.target_node.id.hex()}")
                print(f"  Address: {result.target_node.ip}:{result.target_node.port}")
                print(f"  RWP Port: {result.target_node.rwp_port}")
                if result.target_node.rendezvous_key:
                    print(f"  Rendezvous Key: {result.target_node.rendezvous_key}")
                
                print(f"\nSearch Statistics:")
                print(f"  Total Time: {result.search_time:.3f} seconds")
                print(f"  Hops: {result.hops}")
                print(f"  Nodes Queried: {result.nodes_queried}")
                
                if result.path:
                    print(f"\nSearch Path:")
                    for i, path_node_id in enumerate(result.path, 1):
                        print(f"    {i}. {path_node_id}")
            else:
                print(f"❌ NODE NOT FOUND")
                print(f"\nSearch Statistics:")
                print(f"  Total Time: {result.search_time:.3f} seconds")
                print(f"  Hops: {result.hops}")
                print(f"  Nodes Queried: {result.nodes_queried}")
                
                print(f"\nPossible reasons:")
                print(f"  • Rendezvous key not registered in DHT")
                print(f"  • Node is offline or unreachable")
                print(f"  • Rendezvous key has expired (epoch changed)")
            
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"❌ Search error: {e}")
            import traceback
            traceback.print_exc()

    def display_neighbors(self):
        """Display all neighbors sorted by distance."""
        if not self.dht_node or not self.dht_node.protocol:
            print("DHT node not initialized")
            return
        
        debug_info = self.dht_node.get_debug_info()
        neighbors = debug_info.get('all_neighbors', [])
        
        if not neighbors:
            print("No neighbors found in routing table")
            return
        
        print(f"\n{'='*80}")
        print(f"ALL NEIGHBORS ({len(neighbors)}) - Sorted by Distance")
        print(f"{'='*80}")
        print(f"{'Rank':<5} {'IP:Port':<22} {'RWP':<6} {'Distance':<20} {'Bucket':<7} {'Status'}")
        print(f"{'-'*80}")
        
        for i, neighbor in enumerate(neighbors[:50], 1):  # Show top 50
            status_flags = []
            if neighbor['is_stale']:
                status_flags.append('STALE')
            if neighbor['failed_pings'] > 0:
                status_flags.append(f'FAIL:{neighbor["failed_pings"]}')
            
            status = ','.join(status_flags) if status_flags else 'OK'
            
            print(f"{i:<5} {neighbor['ip']}:{neighbor['port']:<15} "
                f"{neighbor['rwp_port']:<6} {neighbor['distance']:<20} "
                f"{neighbor['bucket_index']:<7} {status}")
        
        if len(neighbors) > 50:
            print(f"... and {len(neighbors) - 50} more neighbors")
        
        print(f"{'='*80}\n")

    def display_routing_health(self):
        """Display routing health analysis."""
        if not self.dht_node or not self.dht_node.protocol:
            print("DHT node not initialized")
            return
            
        health_report = self.dht_node.protocol.router.analyze_routing_health()
        
        print(f"\n{'='*50}")
        print(f"ROUTING HEALTH ANALYSIS")
        print(f"{'='*50}")
        print(f"Overall Health: {health_report['overall_health']}")
        
        print(f"\nHealth Metrics:")
        for metric, value in health_report['metrics'].items():
            metric_name = metric.replace('_', ' ').title()
            if 'ratio' in metric:
                print(f"  {metric_name}: {value:.2%}")
            else:
                print(f"  {metric_name}: {value:.3f}")
        
        if health_report['issues']:
            print(f"\nIssues Identified:")
            for issue in health_report['issues']:
                print(f"  ⚠️  {issue}")
        
        if health_report['recommendations']:
            print(f"\nRecommendations:")
            for rec in health_report['recommendations']:
                print(f"  💡 {rec}")
        
        if not health_report['issues']:
            print(f"\n✅ No issues detected - routing table is healthy!")
        
        print(f"{'='*50}\n")

    def display_node_status(self):
        """Display current node status with key metrics."""
        if not self.dht_node:
            print("DHT node not initialized")
            return
            
        debug_info = self.dht_node.get_debug_info()
        
        print(f"\n{'='*60}")
        print(f"NODE STATUS")
        print(f"{'='*60}")
        
        # Basic node info
        node_info = debug_info['node_info']
        print(f"Node ID: {node_info['node_id']}")
        print(f"Address: {node_info['ip']}:{node_info['port']} (RWP: {node_info['rwp_port']})")
        print(f"Rendezvous Key: {node_info['rendezvous_key']}")
        
        # Epoch info
        epoch_info = debug_info['epoch_info']
        print(f"\nEpoch: {epoch_info['current_epoch']}")
        print(f"Storage Epochs: {epoch_info['storage_epochs']}")
        print(f"Retrieval Epochs: {epoch_info['retrieval_epochs']}")
        
        # Network status
        routing_info = debug_info.get('routing_info', {})
        print(f"\nNetwork Status:")
        print(f"  Total Neighbors: {debug_info.get('total_neighbors', 0)}")
        print(f"  Active Buckets: {routing_info.get('total_buckets', 0)}")
        print(f"  Lonely Buckets: {routing_info.get('lonely_buckets', 0)}")
        print(f"  Stale Nodes: {routing_info.get('stale_nodes', 0)}")
        print(f"  Failed Nodes: {routing_info.get('failed_nodes', 0)}")
        
        # Web-RWP status
        if self.web_rwp_server:
            print(f"\nWeb-RWP Server:")
            print(f"  Active Sessions: {len(self.web_rwp_server.sessions)}")
            print(f"  Server ID: {self.web_rwp_server.server_id}")
        
        print(f"{'='*60}\n")

    def display_comprehensive_debug(self):
        """Display comprehensive debug information."""
        if not self.dht_node:
            print("DHT node not initialized")
            return
        
        debug_info = self.dht_node.get_debug_info()
        
        print(f"\n{'='*80}")
        print(f"COMPREHENSIVE DEBUG INFORMATION")
        print(f"{'='*80}")
        
        # Use JSON for readable output
        import json
        
        # Create a simplified version for display
        display_info = {
            'node_info': debug_info['node_info'],
            'epoch_info': debug_info['epoch_info'],
            'routing_summary': debug_info.get('routing_info', {}),
            'rwp_info': debug_info['rwp_info'],
            'neighbor_count': debug_info.get('total_neighbors', 0),
            'closest_neighbors': debug_info.get('closest_neighbors', [])[:5]  # Top 5 only
        }
        
        print(json.dumps(display_info, indent=2, default=str))
        print(f"{'='*80}\n")

    async def ping_node_command(self, ip: str, port: int, rwp_port: int):
        """Ping a specific node and display results."""
        print(f"Pinging {ip}:{port} (RWP: {rwp_port})...")
        
        try:
            result = await self.dht_node.ping_node(ip, port, rwp_port)
            
            if result['success']:
                print(f"✅ Ping successful via {result['method'].upper()}")
                print(f"   Node ID: {result['node_id']}")
                if 'rendezvous_key' in result:
                    print(f"   Rendezvous Key: {result['rendezvous_key']}")
                    print(f"   Epoch: {result['epoch']}")
            else:
                print(f"❌ Ping failed")
                
        except Exception as e:
            print(f"❌ Ping error: {e}")

    def display_node_info(self):
        """Display comprehensive node information."""
        debug_info = self.dht_node.get_debug_info()
        
        print(f"\n" + "="*50)
        print(f"NODE INFORMATION")
        print(f"="*50)
        print(f"Node ID: {debug_info['node_info']['node_id']}")
        print(f"Long ID: {debug_info['node_info']['long_id']}")
        print(f"IP: {debug_info['node_info']['ip']}")
        print(f"DHT Port: {debug_info['node_info']['port']}")
        print(f"RWP Port: {debug_info['node_info']['rwp_port']}")
        print(f"Rendezvous Key: {debug_info['node_info']['rendezvous_key']}")
        print(f"\nEPOCH INFORMATION")
        print(f"Current Epoch: {debug_info['epoch_info']['current_epoch']}")
        print(f"Storage Epochs: {debug_info['epoch_info']['storage_epochs']}")
        print(f"Retrieval Epochs: {debug_info['epoch_info']['retrieval_epochs']}")
        print(f"\nROUTING TABLE")
        print(f"Total Buckets: {debug_info['routing_info']['total_buckets']}")
        print(f"Total Nodes: {debug_info['routing_info']['total_nodes']}")
        print(f"Lonely Buckets: {debug_info['routing_info']['lonely_buckets']}")
        
        # Show neighbors if any
        neighbors = self.dht_node.bootstrappable_neighbors()
        if neighbors:
            print(f"\nNEIGHBORS ({len(neighbors)})")
            for i, (ip, port, rwp_port) in enumerate(neighbors[:5]):
                print(f"  {i+1}. {ip}:{port} (RWP: {rwp_port})")
            if len(neighbors) > 5:
                print(f"  ... and {len(neighbors) - 5} more")
        else:
            print(f"\nNEIGHBORS: None (isolated node)")
        
        print(f"="*50)
    
    async def stop_server(self):
        """Stop all server components."""
        self.running = False
        
        if self.web_rwp_server:
            await self.web_rwp_server.stop()
            
        if self.dht_node:
            self.dht_node.stop()
        
        print(f"Server stopped.")

def signal_handler(signum, frame):
    """Handle shutdown signals."""
    print(f"\nReceived signal {signum}, shutting down...")
    sys.exit(0)

async def main():
    """Main entry point."""
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    server_manager = RRKDHTServerManager()
    
    try:
        await server_manager.start_server()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        log.error(f"Fatal error: {e}")
        traceback.print_exc()
    finally:
        await server_manager.stop_server()

if __name__ == "__main__":
    try:
        # Check if websockets is available
        import websockets
    except ImportError:
        print("Error: websockets library is required")
        print("Install with: pip install websockets")
        sys.exit(1)
    
    # Run the server
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        print(f"Failed to start server: {e}")
        traceback.print_exc()
        sys.exit(1)

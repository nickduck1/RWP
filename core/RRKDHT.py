"""
Production Rotating Rendezvous Kademlia DHT (RRKDHT) Implementation

A complete implementation of the Rotating Rendezvous Kademlia Distributed Hash Table
with RWP protocol support, epoch-based key rotation, and production-ready features.
"""

import asyncio
import hashlib
import heapq
import logging
import operator
import pickle
import random
import time
import json
import threading
import socket
import os
import base64
from abc import ABC, abstractmethod
from collections import Counter, OrderedDict
from itertools import chain, takewhile
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from enum import Enum
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

try:
    from rpcudp.protocol import RPCProtocol
except ImportError:
    raise ImportError("This library requires 'rpcudp'. Install with: pip install rpcudp")

log = logging.getLogger(__name__)
logging.getLogger("RRKDHT").setLevel(logging.DEBUG)

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

class Config:
    """Production configuration for RRKDHT."""
    EPOCH_DURATION = 300  # 5 minutes
    OVERLAP_DURATION = 300  # 5 minutes
    REPLICATION_FACTOR = 3
    HEARTBEAT_INTERVAL = 10
    FAILURE_TIMEOUT = 30
    DEFAULT_TTL = 86400  # 24 hours
    QUORUM_SIZE = 2
    ANTI_ENTROPY_INTERVAL = 600
    RWP_TIMEOUT = 10.0
    MAX_MESSAGE_SIZE = 65536
    
    # NEW: Search and routing limits
    MAX_NEIGHBORS_PER_NODE = 3
    SEARCH_MAX_HOPS = 10
    SEARCH_TIMEOUT = 30.0
    SEARCH_PARALLELISM = 3
    
    # NEW: Responsible node tracking
    MIN_RESPONSIBLE_NODES = 1  # Minimum nodes that must know about us
    RESPONSIBLE_CHECK_INTERVAL = 180  # Check every 3 minutes

    MAX_REJOIN_ATTEMPTS = 5  # Try 5 times before regenerating identity
    MAX_IDENTITY_REGENERATIONS = 3  # Maximum identity regenerations before giving up
    REJOIN_VERIFICATION_WAIT = 2
# ============================================================================
# CRYPTOGRAPHIC UTILITIES
# ============================================================================

def create_ed25519_key_pair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 key pair for signing."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_peer_id(public_key: ed25519.Ed25519PublicKey) -> str:
    """Generate a peer ID from an Ed25519 public key."""
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(public_bytes).hexdigest()

def digest(string):
    """Create SHA1 digest of a string."""
    if not isinstance(string, bytes):
        string = str(string).encode("utf8")
    return hashlib.sha1(string).digest()

# ============================================================================
# EPOCH MANAGEMENT
# ============================================================================

class EpochManager:
    """Manages epoch-based key rotation for the RRDHT system."""
    
    def __init__(self, epoch_duration: int = Config.EPOCH_DURATION,
                 overlap_duration: int = Config.OVERLAP_DURATION):
        self.epoch_duration = epoch_duration
        self.overlap_duration = overlap_duration
        self.epoch_start = 1704067200  # Fixed start time (Unix timestamp)
    
    def get_current_epoch(self) -> int:
        """Get the current epoch number."""
        return int((time.time() - self.epoch_start) // self.epoch_duration)
    
    def get_storage_epochs(self) -> List[int]:
        """Get epochs where data should be stored."""
        current = self.get_current_epoch()
        epochs = [current]
        return epochs
    
    def get_retrieval_epochs(self) -> List[int]:
        """Get epochs where data should be retrieved from."""
        current = self.get_current_epoch()
        current_time = time.time()
        epoch_start = self.epoch_start + (current * self.epoch_duration)
        time_in_epoch = current_time - epoch_start
        
        epochs = [current]
        if time_in_epoch <= self.overlap_duration:
            epochs.append(current - 1)
        
        return epochs

# ============================================================================
# RWP PROTOCOL COMPONENTS
# ============================================================================

class MessageType(Enum):
    """RWP protocol message types."""
    PING = "ping"
    PONG = "pong"
    NODE_INFO = "node_info"
    NODE_INFO_RESPONSE = "node_info_response"
    FIND_NODE = "find_node"
    HEARTBEAT = "heartbeat"
    DHT_GET = "dht_get"  # Add this
    DHT_SET = "dht_set"  # Add this
    
@dataclass
class Message:
    """RWP protocol message structure."""
    type: MessageType
    sender_id: str
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    message_id: str = field(default_factory=lambda: os.urandom(16).hex())

@dataclass
class NodeInfo:
    """Information about a node in the network."""
    node_id: str
    ip: str
    port: int
    rwp_port: int
    rendezvous_key: str
    signing_public_key: str
    exchange_public_key: str
    epoch: int
    timestamp: float
    
    def is_expired(self, max_age: int = 3600) -> bool:
        """Check if node info is expired."""
        return time.time() - self.timestamp > max_age

# ============================================================================
# SECURE MESSAGING
# ============================================================================

class SecureMessaging:
    """Handles encryption and decryption for RWP protocol messages."""
    
    def __init__(self, signing_private_key: ed25519.Ed25519PrivateKey, 
                 signing_public_key: ed25519.Ed25519PublicKey):
        self.signing_private_key = signing_private_key
        self.signing_public_key = signing_public_key
        
        # Generate X25519 keys for key exchange
        self.exchange_private_key = x25519.X25519PrivateKey.generate()
        self.exchange_public_key = self.exchange_private_key.public_key()
    
    def encrypt_message(self, message: Dict, recipient_exchange_public_key: x25519.X25519PublicKey) -> bytes:
        """Encrypt a message using ChaCha20Poly1305 with X25519 key exchange."""
        try:
            # Perform key exchange
            shared_secret = self.exchange_private_key.exchange(recipient_exchange_public_key)
            
            # Derive encryption key
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'rrdht-encryption',
                backend=default_backend()
            ).derive(shared_secret)
            
            # Encrypt message
            chacha = ChaCha20Poly1305(derived_key)
            nonce = os.urandom(12)  # ChaCha20Poly1305 nonce
            
            message_bytes = json.dumps(message, default=self._json_serializer).encode()
            ciphertext = chacha.encrypt(nonce, message_bytes, None)
            
            return nonce + ciphertext
            
        except Exception as e:
            log.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_message(self, encrypted_data: bytes, sender_exchange_public_key: x25519.X25519PublicKey) -> Dict:
        """Decrypt a message using ChaCha20Poly1305 with X25519 key exchange."""
        try:
            # Perform key exchange
            shared_secret = self.exchange_private_key.exchange(sender_exchange_public_key)
            
            # Derive decryption key
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'rrdht-encryption',
                backend=default_backend()
            ).derive(shared_secret)
            
            # Extract nonce and ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Decrypt message
            chacha = ChaCha20Poly1305(derived_key)
            decrypted = chacha.decrypt(nonce, ciphertext, None)
            
            return json.loads(decrypted.decode())
            
        except Exception as e:
            log.error(f"Decryption failed: {e}")
            raise
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for complex objects."""
        if isinstance(obj, Enum):
            return obj.value
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

# ============================================================================
# NODE CLASSES
# ============================================================================

class Node:
    """Enhanced node with rendezvous key support."""

    def __init__(self, node_id, ip=None, port=None, rwp_port=None, rendezvous_key=None):
        self.id = node_id
        self.ip = ip
        self.port = port
        self.rwp_port = rwp_port
        self.rendezvous_key = rendezvous_key
        self.long_id = int(node_id.hex(), 16)
        self.last_seen = time.time()
        self.failed_pings = 0
        # NEW: Track when this node last confirmed we're in their routing table
        self.last_confirmed_as_neighbor = time.time()

    def same_home_as(self, node):
        return self.ip == node.ip and self.port == node.port

    def distance_to(self, node):
        """Get the distance between this node and another."""
        return self.long_id ^ node.long_id

    def get_rwp_url(self, content=""):
        """Get the RWP URL for this node."""
        if self.rendezvous_key:
            return f"rwp://{self.rendezvous_key}/{content}"
        return None

    def touch(self):
        """Update last seen time and reset failed pings."""
        self.last_seen = time.time()
        self.failed_pings = 0
    
    def confirm_as_neighbor(self):
        """Confirm this node has us in their routing table."""
        self.last_confirmed_as_neighbor = time.time()

    def is_stale(self, timeout=Config.FAILURE_TIMEOUT):
        """Check if node hasn't been seen within timeout period."""
        return time.time() - self.last_seen > timeout

    def __iter__(self):
        return iter([self.id, self.ip, self.port, self.rwp_port])

    def __repr__(self):
        return repr([self.long_id, self.ip, self.port, self.rwp_port, self.rendezvous_key])

    def __str__(self):
        return f"{self.ip}:{self.port}(rwp:{self.rwp_port})"
    
    def __eq__(self, other):
        if isinstance(other, Node):
            return self.id == other.id
        return False

    def __hash__(self):
        return hash(self.id)

class NodeHeap:
    """A heap of nodes ordered by distance to a given node."""

    def __init__(self, node, maxsize):
        self.node = node
        self.heap = []
        self.contacted = set()
        self.maxsize = maxsize

    def remove(self, peers):
        """Remove a list of peer ids from this heap."""
        peers = set(peers)
        if not peers:
            return
        nheap = []
        for distance, node in self.heap:
            if node.id not in peers:
                heapq.heappush(nheap, (distance, node))
        self.heap = nheap

    def get_node(self, node_id):
        for _, node in self.heap:
            if node.id == node_id:
                return node
        return None

    def have_contacted_all(self):
        return len(self.get_uncontacted()) == 0

    def get_ids(self):
        return [n.id for n in self]

    def mark_contacted(self, node):
        self.contacted.add(node.id)

    def popleft(self):
        return heapq.heappop(self.heap)[1] if self else None

    def push(self, nodes):
        """Push nodes onto heap, preventing duplicates."""
        if not isinstance(nodes, list):
            nodes = [nodes]

        for node in nodes:
            if node not in self:
                distance = self.node.distance_to(node)
                heapq.heappush(self.heap, (distance, node))

    def __len__(self):
        return min(len(self.heap), self.maxsize)

    def __iter__(self):
        nodes = heapq.nsmallest(self.maxsize, self.heap)
        return iter(map(operator.itemgetter(1), nodes))

    def __contains__(self, node):
        return any(node.id == other.id for _, other in self.heap)


    def get_uncontacted(self):
        return [n for n in self if n.id not in self.contacted]

# ============================================================================
# SEARCH CLASSES
# ============================================================================

@dataclass
class SearchResult:
    """Result of a node search operation."""
    found: bool
    target_node: Optional['Node']  # Use string annotation to avoid forward reference
    hops: int
    path: List[str]  # List of node IDs traversed
    search_time: float
    nodes_queried: int

class NodeSearch:
    """Handles iterative node search with proper hop limiting."""
    
    def __init__(self, protocol, target_node_id: bytes, max_hops: int = Config.SEARCH_MAX_HOPS,
                timeout: float = Config.SEARCH_TIMEOUT, alpha: int = Config.SEARCH_PARALLELISM):
        """Initialize NodeSearch with proper setup."""
        self.protocol = protocol
        self.target_node_id = target_node_id
        self.target_node = Node(target_node_id)
        self.max_hops = max_hops
        self.timeout = timeout
        self.alpha = alpha
        
        self.queried_nodes: Set[bytes] = set()
        self.path: List[str] = []
        self.start_time = time.time()
        self.nodes_queried = 0
    
    async def search(self) -> SearchResult:
        """
        Perform iterative search with improved convergence detection.
        """
        log.info(f"Starting iterative search for node {self.target_node_id.hex()}")

        # Disable routing-table learning during search
        old_flag = self.protocol.learning_enabled
        self.protocol.learning_enabled = False

        try:
            # Start with our closest known neighbors to target
            current_closest = self.protocol.router.find_neighbors(
                self.target_node,
                k=self.alpha
            )

            if not current_closest:
                log.warning("No neighbors available to start search")
                return SearchResult(
                    found=False, target_node=None, hops=0,
                    path=self.path, search_time=time.time() - self.start_time,
                    nodes_queried=0
                )

            # Check if we already know the target
            for node in current_closest:
                if node.id == self.target_node_id:
                    log.info("Target node found in local routing table!")
                    self.path.append(self.protocol.source_node.id.hex())
                    return SearchResult(
                        found=True, target_node=node, hops=0,
                        path=self.path, search_time=time.time() - self.start_time,
                        nodes_queried=0
                    )

            # Track the closest distance we've seen
            best_distance = min(self.target_node.distance_to(n) for n in current_closest)
            log.debug(f"Starting search with best distance: {best_distance}")

            # Iterative search
            for hop in range(self.max_hops):
                if time.time() - self.start_time > self.timeout:
                    log.warning(f"Search timed out after {hop} hops")
                    break

                unqueried = [n for n in current_closest if n.id not in self.queried_nodes]
                if not unqueried:
                    log.info(f"No more unqueried nodes after {hop} hops")
                    break

                nodes_to_query = unqueried[:self.alpha]
                log.info(f"Hop {hop + 1}: Querying {len(nodes_to_query)} nodes "
                        f"(best distance so far: {best_distance})")

                query_tasks = []
                for node in nodes_to_query:
                    self.queried_nodes.add(node.id)
                    self.path.append(node.id.hex())
                    self.nodes_queried += 1
                    query_tasks.append(self._query_node(node))

                results = await asyncio.gather(*query_tasks, return_exceptions=True)

                new_neighbors = []
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        log.debug(f"Query to {nodes_to_query[i].ip}:{nodes_to_query[i].port} "
                                f"failed: {result}")
                        continue

                    if result['found']:
                        log.info(f"Target node found after {hop + 1} hops!")
                        return SearchResult(
                            found=True, target_node=result['node'],
                            hops=hop + 1, path=self.path,
                            search_time=time.time() - self.start_time,
                            nodes_queried=self.nodes_queried
                        )

                    if result['neighbors']:
                        new_neighbors.extend(result['neighbors'])

                if not new_neighbors:
                    log.info(f"No new neighbors discovered after {hop + 1} hops")
                    break

                # Merge and deduplicate
                all_candidates = current_closest + new_neighbors
                all_candidates = [n for n in all_candidates if n.id not in self.queried_nodes]

                # Remove duplicates by ID
                unique_candidates = {node.id: node for node in all_candidates}
                
                # Sort by distance to target and keep closest ones
                current_closest = sorted(
                    unique_candidates.values(),
                    key=lambda n: self.target_node.distance_to(n)
                )[:self.alpha * 2]

                # Check if we're making progress
                if current_closest:
                    new_best = self.target_node.distance_to(current_closest[0])
                    if new_best < best_distance:
                        log.debug(f"Progress: distance improved from {best_distance} to {new_best}")
                        best_distance = new_best
                    elif new_best == best_distance:
                        log.debug(f"No improvement in distance (stuck at {best_distance})")
                        # If we've queried all candidates at this distance, we're done
                        closest_unqueried = [n for n in current_closest 
                                            if n.id not in self.queried_nodes]
                        if not closest_unqueried:
                            log.info("Exhausted all nodes at closest distance - search complete")
                            break
                else:
                    break

            # Search exhausted without finding target
            log.info(f"Search completed without finding target after {len(self.path)} queries")
            return SearchResult(
                found=False, target_node=None,
                hops=len(self.path), path=self.path,
                search_time=time.time() - self.start_time,
                nodes_queried=self.nodes_queried
            )

        finally:
            # Restore normal learning behavior
            self.protocol.learning_enabled = old_flag
    
    async def _query_node(self, node: 'Node') -> Dict:
        """
        Query a single node for the target with improved response validation.
        """
        try:
            log.debug(f"Querying {node.ip}:{node.port} for target {self.target_node_id.hex()[:16]}...")
            
            # Use find_node RPC to ask if they know the target
            result = await self.protocol.call_find_node(node, self.target_node)
            
            if not result[0]:
                log.debug(f"Query to {node.ip}:{node.port} failed (no response)")
                return {'found': False, 'neighbors': [], 'node': None}
            
            neighbors = []
            found_target = False
            target_node = None
            
            # Parse response - check if target is in the returned nodes
            if result[1]:
                log.debug(f"Got {len(result[1])} nodes from {node.ip}:{node.port}")
                
                for node_tuple in result[1]:
                    if len(node_tuple) >= 3:
                        returned_id, ip, port = node_tuple[:3]
                        rwp_port = node_tuple[3] if len(node_tuple) > 3 else None
                        
                        returned_node = Node(returned_id, ip, port, rwp_port)
                        
                        # Calculate distance to target for logging
                        distance_to_target = self.target_node.distance_to(returned_node)
                        
                        # Check if this is our target (EXACT match)
                        if returned_id == self.target_node_id:
                            found_target = True
                            target_node = returned_node
                            log.info(f"FOUND TARGET at {ip}:{port}!")
                        else:
                            neighbors.append(returned_node)
                            log.debug(f"  Neighbor: {returned_id.hex()[:16]}... at {ip}:{port} "
                                    f"(distance to target: {distance_to_target})")
            else:
                log.debug(f"Empty response from {node.ip}:{node.port}")
            
            return {
                'found': found_target,
                'neighbors': neighbors,
                'node': target_node
            }
            
        except Exception as e:
            log.error(f"Error querying node {node.ip}:{node.port}: {type(e).__name__}: {e}")
            return {'found': False, 'neighbors': [], 'node': None}

# ============================================================================
# RWP PROTOCOL HANDLER
# ============================================================================

class RWPProtocolHandler:
    """Handles RWP protocol communication."""
    
    def __init__(self, node_id: str, messaging: SecureMessaging, epoch_manager: EpochManager):
        self.node_id = node_id
        self.messaging = messaging
        self.epoch_manager = epoch_manager
        self.rendezvous_key = self._generate_rendezvous_key()
        self.node_info_cache: Dict[str, NodeInfo] = {}
        self.cache_lock = threading.RLock()
        self.rwp_server_socket = None
        self.rwp_server_thread = None
        self.running = False
    
    def _generate_rendezvous_key(self) -> str:
        """Generate a rendezvous key for the current epoch."""
        current_epoch = self.epoch_manager.get_current_epoch()
        key_data = f"{self.node_id}:{current_epoch}:rwp"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]
    
    def start_rwp_server(self, port: int):
        """Start the RWP server on the specified port."""
        if self.running:
            return
            
        self.running = True
        self.rwp_server_thread = threading.Thread(
            target=self._run_rwp_server, 
            args=(port,), 
            daemon=True
        )
        self.rwp_server_thread.start()
        log.info(f"Started RWP server on port {port}")
    
    def stop_rwp_server(self):
        """Stop the RWP server."""
        self.running = False
        if self.rwp_server_socket:
            try:
                self.rwp_server_socket.close()
            except:
                pass
        if self.rwp_server_thread:
            self.rwp_server_thread.join(timeout=5)
    
    def _run_rwp_server(self, port: int):
        """Run the RWP server."""
        try:
            self.rwp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.rwp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.rwp_server_socket.bind(('0.0.0.0', port))
            self.rwp_server_socket.listen(10)
            
            while self.running:
                try:
                    client_socket, address = self.rwp_server_socket.accept()
                    threading.Thread(
                        target=self._handle_rwp_client, 
                        args=(client_socket, address),
                        daemon=True
                    ).start()
                except OSError:
                    break
                    
        except Exception as e:
            log.error(f"RWP server error: {e}")
        finally:
            if self.rwp_server_socket:
                self.rwp_server_socket.close()
    
    def _handle_rwp_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle RWP client connection."""
        try:
            # Receive request
            request_data = b""
            client_socket.settimeout(Config.RWP_TIMEOUT)
            
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                request_data += data
                if b"\r\n\r\n" in request_data:
                    break
                if len(request_data) > Config.MAX_MESSAGE_SIZE:
                    self._send_rwp_error(client_socket, 413, "Request too large")
                    return
            
            if not request_data:
                return
            
            # Parse request
            request_str = request_data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            
            if not lines:
                return
            
            # Parse request line
            request_line = lines[0]
            if not request_line.startswith('GET') and not request_line.startswith('POST'):
                self._send_rwp_error(client_socket, 400, "Bad Request")
                return
            
            parts = request_line.split()
            if len(parts) < 3:
                self._send_rwp_error(client_socket, 400, "Bad Request")
                return
            
            method, path, protocol = parts[0], parts[1], parts[2]
            
            if protocol != "RWP/1.0":
                self._send_rwp_error(client_socket, 505, "Version Not Supported")
                return
            
            # Handle different endpoints
            if path == "/node-info":
                self._handle_node_info_request(client_socket)
            elif path.startswith(f"/{self.rendezvous_key}/"):
                self._handle_rendezvous_request(client_socket, request_str, method, path)
            else:
                self._send_rwp_error(client_socket, 404, "Not Found")
                
        except Exception as e:
            log.error(f"Error handling RWP client: {e}")
            try:
                self._send_rwp_error(client_socket, 500, "Internal Server Error")
            except:
                pass
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _handle_node_info_request(self, client_socket: socket.socket):
        """Handle node info request."""
        try:
            signing_public_key_pem = self.messaging.signing_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            exchange_public_key_pem = self.messaging.exchange_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            info = {
                'node_id': self.node_id,
                'rendezvous_key': self.rendezvous_key,
                'signing_public_key': signing_public_key_pem,
                'exchange_public_key': exchange_public_key_pem,
                'epoch': self.epoch_manager.get_current_epoch(),
                'timestamp': time.time()
            }
            
            response = json.dumps(info)
            self._send_rwp_response(client_socket, 200, response, 'application/json')
            
        except Exception as e:
            log.error(f"Error handling node info request: {e}")
            self._send_rwp_error(client_socket, 500, "Internal Server Error")
    
    def _handle_rendezvous_request(self, client_socket: socket.socket, 
                                 request_str: str, method: str, path: str):
        """Handle encrypted rendezvous request with proper response format."""
        try:
            # Extract request body for POST requests
            if method == "POST" and "\r\n\r\n" in request_str:
                headers, body = request_str.split("\r\n\r\n", 1)
                request_data = json.loads(body)
                
                # Decrypt message
                encrypted_data = base64.b64decode(request_data['encrypted_data'])
                sender_exchange_key = serialization.load_pem_public_key(
                    request_data['sender_exchange_key'].encode(),
                    backend=default_backend()
                )
                
                decrypted_message = self.messaging.decrypt_message(
                    encrypted_data, sender_exchange_key
                )
                
                # Handle different message types
                message_type = MessageType(decrypted_message['type'])
                response_data = self._handle_dht_message(message_type, decrypted_message)
                
                # Encrypt response
                encrypted_response = self.messaging.encrypt_message(
                    response_data, sender_exchange_key
                )
                
                # FIXED: Prepare response body without top-level success field
                response_body = {
                    'encrypted_data': base64.b64encode(encrypted_response).decode(),
                    'message_id': decrypted_message['message_id'],
                    'timestamp': time.time()
                }
                
                self._send_rwp_response(
                    client_socket, 200, 
                    json.dumps(response_body), 
                    'application/json'
                )
                log.debug(f"Successfully handled RWP request: {message_type.value}")
                
            else:
                self._send_rwp_error(client_socket, 400, "Bad Request")
                
        except json.JSONDecodeError as e:
            log.error(f"JSON decode error in rendezvous request: {e}")
            self._send_rwp_error(client_socket, 400, "Invalid JSON")
        except Exception as e:
            log.error(f"Error handling rendezvous request: {e}")
            self._send_rwp_error(client_socket, 500, "Internal Server Error")

    def _send_rwp_response(self, client_socket: socket.socket, 
                          status_code: int, body: str, content_type: str = 'text/plain'):
        """Send RWP response."""
        status_text = {
            200: "OK",
            400: "Bad Request",
            404: "Not Found",
            413: "Request Too Large",
            500: "Internal Server Error",
            501: "Not Implemented",
            505: "Version Not Supported"
        }.get(status_code, "Unknown")
        
        response = f"RWP/1.0 {status_code} {status_text}\r\n"
        response += f"Content-Type: {content_type}\r\n"
        response += f"Content-Length: {len(body.encode())}\r\n"
        response += f"Server: RRKDHT/1.0\r\n"
        response += "\r\n"
        response += body
        
        try:
            client_socket.sendall(response.encode())
        except:
            pass
    
    def _send_rwp_error(self, client_socket: socket.socket, status_code: int, message: str):
        """Send RWP error response."""
        self._send_rwp_response(client_socket, status_code, message)
    
    def get_node_info(self, ip: str, rwp_port: int) -> Optional[NodeInfo]:
        """Enhanced get_node_info with better error handling and caching."""
        cache_key = f"{ip}:{rwp_port}"
        
        with self.cache_lock:
            if cache_key in self.node_info_cache:
                cached_info = self.node_info_cache[cache_key]
                # Use shorter expiration for more frequent refresh (30 seconds instead of 3600)
                if time.time() - cached_info.timestamp < 30:
                    return cached_info
                else:
                    del self.node_info_cache[cache_key]
        
        # Try multiple times with exponential backoff
        for attempt in range(2):  # Reduced from 3 to 2 attempts
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)  # Reduced from Config.RWP_TIMEOUT
                
                # Connect with timeout
                sock.connect((ip, rwp_port))
                
                request = "GET /node-info RWP/1.0\r\n"
                request += f"Host: {ip}\r\n"
                request += "Connection: close\r\n"
                request += "\r\n"
                
                sock.sendall(request.encode())
                
                # Receive response with proper buffering
                response_data = b""
                sock.settimeout(2.0)  # Shorter timeout for reading
                
                while True:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            break
                        response_data += data
                        if len(response_data) > Config.MAX_MESSAGE_SIZE:
                            raise ValueError("Response too large")
                        # Check if we have complete response
                        if b"\r\n\r\n" in response_data:
                            break
                    except socket.timeout:
                        if response_data:  # We got some data
                            break
                        else:
                            raise
                
                sock.close()
                
                if not response_data:
                    raise ConnectionError("No response received")
                
                # Parse response
                response_str = response_data.decode('utf-8', errors='ignore')
                if "RWP/1.0 200 OK" in response_str and "\r\n\r\n" in response_str:
                    try:
                        _, body = response_str.split("\r\n\r\n", 1)
                        node_data = json.loads(body)
                        
                        node_info = NodeInfo(
                            node_id=node_data['node_id'],
                            ip=ip,
                            port=0,
                            rwp_port=rwp_port,
                            rendezvous_key=node_data['rendezvous_key'],
                            signing_public_key=node_data['signing_public_key'],
                            exchange_public_key=node_data['exchange_public_key'],
                            epoch=node_data['epoch'],
                            timestamp=time.time()
                        )
                        
                        with self.cache_lock:
                            self.node_info_cache[cache_key] = node_info
                        
                        log.debug(f"Successfully got node info from {ip}:{rwp_port}")
                        return node_info
                        
                    except (json.JSONDecodeError, KeyError) as e:
                        log.error(f"Failed to parse node info response: {e}")
                        raise
                else:
                    log.warning(f"Invalid response from {ip}:{rwp_port}")
                    raise ConnectionError("Invalid response")
                    
            except (socket.timeout, socket.error, OSError, ConnectionError, ValueError) as e:
                if attempt < 1:  # Don't sleep on last attempt
                    time.sleep(0.2 * (attempt + 1))  # Shorter backoff
                    continue
                log.debug(f"Failed to get node info from {ip}:{rwp_port}: {e}")
            except Exception as e:
                log.error(f"Unexpected error getting node info from {ip}:{rwp_port}: {e}")
                break
            finally:
                try:
                    if 'sock' in locals():
                        sock.close()
                except:
                    pass
        
        return None
    
    def send_encrypted_message(self, node_info: NodeInfo, message_type: MessageType, 
                             payload: Dict) -> Optional[Dict]:
        """Fixed send_encrypted_message with proper response validation."""
        for attempt in range(2):  # Try twice
            try:
                # Load recipient's exchange public key
                exchange_key = serialization.load_pem_public_key(
                    node_info.exchange_public_key.encode(),
                    backend=default_backend()
                )
                
                # Create message
                message = {
                    'type': message_type.value,
                    'sender_id': self.node_id,
                    'payload': payload,
                    'timestamp': time.time(),
                    'message_id': os.urandom(16).hex()
                }
                
                # Encrypt message
                encrypted_data = self.messaging.encrypt_message(message, exchange_key)
                
                # Prepare request
                exchange_public_key_pem = self.messaging.exchange_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                
                request_data = {
                    'encrypted_data': base64.b64encode(encrypted_data).decode(),
                    'sender_exchange_key': exchange_public_key_pem,
                    'message_id': message['message_id'],
                    'timestamp': message['timestamp']
                }
                
                # Send request
                result = self._send_rwp_request(
                    node_info.ip, 
                    node_info.rwp_port,
                    node_info.rendezvous_key,
                    request_data,
                    message_type
                )
                
                # FIXED: Check if we got a response with encrypted_data instead of top-level success
                if result and 'encrypted_data' in result:
                    # Decrypt the response
                    try:
                        encrypted_response = base64.b64decode(result['encrypted_data'])
                        decrypted_response = self.messaging.decrypt_message(
                            encrypted_response, exchange_key
                        )
                        log.debug(f"Successfully sent and decrypted message response from {node_info.ip}:{node_info.rwp_port}")
                        return decrypted_response
                    except Exception as e:
                        log.error(f"Failed to decrypt response: {e}")
                        if attempt < 1:
                            time.sleep(0.5)
                            continue
                        return None
                else:
                    log.warning(f"No encrypted_data in response from {node_info.ip}:{node_info.rwp_port}: {result}")
                    if attempt < 1:
                        time.sleep(0.5)
                        continue
                    
            except Exception as e:
                log.error(f"Attempt {attempt + 1} failed to send encrypted message to {node_info.ip}:{node_info.rwp_port}: {e}")
                if attempt < 1:
                    time.sleep(0.5)
                    continue
        
        log.error(f"All attempts failed to send encrypted message to {node_info.ip}:{node_info.rwp_port}")
        return None
    
    def _send_rwp_request(self, host: str, port: int, rendezvous_key: str,
                         request_data: Dict, message_type: MessageType) -> Optional[Dict]:
        """Send RWP request."""
        try:
            request_body = json.dumps(request_data)
            
            request = f"POST /{rendezvous_key}/message RWP/1.0\r\n"
            request += f"Host: {host}\r\n"
            request += f"Content-Type: application/json\r\n"
            request += f"Content-Length: {len(request_body.encode())}\r\n"
            request += f"RWP-Message-Type: {message_type.value}\r\n"
            request += f"Connection: close\r\n"
            request += "\r\n"
            request += request_body
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(Config.RWP_TIMEOUT)
            sock.connect((host, port))
            sock.sendall(request.encode())
            
            # Receive response
            response_data = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response_data += data
            
            sock.close()
            
            # Parse response
            response_str = response_data.decode('utf-8', errors='ignore')
            if "RWP/1.0 200 OK" in response_str and "\r\n\r\n" in response_str:
                _, body = response_str.split("\r\n\r\n", 1)
                return json.loads(body)
            
            return None
            
        except Exception as e:
            log.error(f"Error sending RWP request: {e}")
            return None

# ============================================================================
# ENHANCED PROTOCOL CLASS
# ============================================================================

class RRKDHTProtocol(RPCProtocol):
    """Enhanced Kademlia protocol with RWP support and key rotation."""
    
    def __init__(self, source_node, ksize, epoch_manager, rwp_handler):
        RPCProtocol.__init__(self)
        self.router = RoutingTable(self, ksize, source_node)
        self.source_node = source_node
        self.epoch_manager = epoch_manager
        self.rwp_handler = rwp_handler
        self.ksize = ksize
        self.learning_enabled = True
        self.server_ref = None

    def get_refresh_ids(self):
        """Get ids to search for to keep old buckets up to date."""
        ids = []
        for bucket in self.router.lonely_buckets():
            rid = random.randint(*bucket.range).to_bytes(20, byteorder="big")
            ids.append(rid)
        return ids

    def rpc_stun(self, sender):
        return sender

    def rpc_ping(self, sender, nodeid, rwp_port=None):
        """Enhanced ping that tracks who contacts us."""
        log.debug(f"Received ping from {sender} with nodeid {nodeid.hex()} and rwp_port {rwp_port}")
        source = Node(nodeid, sender[0], sender[1], rwp_port)
        
        # Track this node as a possible responsible (they know about us since they pinged us)
        self._track_possible_responsible(source)
        
        self.welcome_if_new(source)
        log.debug(f"Sending ping response: node_id={self.source_node.id.hex()}")
        return self.source_node.id

    def _track_possible_responsible(self, node):
        """Track node as possible responsible since they contacted us."""
        # Access the parent RRKDHT instance through the router
        if hasattr(self.router, 'protocol') and hasattr(self.router.protocol, 'server_ref'):
            server = self.router.protocol.server_ref
            if server and hasattr(server, 'possible_responsibles'):
                server.possible_responsibles[node.id] = {
                    'node': node,
                    'last_contact': time.time(),
                    'verified': False
                }
                log.debug(f"Tracked possible responsible: {node.ip}:{node.port}")

    def rpc_find_node(self, sender, nodeid, key, rwp_port=None):
        """Enhanced find_node that returns neighbors closest to the TARGET key."""
        log.debug(f"Received find_node from {sender} with nodeid {nodeid.hex()}, "
                f"searching for target key {key.hex()}, rwp_port {rwp_port}")
        
        source = Node(nodeid, sender[0], sender[1], rwp_port)
        self.welcome_if_new(source)
        
        # Create a node representing the TARGET being searched for
        target_node = Node(key)
        
        # Get neighbors closest to target, excluding source
        neighbors = self.router.find_neighbors(target_node, exclude=source)
        
        # Include self in the candidates (standard Kademlia behavior)
        candidates = neighbors + [self.source_node]
        
        # Exclude source if somehow included
        candidates = [n for n in candidates if n.id != source.id]
        
        # Sort by distance to target and take k closest
        candidates.sort(key=lambda n: target_node.distance_to(n))
        closest = candidates[:self.ksize]
        
        log.debug(f"find_node returning {len(closest)} neighbors closest to TARGET {key.hex()[:16]}...")
        
        # Log the distances to help debug
        if closest:
            log.debug(f"Closest neighbor distance to target: {target_node.distance_to(closest[0])}")
            log.debug(f"My distance to target: {self.source_node.distance_to(target_node)}")
        
        return [
            [n.id if isinstance(n.id, (bytes, bytearray)) else n.id.to_bytes(20, "big"),
            n.ip,
            n.port,
            getattr(n, "rwp_port", None)]
            for n in closest
        ]

    def rpc_verify_neighbor(self, sender, nodeid, target_id, rwp_port=None):
        """
        Verify if we have target_id in our routing table.
        Returns True if we know about target_id, False otherwise.
        """
        log.debug(f"Received verify_neighbor from {sender} asking if we know {target_id.hex()}")
        source = Node(nodeid, sender[0], sender[1], rwp_port)
        self.welcome_if_new(source)
        
        # Check if we have target_id in our routing table
        for bucket in self.router.buckets:
            if bucket[target_id] is not None:
                log.debug(f"Confirmed: We have {target_id.hex()} in our routing table")
                return True
        
        log.debug(f"Not found: {target_id.hex()} is not in our routing table")
        return False

    def _get_epoch_key(self, key, epoch):
        """Generate epoch-specific key."""
        epoch_data = f"{key.hex()}:epoch:{epoch}"
        return digest(epoch_data)

    async def call_find_node(self, node_to_ask, node_to_find):
        """Enhanced find_node call with proper timeout cleanup."""
        log.debug(f"Calling find_node on {node_to_ask.ip}:{node_to_ask.port} (RWP: {node_to_ask.rwp_port}) for key {node_to_find.id.hex()}")
        
        # Try UDP first with timeout and retry logic
        udp_success = False
        result = None
        
        try:
            address = (node_to_ask.ip, node_to_ask.port)
            log.debug(f"Attempting UDP find_node to {address}")
            try:
                result = await asyncio.wait_for(
                    self.find_node(address, self.source_node.id, node_to_find.id, self.source_node.rwp_port),
                    timeout=15.0
                )
            except asyncio.TimeoutError:
                log.warning(f"call_find_node timed out to {address}")
                # CLEANUP: prevent rpcudp._timeout from touching a cancelled future
                for mid, (future, timeout_handle) in list(self._outstanding.items()):
                    if future.done() or future.cancelled():
                        timeout_handle.cancel()
                        del self._outstanding[mid]
                return (False, None)

            # Enhanced result validation and logging
            if result:
                log.debug(f"UDP find_node raw result: {result}")
                if result[0]:
                    udp_success = True
                    log.debug(f"UDP find_node successful with {len(result[1]) if result[1] else 0} nodes")
                else:
                    log.warning(f"UDP find_node returned failure response: success={result[0]}, data={result[1]}")
            else:
                log.warning(f"UDP find_node returned None/empty result")
                
        except Exception as e:
            log.error(f"Unexpected error in UDP find_node to {node_to_ask.ip}:{node_to_ask.port}: {type(e).__name__}: {e}")
            # Clean up on any exception
            for mid, (future, timeout_handle) in list(self._outstanding.items()):
                if future.done() or future.cancelled():
                    timeout_handle.cancel()
                    del self._outstanding[mid]
        
        # If UDP failed, try RWP fallback
        if not udp_success and node_to_ask.rwp_port:
            log.info(f"UDP failed, attempting RWP fallback to {node_to_ask.ip}:{node_to_ask.rwp_port}")
            try:
                node_info = self.rwp_handler.get_node_info(node_to_ask.ip, node_to_ask.rwp_port)
                if node_info:
                    response = self.rwp_handler.send_encrypted_message(
                        node_info,
                        MessageType.FIND_NODE,
                        {'key': node_to_find.id.hex()}
                    )
                    if response and response.get('payload', {}).get('success'):
                        nodes = []
                        for node_data in response['payload'].get('nodes', []):
                            node = Node(
                                bytes.fromhex(node_data['id']),
                                node_data['ip'],
                                node_data['port'],
                                node_data.get('rwp_port'),
                                node_data.get('rendezvous_key')
                            )
                            nodes.append(node)
                            
                            # Add discovered nodes to routing table
                            self.welcome_if_new(node)
                            
                        log.debug(f"RWP find_node successful, got {len(nodes)} nodes")
                        return (True, list(map(tuple, nodes)))
                    else:
                        log.warning(f"RWP find_node unsuccessful response: {response}")
            except Exception as e:
                log.error(f"RWP fallback also failed: {type(e).__name__}: {e}")
        
        # Return UDP result if successful, otherwise return failure
        if udp_success:
            return self.handle_call_response(result, node_to_ask)
        else:
            log.warning(f"Both UDP and RWP failed for find_node to {node_to_ask.ip}")
            return (False, None)

    async def call_ping(self, node_to_ask):
        """Enhanced ping call with proper timeout cleanup."""
        log.debug(f"Calling ping on {node_to_ask.ip}:{node_to_ask.port} (RWP: {node_to_ask.rwp_port})")
        
        # Try UDP first with timeout and retry logic
        udp_success = False
        result = None
        
        try:
            address = (node_to_ask.ip, node_to_ask.port)
            log.debug(f"Attempting UDP ping to {address}")
            try:
                result = await asyncio.wait_for(
                    self.ping(address, self.source_node.id, self.source_node.rwp_port),
                    timeout=15.0
                )
            except asyncio.TimeoutError:
                log.warning(f"call_ping timed out to {address}")
                # CLEANUP: prevent rpcudp._timeout from touching a cancelled future
                for mid, (future, timeout_handle) in list(self._outstanding.items()):
                    if future.done() or future.cancelled():
                        timeout_handle.cancel()
                        del self._outstanding[mid]
                return (False, None)

            # Enhanced result validation and logging
            if result:
                log.debug(f"UDP ping raw result: {result}")
                if result[0]:
                    udp_success = True
                    log.debug(f"UDP ping successful - got node_id: {result[1].hex() if isinstance(result[1], bytes) else result[1]}")
                else:
                    log.warning(f"UDP ping returned failure response: success={result[0]}, data={result[1]}")
            else:
                log.warning(f"UDP ping returned None/empty result")
                
        except Exception as e:
            log.error(f"Unexpected error in UDP ping to {node_to_ask.ip}:{node_to_ask.port}: {type(e).__name__}: {e}")
            # Clean up on any exception
            for mid, (future, timeout_handle) in list(self._outstanding.items()):
                if future.done() or future.cancelled():
                    timeout_handle.cancel()
                    del self._outstanding[mid]
        
        # If UDP failed, try RWP fallback
        if not udp_success and node_to_ask.rwp_port:
            log.info(f"UDP failed, attempting RWP fallback to {node_to_ask.ip}:{node_to_ask.rwp_port}")
            try:
                node_info = self.rwp_handler.get_node_info(node_to_ask.ip, node_to_ask.rwp_port)
                if node_info:
                    response = self.rwp_handler.send_encrypted_message(
                        node_info,
                        MessageType.PING,
                        {'timestamp': time.time()}
                    )
                    if response and response.get('type') == 'pong':
                        log.debug(f"RWP ping successful to {node_to_ask.ip}:{node_to_ask.rwp_port}")
                        return (True, node_to_ask.id)
                    else:
                        log.warning(f"RWP ping unsuccessful response: {response}")
            except Exception as e:
                log.error(f"RWP fallback also failed: {type(e).__name__}: {e}")
        
        # Return UDP result if successful, otherwise return failure
        if udp_success:
            return self.handle_call_response(result, node_to_ask)
        else:
            log.warning(f"Both UDP and RWP failed for ping to {node_to_ask.ip}")
            return (False, None)

    async def call_verify_neighbor(self, node_to_ask, target_id):
        """Ask a node if they have target_id in their routing table."""
        log.debug(f"Asking {node_to_ask.ip}:{node_to_ask.port} if they know {target_id.hex()}")
        
        try:
            address = (node_to_ask.ip, node_to_ask.port)
            result = await asyncio.wait_for(
                self.verify_neighbor(address, self.source_node.id, target_id, self.source_node.rwp_port),
                timeout=10.0
            )
            
            if result and result[0]:
                log.debug(f"Node {node_to_ask.ip}:{node_to_ask.port} has {target_id.hex()}: {result[1]}")
                return (True, result[1])
            else:
                log.debug(f"Node {node_to_ask.ip}:{node_to_ask.port} doesn't have {target_id.hex()}")
                return (False, False)
                
        except asyncio.TimeoutError:
            log.warning(f"Verify neighbor timed out to {node_to_ask.ip}:{node_to_ask.port}")
            # CLEANUP: prevent rpcudp._timeout from touching a cancelled future
            for mid, (future, timeout_handle) in list(self._outstanding.items()):
                if future.done() or future.cancelled():
                    timeout_handle.cancel()
                    del self._outstanding[mid]
            return (False, False)
        except Exception as e:
            log.error(f"Error verifying neighbor: {e}")
            # Clean up on any exception
            for mid, (future, timeout_handle) in list(self._outstanding.items()):
                if future.done() or future.cancelled():
                    timeout_handle.cancel()
                    del self._outstanding[mid]
            return (False, False)

    def welcome_if_new(self, node):
        """
        Enhanced welcome with duplicate prevention
        """
        # Skip if it's ourselves
        if node.id == self.source_node.id:
            return
            
        # Touch the node to update last_seen timestamp
        node.touch()
        
        # Check if this is truly a new node (by ID and address)
        existing_node = self.router._find_existing_node(node)
        if existing_node:
            # Update existing node info and touch it
            existing_node.ip = node.ip
            existing_node.port = node.port
            existing_node.rwp_port = node.rwp_port
            existing_node.rendezvous_key = node.rendezvous_key
            existing_node.touch()
            log.debug(f"Updated existing node: {node.ip}:{node.port}")
            return

        log.info("Never seen %s before, adding to router", node)
        
        # Try to get node info via RWP if rwp_port is available
        if node.rwp_port:
            node_info = self.rwp_handler.get_node_info(node.ip, node.rwp_port)
            if node_info:
                # Update node with rendezvous key
                node.rendezvous_key = node_info.rendezvous_key
        
        # Add to routing table
        self.router.add_contact(node)

    def _find_existing_node(self, target_node):
        """Find existing node in routing table by ID or address."""
        for bucket in self.buckets:
            # Check by ID first (assume Bucket.__getitem__ works, but iterate as fallback)
            for node in bucket.get_nodes():  # Fallback iteration to ensure we find by ID
                if node.id == target_node.id:
                    return node
            # Check by address as before
            for node in bucket.get_nodes():
                if (node.ip == target_node.ip and node.port == target_node.port):
                    return node
        return None

    def handle_call_response(self, result, node):
        """Enhanced response handling with timestamp updates."""
        if not result[0]:
            log.warning("No response from %s, incrementing failed pings", node)
            node.failed_pings += 1
            if node.failed_pings >= 3:
                log.warning("Node %s failed 3+ pings, removing from router", node)
                self.router.remove_contact(node)
            return result

        log.info("Got successful response from %s", node)
        node.touch()  # Update timestamp on successful response
        if self.learning_enabled:           # <-- respect the flag
            self.welcome_if_new(node)
        else:                               # still touch so it isn't marked stale
            node.touch()
        return result

# ============================================================================
# ROUTING TABLE CLASSES
# ============================================================================

class KBucket:
    """A k-bucket implementation for the Kademlia routing table."""
    
    def __init__(self, rangeLower, rangeUpper, ksize, replacementNodeFactor=5):
        self.range = (rangeLower, rangeUpper)
        self.nodes = OrderedDict()
        self.replacement_nodes = OrderedDict()
        self.touch_last_updated()
        self.ksize = ksize
        self.max_replacement_nodes = self.ksize * replacementNodeFactor

    def touch_last_updated(self):
        self.last_updated = time.monotonic()

    def get_nodes(self):
        return list(self.nodes.values())

    def split(self):
        midpoint = (self.range[0] + self.range[1]) // 2
        one = KBucket(self.range[0], midpoint, self.ksize)
        two = KBucket(midpoint + 1, self.range[1], self.ksize)
        nodes = chain(self.nodes.values(), self.replacement_nodes.values())
        for node in nodes:
            bucket = one if node.long_id <= midpoint else two
            bucket.add_node(node)
        return (one, two)

    def remove_node(self, node):
        if node.id in self.replacement_nodes:
            del self.replacement_nodes[node.id]

        if node.id in self.nodes:
            del self.nodes[node.id]
            if self.replacement_nodes:
                newnode_id, newnode = self.replacement_nodes.popitem()
                self.nodes[newnode_id] = newnode

    def has_in_range(self, node):
        return self.range[0] <= node.long_id <= self.range[1]

    def is_new_node(self, node):
        return node.id not in self.nodes

    def add_node(self, node):
        """Add node but prevent duplicates and respect max neighbors limit."""
        # Check if node already exists by ID
        if node.id in self.nodes:
            # Update existing node with new information
            existing = self.nodes[node.id]
            existing.ip = node.ip
            existing.port = node.port
            existing.rwp_port = node.rwp_port
            existing.rendezvous_key = node.rendezvous_key
            existing.touch()
            # Move to end (most recently seen)
            del self.nodes[node.id]
            self.nodes[node.id] = existing
            return True
        
        # Check for duplicate by address (ip:port combination)
        for existing_node in self.nodes.values():
            if (existing_node.ip == node.ip and 
                existing_node.port == node.port):
                # Same address, different ID - update the existing node
                log.debug(f"Found duplicate address {node.ip}:{node.port}, updating existing node")
                existing_node.ip = node.ip
                existing_node.port = node.port
                existing_node.rwp_port = node.rwp_port
                existing_node.rendezvous_key = node.rendezvous_key
                existing_node.touch()
                return True
        
        # New node - add it
        if len(self) < self.ksize:
            self.nodes[node.id] = node
            return True
        else:
            # Bucket full, add to replacement nodes
            if node.id in self.replacement_nodes:
                del self.replacement_nodes[node.id]
            self.replacement_nodes[node.id] = node
            while len(self.replacement_nodes) > self.max_replacement_nodes:
                self.replacement_nodes.popitem(last=False)
            return False

    def depth(self):
        vals = self.nodes.values()
        sprefix = shared_prefix([bytes_to_bit_string(n.id) for n in vals])
        return len(sprefix)

    def head(self):
        return list(self.nodes.values())[0]

    def __getitem__(self, node_id):
        return self.nodes.get(node_id, None)

    def __len__(self):
        return len(self.nodes)

class TableTraverser:
    """Traverser for the routing table buckets."""
    
    def __init__(self, table, startNode):
        index = table.get_bucket_for(startNode)
        table.buckets[index].touch_last_updated()
        self.current_nodes = table.buckets[index].get_nodes()
        self.left_buckets = table.buckets[:index]
        self.right_buckets = table.buckets[(index + 1) :]
        self.left = True

    def __iter__(self):
        return self

    def __next__(self):
        if self.current_nodes:
            return self.current_nodes.pop()

        if self.left and self.left_buckets:
            self.current_nodes = self.left_buckets.pop().get_nodes()
            self.left = False
            return next(self)

        if self.right_buckets:
            self.current_nodes = self.right_buckets.pop(0).get_nodes()
            self.left = True
            return next(self)

        raise StopIteration

class RoutingTable:
    """Enhanced Kademlia routing table with RWP support."""
    
    def __init__(self, protocol, ksize, node):
        self.node = node
        self.protocol = protocol
        self.ksize = ksize
        self.flush()

    def flush(self):
        self.buckets = [KBucket(0, 2**160, self.ksize)]

    def get_detailed_routing_info(self):
        """Get comprehensive routing table information for debugging."""
        routing_info = {
            'total_buckets': len(self.buckets),
            'total_nodes': 0,
            'total_replacement_nodes': 0,
            'lonely_buckets': len(self.lonely_buckets()),
            'buckets': [],
            'node_distribution': {},
            'stale_nodes': 0,
            'failed_nodes': 0
        }
        
        for i, bucket in enumerate(self.buckets):
            nodes = bucket.get_nodes()
            replacement_nodes = list(bucket.replacement_nodes.values())
            
            bucket_nodes = []
            stale_count = 0
            failed_count = 0
            
            for node in nodes:
                node_info = {
                    'id': node.id.hex(),
                    'long_id': node.long_id,
                    'ip': node.ip,
                    'port': node.port,
                    'rwp_port': node.rwp_port,
                    'rendezvous_key': node.rendezvous_key,
                    'last_seen': node.last_seen,
                    'seconds_since_seen': int(time.time() - node.last_seen),
                    'failed_pings': node.failed_pings,
                    'is_stale': node.is_stale(),
                    'distance_to_self': self.node.distance_to(node)
                }
                bucket_nodes.append(node_info)
                
                if node.is_stale():
                    stale_count += 1
                if node.failed_pings > 0:
                    failed_count += 1
            
            replacement_nodes_info = []
            for node in replacement_nodes:
                replacement_info = {
                    'id': node.id.hex(),
                    'ip': node.ip,
                    'port': node.port,
                    'rwp_port': node.rwp_port,
                    'last_seen': node.last_seen,
                    'seconds_since_seen': int(time.time() - node.last_seen)
                }
                replacement_nodes_info.append(replacement_info)
            
            bucket_info = {
                'index': i,
                'range': f"{bucket.range[0]:#x} - {bucket.range[1]:#x}",
                'range_size': bucket.range[1] - bucket.range[0] + 1,
                'node_count': len(nodes),
                'replacement_count': len(replacement_nodes),
                'max_nodes': bucket.ksize,
                'last_updated': bucket.last_updated,
                'seconds_since_update': int(time.monotonic() - bucket.last_updated),
                'is_lonely': bucket in self.lonely_buckets(),
                'stale_nodes': stale_count,
                'failed_nodes': failed_count,
                'nodes': bucket_nodes,
                'replacement_nodes': replacement_nodes_info
            }
            
            routing_info['buckets'].append(bucket_info)
            routing_info['total_nodes'] += len(nodes)
            routing_info['total_replacement_nodes'] += len(replacement_nodes)
            routing_info['stale_nodes'] += stale_count
            routing_info['failed_nodes'] += failed_count
            
            # Track distribution
            if len(nodes) not in routing_info['node_distribution']:
                routing_info['node_distribution'][len(nodes)] = 0
            routing_info['node_distribution'][len(nodes)] += 1
        
        return routing_info

    def get_total_neighbor_count(self):
        """Get total number of neighbors across all buckets."""
        total = 0
        for bucket in self.buckets:
            total += len(bucket.get_nodes())
        return total

    def is_at_neighbor_limit(self):
        """Check if we're at the maximum neighbor limit."""
        return self.get_total_neighbor_count() >= Config.MAX_NEIGHBORS_PER_NODE

    def should_accept_new_neighbor(self, node):
        """Determine if we should accept a new neighbor based on limits and utility."""
        # Always accept if under limit
        if not self.is_at_neighbor_limit():
            return True
        
        # If at limit, only accept if this node is closer than our furthest neighbor
        index = self.get_bucket_for(node)
        bucket = self.buckets[index]
        
        # If bucket isn't full, accept
        if len(bucket) < bucket.ksize:
            return True
        
        # Check if this node would be more useful than existing nodes
        # by comparing distances to our node
        furthest_distance = 0
        furthest_node = None
        
        for b in self.buckets:
            for existing_node in b.get_nodes():
                distance = self.node.distance_to(existing_node)
                if distance > furthest_distance:
                    furthest_distance = distance
                    furthest_node = existing_node
        
        new_node_distance = self.node.distance_to(node)
        
        # Only accept if new node is closer than our furthest node
        if new_node_distance < furthest_distance:
            # Remove the furthest node to make room
            if furthest_node:
                self.remove_contact(furthest_node)
                log.info(f"Replaced furthest neighbor {furthest_node.ip}:{furthest_node.port} "
                        f"with closer node {node.ip}:{node.port}")
            return True
        
        return False

    def print_routing_table(self, show_empty_buckets=False, show_replacement_nodes=False):
        """Print a formatted routing table for debugging."""
        routing_info = self.get_detailed_routing_info()
        
        print(f"\n{'='*80}")
        print(f"ROUTING TABLE DEBUG - Node ID: {self.node.id.hex()}")
        print(f"{'='*80}")
        print(f"Total Buckets: {routing_info['total_buckets']}")
        print(f"Total Nodes: {routing_info['total_nodes']}")
        print(f"Total Replacement Nodes: {routing_info['total_replacement_nodes']}")
        print(f"Lonely Buckets: {routing_info['lonely_buckets']}")
        print(f"Stale Nodes: {routing_info['stale_nodes']}")
        print(f"Failed Nodes: {routing_info['failed_nodes']}")
        
        # Show distribution
        print(f"\nBucket Fill Distribution:")
        for node_count, bucket_count in sorted(routing_info['node_distribution'].items()):
            print(f"  {node_count} nodes: {bucket_count} buckets")
        
        print(f"\n{'Bucket':<6} {'Range':<35} {'Nodes':<6} {'Repl':<5} {'Updated':<8} {'Status':<10}")
        print(f"{'-'*80}")
        
        for bucket_info in routing_info['buckets']:
            if not show_empty_buckets and bucket_info['node_count'] == 0:
                continue
                
            status_flags = []
            if bucket_info['is_lonely']:
                status_flags.append('LONELY')
            if bucket_info['stale_nodes'] > 0:
                status_flags.append(f'STALE({bucket_info["stale_nodes"]})')
            if bucket_info['failed_nodes'] > 0:
                status_flags.append(f'FAILED({bucket_info["failed_nodes"]})')
            
            status = ','.join(status_flags) if status_flags else 'OK'
            
            # Truncate range for display
            range_str = bucket_info['range']
            if len(range_str) > 33:
                range_str = range_str[:30] + "..."
                
            print(f"{bucket_info['index']:<6} {range_str:<35} "
                f"{bucket_info['node_count']:<6} {bucket_info['replacement_count']:<5} "
                f"{bucket_info['seconds_since_update']:<8} {status:<10}")
            
            # Show individual nodes if bucket has nodes
            if bucket_info['node_count'] > 0:
                for node in bucket_info['nodes']:
                    status_str = ""
                    if node['is_stale']:
                        status_str += " [STALE]"
                    if node['failed_pings'] > 0:
                        status_str += f" [FAILED:{node['failed_pings']}]"
                    
                    print(f"       └─ {node['ip']}:{node['port']} "
                        f"(RWP:{node['rwp_port']}) "
                        f"ID:{node['id'][:16]}... "
                        f"Seen:{node['seconds_since_seen']}s{status_str}")
            
            # Show replacement nodes if requested
            if show_replacement_nodes and bucket_info['replacement_count'] > 0:
                print(f"       Replacement nodes:")
                for node in bucket_info['replacement_nodes']:
                    print(f"         └─ {node['ip']}:{node['port']} "
                        f"ID:{node['id'][:16]}... "
                        f"Seen:{node['seconds_since_seen']}s")
        
        print(f"{'='*80}\n")

    def get_neighbors_by_distance(self, target_node_id=None, k=None):
        """Get all neighbors sorted by distance to target (or self)."""
        if target_node_id is None:
            target_node_id = self.node.id
        
        target_node = Node(target_node_id)
        k = k or self.ksize
        
        all_neighbors = []
        for bucket in self.buckets:
            for node in bucket.get_nodes():
                distance = target_node.distance_to(node)
                all_neighbors.append((distance, node))
        
        # Sort by distance and take k closest
        all_neighbors.sort(key=lambda x: x[0])
        return [node for distance, node in all_neighbors[:k]]

    def analyze_routing_health(self):
        """Analyze routing table health and return recommendations."""
        routing_info = self.get_detailed_routing_info()
        health_report = {
            'overall_health': 'GOOD',
            'issues': [],
            'recommendations': [],
            'metrics': {
                'fill_ratio': routing_info['total_nodes'] / (len(self.buckets) * self.ksize),
                'stale_ratio': routing_info['stale_nodes'] / max(routing_info['total_nodes'], 1),
                'failed_ratio': routing_info['failed_nodes'] / max(routing_info['total_nodes'], 1),
                'lonely_ratio': routing_info['lonely_buckets'] / len(self.buckets)
            }
        }
        
        # Analyze issues
        if routing_info['total_nodes'] < 10:
            health_report['issues'].append("Very few neighbors - network connectivity may be poor")
            health_report['recommendations'].append("Try bootstrapping with more nodes")
            health_report['overall_health'] = 'POOR'
        
        if health_report['metrics']['stale_ratio'] > 0.3:
            health_report['issues'].append(f"High stale node ratio: {health_report['metrics']['stale_ratio']:.2%}")
            health_report['recommendations'].append("Increase heartbeat frequency or reduce failure timeout")
            if health_report['overall_health'] == 'GOOD':
                health_report['overall_health'] = 'FAIR'
        
        if health_report['metrics']['failed_ratio'] > 0.2:
            health_report['issues'].append(f"High failed node ratio: {health_report['metrics']['failed_ratio']:.2%}")
            health_report['recommendations'].append("Review network connectivity and node reliability")
            if health_report['overall_health'] == 'GOOD':
                health_report['overall_health'] = 'FAIR'
        
        if health_report['metrics']['lonely_ratio'] > 0.5:
            health_report['issues'].append(f"Many lonely buckets: {health_report['metrics']['lonely_ratio']:.2%}")
            health_report['recommendations'].append("Perform more frequent routing table refreshes")
            if health_report['overall_health'] == 'GOOD':
                health_report['overall_health'] = 'FAIR'
        
        return health_report

    def split_bucket(self, index):
        one, two = self.buckets[index].split()
        self.buckets[index] = one
        self.buckets.insert(index + 1, two)

    def lonely_buckets(self):
        """Get buckets that haven't been updated in over an hour."""
        hrago = time.monotonic() - 3600
        return [b for b in self.buckets if b.last_updated < hrago]

    def remove_contact(self, node):
        index = self.get_bucket_for(node)
        self.buckets[index].remove_node(node)

    def is_new_node(self, node):
        index = self.get_bucket_for(node)
        return self.buckets[index].is_new_node(node)

    def add_contact(self, node):
        """Add contact with duplicate prevention, neighbor limits, and enhanced logging."""
        # Skip if it's ourselves
        if node.id == self.node.id:
            log.debug(f"Skipping self-node: {node.ip}:{node.port}")
            return
            
        # Check if we already have this exact node (by ID and address)
        existing_node = self._find_existing_node(node)
        if existing_node:
            log.debug(f"Updating existing node {existing_node.ip}:{existing_node.port} with new info from {node.ip}:{node.port}")

            # Prefer non-loopback IP (keep existing if new is loopback and existing isn't)
            def is_loopback(ip):
                return ip.startswith('127.') or ip == 'localhost'

            if is_loopback(node.ip) and not is_loopback(existing_node.ip):
                log.debug(f"Ignoring loopback IP update; keeping existing non-loopback IP {existing_node.ip}")
            else:
                existing_node.ip = node.ip
                log.debug(f"Updated IP to {node.ip}")

            # Always update port/rwp/rendezvous if provided (assuming they might change)
            if node.port:
                existing_node.port = node.port
            existing_node.rwp_port = node.rwp_port
            existing_node.rendezvous_key = node.rendezvous_key
            existing_node.touch()
            return
        
        # Check if we should accept this new neighbor based on limits
        if not self.should_accept_new_neighbor(node):
            log.debug(f"At neighbor limit ({Config.MAX_NEIGHBORS_PER_NODE}), "
                    f"rejecting distant node: {node.ip}:{node.port}")
            return
        
        # If at or above limit and acceptable (closer), remove farthest to make space
        if self.get_total_neighbor_count() >= Config.MAX_NEIGHBORS_PER_NODE:
            all_neighbors = self.get_neighbors_by_distance()
            if all_neighbors:
                farthest = all_neighbors[-1]
                log.debug(f"Removing farthest node {farthest.ip}:{farthest.port} to add closer {node.ip}:{node.port}")
                self.remove_contact(farthest)
        
        log.debug(f"Adding new contact: {node.ip}:{node.port} (RWP: {node.rwp_port}) ID: {node.id.hex()}")
        
        # Touch the node to update last_seen
        node.touch()
        
        index = self.get_bucket_for(node)
        bucket = self.buckets[index]

        if bucket.add_node(node):
            log.info(f"Successfully added node to routing table: {node.ip}:{node.port} "
                    f"(RWP: {node.rwp_port}) - Total neighbors: {self.get_total_neighbor_count()}")
            return

        if bucket.has_in_range(self.node) or bucket.depth() % 5 != 0:
            log.debug(f"Splitting bucket {index} to accommodate new node")
            self.split_bucket(index)
            self.add_contact(node)
        else:
            log.debug(f"Node added to replacement nodes in bucket {index}")
            asyncio.ensure_future(self.protocol.call_ping(bucket.head()))

    def _find_existing_node(self, target_node):
        """Find existing node in routing table by ID or address."""
        for bucket in self.buckets:
            # Check by ID first
            existing = bucket[target_node.id]
            if existing:
                return existing
                
            # Check by address
            for node in bucket.get_nodes():
                if (node.ip == target_node.ip and 
                    node.port == target_node.port):
                    return node
        return None

    def get_stale_nodes(self):
        """Get all nodes that haven't been seen recently."""
        stale_nodes = []
        for bucket in self.buckets:
            for node in bucket.get_nodes():
                if node.is_stale():
                    stale_nodes.append(node)
        return stale_nodes
    
    def remove_stale_nodes(self):
        """Remove nodes that have failed multiple heartbeat attempts or are duplicates by ID."""
        removed_count = 0
        seen_ids = set()
        
        for bucket in self.buckets:
            nodes_to_remove = []
            for node in bucket.get_nodes():
                # Check for duplicates by ID
                if node.id in seen_ids:
                    nodes_to_remove.append(node)
                    log.warning(f"Removing duplicate node by ID: {node.ip}:{node.port} (ID: {node.id.hex()[:16]}...)")
                else:
                    seen_ids.add(node.id)
                    # Check for staleness (original logic)
                    if node.failed_pings >= 3 or node.is_stale(Config.FAILURE_TIMEOUT * 2):
                        nodes_to_remove.append(node)
                        log.info(f"Removing stale node: {node.ip}:{node.port} (ID: {node.id.hex()[:16]}...), "
                                f"failed_pings={node.failed_pings}, last_seen={int(time.time() - node.last_seen)}s")
            
            for node in nodes_to_remove:
                bucket.remove_node(node)
                removed_count += 1
        
        if removed_count > 0:
            log.info(f"Removed {removed_count} nodes (stale or duplicates) from routing table")
        
        return removed_count

    def get_bucket_for(self, node):
        log.info("Finding bucket")        
        for index, bucket in enumerate(self.buckets):
            if node.long_id < bucket.range[1]:
                return index
        # Fallback: always return last bucket
        return len(self.buckets) - 1

    def find_neighbors(self, node, k=None, exclude=None):
        k = k or self.ksize
        nodes = []
        seen_ids = set()
        
        for neighbor in TableTraverser(self, node):
            # Skip duplicates by ID
            if neighbor.id in seen_ids:
                continue
            
            notexcluded = exclude is None or not neighbor.same_home_as(exclude)
            if notexcluded:
                heapq.heappush(nodes, (node.distance_to(neighbor), neighbor))
                seen_ids.add(neighbor.id)
            
            if len(nodes) == k:
                break
        
        return list(map(operator.itemgetter(1), heapq.nsmallest(k, nodes)))

# ============================================================================
# CRAWLING CLASSES
# ============================================================================

class RPCFindResponse:
    """Wrapper for RPC find responses"""
    
    def __init__(self, response):
        self.response = response

    def happened(self):
        return self.response[0]

    def get_node_list(self):
        """Handle both 3-tuple and 4-tuple formats."""
        nodelist = self.response[1] or []
        clean_nodes = [nodeple for nodeple in nodelist if nodeple is not None]
        nodes = []
        
        for nodeple in clean_nodes:
            if len(nodeple) >= 4:
                # New format: (node_id, ip, port, rwp_port)
                nodes.append(Node(*nodeple[:4]))
            elif len(nodeple) >= 3:
                # Old format: (node_id, ip, port) - set rwp_port to None
                node_id, ip, port = nodeple[:3]
                nodes.append(Node(node_id, ip, port, None))
            else:
                log.warning(f"Invalid node tuple format: {nodeple}")
        
        return nodes

class SpiderCrawl:
    """Enhanced crawl with RWP support."""

    def __init__(self, protocol, node, peers, ksize, alpha):
        self.protocol = protocol
        self.ksize = ksize
        self.alpha = alpha
        self.node = node
        self.nearest = NodeHeap(self.node, self.ksize)
        self.last_ids_crawled = []
        log.info("Creating spider with peers: %s", peers)
        self.nearest.push(peers)

    async def _find(self, rpcmethod):
        log.info("Crawling network with nearest: %s", str(tuple(self.nearest)))
        count = self.alpha
        if self.nearest.get_ids() == self.last_ids_crawled:
            count = len(self.nearest)
        self.last_ids_crawled = self.nearest.get_ids()

        dicts = {}
        for peer in self.nearest.get_uncontacted()[:count]:
            dicts[peer.id] = rpcmethod(peer, self.node)
            self.nearest.mark_contacted(peer)
        found = await gather_dict(dicts)
        return await self._nodes_found(found)

    async def _nodes_found(self, responses):
        """Process node responses - NO VALUE HANDLING."""
        toremove = []
        for peerid, response in responses.items():
            response = RPCFindResponse(response)
            if not response.happened():
                toremove.append(peerid)
            else:
                self.nearest.push(response.get_node_list())
        self.nearest.remove(toremove)

        if self.nearest.have_contacted_all():
            return list(self.nearest)
        return await self.find()

class NodeSpiderCrawl(SpiderCrawl):
    """Enhanced node spider crawl."""
    
    async def find(self):
        return await self._find(self.protocol.call_find_node)

    async def _nodes_found(self, responses):
        toremove = []
        for peerid, response in responses.items():
            response = RPCFindResponse(response)
            if not response.happened():
                toremove.append(peerid)
            else:
                self.nearest.push(response.get_node_list())
        self.nearest.remove(toremove)

        if self.nearest.have_contacted_all():
            return list(self.nearest)
        return await self.find()

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

async def gather_dict(dic):
    """Gather a dictionary of coroutines into a dictionary of results."""
    cors = list(dic.values())
    results = await asyncio.gather(*cors)
    return dict(zip(dic.keys(), results))

def shared_prefix(args):
    """Find the shared prefix between the strings."""
    i = 0
    while i < min(map(len, args)):
        if len(set(map(operator.itemgetter(i), args))) != 1:
            break
        i += 1
    return args[0][:i]

def bytes_to_bit_string(bites):
    """Convert bytes to bit string representation."""
    bits = [bin(bite)[2:].rjust(8, "0") for bite in bites]
    return "".join(bits)

# ============================================================================
# MAIN RRKDHT CLASS
# ============================================================================

class RRKDHT:
    """
    Production Rotating Rendezvous Kademlia DHT with RWP protocol support.
    
    This is the main class for creating and managing an RRKDHT node.
    """

    protocol_class = RRKDHTProtocol

    def __init__(self, ksize=2, alpha=3, node_id=None, signing_keys=None, rwp_port=None):
        """Create an RRKDHT server instance"""
        self.ksize = ksize
        self.alpha = alpha
        
        # Generate or use provided signing keys
        if signing_keys:
            self.signing_private_key, self.signing_public_key = signing_keys
        else:
            self.signing_private_key, self.signing_public_key = create_ed25519_key_pair()
        
        # Generate node ID from public key if not provided
        if node_id is None:
            node_id = digest(generate_peer_id(self.signing_public_key))
        
        self.node = Node(node_id)
        self.rwp_port = rwp_port
        
        # Initialize epoch manager and messaging
        self.epoch_manager = EpochManager()
        self.messaging = SecureMessaging(self.signing_private_key, self.signing_public_key)
        
        # Initialize RWP handler
        peer_id = generate_peer_id(self.signing_public_key)
        self.rwp_handler = RWPDHTHandler(
            peer_id, 
            self.messaging, 
            self.epoch_manager,
            None  # No router yet
        )
        
        self.network_conditions = {
            'avg_ping_time': 15,
            'success_rate': 1.0,
            'congestion_factor': 1.0
        }
        self.ping_history = []
        self.max_ping_history = 20

        self.heartbeat_sync_time = None
        self.failed_nodes = {}
        self.HEARTBEAT_SYNC_INTERVAL = 60
        self.MAX_FAILURES_BEFORE_REMOVAL = 3

        # Track possible responsible nodes
        self.possible_responsibles = {}
        self.verified_responsibles = set()
        self.last_responsible_check = 0
        self.is_orphaned = False
        self.rejoin_in_progress = False
        self.responsible_check_loop = None
        self._rejoin_attempts = 0
        self._identity_regeneration_count = 0
        self._original_identity = None
        self._pending_verification = False

        # Initialize protocol and other components
        self.transport = None
        self.protocol = None
        self.refresh_loop = None
        self.save_state_loop = None
        self.key_rotation_thread = None
        self.running = False

    def stop(self):
        """Stop the RRKDHT node and cleanup resources."""
        self.running = False
        
        if self.transport is not None:
            self.transport.close()

        if self.refresh_loop:
            self.refresh_loop.cancel()

        if self.save_state_loop:
            self.save_state_loop.cancel()

        if hasattr(self, 'heartbeat_loop') and self.heartbeat_loop: 
            self.heartbeat_loop.cancel()
        
        # NEW: Stop responsible node checking
        if hasattr(self, 'responsible_check_loop') and self.responsible_check_loop:
            self.responsible_check_loop.cancel()
            
        if self.rwp_handler:
            self.rwp_handler.stop_rwp_server()
            
        if self.key_rotation_thread:
            self.key_rotation_thread.join(timeout=5)

        self._rejoin_attempts = 0
        self._identity_regeneration_count = 0
        self._pending_verification = False  

    def _create_protocol(self):
        """Create protocol"""
        protocol = self.protocol_class(
            self.node, self.ksize, 
            self.epoch_manager, self.rwp_handler
        )
        # Set the router reference for the RWP handler
        self.rwp_handler.router = protocol.router
        # Set server reference for tracking possible responsibles
        protocol.server_ref = self
        return protocol

    async def listen(self, port, interface="0.0.0.0", rwp_port=None):
        """
        Start listening on the given port.
        
        Args:
            port: UDP port for Kademlia protocol
            interface: Interface to bind to
            rwp_port: TCP port for RWP protocol (defaults to port + 1000)
        """
        self.running = True
        
        # Set RWP port if not provided
        if rwp_port is not None:
            self.rwp_port = rwp_port
        elif self.rwp_port is None:
            self.rwp_port = port + 1000
            
        # Update node with port information
        self.node.port = port
        self.node.rwp_port = self.rwp_port
        self.node.ip = interface if interface != "0.0.0.0" else "127.0.0.1"
        
        # Start RWP server
        self.rwp_handler.start_rwp_server(self.rwp_port)
        
        # Start Kademlia UDP server
        loop = asyncio.get_event_loop()
        listen = loop.create_datagram_endpoint(
            self._create_protocol, local_addr=(interface, port)
        )
        log.info("Node %i listening on %s:%i (RWP: %i)", 
                self.node.long_id, interface, port, self.rwp_port)
        
        self.transport, self.protocol = await listen
        
        self._rendezvous_storage = {}
        self._schedule_rendezvous_republish()

        # Start key rotation monitoring
        self._start_key_rotation_monitor()
        # Schedule refreshing table
        self.refresh_table()
        self.start_heartbeat()
        # NEW: Start responsible node checking
        self._schedule_responsible_check()

    def _update_network_conditions(self, ping_time, success):
        """Update network conditions based on recent ping performance."""
        # Update ping history
        if success:
            self.ping_history.append(ping_time)
            if len(self.ping_history) > self.max_ping_history:
                self.ping_history.pop(0)
        
        # Calculate average ping time
        if self.ping_history:
            self.network_conditions['avg_ping_time'] = sum(self.ping_history) / len(self.ping_history)
        
        # Calculate success rate (simplified - you could make this more sophisticated)
        recent_successes = sum(1 for t in self.ping_history[-10:] if t < 2.0)  # Under 2 seconds = success
        self.network_conditions['success_rate'] = recent_successes / min(10, len(self.ping_history))
        
        # Adjust congestion factor based on conditions
        if self.network_conditions['avg_ping_time'] > 1.0:
            self.network_conditions['congestion_factor'] = min(2.0, self.network_conditions['congestion_factor'] * 1.1)
        else:
            self.network_conditions['congestion_factor'] = max(0.5, self.network_conditions['congestion_factor'] * 0.95)
        
        log.debug(f"Network conditions: avg_ping={self.network_conditions['avg_ping_time']:.2f}s, "
                f"success_rate={self.network_conditions['success_rate']:.2f}, "
                f"congestion_factor={self.network_conditions['congestion_factor']:.2f}")

    def _get_adaptive_delay(self, base_delay=0.2):
        """Get adaptive delay based on current network conditions."""
        # Adjust delay based on network congestion
        adaptive_delay = base_delay * self.network_conditions['congestion_factor']
        
        # Add randomization to prevent synchronized behavior across nodes
        import random
        jitter = random.uniform(0.8, 1.2)  # ±20% jitter
        
        return adaptive_delay * jitter

    def start_heartbeat(self):
        """Start the enhanced sequential heartbeat system."""
        if not self.running:
            return
            
        # Calculate next sync time (next minute boundary)
        import math
        current_time = time.time()
        self.heartbeat_sync_time = math.ceil(current_time / self.HEARTBEAT_SYNC_INTERVAL) * self.HEARTBEAT_SYNC_INTERVAL
        
        # Schedule first sync
        delay_to_sync = self.heartbeat_sync_time - current_time
        log.info(f"Starting sequential heartbeat system, next sync in {delay_to_sync:.1f}s")
        
        loop = asyncio.get_event_loop()
        self.heartbeat_loop = loop.call_later(delay_to_sync, self._schedule_sync_heartbeat)

    async def _synchronized_heartbeat_check(self):
        """Sequential heartbeat check to prevent network congestion."""
        if not self.running or not self.protocol:
            return
        
        # Get all nodes in routing table
        all_nodes = []
        for bucket in self.protocol.router.buckets:
            all_nodes.extend(bucket.get_nodes())
        
        if not all_nodes:
            log.debug("No nodes in routing table for heartbeat check")
            return
        
        log.debug(f"Sequential heartbeat check for {len(all_nodes)} nodes")
        
        # Stagger the start based on our node ID to spread network load
        node_hash = int(self.node.id.hex()[:8], 16)
        stagger_delay = (node_hash % 2000) / 1000.0  # 0-2 second delay
        
        if stagger_delay > 0:
            log.debug(f"Staggering heartbeat by {stagger_delay:.3f}s")
            await asyncio.sleep(stagger_delay)
        
        # Ping nodes sequentially with controlled timing
        successful_pings = 0
        
        for i, node in enumerate(all_nodes):
            try:
                # Ping with shorter timeout for heartbeat
                ping_start = time.time()
                result = await self._safe_heartbeat_ping(node)
                ping_duration = time.time() - ping_start
                
                if result and result[0]:  # Successful ping
                    successful_pings += 1
                    node.touch()  # Reset failure count and update timestamp
                    self.failed_nodes.pop(node.id, None)  # Remove from failed list
                    log.debug(f"Heartbeat ping successful to {node.ip}:{node.port} in {ping_duration:.2f}s")
                else:  # Failed ping
                    self._handle_ping_failure(node)
                    log.debug(f"Heartbeat ping failed to {node.ip}:{node.port} after {ping_duration:.2f}s")
                
                # Add delay between pings to prevent overwhelming the network
                # Shorter delay for successful pings, longer for failures
                if result and result[0]:
                    await asyncio.sleep(0.2)  # 200ms between successful pings
                else:
                    await asyncio.sleep(0.5)  # 500ms after failed pings
                    
            except Exception as e:
                log.warning(f"Exception during heartbeat ping to {node.ip}:{node.port}: {e}")
                self._handle_ping_failure(node)
                await asyncio.sleep(0.5)  # 500ms after exceptions
        
        log.info(f"Heartbeat completed: {successful_pings}/{len(all_nodes)} nodes responded")
        
        # Clean up failed nodes after heartbeat round
        self._remove_failed_nodes()

    async def _check_responsible_nodes(self):
        """
        Verify which nodes that contacted us are actually responsible for us.
        Enhanced with better orphan detection.
        """
        if not self.running or not self.protocol:
            return
        
        log.debug("Starting responsible node verification")
        
        # Clean up old entries
        current_time = time.time()
        stale_threshold = 600  # 10 minutes
        stale_nodes = [
            node_id for node_id, info in self.possible_responsibles.items()
            if current_time - info['last_contact'] > stale_threshold
        ]
        for node_id in stale_nodes:
            log.debug(f"Removing stale possible responsible: {self.possible_responsibles[node_id]['node'].ip}")
            del self.possible_responsibles[node_id]
        
        if not self.possible_responsibles:
            log.info("No nodes have contacted us recently")
            
            # Check if we've ever had contacts
            if not hasattr(self, '_ever_had_contacts'):
                self._ever_had_contacts = False
            
            if not self._ever_had_contacts:
                # Check if routing table is empty
                routing_table_empty = True
                if self.protocol and self.protocol.router:
                    routing_table_empty = all(len(bucket.get_nodes()) == 0 
                                            for bucket in self.protocol.router.buckets)
                
                if routing_table_empty:
                    log.info("First node in network - no orphan status")
                    self.is_orphaned = False
                    self.verified_responsibles = set()
                    return
                else:
                    log.warning("Never received contacts but have neighbors - checking network")
                    if not self.rejoin_in_progress:
                        self.is_orphaned = True
                        asyncio.ensure_future(self._attempt_rejoin())
                    return
            else:
                log.warning("Lost all contacts - potentially orphaned")
                if not self.rejoin_in_progress:
                    self.is_orphaned = True
                    asyncio.ensure_future(self._attempt_rejoin())
                return
        
        # Mark that we've had contacts
        if self.possible_responsibles:
            self._ever_had_contacts = True
        
        # Verify each possible responsible
        log.debug(f"Verifying {len(self.possible_responsibles)} possible responsible nodes")
        
        new_verified = set()
        successful_checks = 0
        failed_checks = 0
        
        for node_id, info in list(self.possible_responsibles.items()):
            node = info['node']
            
            try:
                result = await self.protocol.call_verify_neighbor(node, self.node.id)
                
                if result[0] and result[1]:
                    new_verified.add(node_id)
                    self.possible_responsibles[node_id]['verified'] = True
                    node.confirm_as_neighbor()
                    log.debug(f"[VERIFIED] {node.ip}:{node.port} is responsible for us")
                    successful_checks += 1
                elif result[0] and not result[1]:
                    log.debug(f"[REJECTED] {node.ip}:{node.port} doesn't have us in routing table")
                    del self.possible_responsibles[node_id]
                    successful_checks += 1
                else:
                    log.debug(f"No response from {node.ip}:{node.port}")
                    failed_checks += 1
                
                await asyncio.sleep(0.15)
                
            except Exception as e:
                log.debug(f"Error verifying {node.ip}:{node.port}: {e}")
                failed_checks += 1
                continue
        
        # Update verified responsibles
        old_count = len(self.verified_responsibles)
        self.verified_responsibles = new_verified
        new_count = len(self.verified_responsibles)
        
        log.info(f"Verification: {new_count} verified from {len(self.possible_responsibles)} candidates "
                f"(was {old_count}, {successful_checks} responses, {failed_checks} failed)")
        
        # Determine orphan status
        if new_count < Config.MIN_RESPONSIBLE_NODES:
            if successful_checks > 0:
                log.warning(f"ORPHANED: Only {new_count} verified nodes (need {Config.MIN_RESPONSIBLE_NODES})")
                
                if not self.rejoin_in_progress:
                    self.is_orphaned = True
                    asyncio.ensure_future(self._attempt_rejoin())
            else:
                log.warning(f"Network unreachable ({failed_checks} failures) - not marking orphaned yet")
        else:
            if self.is_orphaned:
                log.info(f"[OK] Connectivity restored: {new_count} verified nodes")
            self.is_orphaned = False
            self.rejoin_in_progress = False
            self._rejoin_attempts = 0
        
        self.last_responsible_check = time.time()

    def _schedule_responsible_check(self):
        """Schedule the next responsible node check."""
        if not self.running:
            return
        
        log.debug("Scheduling responsible node check")
        asyncio.ensure_future(self._check_responsible_nodes())
        
        loop = asyncio.get_event_loop()
        self.responsible_check_loop = loop.call_later(
            Config.RESPONSIBLE_CHECK_INTERVAL,
            self._schedule_responsible_check
        )

    async def store_rendezvous_key(self, rendezvous_key: str, node_id: bytes, ttl: int = None) -> bool:
        """
        Store a rendezvous key mapping on the node(s) with Node_ID closest to the key's hash.
        Uses iterative search to find the actual closest nodes.
        """
        try:
            # Hash the rendezvous key to get storage location
            key_hash = digest(rendezvous_key)
            
            # Use epoch duration as default TTL
            if ttl is None:
                ttl = self.epoch_manager.epoch_duration
            
            # Create storage value
            current_epoch = self.epoch_manager.get_current_epoch()
            storage_value = {
                'node_id': node_id.hex(),
                'rendezvous_key': rendezvous_key,
                'stored_at': time.time(),
                'epoch': current_epoch,
                'expires_at': time.time() + ttl
            }
            
            log.info(f"Storing rendezvous key '{rendezvous_key}' for node {node_id.hex()[:16]}...")
            log.debug(f"Key hash: {key_hash.hex()[:16]}...")
            
            # Find nodes with Node_ID closest to the key hash
            closest_nodes = await self._find_closest_nodes_to_key(key_hash, k=Config.REPLICATION_FACTOR)
            
            if not closest_nodes:
                log.error(f"Could not find any nodes to store rendezvous key")
                return False
            
            log.info(f"Found {len(closest_nodes)} closest nodes for storage:")
            target_node = Node(key_hash)
            for i, node in enumerate(closest_nodes):
                distance = target_node.distance_to(node)
                is_us = " US" if node.id == self.protocol.source_node.id else ""
                log.info(f"  {i+1}. {node.ip}:{node.port} (distance: {distance}){is_us}")
            
            # Store on all closest nodes
            store_tasks = []
            for node in closest_nodes:
                store_tasks.append(self._store_rendezvous_on_node(node, key_hash, storage_value))
            
            results = await asyncio.gather(*store_tasks, return_exceptions=True)
            
            # Count successes and failures
            success_count = sum(1 for r in results if r is True)
            failed_count = len(results) - success_count
            
            # Calculate minimum required successes (at least 1, or majority if multiple nodes)
            min_required = 1 if len(closest_nodes) == 1 else (len(closest_nodes) + 1) // 2
            
            if success_count >= min_required:
                log.info(f"[OK] Successfully stored rendezvous key on {success_count}/{len(closest_nodes)} nodes")
                if failed_count > 0:
                    log.warning(f"  {failed_count} storage operations failed (acceptable)")
                return True
            else:
                log.error(f"[NEGATIVE] Failed to store on enough nodes: {success_count}/{len(closest_nodes)} (needed {min_required})")
                return False
                
        except Exception as e:
            log.error(f"Error storing rendezvous key: {e}")
            import traceback
            traceback.print_exc()
            return False

    async def _find_closest_nodes_to_key(self, key_hash: bytes, k: int = None) -> List[Node]:
        """
        Find the k nodes with Node_IDs closest to the given key hash using iterative search.
        
        Args:
            key_hash: The key hash to find closest nodes for
            k: Number of closest nodes to find (defaults to REPLICATION_FACTOR)
        
        Returns:
            List of k closest nodes
        """
        if k is None:
            k = Config.REPLICATION_FACTOR
        
        try:
            target_node = Node(key_hash)
            
            # Start with our closest known neighbors
            current_closest = self.protocol.router.find_neighbors(target_node, k=self.alpha)
            
            if not current_closest:
                # If we have no neighbors, we're the only node
                log.debug(f"No neighbors found, we are the only node for this key")
                return [self.protocol.source_node]
            
            # Check if we are closer than any neighbor
            our_distance = target_node.distance_to(self.protocol.source_node)
            
            queried_nodes = set()
            best_distance = min(target_node.distance_to(n) for n in current_closest)
            
            # Build initial candidate list including ourselves if we're close
            all_candidates = list(current_closest)
            all_candidates.append(self.protocol.source_node)
            
            log.debug(f"Initial search - our distance: {our_distance}, best neighbor distance: {best_distance}")
            
            # Iteratively find closer nodes
            improved = True
            iteration = 0
            
            while improved and iteration < Config.SEARCH_MAX_HOPS:
                iteration += 1
                improved = False
                
                unqueried = [n for n in current_closest if n.id not in queried_nodes]
                
                if not unqueried:
                    log.debug(f"No more unqueried nodes after {iteration} iterations")
                    break
                
                # Query alpha nodes in parallel
                nodes_to_query = unqueried[:self.alpha]
                
                query_tasks = []
                for node in nodes_to_query:
                    queried_nodes.add(node.id)
                    query_tasks.append(self._query_node_for_closest(node, key_hash))
                
                results = await asyncio.gather(*query_tasks, return_exceptions=True)
                
                new_neighbors = []
                for result in results:
                    if isinstance(result, list):
                        new_neighbors.extend(result)
                
                if new_neighbors:
                    # Add new neighbors to candidates
                    all_candidates.extend(new_neighbors)
                    
                    # Merge with current_closest and remove duplicates
                    all_nodes = current_closest + new_neighbors
                    unique_nodes = {n.id: n for n in all_nodes if n.id not in queried_nodes}
                    
                    # Sort by distance and keep closest
                    current_closest = sorted(
                        unique_nodes.values(),
                        key=lambda n: target_node.distance_to(n)
                    )[:self.alpha * 2]
                    
                    # Check if we found closer nodes
                    new_best = target_node.distance_to(current_closest[0]) if current_closest else float('inf')
                    if new_best < best_distance:
                        best_distance = new_best
                        improved = True
                        log.debug(f"Iteration {iteration}: Found closer nodes, best distance now: {best_distance}")
            
            # Remove duplicates from all candidates
            unique_candidates = {n.id: n for n in all_candidates}
            
            # Sort by distance and return k closest
            sorted_candidates = sorted(
                unique_candidates.values(),
                key=lambda n: target_node.distance_to(n)
            )[:k]
            
            log.debug(f"Found {len(sorted_candidates)} closest nodes after {iteration} iterations")
            
            # Log the final distances
            for i, node in enumerate(sorted_candidates):
                distance = target_node.distance_to(node)
                is_us = " (US)" if node.id == self.protocol.source_node.id else ""
                log.debug(f"  Closest node {i+1}: {node.ip}:{node.port} (distance: {distance}){is_us}")
            
            return sorted_candidates
            
        except Exception as e:
            log.error(f"Error finding closest nodes: {e}")
            # Return ourselves as fallback
            return [self.protocol.source_node]

    async def _query_node_for_closest(self, node: Node, key_hash: bytes) -> List[Node]:
        """Query a node for nodes closest to the key hash."""
        try:
            result = await self.protocol.call_find_node(node, Node(key_hash))
            
            if not result[0]:
                return []
            
            neighbors = []
            if result[1]:
                for node_tuple in result[1]:
                    if len(node_tuple) >= 3:
                        returned_id, ip, port = node_tuple[:3]
                        rwp_port = node_tuple[3] if len(node_tuple) > 3 else None
                        neighbors.append(Node(returned_id, ip, port, rwp_port))
            
            return neighbors
            
        except Exception as e:
            log.debug(f"Error querying node {node.ip}:{node.port}: {e}")
            return []

    async def _store_rendezvous_on_node(self, node: Node, key_hash: bytes, value: Dict) -> bool:
        """Store rendezvous key data on a specific node with retry logic."""
        max_retries = 2
        retry_delay = 0.5
        
        try:
            # Check if this is us - compare by Node ID
            if node.id == self.protocol.source_node.id:
                log.debug(f"Storing locally (we are the target node)")
                return await self._store_local_rendezvous(key_hash, value)
            
            # Try RWP for remote nodes with retries
            if not node.rwp_port:
                log.debug(f"Node {node.ip}:{node.port} has no RWP port")
                return False
            
            for attempt in range(max_retries):
                try:
                    node_info = self.rwp_handler.get_node_info(node.ip, node.rwp_port)
                    if not node_info:
                        if attempt < max_retries - 1:
                            log.debug(f"Could not get node info for {node.ip}:{node.rwp_port}, retrying...")
                            await asyncio.sleep(retry_delay)
                            continue
                        else:
                            log.warning(f"Could not get node info for {node.ip}:{node.rwp_port} after {max_retries} attempts")
                            return False
                    
                    response = self.rwp_handler.send_encrypted_message(
                        node_info,
                        MessageType.DHT_SET,
                        {
                            'key': key_hash.hex(),
                            'value': json.dumps(value),
                            'ttl': int(value['expires_at'] - value['stored_at'])
                        }
                    )
                    
                    if response:
                        # Check response format
                        success = False
                        if isinstance(response, dict):
                            payload = response.get('payload', {})
                            success = payload.get('success', False)
                        
                        if success:
                            log.info(f"[OK] Successfully stored on remote node {node.ip}:{node.port}")
                            return True
                        else:
                            if attempt < max_retries - 1:
                                log.debug(f"Store failed on {node.ip}:{node.port}, retrying...")
                                await asyncio.sleep(retry_delay)
                                continue
                            else:
                                log.warning(f"Failed to store on remote node {node.ip}:{node.port} after {max_retries} attempts")
                                return False
                    else:
                        if attempt < max_retries - 1:
                            log.debug(f"No response from {node.ip}:{node.port}, retrying...")
                            await asyncio.sleep(retry_delay)
                            continue
                        else:
                            log.warning(f"No response from {node.ip}:{node.port} after {max_retries} attempts")
                            return False
                            
                except Exception as e:
                    if attempt < max_retries - 1:
                        log.debug(f"Error storing on {node.ip}:{node.port} (attempt {attempt + 1}): {e}, retrying...")
                        await asyncio.sleep(retry_delay)
                        continue
                    else:
                        log.error(f"Error storing on {node.ip}:{node.port} after {max_retries} attempts: {e}")
                        return False
            
            return False
            
        except Exception as e:
            log.error(f"Unexpected error storing on node {node.ip}:{node.port}: {e}")
            return False
    
    async def _store_local_rendezvous(self, key_hash: bytes, value: Dict) -> bool:
        """Store rendezvous key data locally."""
        try:
            if not hasattr(self, '_rendezvous_storage'):
                self._rendezvous_storage = {}
            
            self._rendezvous_storage[key_hash] = value
            log.info(f"[OK] Stored rendezvous key '{value['rendezvous_key']}' locally (key_hash: {key_hash.hex()[:16]}...)")
            log.debug(f"  Node ID: {value['node_id'][:16]}...")
            log.debug(f"  Expires at epoch: {value['epoch']}")
            log.debug(f"  Total local storage entries: {len(self._rendezvous_storage)}")
            return True
        except Exception as e:
            log.error(f"Error storing locally: {e}")
            return False

    async def lookup_rendezvous_key(self, rendezvous_key: str) -> Optional[Dict]:
        """
        Look up a node ID by its rendezvous key.
        Uses iterative search to find nodes with Node_ID closest to the key hash.
        
        Args:
            rendezvous_key: The rendezvous key to look up
        
        Returns:
            Dict with node_id and metadata, or None if not found
        """
        try:
            # Hash the rendezvous key to find storage location
            key_hash = digest(rendezvous_key)
            
            log.info(f"Looking up rendezvous key {rendezvous_key} (hash: {key_hash.hex()[:16]}...)")
            
            # Find nodes with Node_ID closest to the key hash
            closest_nodes = await self._find_closest_nodes_to_key(key_hash, k=Config.REPLICATION_FACTOR)
            
            if not closest_nodes:
                log.warning(f"No nodes found close to rendezvous key hash")
                return None
            
            log.debug(f"Looking up on {len(closest_nodes)} closest nodes")
            
            # Query nodes in parallel
            lookup_tasks = []
            for node in closest_nodes:
                lookup_tasks.append(self._lookup_rendezvous_on_node(node, key_hash))
            
            results = await asyncio.gather(*lookup_tasks, return_exceptions=True)
            
            # Return first valid result
            current_epoch = self.epoch_manager.get_current_epoch()
            
            for result in results:
                if isinstance(result, dict) and result:
                    # Check if expired
                    if result.get('expires_at', 0) < time.time():
                        log.debug(f"Found expired rendezvous key entry")
                        continue
                    
                    # Check if from wrong epoch
                    if result.get('epoch') != current_epoch:
                        log.debug(f"Found rendezvous key from old epoch")
                        continue
                    
                    log.info(f"Found rendezvous key mapping: {rendezvous_key} -> {result['node_id'][:16]}...")
                    return result
            
            log.info(f"Rendezvous key {rendezvous_key} not found on any closest nodes")
            return None
            
        except Exception as e:
            log.error(f"Error looking up rendezvous key: {e}")
            return None

    async def _lookup_rendezvous_on_node(self, node: Node, key_hash: bytes) -> Optional[Dict]:
        """Look up rendezvous key data on a specific node with retry logic."""
        max_retries = 2
        retry_delay = 0.3
        
        try:
            # Check if this is us - compare by Node ID
            if node.id == self.protocol.source_node.id:
                log.debug(f"Looking up locally (we are the target node)")
                return await self._lookup_local_rendezvous(key_hash)
            
            # Use RWP for remote nodes with retries
            if not node.rwp_port:
                log.debug(f"Node {node.ip}:{node.port} has no RWP port")
                return None
            
            for attempt in range(max_retries):
                try:
                    node_info = self.rwp_handler.get_node_info(node.ip, node.rwp_port)
                    if not node_info:
                        if attempt < max_retries - 1:
                            await asyncio.sleep(retry_delay)
                            continue
                        else:
                            log.debug(f"Could not get node info for {node.ip}:{node.rwp_port}")
                            return None
                    
                    response = self.rwp_handler.send_encrypted_message(
                        node_info,
                        MessageType.DHT_GET,
                        {'key': key_hash.hex()}
                    )
                    
                    if response and isinstance(response, dict):
                        payload = response.get('payload', {})
                        if payload.get('found'):
                            value_str = payload.get('value')
                            if value_str:
                                log.debug(f"[OK] Found value on remote node {node.ip}:{node.port}")
                                return json.loads(value_str)
                        
                        # If not found, don't retry
                        log.debug(f"Value not found on remote node {node.ip}:{node.port}")
                        return None
                    else:
                        if attempt < max_retries - 1:
                            log.debug(f"No valid response from {node.ip}:{node.port}, retrying...")
                            await asyncio.sleep(retry_delay)
                            continue
                        else:
                            log.debug(f"No valid response from {node.ip}:{node.port} after {max_retries} attempts")
                            return None
                            
                except Exception as e:
                    if attempt < max_retries - 1:
                        log.debug(f"Error looking up on {node.ip}:{node.port} (attempt {attempt + 1}): {e}, retrying...")
                        await asyncio.sleep(retry_delay)
                        continue
                    else:
                        log.debug(f"Error looking up on {node.ip}:{node.port} after {max_retries} attempts: {e}")
                        return None
            
            return None
            
        except Exception as e:
            log.debug(f"Unexpected error looking up on node {node.ip}:{node.port}: {e}")
            return None

    async def _lookup_local_rendezvous(self, key_hash: bytes) -> Optional[Dict]:
        """Look up rendezvous key data locally."""
        try:
            if not hasattr(self, '_rendezvous_storage'):
                self._rendezvous_storage = {}
                log.debug(f"Local storage not initialized")
                return None
            
            value = self._rendezvous_storage.get(key_hash)
            if value:
                log.info(f"[OK] Found rendezvous key '{value['rendezvous_key']}' in local storage")
                log.debug(f"  Node ID: {value['node_id'][:16]}...")
                log.debug(f"  Stored at epoch: {value['epoch']}")
            else:
                log.debug(f"Key hash {key_hash.hex()[:16]}... not found in local storage")
                log.debug(f"  Available keys: {[k.hex()[:16] + '...' for k in self._rendezvous_storage.keys()]}")
            
            return value
        except Exception as e:
            log.error(f"Error looking up locally: {e}")
            return None

    async def republish_rendezvous_key(self):
        """
        Republish our rendezvous key to ensure it's stored on correct nodes.
        Should be called periodically and after routing table changes.
        """
        try:
            if not self.running or not self.protocol:
                return
            
            rendezvous_key = self.get_rendezvous_key()
            if not rendezvous_key:
                log.warning("No rendezvous key to republish")
                return
            
            log.debug(f"Republishing rendezvous key: {rendezvous_key}")
            success = await self.store_rendezvous_key(rendezvous_key, self.node.id)
            
            if success:
                log.info(f"Successfully republished rendezvous key")
            else:
                log.warning(f"Failed to republish rendezvous key")
                
        except Exception as e:
            log.error(f"Error republishing rendezvous key: {e}")

    def _cleanup_expired_rendezvous(self):
        """Clean up expired rendezvous key entries from local storage."""
        try:
            if not hasattr(self, '_rendezvous_storage'):
                return
            
            current_time = time.time()
            current_epoch = self.epoch_manager.get_current_epoch()
            
            expired_keys = []
            for key_hash, value in self._rendezvous_storage.items():
                # Remove if expired or from old epoch
                if (value.get('expires_at', 0) < current_time or 
                    value.get('epoch') != current_epoch):
                    expired_keys.append(key_hash)
            
            for key_hash in expired_keys:
                del self._rendezvous_storage[key_hash]
            
            if expired_keys:
                log.info(f"Cleaned up {len(expired_keys)} expired rendezvous keys")
                
        except Exception as e:
            log.error(f"Error cleaning up rendezvous keys: {e}")

    async def search_by_rendezvous_key(self, rendezvous_key: str) -> SearchResult:
        """
        Search for a node by its rendezvous key.
        
        Args:
            rendezvous_key: The rendezvous key to search for
        
        Returns:
            SearchResult with node information if found
        """
        start_time = time.time()
        
        try:
            # First, look up the node ID from the rendezvous key
            log.info(f"Looking up node ID for rendezvous key: {rendezvous_key}")
            mapping = await self.lookup_rendezvous_key(rendezvous_key)
            
            if not mapping:
                log.warning(f"Rendezvous key {rendezvous_key} not found in DHT")
                return SearchResult(
                    found=False,
                    target_node=None,
                    hops=0,
                    path=[],
                    search_time=time.time() - start_time,
                    nodes_queried=0
                )
            
            # Extract node ID
            target_node_id = bytes.fromhex(mapping['node_id'])
            log.info(f"Found mapping: {rendezvous_key} -> {target_node_id.hex()[:16]}...")
            
            # Now search for the actual node
            log.info(f"Searching for node by ID: {target_node_id.hex()}")
            search_result = await self.search_node(target_node_id.hex())
            
            # Add rendezvous lookup time to total
            search_result.search_time = time.time() - start_time
            
            return search_result
            
        except Exception as e:
            log.error(f"Error searching by rendezvous key: {e}")
            return SearchResult(
                found=False,
                target_node=None,
                hops=0,
                path=[],
                search_time=time.time() - start_time,
                nodes_queried=0
            )

    def _schedule_rendezvous_republish(self):
        """Schedule periodic rendezvous key republishing."""
        if not self.running:
            return
        
        asyncio.ensure_future(self.republish_rendezvous_key())
        asyncio.ensure_future(self._cleanup_expired_rendezvous_task())
        
        loop = asyncio.get_event_loop()
        # Republish every 2 minutes
        loop.call_later(120, self._schedule_rendezvous_republish)

    async def _cleanup_expired_rendezvous_task(self):
        """Async wrapper for cleanup."""
        self._cleanup_expired_rendezvous()

    async def _attempt_rejoin(self):
        """
        Attempt to rejoin the network when orphaned with identity regeneration fallback.
        """
        if self.rejoin_in_progress:
            log.debug("Rejoin already in progress, skipping")
            return
        
        self.rejoin_in_progress = True
        self._rejoin_attempts += 1
        
        log.warning(f"Attempting to rejoin network (attempt #{self._rejoin_attempts}/{Config.MAX_REJOIN_ATTEMPTS}, "
                f"identity regeneration #{self._identity_regeneration_count})")
        
        try:
            # Get all known neighbors
            all_neighbors = []
            for bucket in self.protocol.router.buckets:
                all_neighbors.extend(bucket.get_nodes())
            
            if not all_neighbors:
                log.error("No known neighbors to rejoin through")
                # Check if we should regenerate identity
                if self._rejoin_attempts >= Config.MAX_REJOIN_ATTEMPTS:
                    await self._regenerate_identity()
                return
            
            # Find nodes closest to us
            closest_nodes = sorted(all_neighbors, key=lambda n: self.node.distance_to(n))[:self.ksize * 3]
            
            log.info(f"Re-announcing ourselves to {len(closest_nodes)} nearby nodes")
            
            # Ping each node and verify acceptance
            verified_acceptances = []
            successful_pings = 0
            
            for node in closest_nodes:
                try:
                    # Ping the node
                    result = await self.protocol.call_ping(node)
                    if result[0]:
                        successful_pings += 1
                        log.debug(f"Successfully pinged {node.ip}:{node.port}")
                        
                        # CRITICAL: Wait a moment for their routing table to update
                        await asyncio.sleep(0.5)
                        
                        # Verify they actually added us
                        verify_result = await self.protocol.call_verify_neighbor(node, self.node.id)
                        if verify_result[0] and verify_result[1]:
                            verified_acceptances.append(node)
                            # Add to possible_responsibles with verified status
                            self.possible_responsibles[node.id] = {
                                'node': node,
                                'last_contact': time.time(),
                                'verified': True
                            }
                            self.verified_responsibles.add(node.id)
                            log.info(f"[VERIFIED] Node {node.ip}:{node.port} confirmed acceptance")
                        else:
                            log.warning(f"[REJECTED] Node {node.ip}:{node.port} did not add us to routing table")
                    else:
                        log.debug(f"Failed to ping {node.ip}:{node.port}")
                        
                    await asyncio.sleep(0.3)
                    
                except Exception as e:
                    log.debug(f"Error re-announcing to {node.ip}:{node.port}: {e}")
                    continue
            
            log.info(f"Rejoin attempt {self._rejoin_attempts}: {successful_pings} pings, "
                    f"{len(verified_acceptances)} verified acceptances")
            
            if len(verified_acceptances) >= Config.MIN_RESPONSIBLE_NODES:
                # Success - we have verified acceptances
                log.info(f"[SUCCESS] Rejoined network with {len(verified_acceptances)} verified nodes")
                self._rejoin_attempts = 0
                self.is_orphaned = False
                self.rejoin_in_progress = False
                return
            
            # Check if we should regenerate identity
            if self._rejoin_attempts >= Config.MAX_REJOIN_ATTEMPTS:
                log.warning(f"Failed to rejoin after {Config.MAX_REJOIN_ATTEMPTS} attempts - "
                        f"attempting identity regeneration")
                await self._regenerate_identity()
            else:
                # Still have attempts left with current identity
                log.warning(f"Rejoin attempt {self._rejoin_attempts} failed - "
                        f"{Config.MAX_REJOIN_ATTEMPTS - self._rejoin_attempts} attempts remaining")
                self.rejoin_in_progress = False
                
        except Exception as e:
            log.error(f"Error during rejoin attempt: {e}")
            self.rejoin_in_progress = False

    async def _regenerate_identity(self):
        """
        Regenerate node identity (new keys -> new node ID) to escape orphaned state.
        This is the last resort when repeated rejoin attempts fail.
        """
        if self._identity_regeneration_count >= Config.MAX_IDENTITY_REGENERATIONS:
            log.error(f"Reached maximum identity regenerations ({Config.MAX_IDENTITY_REGENERATIONS}). "
                    f"Network may be incompatible or node is truly isolated.")
            self.rejoin_in_progress = False
            self._rejoin_attempts = 0
            return
        
        self._identity_regeneration_count += 1
        log.warning(f"=== REGENERATING IDENTITY #{self._identity_regeneration_count}/{Config.MAX_IDENTITY_REGENERATIONS} ===")
        
        try:
            # Store original identity info on first regeneration
            if self._original_identity is None:
                self._original_identity = {
                    'node_id': self.node.id.hex(),
                    'signing_public_key': self.signing_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode()
                }
                log.info(f"Original identity: {self._original_identity['node_id'][:16]}...")
            
            # Generate new signing keys
            old_node_id = self.node.id.hex()
            self.signing_private_key, self.signing_public_key = create_ed25519_key_pair()
            
            # Generate new node ID from new public key
            new_node_id = digest(generate_peer_id(self.signing_public_key))
            old_long_id = self.node.long_id
            
            # Update node identity
            self.node.id = new_node_id
            self.node.long_id = int(new_node_id.hex(), 16)
            
            # Regenerate messaging with new keys
            self.messaging = SecureMessaging(self.signing_private_key, self.signing_public_key)
            
            # Update RWP handler with new identity
            peer_id = generate_peer_id(self.signing_public_key)
            old_rendezvous_key = self.rwp_handler.rendezvous_key
            
            # Recreate RWP handler with new identity
            self.rwp_handler.stop_rwp_server()
            self.rwp_handler = RWPDHTHandler(
                peer_id,
                self.messaging,
                self.epoch_manager,
                self.protocol.router if self.protocol else None
            )
            self.rwp_handler.start_rwp_server(self.rwp_port)
            
            # Update protocol's source node
            if self.protocol:
                self.protocol.source_node = self.node
                self.protocol.rwp_handler = self.rwp_handler
            
            # Update node in existing connections
            self.node.rendezvous_key = self.rwp_handler.rendezvous_key
            
            # Clear orphan tracking
            self._rejoin_attempts = 0
            self.possible_responsibles.clear()
            self.verified_responsibles.clear()
            
            log.warning(f"Identity regenerated:")
            log.warning(f"  Old ID: {old_node_id[:16]}... (long_id: {old_long_id})")
            log.warning(f"  New ID: {new_node_id.hex()[:16]}... (long_id: {self.node.long_id})")
            log.warning(f"  Old rendezvous: {old_rendezvous_key}")
            log.warning(f"  New rendezvous: {self.rwp_handler.rendezvous_key}")
            
            # Wait a moment for RWP server to stabilize
            await asyncio.sleep(1)
            
            # Attempt to rejoin with new identity
            log.info("Attempting rejoin with new identity...")
            self.rejoin_in_progress = False  # Reset flag so rejoin can proceed
            await self._attempt_rejoin()
            
        except Exception as e:
            log.error(f"Error during identity regeneration: {e}")
            self.rejoin_in_progress = False
            self._rejoin_attempts = 0

    async def search_node(self, node_id: str) -> SearchResult:
        """
        Search for a node by its Node ID using iterative search.
        
        Args:
            node_id: Hexadecimal string of the target node ID
            
        Returns:
            SearchResult with details about the search
        """
        try:
            # Convert hex string to bytes
            target_node_id = bytes.fromhex(node_id)
            
            # Create and execute search
            searcher = NodeSearch(
                self.protocol,
                target_node_id,
                max_hops=Config.SEARCH_MAX_HOPS,
                timeout=Config.SEARCH_TIMEOUT,
                alpha=Config.SEARCH_PARALLELISM
            )
            
            result = await searcher.search()
            
            return result
            
        except ValueError as e:
            log.error(f"Invalid node ID format: {e}")
            return SearchResult(
                found=False,
                target_node=None,
                hops=0,
                path=[],
                search_time=0,
                nodes_queried=0
            )
        except Exception as e:
            log.error(f"Search failed: {e}")
            return SearchResult(
                found=False,
                target_node=None,
                hops=0,
                path=[],
                search_time=0,
                nodes_queried=0
            )

    def _schedule_sync_heartbeat(self):
        """Schedule the next synchronized heartbeat."""
        if not self.running:
            return
            
        log.debug("Synchronized heartbeat check starting")
        asyncio.ensure_future(self._synchronized_heartbeat_check())
        
        # Schedule next sync exactly 1 minute later
        loop = asyncio.get_event_loop()
        self.heartbeat_loop = loop.call_later(self.HEARTBEAT_SYNC_INTERVAL, self._schedule_sync_heartbeat)
        
    def _cleanup_outstanding_futures(self):
        """Clean up outstanding futures to prevent InvalidStateError."""
        try:
            if hasattr(self.protocol, '_outstanding'):
                for mid, (future, timeout_handle) in list(self.protocol._outstanding.items()):
                    try:
                        if future.done() or future.cancelled():
                            timeout_handle.cancel()
                            del self.protocol._outstanding[mid]
                        elif not future.done():
                            # Cancel pending futures during cleanup
                            timeout_handle.cancel()
                            if not future.cancelled():
                                future.set_result((False, None))
                            del self.protocol._outstanding[mid]
                    except Exception as e:
                        log.debug(f"Error cleaning up future {mid}: {e}")
                        # Force removal even if there's an error
                        try:
                            timeout_handle.cancel()
                            del self.protocol._outstanding[mid]
                        except:
                            pass
        except Exception as e:
            log.debug(f"Error in cleanup_outstanding_futures: {e}")

    async def _synchronized_heartbeat_check(self):
        """Enhanced sequential heartbeat with adaptive timing."""
        if not self.running or not self.protocol:
            return
        
        all_nodes = []
        for bucket in self.protocol.router.buckets:
            all_nodes.extend(bucket.get_nodes())
        
        if not all_nodes:
            log.debug("No nodes in routing table for heartbeat check")
            return
        
        log.debug(f"Adaptive sequential heartbeat check for {len(all_nodes)} nodes")
        
        # Adaptive stagger based on network conditions
        node_hash = int(self.node.id.hex()[:8], 16)
        base_stagger = (node_hash % 2000) / 1000.0
        adaptive_stagger = base_stagger * self.network_conditions['congestion_factor']
        
        if adaptive_stagger > 0:
            log.debug(f"Adaptive staggering heartbeat by {adaptive_stagger:.3f}s")
            await asyncio.sleep(adaptive_stagger)
        
        successful_pings = 0
        
        for i, node in enumerate(all_nodes):
            try:
                result = await self._safe_heartbeat_ping(node)
                
                if result and result[0]:  # Successful ping
                    successful_pings += 1
                    node.touch()
                    self.failed_nodes.pop(node.id, None)
                    log.debug(f"Heartbeat ping successful to {node.ip}:{node.port}")
                else:
                    self._handle_ping_failure(node)
                    log.debug(f"Heartbeat ping failed to {node.ip}:{node.port}")
                
                # Use adaptive delay between pings
                if result and result[0]:
                    delay = self._get_adaptive_delay(0.2)  # Base 200ms for success
                else:
                    delay = self._get_adaptive_delay(0.5)  # Base 500ms for failure
                
                await asyncio.sleep(delay)
                    
            except Exception as e:
                log.warning(f"Exception during heartbeat ping to {node.ip}:{node.port}: {e}")
                self._handle_ping_failure(node)
                await asyncio.sleep(self._get_adaptive_delay(0.5))
        
        log.info(f"Adaptive heartbeat completed: {successful_pings}/{len(all_nodes)} nodes responded "
                f"(avg_ping: {self.network_conditions['avg_ping_time']:.2f}s)")
        
        self._remove_failed_nodes()

    async def _safe_heartbeat_ping(self, node):
        """Enhanced heartbeat ping with network condition tracking."""
        ping_start_time = time.time()
        try:
            # Use adaptive timeout based on network conditions
            adaptive_timeout = max(3.0, self.network_conditions['avg_ping_time'] * 3)
            
            ping_future = self.protocol.ping(
                (node.ip, node.port), 
                self.node.id, 
                self.node.rwp_port
            )
            
            result = await asyncio.wait_for(ping_future, timeout=adaptive_timeout)
            
            # Track successful ping
            ping_duration = time.time() - ping_start_time
            self._update_network_conditions(ping_duration, True)
            
            return result
            
        except asyncio.TimeoutError:
            ping_duration = time.time() - ping_start_time
            self._update_network_conditions(ping_duration, False)
            log.debug(f"Adaptive heartbeat ping timed out to {node.ip}:{node.port} after {ping_duration:.2f}s")
            return (False, None)
        except Exception as e:
            ping_duration = time.time() - ping_start_time
            self._update_network_conditions(ping_duration, False)
            log.debug(f"Adaptive heartbeat ping error to {node.ip}:{node.port}: {e}")
            return (False, None)
        finally:
            self._cleanup_outstanding_futures()

    def _handle_ping_failure(self, node):
        """Handle a failed ping during heartbeat with improved tracking."""
        node_id = node.id
        current_failures = self.failed_nodes.get(node_id, 0) + 1
        self.failed_nodes[node_id] = current_failures
        
        log.debug(f"Node {node.ip}:{node.port} failed heartbeat ({current_failures}/{self.MAX_FAILURES_BEFORE_REMOVAL})")
        
        # Update node's failed ping counter
        node.failed_pings = current_failures
        
        # If this is the first failure, log it as a warning
        if current_failures == 1:
            log.warning(f"First heartbeat failure for {node.ip}:{node.port}")
        elif current_failures >= self.MAX_FAILURES_BEFORE_REMOVAL:
            log.error(f"Node {node.ip}:{node.port} has failed {current_failures} heartbeats - will be removed")

    def _remove_failed_nodes(self):
        """Remove nodes that have failed too many heartbeat checks with improved logging."""
        nodes_to_remove = []
        
        # Find nodes that need to be removed
        for node_id, failure_count in list(self.failed_nodes.items()):
            if failure_count >= self.MAX_FAILURES_BEFORE_REMOVAL:
                # Find the node in routing table
                for bucket in self.protocol.router.buckets:
                    node = bucket[node_id]
                    if node:
                        nodes_to_remove.append((node, failure_count))
                        break
        
        # Remove the failed nodes
        removed_count = 0
        for node, failure_count in nodes_to_remove:
            try:
                log.warning(f"Removing failed node after {failure_count} heartbeat failures: {node.ip}:{node.port}")
                self.protocol.router.remove_contact(node)
                self.failed_nodes.pop(node.id, None)
                removed_count += 1
            except Exception as e:
                log.error(f"Error removing failed node {node.ip}:{node.port}: {e}")
        
        if removed_count > 0:
            log.info(f"Removed {removed_count} failed nodes from routing table")
            # Log current routing table size
            total_nodes = sum(len(bucket) for bucket in self.protocol.router.buckets)
            log.info(f"Routing table now has {total_nodes} nodes")
        
        return removed_count

    def _start_key_rotation_monitor(self):
        """Start monitoring for epoch changes and key rotation."""
        def rotation_monitor():
            last_epoch = self.epoch_manager.get_current_epoch()
            while self.running:
                try:
                    current_epoch = self.epoch_manager.get_current_epoch()
                    if current_epoch > last_epoch:
                        log.info(f"Epoch changed from {last_epoch} to {current_epoch}")
                        # Update rendezvous key
                        old_key = self.rwp_handler.rendezvous_key
                        self.rwp_handler.rendezvous_key = self.rwp_handler._generate_rendezvous_key()
                        log.info(f"Rendezvous key rotated: {old_key} -> {self.rwp_handler.rendezvous_key}")
                        last_epoch = current_epoch
                    time.sleep(30)  # Check every 30 seconds
                except Exception as e:
                    log.error(f"Error in key rotation monitor: {e}")
                    time.sleep(60)
        
        self.key_rotation_thread = threading.Thread(target=rotation_monitor, daemon=True)
        self.key_rotation_thread.start()

    def refresh_table(self, interval=3600):
        """Refresh the routing table at regular intervals."""
        if not self.running:
            return
            
        log.debug("Refreshing routing table")
        asyncio.ensure_future(self._refresh_table())
        loop = asyncio.get_event_loop()
        self.refresh_loop = loop.call_later(interval, self.refresh_table)

    async def _refresh_table(self):
        """Refresh buckets"""
        if not self.running:
            return
            
        results = []
        for node_id in self.protocol.get_refresh_ids():
            node = Node(node_id)
            nearest = self.protocol.router.find_neighbors(node, self.alpha)
            spider = NodeSpiderCrawl(
                self.protocol, node, nearest, self.ksize, self.alpha
            )
            results.append(spider.find())

        # Do our crawling
        await asyncio.gather(*results)

    async def bootstrap(self, addrs):
        """
        Bootstrap the server by connecting to other known nodes in the network.

        Args:
            addrs: A list of (ip, port, rwp_port) tuples
        """
        log.debug("Attempting to bootstrap node with %i initial contacts", len(addrs))
        cos = list(map(self.bootstrap_node, addrs))
        gathered = await asyncio.gather(*cos)
        nodes = [node for node in gathered if node is not None]
        spider = NodeSpiderCrawl(
            self.protocol, self.node, nodes, self.ksize, self.alpha
        )
        return await spider.find()

    async def bootstrap_node(self, addr):
        """Bootstrap connection to a single node with duplicate prevention."""
        if len(addr) == 2:
            ip, port = addr
            rwp_port = port + 363  # Default RWP port
        elif len(addr) == 3:
            ip, port, rwp_port = addr
        else:
            log.error(f"Invalid address format: {addr}")
            return None
        
        # Check if we already know about this node
        for bucket in self.protocol.router.buckets:
            for existing_node in bucket.get_nodes():
                if existing_node.ip == ip and existing_node.port == port:
                    log.debug(f"Already know bootstrap node {ip}:{port}, returning existing")
                    return existing_node
        
        log.debug(f"Bootstrapping node {ip}:{port} (RWP: {rwp_port})")
            
        # Try RWP first
        node_info = self.rwp_handler.get_node_info(ip, rwp_port)
        if node_info:
            node_id = bytes.fromhex(node_info.node_id)
            node = Node(node_id, ip, port, rwp_port, node_info.rendezvous_key)
            log.debug(f"Bootstrap via RWP successful: {node}")
            return node
        
        # Fallback to traditional ping
        log.debug(f"Trying UDP ping for bootstrap")
        result = await self.protocol.ping((ip, port), self.node.id)
        log.debug(f"Bootstrap ping result: {result}")
        return Node(result[1], ip, port, rwp_port) if result[0] else None

    def bootstrappable_neighbors(self):
        """Get a list of (ip, port, rwp_port) tuples suitable for bootstrapping."""
        neighbors = self.protocol.router.find_neighbors(self.node)
        seen_addresses = set()
        unique_neighbors = []
        
        for n in neighbors:
            if n.ip and n.port:
                address_key = (n.ip, n.port)
                if address_key not in seen_addresses:
                    seen_addresses.add(address_key)
                    unique_neighbors.append((n.ip, n.port, n.rwp_port))
        
        return unique_neighbors

    def save_state(self, fname):
        log.info("Saving state to %s", fname)
        
        # Get signing keys in serializable format
        signing_private_pem = self.signing_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        signing_public_pem = self.signing_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        data = {
            "ksize": self.ksize,
            "alpha": self.alpha,
            "id": self.node.id.hex(),
            "signing_private_key": signing_private_pem,
            "signing_public_key": signing_public_pem,
            "neighbors": self.bootstrappable_neighbors(),
            "rwp_port": self.rwp_port,
            "epoch": self.epoch_manager.get_current_epoch(),
            "rendezvous_key": self.rwp_handler.rendezvous_key
        }
        
        if not data["neighbors"]:
            log.warning("No known neighbors, so not writing to cache.")
            return
            
        with open(fname, "wb") as file:
            pickle.dump(data, file)

    @classmethod
    async def load_state(cls, fname, port, interface="0.0.0.0", rwp_port=None):
        """Load the state of this node from a cache file and start listening."""
        log.info("Loading state from %s", fname)
        
        with open(fname, "rb") as file:
            data = pickle.load(file)
        
        # Reconstruct signing keys
        signing_private_key = serialization.load_pem_private_key(
            data["signing_private_key"].encode(),
            password=None,
            backend=default_backend()
        )
        signing_public_key = serialization.load_pem_public_key(
            data["signing_public_key"].encode(),
            backend=default_backend()
        )
        
        # Create server instance
        svr = cls(
            ksize=data["ksize"],
            alpha=data["alpha"],
            node_id=bytes.fromhex(data["id"]),
            signing_keys=(signing_private_key, signing_public_key),
            rwp_port=data.get("rwp_port", rwp_port)
        )
        
        # Start listening
        await svr.listen(port, interface, rwp_port or data.get("rwp_port"))
        
        # Bootstrap if we have neighbors
        if data["neighbors"]:
            await svr.bootstrap(data["neighbors"])
            
        return svr

    def save_state_regularly(self, fname, frequency=600):
        """Save the state of node regularly to the given filename."""
        if not self.running:
            return
            
        self.save_state(fname)
        loop = asyncio.get_event_loop()
        self.save_state_loop = loop.call_later(
            frequency, self.save_state_regularly, fname, frequency
        )

    def get_debug_info(self):
        """Get comprehensive debug information"""
        basic_info = {
            "node_info": {
                "node_id": self.node.id.hex(),
                "long_id": self.node.long_id,
                "ip": self.node.ip,
                "port": self.node.port,
                "rwp_port": self.rwp_port,
                "rendezvous_key": self.rwp_handler.rendezvous_key if self.rwp_handler else None
            },
            "epoch_info": {
                "current_epoch": self.epoch_manager.get_current_epoch(),
                "storage_epochs": self.epoch_manager.get_storage_epochs(),
                "retrieval_epochs": self.epoch_manager.get_retrieval_epochs()
            },
            "responsible_node_info": {
                "possible_responsibles_count": len(self.possible_responsibles),
                "verified_responsibles_count": len(self.verified_responsibles),
                "verified_node_ids": [node_id.hex() for node_id in self.verified_responsibles],
                "possible_responsibles": [
                    {
                        "node_id": node_id.hex(),
                        "ip": info['node'].ip,
                        "port": info['node'].port,
                        "last_contact": info['last_contact'],
                        "seconds_since_contact": int(time.time() - info['last_contact']),
                        "verified": info['verified']
                    }
                    for node_id, info in self.possible_responsibles.items()
                ],
                "is_orphaned": self.is_orphaned,
                "rejoin_in_progress": self.rejoin_in_progress,
                "last_check": self.last_responsible_check,
                "seconds_since_check": int(time.time() - self.last_responsible_check) if self.last_responsible_check else None
            },
            "rwp_info": {
                "node_info_cache_size": len(self.rwp_handler.node_info_cache) if self.rwp_handler else 0,
                "cached_nodes": list(self.rwp_handler.node_info_cache.keys()) if self.rwp_handler else []
            },
            "identity_info": {
                "current_node_id": self.node.id.hex(),
                "identity_regeneration_count": self._identity_regeneration_count,
                "rejoin_attempts": self._rejoin_attempts,
                "original_identity": self._original_identity['node_id'][:16] + "..." 
                                if self._original_identity else "current",
                "max_regenerations": Config.MAX_IDENTITY_REGENERATIONS,
                "max_rejoin_attempts": Config.MAX_REJOIN_ATTEMPTS
            }
        }
        
        # Get enhanced routing info
        if self.protocol:
            routing_info = self.protocol.router.get_detailed_routing_info()
            health_report = self.protocol.router.analyze_routing_health()
            
            basic_info["routing_info"] = {
                "total_buckets": routing_info['total_buckets'],
                "total_nodes": routing_info['total_nodes'], 
                "total_replacement_nodes": routing_info['total_replacement_nodes'],
                "lonely_buckets": routing_info['lonely_buckets'],
                "stale_nodes": routing_info['stale_nodes'],
                "failed_nodes": routing_info['failed_nodes'],
                "node_distribution": routing_info['node_distribution'],
                "health": health_report
            }
            
            # Add detailed bucket info
            basic_info["detailed_buckets"] = routing_info['buckets']
            
            # Add neighbor summary
            all_neighbors = []
            for bucket_info in routing_info['buckets']:
                for node in bucket_info['nodes']:
                    neighbor_summary = {
                        'id': node['id'],
                        'ip': node['ip'],
                        'port': node['port'],
                        'rwp_port': node['rwp_port'],
                        'rendezvous_key': node['rendezvous_key'],
                        'distance': node['distance_to_self'],
                        'last_seen': node['last_seen'],
                        'is_stale': node['is_stale'],
                        'failed_pings': node['failed_pings'],
                        'bucket_index': bucket_info['index']
                    }
                    all_neighbors.append(neighbor_summary)
            
            # Sort neighbors by distance
            all_neighbors.sort(key=lambda x: x['distance'])
            basic_info["all_neighbors"] = all_neighbors
            basic_info["total_neighbors"] = len(all_neighbors)
            
            # Add closest neighbors summary
            basic_info["closest_neighbors"] = all_neighbors[:10]
            
        else:
            basic_info["routing_info"] = {
                "total_buckets": 0,
                "total_nodes": 0,
                "lonely_buckets": 0
            }
            basic_info["all_neighbors"] = []
            basic_info["total_neighbors"] = 0
        
        return basic_info

    def get_rendezvous_key(self):
        """Get the current rendezvous key."""
        return self.rwp_handler.rendezvous_key if self.rwp_handler else None

    def get_rwp_url(self, content=""):
        """Get the RWP URL for this node."""
        if self.rwp_handler and self.rwp_handler.rendezvous_key:
            return f"rwp://{self.rwp_handler.rendezvous_key}/{content}"
        return None

    def find_node_by_rendezvous_key(self, rendezvous_key):
        """Find nodes in routing table by rendezvous key."""
        if not self.protocol:
            return []
            
        matching_nodes = []
        for bucket in self.protocol.router.buckets:
            for node in bucket.get_nodes():
                if node.rendezvous_key == rendezvous_key:
                    matching_nodes.append(node)
        
        return matching_nodes

    async def ping_node(self, ip, port, rwp_port=None):
        """Ping a specific node and return node information if successful."""
        if rwp_port:
            # Try RWP first
            node_info = self.rwp_handler.get_node_info(ip, rwp_port)
            if node_info:
                return {
                    "success": True,
                    "method": "rwp",
                    "node_id": node_info.node_id,
                    "rendezvous_key": node_info.rendezvous_key,
                    "epoch": node_info.epoch
                }
        
        # Fallback to traditional ping
        try:
            result = await self.protocol.ping((ip, port), self.node.id)
            if result[0]:
                return {
                    "success": True,
                    "method": "udp",
                    "node_id": result[1].hex()
                }
        except Exception as e:
            log.error(f"Ping failed: {e}")
        
        return {"success": False}

# ============================================================================
# ENHANCED RWP PROTOCOL HANDLER FOR DHT OPERATIONS
# ============================================================================

class RWPDHTHandler(RWPProtocolHandler):
    """Enhanced RWP handler with DHT operation support."""
    
    def __init__(self, node_id: str, messaging: SecureMessaging, 
                epoch_manager: EpochManager, router):
        """Enhanced RWP handler."""
        super().__init__(node_id, messaging, epoch_manager)
        self.router = router
    
    def _handle_rendezvous_request(self, client_socket: socket.socket, 
                                 request_str: str, method: str, path: str):
        """Handle encrypted rendezvous request with DHT operations."""
        try:
            # Extract request body for POST requests
            if method == "POST" and "\r\n\r\n" in request_str:
                headers, body = request_str.split("\r\n\r\n", 1)
                request_data = json.loads(body)
                
                # Decrypt message
                encrypted_data = base64.b64decode(request_data['encrypted_data'])
                sender_exchange_key = serialization.load_pem_public_key(
                    request_data['sender_exchange_key'].encode(),
                    backend=default_backend()
                )
                
                decrypted_message = self.messaging.decrypt_message(
                    encrypted_data, sender_exchange_key
                )
                
                # Handle different message types
                message_type = MessageType(decrypted_message['type'])
                response_data = self._handle_dht_message(message_type, decrypted_message)
                
                # Encrypt response
                encrypted_response = self.messaging.encrypt_message(
                    response_data, sender_exchange_key
                )
                
                response_body = {
                    'encrypted_data': base64.b64encode(encrypted_response).decode(),
                    'message_id': decrypted_message['message_id'],
                    'timestamp': time.time()
                }
                
                self._send_rwp_response(
                    client_socket, 200, 
                    json.dumps(response_body), 
                    'application/json'
                )
                
        except Exception as e:
            log.error(f"Error handling rendezvous request: {e}")
            self._send_rwp_error(client_socket, 500, "Internal Server Error")
    
    def _handle_dht_message(self, message_type: MessageType, message: Dict) -> Dict:
        """Handle DHT messages - ONLY ROUTING OPERATIONS."""
        payload = message['payload']
        
        if message_type == MessageType.PING or message_type == MessageType.HEARTBEAT:
            return {
                'type': MessageType.PONG.value,
                'sender_id': self.node_id,
                'payload': {
                    'timestamp': time.time(),
                    'node_id': self.node_id
                },
                'timestamp': time.time(),
                'message_id': os.urandom(16).hex()
            }
            
        elif message_type == MessageType.FIND_NODE:
            key_bytes = bytes.fromhex(payload['key'])
            node = Node(key_bytes)
            neighbors = self.router.find_neighbors(node)
            
            return {
                'type': 'find_node_response',
                'sender_id': self.node_id,
                'payload': {
                    'success': True,
                    'nodes': [
                        {
                            'id': n.id.hex(),
                            'ip': n.ip,
                            'port': n.port,
                            'rwp_port': n.rwp_port,
                            'rendezvous_key': n.rendezvous_key
                        }
                        for n in neighbors
                    ]
                },
                'timestamp': time.time(),
                'message_id': os.urandom(16).hex()
            }
            
        elif message_type == MessageType.DHT_GET:
            # Handle GET request
            try:
                key_hash = bytes.fromhex(payload['key'])
                
                # Check local storage
                value = None
                if hasattr(self.router.protocol, 'server_ref'):
                    server = self.router.protocol.server_ref
                    if hasattr(server, '_rendezvous_storage'):
                        value = server._rendezvous_storage.get(key_hash)
                
                return {
                    'type': 'dht_get_response',
                    'sender_id': self.node_id,
                    'payload': {
                        'success': True,
                        'found': value is not None,
                        'value': json.dumps(value) if value else None
                    },
                    'timestamp': time.time(),
                    'message_id': os.urandom(16).hex()
                }
                
            except Exception as e:
                log.error(f"Error handling DHT_GET: {e}")
                return {
                    'type': 'error',
                    'sender_id': self.node_id,
                    'payload': {
                        'success': False,
                        'message': str(e)
                    },
                    'timestamp': time.time(),
                    'message_id': os.urandom(16).hex()
                }
        
        elif message_type == MessageType.DHT_SET:
            # Handle SET request
            try:
                key_hash = bytes.fromhex(payload['key'])
                value = json.loads(payload['value'])
                
                # Store locally
                success = False
                if hasattr(self.router.protocol, 'server_ref'):
                    server = self.router.protocol.server_ref
                    if not hasattr(server, '_rendezvous_storage'):
                        server._rendezvous_storage = {}
                    
                    server._rendezvous_storage[key_hash] = value
                    success = True
                    log.info(f"Stored rendezvous key {value.get('rendezvous_key')} locally")
                
                return {
                    'type': 'dht_set_response',
                    'sender_id': self.node_id,
                    'payload': {
                        'success': success
                    },
                    'timestamp': time.time(),
                    'message_id': os.urandom(16).hex()
                }
                
            except Exception as e:
                log.error(f"Error handling DHT_SET: {e}")
                return {
                    'type': 'error',
                    'sender_id': self.node_id,
                    'payload': {
                        'success': False,
                        'message': str(e)
                    },
                    'timestamp': time.time(),
                    'message_id': os.urandom(16).hex()
                }

        else:
            return {
                'type': 'error',
                'sender_id': self.node_id,
                'payload': {
                    'success': False,
                    'message': f'Unknown message type: {message_type.value}'
                },
                'timestamp': time.time(),
                'message_id': os.urandom(16).hex()
            }
    
    def _get_epoch_key(self, key, epoch):
        """Generate epoch-specific key."""
        epoch_data = f"{key.hex()}:epoch:{epoch}"
        return digest(epoch_data)

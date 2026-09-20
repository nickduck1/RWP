import socket
import json
import select
import os
import time
import threading
import ssl
import re
import hmac
import struct
import random
import hashlib
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
import queue
import subprocess
import logging
from typing import List, Optional, Tuple, Dict, Any

log = logging.getLogger(__name__)

# ============================================================================
# RRKDHT Subprocess Communicator
# Wraps rrkdht.exe ("Rotating Rendezvous Kademlia DHT") over stdin/stdout so
# this server can be found by its rendezvous key instead of a fixed IP.
# rrkdht.exe must sit in the same directory as this script.
# ============================================================================
RRKDHT_EXE = "rrkdht.exe"
RRKDHT_SENTINEL = "__RRKDHT_CMD_END_a1b2c3__"        # Marks end of command output
RRKDHT_READY_MARKER = "__RRKDHT_READY_d4e5f6__"      # Marks end of startup banner

# Hardcoded candidate DHT UDP ports. Used two ways: (1) to auto-detect a
# free port for OUR OWN node to listen on, so nobody has to be asked for
# one, and (2) to probe a bootstrap IP for a legitimate RRKDHT node on,
# so nobody has to be asked for that port either.
RRKDHT_PORT_CANDIDATES = [9000, 9001, 9002, 9003, 9004]

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class RRKDHTNode:
    """
    Wraps a single rrkdht.exe subprocess.
    Commands are queued and sent to stdin; responses are read from stdout
    and delivered back via output_queue.

    Use .query(cmd) for simple synchronous request/response calls
    (key, id, resolve, lookup, status, ...) -- it takes care of locking so
    calls from multiple threads don't interleave with each other.
    """

    def __init__(self, node_id: int, base_ip: str, base_dht_port: int,
                 base_rwp_port: Optional[int] = None, ksize: int = 10,
                 no_publish: bool = False):
        self.node_id = node_id
        self.base_ip = base_ip
        self.dht_port = base_dht_port + node_id
        # base_rwp_port=None means "this node hosts nothing findable"
        self.rwp_port = (base_rwp_port + node_id) if base_rwp_port else None
        self.ksize = ksize
        self.no_publish = no_publish

        # Subprocess handles
        self.proc: Optional[subprocess.Popen] = None
        self.reader_thread: Optional[threading.Thread] = None
        self.running = False

        # Bootstrap peers passed on startup
        self.bootstrap_addresses: List[Tuple[str, int, int]] = []

        # Thread-safe I/O queues
        self.command_queue: queue.Queue = queue.Queue()
        self.output_queue: queue.Queue = queue.Queue()

        # Serializes query() round-trips so concurrent callers don't read
        # each other's answers.
        self._query_lock = threading.Lock()

        # Metadata parsed from the startup banner
        self.node_info = {
            'node_id_hex': None,
            'rendezvous_key': None,
            'long_id': None,
            'bootstrap_count': None,   # set from "Bootstrapped with N nodes" -- None if no bootstrap was attempted
            'status': 'INITIALIZING'
        }

        # Synchronisation primitives
        self._ready_event = threading.Event()      # Set when READY_MARKER seen
        self._collecting = threading.Event()       # True while capturing cmd output
        self._cmd_buffer: List[str] = []           # Lines between command and SENTINEL
        self._buffer_lock = threading.Lock()
        self._startup_lines: List[str] = []        # Every line seen before READY (for diagnostics)

    # ------------------------------------------------------------------
    # Lifecycle - start the binary
    # ------------------------------------------------------------------
    def start(self, bootstrap_addresses: List[Tuple[str, int, int]] = None, timeout: float = None):
        """Spawn rrkdht.exe and begin the reader/dispatcher threads."""
        if self.running:
            log.warning(f"Node {self.node_id} is already running")
            return

        self.bootstrap_addresses = bootstrap_addresses or []

        # Build command line:
        #   rrkdht.exe <dht_port> [rwp_port] --ksize N [--bootstrap ip:port[:rwp]]... [--no-publish]
        cmd = [RRKDHT_EXE, str(self.dht_port)]
        if self.rwp_port:
            cmd.append(str(self.rwp_port))
        cmd.extend(["--ksize", str(self.ksize)])
        cmd.extend(["--require-sigs"])
        for ip, dport, rport in self.bootstrap_addresses:
            if rport and rport > 0:
                cmd.extend(["--bootstrap", f"{ip}:{dport}:{rport}"])
            else:
                cmd.extend(["--bootstrap", f"{ip}:{dport}"])
        if self.no_publish:
            cmd.append("--no-publish")

        # Always printed (not just logged) -- this is the #1 thing to check
        # when a node fails to start: a blank/garbled --bootstrap value
        # here means the bootstrap IP/port you entered was bad.
        print(f"[RRKDHT] Launching: {' '.join(cmd)}")
        log.info(f"Starting Node {self.node_id}: {' '.join(cmd)}")

        env = os.environ.copy()
        env['RRKDHT_LOG_LEVEL'] = env.get('RRKDHT_LOG_LEVEL', 'ERROR')

        try:
            self.proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
        except FileNotFoundError:
            self.node_info['status'] = f'ERROR: {RRKDHT_EXE} not found in {os.getcwd()}'
            log.error(self.node_info['status'])
            return
        except Exception as e:
            self.node_info['status'] = f'ERROR: {e}'
            log.error(f"Failed to start node {self.node_id}: {e}")
            return

        self.running = True
        self.node_info['status'] = 'STARTING'

        self.reader_thread = threading.Thread(
            target=self._reader_loop, daemon=True, name=f"NodeReader-{self.node_id}")
        self.reader_thread.start()

        threading.Thread(
            target=self._command_dispatcher, daemon=True, name=f"NodeCmd-{self.node_id}").start()

        # Poll responsively instead of blocking a flat window: if the
        # process crashes immediately we find out immediately. The window
        # itself is wider when bootstrapping, since rrkdht.exe blocks
        # SYNCHRONOUSLY on the bootstrap RPC (up to 15s) before it even
        # prints "Node ID:" -- this isn't async under the hood.
        wait_window = timeout if timeout is not None else (30 if self.bootstrap_addresses else 15)
        deadline = time.time() + wait_window
        while time.time() < deadline:
            if self._ready_event.wait(timeout=0.25):
                break
            if self.proc.poll() is not None:
                break

        if self._ready_event.is_set():
            self.node_info['status'] = 'RUNNING'
            log.info(f"Node {self.node_id} ready - "
                     f"ID={self.node_info['node_id_hex']}, "
                     f"RK={self.node_info['rendezvous_key']}")
        else:
            # Give the reader thread a brief moment to finish draining
            # whatever the process printed before it died.
            time.sleep(0.2)
            captured = "\n".join(self._startup_lines).strip()
            if self.proc.poll() is not None:
                exit_code = self.proc.returncode
                if captured:
                    self.node_info['status'] = f'ERROR: process exited (code {exit_code}) - {captured[:500]}'
                else:
                    self.node_info['status'] = (
                        f'ERROR: process exited (code {exit_code}) with no output. '
                        f'Try running the exact command above directly to see why '
                        f'(missing DLL, blocked by antivirus, port already in use, etc).'
                    )
            else:
                self.node_info['status'] = (
                    'ERROR: timeout waiting for ready'
                    + (f' - last output: {captured[-500:]}' if captured else ' (no output yet)')
                )
            self.running = False
            log.error(f"Node {self.node_id} failed: {self.node_info['status']}")

    # ------------------------------------------------------------------
    # stdout reader - banner parsing + command output collection
    # ------------------------------------------------------------------
    def _reader_loop(self):
        try:
            for line in self.proc.stdout:
                line = line.rstrip('\n').rstrip('\r')

                if not self._ready_event.is_set():
                    # Keep every pre-ready line (bounded) so a crash/error
                    # printed before READY still shows up somewhere instead
                    # of being silently swallowed.
                    if line:
                        self._startup_lines.append(line)
                        if len(self._startup_lines) > 60:
                            self._startup_lines.pop(0)
                    if line.startswith("Node ID:"):
                        self.node_info['node_id_hex'] = line.split(":", 1)[1].strip()
                    elif line.startswith("Rendezvous key:"):
                        self.node_info['rendezvous_key'] = line.split(":", 1)[1].strip()
                    elif line.startswith("Bootstrapped with "):
                        # e.g. "Bootstrapped with 3 nodes" / "Bootstrapped with 0 nodes"
                        # -- printed synchronously BEFORE Node ID/READY, and is
                        # the ground truth for "did we actually reach a real
                        # peer" vs. "the process just started standalone".
                        try:
                            self.node_info['bootstrap_count'] = int(line.split("Bootstrapped with ", 1)[1].split(" ")[0])
                        except (ValueError, IndexError):
                            pass
                    elif line == RRKDHT_READY_MARKER:
                        self._ready_event.set()
                    continue

                if line == RRKDHT_SENTINEL:
                    with self._buffer_lock:
                        output = "\n".join(self._cmd_buffer)
                        self._cmd_buffer = []
                    self.output_queue.put(output)
                    self._collecting.clear()

                elif self._collecting.is_set():
                    with self._buffer_lock:
                        self._cmd_buffer.append(line)

        except Exception as e:
            log.error(f"Reader thread for Node {self.node_id} error: {e}")
        finally:
            self.running = False

    # ------------------------------------------------------------------
    # stdin dispatcher - sends queued commands to the binary
    # ------------------------------------------------------------------
    def _command_dispatcher(self):
        while self.running and self.proc and self.proc.poll() is None:
            try:
                command = self.command_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if command == '__STOP__':
                try:
                    if self.proc.stdin:
                        self.proc.stdin.write("quit\n")
                        self.proc.stdin.flush()
                except Exception:
                    pass
                break

            try:
                with self._buffer_lock:
                    self._cmd_buffer = []
                self._collecting.set()

                if self.proc.stdin:
                    self.proc.stdin.write(command + "\n")
                    self.proc.stdin.flush()

            except Exception as e:
                self._collecting.clear()
                self.output_queue.put(f"Error sending command: {e}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def send_command(self, command: str):
        """Queue a command string to be sent to the binary (fire-and-forget)."""
        self.command_queue.put(command)

    def query(self, command: str, timeout: float = 20.0) -> Optional[str]:
        """Send a command and block for its response text (thread-safe)."""
        with self._query_lock:
            while True:
                try:
                    self.output_queue.get_nowait()
                except queue.Empty:
                    break
            self.send_command(command)
            try:
                return self.output_queue.get(timeout=timeout)
            except queue.Empty:
                return None

    def get_current_rendezvous_key(self, timeout: float = 10.0) -> Optional[str]:
        """Fetch our own current rendezvous key (rotates every epoch)."""
        raw = self.query("key", timeout=timeout)
        if raw is None:
            return None
        raw = raw.strip()
        return raw if raw else None

    def get_current_node_id(self, timeout: float = 10.0) -> Optional[str]:
        raw = self.query("id", timeout=timeout)
        if raw is None:
            return None
        raw = raw.strip()
        return raw if raw else None

    def bootstrap_succeeded(self) -> bool:
        """
        True if we asked to bootstrap AND actually reached at least one
        real peer (rrkdht.exe reports this synchronously via "Bootstrapped
        with N nodes" before it's even ready). False if no bootstrap was
        requested, or the target never responded (0 nodes) -- i.e. nothing
        legitimate was found at that address.
        """
        if not self.bootstrap_addresses:
            return False
        return (self.node_info.get('bootstrap_count') or 0) > 0

    def stop(self):
        """Gracefully stop the node (send 'quit', wait, kill if needed)."""
        if not self.running:
            return
        self.running = False
        self.node_info['status'] = 'STOPPED'
        self.command_queue.put('__STOP__')
        try:
            if self.proc and self.proc.stdin:
                self.proc.stdin.write("quit\n")
                self.proc.stdin.flush()
        except Exception:
            pass
        try:
            if self.proc:
                self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if self.proc:
                self.proc.kill()
        log.info(f"Node {self.node_id} stopped")

    def is_ready(self) -> bool:
        return self._ready_event.is_set()

    def is_running(self) -> bool:
        return self.running and self.proc is not None and self.proc.poll() is None



# ============================================================================
# Polymorphic UDP Signaling
# Replaces port knocking. Both client and server derive the SAME 50 UDP
# ports from the shared, rotating RRKDHT rendezvous key -- no coordination
# needed to agree on the list. Packets are shaped like real DNS
# queries/responses so they don't stand out to naive DPI, and sends are
# spread over ~10s so the pattern doesn't look like a scan.
# ============================================================================
UDP_SIGNAL_COUNT = 50
UDP_SIGNAL_RANGE = 20000  # derived ports span [base_port, base_port + UDP_SIGNAL_RANGE)

_FAKE_DOMAINS = [
    "edge-cache.net", "cdn-static.com", "media-relay.io",
    "api-gateway.cloud", "content-delivery.net", "static-assets.com",
]


def derive_udp_ports(rendezvous_key: str, base_port: int,
                      range_size: int = UDP_SIGNAL_RANGE,
                      count: int = UDP_SIGNAL_COUNT) -> List[int]:
    """Deterministically derive `count` UDP ports from a shared secret.
    Both sides run the same math on the same key and land on the exact
    same port list -- no communication needed to agree on it."""
    ports = []
    seen = set()
    i = 0
    while len(ports) < count and i < count * 8:
        h = hashlib.sha256(f"{rendezvous_key}:{base_port}:{i}".encode()).digest()
        val = int.from_bytes(h[:4], 'big')
        port = base_port + (val % range_size)
        if port not in seen and 1024 < port <= 65535:
            seen.add(port)
            ports.append(port)
        i += 1
    return ports


def _encode_dns_name(name: str) -> bytes:
    out = b''
    for label in name.split('.'):
        label_bytes = label.encode('ascii')[:63]
        out += bytes([len(label_bytes)]) + label_bytes
    return out + b'\x00'


def _decode_first_label(data: bytes, offset: int) -> Optional[str]:
    if offset >= len(data):
        return None
    length = data[offset]
    if length == 0 or length > 63:
        return None
    start = offset + 1
    end = start + length
    if end > len(data):
        return None
    try:
        return data[start:end].decode('ascii')
    except UnicodeDecodeError:
        return None


def _signal_tag(rendezvous_key: str, payload: bytes) -> bytes:
    return hmac.new(rendezvous_key.encode(), payload, hashlib.sha256).digest()[:6]


def build_signal_request(rendezvous_key: str, requested_port: int) -> bytes:
    """requested_port=0 means 'you choose'. Looks like a DNS query."""
    time_bucket = int(time.time()) // 30
    payload = struct.pack('>HI', requested_port, time_bucket)   # 6 bytes
    tag = _signal_tag(rendezvous_key, payload)                   # 6 bytes
    combined = payload + tag                                     # 12 bytes
    label = base64.b32encode(combined).decode('ascii').lower().rstrip('=')
    domain = random.choice(_FAKE_DOMAINS)
    txn_id = random.randint(0, 65535)
    header = struct.pack('>HHHHHH', txn_id, 0x0100, 1, 0, 0, 0)
    qname = _encode_dns_name(f"{label}.{domain}")
    question = qname + struct.pack('>HH', 1, 1)   # QTYPE=A, QCLASS=IN
    return header + question


def parse_signal_request(data: bytes, known_keys: List[str]) -> Optional[int]:
    """Returns requested_port if `data` is a validly-signed, fresh
    request under any of known_keys (current + previous, for rotation
    grace). Returns None if it isn't recognized as ours at all."""
    if len(data) < 13:
        return None
    label = _decode_first_label(data, 12)
    if not label:
        return None
    padded = label.upper() + '=' * (-len(label) % 8)
    try:
        combined = base64.b32decode(padded)
    except Exception:
        return None
    if len(combined) != 12:
        return None
    payload, tag = combined[:6], combined[6:]
    try:
        requested_port, time_bucket = struct.unpack('>HI', payload)
    except struct.error:
        return None
    now_bucket = int(time.time()) // 30
    if abs(now_bucket - time_bucket) > 3:   # ~90s tolerance
        return None
    for key in known_keys:
        if not key:
            continue
        expected = _signal_tag(key, payload)
        if hmac.compare_digest(expected, tag):
            return requested_port
    return None


def build_signal_response(opened_port: int) -> bytes:
    """Looks like a DNS answer; the opened port is smuggled in the
    fake A-record's 'IP address' bytes."""
    txn_id = random.randint(0, 65535)
    header = struct.pack('>HHHHHH', txn_id, 0x8180, 1, 1, 0, 0)
    domain = random.choice(_FAKE_DOMAINS)
    label = base64.b32encode(os.urandom(6)).decode('ascii').lower().rstrip('=')
    qname = _encode_dns_name(f"{label}.{domain}")
    question = qname + struct.pack('>HH', 1, 1)
    fake_ip = bytes([(opened_port >> 8) & 0xFF, opened_port & 0xFF,
                      random.randint(0, 255), random.randint(0, 255)])
    answer = b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 300, 4) + fake_ip
    return header + question + answer


def parse_signal_response(data: bytes) -> Optional[int]:
    idx = data.find(b'\xc0\x0c')
    if idx == -1:
        return None
    rdata_start = idx + 12   # pointer(2)+type(2)+class(2)+ttl(4)+rdlength(2)
    if rdata_start + 4 > len(data):
        return None
    ip_bytes = data[rdata_start:rdata_start + 4]
    return (ip_bytes[0] << 8) | ip_bytes[1]


class RWPServer:
    def __init__(self, ports=[7070, 80], host='0.0.0.0', dht_rwp_port=None):
        self.ports = ports
        self.host = host
        # rrkdht node's OWN RWP port. None = auto (UDP + 1000).
        self.dht_rwp_port = dht_rwp_port
        self.running = False
        self.sockets = []
        self.content_dir = "content"
        self.config_file = "server_config.json"
        self.private_key_file = "server_private_key.pem"

        # HTX (HTTPS Tunnel) Configuration
        self.ssl_cert_file = "server_cert.pem"
        self.ssl_key_file = "server_ssl_key.pem"
        self.enable_htx = True  # Enable HTX tunneling support

        # Dynamically-opened ports (via UDP polymorphic signaling, see below)
        self.open_ports = {}  # {port: (socket, creation_time)}
        self.open_port_sockets = []

        # Polymorphic UDP signaling configuration (replaces port knocking).
        # Both sides derive the same 50 UDP ports from the shared, rotating
        # RRKDHT rendezvous key -- no coordination needed to agree on them.
        self.udp_signal_base_port = None   # set via configure_udp_signal_port()
        self._udp_generations = []         # [(rendezvous_key, {port: socket}), ...] newest first, max 2
        self._udp_generations_lock = threading.Lock()
        
        # Track client connections per port
        self.port_client_counts = {}  # {port: count}
        self.port_client_lock = threading.Lock()

        # HTTP server info
        self.title = "testing123"
        self.contents = "long test 1234"

        # Streaming configuration
        self.chunk_size = 1024 * 1024  # 1MB chunks for streaming

        # RRKDHT (decentralized discovery) state
        self.dht: Optional[RRKDHTNode] = None
        self._dht_key_watch_thread = None
        self.current_rendezvous_key = None

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
                    json.load(f)  # Verify file is valid
                
                with open(self.private_key_file, "rb") as f:
                    private_key_data = f.read()
                    self.private_key = serialization.load_pem_private_key(
                        private_key_data,
                        password=None,
                        backend=default_backend()
                    )
                    self.public_key = self.private_key.public_key()
                
                print("Loaded existing server identity")
                return
            except Exception as e:
                print(f"Error loading server identity: {e}")
        
        # Generate new identity
        print("Generating new server identity...")
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        
        try:
            with open(self.private_key_file, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            config = {
                "host": self.host,
                "ports": self.ports,
                "htx_enabled": self.enable_htx
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            print("Saved new server identity")
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
</html>""".format(htx_status="Enabled" if self.enable_htx else "Disabled")
        
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
                            'public_key': public_pem,
                            'htx_enabled': self.enable_htx,
                            'timestamp': time.time()
                        }
                        
                        response_json = json.dumps(response_payload)
                        
                        response_headers = [
                            f"RWP/1.0 200 OK",
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
                    
                    test_request = "GET_SERVER_INFO RWP/1.0\r\n\r\n"
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
                        "ports": self.ports,
                        "htx_enabled": self.enable_htx,
                        "rendezvous_key": self.current_rendezvous_key,
                        "udp_signal_base_port": self.udp_signal_base_port
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
            <h2>Server Info:</h2>
            <p><strong>Title:</strong> {self.title}</p>
            <p><strong>Contents:</strong> {self.contents}</p>
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
            except OSError as e:
                print(f"\n!!! Could not bind HTTP config port 80: {e}")
                print("    Clients fetch server config from this port, so it's needed.")
                print("    This is usually one of:")
                print("      - Port 80 needs Administrator privileges on most systems")
                print("      - Another service (IIS, Skype, etc) is already using port 80")
                print("      - (Windows) The port falls in a range excluded for Hyper-V/WSL2 -- check with:")
                print("          netsh int ipv4 show excludedportrange protocol=tcp")
                print("    Try running as Administrator.\n")
            except Exception as e:
                print(f"HTTP server startup error: {e}")

        http_thread = threading.Thread(target=http_server_loop)
        http_thread.daemon = True
        http_thread.start()

    # ------------------------------------------------------------------
    # RRKDHT setup - join the decentralized network so clients can find
    # us by rendezvous key instead of by IP address.
    # ------------------------------------------------------------------
    def _ask_port_mode(self, label):
        """Ask manual-vs-auto for a given port. Returns True for auto-detect,
        False for manual (manual is the default -- Enter picks it)."""
        print(f"\n{label}")
        print("  1) Manually enter the port (default)")
        print("  2) Auto-detect (tries several candidate ports)")
        choice = input("Choose [1/2, Enter = 1]: ").strip()
        return choice == "2"

    def _ask_exact_port(self, prompt):
        port = 0
        while port <= 0 or port > 65535:
            raw = input(prompt).strip()
            if raw.isdigit() and 0 < int(raw) <= 65535:
                port = int(raw)
            else:
                print("Please enter a valid port number (1-65535).")
        return port

    def configure_and_start_dht(self):
        """
        Ask the operator whether this node is bootstrapping onto an
        existing RRKDHT network or starting a brand new one, then spawn
        rrkdht.exe accordingly. Because we DON'T pass --no-publish, this
        node automatically stores (and keeps re-storing, every ~2 minutes,
        under its rotating rendezvous key) its own address in the DHT --
        that's the whole point of running a server: it needs to be findable.

        Our own local DHT port is entered MANUALLY -- always. When
        joining, the bootstrap peer's port is manual by default, with
        auto-detect (a hardcoded candidate list) available as an explicit
        opt-in. Whatever port is used for bootstrapping -- typed or
        auto-detected -- is only accepted once rrkdht.exe confirms it
        actually reached a live peer there (not just that our own process
        started).

        This is asked fresh every run -- nothing about the choice is cached.
        """
        print("\n=== RRKDHT Network Setup ===")
        print("This server needs to join the RRKDHT network so clients")
        print("can find it by rendezvous key instead of a raw IP address.")
        print("  1) Join an existing network via a bootstrap node (you must provide its IP)")
        print("  2) Create a brand new network (this is the first node)")
        choice = ""
        while choice not in ("1", "2"):
            choice = input("Choose [1/2]: ").strip()

        # Ask for the rrkdht node's OWN RWP port -- the port rrkdht.exe
        # from the content server. Enter = auto: we pass nothing and
        # rrkdht.exe picks (UDP port + 1000).
        announce_port = None
        while True:
            raw = input("DHT node RWP port [Enter = auto (UDP+1000)]: ").strip()
            if raw == "":
                break
            if raw.isdigit() and 0 < int(raw) <= 65535:
                p = int(raw)
                if p in self.ports:
                    print(f"  {p} is one of your CONTENT ports -- the rrkdht node")
                    print("  would steal it from the content server. Pick a")
                    print("  different port, or press Enter for auto.")
                    continue
                announce_port = p
                break
            print("  Enter a number 1-65535, or press Enter for auto.")
        self.dht_rwp_port = announce_port
        print(f"[RRKDHT] Node RWP port: {announce_port if announce_port else 'auto (UDP + 1000)'}")

        # --- Local DHT port: manual only ---
        local_port = self._ask_exact_port("Local DHT UDP port to listen on: ")
        print(f"[RRKDHT] Trying local port {local_port}...")
        trial = RRKDHTNode(node_id=0, base_ip="0.0.0.0", base_dht_port=local_port,
                            base_rwp_port=announce_port, ksize=10, no_publish=False)
        trial.start([], timeout=10)
        if not trial.is_running():
            print(f"WARNING: Could not bind port {local_port}: {trial.node_info['status']}")
            print("The server will still run, but clients won't be able to find it by key.")
            return

        if choice == "2":
            print("Starting a brand new RRKDHT network as the first node.")
            self.dht = trial
        else:
            # Need to restart with a bootstrap peer attached, so let go of
            # the throwaway/manual instance first.
            trial.stop()

            boot_ip = ""
            while not _IPV4_RE.match(boot_ip):
                boot_ip = input("Bootstrap node IP (required, e.g. 203.0.113.5): ").strip()
                if not _IPV4_RE.match(boot_ip):
                    print("Please enter a valid IPv4 address.")

            is_loopback = boot_ip in ("127.0.0.1", "localhost", "::1")

            if self._ask_port_mode("Bootstrap peer's DHT port:"):
                candidates = [p for p in RRKDHT_PORT_CANDIDATES
                              if not (is_loopback and p == local_port)]
                print(f"Probing {boot_ip} on ports {candidates} for a live RRKDHT "
                      f"node (each attempt can take up to ~15s if unreachable)...")
                self.dht = None
                for boot_port in candidates:
                    print(f"[RRKDHT] Trying bootstrap {boot_ip}:{boot_port}...")
                    candidate = RRKDHTNode(node_id=0, base_ip="0.0.0.0",
                                            base_dht_port=local_port,
                                            base_rwp_port=announce_port, ksize=10, no_publish=False)
                    candidate.start([(boot_ip, boot_port, 0)])
                    if candidate.is_running() and candidate.bootstrap_succeeded():
                        n = candidate.node_info.get('bootstrap_count')
                        print(f"[RRKDHT] Found a live node at {boot_ip}:{boot_port} "
                              f"(joined via {n} peer(s))")
                        self.dht = candidate
                        break
                    if candidate.is_running():
                        print(f"[RRKDHT] {boot_ip}:{boot_port} started locally but nothing "
                              f"answered there -- not a live RRKDHT node, or wrong port.")
                        candidate.stop()
                    else:
                        print(f"[RRKDHT] Could not even start locally on this attempt: "
                              f"{candidate.node_info['status']}")
                if not self.dht:
                    print(f"\nWARNING: No legitimate RRKDHT node found at {boot_ip} on any "
                          f"of ports {candidates}.")
                    print("Double check the IP, and that a server is actually running there.")
                    print("The server will still run, but won't be joined to that network.")
                    return
            else:
                boot_port = self._ask_exact_port("Bootstrap node DHT port: ")
                if is_loopback and boot_port == local_port:
                    print(f"WARNING: bootstrap port {boot_port} is the same as our own "
                          f"local port -- that would just ping ourselves. Pick a "
                          f"different local port or the peer's real port.")
                    self.dht = None
                    return
                print(f"[RRKDHT] Trying bootstrap {boot_ip}:{boot_port} (this can take "
                      f"up to ~15s if unreachable)...")
                candidate = RRKDHTNode(node_id=0, base_ip="0.0.0.0", base_dht_port=local_port,
                                        base_rwp_port=announce_port, ksize=10, no_publish=False)
                candidate.start([(boot_ip, boot_port, 0)])
                if candidate.is_running() and candidate.bootstrap_succeeded():
                    n = candidate.node_info.get('bootstrap_count')
                    print(f"[RRKDHT] Reached a live node at {boot_ip}:{boot_port} (joined via {n} peer(s))")
                    self.dht = candidate
                else:
                    if candidate.is_running():
                        print(f"[RRKDHT] {boot_ip}:{boot_port} started locally but nothing "
                              f"answered there -- not a live RRKDHT node, or wrong port.")
                        candidate.stop()
                    else:
                        print(f"[RRKDHT] Could not start: {candidate.node_info['status']}")
                    print(f"\nWARNING: Could not confirm a live RRKDHT node at {boot_ip}:{boot_port}.")
                    print("Double check the IP and port -- or re-run and try auto-detect instead.")
                    print("The server will still run, but won't be joined to that network.")
                    return

        self.current_rendezvous_key = self.dht.node_info['rendezvous_key']

        print("\n=== RRKDHT Node Ready ===")
        print(f"Node ID:         {self.dht.node_info['node_id_hex']}")
        print(f"Rendezvous key:  {self.current_rendezvous_key}")
        print(f"Share with clients as:  rwp://{self.current_rendezvous_key}/")
        print("(this key rotates every ~5 minutes; rrkdht.exe re-publishes")
        print(" the new one automatically -- watch this console for updates)")
        print("==========================\n")

        # Watch for key rotation and print the new key whenever it changes,
        # so whoever is running this server always has the current key to
        # hand out to clients, and so the HTTP config (which clients poll)
        # always reports the live key.
        def _watch_key():
            last = self.current_rendezvous_key
            while self.running and self.dht and self.dht.is_running():
                time.sleep(30)
                current = self.dht.get_current_rendezvous_key(timeout=10)
                if current and current != last:
                    print(f"\n[RRKDHT] Rendezvous key rotated: {last} -> {current}")
                    print(f"[RRKDHT] Share with clients as: rwp://{current}/\n")
                    self.current_rendezvous_key = current
                    last = current
                    if self.udp_signal_base_port:
                        self.bind_udp_signal_ports()

        self._dht_key_watch_thread = threading.Thread(target=_watch_key, daemon=True)
        self._dht_key_watch_thread.start()

    def _bind_listener(self, port, purpose="RWP"):
        """Bind a TCP listener socket, with an actionable message instead of
        a raw traceback if it fails (very common on Windows: excluded port
        ranges from Hyper-V/WSL2, privileges, or another process/firewall)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, port))
            sock.listen(5)
            return sock
        except OSError as e:
            print(f"\n!!! Could not bind {purpose} port {port}: {e}")
            print("    This is usually one of:")
            print("      - Another process is already using this port")
            print("      - (Windows) The port falls in a range excluded for Hyper-V/WSL2 -- check with:")
            print("          netsh int ipv4 show excludedportrange protocol=tcp")
            print("      - Ports below 1024 need Administrator privileges")
            print("      - A firewall or antivirus is blocking it")
            print(f"    Skipping port {port}.\n")
            return None

    def configure_udp_signal_port(self):
        """Ask for the base port used to derive the 50 polymorphic UDP
        signaling ports. Asked fresh every run -- nothing here is cached."""
        print("\n=== UDP Signaling Setup ===")
        print("Clients that can't reach any TCP port (RWP ports or port 80)")
        print("fall back to spraying a signed, DNS-shaped UDP packet across")
        print("50 ports derived from the current rendezvous key. Pick the")
        print("base of the range those derived ports fall in.")
        base = 0
        while base <= 0 or base + UDP_SIGNAL_RANGE > 65535:
            raw = input(f"UDP signaling base port (a {UDP_SIGNAL_RANGE}-wide "
                        f"range starting here will be used, e.g. 40000): ").strip()
            if raw.isdigit() and 0 < int(raw) and int(raw) + UDP_SIGNAL_RANGE <= 65535:
                base = int(raw)
            else:
                print(f"Please enter a port such that base + {UDP_SIGNAL_RANGE} <= 65535.")
        self.udp_signal_base_port = base
        print(f"UDP signaling base port: {base}\n")

    def _udp_known_keys(self):
        with self._udp_generations_lock:
            return [key for key, _ in self._udp_generations]

    def bind_udp_signal_ports(self):
        """
        Derive the 50 UDP ports from the CURRENT rendezvous key and bind
        as many as possible. Called once at startup and again on every
        key rotation. Keeps at most 2 generations (current + previous)
        alive at once, mirroring RRKDHT's own rotation overlap, so a
        client that hasn't caught up to a just-rotated key yet still
        gets through.
        """
        key = self.current_rendezvous_key
        if not key or not self.udp_signal_base_port:
            return

        ports = derive_udp_ports(key, self.udp_signal_base_port)
        bound = {}
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((self.host, port))
                bound[port] = sock
            except OSError:
                continue

        if not bound:
            print("WARNING: could not bind ANY UDP signaling port -- clients "
                  "with no direct TCP path won't be able to reach this server.")
        else:
            print(f"[UDP signal] Bound {len(bound)}/{len(ports)} derived ports "
                  f"for key {key[:8]}...")

        with self._udp_generations_lock:
            self._udp_generations.insert(0, (key, bound))
            while len(self._udp_generations) > 2:
                _, old_sockets = self._udp_generations.pop()
                for s in old_sockets.values():
                    try:
                        s.close()
                    except Exception:
                        pass

    def udp_signal_listener(self):
        """Background loop: listen across every bound UDP signal socket
        (both current and previous key's generation), validate incoming
        packets, and open whatever port was legitimately requested."""
        while self.running:
            with self._udp_generations_lock:
                all_socks = [s for _, gen in self._udp_generations for s in gen.values()]
            if not all_socks:
                time.sleep(1.0)
                continue

            readable, _, _ = select.select(all_socks, [], [], 1.0)
            for sock in readable:
                try:
                    data, addr = sock.recvfrom(512)
                except Exception:
                    continue

                requested_port = parse_signal_request(data, self._udp_known_keys())
                if requested_port is None:
                    continue  # not one of ours (or replayed/stale) -- silently drop

                ip = addr[0]
                if requested_port == 0:
                    # "you choose" -- hand back a live default port if we
                    # have one, otherwise open a fresh ephemeral one.
                    actual_port = self.ports[0] if self.ports else None
                    if actual_port is None:
                        actual_port = random.randint(30000, 39999)
                        self.open_port(actual_port)
                    print(f"[UDP signal] {ip} asked for any port -> offering {actual_port}")
                else:
                    if self.is_port_running_rwp(requested_port):
                        actual_port = requested_port
                    else:
                        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        test_sock.settimeout(1)
                        in_use = test_sock.connect_ex((self.host, requested_port)) == 0
                        test_sock.close()
                        if in_use:
                            print(f"[UDP signal] {ip} requested port {requested_port}, "
                                  f"but it's used by something else -- ignoring")
                            continue
                        self.open_port(requested_port)
                        actual_port = requested_port
                    print(f"[UDP signal] {ip} requested port {requested_port} -> opened")

                try:
                    sock.sendto(build_signal_response(actual_port), addr)
                except Exception:
                    pass

    def start(self):
        """Start the RWP server on multiple ports"""
        self.running = True

        # Join the RRKDHT network first -- we need a rendezvous key before
        # we can derive the UDP signaling ports from it.
        self.configure_and_start_dht()

        # Ask for the UDP signaling base port, then derive+bind the 50
        # ports from it and the current rendezvous key.
        self.configure_udp_signal_port()
        self.bind_udp_signal_ports()

        # Initialize client counts for all ports
        with self.port_client_lock:
            for port in self.ports:
                self.port_client_counts[port] = 0

        # Start HTTP server on port 80
        self.start_http_server()

        # Create server sockets for each port
        for port in self.ports:
            sock = self._bind_listener(port, purpose="RWP")
            if sock is None:
                continue
            self.sockets.append(sock)
            print(f"RWP Server listening on {self.host}:{port} (HTX: {self.enable_htx})")

        if not self.sockets:
            print("ERROR: Could not bind ANY RWP port. The server cannot accept connections.")
            print("See the messages above for why each port failed, then fix and re-run.")
            self.running = False
            return

        # Start UDP polymorphic signaling listener (sockets already bound above)
        udp_thread = threading.Thread(target=self.udp_signal_listener)
        udp_thread.daemon = True
        udp_thread.start()

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

        if self.dht:
            self.dht.stop()

        for sock in self.sockets:
            sock.close()

        for port, (sock, _) in self.open_ports.items():
            sock.close()

        with self._udp_generations_lock:
            for _, gen in self._udp_generations:
                for sock in gen.values():
                    try:
                        sock.close()
                    except Exception:
                        pass

        print("RWP Server stopped")

if __name__ == "__main__":
    server = RWPServer(ports=[7070, 80])
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()

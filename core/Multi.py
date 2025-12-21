#!/usr/bin/env python3
"""
RRKDHT Network Test Manager - Production Grade
Manages multiple RRKDHT nodes with automatic port configuration and unified GUI control.
"""

import asyncio
import json
import logging
import threading
import re
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
from typing import Dict, List, Optional, Tuple, Any
import queue
import signal
import sys
import os
import datetime

# Import the core RRKDHT implementation
from RRKDHT import RRKDHT, create_ed25519_key_pair, Config

# Configure logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rrkdht_manager.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger(__name__)


class NodeInstance:
    """Encapsulates a single DHT node instance with its lifecycle management."""
    
    def __init__(self, node_id: int, base_ip: str, base_dht_port: int, base_rwp_port: int, ksize: int = 10):
        self.node_id = node_id
        self.base_ip = base_ip
        self.dht_port = base_dht_port + node_id
        self.rwp_port = base_rwp_port + node_id
        self.ksize = ksize
        
        self.dht_node: Optional[RRKDHT] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self.bootstrap_addresses: List[Tuple[str, int, int]] = []
        
        # Thread-safe command queue
        self.command_queue = queue.Queue()
        self.output_queue = queue.Queue()
        
        # Node metadata
        self.node_info = {
            'node_id_hex': None,
            'rendezvous_key': None,
            'long_id': None,
            'status': 'INITIALIZING'
        }
        
        log.info(f"NodeInstance {self.node_id} created - DHT:{self.dht_port} RWP:{self.rwp_port}")
    
    def start(self, bootstrap_addresses: List[Tuple[str, int, int]] = None):
        """Start the node in a separate thread with its own event loop."""
        if self.running:
            log.warning(f"Node {self.node_id} is already running")
            return
        
        self.bootstrap_addresses = bootstrap_addresses or []
        
        def run_node():
            """Run the asyncio event loop for this node."""
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            
            try:
                self.loop.run_until_complete(self._async_start())
                self.loop.run_forever()
            except Exception as e:
                log.error(f"Node {self.node_id} event loop error: {e}")
            finally:
                self.loop.close()
        
        self.thread = threading.Thread(target=run_node, daemon=True, name=f"Node-{self.node_id}")
        self.thread.start()
        self.running = True
        log.info(f"Node {self.node_id} thread started")
    
    async def _async_start(self):
        """Asynchronous startup routine."""
        try:
            # Generate keys
            signing_private_key, signing_public_key = create_ed25519_key_pair()
            
            # Create DHT node
            self.dht_node = RRKDHT(
                ksize=self.ksize,
                alpha=10,
                signing_keys=(signing_private_key, signing_public_key),
                rwp_port=self.rwp_port
            )
            
            # Start listening
            await self.dht_node.listen(self.dht_port, self.base_ip, self.rwp_port)
            
            # Bootstrap if addresses provided
            if self.bootstrap_addresses:
                log.info(f"Node {self.node_id} bootstrapping with {len(self.bootstrap_addresses)} nodes")
                await self.dht_node.bootstrap(self.bootstrap_addresses)
            
            # Store node info
            self._update_node_info()  # Changed to use new method
            
            log.info(f"Node {self.node_id} is fully operational")
            
            # Start command handler
            asyncio.create_task(self._command_handler())
            
        except Exception as e:
            log.error(f"Failed to start node {self.node_id}: {e}")
            self.node_info['status'] = f'ERROR: {str(e)}'
    
    def _update_node_info(self):
        """Update node_info with current values from dht_node."""
        if self.dht_node:
            self.node_info.update({
                'node_id_hex': self.dht_node.node.id.hex(),
                'rendezvous_key': self.dht_node.get_rendezvous_key(),
                'long_id': self.dht_node.node.long_id,
                'status': 'RUNNING'
            })

    async def _command_handler(self):
        """Handle commands from the GUI thread."""
        while self.running:
            try:
                # Check for commands with timeout to allow loop to continue
                command = await asyncio.get_event_loop().run_in_executor(None, 
                    lambda: self.command_queue.get(timeout=0.1))
                
                if command == 'STOP':
                    break
                
                # Execute command and capture output
                output = await self._execute_command(command)
                self.output_queue.put(output)
                
            except queue.Empty:
                continue
            except Exception as e:
                self.output_queue.put(f"Command error: {e}")
    
    async def _execute_command(self, command: str) -> str:
        """Execute a command and return formatted output."""
        if not self.dht_node or not self.dht_node.protocol:
            return "Error: Node not ready"
        
        parts = command.strip().split(maxsplit=1)
        if not parts:
            return "Error: Empty command"
        
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        try:
            if cmd in ['rt', 'routing']:
                return self._format_routing_table()
            elif cmd in ['quit', 'exit']:
                # Handle quit/exit command to stop the node
                self.stop()
                return f"🛑 Node {self.node_id} has stopped"
            elif cmd == 'rt-full':
                return self._format_routing_table(show_empty=True)
            elif cmd == 'rt-repl':
                return self._format_routing_table(show_replacement=True)
            elif cmd == 'rt-info':
                return self._format_routing_info()
            elif cmd == 'neighbors':
                return self._format_neighbors()
            elif cmd == 'health':
                return self._format_health()
            elif cmd == 'status':
                return self._format_status()
            elif cmd == 'debug':
                return self._format_debug()
            elif cmd.startswith('ping'):
                return await self._handle_ping(args)
            elif cmd.startswith('search'):
                return await self._handle_search(args)
            elif cmd.startswith('search-rk'):
                return await self._handle_search_rk(args)
            elif cmd == 'help':
                return self._format_help()
            else:
                return f"Unknown command: {cmd}. Type 'help' for available commands."
        except Exception as e:
            return f"Command execution error: {e}"
    
    def _format_routing_table(self, show_empty=False, show_replacement=False) -> str:
        """Format routing table for display."""
        if not self.dht_node.protocol:
            return "Node not ready"
        
        import io
        from contextlib import redirect_stdout
        
        output = io.StringIO()
        with redirect_stdout(output):
            # Get max_neighbors from router config
            max_neighbors = self.dht_node.protocol.router.max_neighbors
            print(f"Max Neighbors Limit: {max_neighbors}\n")  # ← ADD THIS LINE
            self.dht_node.protocol.router.print_routing_table(
                show_empty_buckets=show_empty,
                show_replacement_nodes=show_replacement
            )
        return output.getvalue()
    
    def _format_routing_info(self) -> str:
        """Format concise routing table info including max_neighbors."""
        if not self.dht_node.protocol:
            return "Node not ready"
        
        # Get routing info
        routing_info = self.dht_node.protocol.router.get_detailed_routing_info()
        
        # Get health info SEPARATELY (this is the fix!)
        health_report = self.dht_node.protocol.router.analyze_routing_health()
        
        output = [f"\n📊 Routing Info for Node {self.node_id}:"]
        output.append("=" * 60)
        output.append(f"{'Configuration':<20} {'Value':<15} {'Status':<15}")
        output.append("-" * 60)
        output.append(f"{'Max Neighbors':<20} {routing_info['max_neighbors']:<15} {'(LIMIT)':<15}")
        output.append(f"{'KSize':<20} {routing_info['ksize']:<15} {'(BUCKET SIZE)':<15}")
        output.append(f"{'Total Nodes':<20} {routing_info['total_nodes']:<15} {'(CURRENT)':<15}")
        output.append(f"{'Total Buckets':<20} {routing_info['total_buckets']:<15}")
        output.append(f"{'Lonely Buckets':<20} {routing_info['lonely_buckets']:<15}")
        output.append(f"{'Stale Nodes':<20} {routing_info['stale_nodes']:<15} {'⚠️' if routing_info['stale_nodes'] > 0 else '✓':<15}")
        output.append(f"{'Failed Nodes':<20} {routing_info['failed_nodes']:<15} {'❌' if routing_info['failed_nodes'] > 0 else '✓':<15}")
        output.append(f"{'Replacement Nodes':<20} {routing_info['total_replacement_nodes']:<15}")
        
        # Health status (using the separate health_report variable)
        output.append("\n" + "=" * 60)
        health_status = health_report['overall_health']
        status_icon = '✅' if health_status == 'GOOD' else '⚠️'
        output.append(f"Health: {health_status} {status_icon}")
        output.append("-" * 60)
        output.append(f"Fill Ratio:     {health_report['metrics']['fill_ratio']:.2%}")
        output.append(f"Stale Ratio:    {health_report['metrics']['stale_ratio']:.2%}")
        output.append(f"Failed Ratio:   {health_report['metrics']['failed_ratio']:.2%}")
        
        # Show issues if any
        if health_report['issues']:
            output.append("\n⚠️  Issues Found:")
            for issue in health_report['issues']:
                output.append(f"   • {issue}")
        
        return "\n".join(output)

    def _format_neighbors(self) -> str:
        """Format neighbors list."""
        if not self.dht_node.protocol:
            return "Node not ready"
        
        neighbors = self.dht_node.protocol.router.get_neighbors_by_distance()
        if not neighbors:
            return "No neighbors found"
        
        output = [f"\nNeighbors for Node {self.node_id}:"]
        output.append("=" * 60)
        output.append(f"{'Rank':<5} {'Node ID (trunc)':<18} {'IP:Port':<22} {'RWP':<8}")
        output.append("-" * 60)
        
        for i, neighbor in enumerate(neighbors[:20], 1):
            node_id_trunc = neighbor.id.hex()[:16] + "..."
            output.append(f"{i:<5} {node_id_trunc:<18} {neighbor.ip}:{neighbor.port:<15} {neighbor.rwp_port or 'N/A':<8}")
        
        return "\n".join(output)
    
    def _format_health(self) -> str:
        """Format health report."""
        if not self.dht_node.protocol:
            return "Node not ready"
        
        health = self.dht_node.protocol.router.analyze_routing_health()
        output = [f"\nHealth Report for Node {self.node_id}:"]
        output.append("=" * 50)
        output.append(f"Overall Health: {health['overall_health']}")
        output.append("\nMetrics:")
        for k, v in health['metrics'].items():
            output.append(f"  {k}: {v}")
        if health['issues']:
            output.append("\nIssues:")
            for issue in health['issues']:
                output.append(f"  ⚠️  {issue}")
        return "\n".join(output)
    
    def _format_status(self) -> str:
        """Format node status with live rendezvous key."""
        output = [f"\nStatus for Node {self.node_id}:"]
        output.append("=" * 50)
        output.append(f"DHT Port: {self.dht_port}")
        output.append(f"RWP Port: {self.rwp_port}")
        
        if self.dht_node:
            # Get live values from dht_node
            output.append(f"Node ID: {self.dht_node.node.id.hex()}")
            output.append(f"Rendezvous Key: {self.dht_node.get_rendezvous_key()}")
            output.append(f"Status: RUNNING")
            output.append(f"Neighbors: {len(self.dht_node.bootstrappable_neighbors())}")
        else:
            # Fallback to cached values
            output.append(f"Node ID: {self.node_info.get('node_id_hex', 'N/A')}")
            output.append(f"Rendezvous Key: {self.node_info.get('rendezvous_key', 'N/A')}")
            output.append(f"Status: {self.node_info.get('status', 'UNKNOWN')}")
        
        return "\n".join(output)
    
    def _format_debug(self) -> str:
        """Format debug info."""
        if not self.dht_node:
            return "Node not ready"
        
        debug = self.dht_node.get_debug_info()
        return json.dumps(debug, indent=2, default=str)
    
    def _format_help(self) -> str:
        """Format help text."""
        return """
Available Commands:
  rt, routing         - Show routing table
  rt-full             - Show routing table with empty buckets
  rt-repl             - Show routing table with replacement nodes
  rt-info             - Show concise routing info (including max_neighbors)
  neighbors           - Show all neighbors
  health              - Show routing health analysis
  status              - Show node status
  debug               - Show comprehensive debug info
  ping <ip> <port> [rwp_port] - Ping a specific node
  search <node_id>    - Search for a node by Node ID
  search-rk <key>     - Search for a node by Rendezvous Key
  quit, exit          - Stop this node
  help                - Show this help message
"""
    
    async def _handle_ping(self, args: str) -> str:
        """Handle ping command."""
        parts = args.split()
        if len(parts) < 2:
            return "Usage: ping <ip> <port> [rwp_port]"
        
        try:
            ip = parts[0]
            port = int(parts[1])
            rwp_port = int(parts[2]) if len(parts) > 2 else port + 1000
            
            result = await self.dht_node.ping_node(ip, port, rwp_port)
            return f"Ping result: {json.dumps(result, indent=2)}"
        except Exception as e:
            return f"Ping failed: {e}"
    
    async def _handle_search(self, args: str) -> str:
        """Handle search command."""
        if not args:
            return "Usage: search <node_id>"
        
        try:
            result = await self.dht_node.search_node(args.strip())
            return f"Search result: {json.dumps(result.__dict__, default=str, indent=2)}"
        except Exception as e:
            return f"Search failed: {e}"
    
    async def _handle_search_rk(self, args: str) -> str:
        """Handle search-rk command."""
        if not args:
            return "Usage: search-rk <rendezvous_key>"
        
        try:
            result = await self.dht_node.search_by_rendezvous_key(args.strip())
            return f"Search by RK result: {json.dumps(result.__dict__, default=str, indent=2)}"
        except Exception as e:
            return f"Search by RK failed: {e}"
    
    def extract_routing_table_data(self) -> Dict:
        """Extract routing table structure for JSON export."""
        # 1. Prepare default structure if node isn't ready
        if not self.dht_node or not self.dht_node.protocol:
            return {
                "node_id": self.node_id,
                "ip": self.base_ip,
                "dht_port": self.dht_port,
                "rwp_port": self.rwp_port,
                "buckets": []
            }
            
        router = self.dht_node.protocol.router
        buckets_data = []
        
        try:
            # 2. Iterate through buckets
            for i, bucket in enumerate(router.buckets):
                bucket_nodes = []
                
                # Handle different Kademlia implementations (dict vs list)
                nodes_iter = bucket.nodes.values() if isinstance(bucket.nodes, dict) else bucket.nodes
                
                for node in nodes_iter:
                    bucket_nodes.append({
                        # id_hex REMOVED as requested
                        "ip": node.ip,
                        "port": node.port,
                        "rwp_port": getattr(node, 'rwp_port', None)
                    })
                
                # Only include buckets that have nodes
                if bucket_nodes:
                    buckets_data.append({
                        "bucket_index": i,
                        "range_min": getattr(bucket, 'range', (0,0))[0],
                        "node_count": len(bucket_nodes),
                        "nodes": bucket_nodes
                    })
                    
        except Exception as e:
            log.error(f"Error extracting RT for node {self.node_id}: {e}")
            
        # 3. Return clean dictionary
        return {
            "node_id": self.node_id,
            "ip": self.base_ip,        # Added
            "dht_port": self.dht_port, # Added
            "rwp_port": self.rwp_port, # Added
            # node_id_hex REMOVED
            # status REMOVED
            "buckets": buckets_data
        }

    def restart(self):
        """Restart a stopped node with fresh state."""
        if self.running:
            log.warning(f"Node {self.node_id} is already running")
            return
        
        # Reset status and queues
        self.node_info['status'] = 'INITIALIZING'
        self.output_queue = queue.Queue()
        self.command_queue = queue.Queue()
        
        log.info(f"Restarting Node {self.node_id}...")
        self.start(self.bootstrap_addresses)
    
    def can_delete(self):
        """Check if node can be safely deleted."""
        return not self.running and self.node_info['status'] in ['STOPPED', 'ERROR']
    
    def stop(self):
        """Stop the node."""
        if not self.running:
            return
        
        self.running = False
        self.node_info['status'] = 'STOPPED'
        
        # Send stop command to queue
        self.command_queue.put('STOP')
        
        # Stop DHT node
        if self.dht_node:
            self.dht_node.stop()
        
        # Wait for thread to finish
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        
        log.info(f"Node {self.node_id} stopped")


class TestNetworkGUI:
    """Production-grade GUI for managing multiple RRKDHT nodes."""
    
    def __init__(self, master: tk.Tk):
        self.master = master
        self.master.title("RRKDHT Network Test Manager - Production")
        self.master.geometry("1200x800")
        
        # Configuration
        self.base_ip = "127.0.0.1"
        self.base_dht_port = 8080
        self.base_rwp_port = 8443
        self.ksize = 10
        
        # Node management
        self.nodes: Dict[int, NodeInstance] = {}
        self.selected_node_id = tk.IntVar(value=0)
        
        # Button references for state management
        self.stop_button = None
        self.activate_button = None
        self.delete_button = None
        
        # Output buffer for performance
        self.output_buffer = []
        self.buffer_limit = 1000
        
        self.setup_gui()
        self.start_update_timer()
        
        log.info("TestNetworkGUI initialized")
    
    def setup_gui(self):
        """Setup the GUI components with professional layout."""
        # Main container
        main_container = ttk.Frame(self.master, padding="10")
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)
        main_container.columnconfigure(1, weight=1)
        main_container.columnconfigure(2, weight=0) # New column for the test panel
        main_container.rowconfigure(2, weight=1)

        # ===== TOP CONTROL PANEL =====
        control_frame = ttk.LabelFrame(main_container, text="Network Controls", padding="10")
        control_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)) # Span 3 columns

        # Node creation controls
        ttk.Label(control_frame, text="IP:").grid(row=0, column=0, sticky=tk.W)
        self.ip_entry = ttk.Entry(control_frame, width=15)
        self.ip_entry.insert(0, self.base_ip)
        self.ip_entry.grid(row=0, column=1, padx=5)

        ttk.Label(control_frame, text="Base DHT Port:").grid(row=0, column=2, sticky=tk.W, padx=(20, 5))
        self.dht_port_entry = ttk.Entry(control_frame, width=8)
        self.dht_port_entry.insert(0, str(self.base_dht_port))
        self.dht_port_entry.grid(row=0, column=3, padx=5)

        ttk.Label(control_frame, text="Base RWP Port:").grid(row=0, column=4, sticky=tk.W, padx=(20, 5))
        self.rwp_port_entry = ttk.Entry(control_frame, width=8)
        self.rwp_port_entry.insert(0, str(self.base_rwp_port))
        self.rwp_port_entry.grid(row=0, column=5, padx=5)

        ttk.Label(control_frame, text="KSize:").grid(row=0, column=6, sticky=tk.W, padx=(20, 5))
        self.ksize_entry = ttk.Entry(control_frame, width=5)
        self.ksize_entry.insert(0, str(self.ksize))
        self.ksize_entry.grid(row=0, column=7, padx=5)

        # Buttons with state management
        ttk.Button(control_frame, text="Add Node", command=self.add_node_dialog).grid(
            row=0, column=8, padx=(20, 5))

        # Store button references for state updates
        self.stop_button = ttk.Button(control_frame, text="Stop Selected", command=self.stop_selected_node, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=9, padx=5)

        self.activate_button = ttk.Button(control_frame, text="Activate Selected", command=self.activate_selected_node, state=tk.DISABLED)
        self.activate_button.grid(row=0, column=10, padx=5)

        self.delete_button = ttk.Button(control_frame, text="Delete Selected", command=self.delete_selected_node, state=tk.DISABLED)
        self.delete_button.grid(row=0, column=11, padx=5)

        ttk.Button(control_frame, text="Export RTs (JSON)", command=self.export_routing_tables).grid(
            row=0, column=13, padx=5)

        ttk.Button(control_frame, text="Stop All", command=self.stop_all_nodes).grid(
            row=0, column=12, padx=5)

        # ===== LEFT PANEL - NODE LIST =====
        left_panel = ttk.Frame(main_container)
        left_panel.grid(row=1, column=0, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))

        ttk.Label(left_panel, text="Active Nodes", font=('TkDefaultFont', 10, 'bold')).grid(
            row=0, column=0, sticky=tk.W, pady=(0, 5))

        # Node list with scrollbar
        list_frame = ttk.Frame(left_panel)
        list_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.node_listbox = tk.Listbox(list_frame, width=40, height=20, selectmode=tk.SINGLE)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.node_listbox.yview)
        self.node_listbox.configure(yscrollcommand=scrollbar.set)

        self.node_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # Bind selection event to auto-select target node
        self.node_listbox.bind('<<ListboxSelect>>', self.on_node_select)

        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        # Node selector for commands
        ttk.Label(left_panel, text="Command Target Node:", font=('TkDefaultFont', 10, 'bold')).grid(
            row=2, column=0, sticky=tk.W, pady=(10, 5))

        selector_frame = ttk.Frame(left_panel)
        selector_frame.grid(row=3, column=0, sticky=(tk.W, tk.E))

        self.node_selector = ttk.Spinbox(selector_frame, from_=0, to=99, width=5, 
                                        textvariable=self.selected_node_id)
        self.node_selector.grid(row=0, column=0, padx=(0, 10))
        ttk.Button(selector_frame, text="Refresh List", command=self.refresh_node_list).grid(
            row=0, column=1)

        # ===== RIGHT PANEL - COMMAND INTERFACE =====
        right_panel = ttk.Frame(main_container)
        right_panel.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Command entry
        cmd_frame = ttk.Frame(right_panel)
        cmd_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(cmd_frame, text="Command:").grid(row=0, column=0, sticky=tk.W)
        self.command_entry = ttk.Entry(cmd_frame, width=60)
        self.command_entry.grid(row=0, column=1, padx=10, sticky=(tk.W, tk.E))
        self.command_entry.bind('<Return>', lambda e: self.execute_command())

        ttk.Button(cmd_frame, text="Execute", command=self.execute_command).grid(
            row=0, column=2)

        cmd_frame.columnconfigure(1, weight=1)

        # Output area
        output_frame = ttk.LabelFrame(right_panel, text="Command Output", padding="5")
        output_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.output_text = scrolledtext.ScrolledText(output_frame, width=80, height=25, 
                                                     wrap=tk.WORD, font=('Courier', 9))
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Make output read-only
        self.output_text.config(state=tk.DISABLED)

        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        # ===== NEW FAR-RIGHT PANEL - TEST LISTBOX (Column 2) =====
        test_panel = ttk.LabelFrame(main_container, text="NETWORK TEST", padding="5") # Changed text for clarity
        test_panel.grid(row=1, column=2, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(10, 0))

        # Test Listbox with Scrollbar
        test_list_frame = ttk.Frame(test_panel)
        test_list_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        self.test_listbox = tk.Listbox(test_list_frame, width=25, height=20, selectmode=tk.SINGLE, font=('Courier', 9))
        test_scrollbar = ttk.Scrollbar(test_list_frame, orient=tk.VERTICAL, command=self.test_listbox.yview)
        self.test_listbox.configure(yscrollcommand=test_scrollbar.set)
        
        self.test_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        test_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # Buttons for the Test Panel
        button_frame = ttk.Frame(test_panel)
        button_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)

        ttk.Button(button_frame, text="Search All Nodes", command=self.search_all_nodes_from_selected).pack(fill=tk.X)
        ttk.Button(button_frame, text="Clear Test List", command=self.clear_test_list).pack(fill=tk.X, pady=(5,0))
        ttk.Button(button_frame, text="Export Results", command=self.export_test_results).pack(fill=tk.X, pady=(5,0))
            
        # Configure weights for the test panel
        test_panel.columnconfigure(0, weight=1)
        test_panel.rowconfigure(0, weight=1)
        test_list_frame.columnconfigure(0, weight=1)
        test_list_frame.rowconfigure(0, weight=1)

        # ===== BOTTOM STATUS BAR =====
        self.status_bar = ttk.Label(main_container, text="Ready | Nodes: 0", relief=tk.SUNKEN)
        self.status_bar.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0)) # Span 3 columns

        # Configure weights
        left_panel.rowconfigure(1, weight=1)
        right_panel.rowconfigure(1, weight=1)
    
    def on_node_select(self, event):
        """Auto-select target node when clicking on a node in the list."""
        selection = self.node_listbox.curselection()
        if selection:
            try:
                text = self.node_listbox.get(selection[0])
                # Extract number after "Node" using regex
                match = re.search(r'Node\s+(\d+)', text)
                if match:
                    node_id = int(match.group(1))
                    self.selected_node_id.set(node_id)
                    self.log_to_output(f"✅ Target node auto-selected: Node {node_id}")
                    self.update_button_states()
                else:
                    raise ValueError("Node ID pattern not found")
            except (ValueError, IndexError) as e:
                log.error(f"Failed to parse node ID from selection: {e}")
    
    def refresh_node_list(self):
        """Refresh the node list display maintaining scroll position."""
        # 1. Save current scroll position and selection
        y_scroll = self.node_listbox.yview()
        current_selection = self.node_listbox.curselection()
        
        self.node_listbox.delete(0, tk.END)
        
        for node_id in sorted(self.nodes.keys()):
            node = self.nodes[node_id]
            status_indicator = "🟢" if node.running else "🔴"
            
            # Update node_info with live data if node is running
            if node.running and node.dht_node:
                node._update_node_info()
            
            display_text = f"{status_indicator} Node {node_id:2d} | DHT:{node.dht_port} RWP:{node.rwp_port} | {node.node_info['status']}"
            self.node_listbox.insert(tk.END, display_text)
        
        # 2. Restore scroll position
        self.node_listbox.yview_moveto(y_scroll[0])
        
        # 3. Restore selection if the index is still valid
        if current_selection and current_selection[0] < self.node_listbox.size():
            self.node_listbox.selection_set(current_selection)
            
        self.update_status_bar()
        self.update_button_states()
    
    def update_status_bar(self):
        """Update the status bar with current statistics."""
        running_count = sum(1 for node in self.nodes.values() if node.running)
        total_count = len(self.nodes)
        self.status_bar.config(text=f"Nodes: {running_count}/{total_count} running | Target Node: {self.selected_node_id.get()}")
    
    def start_update_timer(self):
        """Start periodic updates of node status."""
        self.refresh_node_list()
        
        # Schedule next update
        self.master.after(2000, self.start_update_timer)  # Update every 2 seconds
    
    def add_node_dialog(self):
        """Dialog to add one or more new nodes with bootstrap selection and sequential spawning."""
        dialog = tk.Toplevel(self.master)
        dialog.title("Add New Node(s)")
        dialog.geometry("500x450")
        dialog.transient(self.master)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Configure New Node(s)", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Number of nodes to add
        ttk.Label(dialog, text="Number of nodes to add:", font=('TkDefaultFont', 10, 'bold')).pack(
            anchor=tk.W, padx=20, pady=(10, 5))
        
        node_count_frame = ttk.Frame(dialog)
        node_count_frame.pack(fill=tk.X, padx=20, pady=(0, 10))
        
        node_count_spinbox = ttk.Spinbox(node_count_frame, from_=1, to=100, width=5)
        node_count_spinbox.set(1)  # Default to 1 node
        node_count_spinbox.pack(side=tk.LEFT)
        
        ttk.Label(node_count_frame, text=" (max 100 per batch)", foreground='gray').pack(side=tk.LEFT, padx=(10, 0))
        
        # Bootstrap selection
        ttk.Label(dialog, text="Select Bootstrap Node (optional):", font=('TkDefaultFont', 10, 'bold')).pack(
            anchor=tk.W, padx=20, pady=(10, 5))
        
        # Create listbox for bootstrap selection
        list_frame = ttk.Frame(dialog)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        bootstrap_listbox = tk.Listbox(list_frame, height=8)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=bootstrap_listbox.yview)
        bootstrap_listbox.configure(yscrollcommand=scrollbar.set)
        
        bootstrap_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Populate bootstrap options
        bootstrap_listbox.insert(tk.END, "No Bootstrap (Create Genesis Node)")
        for node_id in sorted(self.nodes.keys()):
            node = self.nodes[node_id]
            if node.running:
                bootstrap_listbox.insert(tk.END, f"Node {node_id} - {node.base_ip}:{node.dht_port}")
        
        bootstrap_listbox.selection_set(0)
        
        # Auto-configure checkbox
        auto_configure = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Auto-configure ports from entries", variable=auto_configure).pack(
            padx=20, pady=10)
        
        def do_add_nodes():
            """Execute node addition with sequential spawning."""
            # Validate and parse node count
            try:
                count = int(node_count_spinbox.get())
                if count < 1 or count > 20:
                    raise ValueError("Count out of range")
            except (ValueError, TypeError) as e:
                log.warning(f"Invalid node count input: {e}")
                messagebox.showwarning("Invalid Input", "Please enter a valid number (1-20)")
                return
            
            # Get bootstrap selection
            selection = bootstrap_listbox.curselection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a bootstrap option")
                return
            
            bootstrap_addrs = None
            if selection[0] > 0:
                selected_node_id = sorted(self.nodes.keys())[selection[0] - 1]
                selected_node = self.nodes[selected_node_id]
                bootstrap_addrs = [(selected_node.base_ip, selected_node.dht_port, selected_node.rwp_port)]
            
            # Parse configuration values
            try:
                if auto_configure.get():
                    base_ip = self.ip_entry.get()
                    base_dht = int(self.dht_port_entry.get())
                    base_rwp = int(self.rwp_port_entry.get())
                    ksize = int(self.ksize_entry.get())
                else:
                    base_ip = self.base_ip
                    base_dht = self.base_dht_port
                    base_rwp = self.base_rwp_port
                    ksize = self.ksize
            except ValueError as e:
                log.error(f"Configuration parsing error: {e}")
                messagebox.showerror("Configuration Error", f"Invalid configuration values: {e}")
                dialog.destroy()
                return
            
            dialog.destroy()
            
            # Log batch initiation
            self.log_to_output(f"\n🔄 Starting batch addition of {count} node(s)...")
            if bootstrap_addrs:
                self.log_to_output(f"   Bootstrap: {bootstrap_addrs[0]}")
            else:
                self.log_to_output("   Genesis network (no bootstrap)")
            
            # Begin sequential node addition
            self._add_nodes_sequential(count, base_ip, base_dht, base_rwp, ksize, bootstrap_addrs)
        
        ttk.Button(dialog, text="Add Node(s)", command=do_add_nodes).pack(pady=20)
        ttk.Button(dialog, text="Cancel", command=dialog.destroy).pack()
    
    def export_test_results(self):
        """Export the contents of the test results listbox to a timestamped text file."""
        if self.test_listbox.size() == 0:
            self.log_to_output("⚠️ No test results to export.")
            return

        # Generate default filename with timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"rrkdht_search_results_{timestamp}.txt"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=default_filename,
            title="Export Search Results"
        )
        
        if not filename:
            self.log_to_output("⚠️ Export cancelled.")
            return
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Write comprehensive header
                f.write("=" * 60 + "\n")
                f.write("RRKDHT Network Search Results\n")
                f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Source Node: Node {self.selected_node_id.get()}\n")
                f.write(f"Total Results: {self.test_listbox.size()}\n")
                f.write("=" * 60 + "\n\n")
                
                # Write results with line numbers
                for i in range(self.test_listbox.size()):
                    result = self.test_listbox.get(i)
                    f.write(f"{i+1:3d}. {result}\n")
            
            self.log_to_output(f"✅ Test results exported to: {filename}")
            self.log_to_output(f"   {self.test_listbox.size()} entries saved")
        except Exception as e:
            error_msg = f"Failed to export test results: {str(e)}"
            self.log_to_output(f"❌ {error_msg}")
            log.error(error_msg, exc_info=True)
            messagebox.showerror("Export Error", error_msg)
    
    def _add_nodes_sequential(self, remaining_count: int, base_ip: str, base_dht: int, 
                            base_rwp: int, ksize: int, bootstrap_addrs: Optional[List[Tuple[str, int, int]]]):
        """
        Recursively add nodes with a delay between each to prevent system overload
        and ensure proper network formation sequencing.
        """
        if remaining_count <= 0:
            self.log_to_output(f"✅ Batch addition complete")
            return
        
        # Calculate next sequential node ID
        next_id = max(self.nodes.keys()) + 1 if self.nodes else 0
        
        try:
            # Create node instance (but don't start it yet)
            node = NodeInstance(next_id, base_ip, base_dht, base_rwp, ksize)
            
            # CRITICAL: Add to dictionary BEFORE starting to ensure UI consistency
            self.nodes[next_id] = node
            
            # Now start the node
            node.start(bootstrap_addrs.copy() if bootstrap_addrs else None)
            
            # Update selected node ID
            self.selected_node_id.set(next_id)
            
            self.log_to_output(f"   ✅ Node {next_id} started on DHT port {node.dht_port}")
            
            # Schedule next node after 1 second delay
            self.master.after(1000, lambda: self._add_nodes_sequential(
                remaining_count - 1, base_ip, base_dht, base_rwp, ksize, bootstrap_addrs))
            
        except Exception as e:
            log.error(f"Failed to start node {next_id}: {e}", exc_info=True)
            self.log_to_output(f"   ❌ Node {next_id} failed: {str(e)}")
            
            # Clean up: remove the node from dictionary if it was added
            if next_id in self.nodes:
                del self.nodes[next_id]
                
            # Schedule next node even if this one failed
            self.master.after(1000, lambda: self._add_nodes_sequential(
                remaining_count - 1, base_ip, base_dht, base_rwp, ksize, bootstrap_addrs))

    def add_node_dialog(self):
        """Dialog to add one or more new nodes with bootstrap selection and sequential spawning."""
        dialog = tk.Toplevel(self.master)
        dialog.title("Add New Node(s)")
        dialog.geometry("500x450")
        dialog.transient(self.master)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Configure New Node(s)", font=('TkDefaultFont', 12, 'bold')).pack(pady=10)
        
        # Number of nodes to add
        ttk.Label(dialog, text="Number of nodes to add:", font=('TkDefaultFont', 10, 'bold')).pack(
            anchor=tk.W, padx=20, pady=(10, 5))
        
        node_count_frame = ttk.Frame(dialog)
        node_count_frame.pack(fill=tk.X, padx=20, pady=(0, 10))
        
        node_count_spinbox = ttk.Spinbox(node_count_frame, from_=1, to=100, width=5)
        node_count_spinbox.set(1)  # Default to 1 node
        node_count_spinbox.pack(side=tk.LEFT)
        
        ttk.Label(node_count_frame, text=" (max 100 per batch)", foreground='gray').pack(side=tk.LEFT, padx=(10, 0))
        
        # Bootstrap selection
        ttk.Label(dialog, text="Select Bootstrap Node (optional):", font=('TkDefaultFont', 10, 'bold')).pack(
            anchor=tk.W, padx=20, pady=(10, 5))
        
        # Create listbox for bootstrap selection
        list_frame = ttk.Frame(dialog)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        bootstrap_listbox = tk.Listbox(list_frame, height=8)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=bootstrap_listbox.yview)
        bootstrap_listbox.configure(yscrollcommand=scrollbar.set)
        
        bootstrap_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Populate bootstrap options
        bootstrap_listbox.insert(tk.END, "No Bootstrap (Create Genesis Node)")
        for node_id in sorted(self.nodes.keys()):
            node = self.nodes[node_id]
            if node.running:
                bootstrap_listbox.insert(tk.END, f"Node {node_id} - {node.base_ip}:{node.dht_port}")
        
        bootstrap_listbox.selection_set(0)
        
        # Auto-configure checkbox
        auto_configure = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Auto-configure ports from entries", variable=auto_configure).pack(
            padx=20, pady=10)
        
        def do_add_nodes():
            """Execute node addition with sequential spawning."""
            # Validate and parse node count
            try:
                count = int(node_count_spinbox.get())
                if count < 1 or count > 100:
                    raise ValueError("Count out of range")
            except (ValueError, TypeError) as e:
                log.warning(f"Invalid node count input: {e}")
                messagebox.showwarning("Invalid Input", "Please enter a valid number (1-100)")
                return
            
            # Get bootstrap selection
            selection = bootstrap_listbox.curselection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a bootstrap option")
                return
            
            bootstrap_addrs = None
            if selection[0] > 0:
                selected_node_id = sorted(self.nodes.keys())[selection[0] - 1]
                selected_node = self.nodes[selected_node_id]
                bootstrap_addrs = [(selected_node.base_ip, selected_node.dht_port, selected_node.rwp_port)]
            
            # Parse configuration values
            try:
                if auto_configure.get():
                    base_ip = self.ip_entry.get()
                    base_dht = int(self.dht_port_entry.get())
                    base_rwp = int(self.rwp_port_entry.get())
                    ksize = int(self.ksize_entry.get())
                else:
                    base_ip = self.base_ip
                    base_dht = self.base_dht_port
                    base_rwp = self.base_rwp_port
                    ksize = self.ksize
            except ValueError as e:
                log.error(f"Configuration parsing error: {e}")
                messagebox.showerror("Configuration Error", f"Invalid configuration values: {e}")
                dialog.destroy()
                return
            
            dialog.destroy()
            
            # Log batch initiation
            self.log_to_output(f"\n🔄 Starting batch addition of {count} node(s)...")
            if bootstrap_addrs:
                self.log_to_output(f"   Bootstrap: {bootstrap_addrs[0]}")
            else:
                self.log_to_output("   Genesis network (no bootstrap)")
            
            # Begin sequential node addition
            self._add_nodes_sequential(count, base_ip, base_dht, base_rwp, ksize, bootstrap_addrs)
        
        ttk.Button(dialog, text="Add Node(s)", command=do_add_nodes).pack(pady=20)
        ttk.Button(dialog, text="Cancel", command=dialog.destroy).pack()

    def search_all_nodes_from_selected(self):
        """
        Initiates a network-wide search from the selected node.
        The selected node searches for the Node ID of every other running node.
        Results are displayed in the test_listbox.
        """
        target_node_id = self.selected_node_id.get()
        
        if target_node_id not in self.nodes or not self.nodes[target_node_id].running:
            self.log_to_output(f"❌ Error: Target Node {target_node_id} is not running or doesn't exist.")
            return

        self.clear_test_list()
        self.log_to_output(f"\n🔬 Starting network-wide search from Node {target_node_id}...")
        
        search_node = self.nodes[target_node_id]
        
        # Determine the nodes to search for (all *other* running nodes)
        nodes_to_search_for = [
            node_id for node_id, node in self.nodes.items() 
            if node_id != target_node_id and node.running
        ]

        if not nodes_to_search_for:
            self.log_to_output("⚠️ No other running nodes to search for.")
            return

        # Start the sequential search process
        self.master.after(100, lambda: self._sequential_node_search(
            search_node, 
            nodes_to_search_for, 
            0
        ))

    def _sequential_node_search(self, search_node: 'NodeInstance', target_ids: List[int], index: int):
        """
        Sequentially executes search commands to prevent command queue flooding.
        """
        if index >= len(target_ids):
            self.log_to_output("✅ Network search complete.")
            return

        target_node_id = target_ids[index]
        target_node = self.nodes[target_node_id]
        
        # The key to search for is the target node's Kademlia Node ID
        search_id = target_node.node_info.get('node_id_hex')
        
        if not search_id:
            self.test_listbox.insert(tk.END, f"Node {target_node_id}: ID Not Ready")
            # Move to the next search immediately
            self.master.after(100, lambda: self._sequential_node_search(search_node, target_ids, index + 1))
            return

        command = f"search {search_id}"
        
        self.log_to_output(f"   -> Searching for Node {target_node_id}...")
        
        # Enqueue the command
        search_node.command_queue.put(command)
        
        # Start the result collector for this specific search
        self.master.after(100, lambda: self._collect_search_result(
            search_node, 
            target_node_id, 
            target_ids, 
            index
        ))

    def _collect_search_result(self, search_node: 'NodeInstance', target_id: int, target_ids: List[int], index: int):
        """
        Collects the search result from the node's output queue for a single search.
        **UPDATED to parse the actual RRKDHT search result structure.**
        """
        try:
            # Non-blocking get from the output queue
            result_output = search_node.output_queue.get_nowait()
            
            # --- START Robust Parsing Logic ---
            search_path_len = 'N/A'
            path_summary = "NOT FOUND"
            
            try:
                # 1. Use regex to find the JSON structure within the output string
                match = re.search(r'\{.*\}', result_output, re.DOTALL)
                
                if match:
                    json_str = match.group(0)
                    result_dict = json.loads(json_str)
                    
                    # 2. Check for a successful find using the 'found' key
                    if result_dict.get('found') is True:
                        path_summary = "FOUND"
                        
                    # 3. Extract path length from the 'hops' key
                    hops_value = result_dict.get('hops')
                    if hops_value is not None:
                         search_path_len = str(hops_value)
                    
                # If no JSON found, or parse error occurs:
                else:
                    path_summary = "COMMAND FAILED"
                    self.log_to_output(f"   Parser Failed (No JSON): Raw Output: {result_output.strip().splitlines()[-1]}")
                        
            except (json.JSONDecodeError, AttributeError, TypeError, KeyError):
                # Handle cases where the command output is malformed or unexpected
                path_summary = "ERROR"
                self.log_to_output(f"   Parser Failed (JSON Error): Raw Output: {result_output.strip().splitlines()[-1]}")
            
            # --- END Robust Parsing Logic ---
            
            # Format the output for the listbox
            listbox_output = f"Node {target_id:2d} | Path: {search_path_len:<3} | {path_summary}"
            self.test_listbox.insert(tk.END, listbox_output)
            
            # Always schedule the next search regardless of result
            self.master.after(100, lambda: self._sequential_node_search(search_node, target_ids, index + 1))
            
        except queue.Empty:
            # Command result hasn't arrived yet, check again soon
            if search_node.running:
                # Still running, try again in 50ms
                self.master.after(50, lambda: self._collect_search_result(search_node, target_id, target_ids, index))
            else:
                # Node stopped, log error and continue to the next search
                self.test_listbox.insert(tk.END, f"Node {target_id}: Target Node Stopped")
                self.master.after(100, lambda: self._sequential_node_search(search_node, target_ids, index + 1))

    def clear_test_list(self):
        """Clear the Test/Search Results Listbox."""
        self.test_listbox.delete(0, tk.END)
        self.log_to_output("✨ Test list cleared.")

    def stop_selected_node(self):
        """Stop the currently selected node."""
        target_node_id = self.selected_node_id.get()
        
        if target_node_id not in self.nodes:
            self.log_to_output(f"❌ Error: Node {target_node_id} does not exist")
            return
        
        node = self.nodes[target_node_id]
        if not node.running:
            self.log_to_output(f"⚠️  Node {target_node_id} is already stopped")
            return
        
        self.log_to_output(f"\n🛑 Stopping Node {target_node_id}...")
        
        # Send quit command to the node
        node.command_queue.put("quit")
        
        # Wait a moment and refresh
        self.master.after(500, self.refresh_node_list)
    
    def export_routing_tables(self):
        """Export routing tables of all nodes to a JSON file."""
        if not self.nodes:
            messagebox.showinfo("Info", "No nodes to export.")
            return

        # Prepare data structure
        network_dump = {
            "timestamp": datetime.datetime.now().isoformat(),
            "total_nodes": len(self.nodes),
            "nodes_data": {}
        }
        
        self.log_to_output("\n📦 Exporting routing tables...")
        
        try:
            # Gather data from all nodes
            for node_id, node in self.nodes.items():
                network_dump["nodes_data"][node_id] = node.extract_routing_table_data()
            
            # Ask user where to save
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                initialfile=f"rrkdht_network_dump_{int(time.time())}.json",
                title="Save Network Routing Tables"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(network_dump, f, indent=4)
                self.log_to_output(f"✅ Export saved to: {filename}")
            else:
                self.log_to_output("⚠️ Export cancelled")
                
        except Exception as e:
            error_msg = f"Failed to export data: {str(e)}"
            self.log_to_output(f"❌ {error_msg}")
            log.error(error_msg)
            messagebox.showerror("Export Error", error_msg)

    def activate_selected_node(self):
        """Activate (restart) the currently selected node."""
        target_node_id = self.selected_node_id.get()
        
        if target_node_id not in self.nodes:
            self.log_to_output(f"❌ Error: Node {target_node_id} does not exist")
            return
        
        node = self.nodes[target_node_id]
        if node.running:
            self.log_to_output(f"⚠️  Node {target_node_id} is already running")
            return
        
        self.log_to_output(f"\n▶️  Activating Node {target_node_id}...")
        
        # Restart the node - it will reuse the same bootstrap addresses
        node.restart()
        
        # Refresh after a moment
        self.master.after(500, self.refresh_node_list)
    
    def delete_selected_node(self):
        """Delete the currently selected stopped node."""
        target_node_id = self.selected_node_id.get()
        
        if target_node_id not in self.nodes:
            self.log_to_output(f"❌ Error: Node {target_node_id} does not exist")
            return
        
        node = self.nodes[target_node_id]
        if node.running:
            self.log_to_output(f"❌ Error: Cannot delete running node {target_node_id}. Stop it first.")
            return
        
        if not node.can_delete():
            self.log_to_output(f"❌ Error: Node {target_node_id} cannot be deleted (not fully stopped)")
            return
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm Delete", 
                                   f"Delete Node {target_node_id} permanently?\nThis cannot be undone."):
            return
        
        self.log_to_output(f"\n🗑️  Deleting Node {target_node_id}...")
        
        # Remove from dictionary
        del self.nodes[target_node_id]
        
        # Adjust selection if needed
        if self.nodes:
            new_selection = min(self.nodes.keys())
            self.selected_node_id.set(new_selection)
        else:
            self.selected_node_id.set(0)
        
        self.log_to_output(f"✅ Node {target_node_id} deleted")
        self.refresh_node_list()
    
    def update_button_states(self):
        """Update button states based on selected node status."""
        target_node_id = self.selected_node_id.get()
        
        # Default: disable node-specific buttons
        activate_state = tk.DISABLED
        delete_state = tk.DISABLED
        stop_state = tk.DISABLED
        
        if target_node_id in self.nodes:
            node = self.nodes[target_node_id]
            if node.running:
                stop_state = tk.NORMAL  # Can stop running nodes
            else:
                activate_state = tk.NORMAL  # Can activate stopped nodes
                if node.can_delete():
                    delete_state = tk.NORMAL  # Can delete fully stopped nodes
        
        self.stop_button.config(state=stop_state)
        self.activate_button.config(state=activate_state)
        self.delete_button.config(state=delete_state)
    
    def execute_command(self):
        """Execute command on selected node."""
        command = self.command_entry.get().strip()
        if not command:
            return
        
        target_node_id = self.selected_node_id.get()
        
        if target_node_id not in self.nodes:
            self.log_to_output(f"❌ Error: Node {target_node_id} does not exist")
            return
        
        node = self.nodes[target_node_id]
        if not node.running:
            self.log_to_output(f"❌ Error: Node {target_node_id} is not running")
            return
        
        # Clear command entry
        self.command_entry.delete(0, tk.END)
        
        # Log command execution
        self.log_to_output(f"\n[{time.strftime('%H:%M:%S')}] Node {target_node_id}> {command}")
        
        # Add to node's command queue
        node.command_queue.put(command)
        
        # Start result collector
        self.master.after(100, lambda: self.collect_command_result(target_node_id))
    
    def collect_command_result(self, node_id: int):
        """Collect and display command result from node."""
        node = self.nodes[node_id]
        
        try:
            # Non-blocking get
            result = node.output_queue.get_nowait()
            self.log_to_output(result)
        except queue.Empty:
            # Check again later
            if node.running:
                self.master.after(50, lambda: self.collect_command_result(node_id))
    
    def log_to_output(self, message: str):
        """Log message to output area with thread safety."""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, message + "\n")
        
        # Limit buffer size
        if int(self.output_text.index('end-1c').split('.')[0]) > self.buffer_limit:
            self.output_text.delete('1.0', f'{self.buffer_limit - 100}.0')
        
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def stop_all_nodes(self):
        """Stop all running nodes."""
        if not self.nodes:
            return
        
        if not messagebox.askyesno("Confirm", "Stop all nodes? This will terminate the network."):
            return
        
        self.log_to_output("\n🛑 Stopping all nodes...")
        
        for node_id, node in self.nodes.items():
            if node.running:
                self.log_to_output(f"   Stopping Node {node_id}...")
                node.stop()
        
        self.log_to_output("✅ All nodes stopped")
        self.refresh_node_list()
    
    def on_closing(self):
        """Handle window closing."""
        if self.nodes and any(node.running for node in self.nodes.values()):
            if not messagebox.askyesno("Confirm Exit", "Nodes are still running. Exit anyway?"):
                return
        
        self.log_to_output("Shutting down network manager...")
        
        # Stop all nodes
        for node in self.nodes.values():
            node.stop()
        
        # Wait a moment for cleanup
        time.sleep(1)
        
        self.master.destroy()
        log.info("GUI closed, application exiting")


def main():
    """Main entry point."""
    # Setup signal handlers
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
    
    # Create GUI
    root = tk.Tk()
    app = TestNetworkGUI(root)
    
    # Set close handler
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Start with one node by default
    log.info("Starting initial genesis node...")
    root.after(500, lambda: app.add_node_dialog())
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        log.info("Keyboard interrupt, exiting...")
    except Exception as e:
        log.error(f"Fatal GUI error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.error(f"Application failed to start: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

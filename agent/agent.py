#!/usr/bin/env python3
"""
ionShell Agent (Beacon Client)
Educational use only — lab environments only.

Responsibilities:
- Connect to controller
- Report system metadata
- Execute ONLY whitelisted commands
- Return results securely
- Exit on disconnect
"""

import argparse
import json
import os
import platform
import shlex
import socket
import subprocess
import sys
import time
from typing import Dict, List

# Local modules
from . import crypto, protocol


# Whitelist of safe, informational commands only
# ⚠️ Never add destructive or privilege-escalation commands
COMMAND_WHITELIST = {
    # Linux/macOS
    "pwd", "ls", "whoami", "uname", "hostname", "id", "date",
    # Windows
    "cd", "dir", "whoami", "ver", "hostname", "echo %cd%",
    # Cross-platform safe
    "echo"
}

SAFE_ENV = {
    'PATH': '/usr/bin:/bin:/usr/sbin:/sbin' if os.name != 'nt' else os.environ.get('PATH', ''),
    'HOME': os.environ.get('HOME', ''),
    'USER': os.environ.get('USER', ''),
}


class Agent:
    def __init__(self, host: str, port: int, psk: bytes):
        self.host = host
        self.port = port
        self.psk = psk
        self.sock = None

    def connect(self) -> bool:
        """Establish connection to controller."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print(f"[+] Connected to controller {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}", file=sys.stderr)
            return False

    def send_message(self, msg: dict) -> bool:
        """Send encrypted message to controller."""
        try:
            encrypted = crypto.encrypt_message(msg, self.psk)
            self.sock.sendall(len(encrypted).to_bytes(4, 'big') + encrypted)
            return True
        except Exception as e:
            print(f"[!] Send error: {e}", file=sys.stderr)
            return False

    def recv_message(self) -> Dict:
        """Receive and decrypt message from controller."""
        try:
            raw_len = self.sock.recv(4)
            if not raw_len:
                return {}
            msg_len = int.from_bytes(raw_len, 'big')
            if msg_len > 1024 * 1024:
                raise ValueError("Message too large")
            encrypted = self.sock.recv(msg_len)
            return crypto.decrypt_message(encrypted, self.psk)
        except Exception as e:
            print(f"[!] Recv error: {e}", file=sys.stderr)
            return {}

    def get_metadata(self) -> dict:
        """Collect safe system metadata for handshake."""
        return {
            "type": "hello",
            "os": platform.system(),
            "hostname": platform.node(),
            "user": getpass.getuser() if hasattr(getpass, 'getuser') else os.getenv('USER', 'unknown'),
            "pid": os.getpid()
        }

    def execute_command(self, cmd: str) -> dict:
        """
        Execute a whitelisted command safely.
        
        Defense-in-depth:
        - Strict whitelist
        - No shell=True (prevents injection)
        - Timeout
        - Environment sanitization
        """
        # Normalize and check whitelist
        parts = shlex.split(cmd)
        if not parts:
            return {"type": "error", "msg": "Empty command"}
        
        base_cmd = parts[0].lower()
        
        # Whitelist check (case-insensitive for Windows)
        if base_cmd not in {c.lower() for c in COMMAND_WHITELIST}:
            return {
                "type": "error",
                "msg": f"Command '{base_cmd}' not allowed"
            }

        try:
            # Use timeout to prevent hangs
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=10,
                env=SAFE_ENV,
                cwd=os.getcwd()
            )
            return {
                "type": "result",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"type": "error", "msg": "Command timed out"}
        except FileNotFoundError:
            return {"type": "error", "msg": f"Command '{base_cmd}' not found"}
        except Exception as e:
            return {"type": "error", "msg": f"Execution failed: {e}"}

    def run(self):
        """Main agent loop."""
        if not self.connect():
            sys.exit(1)

        # Send handshake
        metadata = self.get_metadata()
        if not self.send_message(metadata):
            print("[!] Failed to send handshake", file=sys.stderr)
            sys.exit(1)

        print(f"[i] Agent started as PID {metadata['pid']}")

        try:
            while True:
                msg = self.recv_message()
                if not msg:
                    print("[i] Controller disconnected")
                    break

                msg_type = msg.get("type")
                if msg_type == "disconnect":
                    print("[i] Disconnect requested by controller")
                    break
                elif msg_type == "command":
                    cmd = msg.get("cmd", "").strip()
                    if cmd:
                        result = self.execute_command(cmd)
                        self.send_message(result)
                    else:
                        self.send_message({"type": "error", "msg": "No command provided"})
                else:
                    print(f"[?] Unknown message type: {msg_type}", file=sys.stderr)
        except KeyboardInterrupt:
            print("\n[i] Agent interrupted")
        finally:
            self.sock.close()


# Fallback for getpass.getuser() on minimal systems
try:
    import getpass
except ImportError:
    import pwd
    def getpass_getuser():
        return pwd.getpwuid(os.getuid()).pw_name
    getpass = type('getpass', (), {'getuser': getpass_getuser})()


def main():
    parser = argparse.ArgumentParser(description="ionShell Agent (Beacon) — Educational Use Only")
    parser.add_argument("--host", "-H", required=True,
                        help="Controller IP address")
    parser.add_argument("--port", "-p", type=int, default=8080,
                        help="Controller port (default: 8080)")
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

    print("[i] ionShell Agent v0.1 (edu)")
    print("[i] For authorized lab use only.\n")

    agent = Agent(args.host, args.port, psk)
    agent.run()


if __name__ == "__main__":
    main()
"""
ionShell Protocol Definitions (Shared)
Message schemas for controller-agent communication.

All messages are JSON objects with a "type" field.

Design philosophy:
- Explicit types prevent ambiguity
- Minimal fields reduce attack surface
- Human-readable for learning
"""

# Example messages:

# Agent → Controller (Handshake)
# {
#   "type": "hello",
#   "os": "Linux",
#   "hostname": "lab-ubuntu",
#   "user": "student",
#   "pid": 1234
# }

# Controller → Agent (Command)
# {
#   "type": "command",
#   "cmd": "pwd"
# }

# Agent → Controller (Result)
# {
#   "type": "result",
#   "stdout": "/home/student\n",
#   "stderr": "",
#   "exit_code": 0
# }

# Agent → Controller (Error)
# {
#   "type": "error",
#   "msg": "Command not allowed"
# }
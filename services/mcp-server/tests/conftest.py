import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MCP_ALLOWED_HOSTS", "testserver,localhost:*,127.0.0.1:*")

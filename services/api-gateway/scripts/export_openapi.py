"""
Write the gateway's OpenAPI schema to openapi.json (or the path given as an argument).

The dashboard's TypeScript API types are generated from this file, and CI checks that
both are up to date. Importing the app does not connect to MongoDB or start a server.
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Settings require these; no connection is made while exporting the schema.
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")
os.environ.setdefault("JWT_SECRET", "schema-export-only")

from app import app  # noqa: E402

output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "openapi.json"
output.write_text(json.dumps(app.openapi(), indent=2) + "\n")
print(f"Wrote {output}")

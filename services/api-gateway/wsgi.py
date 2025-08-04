import os
import uvicorn

from app import app

if __name__ == "__main__":
    # Use environment variables for host and port configuration
    # Default to localhost for security, allow override via environment
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    reload = os.getenv("RELOAD", "true").lower() == "true"
    
    uvicorn.run("app:app", host=host, port=port, reload=reload)

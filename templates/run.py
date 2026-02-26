#!/usr/bin/env python3
"""
run.py — Start the NetControl server.

Usage:
    python run.py              # Starts on port 8080
    python run.py --port 9000  # Custom port
"""

import argparse
import sys
import os
import uvicorn

# Add project root to Python path so we can import netcontrol
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetControl Automation Hub")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=8080, help="Port number")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on changes")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════╗
║           NetControl Automation Hub              ║
║                                                  ║
║   API:       http://localhost:{args.port}/api           ║
║   Frontend:  http://localhost:{args.port}/              ║
║   Docs:      http://localhost:{args.port}/docs          ║
╚══════════════════════════════════════════════════╝
    """)

    uvicorn.run("netcontrol.app:app", host=args.host, port=args.port, reload=args.reload)

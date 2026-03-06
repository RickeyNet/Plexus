
#!/usr/bin/env python3
"""
run.py — Start the Plexus server.

Usage:
    python run.py                   # Starts on localhost:8080
    python run.py --port 9000       # Custom port
    python run.py --https           # Enable HTTPS with auto-generated certs
    python run.py --expose          # Bind to 0.0.0.0 (accessible on network)
"""

# Ensure Plexus is in the Python path for netcontrol.* imports
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import argparse
import asyncio
import functools
import os
import socket
import sys

import uvicorn
from netcontrol.version import APP_VERSION

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

CERTS_DIR = os.path.join(project_root, "certs")


def _env_flag(name: str, default: bool = False) -> bool:
    """Parse truthy/falsey env vars like '1', 'true', 'yes', 'on'."""
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def generate_self_signed_cert():
    """Generate a self-signed SSL certificate for HTTPS."""
    os.makedirs(CERTS_DIR, exist_ok=True)
    cert_file = os.path.join(CERTS_DIR, "cert.pem")
    key_file = os.path.join(CERTS_DIR, "key.pem")

    if os.path.isfile(cert_file) and os.path.isfile(key_file):
        return cert_file, key_file

    try:
        import datetime
        import ipaddress

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Plexus"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Plexus"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))

        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass

        print(f"[ssl] Generated self-signed certificate in {CERTS_DIR}/")
        return cert_file, key_file

    except ImportError:
        print("[ssl] ERROR: 'cryptography' package required for HTTPS.")
        sys.exit(1)


# Graceful shutdown handler
def handle_shutdown(signal, loop):
    print("\nShutting down gracefully...")
    for task in asyncio.all_tasks(loop):
        task.cancel()
    loop.stop()


# Suppress ConnectionResetError globally for socket operations
def ignore_connection_reset_error(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ConnectionResetError:
            pass
    return wrapper

if os.name == "nt":
    original_shutdown = socket.socket.shutdown
    socket.socket.shutdown = ignore_connection_reset_error(original_shutdown)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plexus Automation Hub")
    parser.add_argument("--version", action="version", version=f"Plexus {APP_VERSION}")
    parser.add_argument("--host", default=os.getenv("APP_HOST"), help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=int(os.getenv("APP_PORT", "8080")), help="Port number")
    parser.add_argument("--reload", action="store_true", default=_env_flag("APP_RELOAD", False), help="Auto-reload on changes")
    parser.add_argument("--https", action="store_true", default=_env_flag("APP_HTTPS", False), help="Enable HTTPS with self-signed cert")
    parser.add_argument("--expose", action="store_true", default=_env_flag("APP_EXPOSE", False), help="Bind to 0.0.0.0 (network accessible)")
    args = parser.parse_args()

    bind_host = args.host or ("0.0.0.0" if args.expose else "127.0.0.1")
    protocol = "https" if args.https else "http"

    ssl_kwargs = {}
    if args.https:
        cert_file, key_file = generate_self_signed_cert()
        ssl_kwargs = {"ssl_certfile": cert_file, "ssl_keyfile": key_file}

    access_note = "network" if bind_host == "0.0.0.0" else "localhost only"

    print(f"""
╔══════════════════════════════════════════════════════╗
║            Plexus Automation Hub                     ║
║                                                      ║
║   URL:     {protocol}://localhost:{args.port:<5}                  ║
║   Docs:    {protocol}://localhost:{args.port:<5}/docs             ║
║   Bind:    {bind_host:<15} ({access_note})           ║
║   HTTPS:   {"Enabled" if args.https else "Disabled (use --https)":42}║
║                                                      ║
║   Default login:  admin / netcontrol                 ║
╚══════════════════════════════════════════════════════════╝
    """)

    uvicorn.run(
        "netcontrol.app:app",
        host=bind_host,
        port=args.port,
        reload=args.reload,
        **ssl_kwargs,
    )

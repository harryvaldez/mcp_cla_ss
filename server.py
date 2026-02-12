import asyncio
import json
import hashlib
import logging
import os
import re
import sys
import time
import uuid
import threading
import atexit
import signal
import decimal
from datetime import datetime, date, timedelta
from urllib.parse import quote, urlparse, urlunparse, urlsplit, urlunsplit
from typing import Any, Optional

from sshtunnel import SSHTunnelForwarder
from fastmcp import FastMCP
import pyodbc
from starlette.requests import Request
from starlette.responses import PlainTextResponse, JSONResponse, HTMLResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware import Middleware
from starlette.applications import Starlette
from starlette.routing import Route
import uvicorn

# Startup Confirmation Dialog
# As requested: "once this MCP is loaded, it will load a dialog box asking the user's confirmation"
if sys.platform == 'win32':
    try:
        import ctypes
        def show_startup_confirmation():
            # MessageBox constants
            MB_YESNO = 0x04
            MB_ICONQUESTION = 0x20
            MB_TOPMOST = 0x40000
            MB_SETFOREGROUND = 0x10000
            IDYES = 6

            result = ctypes.windll.user32.MessageBoxW(
                0, 
                "This MCP server is in Beta version.  Review all commands before running.  Do you want to proceed?", 
                "MCP Server Confirmation", 
                MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND
            )
            
            if result != IDYES:
                sys.exit(0)

        if os.environ.get("MCP_SKIP_CONFIRMATION", "").lower() != "true":
            show_startup_confirmation()
    except Exception as e:
        # If dialog fails, log it but proceed (or exit? safe to proceed if UI fails, but maybe log to stderr)
        sys.stderr.write(f"Warning: Could not show startup confirmation dialog: {e}\n")

# Configure structured logging
log_level_str = os.environ.get("MCP_LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_str, logging.INFO)
log_file = os.environ.get("MCP_LOG_FILE")

logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=log_file,
    filemode='a' if log_file else None
)
logger = logging.getLogger("mcp-sqlserver")

# Patch for Windows asyncio ProactorEventLoop "ConnectionResetError" noise on shutdown
# References:
# - https://bugs.python.org/issue39232 (bpo-39232)
# - https://github.com/python/cpython/issues/83413
# Rationale:
# On Windows, when the ProactorEventLoop is closing, if a connection is forcibly closed
# by the remote (or the process is terminating), _call_connection_lost can raise
# ConnectionResetError (WinError 10054). This is harmless but noisy in logs.
if sys.platform == 'win32':
    # This issue primarily affects Python 3.8+, where Proactor is the default.
    if sys.version_info >= (3, 8):
        try:
            from asyncio.proactor_events import _ProactorBasePipeTransport

            _original_call_connection_lost = _ProactorBasePipeTransport._call_connection_lost

            def _silenced_call_connection_lost(self, exc):
                try:
                    _original_call_connection_lost(self, exc)
                except ConnectionResetError:
                    pass  # Benign: connection forcibly closed by remote host during shutdown

            _ProactorBasePipeTransport._call_connection_lost = _silenced_call_connection_lost
            logger.debug("Applied workaround for asyncio ProactorEventLoop ConnectionResetError")
        except ImportError:
            logger.info("Could not import asyncio.proactor_events._ProactorBasePipeTransport; skipping workaround")
    else:
        logger.debug("Skipping asyncio ProactorEventLoop workaround (Python version < 3.8)")

def _get_auth() -> Any:
    auth_type = os.environ.get("FASTMCP_AUTH_TYPE")
    if not auth_type:
        return None

    auth_type_lower = auth_type.lower()
    allowed_auth_types = {"oidc", "jwt", "azure-ad", "github", "google", "oauth2", "none"}
    
    if auth_type_lower not in allowed_auth_types:
        raise ValueError(
            f"Invalid FASTMCP_AUTH_TYPE: '{auth_type}'. "
            f"Accepted values are: {', '.join(sorted(allowed_auth_types))}"
        )

    if auth_type_lower == "none":
        return None

    # Full OIDC Proxy (handles login flow)
    if auth_type_lower == "oidc":
        from fastmcp.server.auth.providers.oidc import OIDCProxy

        config_url = os.environ.get("FASTMCP_OIDC_CONFIG_URL")
        client_id = os.environ.get("FASTMCP_OIDC_CLIENT_ID")
        client_secret = os.environ.get("FASTMCP_OIDC_CLIENT_SECRET")
        base_url = os.environ.get("FASTMCP_OIDC_BASE_URL")

        if not all([config_url, client_id, client_secret, base_url]):
            raise RuntimeError(
                "OIDC authentication requires FASTMCP_OIDC_CONFIG_URL, FASTMCP_OIDC_CLIENT_ID, "
                "FASTMCP_OIDC_CLIENT_SECRET, and FASTMCP_OIDC_BASE_URL"
            )

        return OIDCProxy(
            config_url=config_url,
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            audience=os.environ.get("FASTMCP_OIDC_AUDIENCE"),
        )

    # Pure JWT Verification (resource server mode)
    if auth_type_lower == "jwt":
        from fastmcp.server.auth.providers.jwt import JWTVerifier

        jwks_uri = os.environ.get("FASTMCP_JWT_JWKS_URI")
        issuer = os.environ.get("FASTMCP_JWT_ISSUER")

        if not all([jwks_uri, issuer]):
            raise RuntimeError(
                "JWT verification requires FASTMCP_JWT_JWKS_URI and FASTMCP_JWT_ISSUER"
            )

        return JWTVerifier(
            jwks_uri=jwks_uri,
            issuer=issuer,
            audience=os.environ.get("FASTMCP_JWT_AUDIENCE"),
        )

    # Azure AD (Microsoft Entra ID) simplified configuration
    if auth_type_lower == "azure-ad":
        tenant_id = os.environ.get("FASTMCP_AZURE_AD_TENANT_ID")
        client_id = os.environ.get("FASTMCP_AZURE_AD_CLIENT_ID")
        
        if not all([tenant_id, client_id]):
            raise RuntimeError(
                "Azure AD authentication requires FASTMCP_AZURE_AD_TENANT_ID and FASTMCP_AZURE_AD_CLIENT_ID"
            )
            
        # Determine if we should use full OIDC flow or just JWT verification
        # If client_secret and base_url are provided, we use OIDC Proxy
        client_secret = os.environ.get("FASTMCP_AZURE_AD_CLIENT_SECRET")
        base_url = os.environ.get("FASTMCP_AZURE_AD_BASE_URL")
        
        config_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
        
        if client_secret and base_url:
            from fastmcp.server.auth.providers.oidc import OIDCProxy
            return OIDCProxy(
                config_url=config_url,
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
                audience=os.environ.get("FASTMCP_AZURE_AD_AUDIENCE", client_id),
            )
        else:
            from fastmcp.server.auth.providers.jwt import JWTVerifier
            jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
            issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
            return JWTVerifier(
                jwks_uri=jwks_uri,
                issuer=issuer,
                audience=os.environ.get("FASTMCP_AZURE_AD_AUDIENCE", client_id),
            )
            
    # GitHub OAuth2
    if auth_type_lower == "github":
        from fastmcp.server.auth.providers.github import GitHubProvider
        
        client_id = os.environ.get("FASTMCP_GITHUB_CLIENT_ID")
        client_secret = os.environ.get("FASTMCP_GITHUB_CLIENT_SECRET")
        if not all([client_id, client_secret]):
            raise RuntimeError(
                "GitHub authentication requires FASTMCP_GITHUB_CLIENT_ID and FASTMCP_GITHUB_CLIENT_SECRET"
            )

        # Default to public GitHub URL if the env var is not set
        base_url = os.environ.get("FASTMCP_GITHUB_BASE_URL", "https://github.com")

        return GitHubProvider(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )

    # Google OAuth2
    if auth_type_lower == "google":
        from fastmcp.server.auth.providers.google import GoogleProvider
        
        client_id = os.environ.get("FASTMCP_GOOGLE_CLIENT_ID")
        client_secret = os.environ.get("FASTMCP_GOOGLE_CLIENT_SECRET")
        base_url = os.environ.get("FASTMCP_GOOGLE_BASE_URL")
        
        if not all([client_id, client_secret, base_url]):
            raise RuntimeError(
                "Google authentication requires FASTMCP_GOOGLE_CLIENT_ID, "
                "FASTMCP_GOOGLE_CLIENT_SECRET, and FASTMCP_GOOGLE_BASE_URL"
            )
            
        return GoogleProvider(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )

    # Generic OAuth2 Proxy
    if auth_type_lower == "oauth2":
        from fastmcp.server.auth import OAuthProxy
        from fastmcp.server.auth.providers.jwt import JWTVerifier
        
        auth_url = os.environ.get("FASTMCP_OAUTH_AUTHORIZE_URL")
        token_url = os.environ.get("FASTMCP_OAUTH_TOKEN_URL")
        client_id = os.environ.get("FASTMCP_OAUTH_CLIENT_ID")
        client_secret = os.environ.get("FASTMCP_OAUTH_CLIENT_SECRET")
        base_url = os.environ.get("FASTMCP_OAUTH_BASE_URL")
        
        # Token verifier details
        jwks_uri = os.environ.get("FASTMCP_OAUTH_JWKS_URI")
        issuer = os.environ.get("FASTMCP_OAUTH_ISSUER")
        
        if not all([auth_url, token_url, client_id, client_secret, base_url, jwks_uri, issuer]):
            raise RuntimeError(
                "Generic OAuth2 requires FASTMCP_OAUTH_AUTHORIZE_URL, FASTMCP_OAUTH_TOKEN_URL, "
                "FASTMCP_OAUTH_CLIENT_ID, FASTMCP_OAUTH_CLIENT_SECRET, FASTMCP_OAUTH_BASE_URL, "
                "FASTMCP_OAUTH_JWKS_URI, and FASTMCP_OAUTH_ISSUER"
            )
            
        token_verifier = JWTVerifier(
            jwks_uri=jwks_uri,
            issuer=issuer,
            audience=os.environ.get("FASTMCP_OAUTH_AUDIENCE")
        )
        
        return OAuthProxy(
            upstream_authorization_endpoint=auth_url,
            upstream_token_endpoint=token_url,
            upstream_client_id=client_id,
            upstream_client_secret=client_secret,
            token_verifier=token_verifier,
            base_url=base_url
        )
            
def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return int(value)


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


# Initialize FastMCP
auth_type = os.environ.get("FASTMCP_AUTH_TYPE", "").lower()
mcp = FastMCP(
    name=os.environ.get("MCP_SERVER_NAME", "SQL Server MCP Server"),
    auth=_get_auth() if auth_type != "apikey" else None
)

# API Key Middleware for simple static token auth
class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # DEBUG LOG
        # logger.info(f"APIKeyMiddleware checking path: {path}")

        # 1. Compatibility Redirect: Redirect /mcp to /sse
        # Many users might try /mcp based on old docs or assumptions
        # Only redirect GET requests; POST requests might be for stateless JSON-RPC
        if path == "/mcp" and request.method == "GET":
            return RedirectResponse(url="/sse")

        # 2. Enforce API Key on SSE and Message endpoints
        # FastMCP mounts SSE at /sse and messages at /messages
        # We must protect both to prevent unauthorized access
        if path.startswith("/sse") or path.startswith("/messages"):
            auth_type = os.environ.get("FASTMCP_AUTH_TYPE", "").lower()
            logger.info(f"APIKeyMiddleware match. Auth type: {auth_type}")
            if auth_type == "apikey":
                auth_header = request.headers.get("Authorization")
                expected_key = os.environ.get("FASTMCP_API_KEY")
                
                if not expected_key:
                    logger.error("FASTMCP_API_KEY not configured but auth type is apikey")
                    return JSONResponse({"detail": "Server configuration error"}, status_code=500)
                
                # Check query param for SSE as fallback (standard for EventSource in some clients)
                token = None
                if auth_header and auth_header.startswith("Bearer "):
                    token = auth_header.split(" ")[1]
                elif "token" in request.query_params:
                    token = request.query_params["token"]
                elif "api_key" in request.query_params:
                    token = request.query_params["api_key"]
                
                if not token:
                    return JSONResponse({"detail": "Missing Authorization header or token"}, status_code=401)
                
                if token != expected_key:
                    return JSONResponse({"detail": "Invalid API Key"}, status_code=403)
        
        return await call_next(request)

# Browser-friendly middleware to handle direct visits to the SSE endpoint
class BrowserFriendlyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # If visiting the MCP endpoint with a browser (Accept: text/html)
        # and NOT providing the required text/event-stream header
        if request.url.path == "/mcp":
            accept = request.headers.get("accept", "")
            if "text/html" in accept and "text/event-stream" not in accept:
                logger.info(f"Interposing browser-friendly response for {request.url.path}")
                return HTMLResponse(f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>SQL Server MCP Server</title>
                        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                        <style>
                            .bg-gradient {{ background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); }}
                        </style>
                    </head>
                    <body class="bg-gray-50 min-h-screen flex items-center justify-center p-4">
                        <div class="bg-white rounded-2xl shadow-2xl max-w-2xl w-full overflow-hidden">
                            <div class="bg-gradient p-8 text-white">
                                <h1 class="text-4xl font-extrabold mb-2">SQL Server MCP Server</h1>
                                <p class="text-blue-100 text-lg opacity-90">Protocol Endpoint Detected</p>
                            </div>
                            
                            <div class="p-8">
                                <div class="flex items-start mb-6 bg-blue-50 p-4 rounded-xl border border-blue-100">
                                    <div class="bg-blue-500 text-white rounded-full p-2 mr-4 mt-1">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="id-circle" />
                                            <circle cx="12" cy="12" r="9" />
                                            <line x1="12" y1="8" x2="12" y2="12" />
                                            <line x1="12" y1="16" x2="12.01" y2="16" />
                                        </svg>
                                    </div>
                                    <div>
                                        <h3 class="text-blue-800 font-bold text-lg mb-1">MCP Protocol Active</h3>
                                        <p class="text-blue-700">
                                            This endpoint (<code class="bg-blue-100 px-1 rounded">/mcp</code>) is reserved for <strong>Model Context Protocol</strong> clients.
                                        </p>
                                    </div>
                                </div>

                                <p class="text-gray-600 mb-8 leading-relaxed">
                                    You are seeing this page because your browser cannot speak the <code>text/event-stream</code> protocol required for MCP. 
                                    To use this server, add this URL to your MCP client configuration (e.g., Claude Desktop).
                                </p>

                                <div class="space-y-4">
                                    <h4 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-2">Available Dashboards</h4>
                                    
                                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <a href="/data-model-analysis" class="group flex flex-col p-5 border border-gray-100 rounded-xl hover:border-blue-300 hover:shadow-md transition-all bg-white">
                                            <span class="text-blue-600 font-bold mb-1 group-hover:text-blue-700">Data Model Analysis</span>
                                            <span class="text-sm text-gray-500">View interactive ERD and schema health score.</span>
                                        </a>
                                        
                                        <a href="/sessions-monitor" class="group flex flex-col p-5 border border-gray-100 rounded-xl hover:border-blue-300 hover:shadow-md transition-all bg-white">
                                            <span class="text-blue-600 font-bold mb-1 group-hover:text-blue-700">Sessions Monitor</span>
                                            <span class="text-sm text-gray-500">Track real-time database connections and queries.</span>
                                        </a>
                                    </div>
                                </div>

                                <div class="mt-10 pt-6 border-t border-gray-100 flex justify-between items-center">
                                    <a href="/health" class="text-sm text-gray-400 hover:text-gray-600 transition-colors italic">Server Status: Healthy</a>
                                    <a href="/" class="bg-gray-900 text-white px-6 py-2 rounded-lg font-medium hover:bg-black transition-colors shadow-sm">
                                        View Server Info
                                    </a>
                                </div>
                            </div>
                        </div>
                    </body>
                    </html>
                """)
        return await call_next(request)

# Add the middleware to the FastMCP app
# MOVED to main() to ensure transport-specific app is configured correctly
# mcp.http_app().add_middleware(APIKeyMiddleware)
# mcp.http_app().add_middleware(BrowserFriendlyMiddleware)


def _build_connection_string_from_env() -> str | None:
    server = os.environ.get("SQL_SERVER")
    port = os.environ.get("SQL_PORT", "1433")
    user = os.environ.get("SQL_USER")
    password = os.environ.get("SQL_PASSWORD")
    database = os.environ.get("SQL_DATABASE")
    driver = os.environ.get("SQL_DRIVER", "ODBC Driver 17 for SQL Server")
    
    if not server or not user or not database:
        return None
        
    return f"DRIVER={{{driver}}};SERVER={server},{port};DATABASE={database};UID={user};PWD={password}"


CONNECTION_STRING = os.environ.get("SQL_CONNECTION_STRING") or _build_connection_string_from_env()
if not CONNECTION_STRING:
    raise RuntimeError(
        "Missing SQL_CONNECTION_STRING or SQL_SERVER/SQL_USER/SQL_DATABASE environment variables"
    )

# Capture original connection details
ORIGINAL_DB_HOST = os.environ.get("SQL_SERVER")
ORIGINAL_DB_PORT = int(os.environ.get("SQL_PORT", 1433))
ORIGINAL_DB_NAME = os.environ.get("SQL_DATABASE")

if os.environ.get("MCP_ALLOW_WRITE") is None:
    raise RuntimeError("MCP_ALLOW_WRITE environment variable is required (e.g. 'true' or 'false')")

ALLOW_WRITE = _env_bool("MCP_ALLOW_WRITE", False)
CONFIRM_WRITE = _env_bool("MCP_CONFIRM_WRITE", False)
TRANSPORT = os.environ.get("MCP_TRANSPORT", "http").lower()
AUTH_TYPE = os.environ.get("FASTMCP_AUTH_TYPE")

# Security Mechanisms for Write Mode
if ALLOW_WRITE:
    # Mechanism 1: Explicit Confirmation Latch (Prevents accidental enablement)
    if not CONFIRM_WRITE:
        raise RuntimeError(
            "Security Check Failed: Write mode enabled (MCP_ALLOW_WRITE=true) "
            "but missing confirmation. You must also set MCP_CONFIRM_WRITE=true."
        )

    # Mechanism 2: Transport Security / Auth Enforcement (Prevents insecure exposure)
    # If running over HTTP, we MUST have some form of authentication configured.
    if TRANSPORT == "http" and not AUTH_TYPE:
        raise RuntimeError(
            "Security Check Failed: Write mode enabled over HTTP without authentication. "
            "You must configure FASTMCP_AUTH_TYPE (e.g., 'azure-ad', 'oidc', 'jwt') "
            "or use stdio transport for local access."
        )

DEFAULT_MAX_ROWS = _env_int("MCP_MAX_ROWS", 500)
POOL_MIN_SIZE = _env_int("MCP_POOL_MIN_SIZE", 1)
POOL_MAX_SIZE = _env_int("MCP_POOL_MAX_SIZE", 20)
POOL_TIMEOUT = float(os.environ.get("MCP_POOL_TIMEOUT", "60.0"))
POOL_MAX_WAITING = _env_int("MCP_POOL_MAX_WAITING", 20)
STATEMENT_TIMEOUT_MS = _env_int("MCP_STATEMENT_TIMEOUT_MS", 120000) # 120s default


# SSH Tunnel Configuration
SSH_HOST = os.environ.get("SSH_HOST")
SSH_USER = os.environ.get("SSH_USER")
SSH_PASSWORD = os.environ.get("SSH_PASSWORD")
SSH_PKEY = os.environ.get("SSH_PKEY")
SSH_PORT = _env_int("SSH_PORT", 22)

# Global reference to keep tunnel alive
_ssh_tunnel = None

if SSH_HOST and SSH_USER:
    logger.info(f"Configuring SSH tunnel to {SSH_USER}@{SSH_HOST}:{SSH_PORT}...")
    
    # Use explicitly provided host/port for binding
    remote_bind_host = ORIGINAL_DB_HOST
    remote_bind_port = ORIGINAL_DB_PORT
    
    if not remote_bind_host:
        raise RuntimeError(
            "SSH requested but SQL_SERVER is missing."
        )
    
        # Read allow_agent configuration from environment variable
        allow_ssh_agent = os.environ.get("ALLOW_SSH_AGENT", "false").lower() in ("true", "1", "yes", "on")
        
        ssh_args = {
            "ssh_address_or_host": (SSH_HOST, SSH_PORT),
            "ssh_username": SSH_USER,
            "remote_bind_address": (remote_bind_host, remote_bind_port),
            "allow_agent": allow_ssh_agent, # Configurable via ALLOW_SSH_AGENT environment variable
        }
        
        if SSH_PASSWORD:
            ssh_args["ssh_password"] = SSH_PASSWORD
        if SSH_PKEY:
            ssh_args["ssh_pkey"] = SSH_PKEY
            
        logger.info(f"Starting SSH tunnel to remote bind: {remote_bind_host}:{remote_bind_port}")
        _ssh_tunnel = SSHTunnelForwarder(**ssh_args)
        _ssh_tunnel.start()
        
        logger.info(f"SSH tunnel established. Local bind port: {_ssh_tunnel.local_bind_port}")
        
        # Reconstruct CONNECTION_STRING with local port
        driver = os.environ.get("SQL_DRIVER", "ODBC Driver 17 for SQL Server")
        user = os.environ.get("SQL_USER")
        password = os.environ.get("SQL_PASSWORD")
        database = os.environ.get("SQL_DATABASE")
        
        # Note: SQL Server ODBC uses comma for port in SERVER connection string parameter
        CONNECTION_STRING = f"DRIVER={{{driver}}};SERVER=127.0.0.1,{_ssh_tunnel.local_bind_port};DATABASE={database};UID={user};PWD={password}"
        
        logger.info("Updated CONNECTION_STRING to use SSH tunnel.")
        
    except Exception as e:
        logger.error(f"Failed to establish SSH tunnel: {e}")
        # We raise here because if the user asked for SSH and it fails, we shouldn't proceed
        # attempting to connect directly (which would likely timeout or fail anyway)
        raise RuntimeError(f"SSH Tunnel setup failed: {e}") from e


def _cleanup_ssh_tunnel():
    """Cleanup function to stop SSH tunnel on process exit."""
    global _ssh_tunnel
    if _ssh_tunnel is not None:
        try:
            logger.info("Closing SSH tunnel...")
            _ssh_tunnel.stop()
            _ssh_tunnel = None
            logger.info("SSH tunnel closed.")
        except Exception as e:
            logger.error(f"Error closing SSH tunnel: {e}")


# Register cleanup handlers
atexit.register(_cleanup_ssh_tunnel)

# Register signal handlers for graceful shutdown
def _signal_handler(signum, frame):
    logger.info(f"Received signal {signum}, cleaning up...")
    _cleanup_ssh_tunnel()
    sys.exit(0)

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


def get_connection():
    return pyodbc.connect(CONNECTION_STRING)


_SINGLE_QUOTED = re.compile(r"'(?:''|[^'])*'")
_DOUBLE_QUOTED = re.compile(r'"(?:[^"]|"")*"')
_LINE_COMMENT = re.compile(r"--[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*[\s\S]*?\*/")


def _strip_sql_noise(sql: str) -> str:
    s = _BLOCK_COMMENT.sub(" ", sql)
    s = _LINE_COMMENT.sub(" ", s)
    s = _SINGLE_QUOTED.sub(" ", s)
    s = _DOUBLE_QUOTED.sub(" ", s)
    return s


_WRITE_KEYWORDS = {
    "insert",
    "update",
    "delete",
    "merge",
    "create",
    "alter",
    "drop",
    "truncate",
    "grant",
    "revoke",
    "comment",
    "vacuum",
    "analyze",
    "reindex",
    "cluster",
    "refresh",
    "copy",
    "call",
    "do",
    "execute",
    "reset",
    "lock",
    "commit",
    "rollback",
    "begin",
    "savepoint",
    "release",
}

_READONLY_START = {"select", "with", "show", "explain", "set"}


def _is_sql_readonly(sql: str) -> bool:
    cleaned = _strip_sql_noise(sql).strip().lower()
    if not cleaned:
        return False
    # Check if first word is a known read-only starting keyword
    first = cleaned.split(None, 1)[0]
    if first not in _READONLY_START:
        return False
    # Ensure no write keywords exist anywhere in the tokens
    tokens = re.findall(r"[a-zA-Z_]+", cleaned)
    return not any(t in _WRITE_KEYWORDS for t in tokens)


def _require_readonly(sql: str) -> None:
    if ALLOW_WRITE:
        return
    if not _is_sql_readonly(sql):
        logger.warning(f"BLOCKED write attempt in read-only mode: {sql[:200]}...")
        raise ValueError(
            "Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable."
        )


def _fetch_limited(cur, max_rows: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    remaining = max_rows
    while remaining > 0:
        batch = cur.fetchmany(min(remaining, 200))
        if not batch:
            break
        rows.extend(batch)
        remaining -= len(batch)
    return rows


def _execute_safe(cur, sql_query: str, params: Any = None) -> None:
    """Executes a query with sanitized error handling."""
    try:
        if logger.isEnabledFor(logging.DEBUG):
            # Log query (truncated if too long for sanity)
            query_str = str(sql_query)
            if len(query_str) > 1000:
                query_str = query_str[:1000] + "..."
            logger.debug(f"Executing SQL: {query_str} | Params: {params}")

        # SQL Server timeout
        # cur.timeout = int(STATEMENT_TIMEOUT_MS / 1000)
        
        if params:
            cur.execute(sql_query, params)
        else:
            cur.execute(sql_query)
            
    except pyodbc.Error as e:
        logger.error(f"Database error: {str(e)}")
        if "timeout" in str(e).lower():
            raise RuntimeError("Query execution timed out.") from e
        raise RuntimeError(f"Database operation failed: {str(e)}") from e
    except Exception as e:
        logger.exception("Unexpected error during query execution")
        raise RuntimeError("An unexpected error occurred while processing the query.") from e


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


@mcp.custom_route("/", methods=["GET"])
async def root(_request: Request) -> HTMLResponse:
    return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PostgreSQL MCP Server</title>
            <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
            <style>
                .bg-gradient {{ background: linear-gradient(135deg, #111827 0%, #1f2937 100%); }}
            </style>
        </head>
        <body class="bg-gray-50 min-h-screen font-sans">
            <nav class="bg-gradient text-white p-6 shadow-lg">
                <div class="max-w-5xl mx-auto flex justify-between items-center">
                    <h1 class="text-2xl font-bold tracking-tight">PostgreSQL MCP Server</h1>
                    <span class="bg-green-500 text-white text-xs font-bold px-3 py-1 rounded-full uppercase tracking-widest">Online</span>
                </div>
            </nav>

            <main class="max-w-5xl mx-auto p-8">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
                    <div class="md:col-span-2">
                        <h2 class="text-3xl font-extrabold text-gray-900 mb-4">Server Status & Info</h2>
                        <p class="text-lg text-gray-600 mb-6">
                            This server provides a high-performance <strong>Model Context Protocol (MCP)</strong> interface to your PostgreSQL database.
                        </p>
                        
                        <div class="bg-white p-6 rounded-2xl border border-gray-100 shadow-sm mb-8">
                            <h3 class="text-sm font-bold text-gray-400 uppercase tracking-widest mb-4">Connection Details</h3>
                            <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-6">
                                <div>
                                    <dt class="text-sm text-gray-500">MCP Protocol Endpoint</dt>
                                    <dd class="text-gray-900 font-mono text-sm bg-gray-50 p-2 rounded mt-1 border border-gray-100">/mcp</dd>
                                </div>
                                <div>
                                    <dt class="text-sm text-gray-500">Health Check</dt>
                                    <dd class="text-gray-900 font-mono text-sm bg-gray-50 p-2 rounded mt-1 border border-gray-100">/health</dd>
                                </div>
                                <div>
                                    <dt class="text-sm text-gray-500">Database Host</dt>
                                    <dd class="text-gray-900 font-medium mt-1">{ORIGINAL_DB_HOST or "N/A"}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm text-gray-500">Database Name</dt>
                                    <dd class="text-gray-900 font-medium mt-1">{ORIGINAL_DB_NAME or "N/A"}</dd>
                                </div>
                            </dl>
                        </div>
                    </div>

                    <div class="space-y-6">
                        <div class="bg-blue-600 p-6 rounded-2xl text-white shadow-xl">
                            <h3 class="font-bold text-xl mb-3 text-white">Interactive Tools</h3>
                            <p class="text-blue-100 text-sm mb-6 opacity-90">Access your database insights through these specialized dashboards.</p>
                            
                            <div class="space-y-3">
                                <a href="/data-model-analysis" class="block w-full text-center bg-white text-blue-700 font-bold py-3 rounded-xl hover:bg-blue-50 transition-colors">
                                    Data Model Analysis
                                </a>
                                <a href="/sessions-monitor" class="block w-full text-center bg-blue-500 text-white border border-blue-400 font-bold py-3 rounded-xl hover:bg-blue-400 transition-colors">
                                    Sessions Monitor
                                </a>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="bg-yellow-50 border-l-4 border-yellow-400 p-6 rounded-r-2xl mb-12">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <svg class="h-6 w-6 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <div class="ml-3">
                            <h3 class="text-sm font-bold text-yellow-800 uppercase tracking-wider">How to connect</h3>
                            <div class="mt-2 text-sm text-yellow-700">
                                <p>To use this server with Claude Desktop, add the following to your configuration:</p>
                                <pre class="mt-2 p-3 bg-white bg-opacity-50 rounded font-mono text-xs overflow-x-auto">"mcpServers": {{
    "sqlserver": {{
        "command": "docker",
        "args": ["run", "-i", "--rm", "-e", "SQL_SERVER=...", "harryvaldez/mcp-sql-server:latest"]
    }}
}}</pre>
                            </div>
                        </div>
                    </div>
                </div>
            </main>

            <footer class="max-w-5xl mx-auto p-8 border-t border-gray-100 text-center text-gray-400 text-sm">
                &copy; {datetime.now().year} MCP SQL Server &bull; Running on FastMCP
            </footer>
        </body>
        </html>
    """)


@mcp.tool
def db_sql2019_create_db_user(
    username: str,
    password: str,
    privileges: str = "read",
    database: str | None = None
) -> str:
    """
    Creates a new database user and assigns privileges.

    Args:
        username: The name of the user to create.
        password: The password for the new user.
        privileges: 'read' for SELECT only, 'read-write' for full DML access.
        database: The database to grant access to (default: current database).
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable user creation.")

    if privileges not in ["read", "read-write"]:
        raise ValueError("privileges must be either 'read' or 'read-write'")

    # Basic input validation for username to prevent SQL injection in identifiers
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", username):
        raise ValueError("Invalid username format. Use only alphanumeric characters and underscores, starting with a letter.")

    conn = get_connection()
    try:
        cur = conn.cursor()
        
        # Resolve database if not provided
        cur.execute("SELECT DB_NAME()")
        current_db = cur.fetchone()[0]
        
        target_db = database if database is not None else current_db
        is_same_db = target_db == current_db

        if not is_same_db:
             # For SQL Server, we can switch database context easily if the login has access
             # But for simplicity, we'll warn if target is different or try to USE it.
             # However, USE statement changes context for the connection.
             # Let's try to stick to current DB or warn.
             pass

        # 1. Create Login (Server Level)
        # Check if login exists
        cur.execute("SELECT name FROM sys.sql_logins WHERE name = ?", username)
        if not cur.fetchone():
            logger.info(f"Creating SQL login: {username}")
            # Dynamic SQL for CREATE LOGIN as it doesn't support parameters directly
            cur.execute(f"CREATE LOGIN [{username}] WITH PASSWORD = '{password}'")
        else:
            logger.info(f"Login {username} already exists, proceeding to create user in database.")

        # 2. Create User in Database (Database Level)
        # We need to be in the target database. 
        # In SQL Server, we can execute: USE [TargetDB]; CREATE USER ...
        
        logger.info(f"Creating database user {username} in {target_db}")
        
        # Switch to target DB
        cur.execute(f"USE [{target_db}]")
        
        # Check if user exists in DB
        cur.execute("SELECT name FROM sys.database_principals WHERE name = ?", username)
        if not cur.fetchone():
            cur.execute(f"CREATE USER [{username}] FOR LOGIN [{username}]")
        
        # 3. Grant Permissions
        if privileges == "read":
            cur.execute(f"ALTER ROLE [db_datareader] ADD MEMBER [{username}]")
        else:
            cur.execute(f"ALTER ROLE [db_datareader] ADD MEMBER [{username}]")
            cur.execute(f"ALTER ROLE [db_datawriter] ADD MEMBER [{username}]")
            # If full DML/DDL needed, maybe db_owner? But 'read-write' usually implies data modification.
            # Let's stick to reader/writer roles.

        conn.commit()
        return f"User '{username}' created successfully with {privileges} privileges on database '{target_db}'."
        
    finally:
        conn.close()


@mcp.tool
def db_sql2019_drop_db_user(username: str) -> str:
    """
    Drops a database user and login.

    Args:
        username: The name of the user to drop.

    Returns:
        A message indicating success.
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable user deletion.")

    # Basic input validation for username
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", username):
        raise ValueError("Invalid username format.")

    conn = get_connection()
    try:
        cur = conn.cursor()
        logger.info(f"Dropping database user: {username}")
        
        # 1. Drop User from Current Database
        cur.execute("SELECT DB_NAME()")
        current_db = cur.fetchone()[0]
        
        cur.execute("SELECT name FROM sys.database_principals WHERE name = ?", username)
        if cur.fetchone():
            cur.execute(f"DROP USER [{username}]")
        
        # 2. Drop Login (Server Level)
        cur.execute("SELECT name FROM sys.server_principals WHERE name = ?", username)
        if cur.fetchone():
             cur.execute(f"DROP LOGIN [{username}]")
             
        conn.commit()
        return f"User and Login '{username}' dropped successfully from '{current_db}'."
    finally:
        conn.close()
            _execute_safe(
                cur,
                sql.SQL("DROP OWNED BY {}").format(sql.Identifier(username)),
            )
            _execute_safe(
                cur,
                sql.SQL("DROP ROLE {}").format(sql.Identifier(username)),
            )
            return f"User '{username}' dropped successfully."


@mcp.tool
def db_sql2019_alter_object(
    object_type: str,
    object_name: str,
    operation: str,
    schema: str | None = None,
    owner: str | None = None,
    parameters: dict[str, Any] | None = None
) -> str:
    """
    Executes ALTER DDL statements for database objects.
    
    Args:
        object_type: One of: database, schema, table, view, index, function, procedure, trigger, server.
        object_name: Name of the object.
        operation: One of: rename, owner_to, set_schema, add_column, rename_column, alter_column, drop_column.
        schema: Schema name (required for schema-scoped objects).
        owner: New owner name (for 'owner_to' operation).
        parameters: Additional parameters for specific operations:
            - new_name: for 'rename' (target name)
            - new_schema: for 'set_schema'
            - column_name: for column operations
            - new_column_name: for 'rename_column'
            - data_type: for 'add_column', 'alter_column'
            - not_null: bool, for 'alter_column'
            - default: any, for 'alter_column' (ADD DEFAULT CONSTRAINT)
            - constraints: str, for 'add_column' (e.g. "NOT NULL DEFAULT 0")
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable.")

    params = parameters or {}
    op = operation.lower()
    obj_type = object_type.lower()
    
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        # --- Universal Operations ---
        
        if op == 'rename':
            new_name = params.get('new_name')
            if not new_name:
                raise ValueError("Parameter 'new_name' required for rename.")
            
            # SQL Server uses sp_rename for tables, columns, indexes
            # EXEC sp_rename 'schema.table', 'new_table';
            # EXEC sp_rename 'schema.table.col', 'new_col', 'COLUMN';
            
            full_obj_name = f"{schema}.{object_name}" if schema else object_name
            
            if obj_type == 'column':
                # Special case handled via rename_column op, but if called here:
                raise ValueError("Use 'rename_column' operation for columns.")
            elif obj_type == 'index':
                # sp_rename 'table.index', 'new_index', 'INDEX'
                table_name = params.get('table_name')
                if not table_name:
                     raise ValueError("Parameter 'table_name' required for renaming indexes.")
                full_obj_name = f"{schema}.{table_name}.{object_name}" if schema else f"{table_name}.{object_name}"
                cur.execute(f"EXEC sp_rename '{full_obj_name}', '{new_name}', 'INDEX'")
            elif obj_type == 'trigger':
                 # sp_rename 'schema.trigger', 'new_trigger'
                 cur.execute(f"EXEC sp_rename '{full_obj_name}', '{new_name}'")
            elif obj_type == 'database':
                # ALTER DATABASE [Old] MODIFY NAME = [New]
                cur.execute(f"ALTER DATABASE [{object_name}] MODIFY NAME = [{new_name}]")
            else:
                # Tables, Views, Procs, Functions
                cur.execute(f"EXEC sp_rename '{full_obj_name}', '{new_name}'")

        elif op == 'owner_to':
            if not owner:
                raise ValueError("Parameter 'owner' required for owner_to operation.")
            
            if obj_type == 'schema':
                # ALTER AUTHORIZATION ON SCHEMA::[schema] TO [owner]
                cur.execute(f"ALTER AUTHORIZATION ON SCHEMA::[{object_name}] TO [{owner}]")
            elif obj_type == 'database':
                # ALTER AUTHORIZATION ON DATABASE::[db] TO [owner]
                cur.execute(f"ALTER AUTHORIZATION ON DATABASE::[{object_name}] TO [{owner}]")
            elif obj_type in ('table', 'view', 'function', 'procedure'):
                 full_obj_name = f"[{schema}].[{object_name}]" if schema else f"[{object_name}]"
                 cur.execute(f"ALTER AUTHORIZATION ON OBJECT::{full_obj_name} TO [{owner}]")
            else:
                raise ValueError(f"Changing owner for {obj_type} is not directly supported via this tool.")

        elif op == 'set_schema':
            new_schema = params.get('new_schema')
            if not new_schema:
                raise ValueError("Parameter 'new_schema' required for set_schema.")
            
            # ALTER SCHEMA [NewSchema] TRANSFER [OldSchema].[Object]
            if not schema:
                raise ValueError("Current schema required for set_schema.")
            
            cur.execute(f"ALTER SCHEMA [{new_schema}] TRANSFER [{schema}].[{object_name}]")

        elif op == 'add_column':
             # ALTER TABLE [Table] ADD [Column] [Type] [Constraints]
             if obj_type != 'table':
                 raise ValueError("add_column only supported for tables.")
             
             col_name = params.get('column_name')
             data_type = params.get('data_type')
             constraints = params.get('constraints', '')
             
             if not col_name or not data_type:
                 raise ValueError("column_name and data_type required.")
             
             full_table = f"[{schema}].[{object_name}]" if schema else f"[{object_name}]"
             cur.execute(f"ALTER TABLE {full_table} ADD [{col_name}] {data_type} {constraints}")

        elif op == 'drop_column':
             # ALTER TABLE [Table] DROP COLUMN [Column]
             if obj_type != 'table':
                 raise ValueError("drop_column only supported for tables.")
             
             col_name = params.get('column_name')
             if not col_name:
                 raise ValueError("column_name required.")
             
             full_table = f"[{schema}].[{object_name}]" if schema else f"[{object_name}]"
             cur.execute(f"ALTER TABLE {full_table} DROP COLUMN [{col_name}]")

        elif op == 'rename_column':
             # sp_rename 'table.col', 'new_col', 'COLUMN'
             if obj_type != 'table':
                 raise ValueError("rename_column only supported for tables.")
             
             col_name = params.get('column_name')
             new_col_name = params.get('new_column_name')
             
             if not col_name or not new_col_name:
                 raise ValueError("column_name and new_column_name required.")
             
             full_obj = f"{schema}.{object_name}.{col_name}" if schema else f"{object_name}.{col_name}"
             cur.execute(f"EXEC sp_rename '{full_obj}', '{new_col_name}', 'COLUMN'")

        elif op == 'alter_column':
             # ALTER TABLE [Table] ALTER COLUMN [Col] [Type] [Nullability]
             if obj_type != 'table':
                 raise ValueError("alter_column only supported for tables.")
             
             col_name = params.get('column_name')
             data_type = params.get('data_type') # Required in SQL Server even if not changing
             not_null = params.get('not_null')
             
             if not col_name or not data_type:
                 raise ValueError("column_name and data_type required for alter_column in SQL Server.")
             
             null_clause = "NOT NULL" if not_null else "NULL"
             if not_null is None:
                 null_clause = "" # Keep existing? No, SQL Server requires specifying. 
                 # If user didn't specify, we might error or default. Let's error if unsure.
                 # Actually, usually if omitted it defaults to NULL unless specified.
                 # Let's assume user provides full definition.
                 pass
             
             full_table = f"[{schema}].[{object_name}]" if schema else f"[{object_name}]"
             cur.execute(f"ALTER TABLE {full_table} ALTER COLUMN [{col_name}] {data_type} {null_clause}")

        else:
            raise ValueError(f"Operation {op} not supported or implemented.")

        conn.commit()
        return f"Operation '{op}' on {obj_type} '{object_name}' completed successfully."
        
    finally:
        conn.close()
@mcp.tool
def db_sql2019_create_object(
    object_type: str,
    object_name: str,
    schema: str | None = None,
    owner: str | None = None,
    parameters: dict[str, Any] | None = None
) -> str:
    """
    Executes CREATE DDL statements for database objects.
    
    Args:
        object_type: One of: database, schema, table, view, index, function, procedure, trigger, server.
        object_name: Name of the object.
        schema: Schema name (required for schema-scoped objects like table, view, index, function, trigger).
        owner: Optional owner of the object (AUTHORIZATION clause).
        parameters: Additional parameters for specific objects:
            - columns: list of dicts for 'table' (e.g. [{'name': 'id', 'type': 'int', 'constraints': 'PRIMARY KEY'}])
            - query: str for 'view' (AS query)
            - table_name: str for 'index' or 'trigger'
            - index_columns: list of str for 'index' (column names or expressions)
            - unique: bool for 'index'
            - method: str for 'index' (e.g. 'CLUSTERED', 'NONCLUSTERED')
            - function_args: str for 'function'/'procedure' (e.g. "@a int, @b varchar(50)")
            - return_type: str for 'function' (e.g. "int" or "TABLE (...)")
            - body: str for 'function' body
            - replace: bool (CREATE OR ALTER)
            - event: str for 'trigger' (e.g. "FOR INSERT")
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable.")

    params = parameters or {}
    obj_type = object_type.lower()
    
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        # --- Database ---
        if obj_type == 'database':
            # CREATE DATABASE name
            cur.execute(f"CREATE DATABASE [{object_name}]")
            if owner:
                 cur.execute(f"ALTER AUTHORIZATION ON DATABASE::[{object_name}] TO [{owner}]")
        
        # --- Schema ---
        elif obj_type == 'schema':
            # CREATE SCHEMA name [AUTHORIZATION user]
            sql = f"CREATE SCHEMA [{object_name}]"
            if owner:
                sql += f" AUTHORIZATION [{owner}]"
            cur.execute(sql)

        # --- Table ---
        elif obj_type == 'table':
            if not schema:
                raise ValueError("Parameter 'schema' required for creating table.")
            
            cols = params.get('columns', [])
            if not cols:
                raise ValueError("Parameter 'columns' (list) required for creating table.")
            
            col_defs = []
            for col in cols:
                c_name = col.get('name')
                c_type = col.get('type')
                if not c_name or not c_type:
                    raise ValueError("Column definition requires 'name' and 'type'.")
                
                c_def = f"[{c_name}] {c_type}"
                if col.get('constraints'):
                    c_def += f" {col['constraints']}"
                col_defs.append(c_def)
            
            full_table = f"[{schema}].[{object_name}]"
            cur.execute(f"CREATE TABLE {full_table} ({', '.join(col_defs)})")
            
        # --- View ---
        elif obj_type == 'view':
            if not schema:
                raise ValueError("Parameter 'schema' required for creating view.")
            
            view_query = params.get('query')
            if not view_query:
                raise ValueError("Parameter 'query' required for creating view.")
            
            replace = "OR ALTER" if params.get('replace') else ""
            full_view = f"[{schema}].[{object_name}]"
            
            cur.execute(f"CREATE {replace} VIEW {full_view} AS {view_query}")
            
        # --- Index ---
        elif obj_type == 'index':
             table_name = params.get('table_name')
             if not table_name:
                 raise ValueError("Parameter 'table_name' required for creating index.")
             
             idx_cols = params.get('index_columns', [])
             if not idx_cols:
                 raise ValueError("Parameter 'index_columns' required for creating index.")
             
             unique = "UNIQUE" if params.get('unique') else ""
             method = params.get('method', 'NONCLUSTERED') # CLUSTERED, NONCLUSTERED, XML, SPATIAL
             
             full_table = f"[{schema}].[{table_name}]" if schema else f"[{table_name}]"
             cols_str = ", ".join([f"[{c}]" for c in idx_cols])
             
             cur.execute(f"CREATE {unique} {method} INDEX [{object_name}] ON {full_table} ({cols_str})")

        # --- Function / Procedure ---
        elif obj_type in ('function', 'procedure'):
             if not schema:
                  raise ValueError(f"Parameter 'schema' required for creating {obj_type}.")
             
             args = params.get('function_args', '')
             ret_type = params.get('return_type', '')
             body = params.get('body', '')
             replace = "OR ALTER" if params.get('replace') else ""
             
             full_name = f"[{schema}].[{object_name}]"
             
             if obj_type == 'function':
                 if not ret_type:
                     raise ValueError("Parameter 'return_type' required for function.")
                 # CREATE OR ALTER FUNCTION schema.name (@args) RETURNS type AS BEGIN body END
                 cur.execute(f"CREATE {replace} FUNCTION {full_name} ({args}) RETURNS {ret_type} AS BEGIN {body} END")
             else:
                 # CREATE OR ALTER PROCEDURE schema.name @args AS body
                 cur.execute(f"CREATE {replace} PROCEDURE {full_name} {args} AS {body}")

        # --- Trigger ---
        elif obj_type == 'trigger':
             table_name = params.get('table_name')
             if not table_name:
                 raise ValueError("Parameter 'table_name' required for trigger.")
             
             event = params.get('event') # FOR INSERT, UPDATE, DELETE
             body = params.get('body')
             replace = "OR ALTER" if params.get('replace') else ""
             
             if not event or not body:
                 raise ValueError("Parameters 'event' and 'body' required for trigger.")

             full_table = f"[{schema}].[{table_name}]" if schema else f"[{table_name}]"
             full_trigger = f"[{schema}].[{object_name}]" if schema else f"[{object_name}]"
             
             cur.execute(f"CREATE {replace} TRIGGER {full_trigger} ON {full_table} {event} AS {body}")

        else:
            raise ValueError(f"Object type {obj_type} not supported for creation.")

        conn.commit()
        return f"Object {obj_type} '{object_name}' created successfully."
        
    finally:
        conn.close()









@mcp.tool
def db_sql2019_drop_object(
    object_type: str,
    object_name: str,
    schema: str | None = None,
    parameters: dict[str, Any] | None = None
) -> str:
    """
    Executes DROP DDL statements for database objects.
    
    Args:
        object_type: One of: database, schema, table, view, index, function, procedure, trigger, server.
        object_name: Name of the object.
        schema: Schema name (required for schema-scoped objects).
        parameters: Additional parameters:
            - cascade: bool (not supported in SQL Server DROP usually, but dependencies check)
            - if_exists: bool (DROP ... IF EXISTS)
            - table_name: str (required for 'trigger' or 'index')
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable.")

    params = parameters or {}
    obj_type = object_type.lower()
    
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        if_exists = "IF EXISTS" if params.get('if_exists') else ""
        
        # --- Database ---
        if obj_type == 'database':
            cur.execute(f"DROP DATABASE {if_exists} [{object_name}]")

        # --- Schema ---
        elif obj_type == 'schema':
            cur.execute(f"DROP SCHEMA {if_exists} [{object_name}]")

        # --- Table ---
        elif obj_type == 'table':
            if not schema:
                 raise ValueError("Parameter 'schema' required.")
            cur.execute(f"DROP TABLE {if_exists} [{schema}].[{object_name}]")
            
        # --- View ---
        elif obj_type == 'view':
            if not schema:
                 raise ValueError("Parameter 'schema' required.")
            cur.execute(f"DROP VIEW {if_exists} [{schema}].[{object_name}]")

        # --- Index ---
        elif obj_type == 'index':
             if not schema:
                  raise ValueError("Parameter 'schema' required.")
             table_name = params.get('table_name')
             if not table_name:
                  raise ValueError("Parameter 'table_name' required for dropping index.")
             
             cur.execute(f"DROP INDEX {if_exists} [{object_name}] ON [{schema}].[{table_name}]")

        # --- Procedure / Function ---
        elif obj_type == 'procedure':
             if not schema:
                  raise ValueError("Parameter 'schema' required.")
             cur.execute(f"DROP PROCEDURE {if_exists} [{schema}].[{object_name}]")
             
        elif obj_type == 'function':
             if not schema:
                  raise ValueError("Parameter 'schema' required.")
             cur.execute(f"DROP FUNCTION {if_exists} [{schema}].[{object_name}]")

        # --- Trigger ---
        elif obj_type == 'trigger':
             if not schema:
                  raise ValueError("Parameter 'schema' required.")
             # Triggers are dropped like: DROP TRIGGER [schema].[trigger]
             cur.execute(f"DROP TRIGGER {if_exists} [{schema}].[{object_name}]")

        else:
             raise ValueError(f"Dropping object type '{obj_type}' not supported.")
             
        conn.commit()
        return f"{obj_type.capitalize()} '{object_name}' dropped successfully."
        
    finally:
        conn.close()


@mcp.tool
def db_sql2019_check_fragmentation(limit: int = 50) -> list[dict[str, Any]]:
    """
    Identifies fragmented indexes and provides maintenance commands (REBUILD/REORGANIZE).

    Args:
        limit: Maximum number of objects to return (default: 50).

    Returns:
        List of objects with fragmentation statistics and suggested maintenance commands.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        # SQL Server Index Fragmentation
        _execute_safe(
            cur,
            """
            SELECT TOP (?)
                SCHEMA_NAME(o.schema_id) as [schema],
                o.name AS object_name,
                i.name AS index_name,
                ips.index_type_desc,
                CAST(ips.avg_fragmentation_in_percent AS DECIMAL(5,2)) as fragmentation_percent,
                ips.page_count,
                CASE 
                    WHEN ips.avg_fragmentation_in_percent > 30 THEN 'ALTER INDEX [' + i.name + '] ON [' + SCHEMA_NAME(o.schema_id) + '].[' + o.name + '] REBUILD'
                    WHEN ips.avg_fragmentation_in_percent > 5 THEN 'ALTER INDEX [' + i.name + '] ON [' + SCHEMA_NAME(o.schema_id) + '].[' + o.name + '] REORGANIZE'
                    ELSE 'OK'
                END AS maintenance_cmd
            FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ips
            JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
            JOIN sys.objects o ON ips.object_id = o.object_id
            WHERE ips.avg_fragmentation_in_percent > 5
            AND ips.page_count > 100 -- Ignore small tables
            AND o.is_ms_shipped = 0
            ORDER BY ips.avg_fragmentation_in_percent DESC
            """,
            (limit,)
        )
        
        columns = [column[0] for column in cur.description]
        results = []
        for row in cur.fetchall():
            results.append(dict(zip(columns, row)))
        return results
    finally:
        conn.close()


@mcp.tool
def db_sql2019_db_stats(database: str | None = None) -> list[dict[str, Any]] | dict[str, Any]:
    """
    Get database-level statistics including active connections, state, and recovery model.
    
    Args:
        database: Optional database name to filter results. If None, returns all databases.
    
    Returns:
        List of database statistics or single database stats if database specified.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        query = """
            SELECT 
                d.name as [database],
                (SELECT count(*) FROM sys.dm_exec_sessions WHERE database_id = d.database_id) as active_connections,
                d.state_desc,
                d.recovery_model_desc,
                d.log_reuse_wait_desc,
                d.create_date
            FROM sys.databases d
        """
        params = []
        if database:
            query += " WHERE d.name = ?"
            params.append(database)
        else:
            query += " ORDER BY d.name"

        _execute_safe(cur, query, tuple(params) if params else None)
        
        columns = [column[0] for column in cur.description]
        results = []
        for row in cur.fetchall():
            results.append(dict(zip(columns, row)))

        if database:
            if not results:
                return {"error": f"Database '{database}' not found"}
            return results[0]
            
        return results
    finally:
        conn.close()



@mcp.tool
def db_sql2019_analyze_index_health(
    schema: str | None = None,
    min_fragmentation: int = 10,
    include_missing: bool = True,
    include_unused: bool = True,
    limit: int = 30
) -> dict[str, Any]:
    """
    Comprehensive index health analysis combining fragmentation, missing indexes, and unused indexes.
    
    Args:
        schema: Optional schema name to filter analysis.
        min_fragmentation: Minimum fragmentation percentage to consider (default: 10).
        include_missing: Include missing index analysis (default: True).
        include_unused: Include unused index analysis (default: True).
        limit: Maximum number of results per category (default: 30).
    
    Returns:
        Dictionary containing index health summary, detailed analysis, and recommendations.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        results = {
            "summary": {
                "fragmented_indexes": 0,
                "missing_indexes": 0,
                "unused_indexes": 0,
                "recommendations": []
            },
            "fragmentation": [],
            "missing_indexes": [],
            "unused_indexes": []
        }

        # 1. Fragmentation
        fragmentation_query = """
            SELECT TOP (?)
                SCHEMA_NAME(o.schema_id) as [schema],
                o.name AS object_name,
                i.name AS index_name,
                CAST(ips.avg_fragmentation_in_percent AS DECIMAL(5,2)) as fragmentation_percent,
                CASE 
                    WHEN ips.avg_fragmentation_in_percent > 30 THEN 'REBUILD'
                    ELSE 'REORGANIZE'
                END AS recommendation
            FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ips
            JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
            JOIN sys.objects o ON ips.object_id = o.object_id
            WHERE ips.avg_fragmentation_in_percent > ?
            AND ips.page_count > 100
            AND o.is_ms_shipped = 0
        """
        params = [limit, min_fragmentation]
        if schema:
            fragmentation_query += " AND SCHEMA_NAME(o.schema_id) = ?"
            params.append(schema)
        fragmentation_query += " ORDER BY ips.avg_fragmentation_in_percent DESC"
        
        _execute_safe(cur, fragmentation_query, tuple(params))
        cols = [c[0] for c in cur.description]
        results["fragmentation"] = [dict(zip(cols, r)) for r in cur.fetchall()]
        results["summary"]["fragmented_indexes"] = len(results["fragmentation"])

        # 2. Missing Indexes
        if include_missing:
            missing_query = """
                SELECT TOP (?)
                    d.statement as object_name,
                    gs.avg_total_user_cost * gs.avg_user_impact * (gs.user_seeks + gs.user_scans) as impact_score,
                    'CREATE INDEX [IX_' + OBJECT_NAME(d.object_id) + '_' + CONVERT(varchar, gs.group_handle) + '] ON ' + d.statement + 
                    ' (' + ISNULL(d.equality_columns, '') + 
                    CASE WHEN d.equality_columns IS NOT NULL AND d.inequality_columns IS NOT NULL THEN ', ' ELSE '' END + 
                    ISNULL(d.inequality_columns, '') + ')' + 
                    ISNULL(' INCLUDE (' + d.included_columns + ')', '') as create_statement
                FROM sys.dm_db_missing_index_groups g
                JOIN sys.dm_db_missing_index_group_stats gs ON gs.group_handle = g.index_group_handle
                JOIN sys.dm_db_missing_index_details d ON g.index_handle = d.index_handle
                WHERE d.database_id = DB_ID()
            """
            m_params = [limit]
            if schema:
                missing_query += " AND d.statement LIKE '%[' + ? + ']%'"
                m_params.append(schema)
                
            missing_query += " ORDER BY impact_score DESC"
            
            _execute_safe(cur, missing_query, tuple(m_params))
            if cur.description:
                cols = [c[0] for c in cur.description]
                results["missing_indexes"] = [dict(zip(cols, r)) for r in cur.fetchall()]
                results["summary"]["missing_indexes"] = len(results["missing_indexes"])

        # 3. Unused Indexes
        if include_unused:
            unused_query = """
                SELECT TOP (?)
                    SCHEMA_NAME(o.schema_id) as [schema],
                    OBJECT_NAME(s.object_id) as object_name,
                    i.name as index_name,
                    s.user_seeks,
                    s.user_scans,
                    s.user_lookups,
                    s.user_updates,
                    'DROP INDEX [' + i.name + '] ON [' + SCHEMA_NAME(o.schema_id) + '].[' + OBJECT_NAME(s.object_id) + ']' as drop_statement
                FROM sys.dm_db_index_usage_stats s
                JOIN sys.indexes i ON i.object_id = s.object_id AND i.index_id = s.index_id
                JOIN sys.objects o ON o.object_id = s.object_id
                WHERE OBJECTPROPERTY(s.object_id, 'IsUserTable') = 1
                AND s.database_id = DB_ID()
                AND i.type_desc = 'NONCLUSTERED'
                AND i.is_primary_key = 0
                AND i.is_unique_constraint = 0
                AND (s.user_seeks + s.user_scans + s.user_lookups) = 0
            """
            u_params = [limit]
            if schema:
                unused_query += " AND SCHEMA_NAME(o.schema_id) = ?"
                u_params.append(schema)
            
            unused_query += " ORDER BY s.user_updates DESC"
            
            _execute_safe(cur, unused_query, tuple(u_params))
            if cur.description:
                cols = [c[0] for c in cur.description]
                results["unused_indexes"] = [dict(zip(cols, r)) for r in cur.fetchall()]
                results["summary"]["unused_indexes"] = len(results["unused_indexes"])
            
        return results
    finally:
        conn.close()



@mcp.tool
def db_sql2019_sec_perf_metrics(
    cache_hit_threshold: int | None = None,
    connection_usage_threshold: float | None = None,
    profile: str = "oltp"
) -> dict[str, Any]:
    """
    Analyzes database security and performance metrics for SQL Server.
    
    Args:
        cache_hit_threshold: Minimum acceptable buffer cache hit ratio percentage.
        connection_usage_threshold: Maximum acceptable connection usage ratio (if max_connections is configured).
        profile: Workload profile to tune thresholds (oltp/olap).
    
    Returns:
        Dictionary containing security metrics, performance metrics, issues found, and recommended fixes.
    """
    profile_value = (profile or "oltp").lower()
    if profile_value == "olap":
        default_cache_threshold = 90 # SQL Server usually keeps this high
        default_conn_threshold = 0.9
        page_life_expectancy_threshold = 300 # seconds
    else:
        default_cache_threshold = 98
        default_conn_threshold = 0.8
        page_life_expectancy_threshold = 300

    cache_hit_limit = cache_hit_threshold if cache_hit_threshold is not None else default_cache_threshold
    
    conn = get_connection()
    try:
        cur = conn.cursor()
        results = {
            "security_metrics": {},
            "performance_metrics": {},
            "issues_found": [],
            "recommended_fixes": [],
            "profile_applied": profile_value
        }

        # 1. Mixed Authentication Mode
        # SQL Server authentication mode: 1 = Windows only, 0 = Mixed
        try:
            cur.execute("SELECT SERVERPROPERTY('IsIntegratedSecurityOnly')")
            is_integrated_only = cur.fetchone()[0]
            results["security_metrics"]["auth_mode"] = "Windows Authentication Mode" if is_integrated_only == 1 else "SQL Server and Windows Authentication Mode"
            
            if is_integrated_only == 0:
                 # If mixed mode, check SA account
                 cur.execute("SELECT is_disabled FROM sys.server_principals WHERE name = 'sa'")
                 sa_row = cur.fetchone()
                 if sa_row and sa_row[0] == 0:
                     results["issues_found"].append("SA account is enabled")
                     results["recommended_fixes"].append("Disable SA account and use individual logins")
        except Exception:
            pass

        # 2. Sysadmin Check
        cur.execute("SELECT name FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN')")
        sysadmins = [row[0] for row in cur.fetchall()]
        results["security_metrics"]["sysadmins"] = sysadmins
        if len(sysadmins) > 3:
             results["issues_found"].append(f"High number of sysadmins: {len(sysadmins)}")

        # 3. Buffer Cache Hit Ratio
        # SQL Server stores this in perf counters. 
        # Ratio is Buffer Cache Hit Ratio / Buffer Cache Hit Ratio Base
        cur.execute("""
            SELECT 
                cntr_value 
            FROM sys.dm_os_performance_counters 
            WHERE counter_name = 'Buffer cache hit ratio'
        """)
        row_a = cur.fetchone()
        cur.execute("""
            SELECT 
                cntr_value 
            FROM sys.dm_os_performance_counters 
            WHERE counter_name = 'Buffer cache hit ratio base'
        """)
        row_b = cur.fetchone()
        
        if row_a and row_b and row_b[0] > 0:
            ratio = (row_a[0] / row_b[0]) * 100
            results["performance_metrics"]["buffer_cache_hit_ratio"] = round(ratio, 2)
            
            if ratio < cache_hit_limit:
                results["issues_found"].append(f"Low Buffer Cache Hit Ratio: {ratio:.2f}%")
                results["recommended_fixes"].append(f"Investigate memory pressure. Ensure Max Server Memory is configured correctly.")
        
        # 4. Page Life Expectancy (PLE)
        cur.execute("""
            SELECT cntr_value 
            FROM sys.dm_os_performance_counters 
            WHERE object_name LIKE '%Buffer Manager%' 
            AND counter_name = 'Page life expectancy'
        """)
        ple_row = cur.fetchone()
        if ple_row:
            ple = ple_row[0]
            results["performance_metrics"]["page_life_expectancy"] = ple
            if ple < page_life_expectancy_threshold:
                 results["issues_found"].append(f"Low Page Life Expectancy: {ple}s")
                 results["recommended_fixes"].append("Memory pressure detected. Add RAM or optimize queries.")

        # 5. Connection Counts
        cur.execute("SELECT count(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1")
        active_conns = cur.fetchone()[0]
        results["performance_metrics"]["user_connections"] = active_conns
        
        # Check max connections setting
        cur.execute("SELECT value FROM sys.configurations WHERE name = 'user connections'")
        max_conns = cur.fetchone()[0]
        # 0 means unlimited (up to 32767)
        effective_max = 32767 if max_conns == 0 else max_conns
        
        results["performance_metrics"]["max_configured_connections"] = effective_max
        
        if active_conns > effective_max * (connection_usage_threshold or default_conn_threshold):
             results["issues_found"].append(f"High connection usage: {active_conns}")

        # 6. Wait Stats (Top 3)
        cur.execute("""
            SELECT TOP 3 wait_type, wait_time_ms, signal_wait_time_ms
            FROM sys.dm_os_wait_stats
            WHERE wait_type NOT IN ('CLR_SEMAPHORE', 'LAZYWRITER_SLEEP', 'RESOURCE_QUEUE', 'SLEEP_TASK', 'SLEEP_SYSTEMTASK', 'SQLTRACE_BUFFER_FLUSH', 'WAITFOR', 'LOGMGR_QUEUE', 'CHECKPOINT_QUEUE', 'REQUEST_FOR_DEADLOCK_SEARCH', 'XE_TIMER_EVENT', 'BROKER_TO_FLUSH', 'BROKER_TASK_STOP', 'CLR_MANUAL_EVENT', 'CLR_AUTO_EVENT', 'DISPATCHER_QUEUE_SEMAPHORE', 'FT_IFTS_SCHEDULER_IDLE_WAIT', 'XE_DISPATCHER_WAIT', 'XE_DISPATCHER_JOIN', 'BROKER_EVENTHANDLER', 'TRACEWRITE', 'FT_IFTSHC_MUTEX', 'SQLTRACE_INCREMENTAL_FLUSH_SLEEP', 'DIRTY_PAGE_POLL', 'SP_SERVER_DIAGNOSTICS_SLEEP')
            ORDER BY wait_time_ms DESC
        """)
        waits = []
        for row in cur.fetchall():
            waits.append({"type": row[0], "time_ms": row[1], "signal_ms": row[2]})
        results["performance_metrics"]["top_waits"] = waits

        return results
        
    finally:
        conn.close()



@mcp.tool
def db_sql2019_recommend_partitioning(
    min_size_gb: float = 1.0,
    schema: str | None = None,
    limit: int = 50
) -> dict[str, Any]:
    """
    Suggests tables for partitioning based primarily on size.
    
    Args:
        min_size_gb: Minimum total table size in gigabytes to consider as a candidate.
        schema: Optional schema name to filter tables.
        limit: Maximum number of candidate tables to return.
    
    Returns:
        Dictionary containing a summary and a list of candidate tables.
    """
    if min_size_gb <= 0:
        raise ValueError("min_size_gb must be positive")
    
    size_mb_threshold = min_size_gb * 1024
    
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        # Identify large tables using DMVs
        query = """
            SELECT TOP (?)
                SCHEMA_NAME(t.schema_id) AS [schema],
                t.name AS [table],
                SUM(ps.reserved_page_count) * 8.0 / 1024 AS size_mb,
                SUM(ps.row_count) AS row_count
            FROM sys.dm_db_partition_stats ps
            JOIN sys.tables t ON ps.object_id = t.object_id
            WHERE ps.index_id IN (0, 1) -- Heap or Clustered Index
        """
        params = [limit]
        
        if schema:
            query += " AND SCHEMA_NAME(t.schema_id) = ?"
            params.append(schema)
            
        query += """
            GROUP BY t.schema_id, t.name
            HAVING SUM(ps.reserved_page_count) * 8.0 / 1024 >= ?
            ORDER BY size_mb DESC
        """
        params.append(size_mb_threshold)
        
        _execute_safe(cur, query, tuple(params))
        
        candidates = []
        for row in cur.fetchall():
            size_gb = row[2] / 1024.0
            row_count = row[3]
            
            benefit = "low"
            if size_gb > 50 or row_count > 100000000:
                benefit = "high"
            elif size_gb > 10 or row_count > 10000000:
                benefit = "medium"
                
            candidates.append({
                "schema": row[0],
                "table": row[1],
                "size_gb": round(size_gb, 3),
                "row_count": row_count,
                "estimated_partitioning_benefit": benefit
            })
            
        return {
            "summary": {
                "min_size_gb": min_size_gb,
                "candidate_count": len(candidates)
            },
            "candidates": candidates
        }
        
    finally:
        conn.close()



@mcp.tool
def db_sql2019_analyze_sessions(
    include_idle: bool = True,
    include_active: bool = True,
    include_locked: bool = True,
    min_duration_seconds: int = 60,
    min_idle_seconds: int = 60
) -> dict[str, Any]:
    """
    Comprehensive session analysis combining active queries, idle sessions, and locks.
    
    Args:
        include_idle: Include idle sessions (sleeping).
        include_active: Include active query sessions.
        include_locked: Include sessions involved in locks/blocking.
        min_duration_seconds: Minimum active query duration to include.
        min_idle_seconds: Minimum idle time for idle sessions.
    
    Returns:
        Dictionary containing session summary, detailed sessions, and recommendations.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        results = {
            "summary": {},
            "active_sessions": [],
            "idle_sessions": [],
            "locked_sessions": [],
            "recommendations": []
        }

        # Summary
        cur.execute("""
            SELECT 
                COUNT(*) as total_sessions,
                SUM(CASE WHEN status = 'running' OR status = 'runnable' THEN 1 ELSE 0 END) as active_count,
                SUM(CASE WHEN status = 'sleeping' THEN 1 ELSE 0 END) as idle_count,
                SUM(CASE WHEN blocking_session_id <> 0 THEN 1 ELSE 0 END) as blocked_count
            FROM sys.dm_exec_sessions
            WHERE is_user_process = 1
        """)
        row = cur.fetchone()
        results["summary"] = {
            "total_sessions": row[0],
            "active_count": row[1],
            "idle_count": row[2],
            "blocked_count": row[3]
        }

        # Active Sessions
        if include_active:
            cur.execute("""
                SELECT 
                    r.session_id,
                    s.login_name,
                    DB_NAME(r.database_id) as [database],
                    s.program_name,
                    s.client_interface_name,
                    r.status,
                    r.total_elapsed_time / 1000.0 as elapsed_seconds,
                    r.wait_type,
                    r.wait_time,
                    r.blocking_session_id,
                    t.text as query_text
                FROM sys.dm_exec_requests r
                JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
                CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
                WHERE r.total_elapsed_time >= ? * 1000
            """, min_duration_seconds)
            
            columns = [c[0] for c in cur.description]
            for row in cur.fetchall():
                results["active_sessions"].append(dict(zip(columns, row)))

        # Idle Sessions
        if include_idle:
            cur.execute("""
                SELECT 
                    s.session_id,
                    s.login_name,
                    s.program_name,
                    s.status,
                    DATEDIFF(SECOND, s.last_request_end_time, GETDATE()) as idle_seconds,
                    s.last_request_start_time,
                    s.last_request_end_time
                FROM sys.dm_exec_sessions s
                LEFT JOIN sys.dm_exec_requests r ON s.session_id = r.session_id
                WHERE s.is_user_process = 1
                AND s.status = 'sleeping'
                AND r.session_id IS NULL -- No active request
                AND DATEDIFF(SECOND, s.last_request_end_time, GETDATE()) >= ?
            """, min_idle_seconds)
            
            columns = [c[0] for c in cur.description]
            for row in cur.fetchall():
                results["idle_sessions"].append(dict(zip(columns, row)))

        # Locked/Blocking Sessions
        if include_locked:
            cur.execute("""
                SELECT 
                    r.session_id as blocked_session_id,
                    s.login_name as blocked_user,
                    r.wait_type,
                    r.wait_time,
                    r.blocking_session_id,
                    sb.login_name as blocking_user,
                    sb.program_name as blocking_program,
                    t.text as blocked_query
                FROM sys.dm_exec_requests r
                JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
                LEFT JOIN sys.dm_exec_sessions sb ON r.blocking_session_id = sb.session_id
                OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
                WHERE r.blocking_session_id <> 0
            """)
            
            columns = [c[0] for c in cur.description]
            for row in cur.fetchall():
                results["locked_sessions"].append(dict(zip(columns, row)))

        # Recommendations
        if results["active_sessions"]:
            longest = max(results["active_sessions"], key=lambda x: x["elapsed_seconds"])
            results["recommendations"].append(f"Longest running query: Session {longest['session_id']} ({longest['elapsed_seconds']}s)")
            
        if results["locked_sessions"]:
             results["recommendations"].append(f"Blocking detected! {len(results['locked_sessions'])} sessions blocked.")

        return results
        
    finally:
        conn.close()



@mcp.tool
def db_sql2019_kill_session(session_id: int) -> dict[str, Any]:
    """
    Terminates a database session by its session ID (SPID).
    Requires MCP_ALLOW_WRITE=true.

    Args:
        session_id: The session ID to terminate.

    Returns:
        Dictionary indicating success or failure of the termination attempt.
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable killing sessions.")

    conn = get_connection()
    try:
        cur = conn.cursor()
        logger.info(f"Terminating session with SPID: {session_id}")
        
        # Prevent killing self or system sessions
        cur.execute("SELECT @@SPID")
        my_spid = cur.fetchval()
        if session_id == my_spid:
            raise ValueError("Cannot kill the current session.")
        
        cur.execute(f"KILL {session_id}")
        conn.commit()
        
        return {
            "session_id": session_id,
            "terminated": True,
            "message": f"Session {session_id} terminated."
        }
    except Exception as e:
        return {
            "session_id": session_id,
            "terminated": False,
            "message": f"Failed to terminate session {session_id}: {str(e)}"
        }
    finally:
        conn.close()





@mcp.tool
def db_sql2019_server_info() -> dict[str, Any]:
    """
    Retrieves information about the current SQL Server connection and version.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        _execute_safe(
            cur,
            """
            SELECT 
                DB_NAME() as [database],
                SUSER_NAME() as [user],
                @@SERVERNAME as server_name,
                (SELECT local_net_address FROM sys.dm_exec_connections WHERE session_id = @@SPID) as server_addr,
                (SELECT local_tcp_port FROM sys.dm_exec_connections WHERE session_id = @@SPID) as server_port,
                @@VERSION as version
            """
        )
        row = cur.fetchone()
        if row is None:
            # Fallback if dm_exec_connections permission denied or local pipe
            cur.execute("SELECT DB_NAME(), SUSER_NAME(), @@SERVERNAME, 'Unknown', 'Unknown', @@VERSION")
            row = cur.fetchone()

        columns = [c[0] for c in cur.description]
        data = dict(zip(columns, row))
        
        db_name = ORIGINAL_DB_NAME if ORIGINAL_DB_NAME else data["database"]
        server_addr = ORIGINAL_DB_HOST if ORIGINAL_DB_HOST else data.get("server_addr")
        server_port = ORIGINAL_DB_PORT if ORIGINAL_DB_PORT else data.get("server_port")
        
        return {
            "database": db_name,
            "user": data["user"],
            "server_name": data["server_name"],
            "server_addr": server_addr,
            "server_port": server_port,
            "version": data["version"],
            "allow_write": ALLOW_WRITE,
            "default_max_rows": DEFAULT_MAX_ROWS,
        }
    finally:
        conn.close()



@mcp.tool
def db_sql2019_get_db_parameters(pattern: str | None = None) -> list[dict[str, Any]]:
    """
    Retrieves database configuration parameters (sys.configurations).

    Args:
        pattern: Optional wildcard pattern to filter parameter names (e.g., '%memory%').

    Returns:
        List of database parameters with their values and descriptions.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        query = """
            SELECT 
                name,
                value,
                value_in_use,
                description,
                is_dynamic,
                is_advanced
            FROM sys.configurations
        """
        params = []
        if pattern:
            query += " WHERE name LIKE ?"
            params.append(pattern)
        
        query += " ORDER BY name"
        
        _execute_safe(cur, query, tuple(params) if params else None)
        
        columns = [c[0] for c in cur.description]
        results = []
        for row in cur.fetchall():
            results.append(dict(zip(columns, row)))
        return results
    finally:
        conn.close()



@mcp.tool
def db_sql2019_list_objects(
    object_type: str,
    schema: str | None = None,
    owner: str | None = None,
    name_pattern: str | None = None,
    order_by: str | None = None,
    limit: int = 50
) -> list[dict[str, Any]]:
    """
    Consolidated tool to list database objects with filtering and sorting options.

    Args:
        object_type: Type of objects to list.
                     Supported: 'database', 'schema', 'table', 'view', 'index', 'function', 'procedure', 'trigger'.
        schema: Filter by schema name.
        owner: Filter by object owner.
        name_pattern: Filter object name by pattern (LIKE).
        order_by: Column to sort by. Defaults depend on object_type.
        limit: Maximum number of results (default: 50).

    Returns:
        List of objects with relevant details (name, schema, owner, size, stats, etc.).
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        params: list[Any] = []
        filters = []
        
        # Helper for name filtering
        if name_pattern:
            # T-SQL uses LIKE, ensure pattern is compatible
            pass # logic handled in query construction

        query = ""
        sort_clause = ""
        
        # --- Database ---
        if object_type == 'database':
            query = """
                SELECT 
                    d.name,
                    suser_sname(d.owner_sid) as owner,
                    d.state_desc as state,
                    d.recovery_model_desc as recovery_model
                FROM sys.databases d
            """
            if owner:
                filters.append("suser_sname(d.owner_sid) = ?")
                params.append(owner)
            if name_pattern:
                filters.append("d.name LIKE ?")
                params.append(name_pattern)
            
            sort_clause = "ORDER BY d.name"

        # --- Schema ---
        elif object_type == 'schema':
            query = """
                SELECT 
                    s.name,
                    u.name as owner
                FROM sys.schemas s
                JOIN sys.database_principals u ON s.principal_id = u.principal_id
            """
            if owner:
                filters.append("u.name = ?")
                params.append(owner)
            if name_pattern:
                filters.append("s.name LIKE ?")
                params.append(name_pattern)
            if schema:
                filters.append("s.name = ?")
                params.append(schema)
            else:
                filters.append("s.name NOT IN ('sys', 'INFORMATION_SCHEMA', 'guest')")

            sort_clause = "ORDER BY s.name"

        # --- Table ---
        elif object_type == 'table':
            query = """
                SELECT TOP (?)
                    s.name as [schema],
                    t.name as [name],
                    p.rows as [rows],
                    (SUM(a.total_pages) * 8) as size_kb,
                    (SUM(a.used_pages) * 8) as used_kb,
                    t.create_date,
                    t.modify_date
                FROM sys.tables t
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                JOIN sys.indexes i ON t.object_id = i.object_id
                JOIN sys.partitions p ON i.object_id = p.object_id AND i.index_id = p.index_id
                JOIN sys.allocation_units a ON p.partition_id = a.container_id
            """
            # We need to group by because of multiple partitions/indexes
            group_by = """
                GROUP BY s.name, t.name, p.rows, t.create_date, t.modify_date
            """
            
            if schema:
                filters.append("s.name = ?")
                params.append(schema)
            if name_pattern:
                filters.append("t.name LIKE ?")
                params.append(name_pattern)

            # Insert filters before GROUP BY
            # But wait, logic below appends WHERE. So we need to restructure.
            # Simplified approach: Base query is just the joins.
            
            query = """
                SELECT TOP (?)
                    s.name as [schema],
                    t.name as [name],
                    SUM(p.rows) as [rows], -- Sum rows for partitioned tables? Actually sys.partitions has rows per partition.
                    -- For simple heap/clustered, index_id 0 or 1. 
                    -- Let's use a simpler DMV approach for size if possible or just sys.dm_db_partition_stats
                    (SUM(ps.reserved_page_count) * 8) as size_kb,
                    (SUM(ps.used_page_count) * 8) as used_kb
                FROM sys.tables t
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                JOIN sys.dm_db_partition_stats ps ON t.object_id = ps.object_id
                WHERE (ps.index_id < 2) -- 0=Heap, 1=Clustered (Data)
            """
            # Reset params, TOP is first param
            params = [limit] 

            if schema:
                query += " AND s.name = ?"
                params.append(schema)
            if name_pattern:
                query += " AND t.name LIKE ?"
                params.append(name_pattern)
            
            query += " GROUP BY s.name, t.name"
            
            sort_clause = "ORDER BY s.name, t.name"
            if order_by == 'size':
                sort_clause = "ORDER BY size_kb DESC"
            elif order_by == 'rows':
                sort_clause = "ORDER BY [rows] DESC"

            # Skip standard filter appending since we handled it inline
            filters = [] 

        # --- Index ---
        elif object_type == 'index':
            query = """
                SELECT TOP (?)
                    s.name as [schema],
                    t.name as [table],
                    i.name as [name],
                    i.type_desc as [type],
                    i.is_unique,
                    i.is_primary_key,
                    (ps.used_page_count * 8) as size_kb
                FROM sys.indexes i
                JOIN sys.tables t ON i.object_id = t.object_id
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                JOIN sys.dm_db_partition_stats ps ON i.object_id = ps.object_id AND i.index_id = ps.index_id
            """
            params = [limit]
            
            if schema:
                filters.append("s.name = ?")
                params.append(schema)
            if name_pattern:
                filters.append("i.name LIKE ?")
                params.append(name_pattern)
            
            sort_clause = "ORDER BY s.name, t.name, i.name"
            if order_by == 'size':
                sort_clause = "ORDER BY size_kb DESC"

        # --- View ---
        elif object_type == 'view':
            query = """
                SELECT TOP (?)
                    s.name as [schema],
                    v.name as [name],
                    v.create_date,
                    v.modify_date
                FROM sys.views v
                JOIN sys.schemas s ON v.schema_id = s.schema_id
            """
            params = [limit]
            if schema:
                filters.append("s.name = ?")
                params.append(schema)
            if name_pattern:
                filters.append("v.name LIKE ?")
                params.append(name_pattern)
            
            sort_clause = "ORDER BY s.name, v.name"

        # --- Procedure / Function ---
        elif object_type in ('function', 'procedure'):
            obj_type_filter = "('P', 'PC')" if object_type == 'procedure' else "('FN', 'IF', 'TF', 'FS', 'FT')"
            query = f"""
                SELECT TOP (?)
                    s.name as [schema],
                    o.name as [name],
                    o.type_desc,
                    o.create_date,
                    o.modify_date
                FROM sys.objects o
                JOIN sys.schemas s ON o.schema_id = s.schema_id
                WHERE o.type IN {obj_type_filter}
            """
            params = [limit]
            if schema:
                filters.append("s.name = ?")
                params.append(schema)
            if name_pattern:
                filters.append("o.name LIKE ?")
                params.append(name_pattern)
            
            sort_clause = "ORDER BY s.name, o.name"

        # --- Trigger ---
        elif object_type == 'trigger':
             query = """
                SELECT TOP (?)
                    s.name as [schema],
                    t.name as [table],
                    tr.name as [name],
                    tr.create_date,
                    tr.modify_date,
                    tr.is_disabled
                FROM sys.triggers tr
                JOIN sys.tables t ON tr.parent_id = t.object_id
                JOIN sys.schemas s ON t.schema_id = s.schema_id
             """
             params = [limit]
             if schema:
                filters.append("s.name = ?")
                params.append(schema)
             if name_pattern:
                 filters.append("tr.name LIKE ?")
                 params.append(name_pattern)
             
             sort_clause = "ORDER BY s.name, t.name, tr.name"

        else:
             return [{"error": f"Unsupported object_type: {object_type}"}]

        # Construct final query
        # Note: Table query constructed itself differently, need to handle that.
        if object_type != 'table':
            where_clause = ""
            if filters:
                # If query already has WHERE (like function), append with AND
                prefix = " AND " if "WHERE" in query else " WHERE "
                where_clause = prefix + " AND ".join(filters)
            
            full_sql = f"{query} {where_clause} {sort_clause}"
        else:
             # Table query was fully built above
             full_sql = f"{query} {sort_clause}"

        # Execute
        # Note: We need to handle params carefully. Table/Index/View/Proc used TOP(?) so limit is first param.
        # Database query didn't use TOP.
        if object_type == 'database':
             # Manual limit if not using TOP (but we should use TOP for consistency)
             # Let's add TOP to database query
             query = query.replace("SELECT", "SELECT TOP (?)", 1)
             params.insert(0, limit)
             full_sql = f"{query} {where_clause} {sort_clause}"

        _execute_safe(cur, full_sql, tuple(params))
        
        columns = [c[0] for c in cur.description]
        results = []
        for row in cur.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    finally:
        conn.close()





@mcp.tool
def db_sql2019_analyze_indexes(schema: str | None = None, limit: int = 50) -> dict[str, Any]:
    """
    Identify unused and missing indexes using SQL Server DMVs.
    
    Args:
        schema: Optional schema name to filter.
        limit: Maximum number of rows to return for each category.

    Returns:
        Dictionary containing lists of unused and missing indexes.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        results = {
            "unused_indexes": [],
            "missing_indexes": [],
            # "duplicate_indexes": [] # Complex to implement reliably in T-SQL without rigorous logic
        }

        # 1. Unused Indexes
        # Indexes that have 0 user seeks/scans/lookups, excluding Primary Keys and Unique Constraints usually,
        # but here we just show low usage.
        query_unused = """
            SELECT TOP (?)
                s.name as [schema],
                t.name as [table],
                i.name as [index],
                (ps.used_page_count * 8) as size_kb,
                (ISNULL(ius.user_seeks, 0) + ISNULL(ius.user_scans, 0) + ISNULL(ius.user_lookups, 0)) as total_usage,
                ius.last_user_seek,
                ius.last_user_scan
            FROM sys.indexes i
            JOIN sys.tables t ON i.object_id = t.object_id
            JOIN sys.schemas s ON t.schema_id = s.schema_id
            LEFT JOIN sys.dm_db_index_usage_stats ius 
                ON i.object_id = ius.object_id AND i.index_id = ius.index_id AND ius.database_id = DB_ID()
            JOIN sys.dm_db_partition_stats ps 
                ON i.object_id = ps.object_id AND i.index_id = ps.index_id
            WHERE i.type_desc <> 'HEAP' 
              AND i.is_primary_key = 0 
              AND i.is_unique = 0
              AND (ISNULL(ius.user_seeks, 0) + ISNULL(ius.user_scans, 0) + ISNULL(ius.user_lookups, 0)) = 0
        """
        params_unused = [limit]
        if schema:
            query_unused += " AND s.name = ?"
            params_unused.append(schema)
        
        query_unused += " ORDER BY size_kb DESC"
        
        _execute_safe(cur, query_unused, tuple(params_unused))
        columns = [c[0] for c in cur.description]
        results["unused_indexes"] = [dict(zip(columns, row)) for row in cur.fetchall()]

        # 2. Missing Indexes
        query_missing = """
            SELECT TOP (?)
                s.name as [schema],
                t.name as [table],
                mid.equality_columns,
                mid.inequality_columns,
                mid.included_columns,
                migs.unique_compiles,
                migs.user_seeks,
                migs.avg_total_user_cost,
                migs.avg_user_impact
            FROM sys.dm_db_missing_index_groups mig
            JOIN sys.dm_db_missing_index_group_stats migs ON mig.index_group_handle = migs.group_handle
            JOIN sys.dm_db_missing_index_details mid ON mig.index_handle = mid.index_handle
            JOIN sys.tables t ON mid.object_id = t.object_id
            JOIN sys.schemas s ON t.schema_id = s.schema_id
            WHERE mid.database_id = DB_ID()
        """
        params_missing = [limit]
        if schema:
            query_missing += " AND s.name = ?"
            params_missing.append(schema)
            
        query_missing += " ORDER BY migs.avg_user_impact DESC"
        
        _execute_safe(cur, query_missing, tuple(params_missing))
        columns = [c[0] for c in cur.description]
        results["missing_indexes"] = [dict(zip(columns, row)) for row in cur.fetchall()]

        return results
    finally:
        conn.close()


@mcp.tool
def db_sql2019_analyze_table_health(
    schema: str | None = None,
    min_size_mb: int = 50,
    profile: str = "oltp"
) -> dict[str, Any]:
    """
    Comprehensive health check for tables including fragmentation, missing stats, and size.

    Args:
        schema: Optional schema filter.
        min_size_mb: Minimum table size in MB to include in analysis (default: 50).
        profile: Workload profile (oltp, dw) - currently influences thresholds.

    Returns:
        Dictionary containing health issues and recommendations.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        # 1. Check for Outdated Statistics
        # stats older than 7 days or with high modification counter
        days_threshold = 7
        mod_percent_threshold = 20 # > 20% rows modified
        
        stats_query = """
        SELECT TOP 20
            SCHEMA_NAME(o.schema_id) as [schema],
            o.name as [table],
            s.name as [stat_name],
            STATS_DATE(s.object_id, s.stats_id) as last_updated,
            sp.modification_counter,
            sp.rows,
            CAST(CASE WHEN sp.rows > 0 THEN (sp.modification_counter * 100.0) / sp.rows ELSE 0 END AS DECIMAL(5,2)) as mod_percent
        FROM sys.stats s
        CROSS APPLY sys.dm_db_stats_properties(s.object_id, s.stats_id) sp
        JOIN sys.objects o ON s.object_id = o.object_id
        JOIN sys.schemas sch ON o.schema_id = sch.schema_id
        WHERE o.is_ms_shipped = 0
        """
        params = []
        if schema:
            stats_query += " AND sch.name = ?"
            params.append(schema)
            
        stats_query += """
         AND (
            STATS_DATE(s.object_id, s.stats_id) < DATEADD(day, ?, GETDATE())
            OR
            (sp.rows > 1000 AND (sp.modification_counter * 100.0) / sp.rows > ?)
         )
         ORDER BY mod_percent DESC
        """
        params.extend([-days_threshold, mod_percent_threshold])
        
        _execute_safe(cur, stats_query, tuple(params))
        columns = [column[0] for column in cur.description]
        outdated_stats = [dict(zip(columns, row)) for row in cur.fetchall()]
        
        # 2. Check for Heap Tables (No Clustered Index)
        heap_query = """
        SELECT TOP 20
            SCHEMA_NAME(o.schema_id) as [schema],
            o.name as [table],
            p.rows
        FROM sys.indexes i
        JOIN sys.objects o ON i.object_id = o.object_id
        JOIN sys.partitions p ON i.object_id = p.object_id AND i.index_id = p.index_id
        JOIN sys.schemas s ON o.schema_id = s.schema_id
        WHERE i.type = 0 -- Heap
          AND o.is_ms_shipped = 0
          AND o.type = 'U'
        """
        heap_params = []
        if schema:
            heap_query += " AND s.name = ?"
            heap_params.append(schema)
            
        heap_query += " ORDER BY p.rows DESC"
        
        _execute_safe(cur, heap_query, tuple(heap_params) if heap_params else None)
        columns = [column[0] for column in cur.description]
        heaps = [dict(zip(columns, row)) for row in cur.fetchall()]

        return {
            "outdated_statistics": outdated_stats,
            "heap_tables": heaps,
            "note": "For fragmentation details, use db_sql2019_check_fragmentation()."
        }
    finally:
        conn.close()


@mcp.tool
def db_sql2019_db_sec_perf_metrics(profile: str = "oltp") -> dict[str, Any]:
    """
    Comprehensive security and performance audit.

    Args:
        profile: Workload profile (default: "oltp").

    Returns:
        Dictionary containing security and performance findings.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        results = {}
        
        # --- Security Checks ---
        security_findings = []
        
        # 1. Check for Orphaned Users
        _execute_safe(cur, "EXEC sp_change_users_login 'Report'")
        # sp_change_users_login is deprecated, but widely available. 
        # Better: SELECT dp.name AS user_name, dp.sid FROM sys.database_principals dp LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid WHERE sp.sid IS NULL AND dp.type IN ('S', 'U', 'G') AND dp.authentication_type <> 2
        
        cur.execute("""
            SELECT dp.name 
            FROM sys.database_principals dp 
            LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid 
            WHERE sp.sid IS NULL 
            AND dp.type IN ('S', 'U', 'G') 
            AND dp.authentication_type <> 2 -- Not contained database user
            AND dp.name NOT IN ('dbo', 'guest', 'sys', 'INFORMATION_SCHEMA')
        """)
        orphans = [row[0] for row in cur.fetchall()]
        if orphans:
            security_findings.append(f"Found {len(orphans)} orphaned users: {', '.join(orphans)}")
            
        # 2. Check mixed mode authentication (informational)
        cur.execute("SELECT SERVERPROPERTY('IsIntegratedSecurityOnly')")
        is_integrated = cur.fetchone()[0]
        if is_integrated == 0:
             security_findings.append("Server is in Mixed Authentication Mode (SQL Auth + Windows Auth).")
        else:
             security_findings.append("Server is in Windows Authentication Mode only.")

        results["security"] = security_findings
        
        # --- Performance Checks ---
        perf_metrics = {}
        
        # 1. Page Life Expectancy (PLE) - Buffer Pool health
        cur.execute("""
            SELECT cntr_value 
            FROM sys.dm_os_performance_counters 
            WHERE object_name LIKE '%Buffer Manager%' 
            AND counter_name = 'Page life expectancy'
        """)
        row = cur.fetchone()
        if row:
            perf_metrics["page_life_expectancy"] = row[0]
            if row[0] < 300:
                perf_metrics["ple_warning"] = "PLE is low (< 300s), indicating memory pressure."

        # 2. Buffer Cache Hit Ratio
        cur.execute("""
            SELECT 
                CAST(A.cntr_value * 1.0 / B.cntr_value * 100.0 AS DECIMAL(5,2)) as BufferCacheHitRatio
            FROM sys.dm_os_performance_counters A
            CROSS JOIN sys.dm_os_performance_counters B
            WHERE A.object_name LIKE '%Buffer Manager%' AND A.counter_name = 'Buffer cache hit ratio'
            AND B.object_name LIKE '%Buffer Manager%' AND B.counter_name = 'Buffer cache hit ratio base'
        """)
        row = cur.fetchone()
        if row:
            perf_metrics["buffer_cache_hit_ratio"] = float(row[0])
            
        results["performance"] = perf_metrics
        
        return results
        
    finally:
        conn.close()


@mcp.tool
def db_sql2019_analyze_logical_data_model(
    schema: str = "dbo",
    include_views: bool = False,
    max_entities: Optional[int] = None,
    include_attributes: bool = True
) -> dict[str, Any]:
    """
    Generate a logical data model (LDM) for a schema and produce issues and recommendations.

    The model includes entities (tables), attributes (columns), identifiers (PK/UK), and relationships (FK).

    Args:
        schema: Schema to analyze (default: "dbo").
        include_views: Include views/materialized views as entities (default: False).
        max_entities: Maximum number of entities to include (default: 200).
        include_attributes: Include full attribute details (default: True).

    Returns:
        Dictionary containing logical model, issues, and recommendations.
    """
    def _snake_case(name: str) -> bool:
        return bool(re.match(r"^[a-z][a-z0-9_]*$", name))

    def _action(desc: str) -> str:
        # SQL Server uses NO_ACTION, CASCADE, SET_NULL, SET_DEFAULT in sys.foreign_keys
        # We map them to the standard format used in the frontend
        if desc == "NO_ACTION":
            return "NO ACTION"
        if desc == "CASCADE":
            return "CASCADE"
        if desc == "SET_NULL":
            return "SET NULL"
        if desc == "SET_DEFAULT":
            return "SET DEFAULT"
        return desc

    with get_connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(cur, "select GETUTCDATE() as generated_at_utc")
            generated_at_row = cur.fetchone() or []
            generated_at = generated_at_row[0]
            generated_at_iso = generated_at.isoformat() if hasattr(generated_at, "isoformat") else str(generated_at)

            types = "('U')" # User tables
            if include_views:
                types = "('U', 'V')"

            _execute_safe(
                cur,
                f"""
                SELECT TOP {max_entities if max_entities else 1000}
                    t.object_id,
                    s.name as [schema],
                    t.name as [name],
                    t.type
                FROM sys.objects t
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                WHERE s.name = ?
                  AND t.type IN {types}
                ORDER BY t.name
                """,
                (schema,)
            )
            table_rows = [dict(zip([c[0] for c in cur.description], row)) for row in cur.fetchall()]
            table_names = [r["name"] for r in table_rows]
            
            # Create a placeholder string for IN clause
            if not table_names:
                placeholders = "''"
            else:
                placeholders = ",".join("?" * len(table_names))

            columns_by_table: dict[str, list[dict[str, Any]]] = {}
            if include_attributes and table_names:
                _execute_safe(
                    cur,
                    f"""
                    SELECT
                        t.name as table_name,
                        c.name as column_name,
                        c.column_id as ordinal_position,
                        c.is_nullable,
                        ty.name as data_type,
                        c.max_length,
                        c.precision,
                        c.scale,
                        object_definition(c.default_object_id) as column_default
                    FROM sys.columns c
                    JOIN sys.objects t ON c.object_id = t.object_id
                    JOIN sys.schemas s ON t.schema_id = s.schema_id
                    JOIN sys.types ty ON c.user_type_id = ty.user_type_id
                    WHERE s.name = ?
                      AND t.name IN ({placeholders})
                    ORDER BY t.name, c.column_id
                    """,
                    (schema, *table_names)
                )
                
                columns_desc = [c[0] for c in cur.description]
                for row in cur.fetchall():
                    row_dict = dict(zip(columns_desc, row))
                    t = row_dict["table_name"]
                    columns_by_table.setdefault(t, []).append({
                        "name": row_dict["column_name"],
                        "position": row_dict["ordinal_position"],
                        "data_type": row_dict["data_type"],
                        "nullable": bool(row_dict["is_nullable"]),
                        "max_length": row_dict["max_length"],
                        "numeric_precision": row_dict["precision"],
                        "numeric_scale": row_dict["scale"],
                        "default": row_dict["column_default"],
                    })

            # Primary Keys
            _execute_safe(
                cur,
                f"""
                SELECT
                    t.name as [table],
                    i.name as [name],
                    c.name as column_name
                FROM sys.indexes i
                JOIN sys.objects t ON i.object_id = t.object_id
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
                JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
                WHERE s.name = ?
                  AND t.name IN ({placeholders})
                  AND i.is_primary_key = 1
                ORDER BY t.name, ic.key_ordinal
                """,
                (schema, *table_names)
            )
            pk_by_table: dict[str, list[str]] = {}
            for row in cur.fetchall():
                # row: table, name, column_name
                pk_by_table.setdefault(row[0], []).append(row[2])

            # Unique Constraints
            _execute_safe(
                cur,
                f"""
                SELECT
                    t.name as [table],
                    i.name as [name],
                    c.name as column_name
                FROM sys.indexes i
                JOIN sys.objects t ON i.object_id = t.object_id
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
                JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
                WHERE s.name = ?
                  AND t.name IN ({placeholders})
                  AND i.is_unique = 1
                  AND i.is_primary_key = 0
                ORDER BY t.name, i.name, ic.key_ordinal
                """,
                (schema, *table_names)
            )
            uniques_by_table: dict[str, list[list[str]]] = {}
            # Group by table and constraint name
            current_uq_table = None
            current_uq_name = None
            current_uq_cols = []
            
            for row in cur.fetchall():
                tbl, name, col = row
                if tbl != current_uq_table or name != current_uq_name:
                    if current_uq_table:
                        uniques_by_table.setdefault(current_uq_table, []).append(current_uq_cols)
                    current_uq_table = tbl
                    current_uq_name = name
                    current_uq_cols = []
                current_uq_cols.append(col)
            
            # Add last one
            if current_uq_table:
                uniques_by_table.setdefault(current_uq_table, []).append(current_uq_cols)

            # Foreign Keys
            _execute_safe(
                cur,
                f"""
                SELECT
                    t.name as [table],
                    fk.name as [name],
                    c_parent.name as local_column,
                    s_ref.name as ref_schema,
                    t_ref.name as ref_table,
                    c_ref.name as ref_column,
                    fk.update_referential_action_desc,
                    fk.delete_referential_action_desc
                FROM sys.foreign_keys fk
                JOIN sys.tables t ON fk.parent_object_id = t.object_id
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                JOIN sys.tables t_ref ON fk.referenced_object_id = t_ref.object_id
                JOIN sys.schemas s_ref ON t_ref.schema_id = s_ref.schema_id
                JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
                JOIN sys.columns c_parent ON fkc.parent_object_id = c_parent.object_id AND fkc.parent_column_id = c_parent.column_id
                JOIN sys.columns c_ref ON fkc.referenced_object_id = c_ref.object_id AND fkc.referenced_column_id = c_ref.column_id
                WHERE s.name = ?
                  AND t.name IN ({placeholders})
                ORDER BY t.name, fk.name, fkc.constraint_column_id
                """,
                (schema, *table_names)
            )
            
            # Process FKs into structured objects (need to group by FK name)
            fk_rows_raw = [dict(zip([c[0] for c in cur.description], row)) for row in cur.fetchall()]
            fk_grouped = {}
            
            for row in fk_rows_raw:
                fk_name = row["name"]
                if fk_name not in fk_grouped:
                    fk_grouped[fk_name] = {
                        "table": row["table"],
                        "name": fk_name,
                        "local_columns": [],
                        "ref_schema": row["ref_schema"],
                        "ref_table": row["ref_table"],
                        "ref_columns": [],
                        "on_update": _action(row["update_referential_action_desc"]),
                        "on_delete": _action(row["delete_referential_action_desc"]),
                    }
                fk_grouped[fk_name]["local_columns"].append(row["local_column"])
                fk_grouped[fk_name]["ref_columns"].append(row["ref_column"])
            
            fk_rows = list(fk_grouped.values())

            # Indexes (for optimization checks)
            _execute_safe(
                cur,
                f"""
                SELECT
                    t.name as [table],
                    i.name as [index],
                    i.is_unique,
                    i.is_primary_key,
                    c.name as column_name
                FROM sys.indexes i
                JOIN sys.objects t ON i.object_id = t.object_id
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
                JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
                WHERE s.name = ?
                  AND t.name IN ({placeholders})
                ORDER BY t.name, i.name, ic.key_ordinal
                """,
                (schema, *table_names)
            )
            
            indexes_by_table: dict[str, list[dict[str, Any]]] = {}
            current_idx_table = None
            current_idx_name = None
            current_idx_obj = None
            
            idx_desc = [c[0] for c in cur.description]
            for row_raw in cur.fetchall():
                row = dict(zip(idx_desc, row_raw))
                if row["table"] != current_idx_table or row["index"] != current_idx_name:
                    if current_idx_obj:
                        indexes_by_table.setdefault(current_idx_table, []).append(current_idx_obj)
                    current_idx_table = row["table"]
                    current_idx_name = row["index"]
                    current_idx_obj = {
                        "name": row["index"],
                        "columns": [],
                        "is_unique": row["is_unique"],
                        "is_primary": row["is_primary_key"]
                    }
                current_idx_obj["columns"].append(row["column_name"])
                
            if current_idx_obj:
                 indexes_by_table.setdefault(current_idx_table, []).append(current_idx_obj)

            entity_map: dict[str, dict[str, Any]] = {}
            issues = {
                "entities": [],
                "attributes": [],
                "relationships": [],
                "identifiers": [],
                "normalization": [],
            }
            recommendations = {
                "entities": [],
                "attributes": [],
                "relationships": [],
                "identifiers": [],
                "normalization": [],
            }

            for t in table_rows:
                table_name = t["name"]
                attrs = columns_by_table.get(table_name, [])
                pk_cols = pk_by_table.get(table_name, [])
                uniqs = uniques_by_table.get(table_name, [])
                
                fks_for_table = [fk for fk in fk_rows if fk["table"] == table_name]

                col_nullable: dict[str, bool] = {a["name"]: bool(a.get("nullable")) for a in attrs}
                col_types: dict[str, str] = {a["name"]: str(a.get("data_type") or "") for a in attrs}

                for fk in fks_for_table:
                    # Update optional flag based on nullability
                    local_cols = fk["local_columns"]
                    fk["optional"] = any(col_nullable.get(c, False) for c in local_cols)

                if not _snake_case(table_name):
                    issues["entities"].append({
                        "entity": f"{schema}.{table_name}",
                        "issue": "Non-snake_case entity name",
                    })
                    recommendations["entities"].append({
                        "entity": f"{schema}.{table_name}",
                        "recommendation": "Standardize entity naming to snake_case for consistency.",
                    })

                if not pk_cols and t["type"].strip() == "U":
                    issues["identifiers"].append({
                        "entity": f"{schema}.{table_name}",
                        "issue": "Missing primary key",
                    })
                    recommendations["identifiers"].append({
                        "entity": f"{schema}.{table_name}",
                        "recommendation": "Add a primary key to support entity identity, replication, and FK references.",
                    })

                if len(pk_cols) > 1 and len(attrs) > len(pk_cols):
                    issues["normalization"].append({
                        "entity": f"{schema}.{table_name}",
                        "issue": "Composite primary key with non-key attributes requires 2NF review",
                        "details": {"primary_key": pk_cols},
                    })
                    recommendations["normalization"].append({
                        "entity": f"{schema}.{table_name}",
                        "recommendation": "Review for partial dependencies; consider surrogate key if appropriate.",
                    })

                if include_attributes:
                    for a in attrs:
                        col = a["name"]
                        if not _snake_case(col):
                            issues["attributes"].append({
                                "entity": f"{schema}.{table_name}",
                                "attribute": col,
                                "issue": "Non-snake_case attribute name",
                            })
                            recommendations["attributes"].append({
                                "entity": f"{schema}.{table_name}",
                                "attribute": col,
                                "recommendation": "Standardize attribute naming to snake_case for consistency.",
                            })

                        dt = col_types.get(col, "").lower()
                        # SQL Server specific checks
                        is_json = dt in ("nvarchar", "varchar") and (a.get("max_length") == -1) # approximate check for JSON storage
                        # Note: SQL Server doesn't have a native JSON type, stored as NVARCHAR(MAX) usually
                        
                        # Check for XML
                        if dt == "xml":
                             issues["normalization"].append({
                                "entity": f"{schema}.{table_name}",
                                "attribute": col,
                                "issue": "XML data type used",
                                "details": {"data_type": dt},
                            })
                             
                fk_indexes = indexes_by_table.get(table_name, [])
                for fk in fks_for_table:
                    local_cols = fk["local_columns"]
                    if not local_cols:
                        continue
                    # Check if there is an index where the first N columns match the FK columns
                    indexed = any(
                        idx.get("columns", [])[:len(local_cols)] == local_cols 
                        for idx in fk_indexes
                    )
                    if not indexed:
                        issues["relationships"].append({
                            "entity": f"{schema}.{table_name}",
                            "relationship": fk["name"],
                            "issue": "Foreign key columns are not covered by a leading index",
                            "details": {"columns": local_cols},
                        })
                        recommendations["relationships"].append({
                            "entity": f"{schema}.{table_name}",
                            "relationship": fk["name"],
                            "recommendation": f"Create an index on ({', '.join(local_cols)}) to improve join performance and FK maintenance.",
                        })

                col_names = [a["name"] for a in attrs]
                repeated_groups = {}
                for c in col_names:
                    m = re.match(r"^(.*)_(\d+)$", c)
                    if m:
                        base = m.group(1)
                        repeated_groups.setdefault(base, 0)
                        repeated_groups[base] += 1
                for base, count in repeated_groups.items():
                    if count >= 2:
                        issues["normalization"].append({
                            "entity": f"{schema}.{table_name}",
                            "issue": "Potential repeating group pattern in attributes",
                            "details": {"base": base, "count": count},
                        })
                        recommendations["normalization"].append({
                            "entity": f"{schema}.{table_name}",
                            "recommendation": "Consider normalizing repeating groups into a child entity with one row per repeated value.",
                        })

                for c in col_names:
                    if c.endswith("_id"):
                        base = c[:-3]
                        if f"{base}_name" in col_names or f"{base}_code" in col_names:
                            issues["normalization"].append({
                                "entity": f"{schema}.{table_name}",
                                "issue": "Potential transitive dependency / duplicated reference data",
                                "details": {"id_column": c},
                            })
                            recommendations["normalization"].append({
                                "entity": f"{schema}.{table_name}",
                                "recommendation": f"Consider storing only {c} and retrieving related descriptive attributes via relationship joins.",
                            })

                entity_map[table_name] = {
                    "schema": schema,
                    "name": table_name,
                    "kind": t["type"].strip(), # U or V
                    "attributes": attrs if include_attributes else [],
                    "primary_key": pk_cols,
                    "unique_constraints": uniqs,
                    "foreign_keys": fks_for_table,
                }

            relationships: list[dict[str, Any]] = []
            for fk in fk_rows:
                relationships.append({
                    "name": fk["name"],
                    "from_entity": f"{schema}.{fk['table']}",
                    "to_entity": f"{fk['ref_schema']}.{fk['ref_table']}",
                    "local_columns": fk["local_columns"] or [],
                    "ref_columns": fk["ref_columns"] or [],
                    "on_update": fk["on_update"],
                    "on_delete": fk["on_delete"],
                })

            summary = {
                "schema": schema,
                "generated_at_utc": generated_at_iso,
                "entities": len(entity_map),
                "relationships": len(relationships),
                "issues_count": {k: len(v) for k, v in issues.items()},
            }

            result_data = {
                "summary": summary,
                "logical_model": {
                    "entities": list(entity_map.values()),
                    "relationships": relationships,
                },
                "issues": issues,
                "recommendations": recommendations,
            }
            
            # Cache the result
            analysis_id = str(uuid.uuid4())
            DATA_MODEL_CACHE[analysis_id] = result_data
            
            # Construct URL
            # Use MCP_PORT if set, otherwise default to 8085 for UI to avoid 8000 conflicts
            port = os.environ.get("MCP_PORT", "8085")
            host = os.environ.get("MCP_HOST", "localhost")
            if host == "0.0.0.0":
                host = "localhost"
            
            url = f"http://{host}:{port}/data-model-analysis?id={analysis_id}"
            
            return {
                "message": "Analysis complete. View the interactive report at the URL below.",
                "report_url": url,
                "summary": summary
            }






@mcp.tool
def db_sql2019_describe_table(schema: str, table: str) -> dict[str, Any]:
    """
    Get detailed information about a table's structure, including columns, indexes, and size.

    Args:
        schema: The schema the table belongs to.
        table: The name of the table to describe.

    Returns:
        Dictionary containing schema, table name, columns, indexes, sizes, and approximate row count.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        # 1. Columns
        _execute_safe(
            cur,
            """
            SELECT
                c.ordinal_position,
                c.column_name,
                c.data_type,
                c.is_nullable,
                c.column_default,
                c.character_maximum_length,
                c.numeric_precision,
                c.numeric_scale
            FROM information_schema.columns c
            WHERE c.table_schema = ?
              AND c.table_name = ?
            ORDER BY c.ordinal_position
            """,
            (schema, table),
        )
        columns = [dict(zip([d[0] for d in cur.description], row)) for row in cur.fetchall()]

        # 2. Indexes
        _execute_safe(
            cur,
            """
            SELECT
                i.name as index_name,
                i.type_desc as index_type,
                i.is_unique,
                i.is_primary_key,
                STRING_AGG(c.name, ', ') WITHIN GROUP (ORDER BY ic.key_ordinal) as index_keys
            FROM sys.indexes i
            JOIN sys.objects t ON i.object_id = t.object_id
            JOIN sys.schemas s ON t.schema_id = s.schema_id
            JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
            JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
            WHERE s.name = ?
              AND t.name = ?
            GROUP BY i.name, i.type_desc, i.is_unique, i.is_primary_key
            ORDER BY i.name
            """,
            (schema, table),
        )
        indexes = [dict(zip([d[0] for d in cur.description], row)) for row in cur.fetchall()]

        # 3. Size and Row Count
        # Using sys.dm_db_partition_stats for fast approximation
        _execute_safe(
            cur,
            """
            SELECT
                SUM(reserved_page_count) * 8 * 1024 as total_size_bytes,
                SUM(used_page_count) * 8 * 1024 as used_size_bytes,
                SUM(row_count) as approx_rows
            FROM sys.dm_db_partition_stats p
            JOIN sys.objects t ON p.object_id = t.object_id
            JOIN sys.schemas s ON t.schema_id = s.schema_id
            WHERE s.name = ?
              AND t.name = ?
              AND p.index_id < 2 -- Heap or Clustered Index
            """,
            (schema, table),
        )
        size_row = cur.fetchone()
        
        total_bytes = size_row[0] if size_row and size_row[0] is not None else 0
        used_bytes = size_row[1] if size_row and size_row[1] is not None else 0
        approx_rows = size_row[2] if size_row and size_row[2] is not None else 0

        return {
            "schema": schema,
            "table": table,
            "columns": columns,
            "indexes": indexes,
            "total_size_bytes": total_bytes,
            "used_size_bytes": used_bytes,
            "approx_rows": approx_rows,
        }
    finally:
        conn.close()


@mcp.tool
def db_sql2019_run_query(sql: str, params_json: str | None = None, max_rows: int | None = None) -> dict[str, Any]:
    """
    Execute a read-only SQL query against the database.

    Note:
        This tool attempts to enforce read-only execution by analyzing the SQL string.
        Complex queries or obfuscation might bypass this check. 
        Always operate with a user that has restricted permissions at the database level.

    Args:
        sql: The SQL query to execute.
        params_json: Optional JSON string of a LIST of parameters to bind to the query (positional, ?).
        max_rows: Maximum number of rows to return (default: 500).

    Returns:
        Dictionary containing columns, rows, and truncation status.
    """
    _require_readonly(sql)
    limit = max_rows if max_rows is not None else DEFAULT_MAX_ROWS
    if limit < 0:
        raise ValueError("max_rows must be >= 0")
    
    sql_fingerprint = hashlib.sha256(sql.encode("utf-8")).hexdigest()
    params_fingerprint = (
        hashlib.sha256(params_json.encode("utf-8")).hexdigest() if params_json is not None else None
    )
    logger.info(f"run_query called. sql_len={len(sql)} max_rows={limit} sql_sha256={sql_fingerprint}")
    logger.debug(f"run_query params_sha256={params_fingerprint}")
    
    params: list[Any] | None = None
    if params_json:
        params = json.loads(params_json)
        if not isinstance(params, list):
            raise ValueError("params_json must decode to a JSON list (array) for SQL Server positional parameters.")

    conn = get_connection()
    try:
        cur = conn.cursor()
        
        # Enforce limit using TOP if generic SELECT, but it's hard to inject safely.
        # We will just fetch limited rows.
        
        _execute_safe(cur, sql, tuple(params) if params else None)
        
        rows_plus_one = _fetch_limited(cur, limit + 1 if limit >= 0 else 1)
        truncated = len(rows_plus_one) > limit
        rows = rows_plus_one[:limit]
        
        if cur.description:
            columns = [d[0] for d in cur.description]
        else:
            columns = []
            
        return {
            "columns": columns,
            "rows": rows,
            "returned_rows": len(rows),
            "truncated": truncated,
        }
    finally:
        conn.close()


@mcp.tool
def db_sql2019_explain_query(
    sql: str,
    analyze: bool = False,
    output_format: str = "xml",
) -> dict[str, Any]:
    """
    Get the execution plan for a query.

    Args:
        sql: The SQL query to explain.
        analyze: If True, executes the query to get actual runtimes (default: False).
                 Warning: This WILL execute the query. Ensure it is safe.
        output_format: Output format, currently only 'xml' is supported for SQL Server.

    Returns:
        Dictionary containing the plan format and the plan content.
    """
    sql_fingerprint = hashlib.sha256(sql.encode("utf-8")).hexdigest()
    logger.info(
        f"explain_query called. analyze={analyze} sql_len={len(sql)} sql_sha256={sql_fingerprint}"
    )
    _require_readonly(sql)
    
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        if analyze:
            # SET STATISTICS XML ON executes the query and returns plan + results
            # We need to handle this carefully because it returns multiple result sets.
            # The plan is usually in a separate result set or as a column in the last result set.
            cur.execute("SET STATISTICS XML ON")
            try:
                cur.execute(sql)
                # Iterate through result sets to find the plan
                # pyodbc: nextset() returns True if there is another set
                
                plan_xml = None
                
                # We might get normal results first, then the plan
                while True:
                    try:
                        if cur.description:
                            # Check if this is the plan (usually column name is "Microsoft SQL Server 2005 XML Showplan")
                            cols = [d[0] for d in cur.description]
                            if any("Showplan" in c for c in cols):
                                row = cur.fetchone()
                                if row:
                                    plan_xml = row[0]
                    except Exception:
                        pass
                        
                    if not cur.nextset():
                        break
                        
                return {"format": "xml", "plan": plan_xml}
            finally:
                # Ensure we turn it off even if error
                try:
                    cur.execute("SET STATISTICS XML OFF")
                except:
                    pass
        else:
            # SET SHOWPLAN_XML ON compiles but does not execute
            cur.execute("SET SHOWPLAN_XML ON")
            try:
                cur.execute(sql)
                # The plan is returned as a single row single column result set
                row = cur.fetchone()
                plan_xml = row[0] if row else None
                return {"format": "xml", "plan": plan_xml}
            finally:
                 try:
                    cur.execute("SET SHOWPLAN_XML OFF")
                 except:
                    pass
    finally:
        conn.close()


@mcp.tool
def db_sql2019_ping() -> dict[str, Any]:
    """
    Check if the MCP server is responsive.

    Returns:
        Dictionary with "ok": True if the server is responsive.
    """
    return {"ok": True}


@mcp.tool
def db_sql2019_server_info_mcp() -> dict[str, Any]:
    """
    Get information about the MCP server configuration and status.

    Returns:
        Dictionary containing server name, version, status, transport type, and connected database name.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT DB_NAME() as database_name")
        row = cur.fetchone()
        database_name = row[0] if row else "unknown"
    except Exception:
        database_name = "error"
    finally:
        conn.close()

    return {
        "name": mcp.name,
        "version": "1.0.0",
        "status": "healthy",
        "transport": os.environ.get("MCP_TRANSPORT", "http"),
        "database": ORIGINAL_DB_NAME or database_name
    }



def _configure_fastmcp_runtime() -> None:
    cert_file = os.environ.get("SSL_CERT_FILE")
    if cert_file and not os.path.exists(cert_file):
        os.environ.pop("SSL_CERT_FILE", None)
    try:
        import fastmcp

        fastmcp.settings.check_for_updates = "off"
    except Exception:
        pass


DATA_MODEL_CACHE = {}

DATA_MODEL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Data Model Analysis</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/svg-pan-zoom@3.6.1/dist/svg-pan-zoom.min.js"></script>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({ startOnLoad: false, theme: 'default', maxTextSize: 1000000 });
        window.mermaid = mermaid;
    </script>
    <style>
        .mermaid { background: white; }
    </style>
</head>
<body class="bg-gray-100 min-h-screen p-4 md:p-8">
    <div class="max-w-7xl mx-auto bg-white shadow-xl rounded-lg overflow-hidden">
        <!-- Header -->
        <div class="bg-indigo-600 p-6 text-white">
            <h1 class="text-3xl font-bold">Logical Data Model Analysis</h1>
            <div class="mt-2 flex items-center text-indigo-100 text-sm">
                <span id="schemaName" class="font-mono bg-indigo-700 px-2 py-1 rounded mr-4">schema: public</span>
                <span id="generatedAt">Generated at: ...</span>
            </div>
        </div>

        <!-- Summary Stats -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-0 border-b border-gray-200">
            <div class="p-6 border-r border-gray-200 text-center hover:bg-gray-50 transition">
                <div class="text-sm text-gray-500 uppercase tracking-wide font-semibold">Entities</div>
                <div class="text-3xl font-bold text-gray-800 mt-1" id="countEntities">-</div>
            </div>
            <div class="p-6 border-r border-gray-200 text-center hover:bg-gray-50 transition">
                <div class="text-sm text-gray-500 uppercase tracking-wide font-semibold">Relationships</div>
                <div class="text-3xl font-bold text-gray-800 mt-1" id="countRelationships">-</div>
            </div>
            <div class="p-6 border-r border-gray-200 text-center hover:bg-gray-50 transition">
                <div class="text-sm text-gray-500 uppercase tracking-wide font-semibold">Issues</div>
                <div class="text-3xl font-bold text-red-600 mt-1" id="countIssues">-</div>
            </div>
            <div class="p-6 text-center hover:bg-gray-50 transition" title="Score = 100 - (2 * Total Issues). A higher score indicates better adherence to database design best practices (normalization, naming conventions, indexing).">
                <div class="text-sm text-gray-500 uppercase tracking-wide font-semibold">Score</div>
                <div class="text-3xl font-bold text-green-600 mt-1" id="modelScore">-</div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="p-6 space-y-8">
            
            <!-- Diagram Section -->
            <section>
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-xl font-bold text-gray-800 flex items-center">
                        <svg class="w-5 h-5 mr-2 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path></svg>
                        Entity Relationship Diagram
                    </h2>
                    <button onclick="renderMermaid()" class="text-sm text-indigo-600 hover:text-indigo-800 font-medium">Redraw</button>
                </div>
                <div class="overflow-x-auto border border-gray-200 rounded-lg bg-gray-50 p-4 min-h-[300px] flex items-center justify-center">
                    <div class="mermaid w-full text-center" id="mermaidGraph">
                        %% Loading diagram...
                    </div>
                </div>
            </section>

            <!-- Findings & Recommendations Grid -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <!-- Issues -->
                <section class="bg-red-50 rounded-lg p-6 border border-red-100">
                    <h2 class="text-xl font-bold text-red-800 mb-4 flex items-center">
                        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                        Key Findings & Issues
                    </h2>
                    <div id="issuesList" class="space-y-3">
                        <!-- Issues injected here -->
                    </div>
                </section>

                <!-- Recommendations -->
                <section class="bg-blue-50 rounded-lg p-6 border border-blue-100">
                    <h2 class="text-xl font-bold text-blue-800 mb-4 flex items-center">
                        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path></svg>
                        Recommendations
                    </h2>
                    <div id="recommendationsList" class="space-y-3">
                        <!-- Recommendations injected here -->
                    </div>
                </section>
            </div>

            <!-- Detailed Analysis -->
            <section>
                <h2 class="text-xl font-bold text-gray-800 mb-4">Detailed Entity Analysis</h2>
                <div class="overflow-hidden border border-gray-200 rounded-lg shadow-sm">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Entity</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Kind</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Structure</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Constraints</th>
                            </tr>
                        </thead>
                        <tbody id="entityTableBody" class="bg-white divide-y divide-gray-200">
                            <!-- Rows injected here -->
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    </div>

    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const id = urlParams.get('id');

        async function renderMermaid(graphDefinition) {
            const element = document.getElementById('mermaidGraph');
            if (graphDefinition) {
                element.textContent = graphDefinition;
                element.removeAttribute('data-processed');
                // Clean up previous instance
                if (window.panZoomInstance) {
                    window.panZoomInstance.destroy();
                    window.panZoomInstance = null;
                }
            }
            
            await window.mermaid.run({
                nodes: [element]
            });

            const svg = element.querySelector('svg');
            if (svg) {
                // Ensure SVG has explicit dimensions for pan-zoom to work correctly
                svg.style.height = '600px'; 
                svg.style.width = '100%';
                
                try {
                    window.panZoomInstance = svgPanZoom(svg, {
                        zoomEnabled: true,
                        controlIconsEnabled: true,
                        fit: true,
                        center: true,
                        minZoom: 0.1,
                        maxZoom: 10
                    });
                } catch (e) {
                    console.error("PanZoom initialization failed", e);
                }
            }
        }

        async function loadData() {
            if (!id) {
                document.body.innerHTML = '<div class="p-8 text-red-600 text-center font-bold">No analysis ID provided</div>';
                return;
            }

            try {
                const response = await fetch(`/api/data-model/${id}`);
                if (!response.ok) throw new Error('Analysis not found');
                const data = await response.json();
                
                renderDashboard(data);
            } catch (err) {
                console.error(err);
                document.body.innerHTML = `<div class="p-8 text-red-600 text-center font-bold">Error loading analysis: ${err.message}</div>`;
            }
        }

        const ITEMS_PER_PAGE = 20;
        let currentIssuesPage = 1;
        let currentRecsPage = 1;
        let allIssuesData = [];
        let allRecsData = [];

        function renderPaginatedList(containerId, items, page, type) {
            const container = document.getElementById(containerId);
            const start = (page - 1) * ITEMS_PER_PAGE;
            const end = start + ITEMS_PER_PAGE;
            const pageItems = items.slice(start, end);
            const totalPages = Math.ceil(items.length / ITEMS_PER_PAGE);

            if (items.length === 0) {
                 if (type === 'issue') {
                    container.innerHTML = '<div class="text-green-600 italic">No significant issues found. Great job!</div>';
                 } else {
                    container.innerHTML = '<div class="text-gray-500 italic">No specific recommendations at this time.</div>';
                 }
                 return;
            }

            const listHtml = pageItems.map(i => {
                if (type === 'issue') {
                    return `
                    <div class="bg-white p-3 rounded border-l-4 border-red-500 shadow-sm text-sm">
                        <div class="font-bold text-gray-800">${i.entity || 'General'}</div>
                        <div class="text-gray-600">${i.issue}</div>
                         ${i.details ? `<div class="text-xs text-gray-500 mt-1">${typeof i.details === 'string' ? i.details : JSON.stringify(i.details)}</div>` : ''}
                    </div>`;
                } else {
                     return `
                    <div class="bg-white p-3 rounded border-l-4 border-blue-500 shadow-sm text-sm">
                        <div class="font-bold text-gray-800">${i.entity || 'General'}</div>
                        <div class="text-gray-600">${i.recommendation}</div>
                    </div>`;
                }
            }).join('');

            const controlsHtml = totalPages > 1 ? `
                <div class="flex justify-between items-center mt-4 text-sm">
                    <button onclick="changePage('${type}', -1)" ${page === 1 ? 'disabled' : ''} class="px-3 py-1 bg-gray-200 rounded hover:bg-gray-300 disabled:opacity-50 disabled:cursor-not-allowed">Previous</button>
                    <span>Page ${page} of ${totalPages} (${items.length} items)</span>
                    <button onclick="changePage('${type}', 1)" ${page === totalPages ? 'disabled' : ''} class="px-3 py-1 bg-gray-200 rounded hover:bg-gray-300 disabled:opacity-50 disabled:cursor-not-allowed">Next</button>
                </div>
            ` : `<div class="mt-2 text-xs text-gray-500 text-right">Showing all ${items.length} items</div>`;

            container.innerHTML = listHtml + controlsHtml;
        }

        window.changePage = function(type, delta) {
            if (type === 'issue') {
                const totalPages = Math.ceil(allIssuesData.length / ITEMS_PER_PAGE);
                const newPage = currentIssuesPage + delta;
                if (newPage >= 1 && newPage <= totalPages) {
                    currentIssuesPage = newPage;
                    renderPaginatedList('issuesList', allIssuesData, currentIssuesPage, 'issue');
                }
            } else if (type === 'rec') {
                const totalPages = Math.ceil(allRecsData.length / ITEMS_PER_PAGE);
                const newPage = currentRecsPage + delta;
                if (newPage >= 1 && newPage <= totalPages) {
                    currentRecsPage = newPage;
                    renderPaginatedList('recommendationsList', allRecsData, currentRecsPage, 'rec');
                }
            }
        }

        function renderDashboard(data) {
            const summary = data.summary;
            const issues = data.issues;
            const recommendations = data.recommendations;
            const model = data.logical_model;

            // Summary
            document.getElementById('schemaName').textContent = `schema: ${summary.schema}`;
            document.getElementById('generatedAt').textContent = `Generated at: ${new Date(summary.generated_at_utc).toLocaleString()}`;
            document.getElementById('countEntities').textContent = summary.entities;
            document.getElementById('countRelationships').textContent = summary.relationships;
            
            const totalIssues = Object.values(summary.issues_count).reduce((a, b) => a + b, 0);
            document.getElementById('countIssues').textContent = totalIssues;
            
            // Simple Score calculation (100 - issues * 2)
            const score = Math.max(0, 100 - (totalIssues * 2));
            document.getElementById('modelScore').textContent = score + '/100';

            // Issues List Initialization
            allIssuesData = [
                ...issues.entities, 
                ...issues.identifiers, 
                ...issues.normalization, 
                ...issues.relationships, 
                ...issues.attributes
            ];
            renderPaginatedList('issuesList', allIssuesData, currentIssuesPage, 'issue');

            // Recommendations List Initialization
            allRecsData = [
                ...recommendations.entities,
                ...recommendations.identifiers,
                ...recommendations.normalization,
                ...recommendations.relationships,
                ...recommendations.attributes
            ];
            renderPaginatedList('recommendationsList', allRecsData, currentRecsPage, 'rec');

            // Detailed Entity Table
            const entityTable = document.getElementById('entityTableBody');
            entityTable.innerHTML = model.entities.map(e => `
                <tr class="hover:bg-gray-50">
                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${e.name}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${e.kind === 'r' ? 'Table' : e.kind === 'v' ? 'View' : e.kind}</td>
                    <td class="px-6 py-4 text-sm text-gray-500">
                        <div>${e.attributes.length} columns</div>
                        <div class="text-xs text-gray-400 mt-1">${e.attributes.slice(0, 3).map(a => a.name).join(', ')}${e.attributes.length > 3 ? '...' : ''}</div>
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-500">
                        ${e.primary_key.length ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 mr-1">PK: ${e.primary_key.join(', ')}</span>` : '<span class="text-red-400 text-xs">No PK</span>'}
                        ${e.unique_constraints.length ? `<div class="mt-1"><span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">UKs: ${e.unique_constraints.length}</span></div>` : ''}
                    </td>
                </tr>
            `).join('');

            // Generate Mermaid Diagram
            const graph = generateMermaid(model);
            renderMermaid(graph);
        }

        function generateMermaid(model) {
            let s = 'erDiagram\\n';
            
            // Helper to sanitize names for Mermaid
            const safeName = (name) => name.replace(/[^a-zA-Z0-9_]/g, '_');
            const safeType = (type) => type.replace(/\\s+/g, '_');

            // Entities
            model.entities.forEach(e => {
                const entityName = safeName(e.name);
                s += `    ${entityName} {\n`;
                // Add PKs first
                e.attributes.forEach(a => {
                    const isPk = e.primary_key.includes(a.name);
                    const isFk = e.foreign_keys.some(fk => fk.local_columns.includes(a.name));
                    
                    let type = safeType(a.data_type);
                    if (a.max_length) type += `(${a.max_length})`;
                    
                    let markers = [];
                    if (isPk) markers.push('PK');
                    if (isFk) markers.push('FK');
                    
                    // Attribute name might need quotes if it has special chars, but for ERD
                    // Mermaid expects word-like tokens. We'll use safeName just in case.
                    s += `        ${type} ${safeName(a.name)} ${markers.length ? '"' + markers.join(', ') + '"' : ''}\n`;
                });
                s += '    }\\n';
            });

            // Relationships
            model.relationships.forEach(r => {
                // Determine cardinality (basic assumption for now: 1 to Many)
                // If unique constraint exists on local columns, it might be 1 to 1
                // For now, we use ||--o{ as default
                const from = r.to_entity.split('.')[1]; // ref table (parent)
                const to = r.from_entity.split('.')[1]; // local table (child)
                
                // Avoid self-references or missing entities crashing mermaid
                if (from && to) {
                    const label = r.name.replace(/"/g, "'"); // Escape quotes in label
                    s += `    ${safeName(from)} ||--o{ ${safeName(to)} : "${label}"\n`;
                }
            });

            return s;
        }

        window.onload = loadData;
    </script>
</body>
</html>
"""

@mcp.custom_route("/data-model-analysis", methods=["GET"])
async def data_model_analysis_ui(_request: Request) -> HTMLResponse:
    return HTMLResponse(DATA_MODEL_HTML)

def _make_json_serializable(obj: Any) -> Any:
    """Recursively convert objects to JSON-serializable types."""
    if isinstance(obj, dict):
        return {k: _make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_make_json_serializable(v) for v in obj]
    elif isinstance(obj, tuple):
        return tuple(_make_json_serializable(v) for v in obj)
    elif isinstance(obj, (datetime, date)):
        return obj.isoformat()
    elif isinstance(obj, decimal.Decimal):
        return float(obj)
    elif isinstance(obj, uuid.UUID):
        return str(obj)
    return obj

@mcp.custom_route("/api/data-model/{result_id}", methods=["GET"])
async def get_data_model_result(request: Request) -> JSONResponse:
    result_id = request.path_params["result_id"]
    data = DATA_MODEL_CACHE.get(result_id)
    if not data:
        return JSONResponse({"error": "Analysis not found or expired"}, status_code=404)
    
    try:
        # Ensure data is serializable (handle Decimal, UUID, datetime, etc.)
        safe_data = _make_json_serializable(data)
        return JSONResponse(safe_data)
    except Exception as e:
        logger.error(f"Serialization error for result {result_id}: {e}")
        return JSONResponse({"error": f"Internal serialization error: {str(e)}"}, status_code=500)


SESSION_MONITOR_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>DB Sessions Monitor</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: sans-serif; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { text-align: center; }
        .stats { display: flex; justify-content: space-around; margin-bottom: 20px; }
        .stat-box { text-align: center; padding: 10px; border: 1px solid #ddd; border-radius: 5px; min-width: 100px; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .stat-label { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SQL Server Sessions Monitor</h1>
        
        <div class="stats">
            <div class="stat-box">
                <div id="activeVal" class="stat-value">-</div>
                <div class="stat-label">Active</div>
            </div>
            <div class="stat-box">
                <div id="idleVal" class="stat-value">-</div>
                <div class="stat-label">Idle</div>
            </div>
            <div class="stat-box">
                <div id="totalVal" class="stat-value">-</div>
                <div class="stat-label">Total</div>
            </div>
        </div>

        <canvas id="sessionsChart"></canvas>
    </div>
    <script>
        const ctx = document.getElementById('sessionsChart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Active',
                        borderColor: 'rgb(75, 192, 192)',
                        backgroundColor: 'rgba(75, 192, 192, 0.1)',
                        data: [],
                        tension: 0.1,
                        fill: true
                    },
                    {
                        label: 'Idle',
                        borderColor: 'rgb(255, 205, 86)',
                        backgroundColor: 'rgba(255, 205, 86, 0.1)',
                        data: [],
                        tension: 0.1,
                        fill: true
                    },
                    {
                        label: 'Total',
                        borderColor: 'rgb(54, 162, 235)',
                        borderDash: [5, 5],
                        data: [],
                        tension: 0.1,
                        fill: false
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    x: { title: { display: true, text: 'Time' } },
                    y: { beginAtZero: true, title: { display: true, text: 'Count' } }
                }
            }
        });

        async function fetchData() {
            try {
                const response = await fetch('/api/sessions');
                const data = await response.json();
                const now = new Date().toLocaleTimeString();

                // Update text stats
                document.getElementById('activeVal').textContent = data.active;
                document.getElementById('idleVal').textContent = data.idle;
                document.getElementById('totalVal').textContent = data.total;

                // Update chart
                if (chart.data.labels.length > 20) {
                    chart.data.labels.shift();
                    chart.data.datasets[0].data.shift();
                    chart.data.datasets[1].data.shift();
                    chart.data.datasets[2].data.shift();
                }

                chart.data.labels.push(now);
                chart.data.datasets[0].data.push(data.active);
                chart.data.datasets[1].data.push(data.idle);
                chart.data.datasets[2].data.push(data.total);
                chart.update();
            } catch (error) {
                console.error('Error fetching data:', error);
            }
        }

        // Fetch every 5 seconds
        setInterval(fetchData, 5000);
        fetchData(); // Initial fetch
    </script>
</body>
</html>
"""

@mcp.custom_route("/sessions-monitor", methods=["GET"])
async def sessions_monitor(_request: Request) -> HTMLResponse:
    return HTMLResponse(SESSION_MONITOR_HTML)

@mcp.custom_route("/api/sessions", methods=["GET"])
async def api_sessions(_request: Request) -> JSONResponse:
    with get_connection() as conn:
        cur = conn.cursor()
        # Query for session counts in SQL Server
        # Active: status IN ('running', 'runnable')
        # Idle: status = 'sleeping'
        # Total: count(*)
        _execute_safe(
            cur,
            """
            SELECT
                SUM(CASE WHEN status IN ('running', 'runnable') THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN status = 'sleeping' THEN 1 ELSE 0 END) as idle,
                COUNT(*) as total
            FROM sys.dm_exec_sessions
            WHERE is_user_process = 1
            """
        )
        columns = [c[0] for c in cur.description]
        row = cur.fetchone()
        if not row:
             return JSONResponse({"active": 0, "idle": 0, "total": 0, "timestamp": time.time()})

        row_dict = dict(zip(columns, row))
        
        active = row_dict["active"] if row_dict["active"] is not None else 0
        idle = row_dict["idle"] if row_dict["idle"] is not None else 0
        total = row_dict["total"] if row_dict["total"] is not None else 0
        
        return JSONResponse({
            "active": int(active),
            "idle": int(idle),
            "total": int(total),
            "timestamp": time.time()
        })

async def health_check(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "healthy"})

@mcp.tool
def db_sql2019_monitor_sessions() -> str:
    """
    Get the link to the real-time database sessions monitor dashboard.
    
    Returns:
        A message containing the URL to the sessions monitor dashboard.
    """
    port = os.environ.get("MCP_PORT", "8000")
    host = os.environ.get("MCP_HOST", "localhost")
    if host == "0.0.0.0":
        host = "localhost"
        
    url = f"http://{host}:{port}/sessions-monitor"
    return f"Monitor available at: {url}"


def main() -> None:
    _configure_fastmcp_runtime()

    transport = os.environ.get("MCP_TRANSPORT", "http").strip().lower()
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    # Default to 8085 to avoid common 8000 conflicts
    port = _env_int("MCP_PORT", 8085)
    
    stateless = _env_bool("MCP_STATELESS", False)
    json_resp = _env_bool("MCP_JSON_RESPONSE", False)
    
    # SSL Configuration for HTTPS
    ssl_cert = os.environ.get("MCP_SSL_CERT")
    ssl_key = os.environ.get("MCP_SSL_KEY")
    
    if transport in {"http", "sse"}:
        run_kwargs = {
            "transport": transport,
            "host": host,
            "port": port,
            "stateless_http": stateless,
            "json_response": json_resp,
            "middleware": [
                Middleware(APIKeyMiddleware),
                Middleware(BrowserFriendlyMiddleware)
            ]
        }
        
        if ssl_cert and ssl_key:
            run_kwargs["ssl_certfile"] = ssl_cert
            run_kwargs["ssl_keyfile"] = ssl_key
            logger.info(f"Starting MCP server with HTTPS enabled using cert: {ssl_cert}")
        
        mcp.run(**run_kwargs)
    elif transport == "stdio":
        # Hybrid mode: Start HTTP server in background for UI/Custom Routes
        def run_http_background():
            logger.info(f"Starting background HTTP server for UI on port {port}")
            try:
                # Suppress Uvicorn logs to prevent stdout pollution (which breaks stdio transport)
                # Uvicorn defaults to INFO and might print to stdout
                logging.getLogger("uvicorn").setLevel(logging.WARNING)
                logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
                logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
                
                # Create a new event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                # Run the MCP's underlying web app directly with uvicorn
                # This avoids calling mcp.run() twice, which can cause state conflicts.
                # mcp.http_app() contains all routes: MCP protocol (SSE) and custom UI.
                
                # Create app with middleware manually for background server
                app = mcp.http_app()
                app.add_middleware(APIKeyMiddleware)
                app.add_middleware(BrowserFriendlyMiddleware)
                
                uvicorn.run(
                    app,
                    host=host,
                    port=port,
                    log_level="warning"
                )
            except Exception as e:
                logger.error(f"Background HTTP server failed: {e}")

        # Start HTTP server thread
        http_thread = threading.Thread(target=run_http_background, daemon=True)
        http_thread.start()
        
        # Give it a moment to initialize
        time.sleep(1)
        
        # Run stdio transport in main thread
        mcp.run(transport="stdio")
    else:
        raise ValueError(f"Unknown transport: {transport}. Supported transports: http, sse, stdio")


if __name__ == "__main__":
    main()

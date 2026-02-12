# SQL Server MCP Server

A powerful Model Context Protocol (MCP) server for **SQL Server 2019+** database administration, designed for AI agents like **VS Code**, **Claude**, and **Codex**.

This server exposes a suite of DBA-grade tools to inspect schemas, analyze performance, check security, and troubleshoot issues—all through a safe, controlled interface.

## 🚀 Features

- **Deep Inspection**: Discover schemas, tables, indexes, and their sizes.
- **Logical Modeling**: Analyze foreign keys and table relationships to understand the data model.
- **Performance Analysis**: Detect fragmentation, missing indexes, and buffer pool health.
- **Security Audits**: Analyze database privileges, orphaned users, and authentication modes.
- **Safe Execution**: Read-only by default, with optional write capabilities for specific maintenance tasks.
- **Multiple Transports**: Supports `sse` (Server-Sent Events) and `stdio`. HTTPS is supported via SSL configuration variables.
- **Secure Authentication**: Built-in support for **Azure AD (Microsoft Entra ID)** and standard token auth.
- **HTTPS Support**: Native SSL/TLS support for secure remote connections.
- **SSH Tunneling**: Built-in support for connecting via SSH bastion hosts.
- **Python 3.13**: Built on the latest Python runtime for improved performance and security.
- **Broad Compatibility**: Fully tested with **SQL Server 2019** and **SQL Server 2022**.

---

## 📦 Installation & Usage

### ⚡ Quickstart: Docker + n8n

Spin up a complete environment with **SQL Server**, **MCP Server**, and **n8n** in one command.

1.  **Download the Compose File**:
    Save [docker-compose-n8n.yml](docker-compose-n8n.yml) to your project directory.

2.  **Start the Stack**:
    ```bash
    docker compose -f docker-compose-n8n.yml up -d
    ```

3.  **Connect n8n**:
    *   Open n8n at [http://localhost:5678](http://localhost:5678).
    *   Add an **AI Agent** node.
    *   Add an **MCP Tool** to the agent.
    *   Set **Source** to `Remote (SSE)`.
    *   Set **URL** to `http://mcp-sqlserver:8000/sse` (Note: use container name).
    *   **Execute!** You can now ask the AI agent to "count rows in tables" or "check database stats".

---

For detailed deployment instructions on **Azure Container Apps**, **AWS ECS**, and **Docker**, please see our **[Deployment Guide](DEPLOYMENT.md)**.

> **Note**: For details on the required database privileges for read-only and read-write modes, see the **[Database Privileges](DEPLOYMENT.md#database-privileges)** section in the Deployment Guide.

### Option 1: VS Code & Claude Desktop

This section explains how to configure the server for Claude Desktop and VS Code extensions.

1.  **Claude Desktop Integration**:
    Edit your `claude_desktop_config.json` (usually in `~/Library/Application Support/Claude/` on macOS or `%APPDATA%\Claude\` on Windows).

2.  **VS Code Extension Configuration**:
    For extensions like Cline or Roo Code, go to the extension settings in VS Code and look for "MCP Servers" configuration.

You can use either of the following methods to configure the server.

#### Method A: Using Docker (Recommended)
This method ensures you have all dependencies pre-installed. Note the `-i` flag (interactive) and `MCP_TRANSPORT=stdio`.

```json
{
  "mcpServers": {
    "sqlserver": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e", "SQL_SERVER=host.docker.internal",
        "-e", "SQL_USER=sa",
        "-e", "SQL_PASSWORD=YourPassword123",
        "-e", "SQL_DATABASE=master",
        "-e", "MCP_TRANSPORT=stdio",
        "harryvaldez/mcp-sql-server:latest"
      ]
    }
  }
}
```

#### Method B: Using Local Python (uv)
If you prefer running the Python code directly and have `uv` installed:

```json
{
  "mcpServers": {
    "sqlserver": {
      "command": "uv",
      "args": ["run", "mcp-sql-server"],
      "env": {
        "SQL_SERVER": "localhost",
        "SQL_USER": "sa",
        "SQL_PASSWORD": "YourPassword123",
        "SQL_DATABASE": "master"
      }
    }
  }
}
```

### Option 2: Docker (Recommended)

The Docker image is available on Docker Hub at `harryvaldez/mcp-sql-server`.

```bash
# 1. Pull the image
docker pull harryvaldez/mcp-sql-server:latest

# 2. Run in HTTP Mode (SSE)
docker run -d \
  --name mcp-sqlserver-http \
  -e SQL_SERVER=host.docker.internal \
  -e SQL_USER=sa \
  -e SQL_PASSWORD=YourPassword123 \
  -e SQL_DATABASE=master \
  -e MCP_TRANSPORT=http \
  -e MCP_ALLOW_WRITE=false \
  -p 8000:8000 \
  harryvaldez/mcp-sql-server:latest

# 3. Run in Write Mode (HTTP - Secure)
docker run -d \
  --name mcp-sqlserver-write \
  -e SQL_SERVER=host.docker.internal \
  -e SQL_USER=sa \
  -e SQL_PASSWORD=YourPassword123 \
  -e SQL_DATABASE=master \
  -e MCP_TRANSPORT=http \
  -e MCP_ALLOW_WRITE=true \
  -e MCP_CONFIRM_WRITE=true \
  # ⚠️ Untested / Not Production Ready
  -e FASTMCP_AUTH_TYPE=azure-ad \
  -e FASTMCP_AZURE_AD_TENANT_ID=... \
  -e FASTMCP_AZURE_AD_CLIENT_ID=... \
  -p 8001:8000 \
  harryvaldez/mcp-sql-server:latest
```

### Option 2b: Docker with SSH Tunneling

To connect to a database behind a bastion host (e.g., in a private subnet), you can mount your SSH key and configure the tunnel variables. Set `ALLOW_SSH_AGENT=true` to enable SSH agent forwarding if your SSH key is loaded in your SSH agent:

```bash
docker run -d \
  --name mcp-sqlserver-ssh \
  -v ~/.ssh/id_rsa:/root/.ssh/id_rsa:ro \
  -e SQL_SERVER=db-internal-host \
  -e SQL_USER=sa \
  -e SQL_PASSWORD=YourPassword123 \
  -e SQL_DATABASE=master \
  -e SSH_HOST=bastion.example.com \
  -e SSH_USER=ec2-user \
  -e SSH_PKEY="/root/.ssh/id_rsa" \
  -e ALLOW_SSH_AGENT=true \
  -e MCP_TRANSPORT=http \
  -p 8000:8000 \
  harryvaldez/mcp-sql-server:latest
```

**Using Docker Compose:**
The `docker-compose.yml` is configured to use the public image:
```bash
docker compose up -d
```

### Option 3: Local Python (uv)

```bash
# Set connection variables
export SQL_SERVER=localhost
export SQL_USER=sa
export SQL_PASSWORD=YourPassword123
export SQL_DATABASE=master

# Run in HTTP Mode (SSE)
export MCP_TRANSPORT=http
uv run .

# Run in Write Mode (HTTP)
export MCP_TRANSPORT=http
export MCP_ALLOW_WRITE=true
export MCP_CONFIRM_WRITE=true
export FASTMCP_AUTH_TYPE=azure-ad # ⚠️ Untested / Not Production Ready
# ... set auth vars ...
uv run .
```

### Option 4: Node.js (npx)

```bash
# Set connection variables
export SQL_SERVER=localhost
export SQL_USER=sa
export SQL_PASSWORD=YourPassword123
export SQL_DATABASE=master

# Run in HTTP Mode (SSE)
export MCP_TRANSPORT=http
npx .

# Run in Write Mode (HTTP)
export MCP_TRANSPORT=http
export MCP_ALLOW_WRITE=true
export MCP_CONFIRM_WRITE=true
export FASTMCP_AUTH_TYPE=azure-ad # ⚠️ Untested / Not Production Ready
# ... set auth vars ...
npx .
```

### Option 5: n8n Integration (AI Agent)

You can use this MCP server as a "Remote Tool" in n8n to empower AI agents with database capabilities.

1.  **Download Workflow**: Get the [n8n-mcp-workflow.json](n8n-mcp-workflow.json).
2.  **Import to n8n**:
    *   Open your n8n dashboard.
    *   Go to **Workflows** -> **Import from File**.
    *   Select `n8n-mcp-workflow.json`.
3.  **Configure Credentials**:
    *   Open the **AI Agent** node.
    *   Set your **OpenAI** credentials.
    *   If your MCP server is protected, open the **SQL Server MCP** node and update the `Authorization` header in "Header Parameters".
4.  **Run**: Click "Execute Workflow" to test the connection (defaults to `db_sql2019_ping`).

### Troubleshooting n8n Connection

If n8n (Cloud) cannot connect to your local MCP server:
1.  **Public Accessibility**: Your server must be reachable from the internet. `localhost` or local names won't work from n8n Cloud.
2.  **Firewall**: Ensure your firewall allows inbound traffic on the MCP port (default 8085).
    ```powershell
    # Allow port 8085 on Windows
    netsh advfirewall firewall add rule name="MCP Server 8085" dir=in action=allow protocol=TCP localport=8085
    ```
3.  **Quick Fix (ngrok)**: Use [ngrok](https://ngrok.com/) to tunnel your local server to the internet.
    ```bash
    ngrok http 8085
    ```
    Then use the generated `https://....ngrok-free.app/sse` URL in n8n.

---

## ⚙️ Configuration

The server is configured entirely via environment variables.

### Performance Limits
To prevent the MCP server from becoming unresponsive or overloading the database, the following safeguards are in place:

*   **Statement Timeout**: Queries are automatically cancelled if they run longer than **120 seconds** (default).
    *   **Behavior**: The MCP tool will return an error: `Query execution timed out.`
    *   **Configuration**: Set `MCP_STATEMENT_TIMEOUT_MS` (milliseconds) to adjust this limit.
*   **Max Rows**: Queries returning large result sets are truncated to **500 rows** (default).
    *   **Configuration**: Set `MCP_MAX_ROWS` to adjust.

### Core Connection
| Variable | Description | Default |
|----------|-------------|---------|
| `SQL_SERVER` | SQL Server hostname or IP | *Required* |
| `SQL_PORT` | SQL Server port | `1433` |
| `SQL_USER` | SQL User | *Required* |
| `SQL_PASSWORD` | SQL Password | *Required* |
| `SQL_DATABASE` | Target Database | *Required* |
| `SQL_DRIVER` | ODBC Driver name | `ODBC Driver 17 for SQL Server` |
| `MCP_HOST` | Host to bind the server to | `0.0.0.0` |
| `MCP_PORT` | Port to listen on (8000 for Docker, 8085 for local) | `8085` |
| `MCP_TRANSPORT` | Transport mode: `sse`, `http` (uses SSE), or `stdio` | `http` |
| `MCP_ALLOW_WRITE` | Enable write tools (`db_sql2019_create_db_user`, etc.) | `false` |
| `MCP_CONFIRM_WRITE` | **Required if ALLOW_WRITE=true**. Safety latch to confirm write mode. | `false` |
| `MCP_STATEMENT_TIMEOUT_MS` | Max execution time per query in milliseconds | `120000` (2 minutes) |
| `MCP_SKIP_CONFIRMATION` | Set to "true" to skip startup confirmation dialog (Windows) | `false` |
| `MCP_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `MCP_LOG_FILE` | Optional path to write logs to a file | *None* |

### Security Constraints
If `MCP_ALLOW_WRITE=true`, the server enforces the following additional security checks at startup:
1. **Explicit Confirmation**: You must set `MCP_CONFIRM_WRITE=true`.
2. **Mandatory Authentication (HTTP)**: If using `http` transport, you must configure `FASTMCP_AUTH_TYPE` (e.g., `azure-ad`, `oidc`, `jwt`). Write mode over unauthenticated HTTP is prohibited.

> ⚠️ **Warning: Authentication Verification Pending**
> **Token Auth** and **Azure AD Auth** have not been tested and are **not production-ready**.
> While the implementation follows standard FastMCP patterns, end-to-end verification is pending.
> See [Testing & Validation](#testing--validation) for current status.

### 🔐 Authentication & OAuth2

The server supports several authentication modes via `FASTMCP_AUTH_TYPE`.

#### 1. Generic OAuth2 Proxy
Bridge MCP dynamic registration with traditional OAuth2 providers.
Set `FASTMCP_AUTH_TYPE=oauth2`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_OAUTH_AUTHORIZE_URL` | Provider's authorization endpoint |
| `FASTMCP_OAUTH_TOKEN_URL` | Provider's token endpoint |
| `FASTMCP_OAUTH_CLIENT_ID` | Your registered client ID |
| `FASTMCP_OAUTH_CLIENT_SECRET` | Your registered client secret |
| `FASTMCP_OAUTH_BASE_URL` | Public URL of this MCP server |
| `FASTMCP_OAUTH_JWKS_URI` | Provider's JWKS endpoint (for token verification) |
| `FASTMCP_OAUTH_ISSUER` | Expected token issuer |
| `FASTMCP_OAUTH_AUDIENCE` | (Optional) Expected token audience |

#### 2. GitHub / Google (Managed)
Pre-configured OAuth2 providers for simplified setup.
Set `FASTMCP_AUTH_TYPE=github` or `google`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_GITHUB_CLIENT_ID` | GitHub App/OAuth Client ID |
| `FASTMCP_GITHUB_CLIENT_SECRET` | GitHub Client Secret |
| `FASTMCP_GITHUB_BASE_URL` | Public URL of this MCP server |
| `FASTMCP_GOOGLE_CLIENT_ID` | Google OAuth Client ID |
| `FASTMCP_GOOGLE_CLIENT_SECRET` | Google Client Secret |
| `FASTMCP_GOOGLE_BASE_URL` | Public URL of this MCP server |

#### 3. Azure AD (Microsoft Entra ID)
Simplified configuration for Azure AD.
Set `FASTMCP_AUTH_TYPE=azure-ad`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_AZURE_AD_TENANT_ID` | Your Azure Tenant ID |
| `FASTMCP_AZURE_AD_CLIENT_ID` | Your Azure Client ID |
| `FASTMCP_AZURE_AD_CLIENT_SECRET` | (Optional) Client secret for OIDC Proxy mode |
| `FASTMCP_AZURE_AD_BASE_URL` | (Optional) Base URL for OIDC Proxy mode |

#### 4. OpenID Connect (OIDC) Proxy
Standard OIDC flow with discovery.
Set `FASTMCP_AUTH_TYPE=oidc`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_OIDC_CONFIG_URL` | OIDC well-known configuration URL |
| `FASTMCP_OIDC_CLIENT_ID` | OIDC Client ID |
| `FASTMCP_OIDC_CLIENT_SECRET` | OIDC Client Secret |
| `FASTMCP_OIDC_BASE_URL` | Public URL of this MCP server |

#### 5. Pure JWT Verification
Validate tokens signed by known issuers (Resource Server mode).
Set `FASTMCP_AUTH_TYPE=jwt`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_JWT_JWKS_URI` | Provider's JWKS endpoint |
| `FASTMCP_JWT_ISSUER` | Expected token issuer |
| `FASTMCP_JWT_AUDIENCE` | (Optional) Expected token audience |

#### 6. API Key (Static Token)
Simple Bearer token authentication. Ideal for machine-to-machine communication (e.g., n8n, internal services).
Set `FASTMCP_AUTH_TYPE=apikey`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_API_KEY` | The secret key clients must provide in the `Authorization: Bearer <key>` header. |

#### 7. n8n Integration (AI Agent & HTTP Request)
The server is fully compatible with n8n workflows.

**Using the MCP Client Tool (AI Agent):**
1. Run the server with `FASTMCP_AUTH_TYPE=apikey`.
2. In n8n, add an **AI Agent** node.
3. Add the **MCP Tool** to the agent.
4. Set **Source** to `Remote (SSE)`.
5. Set **URL** to `http://<your-ip>:8000/mcp`.
6. Add a header: `Authorization: Bearer <your-api-key>`.

**Using the HTTP Request Node:**
1. Run the server with `FASTMCP_AUTH_TYPE=github` (or another OAuth2 provider).
2. Create an **OAuth2 API** credential in n8n.
3. Use the **HTTP Request** node with that credential to call tools via JSON-RPC.

### HTTPS / SSL
To enable HTTPS, provide both the certificate and key files.

| Variable | Description |
|----------|-------------|
| `MCP_SSL_CERT` | Path to SSL certificate file (`.crt` or `.pem`) |
| `MCP_SSL_KEY` | Path to SSL private key file (`.key`) |

### SSH Tunneling
To access a database behind a bastion host, configure the following SSH variables. The server will automatically establish a secure tunnel.

| Variable | Description | Default |
|----------|-------------|---------|
| `SSH_HOST` | Bastion/Jump host address | *None* |
| `SSH_USER` | SSH username | *None* |
| `SSH_PASSWORD` | SSH password (optional) | *None* |
| `SSH_PKEY` | Path to private key file (optional) | *None* |
| `SSH_PORT` | SSH port | `22` |
| `ALLOW_SSH_AGENT` | Enable SSH agent forwarding (`true`, `1`, `yes`, `on`) | `false` |

> **Note**: When SSH is enabled, the `SQL_SERVER` should point to the database host as seen from the *bastion* (e.g., internal IP or RDS endpoint).

---

## 🔒 Logging & Security

This server implements strict security practices for logging:

- **Sanitized INFO Logs**: High-level operations (like `db_sql2019_run_query` and `db_sql2019_explain_query`) are logged at `INFO` level, but **raw SQL queries and parameters are never included** to prevent sensitive data leaks.
- **Fingerprinting**: Instead of raw SQL, we log SHA-256 fingerprints (`sql_sha256`, `params_sha256`) to allow correlation and debugging without exposing data.
- **Debug Mode**: Raw SQL and parameters are only logged when `MCP_LOG_LEVEL=DEBUG` is explicitly set, and even then, sensitive parameters are hashed where possible.
- **Safe Defaults**: By default, the server runs in `INFO` mode, ensuring production logs are safe.

---

## 🛠️ Tools Reference

### 🏥 Health & Info
- `db_sql2019_ping()`: Simple health check.
- `db_sql2019_server_info()`: Get database version, current user, and connection details.
- `db_sql2019_db_stats(database: str = None)`: Database-level statistics.
- `db_sql2019_server_info_mcp()`: Get internal MCP server status and version.

### 🔍 Schema Discovery
- `db_sql2019_list_objects`: **(Consolidated Tool)** Unified tool to list databases, schemas, tables, views, indexes, functions, and stored procedures.
    - **Signature**: `db_sql2019_list_objects(object_type: str, schema: str = None, name_pattern: str = None, order_by: str = None, limit: int = 50)`
    - **Common Use Cases**:
        - **Table Sizes**: `object_type='table', order_by='size'`
        - **Row Counts**: `object_type='table', order_by='rows'`
        - **Find Procedure**: `object_type='procedure', name_pattern='%my_proc%'`
- `db_sql2019_describe_table(schema: str, table: str)`: Get detailed column and index info for a table.
- `db_sql2019_analyze_logical_data_model(schema: str = "dbo")`: **(Interactive)** Generates a comprehensive HTML report with a **Mermaid.js Entity Relationship Diagram (ERD)**, a **Health Score** (0-100), and detailed findings on normalization, missing keys, and naming conventions. The tool returns a URL to view the report in your browser.

### ⚡ Performance & Tuning
- `db_sql2019_analyze_table_health(schema: str = None, min_size_mb: int = 50, profile: str = "oltp")`: **(Power Tool)** Comprehensive health check for outdated statistics, heap tables, and size.
- `db_sql2019_check_fragmentation(limit: int = 50)`: Identifies fragmented indexes and provides `REBUILD`/`REORGANIZE` commands.
- `db_sql2019_analyze_indexes(schema: str = None, limit: int = 50)`: Identify unused or missing indexes.
- `db_sql2019_explain_query(sql: str, analyze: bool = False, output_format: str = "xml")`: Get the XML execution plan for a query.

### 🕵️ Session & Security
- `db_sql2019_monitor_sessions()`: Real-time session monitoring data for the UI dashboard.
- `db_sql2019_analyze_sessions(include_idle: bool = True)`: Detailed session analysis using `sys.dm_exec_sessions`.
- `db_sql2019_db_sec_perf_metrics(profile: str = "oltp")`: Comprehensive security and performance audit (Orphaned Users, PLE, Buffer Cache Hit Ratio).
- `db_sql2019_get_db_parameters(pattern: str = None)`: Retrieve database configuration parameters (sys.configurations).

### 🔧 Maintenance (Requires `MCP_ALLOW_WRITE=true`)
- `db_sql2019_create_db_user(username: str, password: str, privileges: str = "read", database: str | None = None)`: Create a new SQL Login and User.
- `db_sql2019_drop_db_user(username: str)`: Drop a Login and User.
- `db_sql2019_kill_session(session_id: int)`: Terminate a specific session ID (KILL).
- `db_sql2019_run_query(sql: str, params_json: str | None = None, max_rows: int | None = None)`: Execute ad-hoc SQL. `max_rows` defaults to 500 (configurable via `MCP_MAX_ROWS`). Returns up to `max_rows` rows; if truncated, `truncated: true` is set.
- `db_sql2019_create_object(object_type: str, object_name: str, schema: str = None, parameters: dict = None)`: Create database objects (table, view, index, function, etc.).
- `db_sql2019_alter_object(object_type: str, object_name: str, operation: str, schema: str = None, parameters: dict = None)`: Modify database objects.
- `db_sql2019_drop_object(object_type: str, object_name: str, schema: str = None, parameters: dict = None)`: Drop database objects.

---

## 📊 Session Monitor & Web UI
 
 The server includes built-in, real-time web interfaces for monitoring and analysis. These interfaces run on a background HTTP server, even when using the `stdio` transport (Hybrid Mode).
 
 **Default Port**: `8085` (to avoid conflicts with other local services). Configurable via `MCP_PORT`.
 
 ### 1. Real-time Session Monitor
 **Access**: `http://localhost:8085/sessions-monitor`
 
 **Features**:
 - **Real-time Graph**: Visualizes active vs. idle sessions over time.
 - **Auto-Refresh**: Updates every 5 seconds without page reload.
 - **Session Stats**: Instant view of Active, Idle, and Total connections.
 
 ### 2. Logical Data Model Report
 Generated on-demand via the `db_sql2019_analyze_logical_data_model` tool.
 
 **Access**: `http://localhost:8085/data-model-analysis?id=<UUID>`
 
 **Features**:
 - **Interactive ERD**: Zoomable Mermaid.js diagram of your schema.
 - **Health Score**: Automated grading of your schema design.
 - **Issues List**: Detailed breakdown of missing keys, normalization risks, and naming violations.
 
 ---

## 🛠️ Usage Examples

Here are some real-world examples of using the tools via an MCP client.

### 1. Check MCP Server Info
**Prompt:** `using sqlserver, call db_sql2019_server_info_mcp() and display results`

**Result:**
```json
{
  "name": "SQL Server MCP Server",
  "version": "1.0.0",
  "status": "healthy",
  "transport": "http",
  "database": "master"
}
```

### 2. Check Database Connection Info
**Prompt:** `using sqlserver, call db_sql2019_server_info() and display results`

**Result:**
```json
{
  "product_version": "Microsoft SQL Server 2019 (RTM-CU12) ...",
  "edition": "Developer Edition (64-bit)",
  "database": "master",
  "current_user": "sa",
  "auth_scheme": "SQL"
}
```

### 3. Analyze Table Health (Power Tool)
**Prompt:** `using sqlserver, call db_sql2019_analyze_table_health(schema='Sales', profile='oltp') and display results`

**Result:**
```json
{
  "outdated_statistics": [
    {
      "table": "SalesOrderHeader",
      "stat_name": "_WA_Sys_00000001_12345",
      "last_updated": "2024-01-01T12:00:00",
      "mod_percent": 25.5
    }
  ],
  "heap_tables": [
    {
      "table": "StagingOrders",
      "rows": 50000
    }
  ],
  "note": "For fragmentation details, use db_sql2019_check_fragmentation()."
}
```

### 4. Performance Analysis: Fragmentation
**Prompt:** `using sqlserver, call db_sql2019_check_fragmentation() and display results`

**Result:**
```json
[
  {
    "schema": "Sales",
    "object_name": "SalesOrderDetail",
    "index_name": "PK_SalesOrderDetail_SalesOrderID_SalesOrderDetailID",
    "fragmentation_percent": 45.2,
    "maintenance_cmd": "ALTER INDEX [PK_SalesOrderDetail_SalesOrderID_SalesOrderDetailID] ON [Sales].[SalesOrderDetail] REBUILD"
  }
]
```

### 5. Security Audit
**Prompt:** `using sqlserver, call db_sql2019_db_sec_perf_metrics() and display results`

**Result:**
```json
{
  "security": [
    "Found 1 orphaned users: old_app_user",
    "Server is in Mixed Authentication Mode (SQL Auth + Windows Auth)."
  ],
  "performance": {
    "page_life_expectancy": 450,
    "buffer_cache_hit_ratio": 99.95
  }
}
```

### 6. Logical Data Model Analysis
**Prompt:** `using sqlserver, call db_sql2019_analyze_logical_data_model(schema='Sales'). Review the resulting logical data model.`

**Result (Summarized):**
The analysis of the `Sales` schema reveals...
*   **Total Entities Analyzed:** 15
*   **Missing Primary Keys:** 2 tables (`SalesLog`, `ErrorLog`)
*   **Missing Foreign Keys:** 0
*   **Health Score:** 92/100

---

## 🧪 Testing & Validation

This project has been rigorously tested against **SQL Server 2019**.

### Test Results
- **Deployment**: Docker, `uv`, `npx` (All Passed)
- **Protocol**: SSE (HTTP/HTTPS), Stdio (All Passed)
- **Database**: SQL Server 2019 (All Tools Verified)
- **Auth**: Token Auth, Azure AD Auth (To be verified)

---

## ❓ FAQ & Troubleshooting

### Frequently Asked Questions

**Q: Why is everything prefixed with `db_sql2019_`?**
A: This server is explicitly versioned for SQL Server 2019+ compatibility. This avoids naming conflicts if you run multiple MCP servers for different database versions.

**Q: Can I use this with Azure SQL Database?**
A: Yes! It works with Azure SQL Database and Azure SQL Managed Instance.

**Q: How do I enable write operations?**
A: By default, the server is read-only. To enable write tools (like creating users or killing sessions), set the environment variable `MCP_ALLOW_WRITE=true`.

### Common Issues

**Driver Not Found**
Ensure `ODBC Driver 17 for SQL Server` (or 18) is installed. The Docker image includes this by default.

**Connection Timeout**
Check your firewall settings (port 1433).

---

## 📬 Contact & Support

For comments, issues, or feature enhancements, please contact the maintainer or submit an issue to the repository:

- **Repository**: https://github.com/harryvaldez/mcp-sql-server
- **Maintainer**: Harry Valdez

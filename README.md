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
- **Python 3.11**: Built on a stable Python runtime for improved compatibility.
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
    *   Set **URL** to `http://mcp-sqlserver:8085/sse` (Note: use container name and port 8085).
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
        "--env-file", ".env",
        "harryvaldez/mcp_sqlserver:latest"
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
        "DB_SERVER": "localhost",
        "DB_USER": "sa",
        "DB_PASSWORD": "YourPassword123",
        "DB_NAME": "master",
        "DB_DRIVER": "ODBC Driver 17 for SQL Server"
      }
    }
  }
}
```

### Option 2: Docker (Recommended)

The Docker image is available on Docker Hub at `harryvaldez/mcp_sqlserver`.

```bash
# 1. Pull the image
docker pull harryvaldez/mcp_sqlserver:latest

# 2. Run in HTTP Mode (SSE)
docker run -d \
  --name mcp-sqlserver-http \
  --env-file .env \
  -p 8085:8000 \
  harryvaldez/mcp_sqlserver:latest

# 3. Run in Write Mode (HTTP - Secure)
docker run -d \
  --name mcp-sqlserver-write \
  --env-file .env \
  -e MCP_ALLOW_WRITE=true \
  -e MCP_CONFIRM_WRITE=true \
  # ⚠️ Untested / Not Production Ready
  -e FASTMCP_AUTH_TYPE=azure-ad \
  -e FASTMCP_AZURE_AD_TENANT_ID=... \
  -e FASTMCP_AZURE_AD_CLIENT_ID=... \
  -p 8001:8000 \
  harryvaldez/mcp_sqlserver:latest
```

### Option 2b: Docker with SSH Tunneling

To connect to a database behind a bastion host (e.g., in a private subnet), you can mount your SSH key and configure the tunnel variables. Set `ALLOW_SSH_AGENT=true` to enable SSH agent forwarding if your SSH key is loaded in your SSH agent:

```bash
docker run -d \
  --name mcp-sqlserver-ssh \
  --env-file .env \
  -v ~/.ssh/id_rsa:/root/.ssh/id_rsa:ro \
  -e SSH_HOST=bastion.example.com \
  -e SSH_USER=ec2-user \
  -e SSH_PKEY="/root/.ssh/id_rsa" \
  -e ALLOW_SSH_AGENT=true \
  -p 8000:8000 \
  harryvaldez/mcp_sqlserver:latest
```

**Using Docker Compose:**
The `docker-compose.yml` is configured to use the public image:
```bash
docker compose up -d
```

### Option 3: Local Python (uv)

> **Note:** `SQL_*` aliases (e.g., `SQL_SERVER`) are also supported for backward compatibility.

```bash
# Set connection variables
export DB_SERVER=localhost
export DB_USER=sa
export DB_PASSWORD=YourPassword123
export DB_NAME=master

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
export DB_SERVER=localhost
export DB_USER=sa
export DB_PASSWORD=YourPassword123
export DB_NAME=master

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

### ⚡ Testing & Validation

This project includes a comprehensive test suite covering **Unit**, **Integration**, **Stress**, and **Blackbox** tests.

1.  **Prerequisites**:
    *   Docker (for provisioning the temporary SQL Server 2019 container)
    *   Python 3.10+
    *   `pip install -r tests/requirements-test.txt`

2.  **Run Full Test Cycle**:
    ```bash
    # 1. Provision & Populate Test Database
    python tests/setup_sql_server.py
    
    # 2. Run Comprehensive Test Suite
    pytest -v tests/
    ```

3.  **Verification Coverage**:
    *   ✅ **Unit Tests**: Core connection logic and helper functions, mocked to run without a live database.
    *   ✅ **Integration Tests**: End-to-end verification of all 25+ MCP tools against a live SQL Server 2019 instance.
    *   ✅ **Stress Tests**: Verifies stability under concurrent load (50+ parallel requests).
    *   ✅ **Blackbox Tests**: Validates the MCP protocol implementation and tool discovery.

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
| `DB_SERVER` | SQL Server hostname or IP (also `SQL_SERVER`) | *Required* |
| `DB_PORT` | SQL Server port (also `SQL_PORT`) | `1433` |
| `DB_USER` | SQL User (also `SQL_USER`) | *Required* |
| `DB_PASSWORD` | SQL Password (also `SQL_PASSWORD`) | *Required* |
| `DB_NAME` | Target Database (also `SQL_DATABASE`) | *Required* |
| `DB_DRIVER` | ODBC Driver name (also `SQL_DRIVER`) | `ODBC Driver 17 for SQL Server` |
| `DB_ENCRYPT` | Enable encryption (`yes`/`no`) | `no` |
| `DB_TRUST_CERT` | Trust server certificate (`yes`/`no`) | `yes` |
| `MCP_HOST` | Host to bind the server to | `0.0.0.0` |
| `MCP_PORT` | Internal container port. The host port is typically mapped to this (e.g., 8085 -> 8000). | `8000` (Docker default) |
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

### 🏥 Health & Info (Always Available)
- `db_sql2019_server_info_mcp()`: Get comprehensive MCP server and database connection information (server details, database version, user, connection details, and MCP configuration).

### 🔍 Schema Discovery (Always Available)
- `db_sql2019_list_objects(object_type: str, schema: str = None, name_pattern: str = None, order_by: str = None, limit: int = 50)`: **(Consolidated Tool)** Unified tool to list databases, schemas, tables, views, indexes, functions, and stored procedures.
    - **Supported object_type values**: 'database', 'schema', 'table', 'view', 'index', 'function', 'procedure', 'trigger'
    - **Common Use Cases**:
        - **Table Sizes**: `object_type='table', order_by='size'`
        - **Row Counts**: `object_type='table', order_by='rows'`
        - **Find Objects**: `object_type='procedure', name_pattern='%my_proc%'`
- `db_sql2019_analyze_logical_data_model(database_name: str, schema: str = "dbo", include_views: bool = False, max_entities: int = None, include_attributes: bool = True)`: **(Interactive)** Generates a comprehensive HTML report with a **Mermaid.js Entity Relationship Diagram (ERD)**, a **Health Score** (0-100), and detailed findings on normalization, missing keys, and naming conventions. The tool returns a URL to view the report in your browser.

### ⚡ Performance & Tuning (Always Available)
- `db_sql2019_analyze_table_health(database_name: str, schema: str, table_name: str)`: **(Enhanced Power Tool)** Comprehensive health check for a specific table, including size analysis, index fragmentation, foreign key dependencies, statistics health, **missing constraint analysis** (foreign keys, check constraints, defaults, primary keys), and **enhanced index recommendations** (missing FK indexes, disabled indexes, unused large indexes, redundant indexes). Returns actionable tuning recommendations with severity levels.
- `db_sql2019_show_top_queries(database_name: str)`: **(Query Store Analysis)** Analyzes Query Store data to identify top problematic queries including long-running queries, regressed queries (performance degradation), high CPU consumption, high I/O queries, and frequently executed poor-performing queries. Provides specific recommendations for each issue with actionable steps.
- `db_sql2019_explain_query(sql: str, analyze: bool = False, output_format: str = "xml")`: Get the XML execution plan for a query.

### 🕵️ Session & Security (Always Available)
- `db_sql2019_db_sec_perf_metrics(profile: str = "oltp")`: Comprehensive security and performance audit with tuning recommendations (Orphaned Users, PLE, Buffer Cache Hit Ratio, authentication mode, sysadmin privileges, memory configuration, parallelism settings).

### 🔧 Maintenance (Requires `MCP_ALLOW_WRITE=true`)
- `db_sql2019_run_query(sql: str, params_json: str = None, max_rows: int = None)`: Execute ad-hoc SQL queries. **Read-Only Mode**: Enforces read-only SQL (blocks INSERT/UPDATE/DELETE). **Write Mode**: Allows all SQL operations. `max_rows` defaults to 500 (configurable via `MCP_MAX_ROWS`). Returns up to `max_rows` rows; if truncated, `truncated: true` is set.
- `db_sql2019_create_db_user(username: str, password: str, privileges: str = "read", database: str = None)`: Create a new SQL Login and User with specified privileges.
- `db_sql2019_drop_db_user(username: str)`: Drop a SQL Login and User.
- `db_sql2019_kill_session(session_id: int)`: Terminate a specific database session by SPID.
- `db_sql2019_create_object(object_type: str, object_name: str, schema: str = None, parameters: dict = None)`: Create database objects (table, view, index, function, procedure, trigger).
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
  "server_ip": "localhost",
  "server_port": 8085,
  "allow_write": false,
  "default_max_rows": 500,
  "database": "master",
  "user": "n8n_DBMonitor",
  "server_name": "gisdevsql01",
  "server_addr": "10.125.1.7",
  "version": "Microsoft SQL Server 2019 (RTM-CU32-GDR) (KB5068404) - 15.0.4455.2 (X64) \n\tOct  7 2025 21:10:15 \n\tCopyright (C) 2019 Microsoft Corporation\n\tDeveloper Edition (64-bit) on Windows Server 2019 Datacenter 10.0 <X64> (Build 17763: ) (Hypervisor)\n",
  "product_version": "15.0.4455.2",
  "product_level": "RTM",
  "edition": "Developer Edition (64-bit)"
}
```

### 2. Query Store Performance Analysis
**Prompt:** `using sqlserver_readonly, call db_sql2019_show_top_queries(database='USGISPRO_800') and display results`

**Result:**
```json
{
  "database": "USGISPRO_800",
  "query_store_enabled": true,
  "query_store_config": {
    "state": "READ_WRITE",
    "current_storage_mb": 256,
    "max_storage_mb": 1024,
    "stale_threshold_days": 30,
    "capture_mode": "AUTO"
  },
  "analysis_period": {
    "earliest_data": "2024-02-01T00:00:00",
    "latest_data": "2024-02-18T16:30:00",
    "days_covered": 17
  },
  "long_running_queries": [
    {
      "query_id": 1250,
      "query_text": "SELECT TOP 1000 * FROM large_table lt JOIN other_table ot ON lt.id = ot.foreign_id WHERE lt.status = 'ACTIVE' AND ot.created_date > '2024-01-01'",
      "executions": 2500,
      "avg_duration_ms": 3200.5,
      "avg_cpu_ms": 2100.8,
      "avg_logical_io_reads": 75000,
      "object_name": "large_table"
    },
    {
      "query_id": 892,
      "query_text": "SELECT * FROM user_sessions us LEFT JOIN user_profiles up ON us.user_id = up.user_id WHERE us.last_activity > DATEADD(day, -30, GETDATE())",
      "executions": 1800,
      "avg_duration_ms": 2800.2,
      "avg_cpu_ms": 1850.3,
      "avg_logical_io_reads": 62000,
      "object_name": "user_sessions"
    }
  ],
  "regressed_queries": [
    {
      "query_id": 445,
      "query_text": "SELECT COUNT(*) FROM orders o INNER JOIN customers c ON o.customer_id = c.customer_id WHERE o.order_date >= @start_date",
      "recent_executions": 450,
      "recent_avg_duration_ms": 1850.0,
      "older_avg_duration_ms": 850.0,
      "regression_percent": 117.6,
      "recent_avg_cpu_ms": 1200.5
    }
  ],
  "high_cpu_queries": [
    {
      "query_id": 678,
      "query_text": "SELECT DISTINCT p.product_name FROM products p CROSS APPLY (SELECT TOP 10 * FROM product_reviews pr WHERE pr.product_id = p.product_id ORDER BY pr.rating DESC) pr WHERE p.category_id IN (SELECT category_id FROM categories WHERE parent_category_id IS NULL)",
      "executions": 320,
      "avg_cpu_ms": 850.7,
      "max_cpu_ms": 2100.3,
      "avg_duration_ms": 1200.4,
      "avg_logical_io_reads": 45000
    }
  ],
  "high_io_queries": [
    {
      "query_id": 901,
      "query_text": "SELECT * FROM audit_log al WHERE al.action_timestamp BETWEEN @start_date AND @end_date AND al.user_id = @user_id ORDER BY al.action_timestamp DESC",
      "executions": 890,
      "avg_logical_io_reads": 185000,
      "avg_logical_io_writes": 1200,
      "avg_physical_io_reads": 4500,
      "avg_duration_ms": 950.2,
      "avg_cpu_ms": 650.8
    }
  ],
  "high_execution_queries": [
    {
      "query_id": 234,
      "query_text": "SELECT TOP 1 setting_value FROM system_settings WHERE setting_key = 'CACHE_TIMEOUT'",
      "executions": 15000,
      "avg_duration_ms": 45.2,
      "avg_cpu_ms": 12.8,
      "avg_logical_io_reads": 8
    }
  ],
  "recommendations": [
    {
      "type": "long_running_query",
      "priority": "high",
      "query_id": 1250,
      "issue": "Query with 3200ms average duration executed 2500 times",
      "recommendation": "Analyze execution plan for missing indexes, table scans, or inefficient joins. Consider query optimization or index creation.",
      "potential_actions": [
        "Review execution plan for optimization opportunities",
        "Check for missing indexes on join/filter columns",
        "Consider query parameterization if using literals",
        "Evaluate if query can be rewritten for better performance"
      ]
    },
    {
      "type": "regressed_query",
      "priority": "high",
      "query_id": 445,
      "issue": "Query performance regressed by 117.6% (from 850ms to 1850ms)",
      "recommendation": "Investigate recent plan changes or data/statistics modifications. Check for parameter sniffing issues or stale statistics.",
      "potential_actions": [
        "Compare execution plans between time periods",
        "Update statistics on relevant tables",
        "Check for parameter sniffing issues",
        "Force a better execution plan if regression persists"
      ]
    },
    {
      "type": "high_io_query",
      "priority": "medium",
      "query_id": 901,
      "issue": "Query with high I/O: 185000 logical reads, 4500 physical reads",
      "recommendation": "Optimize I/O patterns by improving index coverage, reducing table scans, or implementing proper indexing strategy.",
      "potential_actions": [
        "Create covering indexes to reduce logical reads",
        "Review execution plan for table/clustered index scans",
        "Consider index defragmentation if fragmentation is high",
        "Optimize WHERE clauses for better selectivity"
      ]
    },
    {
      "type": "frequently_executed_poor_query",
      "priority": "high",
      "query_id": 234,
      "issue": "Frequently executed query (15000 times) with poor performance (45.2ms average)",
      "recommendation": "High-impact query needing immediate optimization. Small improvements here can yield significant overall performance gains.",
      "potential_actions": [
        "Prioritize this query for optimization",
        "Consider query result caching if appropriate",
        "Review application logic for unnecessary executions",
        "Implement proper indexing for this critical query"
      ]
    }
  ],
  "summary": {
    "long_running_queries_count": 2,
    "regressed_queries_count": 1,
    "high_cpu_queries_count": 1,
    "high_io_queries_count": 1,
    "high_execution_queries_count": 1,
    "total_recommendations": 4,
    "high_priority_recommendations": 3,
    "analysis_timestamp": "2024-02-18T16:30:00"
  }
}
```

### 3. Analyze Table Health (Power Tool)
**Prompt:** `using sqlserver, call db_sql2019_analyze_table_health(database_name='USGISPRO_800', schema='dbo', table_name='Account') and display results`

**Result:**
```json
{
  "database": "USGISPRO_800",
  "schema": "dbo",
  "table": "Account",
  "table_size": {
    "schema_name": "dbo",
    "table_name": "Account",
    "row_count": 6398,
    "total_space_mb": "1.46",
    "used_space_mb": "1.23",
    "data_space_mb": "1.19",
    "unused_space_mb": "0.23"
  },
  "indexes": [
    {
      "index_name": "PK_Account",
      "index_type": "CLUSTERED",
      "is_unique": true,
      "is_primary_key": true,
      "fragmentation_percent": 0.77,
      "page_count": 130,
      "index_size_mb": "1.02",
      "index_columns": "AccountID"
    },
    {
      "index_name": "IX_Account_AccountNameStatus",
      "index_type": "NONCLUSTERED",
      "is_unique": false,
      "is_primary_key": false,
      "fragmentation_percent": 77.27,
      "page_count": 22,
      "index_size_mb": "0.17",
      "index_columns": "AccountName, Status"
    }
  ],
  "foreign_keys": {
    "tables_referencing_this": [
      {
        "referencing_schema": "dbo",
        "referencing_table": "AccountModule",
        "fk_name": "FK_AccountModule_Account",
        "referencing_columns": "AccountID",
        "referenced_columns": "AccountID"
      },
      {
        "referencing_schema": "dbo",
        "referencing_table": "AccountLogin",
        "fk_name": "FK_AccountLogin_Account",
        "referencing_columns": "AccountID",
        "referenced_columns": "AccountID"
      }
    ],
    "tables_referenced_by_this": [
      {
        "referenced_schema": "dbo",
        "referenced_table": "Company",
        "fk_name": "FK_Account_Company",
        "referencing_columns": "CompanyID",
        "referenced_columns": "CompanyID"
      },
      {
        "referenced_schema": "dbo",
        "referenced_table": "Account",
        "fk_name": "FK_Account_Account",
        "referencing_columns": "ParentAccountID",
        "referenced_columns": "AccountID"
      }
    ]
  },
  "statistics": [
    {
      "stats_name": "PK_Account",
      "table_name": "Account",
      "last_updated": "2026-01-07T20:41:01.340000",
      "row_count": 3199,
      "rows_sampled": 3199,
      "modification_counter": 0,
      "modification_percent": "0.00"
    },
    {
      "stats_name": "IX_Account_AccountNameStatus",
      "table_name": "Account",
      "last_updated": "2026-01-07T20:41:01.470000",
      "row_count": 3199,
      "rows_sampled": 3199,
      "modification_counter": 0,
      "modification_percent": "0.00"
    }
  ],
  "constraints": {
    "missing_constraints": [
      {
        "type": "missing_foreign_key",
        "column": "CompanyID",
        "potential_reference": "dbo.Company",
        "severity": "medium",
        "recommendation": "Consider adding foreign key constraint to Company table"
      },
      {
        "type": "missing_check_constraint",
        "column": "Status",
        "severity": "low",
        "recommendation": "Consider adding check constraint for Status to enforce valid values"
      }
    ],
    "constraint_analysis": "Found 2 potential constraint issues"
  },
  "index_analysis": {
    "index_issues": [
      {
        "type": "missing_foreign_key_index",
        "column": "CompanyID",
        "severity": "medium",
        "recommendation": "Create index on foreign key column CompanyID to improve join performance"
      },
      {
        "type": "unused_large_index",
        "index": "IX_Account_UnusedField",
        "size_mb": 15.2,
        "updates": 0,
        "severity": "medium",
        "recommendation": "Large unused index IX_Account_UnusedField (15.2 MB) - consider dropping to save space"
      }
    ],
    "analysis_summary": "Found 2 index-related issues"
  },
  "recommendations": [
    {
      "type": "constraint_design",
      "priority": "medium",
      "message": "Column 'CompanyID' may need foreign key constraint to dbo.Company"
    },
    {
      "type": "index_design",
      "priority": "medium",
      "message": "Missing index on foreign key column 'CompanyID' - create to improve join performance"
    },
    {
      "type": "index_design",
      "priority": "medium",
      "message": "Large unused index 'IX_Account_UnusedField' (15.2 MB) - consider dropping to save space"
    }
  ],
  "summary": {
    "total_indexes": 2,
    "total_fk_relationships": 43,
    "total_statistics": 2,
    "recommendation_count": 3,
    "high_priority_issues": 1
  }
}
```

### 4. Performance Analysis: Fragmentation
**Prompt:** `using sqlserver, call db_sql2019_check_fragmentation(database_name='USGISPRO_800') and display results`

**Result:**
```json
{
  "database": "USGISPRO_800",
  "analysis_parameters": {
    "table_filter": "All Tables",
    "schema_filter": "All Schemas",
    "min_fragmentation_percent": 5.0,
    "min_page_count": 100
  },
  "fragmented_indexes": [
    {
      "schema": "dbo",
      "table_name": "datasource_cn5441",
      "index_name": null,
      "index_type": "HEAP",
      "fragmentation_percent": 80.00,
      "page_count": 113,
      "recommended_action": "REBUILD",
      "priority": "High"
    },
    {
      "schema": "dbo",
      "table_name": "AccountAccessAnyZipLevel",
      "index_name": null,
      "index_type": "HEAP",
      "fragmentation_percent": 78.62,
      "page_count": 3359,
      "recommended_action": "REBUILD",
      "priority": "High"
    },
    {
      "schema": "dbo",
      "table_name": "DataHierarchy",
      "index_name": "nc_DataHierarchy_status_pp",
      "index_type": "NONCLUSTERED",
      "fragmentation_percent": 24.70,
      "page_count": 842,
      "recommended_action": "REORGANIZE",
      "maintenance_cmd": "ALTER INDEX [nc_DataHierarchy_status_pp] ON [dbo].[DataHierarchy] REORGANIZE",
      "priority": "Medium"
    }
  ],
  "healthy_indexes": [],
  "recommendations": [
    {
      "priority": "High",
      "type": "maintenance_plan",
      "message": "Found 24 index(es) with >30% fragmentation requiring immediate REBUILD. Schedule maintenance during low-activity period."
    },
    {
      "priority": "Medium",
      "type": "maintenance_plan",
      "message": "Found 58 index(es) with 5-30% fragmentation. Consider REORGANIZE during next maintenance window."
    },
    {
      "priority": "High",
      "type": "index_maintenance",
      "object": "[dbo].[datasource_cn5441].[None]",
      "fragmentation_percent": 80.00,
      "message": "Heap table 'datasource_cn5441' has 80.00% fragmentation. Consider adding a clustered index or running REBUILD.",
      "command": null
    }
  ],
  "summary": {
    "total_indexes_analyzed": 192,
    "high_fragmentation_count": 24,
    "medium_fragmentation_count": 58,
    "low_fragmentation_count": 1,
    "healthy_count": 109,
    "total_pages_analyzed": 2048804
  }
}
```

### 5. Security & Performance Audit
**Prompt:** `using sqlserver, call db_sql2019_db_sec_perf_metrics(profile='oltp') and display results`

**Result:**
```json
{
  "server_info": {
    "version": "Microsoft SQL Server 2019 (RTM-CU32)...",
    "server_name": "gisdevsql01",
    "edition": "Developer Edition (64-bit)",
    "is_clustered": false,
    "is_hadr_enabled": false,
    "online_databases": 8
  },
  "configuration": {
    "max_server_memory_mb": 2147483647,
    "cost_threshold_for_parallelism": 5,
    "max_degree_of_parallelism": 0,
    "config_checks": [
      {
        "setting": "max server memory",
        "current_value": "2147483647 MB",
        "status": "warning",
        "recommendation": "Configure Max Server Memory to leave adequate RAM for OS"
      }
    ]
  },
  "security": {
    "risk_level": "medium",
    "configuration": {
      "authentication_mode": "Mixed Mode (SQL + Windows)",
      "sa_account_disabled": true,
      "sysadmin_count": 2,
      "sysadmin_logins": ["n8n_dbmonitor", "sa"]
    },
    "findings": [
      {
        "severity": "Medium",
        "issue": "3 logins have sysadmin privileges",
        "recommendation": "Review sysadmin role membership and apply principle of least privilege"
      }
    ]
  },
  "performance": {
    "memory": {
      "page_life_expectancy_seconds": 450,
      "ple_status": "healthy",
      "buffer_cache_hit_ratio": 99.95
    },
    "cpu": {
      "top_wait_types": [
        {
          "wait_type": "CXPACKET",
          "signal_wait_percent": 15.2
        }
      ]
    },
    "metrics": {
      "total_connections": 12,
      "active_connections": 3,
      "idle_connections": 9
    }
  },
  "recommendations": {
    "security": [
      {
        "priority": "Medium",
        "category": "Privilege Management",
        "issue": "3 sysadmin logins (too many)",
        "fix": "Review and remove unnecessary sysadmin grants",
        "reason": "Excessive sysadmin access violates least privilege principle"
      }
    ],
    "configuration": [
      {
        "priority": "High",
        "setting": "max server memory (MB)",
        "current_value": 2147483647,
        "recommended_value": "Leave 10-20% of total RAM for OS",
        "reason": "Unlimited memory can cause OS paging"
      },
      {
        "priority": "Medium",
        "setting": "cost threshold for parallelism",
        "current_value": 5,
        "recommended_value": "25-50",
        "reason": "Low threshold causes excessive parallelism on OLTP"
      }
    ],
    "performance": [],
    "priority_high": [
      "Configure Max Server Memory - Currently unlimited"
    ],
    "priority_medium": [
      "Increase Cost Threshold for Parallelism from 5 to 25-50",
      "Review 3 sysadmin logins and reduce privileges"
    ],
    "summary": {
      "total_recommendations": 3,
      "high_priority_count": 1,
      "medium_priority_count": 2,
      "immediate_action_required": true
    }
  },
  "audit_summary": {
    "total_checks": 12,
    "passed_checks": 8,
    "warning_checks": 3,
    "failed_checks": 1,
    "overall_health_score": 67
  }
}
```

### 6. Logical Data Model Analysis
**Prompt:** `using sqlserver_readonly, call db_sql2019_analyze_logical_data_model(database_name='USGISPRO_800', schema='dbo') and display results`

**Result:**
```json
{
  "message": "Analysis complete for database 'USGISPRO_800' schema 'dbo'. View the interactive ERD report at the URL below.",
  "database": "USGISPRO_800",
  "schema": "dbo",
  "report_url": "http://localhost:8000/data-model-analysis?id=5711f174-d4ee-4d97-992f-1ca6aaffadf4",
  "summary": {
    "database": "USGISPRO_800",
    "schema": "dbo",
    "generated_at_utc": "2026-02-18T20:25:22.710000",
    "entities": 265,
    "relationships": 293,
    "issues_count": {
      "entities": 247,
      "attributes": 3061,
      "relationships": 240,
      "identifiers": 75,
      "normalization": 0
    }
  }
}
```

**Interactive ERD Report Features:**
- **Entity-Relationship Diagram**: Interactive Mermaid diagram with pan/zoom controls
- **Key Findings**: Naming convention issues, missing primary keys, normalization problems
- **Recommendations**: Suggested improvements for database design and performance
- **Detailed Analysis**: Complete table structure, constraints, and relationships
- **Model Score**: Overall health score based on best practices (100 - issues × 2)

*Open the `report_url` in your browser to view the full interactive analysis with ERD visualization.*

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

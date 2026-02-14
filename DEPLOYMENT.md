# Deployment Guide for SQL Server MCP Server

This guide provides instructions for deploying the SQL Server MCP Server to various environments, including local development, Docker, Azure Container Apps, and AWS ECS.

## 📋 Prerequisites

Before deploying, ensure you have:
1.  **SQL Server Database**: A running instance (2019+ or Azure SQL).
2.  **Connection Details**: Host, Port (1433), User (sa), Password, Database.
3.  **Container Registry**: A place to push your Docker image (e.g., Docker Hub, ACR, ECR) if deploying to the cloud.

---

## 🌐 Remote Access & Networking

### Exposing the Server
By default, the server binds to `0.0.0.0` (all interfaces) when running via Docker or if `MCP_HOST` is set. To allow external tools (like n8n Cloud) to connect:

1.  **Public IP / DNS**: Ensure your machine has a public IP or dynamic DNS hostname.
2.  **Firewall Rules**: Open the port (default 8085) in your OS firewall.
    *   **Windows (PowerShell)**:
        ```powershell
        netsh advfirewall firewall add rule name="MCP Server 8085" dir=in action=allow protocol=TCP localport=8085
        ```
    *   **Linux (ufw)**:
        ```bash
        sudo ufw allow 8085/tcp
        ```
3.  **Tunnels (Alternative)**: Use a tunneling service like [ngrok](https://ngrok.com/) to bypass firewall/NAT issues during development.
    ```bash
    ngrok http 8085
    ```

---

## 💻 Local Development

### Option 1: Python (uv)
Best for rapid development and testing.

```bash
# 1. Install dependencies
uv sync

# 2. Set environment variables
$env:DB_SERVER="localhost"
$env:DB_USER="sa"
$env:DB_PASSWORD="YourPassword123"
$env:DB_NAME="master"
$env:DB_DRIVER="ODBC Driver 18 for SQL Server"

# 3. Run server
uv run mcp-sql-server
```

### Option 2: Docker Compose
Best for testing the containerized environment locally.

```bash
# 1. Update docker-compose.yml with your database credentials if needed

# 2. Build and run
docker compose up --build
```

---

## 🐳 Building the Docker Image

To deploy to the cloud, you first need to build and push the image.

```bash
# Build
docker build -t harryvaldez/mcp_sqlserver:latest .

# Push
docker push harryvaldez/mcp_sqlserver:latest
```
Notes:
- The base image is python:3.11-slim (Debian based).
- Includes Microsoft ODBC Driver 18 for SQL Server.
- Runs as a non-root `appuser` for enhanced security.
- Automatically loads environment variables from a `.env` file if present.
- Verified to handle connection pooling safely without leaks.
- Default internal port is 8000 (often mapped to 8085 locally); ensure it is available when testing.

---

## ☁️ Azure Container Apps (ACA)

### Features
*   **Serverless**: Scale to zero capability (though minReplicas=1 is recommended).
*   **Secure**: Secrets management for SQL passwords.
*   **Health Checks**: Built-in liveness and readiness probes.

### Deployment Steps (CLI)

1.  **Login to Azure**:
    ```bash
    az login
    ```

2.  **Create Container App**:
    ```bash
    az containerapp create \
      --name mcp-sqlserver \
      --resource-group MyResourceGroup \
      --environment MyEnvironment \
      --image harryvaldez/mcp_sqlserver:latest \
      --target-port 8000 \
      --ingress 'external' \
      --env-vars \
        DB_SERVER=myserver.database.windows.net \
        DB_USER=myadmin \
        DB_PASSWORD=secret-password-here \
        DB_NAME=master \
        MCP_ALLOW_WRITE=false
    ```

---

## ☁️ AWS ECS (Fargate)

### Features
*   **Serverless Compute**: No EC2 instances to manage.
*   **Logging**: Integrated with CloudWatch Logs.
*   **IAM Roles**: Least privilege access for ECS tasks.

### Deployment Steps

1.  **Create Task Definition**:
    *   Image: `harryvaldez/mcp_sqlserver:latest`
    *   Port Mappings: 8000
    *   Environment Variables: `DB_SERVER`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`.

2.  **Configure Network**:
    *   VPC: Must have connectivity to your RDS/SQL Server.
    *   Security Groups: Allow inbound port 1433 from the ECS tasks to the RDS instance.

3.  **Deploy Service**: Create an ECS Service using Fargate.

---

## 🔒 Security Checklist

When deploying to production, verify the following:

1. **Authentication**: If using HTTP transport, enable an auth provider (Azure AD, GitHub, Google, or API Key).
   * Set `FASTMCP_AUTH_TYPE` to your preferred mode.
   * For machine-to-machine (e.g., n8n), use `apikey` with `FASTMCP_API_KEY`.
   * For human-in-the-loop, use `github`, `google`, or `azure-ad`.
2. **Network**: Ensure the container can reach your SQL Server database.
   * **Azure**: Use VNet injection if using Azure SQL Managed Instance or private endpoints.
   * **AWS**: Ensure Security Groups allow inbound port 1433 from the ECS tasks.
3. **Secrets**: Never hardcode passwords. Use Azure Key Vault or AWS Secrets Manager where possible.
4. **Write Access**: Keep `MCP_ALLOW_WRITE=false` unless explicitly required for maintenance tasks.

---

## ⚙️ Environment Variables

Key environment variables supported by the server:
- `DB_SERVER` SQL Server hostname (also `SQL_SERVER`).
- `DB_PORT` SQL Server port, default 1433 (also `SQL_PORT`).
- `DB_USER` SQL User (also `SQL_USER`).
- `DB_PASSWORD` SQL Password (also `SQL_PASSWORD`).
- `DB_NAME` Target Database (also `SQL_DATABASE`).
- `DB_DRIVER` ODBC Driver name (also `SQL_DRIVER`), default `ODBC Driver 18 for SQL Server`.
- `MCP_TRANSPORT` Transport mode: `sse`, `http` (default), or `stdio`.
- `MCP_HOST` Host for HTTP transport, default `0.0.0.0`.
- `MCP_PORT` Port for HTTP transport, default `8000` (Container internal).
- `MCP_ALLOW_WRITE` Allow write operations, default `false`.
- `MCP_CONFIRM_WRITE` Require confirmation for writes, default `false`.
- `FASTMCP_AUTH_TYPE` Authentication type (`apikey`, `github`, `google`, `azure-ad`, `oidc`, `jwt`).
- `FASTMCP_API_KEY` Secret key for `apikey` auth.

---

## 🗝️ Database Privileges

Configure two roles aligned to MCP modes:

### Read-Only User
Minimal privileges for safe querying.

```sql
USE [master];
CREATE LOGIN [mcp_readonly] WITH PASSWORD = 'StrongPassword123!';

USE [YourDatabase];
CREATE USER [mcp_readonly] FOR LOGIN [mcp_readonly];

-- Add to db_datareader role
ALTER ROLE [db_datareader] ADD MEMBER [mcp_readonly];

-- Grant VIEW DEFINITION to see object metadata
GRANT VIEW DEFINITION TO [mcp_readonly];

-- Grant VIEW SERVER STATE for dynamic management views (DMVs) - Server Level
USE [master];
GRANT VIEW SERVER STATE TO [mcp_readonly];
```

### Read/Write User
Full DML privileges and ability to create objects.

```sql
USE [master];
CREATE LOGIN [mcp_rw] WITH PASSWORD = 'StrongPassword123!';

USE [YourDatabase];
CREATE USER [mcp_rw] FOR LOGIN [mcp_rw];

-- Add to db_datareader and db_datawriter
ALTER ROLE [db_datareader] ADD MEMBER [mcp_rw];
ALTER ROLE [db_datawriter] ADD MEMBER [mcp_rw];

-- Grant DDL permissions if needed
GRANT CREATE TABLE TO [mcp_rw];
GRANT CREATE VIEW TO [mcp_rw];
GRANT CREATE PROCEDURE TO [mcp_rw];
GRANT CREATE FUNCTION TO [mcp_rw];

-- Grant VIEW SERVER STATE for DMVs
USE [master];
GRANT VIEW SERVER STATE TO [mcp_rw];
```

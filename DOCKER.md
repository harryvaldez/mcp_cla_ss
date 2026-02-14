# MCP SQL Server

SQL Server Model Context Protocol (MCP) server for AI integration.

## Quick Start

> **Security Warning**: Never pass sensitive credentials (like `DB_PASSWORD`) directly via command-line flags (`-e`), as they can appear in process listings and shell history. Use `--env-file` or Docker Secrets instead.

```bash
# Option 1: Using .env file (Recommended)
# Create a .env file with your variables
docker run -d \
  --name mcp-sqlserver \
  -p 8085:8085 \
  --env-file .env \
  harryvaldez/mcp_sqlserver:latest

# Option 2: Docker Secrets (Swarm/Compose)
# Pass the password via Docker secrets (e.g., /run/secrets/DB_PASSWORD)
```

## Environment Variables

- `DB_SERVER`: SQL Server hostname (also `SQL_SERVER`)
- `DB_DATABASE`: Database name (also `SQL_DATABASE` or `DB_NAME`)
- `DB_USER`: Database user (also `SQL_USER`)
- `DB_PASSWORD`: Database password (also `SQL_PASSWORD`)
- `DB_DRIVER`: ODBC driver (default: `ODBC Driver 18 for SQL Server`) (also `SQL_DRIVER`)
- `DB_PORT`: SQL Server port (default: 1433) (also `SQL_PORT`)
- `SSH_HOST`: SSH tunnel host (optional)
- `SSH_PORT`: SSH tunnel port (default: 22)
- `SSH_USER`: SSH tunnel user (optional)
- `SSH_PASSWORD`: SSH tunnel password (optional)

## Usage

The server exposes MCP tools for SQL Server management:
- Database schema analysis
- Query execution
- Performance monitoring
- User management
- Index optimization

See [README.md](README.md) for detailed API documentation.
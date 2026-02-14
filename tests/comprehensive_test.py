import pytest
import asyncio
import os
import sys
import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

# Add parent directory to path to import server
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configuration for tests is handled via fixture
import server
from server import mcp, get_connection

@pytest.fixture(scope="module", autouse=True)
def setup_env():
    """Set up environment variables for testing"""
    with patch.dict(os.environ, {
        "DB_SERVER": "127.0.0.1",
        "DB_PORT": "1433",
        "DB_USER": "sa",
        "DB_PASSWORD": "McpTestPassword123!", # Should come from secure source in real CI
        "DB_NAME": "testdb",
        "DB_DRIVER": "ODBC Driver 17 for SQL Server",
        "DB_ENCRYPT": "no",
        "DB_TRUST_CERT": "yes",
        "MCP_ALLOW_WRITE": "true",
        "MCP_CONFIRM_WRITE": "true",
        "FASTMCP_AUTH_TYPE": "none",
        "MCP_TRANSPORT": "stdio",
        "MCP_SKIP_CONFIRMATION": "true"
    }):
        yield

def is_db_available():
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception as e:
        print(f"DB Check Failed: {e}")
        return False

db_required = pytest.mark.skipif(not is_db_available(), reason="Database not available")

@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@db_required
class TestUnit:
    """Unit tests for tool logic and helper functions"""

    def test_connection_string_builder(self):
        conn = get_connection()
        assert conn is not None
        conn.close()

@db_required
class TestIntegration:
    """Integration tests for each MCP tool"""

    def test_server_info(self):
        result = server.db_sql2019_server_info.fn()
        assert "server_name" in result
        assert "version" in result

    def test_list_objects(self):
        result = server.db_sql2019_list_objects.fn(object_type="table")
        names = [obj["name"] for obj in result]
        assert "products" in names
        assert "customers" in names

    def test_describe_table(self):
        result = server.db_sql2019_describe_table.fn(schema="dbo", table="products")
        assert result["table"] == "products" # Fixed key
        assert len(result["columns"]) > 0
        col_names = [c["column_name"] for c in result["columns"]] # Fixed key
        assert "id" in col_names
        assert "name" in col_names

    def test_run_query(self):
        result = server.db_sql2019_run_query.fn(sql="SELECT * FROM products")
        assert "rows" in result
        assert len(result["rows"]) == 5
        # FastMCP results are usually list of dicts if row_factory is set
        assert result["rows"][0]["name"] == "Laptop"

    def test_run_query_with_params(self):
        params = json.dumps(["Laptop"])
        result = server.db_sql2019_run_query.fn(sql="SELECT * FROM products WHERE name = ?", params_json=params)
        assert len(result["rows"]) == 1
        assert result["rows"][0]["price"] == 1200.00

    def test_explain_query(self):
        result = server.db_sql2019_explain_query.fn(sql="SELECT * FROM products")
        assert result["format"] == "xml"
        assert "<ShowPlanXML" in result["plan"]

    def test_analyze_index_health(self):
        result = server.db_sql2019_analyze_index_health.fn()
        assert "summary" in result
        # recommendations is inside summary
        assert "recommendations" in result["summary"]

    def test_db_stats(self):
        result = server.db_sql2019_db_stats.fn()
        if isinstance(result, list):
            assert len(result) > 0
            assert "database" in result[0] # Fixed key
        else:
            assert "database" in result # Fixed key

    def test_analyze_sessions(self):
        result = server.db_sql2019_analyze_sessions.fn()
        assert "summary" in result
        assert "active_sessions" in result # Fixed key
        assert "idle_sessions" in result # Fixed key

    def test_create_drop_object(self):
        table_name = "temp_test_table"
        cols = [{"name": "id", "type": "int", "constraints": "PRIMARY KEY"}]
        
        try:
            res_create = server.db_sql2019_create_object.fn(
                object_type="table",
                object_name=table_name,
                schema="dbo",
                parameters={"columns": cols}
            )
            assert "created" in res_create.lower()

            objs = server.db_sql2019_list_objects.fn(object_type="table", name_pattern=table_name)
            assert any(o["name"] == table_name for o in objs)

        finally:
            # Check if exists before dropping to avoid error noise if create failed
            objs = server.db_sql2019_list_objects.fn(object_type="table", name_pattern=table_name)
            if any(o["name"] == table_name for o in objs):
                res_drop = server.db_sql2019_drop_object.fn(
                    object_type="table",
                    object_name=table_name,
                    schema="dbo"
                )
                # Only assert if we actually tried to drop
                assert "dropped" in res_drop.lower()

@db_required
class TestStress:
    """Stress tests for concurrency and load"""

    def test_concurrent_queries(self):
        import concurrent.futures
        
        def run_one_query():
            # Use a slightly different query to avoid caching if any
            return server.db_sql2019_run_query.fn(sql="SELECT COUNT(*) as cnt FROM products")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(run_one_query) for _ in range(50)]
            results = [f.result() for f in futures]
            
        assert len(results) == 50
        for r in results:
            assert r["rows"][0]["cnt"] == 5 # Fixed access

@db_required
class TestBlackbox:
    """Blackbox tests simulating MCP protocol requests"""

    @pytest.mark.asyncio
    async def test_list_tools(self):
        # Use FastMCP's internal get_tools
        tools = await mcp.get_tools()
        assert len(tools) >= 20
        # If it returns strings, tools is the list of names
        assert "db_sql2019_run_query" in tools
        assert "db_sql2019_list_objects" in tools

    def test_ping(self):
        result = server.db_sql2019_ping.fn()
        assert result["ok"] is True

    def test_server_info_mcp(self):
        result = server.db_sql2019_server_info_mcp.fn()
        assert "name" in result # Fixed key
        assert "status" in result
        assert result["status"] == "healthy"

if __name__ == "__main__":
    pytest.main(["-v", __file__])

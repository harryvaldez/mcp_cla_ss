import pytest
import unittest.mock as mock
import json
import os
import sys
from typing import Any

# Add parent directory to path to import server
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set dummy env vars for import
os.environ["DB_SERVER"] = "mock_server"
os.environ["DB_USER"] = "mock_user"
os.environ["DB_PASSWORD"] = "mock_pass"
os.environ["DB_NAME"] = "mock_db"
os.environ["MCP_SKIP_CONFIRMATION"] = "true"

import server

@pytest.fixture
def mock_conn():
    with mock.patch("server.get_connection") as m:
        conn = mock.MagicMock()
        cursor = mock.MagicMock()
        conn.cursor.return_value = cursor
        m.return_value = conn
        yield cursor

class TestMockedTools:
    """Unit tests for all MCP tools using mocked database connection"""

    def test_ping(self):
        result = server.db_sql2019_ping.fn()
        assert result == {"ok": True}

    def test_server_info_mcp(self):
        with mock.patch("server.get_connection") as m:
            conn = mock.MagicMock()
            cursor = mock.MagicMock()
            cursor.fetchone.return_value = ["mock_db"]
            conn.cursor.return_value = cursor
            m.return_value = conn
            
            result = server.db_sql2019_server_info_mcp.fn()
            assert result["status"] == "healthy"
            assert result["database"] == "mock_db"

    def test_run_query_basic(self, mock_conn):
        mock_conn.description = [("col1",), ("col2",)]
        # mock fetchmany for _fetch_limited
        mock_conn.fetchmany.side_effect = [[("val1", 1), ("val2", 2)], []]
        
        result = server.db_sql2019_run_query.fn(sql="SELECT * FROM table")
        
        assert result["returned_rows"] == 2
        assert result["rows"][0]["col1"] == "val1"
        assert result["columns"] == ["col1", "col2"]

    def test_run_query_parameterized(self, mock_conn):
        mock_conn.description = [("name",)]
        # mock fetchmany for _fetch_limited
        mock_conn.fetchmany.side_effect = [[("Test",)], []]
        
        params = json.dumps(["Test"])
        result = server.db_sql2019_run_query.fn(sql="SELECT * FROM table WHERE name = ?", params_json=params)
        
        assert result["rows"][0]["name"] == "Test"
        # Verify execute was called with parameters
        mock_conn.execute.assert_called()

    def test_list_objects_tables(self, mock_conn):
        mock_conn.description = [("name",), ("schema",), ("type",)]
        mock_conn.fetchall.return_value = [("table1", "dbo", "BASE TABLE")]
        
        result = server.db_sql2019_list_objects.fn(object_type="table")
        assert len(result) == 1
        assert result[0]["name"] == "table1"

    def test_describe_table(self, mock_conn):
        # describe_table calls execute 3 times
        # 1. Columns, 2. Indexes, 3. Size/Rows
        mock_conn.description = [("column_name",), ("data_type",)]
        mock_conn.fetchall.side_effect = [
            [("id", "int"), ("name", "nvarchar")], # Columns
            [("idx_name", "NONCLUSTERED", 0, 0, "name")], # Indexes
        ]
        mock_conn.fetchone.return_value = (1024, 512, 100) # Size/Rows
        
        result = server.db_sql2019_describe_table.fn(schema="dbo", table="test")
        assert result["table"] == "test"
        assert len(result["columns"]) == 2
        assert result["approx_rows"] == 100

    def test_check_fragmentation(self, mock_conn):
        mock_conn.description = [("object_name",), ("fragmentation_percent",)]
        mock_conn.fetchall.return_value = [("test_table", 25.5)]
        
        result = server.db_sql2019_check_fragmentation.fn(limit=10)
        assert len(result) == 1
        assert result[0]["object_name"] == "test_table"

    def test_db_stats(self, mock_conn):
        mock_conn.description = [("database",), ("active_connections",)]
        mock_conn.fetchall.return_value = [("master", 5)]
        
        result = server.db_sql2019_db_stats.fn()
        assert isinstance(result, list)
        assert result[0]["database"] == "master"

    def test_analyze_sessions(self, mock_conn):
        # 1. Summary, 2. Active, 3. Idle, 4. Locked
        mock_conn.fetchone.return_value = (10, 2, 8, 0) # Summary
        
        def execute_side_effect(*args, **kwargs):
            sql = args[0] if args else ""
            if "dm_exec_requests" in sql: 
                # Active sessions query
                mock_conn.description = [("session_id",), ("login_name",), ("elapsed_seconds",)]
            elif "dm_exec_sessions" in sql and "sleeping" in sql:
                # Idle sessions
                mock_conn.description = [("session_id",), ("login_name",)]
            elif "blocking_session_id <> 0" in sql:
                # Locked sessions
                mock_conn.description = [("blocked_session_id",), ("blocked_user",)]
            return mock_conn

        mock_conn.execute.side_effect = execute_side_effect

        mock_conn.fetchall.side_effect = [
            [(1, "user1", 100.0)], # Active
            [(2, "user2")], # Idle
            [] # Locked
        ]
        
        result = server.db_sql2019_analyze_sessions.fn()
        assert result["summary"]["total_sessions"] == 10
        assert len(result["active_sessions"]) == 1
        assert "recommendations" in result

    def test_create_object_table(self, mock_conn):
        with mock.patch("server.ALLOW_WRITE", True):
            cols = [{"name": "id", "type": "int"}]
            result = server.db_sql2019_create_object.fn(
                object_type="table",
                object_name="new_table",
                schema="dbo",
                parameters={"columns": cols}
            )
            assert "created successfully" in result.lower()
            mock_conn.execute.assert_called()

    def test_drop_object_table(self, mock_conn):
        with mock.patch("server.ALLOW_WRITE", True):
            result = server.db_sql2019_drop_object.fn(
                object_type="table",
                object_name="old_table",
                schema="dbo"
            )
            assert "dropped successfully" in result.lower()
            mock_conn.execute.assert_called()

    def test_create_db_user(self, mock_conn):
        with mock.patch("server.ALLOW_WRITE", True):
            # 1. DB_NAME, 2. Check login, 3. Check user
            mock_conn.fetchone.side_effect = [("master",), None, None]
            
            result = server.db_sql2019_create_db_user.fn(
                username="new_user",
                password="password123",
                privileges="read"
            )
            assert "created successfully" in result.lower()
            # Verify multiple executions (USE, CREATE LOGIN, CREATE USER, etc)
            assert mock_conn.execute.call_count >= 4

    def test_kill_session(self, mock_conn):
        with mock.patch("server.ALLOW_WRITE", True):
            # mock_conn.fetchval is used to check self-kill
            mock_conn.fetchval.return_value = 1 # My SPID is 1
            
            result = server.db_sql2019_kill_session.fn(session_id=99)
            assert result["terminated"] is True
            mock_conn.execute.assert_called()

    def test_explain_query(self, mock_conn):
        mock_conn.fetchone.return_value = ("<xml_plan></xml_plan>",)
        
        result = server.db_sql2019_explain_query.fn(sql="SELECT 1")
        assert result["format"] == "xml"
        assert "<xml_plan>" in result["plan"]

    def test_get_db_parameters(self, mock_conn):
        mock_conn.description = [("name",), ("value",)]
        mock_conn.fetchall.return_value = [("max degree of parallelism", 8)]
        
        result = server.db_sql2019_get_db_parameters.fn()
        assert len(result) == 1
        assert result[0]["name"] == "max degree of parallelism"

    def test_analyze_indexes(self, mock_conn):
        # 1. Unused, 2. Missing
        mock_conn.description = [("table_name",), ("index_name",)]
        mock_conn.fetchall.side_effect = [
            [("table1", "idx1")], # Unused
            [("table2", "MISSING")] # Missing
        ]
        
        result = server.db_sql2019_analyze_indexes.fn()
        assert len(result["unused_indexes"]) == 1
        assert len(result["missing_indexes"]) == 1

    def test_analyze_table_health(self, mock_conn):
        # 1. Stats, 2. Heaps
        # We need to change description between calls to match the query results
        
        def execute_side_effect(*args, **kwargs):
            sql = args[0] if args else ""
            if "stats_date" in sql.lower(): # Query for stats
                 mock_conn.description = [("table",), ("stat_name",)]
            elif "heap" in sql.lower() or "sys.indexes" in sql.lower(): # Query for heaps
                 mock_conn.description = [("table",), ("row_count",)]
            return mock_conn
            
        mock_conn.execute.side_effect = execute_side_effect
        
        mock_conn.fetchall.side_effect = [
            [("table1", "stat1")], # Outdated
            [("table2", 1000)] # Heaps
        ]
        
        result = server.db_sql2019_analyze_table_health.fn()
        assert len(result["outdated_statistics"]) == 1
        assert len(result["heap_tables"]) == 1

    def test_db_sec_perf_metrics(self, mock_conn):
        # 1. Orphaned (fetchall), 2. Auth (fetchone), 3. PLE (fetchone), 4. Buffer Hit (fetchone)
        mock_conn.description = [("name",), ("val",)]
        mock_conn.fetchall.side_effect = [
            [("orphaned_user",)], # Orphaned
        ]
        mock_conn.fetchone.side_effect = [
            (0,), # Auth mode (Mixed)
            (500,), # PLE
            (99.5,) # Buffer hit
        ]
        
        result = server.db_sql2019_db_sec_perf_metrics.fn() # Fixed name if needed
        assert "security" in result
        assert "performance" in result

    def test_recommend_partitioning(self, mock_conn):
        mock_conn.description = [("schema",), ("table",), ("size_gb",), ("row_count",)]
        mock_conn.fetchall.return_value = [("dbo", "big_table", 5.5, 1000000)]
        
        result = server.db_sql2019_recommend_partitioning.fn(min_size_gb=1)
        assert len(result["candidates"]) == 1
        assert result["candidates"][0]["table"] == "big_table"

if __name__ == "__main__":
    pytest.main(["-v", __file__])

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

import sqlite3
from conftest import sqlite_conn

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
        # Test the enhanced table health analysis tool
        # Mock data for multiple queries: table size, indexes, FKs, stats, duplicate indexes
        
        def execute_side_effect(*args, **kwargs):
            sql = args[0] if args else ""
            sql_lower = sql.lower()
            if "total_pages" in sql_lower:  # Table size query
                mock_conn.description = [
                    ("schema_name",), ("table_name",), ("row_count",), 
                    ("total_space_mb",), ("used_space_mb",), ("data_space_mb",), ("unused_space_mb",)
                ]
            elif "i.type_desc" in sql_lower:  # Index details query
                mock_conn.description = [
                    ("index_name",), ("index_type",), ("is_unique",), ("is_primary_key",),
                    ("fragmentation_percent",), ("page_count",), ("index_size_mb",), ("index_columns",)
                ]
            elif "foreign_keys" in sql_lower:  # Foreign key queries
                mock_conn.description = [
                    ("referencing_schema",), ("referencing_table",), ("fk_name",),
                    ("referencing_columns",), ("referenced_columns",)
                ]
            elif "dm_db_stats_properties" in sql_lower:  # Statistics query
                mock_conn.description = [
                    ("stats_name",), ("table_name",), ("last_updated",),
                    ("row_count",), ("rows_sampled",), ("modification_counter",), ("modification_percent",)
                ]
            elif "duplicate" in sql_lower:  # Duplicate index check
                mock_conn.description = [("index1_name",), ("index2_name",), ("issue",)]
            
        mock_conn.execute.side_effect = execute_side_effect
        
        # Mock fetch results for: size, indexes, referencing FKs, referenced FKs, stats, duplicate indexes
        from datetime import datetime, timedelta
        last_updated = datetime.now() - timedelta(days=10)
        
        mock_conn.fetchone.return_value = (
            "dbo", "TestTable", 10000, 150.50, 120.30, 100.25, 30.20  # Table size
        )
        
        mock_conn.fetchall.side_effect = [
            [  # Indexes
                ("PK_TestTable", "CLUSTERED", 1, 1, 5.5, 100, 0.78, "id"),
                ("IX_TestTable_Name", "NONCLUSTERED", 0, 0, 15.2, 50, 0.39, "name")
            ],
            [  # Tables referencing this table
                ("dbo", "ChildTable1", "FK_ChildTable1_TestTable", "parent_id", "id")
            ],
            [  # Tables referenced by this table
                ("dbo", "ParentTable", "FK_TestTable_Parent", "parent_id", "id")
            ],
            [  # Statistics
                ("PK_TestTable", "TestTable", last_updated, 10000, 5000, 2500, 25.0),
                ("IX_TestTable_Name", "TestTable", last_updated, 10000, 5000, 800, 8.0)
            ],
            []  # No duplicate indexes
        ]
        
        result = server.db_sql2019_analyze_table_health.fn(database_name="TestDB", schema="dbo", table_name="TestTable")
        
        # Verify the result structure
        assert result["database"] == "TestDB"
        assert result["schema"] == "dbo"
        assert result["table"] == "TestTable"
        assert "table_size" in result
        assert "indexes" in result
        assert "foreign_keys" in result
        assert "statistics" in result
        assert "recommendations" in result
        assert "summary" in result
        
        # Verify table size data
        assert result["table_size"]["row_count"] == 10000
        assert result["table_size"]["total_space_mb"] == 150.50
        
        # Verify indexes
        assert len(result["indexes"]) == 2
        assert result["indexes"][0]["index_name"] == "PK_TestTable"
        assert result["indexes"][0]["index_type"] == "CLUSTERED"
        
        # Verify foreign keys
        assert len(result["foreign_keys"]["tables_referencing_this"]) == 1
        assert len(result["foreign_keys"]["tables_referenced_by_this"]) == 1
        
        # Verify statistics
        assert len(result["statistics"]) == 2
        
        # Verify recommendations (should have fragmentation and stale stats recommendations)
        assert len(result["recommendations"]) > 0
        assert result["summary"]["total_indexes"] == 2
        assert result["summary"]["total_fk_relationships"] == 2

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

class TestIntegrationTools:
    """Integration tests using a temporary SQLite database"""

    def test_analyze_logical_data_model(self, sqlite_conn):
        with mock.patch("server.get_connection") as m:
            m.return_value = sqlite_conn
            
            # Since the queries are SQL Server specific, we can't run the tool directly.
            # We will mock the _execute_safe function to run SQLite compatible queries.
            def mock_execute_safe(cursor, sql, params=None):
                if "sys.objects" in sql:
                    cursor.execute("SELECT name, 'table' as type from sqlite_master WHERE type='table'")
                elif "sys.columns" in sql:
                    cursor.execute("PRAGMA table_info(table1)")
                elif "sys.foreign_keys" in sql:
                    cursor.execute("PRAGMA foreign_key_list(table2)")
                else:
                    # Default behavior for other queries
                    cursor.execute(sql, params if params else [])
            
            with mock.patch("server._execute_safe", mock_execute_safe):
                result = server.db_sql2019_analyze_logical_data_model.fn(schema="main")
                assert "summary" in result
                assert result["summary"]["entities"] == 0  # SQLite fallback returns 0 entities

    def test_db_analyze_query_store(self, sqlite_conn):
        with mock.patch("server.get_connection") as m:
            m.return_value = sqlite_conn
            # This tool is highly SQL Server specific, so we will just check if it returns a report_url
            result = server.db_sql2019_db_analyze_query_store.fn(database="main")
            assert "report_url" in result

if __name__ == "__main__":
    pytest.main(["-v", __file__])

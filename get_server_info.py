#!/usr/bin/env python3
"""
Direct SQL Server information retrieval script
"""

import pyodbc
import os

def get_server_info():
    """Get SQL Server information directly using pyodbc"""
    
    # Connection parameters
    server = os.environ.get("DB_SERVER", "127.0.0.1")
    database = os.environ.get("DB_NAME", "master")
    username = os.environ.get("DB_USER", "sa")
    password = os.environ.get("DB_PASSWORD", "Harryv1983")
    driver = os.environ.get("DB_DRIVER", "ODBC Driver 17 for SQL Server")
    
    print(f"Connecting to {server} as {username} using {driver}")
    
    try:
        # Build connection string
        conn_str = f"DRIVER={{{driver}}};SERVER={server};DATABASE={database};UID={username};PWD={password};Encrypt=no;TrustServerCertificate=yes"
        
        # Connect to database
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        
        # Get server version
        cursor.execute("SELECT @@VERSION")
        version = cursor.fetchone()[0]
        
        # Get server name
        cursor.execute("SELECT @@SERVERNAME")
        server_name = cursor.fetchone()[0]
        
        # Get database name
        cursor.execute("SELECT DB_NAME()")
        db_name = cursor.fetchone()[0]
        
        # Get connection info
        cursor.execute("SELECT CONNECTIONPROPERTY('net_transport') as transport, CONNECTIONPROPERTY('protocol_type') as protocol, CONNECTIONPROPERTY('auth_scheme') as auth")
        conn_info = cursor.fetchone()
        
        print("\n=== SQL Server Information ===")
        print(f"Server Name: {server_name}")
        print(f"Database: {db_name}")
        print(f"Version: {version}")
        print(f"Transport: {conn_info.transport}")
        print(f"Protocol: {conn_info.protocol}")
        print(f"Auth Scheme: {conn_info.auth}")
        
        # Get database list
        cursor.execute("SELECT name, database_id, create_date FROM sys.databases ORDER BY name")
        databases = cursor.fetchall()
        
        print(f"\n=== Databases ({len(databases)}) ===")
        for db in databases:
            print(f"- {db.name} (ID: {db.database_id}, Created: {db.create_date})")
        
        # Get server properties
        cursor.execute("SELECT SERVERPROPERTY('ProductVersion') as version, SERVERPROPERTY('ProductLevel') as level, SERVERPROPERTY('Edition') as edition")
        props = cursor.fetchone()
        
        print(f"\n=== Server Properties ===")
        print(f"Product Version: {props.version}")
        print(f"Product Level: {props.level}")
        print(f"Edition: {props.edition}")
        
        cursor.close()
        conn.close()
        
        return {
            "server_name": server_name,
            "database": db_name,
            "version": version,
            "transport": conn_info.transport,
            "protocol": conn_info.protocol,
            "auth_scheme": conn_info.auth,
            "databases": len(databases),
            "product_version": props.version,
            "product_level": props.level,
            "edition": props.edition
        }
        
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    # Set environment variables for testing
    os.environ["DB_SERVER"] = "127.0.0.1"
    os.environ["DB_NAME"] = "master"
    os.environ["DB_USER"] = "sa"
    os.environ["DB_PASSWORD"] = "Harryv1983"
    os.environ["DB_DRIVER"] = "ODBC Driver 17 for SQL Server"
    
    info = get_server_info()
    if info:
        print("\n✅ Successfully connected to SQL Server!")
    else:
        print("\n❌ Failed to connect to SQL Server")
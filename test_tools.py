import asyncio
import sys
sys.path.append('.')

from server import mcp, _configure_fastmcp_runtime

async def list_tools():
    """List all available tools from the MCP server"""
    try:
        # Configure the runtime to ensure all decorators are processed
        _configure_fastmcp_runtime()
        
        tools = await mcp.list_tools()
        print("Available tools:")
        
        # mcp.list_tools() returns a list of tool objects
        tool_names = [tool.name for tool in tools]
        for tool_name in tool_names:
            print(f"- {tool_name}")
        
        # Check specifically for our tool
        if "db_sql2019_db_analyze_query_store" in tool_names:
            print("\n✓ db_sql2019_db_analyze_query_store is available!")
        else:
            print("\n✗ db_sql2019_db_analyze_query_store is NOT available!")
            
    except Exception as e:
        print(f"Error listing tools: {e}")

if __name__ == "__main__":
    asyncio.run(list_tools())
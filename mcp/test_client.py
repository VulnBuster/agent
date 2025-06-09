#!/usr/bin/env python3
"""
Example MCP client for testing Bandit Security Scanner
"""

import os
import asyncio
from smolagents.mcp_client import MCPClient

async def test_bandit_mcp_client():
    """Tests connection to Bandit MCP server"""
    
    # URL of your Bandit MCP server
    server_url = "http://localhost:7860/gradio_api/mcp/sse"
    
    print("🔒 Connecting to Bandit MCP server...")
    
    try:
        async with MCPClient({"url": server_url}) as client:
            # Get list of available tools
            tools = await client.get_tools()
            
            print(f"\n✅ Successfully connected! Available tools: {len(tools)}")
            print("\n📋 Available tools:")
            for tool in tools:
                print(f"  • {tool.name}: {tool.description}")
            
            # Test scanning vulnerable code
            print("\n🧪 Testing vulnerable code scanning...")
            
            vulnerable_code = """
import subprocess
import pickle

# Vulnerabilities for testing
password = "hardcoded_secret123"  # B105: Hardcoded password
eval("print('hello')")  # B307: Use of eval
subprocess.call("ls -la", shell=True)  # B602: subprocess with shell=True
data = pickle.loads(user_input)  # B301: Pickle usage
"""
            
            # Call bandit_scan
            scan_tool = next((t for t in tools if t.name == "bandit_scan"), None)
            if scan_tool:
                result = await client.call_tool(
                    tool_name="bandit_scan",
                    arguments={
                        "code_input": vulnerable_code,
                        "scan_type": "code",
                        "severity_level": "low",
                        "confidence_level": "low",
                        "output_format": "json"
                    }
                )
                
                print("📊 Scan results:")
                if result.get("success"):
                    issues = result.get("results", {}).get("results", [])
                    print(f"  Found security issues: {len(issues)}")
                    
                    for i, issue in enumerate(issues, 1):
                        print(f"\n  🚨 Issue {i}:")
                        print(f"     ID: {issue.get('test_id')}")
                        print(f"     Severity: {issue.get('issue_severity')}")
                        print(f"     Confidence: {issue.get('issue_confidence')}")
                        print(f"     Description: {issue.get('issue_text')}")
                        print(f"     Line: {issue.get('line_number')}")
                        print(f"     Code: {issue.get('code', '').strip()}")
                else:
                    print(f"  ❌ Scan error: {result.get('error')}")
            else:
                print("  ❌ bandit_scan tool not found")
            
            # Test baseline creation (if file exists)
            print("\n🎯 Testing baseline creation...")
            baseline_tool = next((t for t in tools if t.name == "bandit_baseline"), None)
            if baseline_tool:
                # Create temporary file with code
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_file:
                    tmp_file.write(vulnerable_code)
                    tmp_path = tmp_file.name
                
                baseline_result = await client.call_tool(
                    tool_name="bandit_baseline",
                    arguments={
                        "target_path": tmp_path,
                        "baseline_file": "/tmp/bandit_baseline.json"
                    }
                )
                
                print("📋 Baseline result:")
                if baseline_result.get("success"):
                    action = baseline_result.get("action", "unknown")
                    message = baseline_result.get("message", "")
                    print(f"  ✅ Action: {action}")
                    if message:
                        print(f"  📝 Message: {message}")
                else:
                    print(f"  ❌ Baseline error: {baseline_result.get('error')}")
                
                # Clean up temporary file
                try:
                    os.unlink(tmp_path)
                except:
                    pass
            
    except Exception as e:
        print(f"❌ Connection error: {e}")
        print("💡 Make sure Bandit MCP server is running on http://localhost:7860")

if __name__ == "__main__":
    print("🔒 Bandit MCP Client Test")
    print("=" * 50)
    asyncio.run(test_bandit_mcp_client()) 
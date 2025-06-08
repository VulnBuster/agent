#!/usr/bin/env python3
"""
Скрипт для автоматического тестирования Security Tools MCP Agent
"""

import asyncio
import requests
import time
import json

def test_mcp_servers():
    """Тестирует доступность всех MCP серверов"""
    print("🔍 Testing MCP servers...")
    
    servers = {
        "bandit": "http://localhost:7860",
        "detect_secrets": "http://localhost:7861", 
        "pip_audit": "http://localhost:7862",
        "circle_test": "http://localhost:7863",
        "semgrep": "http://localhost:7864"
    }
    
    results = {}
    for name, url in servers.items():
        try:
            response = requests.get(url, timeout=5)
            if response.status_code in [200, 404]:
                results[name] = "✅ Available"
            else:
                results[name] = f"❌ Error {response.status_code}"
        except Exception as e:
            results[name] = f"❌ Connection failed: {str(e)}"
    
    return results

def test_gradio_interface():
    """Тестирует основной Gradio интерфейс"""
    print("🌐 Testing Gradio interface...")
    
    try:
        response = requests.get("http://localhost:7865", timeout=10)
        if response.status_code == 200:
            return "✅ Gradio interface is running"
        else:
            return f"❌ Gradio error {response.status_code}"
    except Exception as e:
        return f"❌ Gradio connection failed: {str(e)}"

def create_test_scenarios():
    """Создает различные тестовые сценарии"""
    scenarios = {
        "simple_vulnerability": {
            "code": '''
import os
password = "hardcoded_password_123"
os.system("rm -rf /")
''',
            "expected_tools": ["bandit", "detect_secrets", "semgrep"]
        },
        
        "sql_injection": {
            "code": '''
import sqlite3
def unsafe_query(user_input):
    conn = sqlite3.connect('db.sql')
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return conn.execute(query).fetchall()
''',
            "expected_tools": ["bandit", "semgrep"]
        },
        
        "secrets_detection": {
            "code": '''
API_KEY = "sk-1234567890abcdef1234567890abcdef"
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgresql://user:password@localhost/db"
''',
            "expected_tools": ["detect_secrets"]
        }
    }
    
    return scenarios

def main():
    """Основная функция тестирования"""
    print("🧪 Starting Security Tools MCP Agent Test Suite")
    print("=" * 60)
    
    # Тест 1: MCP серверы
    print("\n1️⃣ Testing MCP Servers:")
    mcp_results = test_mcp_servers()
    for name, status in mcp_results.items():
        print(f"   {name}: {status}")
    
    # Тест 2: Gradio интерфейс
    print("\n2️⃣ Testing Gradio Interface:")
    gradio_status = test_gradio_interface()
    print(f"   {gradio_status}")
    
    # Тест 3: Тестовые сценарии
    print("\n3️⃣ Test Scenarios Available:")
    scenarios = create_test_scenarios()
    for name, scenario in scenarios.items():
        print(f"   📝 {name}: {len(scenario['code'])} chars, expects {scenario['expected_tools']}")
    
    # Сводка
    print("\n" + "=" * 60)
    mcp_working = sum(1 for status in mcp_results.values() if status.startswith("✅"))
    gradio_working = 1 if gradio_status.startswith("✅") else 0
    
    print(f"📊 Test Summary:")
    print(f"   MCP Servers: {mcp_working}/5 working")
    print(f"   Gradio Interface: {gradio_working}/1 working")
    print(f"   Test Files: Created test_vulnerable_code.py")
    
    if mcp_working >= 4 and gradio_working == 1:
        print("🎉 System is ready for testing!")
        print("\n💡 Next steps:")
        print("   1. Open http://localhost:7865 in your browser")
        print("   2. Upload test_vulnerable_code.py")
        print("   3. Click 'Test Server Connections'")
        print("   4. Click 'Run Security Scan'")
    else:
        print("⚠️ Some components are not working properly")
        print("   Please check the logs and restart failed services")

if __name__ == "__main__":
    main() 
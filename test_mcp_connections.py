#!/usr/bin/env python3
"""
Быстрый тест MCP соединений
"""

import asyncio
import aiohttp
import subprocess
import sys

# Конфигурация MCP серверов
MCP_SERVERS = {
    "bandit": {
        "port": 7861,
        "url": "http://mcp-bandit:7860/gradio_api/mcp/sse",
        "description": "Python code security analysis"
    },
    "detect_secrets": {
        "port": 7862,
        "url": "http://mcp-detect-secrets:7860/gradio_api/mcp/sse",
        "description": "Secret detection in code"
    },
    "pip_audit": {
        "port": 7863,
        "url": "http://mcp-pip-audit:7860/gradio_api/mcp/sse",
        "description": "Python package vulnerability scanning"
    },
    "circle_test": {
        "port": 7864,
        "url": "http://mcp-circle-test:7860/gradio_api/mcp/sse",
        "description": "Security policy compliance checking"
    },
    "semgrep": {
        "port": 7865,
        "url": "http://mcp-semgrep:7860/gradio_api/mcp/sse",
        "description": "Advanced static code analysis"
    }
}

async def test_http_connection(server_name, port):
    """Тестирует HTTP соединение"""
    try:
        timeout = aiohttp.ClientTimeout(total=3)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"http://localhost:{port}") as response:
                if response.status == 200:
                    return True, "HTTP OK"
                else:
                    return False, f"HTTP {response.status}"
    except Exception as e:
        return False, f"HTTP failed: {str(e)}"

async def test_mcp_remote():
    """Тестирует доступность mcp-remote"""
    try:
        result = subprocess.run(
            ["mcp-remote", "--help"], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        if result.returncode == 0:
            return True, "mcp-remote available"
        else:
            return False, "mcp-remote not found"
    except subprocess.TimeoutExpired:
        return False, "mcp-remote timeout"
    except FileNotFoundError:
        return False, "mcp-remote not installed"
    except Exception as e:
        return False, f"mcp-remote error: {str(e)}"

async def main():
    print("🔍 Тестирование MCP соединений")
    print("="*50)
    
    # Тест mcp-remote
    print("📦 Проверка mcp-remote...")
    mcp_available, mcp_msg = await test_mcp_remote()
    print(f"   {'✅' if mcp_available else '❌'} {mcp_msg}")
    
    if not mcp_available:
        print("\n❌ mcp-remote недоступен! Установите командой:")
        print("   npm install -g mcp-remote")
        return
    
    print("\n🌐 Проверка HTTP соединений...")
    all_ok = True
    
    # Тест HTTP соединений
    for server_name, config in MCP_SERVERS.items():
        http_ok, http_msg = await test_http_connection(server_name, config["port"])
        status = "✅" if http_ok else "❌"
        print(f"   {status} {server_name:15} (:{config['port']}) - {http_msg}")
        
        if not http_ok:
            all_ok = False
    
    print("\n📊 Результаты:")
    if all_ok:
        print("✅ Все MCP серверы доступны!")
        print("🚀 Можно запускать анализ безопасности")
    else:
        print("❌ Некоторые MCP серверы недоступны")
        print("🔧 Проверьте состояние Docker контейнеров:")
        print("   docker compose ps")
        print("   docker compose logs")

if __name__ == "__main__":
    asyncio.run(main()) 
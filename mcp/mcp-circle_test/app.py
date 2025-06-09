#!/usr/bin/env python3
"""
MCP server for Circle Test - a tool for checking code against security policies
"""

import gradio as gr
import aiohttp
import ssl
import os
from typing import Dict
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

# Получаем URL из переменных окружения
CIRCLE_API_URL = os.getenv('CIRCLE_API_URL', 'https://api.example.com/protect/check_violation')

async def check_violation(prompt: str, policies: Dict[str, str]) -> Dict:
    """
    Проверяет код на соответствие политикам безопасности.
    
    Args:
        prompt (str): Код для проверки
        policies (Dict[str, str]): Словарь политик безопасности
    
    Returns:
        Dict: Результаты проверки
    """
    try:
        payload = {
            "dialog": [
                {
                    "role": "assistant",
                    "content": prompt
                }
            ],
            "policies": policies
        }

        # Создаем SSL-контекст
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        async with aiohttp.ClientSession() as session:
            async with session.post(
                CIRCLE_API_URL,
                json=payload,
                timeout=30,
                ssl=ssl_context
            ) as response:
                result = await response.json()
                
                # Преобразуем результат в более читаемый формат
                if 'policies' in result:
                    formatted_result = {}
                    for policy_num, value in result['policies'].items():
                        policy_text = policies.get(policy_num, "Unknown policy")
                        formatted_result[policy_num] = {
                            "policy": policy_text,
                            "violation": "yes" if value == 1 else "no"
                        }
                    return {
                        "success": True,
                        "results": formatted_result
                    }
                return {
                    "success": False,
                    "error": "Invalid response format"
                }

    except Exception as e:
        return {
            "success": False,
            "error": f"Error checking violations: {str(e)}"
        }

# Создаем Gradio интерфейс
with gr.Blocks(title="Circle Test MCP") as demo:
    gr.Markdown("# 🔍 Circle Test Scanner")
    gr.Markdown("Security policy compliance checker with MCP support")

    with gr.Tab("Policy Check"):
        with gr.Row():
            with gr.Column():
                code_input = gr.Textbox(
                    lines=10,
                    placeholder="Enter code to check...",
                    label="Code"
                )
                check_btn = gr.Button("🔍 Check Policies", variant="primary")
            
            with gr.Column():
                check_output = gr.JSON(label="Check Results")

        check_btn.click(
            fn=check_violation,
            inputs=[
                code_input,
                gr.State({
                    "1": "Presence of SPDX-License-Identifier with an ID not in the approved list, or missing SPDX tag in top-level LICENSE file.",
                    "2": "Presence of plaintext credentials (passwords, tokens, keys) in configuration files (YAML, JSON, .env, etc.).",
                    "3": "Presence of TODO or FIXME tags in comments inside non-test production code files.",
                    "4": "Presence of any string literal starting with http:// not wrapped in a validated secure-client.",
                    "5": "Presence of logging statements that output sensitive data (user PII, private keys, passwords, tokens) without masking or hashing.",
                    "6": "Presence of calls to deprecated or outdated APIs (functions or methods marked as deprecated).",
                    "7": "Presence of subprocess or os.system calls where user input is concatenated directly without proper sanitization or escaping.",
                    "8": "Presence of file read/write operations using paths derived directly from user input without normalization or path-traversal checks.",
                    "9": "Presence of SQL queries built using string concatenation with user input instead of parameterized queries or ORM methods.",
                    "10": "Presence of string literals matching absolute filesystem paths (e.g., \"/home/...\" or \"C:\\\\...\") rather than relative paths or environment variables.",
                    "11": "Presence of hostnames or URLs containing \"prod\", \"production\", or \"release\" that reference production databases or services in non-test code.",
                    "12": "Presence of dependencies in lock files (Pipfile.lock or requirements.txt) without exact version pins (using version ranges like \">=\" or \"~=\" without a fixed version).",
                    "13": "Presence of hashlib.md5(...) or any MD5-based hashing, since MD5 is cryptographically broken (use SHA-256 or better).",
                    "14": "Presence of pdb.set_trace() or other pdb imports, as debug statements should not remain in production code.",
                    "15": "Presence of logging.debug($SENSITIVE) or similar logging calls that output sensitive information without redaction.",
                    "16": "Presence of re.compile($USER_INPUT) where $USER_INPUT is unsanitized, since this can lead to ReDoS attacks.",
                    "17": "Presence of xml.etree.ElementTree.parse($USER_INPUT) without secure parsing, leading to XXE vulnerabilities.",
                    "18": "Presence of zipfile.ZipFile($USER_INPUT) or similar extraction calls on untrusted zips, which can cause path traversal.",
                    "19": "Presence of tarfile.open($USER_INPUT) on untrusted tar files, leading to path traversal vulnerabilities.",
                    "20": "Presence of os.chmod($PATH, 0o777) or equivalent setting overly permissive permissions, which is insecure.",
                    "21": "Presence of os.environ[$KEY] = $VALUE modifying environment variables at runtime, which can introduce security risks."
                })
            ],
            outputs=check_output
        )

    with gr.Tab("Examples"):
        gr.Markdown("""
        ## 🚨 Examples of code to check:
        
        ### 1. Insecure File Operations
        ```python
        def read_file(filename):
            with open(filename, "r") as f:
                return f.read()
        ```
        
        ### 2. Hardcoded Credentials
        ```python
        DB_PASSWORD = "secret123"
        API_KEY = "sk_live_51H1h2K3L4M5N6O7P8Q9R0S1T2U3V4W5X6Y7Z8"
        ```
        
        ### 3. Insecure Subprocess
        ```python
        import subprocess
        subprocess.call(f"ls {user_input}", shell=True)
        ```
        """)

if __name__ == "__main__":
    import time
    print("🔄 Starting Circle-Test MCP Server...")
    time.sleep(2)  # Стабилизационная задержка
    
    # Добавляем health endpoint
    from fastapi import FastAPI
    app = FastAPI()
    
    @app.get("/health")
    def health_check():
        return {"status": "healthy", "service": "circle-test-mcp"}
    
    demo.queue()\
        .launch(
            mcp_server=True,
            server_name="0.0.0.0",
            server_port=7860,
            app=app  # Добавляем FastAPI app с health endpoint
        )




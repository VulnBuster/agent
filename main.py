import asyncio
import os
import tempfile
import gradio as gr
from textwrap import dedent
from agno.agent import Agent
from agno.tools.mcp import MCPTools
from agno.models.nebius import Nebius
from mcp import ClientSession
from mcp.client.sse import sse_client
from dotenv import load_dotenv
import base64
import difflib
import re
import subprocess
import sys
import shutil
import time
import aiohttp
import logging
import signal
import socket
import json

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def extract_json_payload(raw: str) -> str:
    """
    Извлекает первый JSON объект {...} из строки, удаляя Markdown-разметку и дополнительный текст.
    """
    # Ищем первый '{' и последний '}'
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        return raw[start:end + 1]
    # Если не нашли JSON, возвращаем оригинальную строку
    return raw

# Глобальные переменные для переиспользования сессий
MCP_WRAPPERS = {}

# Загружаем переменные окружения из .env файла
load_dotenv()
api_key = os.getenv("NEBIUS_API_KEY")
if not api_key:
    raise ValueError("NEBIUS_API_KEY not found in .env file")

# Конфигурация MCP серверов
MCP_SERVERS = {
    "bandit": {
        "url": "http://localhost:7861/gradio_api/mcp/sse",
        "description": "Python code security analysis",
        "port": 7861
    },
    "detect_secrets": {
        "url": "http://localhost:7862/gradio_api/mcp/sse",
        "description": "Secret detection in code",
        "port": 7862
    },
    "pip_audit": {
        "url": "http://localhost:7863/gradio_api/mcp/sse",
        "description": "Python package vulnerability scanning",
        "port": 7863
    },
    "circle_test": {
        "url": "http://localhost:7864/gradio_api/mcp/sse",
        "description": "Security policy compliance checking",
        "port": 7864
    },
    "semgrep": {
        "url": "http://localhost:7865/gradio_api/mcp/sse",
        "description": "Advanced static code analysis",
        "port": 7865
    }
}

def check_port(port: int) -> bool:
    """Проверяет доступность порта"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        result = sock.connect_ex(('127.0.0.1', port))
        return result == 0
    finally:
        sock.close()

def signal_handler(signum, frame):
    """Обработчик сигналов для корректного завершения"""
    logger.info("Получен сигнал завершения, закрываем серверы...")
    sys.exit(0)

# Регистрируем обработчики сигналов
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def generate_simple_diff(original_content: str, updated_content: str, file_path: str) -> str:
    """
    Генерирует простой diff между оригинальным и обновленным содержимым
    """
    diff_lines = list(difflib.unified_diff(
        original_content.splitlines(keepends=True),
        updated_content.splitlines(keepends=True),
        fromfile=f"{file_path} (original)",
        tofile=f"{file_path} (modified)",
        n=3
    ))
    if not diff_lines:
        return "No changes detected."
    added_lines = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
    removed_lines = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))
    diff_content = "".join(diff_lines)
    stats = f"\n📊 Changes: +{added_lines} additions, -{removed_lines} deletions"
    return diff_content + stats

async def check_server_availability(url: str, max_retries: int = 5, delay: float = 5.0) -> bool:
    """Проверяет доступность MCP сервера с увеличенными таймаутами"""
    logger.debug(f"Проверка доступности сервера: {url}")
    for i in range(max_retries):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        logger.info(f"Сервер {url} доступен")
                        return True
        except Exception as e:
            logger.warning(f"Попытка {i+1}/{max_retries} не удалась: {str(e)}")
        await asyncio.sleep(delay)
    logger.error(f"Сервер {url} недоступен после {max_retries} попыток")
    return False

async def init_all_tools():
    """Инициализирует все MCP инструменты один раз при старте приложения"""
    global MCP_WRAPPERS
    
    try:
        # Создаем SSE клиенты для каждого сервера
        for name, cfg in MCP_SERVERS.items():
            async with sse_client(cfg["url"]) as (read, write):
                async with ClientSession(read, write) as session:
                    MCP_WRAPPERS[name] = MCPTools(session=session)
            
        logger.info("Все MCP инструменты успешно инициализированы")
    except Exception as e:
        logger.error(f"Ошибка при инициализации MCP инструментов: {str(e)}")
        raise

async def run_mcp_agent(message, server_name):
    """Запускает агента для конкретного MCP сервера"""
    logger.info(f"Запуск MCP агента для {server_name}")
    
    if not api_key:
        logger.error("Nebius API key не найден в .env файле")
        return "Error: Nebius API key not found in .env file"
    
    if server_name not in MCP_SERVERS:
        logger.error(f"Неизвестный MCP сервер: {server_name}")
        return f"Error: Unknown MCP server {server_name}"
    
    if server_name not in MCP_WRAPPERS:
        logger.error(f"MCP инструмент {server_name} не инициализирован")
        return f"Error: MCP tool {server_name} not initialized"
    
    try:
        # Получаем инструмент из кэша
        mcp_tools = MCP_WRAPPERS[server_name]
        
        # Форматируем аргументы в зависимости от сервера
        if server_name == "detect_secrets":
            tool_args = {
                "code_input": message,
                "scan_type": "code",
                "base64_limit": 4.5,
                "hex_limit": 3.0,
                "exclude_lines": ".*test.*|.*example.*",
                "exclude_files": ".*test.*|.*example.*",
                "exclude_secrets": ".*test.*|.*example.*",
                "word_list": "password,secret,key,token,api_key,credential",
                "output_format": "json"
            }
        elif server_name == "bandit":
            tool_args = {
                "code_input": message,
                "scan_type": "code",
                "severity_level": "high",
                "confidence_level": "high",
                "output_format": "json"
            }
        elif server_name == "circle_test":
            tool_args = {
                "prompt": message,
                "policies": {
                    "1": "Presence of SPDX-License-Identifier with an ID not in the approved list, or missing SPDX tag in top-level LICENSE file.",
                    "2": "Presence of plaintext credentials (passwords, tokens, keys) in configuration files (YAML, JSON, .env, etc.).",
                    "3": "Presence of TODO or FIXME tags in comments inside non-test production code files.",
                    "4": "Presence of any string literal starting with http:// not wrapped in a validated secure-client.",
                    "5": "Presence of logging statements that output sensitive data (user PII, private keys, passwords, tokens) without masking or hashing.",
                    "6": "Presence of calls to deprecated or outdated APIs (functions or methods marked as deprecated).",
                    "7": "Presence of subprocess or os.system calls that embed unsanitized user input into shell commands (e.g., f\"rm {user_input}\" with shell=True).",
                    "8": "Presence of open(), read(), write(), or similar file operations using a path directly derived from user input without normalization or path-traversal checks (e.g., open(f\"{user_input}.txt\")).",
                    "9": "Presence of SQL queries built using string concatenation with user input instead of parameterized queries or ORM methods.",
                    "10": "Presence of string literals matching absolute filesystem paths (e.g., \"/home/...\" or \"C:\\\\...\") rather than relative paths or environment variables.",
                    "11": "Presence of hostnames or URLs containing \"prod\", \"production\", or \"release\" that reference production databases or services in non-test code.",
                    "12": "Presence of dependencies in lock files (Pipfile.lock or requirements.txt) without exact version pins (using version ranges like \">=\" or \"~=\" without a fixed version)."
                }
            }
        else:
            tool_args = {"code_input": message}
        
        # Создаем агента
        agent = Agent(
            tools=[mcp_tools],
            instructions=dedent("""\
                You are an intelligent security assistant with access to MCP tools.
                - Automatically select and invoke the appropriate tool(s) based on the user's request.
                - Always choose the highest intensity settings available.
                - If the user specifies particular checks, focus on those.
                - Return ONLY the raw JSON output from the tool—no Markdown fences, no commentary, nothing else.
                - Do not add any explanations or formatting around the JSON output.
            """),
            markdown=False,  # Отключаем Markdown для получения чистого JSON
            show_tool_calls=True,
            model=Nebius(
                id="Qwen/Qwen3-30B-A3B-fast",
                api_key=api_key
            )
        )
        
        # Форматируем сообщение
        formatted_message = {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": f"Please analyze this code using {server_name} with the following parameters: {tool_args}"
                }
            ]
        }
        
        # Запускаем анализ
        response = await agent.arun(formatted_message)
        logger.info(f"Успешное выполнение для {server_name}")
        return response.content
        
    except Exception as e:
        logger.error(f"Ошибка выполнения {server_name}: {str(e)}")
        return f"Error running {server_name}: {str(e)}"

async def run_fix_agent(message):
    """Запускает агента для исправления кода"""
    if not api_key:
        return "Error: Nebius API key not found in .env file"
    
    agent = Agent(
        tools=[],
        instructions=dedent("""\
            You are an intelligent code refactoring assistant.
            Based on the vulnerabilities detected, propose a corrected version of the code.
            Return only the full updated source code, without any additional commentary or markup.
        """),
        markdown=False,
        show_tool_calls=False,
        model=Nebius(
            id="Qwen/Qwen3-30B-A3B-fast",
            api_key=api_key
        )
    )
    try:
        response = await agent.arun(message)
        return response.content
    except Exception as e:
        return f"Error proposing fixes: {e}"

async def process_file(file_obj, custom_checks, selected_servers):
    """Обрабатывает файл с помощью выбранных MCP серверов"""
    if not file_obj:
        return "", "", ""
    
    try:
        # Сохраняем загруженный файл
        temp_dir = tempfile.gettempdir()
        file_path = os.path.join(temp_dir, file_obj.name)
        
        # Получаем содержимое файла из объекта Gradio
        with open(file_obj.name, 'r', encoding='utf-8') as f:
            file_content = f.read()
            
        with open(file_path, "w", encoding='utf-8') as f:
            f.write(file_content)
        
        # Подготавливаем сообщение для всех серверов
        if custom_checks:
            user_message = (
                f"Please analyze this code for {custom_checks}, "
                f"using the most comprehensive settings available:\n\n{file_content}"
            )
        else:
            user_message = (
                f"Please perform a full vulnerability and security analysis on this code, "
                f"selecting the highest intensity settings:\n\n{file_content}"
            )
        
        # Запускаем все анализаторы параллельно
        tasks = {
            server: asyncio.create_task(run_mcp_agent(user_message, server))
            for server in selected_servers
        }
        
        # Собираем результаты
        raw_outputs = {
            server: re.sub(r"<think>.*?</think>", "", await task, flags=re.DOTALL).strip()
            for server, task in tasks.items()
        }

        # Преобразуем raw_outputs в читаемый текст для Markdown
        markdown_output = "\n\n".join(
            f"### {name.upper()}:\n```json\n{json.dumps(json.loads(raw)['results'] if 'results' in json.loads(raw) else json.loads(raw), indent=2)}\n```"
            for name, raw in raw_outputs.items()
        )

        # Читаем оригинальный код
        with open(file_path, 'r', encoding='utf-8') as f_in:
            orig_code = f_in.read()
        
        # Подготавливаем промпт для исправлений
        orig_name = os.path.basename(file_path)
        fix_prompt = f"""Below is the full source code of '{orig_name}':
```python
{orig_code}
```
Please generate a corrected version of this code, addressing all security vulnerabilities. Return only the full updated source code."""
        
        # Получаем исправленный код
        fixed_code = await run_fix_agent(fix_prompt)
        
        # Очищаем код от блоков <think>
        cleaned_code = re.sub(r"<think>.*?</think>", "", fixed_code, flags=re.DOTALL).strip()
        
        # Генерируем diff
        diff_text = generate_simple_diff(orig_code, cleaned_code, orig_name)
        
        return markdown_output, diff_text, cleaned_code
        
    except Exception as e:
        logger.error(f"Ошибка при обработке файла: {str(e)}")
        return f"❌ Произошла ошибка: {str(e)}", "", ""

async def check_all_servers():
    """Проверяет доступность всех MCP серверов"""
    unavailable_servers = []
    for server_name, config in MCP_SERVERS.items():
        if not check_port(config["port"]):
            unavailable_servers.append(f"{server_name} (порт {config['port']})")
    return unavailable_servers

def process_file_sync(file_obj, custom_checks, selected_servers):
    """Синхронная обертка для process_file"""
    return asyncio.run(process_file(file_obj, custom_checks, selected_servers))

# Создаем интерфейс Gradio
with gr.Blocks(title="Security Tools MCP Agent") as demo:
    gr.Markdown("# 🔒 Security Tools MCP Agent")
    
    with gr.Row():
        with gr.Column(scale=1):
            file_input = gr.File(
                label="Upload a code file",
                file_types=[".py", ".js", ".java", ".go", ".rb"]
            )
            custom_checks = gr.Textbox(
                label="Enter specific checks or tools to use (optional)",
                placeholder="e.g., SQL injection, shell injection, detect secrets"
            )
            server_checkboxes = gr.CheckboxGroup(
                choices=list(MCP_SERVERS.keys()),
                value=list(MCP_SERVERS.keys()),
                label="Select MCP Servers"
            )
            scan_button = gr.Button("Run Scan", variant="primary")
    
    with gr.Row():
        with gr.Column(scale=1):
            analysis_output = gr.Markdown(label="Security Analysis Results")
            diff_output = gr.Textbox(label="Proposed Code Fixes", lines=10)
            fixed_code_output = gr.Code(label="Fixed Code", language="python")
            download_button = gr.File(label="Download corrected file")
    
    def update_download_button(fixed_code):
        if fixed_code:
            temp_dir = tempfile.gettempdir()
            fixed_path = os.path.join(temp_dir, "fixed_code.py")
            with open(fixed_path, "w") as f:
                f.write(fixed_code)
            return fixed_path
        return None
    
    scan_button.click(
        fn=process_file_sync,
        inputs=[file_input, custom_checks, server_checkboxes],
        outputs=[analysis_output, diff_output, fixed_code_output]
    ).then(
        fn=update_download_button,
        inputs=[fixed_code_output],
        outputs=[download_button]
    )

if __name__ == "__main__":
    try:
        # Инициализируем все MCP инструменты при старте
        asyncio.run(init_all_tools())
        
        logger.info("Запуск Security Tools MCP Agent...")
        demo.launch(share=True)
    except Exception as e:
        logger.error(f"Ошибка запуска приложения: {str(e)}")
        sys.exit(1)
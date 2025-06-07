import asyncio
import os
import tempfile
import gradio as gr
from textwrap import dedent
from agno.agent import Agent
from agno.tools.mcp import MCPTools
from agno.models.nebius import Nebius
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from dotenv import load_dotenv
import base64
import difflib
import re

# Загружаем переменные окружения из .env файла
load_dotenv()
api_key = os.getenv("NEBIUS_API_KEY")
if not api_key:
    raise ValueError("NEBIUS_API_KEY not found in .env file")

# Конфигурация MCP серверов
MCP_SERVERS = {
    "bandit": {
        "url": "http://localhost:7860/gradio_api/mcp/sse",
        "description": "Python code security analysis"
    },
    "detect_secrets": {
        "url": "http://localhost:7861/gradio_api/mcp/sse",
        "description": "Secret detection in code"
    },
    "pip_audit": {
        "url": "http://localhost:7862/gradio_api/mcp/sse",
        "description": "Python package vulnerability scanning"
    },
    "circle_test": {
        "url": "http://localhost:7863/gradio_api/mcp/sse",
        "description": "Security policy compliance checking"
    },
    "semgrep": {
        "url": "http://localhost:7864/gradio_api/mcp/sse",
        "description": "Advanced static code analysis"
    }
}

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

async def run_mcp_agent(message, server_name):
    """Запускает агента для конкретного MCP сервера"""
    if not api_key:
        return "Error: Nebius API key not found in .env file"
    
    if server_name not in MCP_SERVERS:
        return f"Error: Unknown MCP server {server_name}"
    
    try:
        server_params = StdioServerParameters(
            command="npx",
            args=[
                "-y",
                "mcp-remote",
                MCP_SERVERS[server_name]["url"],
                "--transport",
                "sse-only"
            ],
            env={}
        )
        
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                mcp_tools = MCPTools(session=session)
                await mcp_tools.initialize()
                
                agent = Agent(
                    tools=[mcp_tools],
                    instructions=dedent("""\
                        You are an intelligent security assistant with access to MCP tools.
                        - Automatically select and invoke the appropriate tool(s) based on the user's request.
                        - Always choose the highest intensity settings available.
                        - If the user specifies particular checks, focus on those.
                        - Return results in markdown-friendly format.
                    """),
                    markdown=True,
                    show_tool_calls=True,
                    model=Nebius(
                        id="Qwen/Qwen3-30B-A3B-fast",
                        api_key=api_key
                    )
                )
                
                response = await agent.arun(message)
                return response.content
                
    except Exception as e:
        return f"Error running {server_name} MCP: {str(e)}"

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
        return "", ""
    
    try:
        # Сохраняем загруженный файл
        temp_dir = tempfile.gettempdir()
        file_path = os.path.join(temp_dir, file_obj.name)
        
        # Получаем содержимое файла из объекта Gradio
        with open(file_obj.name, 'r', encoding='utf-8') as f:
            file_content = f.read()
            
        with open(file_path, "w", encoding='utf-8') as f:
            f.write(file_content)
        
        # Запускаем анализ на всех выбранных серверах
        results = []
        for server in selected_servers:
            if custom_checks:
                user_message = (
                    f"Please analyze the file at path '{file_path}' for {custom_checks}, "
                    f"using the most comprehensive settings available."
                )
            else:
                user_message = (
                    f"Please perform a full vulnerability and security analysis on the file at path '{file_path}', "
                    f"selecting the highest intensity settings."
                )
            
            result = await run_mcp_agent(user_message, server)
            results.append(f"## {server.upper()} Analysis\n{result}")
        
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
        
        # Объединяем результаты анализа
        analysis_results = "\n\n".join(results)
        
        return analysis_results, diff_text, cleaned_code
        
    except Exception as e:
        return f"An error occurred: {str(e)}", "", ""

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
        fn=process_file,
        inputs=[file_input, custom_checks, server_checkboxes],
        outputs=[analysis_output, diff_output, fixed_code_output]
    ).then(
        fn=update_download_button,
        inputs=[fixed_code_output],
        outputs=[download_button]
    )

if __name__ == "__main__":
    demo.launch(share=True)
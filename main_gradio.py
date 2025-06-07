import asyncio
import os
import tempfile
import gradio as gr
from textwrap import dedent
from agno.agent import Agent
from agno.tools.mcp import MCPTools
from agno.models.nebius import Nebius
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from dotenv import load_dotenv
import base64
import difflib
import re

# Загружаем переменные окружения из .env файла
load_dotenv()
api_key = os.getenv("NEBIUS_API_KEY")
if not api_key:
    raise ValueError("NEBIUS_API_KEY not found in .env file")

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

async def run_bandit_agent(message):
    if not api_key:
        return "Error: Nebius API key not found in .env file"
    
    try:
        # Используем HTTP транспорт вместо stdio
        async with streamablehttp_client("http://localhost:7860/mcp") as (read, write, _):
            async with ClientSession(read, write) as session:
                # Инициализируем сессию с правильными параметрами
                await session.initialize()
                
                mcp_tools = MCPTools(session=session)
                await mcp_tools.initialize()
                
                agent = Agent(
                    tools=[mcp_tools],
                    instructions=dedent("""\
                        You are an intelligent, universal security assistant with access to multiple MCP tools (e.g., bandit_scan, bandit_profile_scan, detect_secrets_scan, etc.).
                        - Automatically select and invoke the appropriate tool(s) based on the user's request.
                        - Always choose the highest intensity settings available (e.g., severity_level: high, confidence_level: high) for the most thorough analysis.
                        - If the user specifies particular checks or tools (e.g., SQL injection, shell injection), focus on those; otherwise, perform a comprehensive vulnerability scan of the uploaded file.
                        - Support code in any language by using the corresponding MCP tool for that language.
                        - Call MCP tools using JSON-RPC over stdio and return results in markdown-friendly format.
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
        return f"Error: {str(e)}"

async def run_fix_agent(message):
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

async def process_file(file_obj, custom_checks):
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
        
        # Подготавливаем промпт для анализа безопасности
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
        
        # Запускаем анализ безопасности напрямую
        await run_bandit_agent(user_message)
        
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
        
        return diff_text, cleaned_code
        
    except Exception as e:
        return f"An error occurred: {str(e)}", ""

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
            scan_button = gr.Button("Run Scan", variant="primary")
    
    with gr.Row():
        with gr.Column(scale=1):
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
        inputs=[file_input, custom_checks],
        outputs=[diff_output, fixed_code_output]
    ).then(
        fn=update_download_button,
        inputs=[fixed_code_output],
        outputs=[download_button]
    )

if __name__ == "__main__":
    demo.launch(share=True)
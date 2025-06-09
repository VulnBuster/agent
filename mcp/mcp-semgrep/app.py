#!/usr/bin/env python3
"""
MCP server for Semgrep - a tool for static analysis of code
"""

import gradio as gr
import subprocess
import json
import os
import tempfile
from typing import Dict

def semgrep_scan(
    code_input: str,
    scan_type: str = "code",
    rules: str = "p/default",
    output_format: str = "json"
) -> Dict:
    """
    Сканирует код с помощью Semgrep.
    
    Args:
        code_input (str): Код для сканирования или путь к файлу/директории
        scan_type (str): Тип сканирования - 'code' для прямого кода или 'path' для файла/директории
        rules (str): Правила для сканирования (например, 'p/default' или путь к файлу правил)
        output_format (str): Формат вывода - 'json' или 'text'
    
    Returns:
        Dict: Результаты сканирования
    """
    try:
        # Создаем временный файл или используем существующий путь
        if scan_type == "code":
            # Создаем временный файл с кодом
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_file:
                tmp_file.write(code_input)
                target_path = tmp_file.name
        else:
            # Используем существующий путь
            target_path = code_input
            if not os.path.exists(target_path):
                return {
                    "error": f"Path not found: {target_path}",
                    "success": False
                }
        
        # Строим команду semgrep
        cmd = ["semgrep", "scan"]
        
        # Добавляем правила
        cmd.extend(["--config", rules])
        
        # Добавляем формат вывода
        if output_format == "json":
            cmd.extend(["--json"])
        
        # Добавляем путь для сканирования
        cmd.append(target_path)
        
        # Выполняем команду
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Удаляем временный файл, если он был создан
        if scan_type == "code":
            try:
                os.unlink(target_path)
            except:
                pass
        
        # Обрабатываем результат
        if output_format == "json":
            try:
                output_data = json.loads(result.stdout) if result.stdout else {}
                return {
                    "success": True,
                    "results": output_data,
                    "stderr": result.stderr,
                    "return_code": result.returncode
                }
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "error": "JSON parsing error",
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode
                }
        else:
            return {
                "success": True,
                "output": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Error executing Semgrep: {str(e)}"
        }

def semgrep_list_rules() -> Dict:
    """
    Получает список доступных правил Semgrep.
    
    Returns:
        Dict: Список правил
    """
    try:
        cmd = ["semgrep", "list-rules"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            rules = []
            for line in result.stdout.split('\n'):
                if line.strip():
                    rules.append(line.strip())
            return {
                "success": True,
                "rules": rules
            }
        else:
            return {
                "success": False,
                "error": f"Error listing rules: {result.stderr}"
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Error executing Semgrep: {str(e)}"
        }

# Создаем Gradio интерфейс
with gr.Blocks(title="Semgrep MCP") as demo:
    gr.Markdown("# 🔍 Semgrep Scanner")
    gr.Markdown("Static analysis tool with MCP support")
    
    with gr.Tab("Basic Scanning"):
        with gr.Row():
            with gr.Column():
                scan_type = gr.Radio(
                    choices=["code", "path"],
                    value="code",
                    label="Scan Type"
                )
                code_input = gr.Textbox(
                    lines=10,
                    placeholder="Enter code or path to scan...",
                    label="Code or Path"
                )
                rules = gr.Textbox(
                    value="p/default",
                    label="Rules (e.g., p/default or path to rules file)"
                )
                output_format = gr.Dropdown(
                    choices=["json", "text"],
                    value="json",
                    label="Output Format"
                )
                scan_btn = gr.Button("🔍 Scan", variant="primary")
            
            with gr.Column():
                scan_output = gr.JSON(label="Scan Results")
        
        scan_btn.click(
            fn=semgrep_scan,
            inputs=[code_input, scan_type, rules, output_format],
            outputs=scan_output
        )
    
    with gr.Tab("Available Rules"):
        rules_btn = gr.Button("📋 List Rules", variant="secondary")
        rules_output = gr.JSON(label="Available Rules")
        
        rules_btn.click(
            fn=semgrep_list_rules,
            inputs=[],
            outputs=rules_output
        )
    
    with gr.Tab("Examples"):
        gr.Markdown("""
        ## 🚨 Examples of code to scan:
        
        ### 1. SQL Injection
        ```python
        def get_user(user_id):
            query = f"SELECT * FROM users WHERE id = {user_id}"
            return db.execute(query)
        ```
        
        ### 2. Command Injection
        ```python
        import subprocess
        def run_command(command):
            subprocess.call(f"ls {command}", shell=True)
        ```
        
        ### 3. Path Traversal
        ```python
        def read_file(filename):
            with open(f"/home/user/{filename}", "r") as f:
                return f.read()
        ```
        """)

if __name__ == "__main__":
    import time
    print("🔄 Starting Semgrep MCP Server...")
    time.sleep(2)  # Стабилизационная задержка
    
    # Добавляем health endpoint
    from fastapi import FastAPI
    app = FastAPI()
    
    @app.get("/health")
    def health_check():
        return {"status": "healthy", "service": "semgrep-mcp"}
    
    demo.queue()\
        .launch(
            mcp_server=True,
            server_name="0.0.0.0",
            server_port=7860,
            app=app  # Добавляем FastAPI app с health endpoint
        )

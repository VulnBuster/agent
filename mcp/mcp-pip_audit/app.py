#!/usr/bin/env python3
"""
MCP server for pip-audit - a tool for scanning Python environments for known vulnerabilities
"""

import subprocess
import json
from typing import Dict
import gradio as gr

def pip_audit_scan() -> Dict:
    """
    Scans Python environments for known vulnerabilities using pip-audit with basic settings.
    
    Returns:
        Dict: Scan results
    """
    try:
        cmd = ["pip-audit", "--format", "json"]

        print(f"Executing command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        stdout, stderr = result.stdout, result.stderr
        return_code = result.returncode

        if return_code != 0:
            print(f"pip-audit command failed with return code {return_code}")
            print(f"Stderr: {stderr}")
            return {
                "success": False,
                "error": f"pip-audit command failed with return code {return_code}",
                "stdout": stdout,
                "stderr": stderr,
                "return_code": return_code
            }

        try:
            output_data = json.loads(stdout) if stdout else {}
            return {
                "success": True,
                "results": output_data,
                "stderr": stderr,
                "return_code": return_code
            }
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
            print(f"Raw stdout: {stdout}")
            return {
                "success": False,
                "error": "JSON parsing error: " + str(e),
                "stdout": stdout,
                "stderr": stderr,
                "return_code": return_code
            }
            
    except Exception as e:
        print(f"Error executing pip-audit: {str(e)}")
        return {
            "success": False,
            "error": f"Error executing pip-audit: {str(e)}"
        }

# Create Gradio interface
with gr.Blocks(title="Pip Audit MCP") as demo:
    gr.Markdown("# 🛡️ Pip Audit Scanner")
    gr.Markdown("Vulnerability scanning tool for Python environments with MCP support")

    with gr.Tab("Basic Scanning"):
        scan_btn = gr.Button("🔍 Run Basic Audit", variant="primary")
        scan_output = gr.JSON(label="Audit Results")

        scan_btn.click(
            fn=pip_audit_scan,
            inputs=[],
            outputs=scan_output
        )

if __name__ == "__main__":
    import time
    print("🔄 Starting Pip-Audit MCP Server...")
    time.sleep(2)  # Стабилизационная задержка
    
    # Добавляем health endpoint
    from fastapi import FastAPI
    app = FastAPI()
    
    @app.get("/health")
    def health_check():
        return {"status": "healthy", "service": "pip-audit-mcp"}
    
    demo.queue()\
        .launch(
            mcp_server=True,
            server_name="0.0.0.0",
            server_port=7860,
            app=app  # Добавляем FastAPI app с health endpoint
        )

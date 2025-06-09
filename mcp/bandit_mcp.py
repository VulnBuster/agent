import gradio as gr
import subprocess
import json
import os
import tempfile
from typing import Dict, List, Optional
from pathlib import Path


@gr.mcp(                       # ①  регистрируем функцию как MCP-tool
    name="bandit_scan",
    description="Scan code or path with Bandit and return JSON"
)
def bandit_scan(
    code_input: str,
    scan_type: str = "code",
    severity_level: str = "low",
    confidence_level: str = "low",
    output_format: str = "json"
) -> Dict:
    """
    Analyzes Python code for security issues using Bandit.
    
    Args:
        code_input (str): Python code for analysis or path to file/directory
        scan_type (str): Scan type - 'code' for direct code or 'path' for file/directory
        severity_level (str): Minimum severity level - 'low', 'medium', 'high'
        confidence_level (str): Minimum confidence level - 'low', 'medium', 'high'
        output_format (str): Output format - 'json', 'txt', 'xml'
    
    Returns:
        Dict: Security analysis results
    """
    try:
        # Create temporary file or use existing path
        if scan_type == "code":
            # Create temporary file with code
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_file:
                tmp_file.write(code_input)
                target_path = tmp_file.name
        else:
            # Use existing path
            target_path = code_input
            if not os.path.exists(target_path):
                return {
                    "error": f"Path not found: {target_path}",
                    "success": False
                }
        
        # Build bandit command
        cmd = ["bandit"]
        
        # Add severity level flags
        if severity_level == "medium":
            cmd.append("-ll")
        elif severity_level == "high":
            cmd.append("-lll")
        
        # Add confidence level flags
        if confidence_level == "medium":
            cmd.append("-ii")
        elif confidence_level == "high":
            cmd.append("-iii")
        
        # Add output format
        if output_format == "json":
            cmd.extend(["-f", "json"])
        elif output_format == "xml":
            cmd.extend(["-f", "xml"])
        
        # Add recursive scanning for directories
        if scan_type == "path" and os.path.isdir(target_path):
            cmd.append("-r")
        
        # Add scan target path
        cmd.append(target_path)
        
        # Execute command
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Remove temporary file if created
        if scan_type == "code":
            try:
                os.unlink(target_path)
            except:
                pass
        
        # Process result
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
            "error": f"Error executing Bandit: {str(e)}"
        }

@gr.mcp(name="bandit_baseline",
        description="Create or compare a Bandit baseline file")
def bandit_baseline(
    target_path: str,
    baseline_file: str
) -> Dict:
    """
    Creates baseline file for Bandit or compares with existing baseline.
    
    Args:
        target_path (str): Path to code for analysis
        baseline_file (str): Path to baseline file
    
    Returns:
        Dict: Result of baseline creation or comparison
    """
    try:
        if not os.path.exists(target_path):
            return {
                "error": f"Path not found: {target_path}",
                "success": False
            }
        
        # If baseline file doesn't exist, create it
        if not os.path.exists(baseline_file):
            cmd = ["bandit", "-r", target_path, "-f", "json", "-o", baseline_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return {
                "success": True,
                "action": "created",
                "message": f"Baseline file created: {baseline_file}",
                "return_code": result.returncode,
                "stderr": result.stderr
            }
        else:
            # Compare with existing baseline
            cmd = ["bandit", "-r", target_path, "-b", baseline_file, "-f", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            try:
                output_data = json.loads(result.stdout) if result.stdout else {}
                return {
                    "success": True,
                    "action": "compared",
                    "results": output_data,
                    "return_code": result.returncode,
                    "stderr": result.stderr
                }
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "error": "JSON parsing error when comparing with baseline",
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"Error working with baseline: {str(e)}"
        }
    

@gr.mcp(name="bandit_profile_scan",
        description="Run Bandit with a predefined profile")
def bandit_profile_scan(
    target_path: str,
    profile_name: str = "ShellInjection"
) -> Dict:
    """
    Runs Bandit with a specific security profile.
    
    Args:
        target_path (str): Path to code for analysis
        profile_name (str): Profile name (e.g., 'ShellInjection')
    
    Returns:
        Dict: Analysis results using the profile
    """
    try:
        if not os.path.exists(target_path):
            return {
                "error": f"Path not found: {target_path}",
                "success": False
            }
        
        cmd = ["bandit", "-p", profile_name, "-f", "json"]
        
        if os.path.isdir(target_path):
            cmd.extend(["-r", target_path])
        else:
            cmd.append(target_path)
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        try:
            output_data = json.loads(result.stdout) if result.stdout else {}
            return {
                "success": True,
                "profile": profile_name,
                "results": output_data,
                "return_code": result.returncode,
                "stderr": result.stderr
            }
        except json.JSONDecodeError:
            return {
                "success": False,
                "error": "JSON parsing error",
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Error executing profile scan: {str(e)}"
        }

# Create Gradio interfaces
with gr.Blocks(title="Bandit Security Scanner MCP") as demo:
    gr.Markdown("# 🔒 Bandit Security Scanner")
    gr.Markdown("Python code security analyzer with MCP support")
    
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
                    placeholder="Enter Python code or path to file/directory...",
                    label="Code or Path"
                )
                severity = gr.Dropdown(
                    choices=["low", "medium", "high"],
                    value="low",
                    label="Minimum Severity Level"
                )
                confidence = gr.Dropdown(
                    choices=["low", "medium", "high"],
                    value="low", 
                    label="Minimum Confidence Level"
                )
                output_format = gr.Dropdown(
                    choices=["json", "txt"],
                    value="json",
                    label="Output Format"
                )
                scan_btn = gr.Button("🔍 Scan", variant="primary")
            
            with gr.Column():
                scan_output = gr.JSON(label="Scan Results")
        
        scan_btn.click(
            fn=bandit_scan,
            inputs=[code_input, scan_type, severity, confidence, output_format],
            outputs=scan_output
        )
    
    with gr.Tab("Baseline Management"):
        with gr.Row():
            with gr.Column():
                baseline_path = gr.Textbox(
                    label="Project Path",
                    placeholder="/path/to/your/project"
                )
                baseline_file = gr.Textbox(
                    label="Baseline File Path",
                    placeholder="/path/to/baseline.json"
                )
                baseline_btn = gr.Button("📋 Create/Compare Baseline", variant="secondary")
            
            with gr.Column():
                baseline_output = gr.JSON(label="Baseline Results")
        
        baseline_btn.click(
            fn=bandit_baseline,
            inputs=[baseline_path, baseline_file],
            outputs=baseline_output
        )
    
    with gr.Tab("Profile Scanning"):
        with gr.Row():
            with gr.Column():
                profile_path = gr.Textbox(
                    label="Project Path",
                    placeholder="/path/to/your/project"
                )
                profile_name = gr.Dropdown(
                    choices=["ShellInjection", "SqlInjection", "Crypto", "Subprocess"],
                    value="ShellInjection",
                    label="Security Profile"
                )
                profile_btn = gr.Button("🎯 Scan with Profile", variant="secondary")
            
            with gr.Column():
                profile_output = gr.JSON(label="Profile Scan Results")
        
        profile_btn.click(
            fn=bandit_profile_scan,
            inputs=[profile_path, profile_name],
            outputs=profile_output
        )
    
    with gr.Tab("Examples"):
        gr.Markdown("""
        ## 🚨 Vulnerable code examples for testing:
        
        ### 1. Using eval()
        ```python
        user_input = "print('hello')"
        eval(user_input)  # B307: Use of possibly insecure function
        ```
        
        ### 2. Hardcoded password
        ```python
        password = "secret123"  # B105: Possible hardcoded password
        ```
        
        ### 3. Insecure subprocess
        ```python
        import subprocess
        subprocess.call("ls -la", shell=True)  # B602: subprocess call with shell=True
        ```
        
        ### 4. Using pickle
        ```python
        import pickle
        data = pickle.loads(user_data)  # B301: Pickle usage
        ```
        """)

if __name__ == "__main__":
    demo.queue(concurrency_count=8)\
    .launch(mcp_server=True, server_name="0.0.0.0", server_port=7860)

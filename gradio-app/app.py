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
import difflib
import re
import aiohttp
import logging


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()
api_key = os.getenv("NEBIUS_API_KEY")
if not api_key:
    raise ValueError("NEBIUS_API_KEY not found in .env file")


MCP_SERVERS = {
    "bandit": {
        "url": os.environ.get("MCP_BANDIT_URL", "http://mcp-bandit:7860/gradio_api/mcp/sse"),
        "description": "Python code security analysis"
    },
    "detect_secrets": {
        "url": os.environ.get("MCP_DETECT_SECRETS_URL", "http://mcp-detect-secrets:7860/gradio_api/mcp/sse"),
        "description": "Secret detection in code"
    },
    "pip_audit": {
        "url": os.environ.get("MCP_PIP_AUDIT_URL", "http://mcp-pip-audit:7860/gradio_api/mcp/sse"),
        "description": "Python package vulnerability scanning"
    },
    "circle_test": {
        "url": os.environ.get("MCP_CIRCLE_TEST_URL", "http://mcp-circle-test:7860/gradio_api/mcp/sse"),
        "description": "Security policy compliance checking"
    },
    "semgrep": {
        "url": os.environ.get("MCP_SEMGREP_URL", "http://mcp-semgrep:7860/gradio_api/mcp/sse"),
        "description": "Advanced static code analysis"
    }
}



def generate_simple_diff(original_content: str, updated_content: str, file_path: str) -> str:
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
    if not api_key:
        return "Error: Nebius API key not found in .env file"
    
    if server_name not in MCP_SERVERS:
        return f"Error: Unknown MCP server {server_name}"
    

    
    max_connection_attempts = 2  # decrease attempts for faster response
    
    for attempt in range(max_connection_attempts):
        try:
            logger.info(f"Attempting to connect to {server_name} (attempt {attempt + 1}/{max_connection_attempts})")
            logger.info(f"Server URL: {MCP_SERVERS[server_name]['url']}")
            
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
            
            try:
                async with asyncio.timeout(30):  # Уменьшен с 60 до 30 секунд
                    async with stdio_client(server_params) as (read, write):
                        async with ClientSession(read, write) as session:
                            await asyncio.sleep(1)  # Уменьшен с 2 до 1 секунды
                            
                            logger.info(f"Starting MCP session for {server_name}")
                            
                            mcp_tools = MCPTools(session=session)
                            try:
                                async with asyncio.timeout(15):  # decrease timeout for faster response
                                    await mcp_tools.initialize()
                                logger.info(f"MCP tools initialized successfully for {server_name}")
                            except asyncio.TimeoutError:
                                logger.error(f"MCP tools initialization timeout for {server_name}")
                                if attempt == max_connection_attempts - 1:
                                    return f"Error: MCP tools initialization timeout for {server_name}"
                                continue
                            except Exception as tools_error:
                                logger.error(f"MCP tools initialization failed for {server_name}: {tools_error}")
                                if attempt == max_connection_attempts - 1:
                                    return f"Error: Failed to initialize MCP tools for {server_name}: {str(tools_error)}"
                                continue  
                            if server_name == "bandit":
                                instructions = """🛡️ BANDIT Security Analyst - Python Code Analysis

## 🔧 bandit_scan()
**Параметры**:
- `code_input` (str) - **код ИЛИ путь** к файлу/директории  
- `scan_type="path"` - **"code"** для прямого кода или **"path"** для файла/директории
- `severity_level="medium"` - **"low"** (все), **"medium"** (сбалансированно), **"high"** (критичные)
- `confidence_level="medium"` - **"low"** (все), **"medium"** (сбалансированно), **"high"** (точные)

## 🚀 СТРАТЕГИЯ:
```python
bandit_scan(code_input="/path/to/file", scan_type="path", severity_level="medium", confidence_level="medium")
```

## 📊 ПРИОРИТИЗАЦИЯ:
- **🚨 CRITICAL**: RCE, Command injection, Shell execution
- **⚠️ HIGH**: SQL injection, Hardcoded passwords  
- **🔶 MEDIUM**: Crypto issues, Unsafe imports
- **📋 LOW**: Code style, Deprecation warnings

**Результат**: Полный JSON + объяснение каждой уязвимости с номером строки и способом исправления."""
                            
                            elif server_name == "semgrep":
                                instructions = """🛡️ SEMGREP Security Analyst - Static Code Analysis

## 🎯 semgrep_scan()
**Параметры**:
- `code_input` (str) - **код ИЛИ путь** к файлу/директории
- `scan_type="path"` - **"code"** для прямого кода или **"path"** для файла/директории  
- `rules="p/security-audit"` - **"p/default"**, **"p/security-audit"**, **"p/owasp-top-ten"**
- `output_format="json"` - формат вывода

## 🚀 СТРАТЕГИЯ:
```python
semgrep_scan(code_input="/path/to/file", scan_type="path", rules="p/security-audit")
```

## 📊 ПРИОРИТИЗАЦИЯ:
- **🚨 CRITICAL**: OWASP Top 10 violations
- **⚠️ HIGH**: XSS, CSRF, Path traversal
- **🔶 MEDIUM**: Input validation, Auth bypasses  
- **📋 LOW**: Code patterns, Best practices

**Результат**: Полный JSON + объяснение каждого правила с ID, severity и способом исправления."""
                            
                            elif server_name == "detect_secrets":
                                instructions = """🛡️ DETECT-SECRETS Security Analyst - Secret Detection

## 🔍 detect_secrets_scan()  
**Параметры**:
- `code_input` (str) - **код ИЛИ путь** к файлу/директории
- `scan_type="path"` - **"code"** для прямого кода или **"path"** для файла/директории
- `base64_limit=3.0` - лимит энтропии base64 (ниже = строже)
- `hex_limit=2.0` - лимит энтропии hex (ниже = строже)  
- `exclude_secrets=""` - regex исключений для секретов

## 🚀 СТРАТЕГИЯ:
```python
detect_secrets_scan(code_input="/path/to/file", scan_type="path", base64_limit=3.0, hex_limit=2.0)
```

## 📊 ПРИОРИТИЗАЦИЯ:
- **🚨 CRITICAL**: API keys, Private keys, OAuth tokens
- **⚠️ HIGH**: Database credentials, Hardcoded passwords
- **🔶 MEDIUM**: High entropy strings
- **📋 LOW**: Potential false positives

**Результат**: Полный JSON + объяснение каждого найденного секрета с типом, номером строки и рекомендациями."""
                            
                            elif server_name == "pip_audit":
                                instructions = """🛡️ PIP-AUDIT Security Analyst - Dependency Vulnerability Scanner

## 🛡️ pip_audit_scan()
**Параметры**: Не требует (сканирует текущее окружение)
**Возвращает**: JSON с уязвимыми пакетами и CVE

## 🚀 СТРАТЕГИЯ:
```python
pip_audit_scan()  # всегда для текущего окружения  
```

## 📊 ПРИОРИТИЗАЦИЯ:
- **🚨 CRITICAL**: CVE 9.0-10.0, RCE vulnerabilities
- **⚠️ HIGH**: CVE 7.0-8.9, Data exposure  
- **🔶 MEDIUM**: CVE 4.0-6.9, DoS vulnerabilities
- **📋 LOW**: CVE 0.1-3.9, Minor issues

**Результат**: Список уязвимых пакетов с CVE ID, severity и версиями для обновления."""
                            
                            elif server_name == "circle_test":
                                instructions = """🛡️ CIRCLE-TEST Security Analyst - Corporate Policy Compliance

## 🔒 check_violation()
**Параметры**:  
- `prompt` (str) - **код для проверки** (только прямой код)
- `policies` (Dict) - словарь из 21 политики безопасности

## 🚀 СТРАТЕГИЯ:
```python
check_violation(prompt="code_content", policies={...})
```

## 📊 ПРИОРИТИЗАЦИЯ:
- **🚨 CRITICAL**: Production credentials, Debug statements в prod
- **⚠️ HIGH**: HTTP без валидации, SQL инъекции, Path traversal
- **🔶 MEDIUM**: TODO в продакшн коде, незафиксированные версии  
- **📋 LOW**: Licensing issues, deprecated API

**Результат**: Нарушения корпоративных политик с объяснением и способами исправления."""
                            
                            else:
                                instructions = f"""🛡️ {server_name.upper()} Security Analyst

Analyze the provided file for security vulnerabilities using available tools.
Show complete results and explain each finding clearly with priority levels."""

                            agent = Agent(
                                tools=[mcp_tools],
                                instructions=instructions,
                                markdown=True,
                                show_tool_calls=True,
                                model=Nebius(
                                    id="Qwen/Qwen3-235B-A22B",
                                    api_key=api_key
                                )
                            )
                            
                            try:
                                async with asyncio.timeout(60):  # Уменьшен с 120 до 60 секунд
                                    response = await agent.arun(message)
                                return response.content
                            except asyncio.TimeoutError:
                                logger.error(f"Agent execution timeout for {server_name}")
                                if attempt == max_connection_attempts - 1:
                                    return f"Error: Agent execution timeout for {server_name}"
                                continue
                            
            except asyncio.TimeoutError:
                logger.error(f"Connection timeout for {server_name} (attempt {attempt + 1})")
                if attempt == max_connection_attempts - 1:
                    return f"Error: Connection timeout for {server_name} after {max_connection_attempts} attempts"
                await asyncio.sleep(2)
                continue
                
        except Exception as e:
            logger.error(f"Error in run_mcp_agent for {server_name} (attempt {attempt + 1}): {str(e)}")
            if attempt == max_connection_attempts - 1:
                return f"Error running {server_name} MCP after {max_connection_attempts} attempts: {str(e)}"
            await asyncio.sleep(2)
            continue
    
    return f"Error: Failed to connect to {server_name} after {max_connection_attempts} attempts"

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

async def process_file(file_obj, custom_checks, selected_servers):
    if not file_obj:
        return "", "", ""
    
    try:
        temp_dir = tempfile.gettempdir()
        file_path = os.path.join(temp_dir, file_obj.name)
        
        with open(file_obj.name, 'r', encoding='utf-8') as f:
            file_content = f.read()
            
        with open(file_path, "w", encoding='utf-8') as f:
            f.write(file_content)
        
        results = []
        successful_analyses = 0
        
        for server in selected_servers:
            if custom_checks:
                user_message = (
                    f"Please analyze the file at path '{file_path}' for {custom_checks}. "
                    f"IMPORTANT: First show detailed analysis results from each security tool, "
                    f"including all vulnerabilities found, their severity levels, and explanations. "
                    f"Use comprehensive settings: for detect_secrets use base64_limit=3.0, hex_limit=2.0; "
                    f"for bandit use severity_level='medium' and confidence_level='medium' for balanced performance; "
                    f"for semgrep use rules='p/security-audit'; "
                    f"run pip_audit_scan() to check dependencies; "
                    f"use check_violation for policy compliance."
                )
            else:
                user_message = (
                    f"Please perform a complete security vulnerability analysis on the file at path '{file_path}'. "
                    f"IMPORTANT: First show detailed analysis results from each security tool, "
                    f"including all vulnerabilities found, their types, severity levels, line numbers, and explanations. "
                    f"Use comprehensive settings: for detect_secrets use base64_limit=3.0, hex_limit=2.0; "
                    f"for bandit use severity_level='medium' and confidence_level='medium' for balanced performance; "
                    f"for semgrep use rules='p/default'; "
                    f"run pip_audit_scan() to check dependencies; "
                    f"use check_violation for policy compliance."
                )
            
            logger.info(f"Starting analysis with {server}...")
            
            is_available, status_msg = await test_mcp_server_connection(server)
            if not is_available:
                logger.warning(f"Server {server} is not accessible: {status_msg}")
                results.append(f"## {server.upper()} Analysis\n❌ **Server not accessible**: {status_msg}\n\nPlease ensure the MCP server is running on the configured port.")
                continue
            
            max_retries = 2
            analysis_successful = False
            
            for attempt in range(max_retries):
                try:
                    logger.info(f"Running analysis with {server} (attempt {attempt + 1}/{max_retries})")
                    result = await run_mcp_agent(user_message, server)
                    
                    if not result.startswith("Error"):
                        results.append(f"## {server.upper()} Analysis\n{result}")
                        successful_analyses += 1
                        analysis_successful = True
                        logger.info(f"✅ {server} analysis completed successfully")
                        break
                    else:
                        logger.warning(f"❌ {server} analysis failed (attempt {attempt + 1}): {result}")
                        if attempt == max_retries - 1:
                            results.append(f"## {server.upper()} Analysis\n❌ **Failed after {max_retries} attempts**\n\n{result}")
                        
                except Exception as e:
                    logger.error(f"❌ {server} analysis error (attempt {attempt + 1}): {str(e)}")
                    if attempt == max_retries - 1:
                        results.append(f"## {server.upper()} Analysis\n❌ **Failed after {max_retries} attempts**\n\nError: {str(e)}")
                
                if attempt < max_retries - 1 and not analysis_successful:
                    logger.info(f"Waiting 3 seconds before retry for {server}...")
                    await asyncio.sleep(3)
        
        with open(file_path, 'r', encoding='utf-8') as f_in:
            orig_code = f_in.read()
        
        if successful_analyses > 0:
            orig_name = os.path.basename(file_path)
            analysis_summary = "\n\n".join(results)
            fix_prompt = f"""Based on the security analysis below, please generate a corrected version of the code.

Security Analysis Results:
{analysis_summary}

Original source code of '{orig_name}':
```python
{orig_code}
```

Please generate a corrected version of this code, addressing the security vulnerabilities found in the analysis above. Return only the full updated source code without any additional commentary."""
            
            try:
                fixed_code = await run_fix_agent(fix_prompt)
                cleaned_code = re.sub(r"<think>.*?</think>", "", fixed_code, flags=re.DOTALL).strip()
                diff_text = generate_simple_diff(orig_code, cleaned_code, orig_name)
            except Exception as fix_error:
                print(f"Error generating fixes: {fix_error}")
                cleaned_code = orig_code
                diff_text = f"❌ **Failed to generate fixes**: {str(fix_error)}"
        else:
            print("⚠️ No successful analyses - skipping code fixes")
            cleaned_code = orig_code
            diff_text = "⚠️ **No fixes generated** - All security analyses failed. Please check MCP server connections."
        
        analysis_results = "\n\n".join(results)
        
        if successful_analyses == 0:
            analysis_results += f"\n\n⚠️ **Warning**: All {len(selected_servers)} security analyses failed. Please check that the MCP servers are running and accessible."
        else:
            analysis_results += f"\n\n✅ **Summary**: {successful_analyses}/{len(selected_servers)} security analyses completed successfully."
        
        return analysis_results, diff_text, cleaned_code
        
    except Exception as e:
        error_msg = f"An error occurred during file processing: {str(e)}"
        print(error_msg)
        return error_msg, "", ""

async def test_mcp_server_connection(server_name):
    if server_name not in MCP_SERVERS:
        return False, f"Unknown server: {server_name}"
    
    server_config = MCP_SERVERS[server_name]
    
    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            test_urls = [
                server_config["url"].replace("/mcp/sse", "/health"),
                server_config["url"].replace("/mcp/sse", ""),
                server_config["url"].replace("/gradio_api/mcp/sse", "")
            ]
            
            for url in test_urls:
                try:
                    async with session.get(url) as response:
                        if response.status in [200, 404]:
                            return await test_mcp_protocol_connection(server_name)
                except aiohttp.ClientError:
                    continue
            
            return False, "HTTP connection failed - server may be down"
            
    except Exception as e:
        return False, f"Connection test failed: {str(e)}"

async def test_mcp_protocol_connection(server_name):
    """Тестирует MCP протокол соединение"""
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
        
        # Quick MCP protocol test with timeout
        async with asyncio.timeout(10):
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    # Just try to create session without full initialization
                    await asyncio.sleep(0.5)  # Brief wait
                    return True, "MCP protocol connection successful"
                    
    except asyncio.TimeoutError:
        return False, "MCP protocol connection timeout"
    except Exception as e:
        return False, f"MCP protocol connection failed: {str(e)}"

async def check_servers_status(selected_servers):
    """Проверяет статус выбранных MCP серверов"""
    if not selected_servers:
        return "⚠️ No servers selected for testing."
    
    status_results = []
    
    # Test servers concurrently for faster results
    async def test_single_server(server):
        is_available, message = await test_mcp_server_connection(server)
        status_icon = "✅" if is_available else "❌"
        server_desc = MCP_SERVERS[server]["description"]
        return f"{status_icon} **{server}** ({server_desc}): {message}"
    
    # Run all tests concurrently
    tasks = [test_single_server(server) for server in selected_servers]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            server = selected_servers[i]
            status_results.append(f"❌ **{server}**: Error during testing - {str(result)}")
        else:
            status_results.append(result)
    
    # Add summary
    successful_servers = sum(1 for result in results if isinstance(result, str) and result.startswith("✅"))
    total_servers = len(selected_servers)
    
    summary = f"\n\n📊 **Summary**: {successful_servers}/{total_servers} servers are accessible"
    
    if successful_servers == 0:
        summary += "\n\n⚠️ **Warning**: No MCP servers are accessible. Please check that they are running on the configured ports."
    elif successful_servers < total_servers:
        summary += f"\n\n⚠️ **Note**: {total_servers - successful_servers} server(s) are not accessible."
    
    return "\n\n".join(status_results) + summary

# Создаем интерфейс Gradio
with gr.Blocks(title="Security Tools MCP Agent") as demo:
    gr.Markdown("# 🔒 Security Tools MCP Agent")
    gr.Markdown("""
    **Welcome to the Security Analysis Tool!** 
    
    This tool uses MCP (Model Context Protocol) servers to perform comprehensive security analysis on your code files.
    
    📋 **How to use:**
    1. First, **test server connections** to ensure MCP servers are running
    2. Upload a code file (Python, JavaScript, Java, Go, or Ruby)
    3. Optionally specify particular security checks to focus on
    4. Select which security tools to use
    5. Run the security scan to get analysis and automated fixes
    
    ⚠️ **Important**: Make sure your MCP servers are running on the configured ports before starting analysis.
    """)
    
    with gr.Row():
        with gr.Column(scale=1):
            file_input = gr.File(
                label="📁 Upload a code file",
                file_types=[".py", ".js", ".java", ".go", ".rb"]
            )
            custom_checks = gr.Textbox(
                label="🎯 Enter specific checks or tools to use (optional)",
                placeholder="e.g., SQL injection, shell injection, detect secrets"
            )
            server_checkboxes = gr.CheckboxGroup(
                choices=list(MCP_SERVERS.keys()),
                value=list(MCP_SERVERS.keys()),
                label="🛠️ Select MCP Security Tools"
            )
            
            with gr.Row():
                test_connection_button = gr.Button("🔍 Test Server Connections", variant="secondary")
                scan_button = gr.Button("🔍 Run Security Scan", variant="primary")
            
            server_status = gr.Markdown(label="📊 Server Connection Status")
    
    with gr.Row():
        with gr.Column(scale=1):
            analysis_output = gr.Markdown(label="🔍 Security Analysis Results")
            diff_output = gr.Textbox(label="🔧 Proposed Code Fixes (Diff)", lines=10)
            fixed_code_output = gr.Code(label="✅ Fixed Code", language="python")
            download_button = gr.File(label="💾 Download corrected file")
    
    def update_download_button(fixed_code):
        if fixed_code:
            temp_dir = tempfile.gettempdir()
            fixed_path = os.path.join(temp_dir, "fixed_code.py")
            with open(fixed_path, "w") as f:
                f.write(fixed_code)
            return fixed_path
        return None
    
    # Event handlers
    
    test_connection_button.click(
        fn=check_servers_status,
        inputs=[server_checkboxes],
        outputs=[server_status]
    )
    
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
    print("🚀 Launching Security Tools MCP Agent...")
    print("📡 Connecting to existing MCP servers...")
    print("⚠️ Make sure all MCP servers are running on configured ports before starting analysis")
    demo.launch(share=True)
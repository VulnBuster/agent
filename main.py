import asyncio
import os
import tempfile
import streamlit as st
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
load_dotenv()


# Page config
st.set_page_config(page_title="Bandit MCP Agent", page_icon="🔒", layout="wide")



# Setup sidebar for API key
with st.sidebar:    
    api_key = st.text_input("Enter your Nebius API key", type="password")
    if api_key:
        os.environ["NEBIUS_API_KEY"] = api_key
    st.markdown("---")

# File upload and optional checks
uploaded_file = st.file_uploader("Upload a code file", type=["py", "js", "java", "go", "rb"])
if uploaded_file:
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.read())
    st.info(f"File saved to {file_path}")
else:
    file_path = None

custom_checks = st.text_input(
    "Enter specific checks or tools to use (optional)",
    placeholder="e.g., SQL injection, shell injection, detect secrets"
)

# Generate diff function
def generate_simple_diff(original_content: str, updated_content: str, file_path: str) -> str:
    """
    Генерирует простой diff между оригинальным и обновленным содержимым
    """
    # Generate unified diff
    diff_lines = list(difflib.unified_diff(
        original_content.splitlines(keepends=True),
        updated_content.splitlines(keepends=True),
        fromfile=f"{file_path} (original)",
        tofile=f"{file_path} (modified)",
        n=3
    ))
    if not diff_lines:
        return "No changes detected."
    # Count additions and deletions
    added_lines = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
    removed_lines = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))
    # Build plain diff content
    diff_content = "".join(diff_lines)
    stats = f"\n📊 Changes: +{added_lines} additions, -{removed_lines} deletions"
    return diff_content + stats

# Main function to run agent
async def run_bandit_agent(message):
    if not api_key:
        return "Error: Nebius API key not provided"
    
    try:
        server_params = StdioServerParameters(
            command="npx",
            args=[
                "-y",
                "mcp-remote",
                "http://localhost:7860/gradio_api/mcp/sse",
                "--transport",
                "sse-only"
            ],
            env={}
        )
        
        # Create client session with proper error handling
        try:
            async with stdio_client(server_params) as (read, write):
                try:
                    async with ClientSession(read, write) as session:
                        # Initialize MCP toolkit
                        mcp_tools = MCPTools(session=session)
                        try:
                            await mcp_tools.initialize()
                            
                            # Create agent
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
                                    api_key="..."
                                )
                            )
                            
                            # Run agent with error handling
                            try:
                                response = await agent.arun(message)
                                return response.content
                            except Exception as agent_error:
                                return f"Error running agent: {str(agent_error)}"
                                
                        except Exception as init_error:
                            return f"Error initializing MCP tools: {str(init_error)}"
                            
                except Exception as session_error:
                    return f"Error creating client session: {str(session_error)}"
                    
        except Exception as client_error:
            return f"Error creating stdio client: {str(client_error)}"
            
    except Exception as e:
        return f"Error setting up server parameters: {str(e)}"

# Function to propose code fixes using LLM
async def run_fix_agent(message):
    if not api_key:
        return "Error: Nebius API key not provided"
    # Create an agent without MCP tools for code refactoring
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
            id="Qwen/Qwen3-30B-A3B",
            api_key=api_key
        )
    )
    try:
        response = await agent.arun(message)
        return response.content
    except Exception as e:
        return f"Error proposing fixes: {e}"

# Run button
if st.button("Run Scan", type="primary", use_container_width=True):
    if not file_path:
        st.error("Please upload a file before scanning")
    else:
        with st.spinner("Scanning and generating fixes..."):
            try:
                # Prepare prompt for security analysis
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
                # Run security analysis
                report = asyncio.run(run_bandit_agent(user_message))
                # Run code fix proposal with full source
                # Read original file content
                with open(file_path, 'r') as f_in:
                    orig_code = f_in.read()
                # Prepare fix prompt including the source code
                orig_name = os.path.basename(file_path)
                fix_prompt = f"""Below is the full source code of '{orig_name}':
```python
{orig_code}
```
Please generate a corrected version of this code, addressing all security vulnerabilities. Return only the full updated source code."""
                fixed_code = asyncio.run(run_fix_agent(fix_prompt))
                # Save fixed code to temp file
                temp_dir = tempfile.gettempdir()
                fixed_filename = f"fixed_{orig_name}"
                fixed_path = os.path.join(temp_dir, fixed_filename)
                with open(fixed_path, "w") as f:
                    f.write(fixed_code)
                # Clean out any <think> blocks from fixed code
                cleaned_code = re.sub(r"<think>.*?</think>", "", fixed_code, flags=re.DOTALL).strip()
                # Generate mechanical diff
                diff_text = generate_simple_diff(orig_code, cleaned_code, orig_name)
                # Display report and diff
                st.markdown(f"## 🔍🛡️ Security Scan Report for `{orig_name}`")
                st.markdown("---")
                st.markdown(report)
                st.markdown(f"## 🛠️ Proposed Code Fixes for `{orig_name}`")
                st.code(diff_text, language="diff")
                # Download button for fixed file
                st.download_button(
                    label="Download corrected file",
                    data=cleaned_code,
                    file_name=fixed_filename,
                    mime="text/plain"
                )
            except Exception as e:
                st.error(f"An error occurred: {e}")
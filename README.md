# 🔒 Security Tools MCP Agent

A universal security agent that combines the capabilities of multiple static code analysis tools through MCP (Model Context Protocol).

## 🌟 Features

- **Multiple Security Tools:**
  - Bandit: Python code security analysis
  - Detect Secrets: Secret detection in code
  - Pip Audit: Python package vulnerability scanning
  - Circle Test: Security policy compliance checking
  - Semgrep: Advanced static code analysis

- **User-friendly Web Interface:**
  - File upload for analysis
  - Security tool selection
  - Detailed reports
  - Fix suggestions
  - Corrected code download

## 🚀 Installation

1. Install Node.js and npm:
   - Download and install Node.js from the official website: https://nodejs.org/
   - Verify the installation by running in terminal:
     ```bash
     node --version
     npm --version
     ```
   - If not installed, install using:
     ```bash
     brew install node
     ```

2. Clone the repository:
```bash
git clone <repository-url>
cd agent
```

3. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # for Linux/Mac
# or
venv\Scripts\activate  # for Windows
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Install required security tools:
```bash
# Bandit
pip install bandit

# Detect Secrets
pip install detect-secrets

# Pip Audit
pip install pip-audit

# Semgrep
pip install semgrep

# Circle Test dependencies
pip install aiohttp python-dotenv
```

## 🏃‍♂️ Running

1. Start all MCP servers in separate terminals:

```bash
# Terminal 1 - Bandit MCP
python ../MCP-Hackathon/bandit_mcp.py

# Terminal 2 - Detect Secrets MCP
python ../MCP-Hackathon/detect_secrets_mcp.py

# Terminal 3 - Pip Audit MCP
python ../MCP-Hackathon/pip_audit_mcp.py

# Terminal 4 - Circle Test MCP
python ../MCP-Hackathon/circle_test_mcp.py

# Terminal 5 - Semgrep MCP
python ../MCP-Hackathon/semgrep_mcp.py
```

2. Start the agent:
```bash
python main_gradio.py
```

3. Open the web interface:
```
http://localhost:8501
```

## 🎯 Usage

1. Enter your Nebius API key in the sidebar
2. Select security tools to use
3. Upload a file for analysis
4. (Optional) Specify particular checks
5. Click "Run Security Analysis"
6. Review the report and suggested fixes
7. Download the corrected code version

## 🔧 Configuration

### MCP Server Ports:
- Bandit: 7860
- Detect Secrets: 7861
- Pip Audit: 7862
- Circle Test: 7863
- Semgrep: 7864

### Environment Variables:
- `NEBIUS_API_KEY`: Your Nebius API key

## 📝 Usage Examples

### Basic Scanning:
1. Upload a Python file
2. Select all tools
3. Click "Run Security Analysis"

### Specific Checks:
1. Upload a file
2. Enter "SQL injection, shell injection"
3. Select desired tools
4. Run the analysis

## ⚠️ Notes

- Ensure all MCP servers are running before using the agent
- For complete analysis, it's recommended to use all tools
- Some tools may require additional configuration
- Analysis results may vary depending on selected tools

## 🔗 Useful Links

- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Detect Secrets Documentation](https://github.com/Yelp/detect-secrets)
- [Pip Audit Documentation](https://pypi.org/project/pip-audit/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MCP Specification](https://spec.modelcontextprotocol.io/) 
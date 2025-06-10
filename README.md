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

1. **Install Node.js and npm:**
   ```bash
   # Download and install Node.js from: https://nodejs.org/
   # Verify installation:
   node --version
   npm --version
   
   # On macOS with Homebrew:
   brew install node
   ```

2. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd agent
   ```

3. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # for Linux/Mac
   # or
   venv\Scripts\activate  # for Windows
   ```

4. **Install main application dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Install MCP server dependencies:**
   ```bash
   # Install dependencies for each MCP server
   cd ../mcp/mcp-bandit
   pip install -r requirements.txt

   cd ../mcp-detect_secrets
   pip install -r requirements.txt

   cd ../mcp-pip_audit
   pip install -r requirements.txt

   cd ../mcp-circle_test
   pip install -r requirements.txt

   cd ../mcp-semgrep
   pip install -r requirements.txt
   ```

6. **Configure environment variables:**
   ```bash

   cp .env.example .env  # if exists, or create .env file
   # Edit .env file and add your Nebius API key:
   # NEBIUS_API_KEY=your_api_key_here
   # CIRCLE_API_URL=link
   ```

## 🏃‍♂️ Running the Application

### Step 1: Start all MCP servers

Open 5 separate terminals and run each MCP server:

```bash
# Terminal 1 - Bandit MCP Server (Port 7861)
cd agent/mcp/mcp-bandit
python app.py

# Terminal 2 - Detect Secrets MCP Server (Port 7862)  
cd agent/mcp/mcp-detect_secrets
python app.py

# Terminal 3 - Pip Audit MCP Server (Port 7863)
cd agent/mcp/mcp-pip_audit
python app.py

# Terminal 4 - Circle Test MCP Server (Port 7864)
cd agent/mcp/mcp-circle_test
python app.py

# Terminal 5 - Semgrep MCP Server (Port 7865)
cd agent/mcp/mcp-semgrep
python app.py
```

### Step 2: Start the main application

```bash
# Terminal 6 - Main Gradio Application
cd agent
python main.py
```

### Step 3: Access the web interface

Open your browser and go to:
```
http://localhost:7860
```

## 🎯 Usage

1. **Upload a code file** (supports .py, .js, .java, .go, .rb)
2. **Select security tools** to use for analysis
3. **(Optional)** Specify particular checks in the text field
4. **Click "Run Scan"** to start the security analysis
5. **Review the analysis results** in the interface
6. **Download the corrected code** if fixes are suggested

## 🔧 Configuration

### MCP Server Ports:
- **Bandit**: 7861
- **Detect Secrets**: 7862  
- **Pip Audit**: 7863
- **Circle Test**: 7864
- **Semgrep**: 7865

### Main Application Port:
- **Gradio App**: 7860

### Environment Variables:
Create a `.env` file in the `gradio-app` directory:
```bash
NEBIUS_API_KEY=your_nebius_api_key_here
CIRCLE_API_URL=your_circle_api_url_here  # for Circle Test
```

## 📝 Usage Examples

### Basic Security Scanning:
1. Upload a Python file
2. Keep all tools selected (default)
3. Click "Run Scan"
4. Review comprehensive security analysis

### Targeted Security Checks:
1. Upload any supported code file
2. Enter specific checks: "SQL injection, shell injection, secrets"
3. Select relevant tools (e.g., Bandit, Detect Secrets)
4. Run the analysis for focused results

### Vulnerability Assessment:
1. Upload your project files one by one
2. Use all tools for comprehensive coverage
3. Review detailed vulnerability reports
4. Download fixed versions of your code

## 🐛 Troubleshooting

### Common Issues:

1. **"Server not available" errors:**
   - Ensure all MCP servers are running on their respective ports
   - Check if ports 7861-7865 are not occupied by other processes

2. **"API key not found" errors:**
   - Make sure `.env` file exists in `gradio-app` directory
   - Verify `NEBIUS_API_KEY` is set correctly

3. **JSON parsing errors:**
   - This usually indicates MCP server communication issues
   - Restart the problematic MCP server
   - Check server logs for detailed error information

4. **Port conflicts:**
   ```bash
   # Check if ports are in use:
   lsof -i :7860-7865
   
   # Kill processes if needed:
   kill -9 <PID>
   ```

## 🔗 Useful Links

- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Detect Secrets Documentation](https://github.com/Yelp/detect-secrets)
- [Pip Audit Documentation](https://pypi.org/project/pip-audit/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [Gradio Documentation](https://gradio.app/docs/)

## 📁 Project Structure

```
test_docker/agent/
├── README.md                 # This file
├── .gitignore               # Git ignore rules
├── gradio-app/              # Main application
│   ├── main.py             # Gradio web interface
│   ├── requirements.txt    # Python dependencies
│   └── .env                # Environment variables
└── mcp/                    # MCP servers
    ├── mcp-bandit/         # Bandit security scanner
    ├── mcp-detect_secrets/ # Secret detection
    ├── mcp-pip_audit/      # Package vulnerability scanner
    ├── mcp-circle_test/    # Policy compliance checker
    └── mcp-semgrep/        # Advanced static analysis
```

## ⚠️ Important Notes

- **All MCP servers must be running** before starting the main application
- **Gradio interface** will be available on `http://localhost:7860`
- **Network connectivity** is required for Nebius API calls
- **File upload limits** apply based on Gradio's default settings
- **Analysis time** varies depending on file size and selected tools 
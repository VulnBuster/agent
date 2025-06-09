#!/bin/bash

# Security Tools MCP Agent - Launcher Script
# Запускает все MCP серверы и главное приложение

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Директории
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS_DIR="$SCRIPT_DIR/logs"
PIDS_FILE="$SCRIPT_DIR/.pids"

# Создаем директорию для логов
mkdir -p "$LOGS_DIR"

# Функция для логирования
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

# Функция для запуска MCP сервера
start_mcp_server() {
    local name="$1"
    local port="$2"
    local script_path="$3"
    
    log "🚀 Starting $name MCP Server on port $port..."
    
    cd "$(dirname "$script_path")"
    
    # Активируем виртуальное окружение и запускаем в фоне
    source "$SCRIPT_DIR/venv/bin/activate" && python "$script_path" > "$LOGS_DIR/$name.log" 2>&1 &
    local pid=$!
    
    # Сохраняем PID в файл
    echo "$name:$pid" >> "$PIDS_FILE"
    
    log "✅ $name started with PID $pid, logs: $LOGS_DIR/$name.log"
    
    # Возвращаемся в корневую директорию
    cd "$SCRIPT_DIR"
}

# Функция проверки доступности порта
check_port() {
    local port="$1"
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "http://localhost:$port/health" > /dev/null 2>&1; then
            return 0
        fi
        sleep 1
        ((attempt++))
    done
    return 1
}

# Проверяем, что процессы не запущены
if [ -f "$PIDS_FILE" ]; then
    error "Сервисы уже запущены. Сначала выполните ./stop.sh"
    exit 1
fi

# Создаем новый файл PID
: > "$PIDS_FILE"

log "🎯 Starting Security Tools MCP Agent..."

# 1. Проверяем зависимости
log "🔍 Checking dependencies..."

if ! command -v python3 &> /dev/null; then
    error "Python3 not found. Please install Python 3.11+"
    exit 1
fi

if ! command -v npx &> /dev/null; then
    error "npx not found. Please install Node.js"
    exit 1
fi

# Проверяем виртуальное окружение
if [ ! -d "venv" ]; then
    log "🔨 Creating virtual environment..."
    python3 -m venv venv
fi

# Активируем виртуальное окружение и проверяем Gradio
source venv/bin/activate
if ! python -c "import gradio" &> /dev/null; then
    warn "Gradio not found. Installing requirements..."
    pip install -r gradio-app/requirements.txt
fi

log "✅ Dependencies OK"

# 2. Запускаем MCP серверы
log "🚀 Starting MCP Servers..."

start_mcp_server "bandit" "7861" "$SCRIPT_DIR/mcp/mcp-bandit/app.py"
start_mcp_server "detect-secrets" "7862" "$SCRIPT_DIR/mcp/mcp-detect_secrets/app.py"  
start_mcp_server "pip-audit" "7863" "$SCRIPT_DIR/mcp/mcp-pip_audit/app.py"
start_mcp_server "circle-test" "7864" "$SCRIPT_DIR/mcp/mcp-circle_test/app.py"
start_mcp_server "semgrep" "7865" "$SCRIPT_DIR/mcp/mcp-semgrep/app.py"

# 3. Ждем готовности серверов
log "⏳ Waiting for MCP servers to be ready..."

# Проверяем каждый сервер
servers=("bandit:7861" "detect-secrets:7862" "pip-audit:7863" "circle-test:7864" "semgrep:7865")

for server_port in "${servers[@]}"; do
    IFS=':' read -r server port <<< "$server_port"
    log "⏳ Checking $server on port $port..."
    
    if check_port "$port"; then
        log "✅ $server is ready on port $port"
    else
        error "❌ $server failed to start on port $port"
        log "📋 Checking logs..."
        tail -10 "$LOGS_DIR/$server.log"
        ./stop.sh
        exit 1
    fi
done

# 4. Запускаем главное приложение
log "🎯 Starting main Gradio application..."

cd "$SCRIPT_DIR/gradio-app"
source "$SCRIPT_DIR/venv/bin/activate" && python app.py > "$LOGS_DIR/gradio-app.log" 2>&1 &
main_pid=$!
echo "gradio-app:$main_pid" >> "$PIDS_FILE"

log "✅ Main application started with PID $main_pid"

# 5. Ждем готовности главного приложения
log "⏳ Waiting for main application..."

if check_port "7860"; then
    log "✅ Main application is ready on port 7860"
else
    error "❌ Main application failed to start"
    ./stop.sh
    exit 1
fi

# 6. Финальное сообщение
log ""
log "🎉 Security Tools MCP Agent is ready!"
log ""
log "🌐 Web Interface: http://localhost:7860"
log "📊 MCP Servers:"
log "   • Bandit (Python security): http://localhost:7861"
log "   • Detect-Secrets: http://localhost:7862"
log "   • Pip-Audit: http://localhost:7863"
log "   • Circle-Test: http://localhost:7864"
log "   • Semgrep: http://localhost:7865"
log ""
log "📋 Logs directory: $LOGS_DIR"
log "🛑 To stop all services: ./stop.sh"
log "📊 To view logs: ./logs.sh"
log ""
log "✨ Happy security scanning!" 
#!/bin/bash

# Security Tools MCP Agent - Stop Script
# Останавливает все MCP серверы и главное приложение

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Директории
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDS_FILE="$SCRIPT_DIR/.pids"

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

# Функция для остановки процесса
stop_process() {
    local name="$1"
    local pid="$2"
    
    if ps -p "$pid" > /dev/null 2>&1; then
        log "🛑 Stopping $name (PID: $pid)..."
        kill "$pid"
        
        # Ждем 5 секунд для graceful shutdown
        local count=0
        while ps -p "$pid" > /dev/null 2>&1 && [ $count -lt 5 ]; do
            sleep 1
            ((count++))
        done
        
        # Если процесс еще работает, принудительно убиваем
        if ps -p "$pid" > /dev/null 2>&1; then
            warn "Force killing $name (PID: $pid)..."
            kill -9 "$pid"
        fi
        
        log "✅ $name stopped"
    else
        warn "$name (PID: $pid) was not running"
    fi
}

log "🛑 Stopping Security Tools MCP Agent..."

# Проверяем существование файла с PID
if [ ! -f "$PIDS_FILE" ]; then
    warn "No PID file found. Services may not be running."
    exit 0
fi

# Останавливаем все процессы из файла PID
while IFS=':' read -r name pid; do
    if [ -n "$name" ] && [ -n "$pid" ]; then
        stop_process "$name" "$pid"
    fi
done < "$PIDS_FILE"

# Удаляем файл PID
rm -f "$PIDS_FILE"

# Дополнительная очистка - поиск оставшихся процессов
log "🔍 Checking for remaining processes..."

# Ищем процессы Python с нашими портами
for port in 7860 7861 7862 7863 7864 7865; do
    pid=$(lsof -ti:$port 2>/dev/null || true)
    if [ -n "$pid" ]; then
        warn "Found process on port $port (PID: $pid), killing..."
        kill -9 "$pid" 2>/dev/null || true
    fi
done

log "✅ All services stopped"
log ""
log "🧹 Cleanup complete!"
log "📊 To view logs: ./logs.sh"
log "🚀 To start again: ./start.sh" 
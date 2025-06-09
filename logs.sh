#!/bin/bash

# Security Tools MCP Agent - Logs Viewer
# Показывает логи всех сервисов

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Директории
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS_DIR="$SCRIPT_DIR/logs"

# Функция для логирования
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

# Проверяем существование директории логов
if [ ! -d "$LOGS_DIR" ]; then
    error "Logs directory not found: $LOGS_DIR"
    exit 1
fi

# Функция для показа логов сервиса
show_service_logs() {
    local service="$1"
    local log_file="$LOGS_DIR/$service.log"
    
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}🔍 LOGS: $service${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    
    if [ -f "$log_file" ]; then
        echo -e "${YELLOW}📄 File: $log_file${NC}"
        echo -e "${YELLOW}📊 Size: $(du -h "$log_file" | cut -f1)${NC}"
        echo -e "${YELLOW}🕒 Modified: $(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$log_file" 2>/dev/null || date -r "$log_file" 2>/dev/null)${NC}"
        echo ""
        
        # Показываем последние 50 строк
        tail -50 "$log_file"
    else
        error "Log file not found: $log_file"
    fi
}

# Показываем меню или конкретный сервис
if [ $# -eq 0 ]; then
    log "📋 Security Tools MCP Agent - Logs"
    log ""
    log "📂 Logs directory: $LOGS_DIR"
    log ""
    
    # Список всех сервисов
    services=("gradio-app" "bandit" "detect-secrets" "pip-audit" "circle-test" "semgrep")
    
    echo -e "${BLUE}Available services:${NC}"
    for i in "${!services[@]}"; do
        service="${services[$i]}"
        log_file="$LOGS_DIR/$service.log"
        if [ -f "$log_file" ]; then
            size=$(du -h "$log_file" | cut -f1)
            echo -e "  ${GREEN}$((i+1)). $service${NC} (${size})"
        else
            echo -e "  ${RED}$((i+1)). $service${NC} (no log)"
        fi
    done
    
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo -e "  ./logs.sh                    - Show this menu"
    echo -e "  ./logs.sh <service>          - Show logs for specific service"
    echo -e "  ./logs.sh all                - Show logs for all services"
    echo -e "  ./logs.sh follow <service>   - Follow logs for specific service"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "  ./logs.sh gradio-app"
    echo -e "  ./logs.sh bandit"
    echo -e "  ./logs.sh all"
    echo -e "  ./logs.sh follow gradio-app"
    
elif [ "$1" = "all" ]; then
    # Показываем все логи
    services=("gradio-app" "bandit" "detect-secrets" "pip-audit" "circle-test" "semgrep")
    
    for service in "${services[@]}"; do
        show_service_logs "$service"
    done
    
elif [ "$1" = "follow" ] && [ -n "$2" ]; then
    # Следим за логами в реальном времени
    service="$2"
    log_file="$LOGS_DIR/$service.log"
    
    if [ -f "$log_file" ]; then
        log "👀 Following logs for $service (Ctrl+C to stop)"
        echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
        tail -f "$log_file"
    else
        error "Log file not found: $log_file"
        exit 1
    fi
    
elif [ -n "$1" ]; then
    # Показываем логи конкретного сервиса
    service="$1"
    show_service_logs "$service"
    
else
    error "Invalid usage. Run './logs.sh' for help."
    exit 1
fi 
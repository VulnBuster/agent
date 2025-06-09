#!/bin/bash

echo "🚀 Тестирование времени запуска Security Tools MCP Agent (Docker)"
echo "=================================================================="

# Засекаем время начала
start_time=$(date +%s)
echo "📅 Время начала: $(date)"

# Очищаем старые контейнеры и образы
echo "🧹 Очистка старых контейнеров..."
docker compose down --remove-orphans --volumes 2>/dev/null || true

# Удаляем старые образы для чистого теста
echo "🗑️  Удаление старых образов..."
docker system prune -f 2>/dev/null || true

# Запускаем сборку и запуск с выводом логов
echo "🔨 Запуск сборки и старта всех сервисов..."
docker compose up --build -d

# Ждем готовности всех сервисов
echo "⏳ Ожидание готовности сервисов..."

# Функция проверки готовности сервиса
check_service() {
    local service_name=$1
    local port=$2
    local max_attempts=60
    local attempt=1
    
    echo "🔍 Проверка сервиса $service_name на порту $port..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "http://localhost:$port" >/dev/null 2>&1; then
            echo "✅ $service_name готов (попытка $attempt)"
            return 0
        fi
        
        if [ $((attempt % 10)) -eq 0 ]; then
            echo "⏳ $service_name еще не готов (попытка $attempt/$max_attempts)"
        fi
        
        sleep 2
        ((attempt++))
    done
    
    echo "❌ $service_name не готов после $max_attempts попыток"
    return 1
}

# Проверяем готовность всех сервисов
services_ready=0

# Основное Gradio приложение
if check_service "gradio-app" "7860"; then
    ((services_ready++))
fi

# MCP сервисы
if check_service "mcp-bandit" "7861"; then
    ((services_ready++))
fi

if check_service "mcp-detect-secrets" "7862"; then
    ((services_ready++))
fi

if check_service "mcp-pip-audit" "7863"; then
    ((services_ready++))
fi

if check_service "mcp-circle-test" "7864"; then
    ((services_ready++))
fi

if check_service "mcp-semgrep" "7865"; then
    ((services_ready++))
fi

# Засекаем время окончания
end_time=$(date +%s)
total_time=$((end_time - start_time))

echo ""
echo "=================================================================="
echo "📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ"
echo "=================================================================="
echo "📅 Время начала:    $(date -r $start_time)"
echo "📅 Время окончания: $(date -r $end_time)"
echo "⏱️  Общее время:     ${total_time} секунд ($(($total_time / 60)) мин $(($total_time % 60)) сек)"
echo "✅ Готовых сервисов: $services_ready/6"

if [ $services_ready -eq 6 ]; then
    echo "🎉 ВСЕ СЕРВИСЫ ГОТОВЫ!"
    echo "🌐 Градио интерфейс: http://localhost:7860"
    echo ""
    echo "📋 Доступные MCP сервисы:"
    echo "   • Bandit:         http://localhost:7861"
    echo "   • Detect-Secrets: http://localhost:7862" 
    echo "   • Pip-Audit:      http://localhost:7863"
    echo "   • Circle-Test:    http://localhost:7864"
    echo "   • Semgrep:        http://localhost:7865"
else
    echo "⚠️  НЕ ВСЕ СЕРВИСЫ ГОТОВЫ"
    echo "🔍 Проверьте логи: docker compose logs"
fi

echo ""
echo "🐳 Статус контейнеров:"
docker compose ps

echo ""
echo "💾 Использование ресурсов:"
docker stats --no-stream

echo ""
echo "🔧 Команды для управления:"
echo "   Логи:       docker compose logs -f"
echo "   Остановка:  docker compose down"
echo "   Рестарт:    docker compose restart" 
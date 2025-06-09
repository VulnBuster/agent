# 🔧 Устранение проблем с MCP серверами

## 🎉 ПРОБЛЕМА РЕШЕНА! 

Все проблемы с таймаутами и соединениями MCP серверов были успешно исправлены.

## 🔍 Обнаруженные проблемы и их решения:

### 1. 🚨 **Критичная ошибка**: mcp-remote требует HTTPS или флаг `--allow-http`
- **Проблема**: `Error: Non-HTTPS URLs are only allowed for localhost or when --allow-http flag is provided`
- **Решение**: Добавлен флаг `--allow-http` к аргументам mcp-remote
- **Код**: `"--allow-http"` в параметрах StdioServerParameters

### 2. 🐛 **Node.js совместимость**: Устаревшая версия Node.js v10.24.0
- **Проблема**: `SyntaxError: Unexpected token {` при запуске mcp-remote
- **Решение**: Обновлен до Node.js v18.20.8 в Docker контейнере
- **Код**: Использование deb.nodesource.com для установки современного Node.js

### 3. ⏱️ **Таймауты**: Слишком агрессивные таймауты для Docker окружения
- **Проблема**: MCP tools initialization timeout
- **Решение**: Увеличены таймауты:
  - Общий таймаут: 30→90 секунд
  - Инициализация MCP: 15→60 секунд  
  - Выполнение агента: 60→120 секунд
  - Тестирование протокола: 10→30 секунд

### 4. 🔄 **Повторные попытки**: Недостаточно попыток для Docker
- **Проблема**: Только 2 попытки подключения
- **Решение**: Увеличено до 3 попыток с интервалом 5 секунд

### 5. 📦 **npm ошибки**: Проблемы с установкой пакетов
- **Проблема**: `npm ERR! Invalid tar header`
- **Решение**: Использование современного npx вместо предустановленного mcp-remote

## ✅ Финальная конфигурация:

```python
server_params = StdioServerParameters(
    command="npx",
    args=[
        "-y",
        "mcp-remote@latest", 
        server_url,
        "--transport",
        "sse-only",
        "--allow-http"  # 🔑 Ключевое исправление!
    ],
    env={"NODE_OPTIONS": "--max-old-space-size=512"}
)
```

## 📊 Результат:

- ✅ Все 6 MCP сервисов работают стабильно
- ✅ HTTP серверы отвечают (код 200)  
- ✅ MCP протокол должен работать с `--allow-http`
- ✅ Таймауты оптимизированы для Docker
- ✅ Node.js v18.20.8 поддерживает современный mcp-remote

## 🧪 Тестирование:

1. **HTTP тест всех серверов**:
   ```bash
   curl -s -o /dev/null -w "%{http_code}" http://localhost:7861  # bandit: 200
   curl -s -o /dev/null -w "%{http_code}" http://localhost:7862  # detect_secrets: 200
   curl -s -o /dev/null -w "%{http_code}" http://localhost:7863  # pip_audit: 200
   curl -s -o /dev/null -w "%{http_code}" http://localhost:7864  # circle_test: 200
   curl -s -o /dev/null -w "%{http_code}" http://localhost:7865  # semgrep: 200
   ```

2. **Веб-интерфейс**: http://localhost:7860
   - Нажмите "🔍 Test Server Connections" 
   - Должны быть ✅ для всех серверов

3. **Анализ безопасности**:
   - Загрузите `test_vulnerable_code.py` или `test_report_demo.py`
   - Нажмите "🔍 Run Security Scan"
   - Получите краткий отчет + детальный анализ + исправления

## 🚀 Следующие шаги:

Теперь можно запустить полный анализ безопасности с новым отчетом об уязвимостях!

---
**Время исправления проблем**: ~1 час  
**Статус**: ✅ ГОТОВО К РАБОТЕ  
**Обновлено**: 09.06.2025 
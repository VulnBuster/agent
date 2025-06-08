# 🚀 Quick Start Guide - Security Tools MCP Agent

## ⚡ Быстрый запуск (30 секунд)

1. **Убедитесь, что активировано окружение:**
   ```bash
   source venv_gradio/bin/activate
   ```

2. **Запустите приложение одной командой:**
   ```bash
   python main_gradio.py
   ```
   
   ✅ Приложение автоматически:
   - Запустит все 5 MCP серверов
   - Откроет веб-интерфейс
   - Покажет ссылку для доступа

3. **Откройте в браузере:**
   - Локально: `http://localhost:7865`
   - Публично: будет показан Gradio link

## 🧪 Быстрое тестирование

1. **Загрузите тестовый файл:**
   - Используйте созданный `test_vulnerable_code.py`
   - Или создайте свой файл с уязвимостями

2. **Запустите анализ:**
   - Нажмите "🚀 Start All MCP Servers" (если нужно)
   - Нажмите "🔍 Test Server Connections"
   - Нажмите "🔍 Run Security Scan"

## 📊 Что протестирует система:

### 🔍 detect_secrets:
- Hardcoded passwords
- API keys
- Private keys
- Database credentials

### 🛡️ bandit:
- SQL injection
- Command injection
- Weak cryptography
- Insecure random numbers
- YAML load vulnerabilities

### 🎯 semgrep:
- XSS vulnerabilities
- Path traversal
- Advanced code patterns
- OWASP Top 10 issues

### 📦 pip_audit:
- Package vulnerabilities
- CVE scanning
- Dependency issues

### 🏢 circle_test:
- Corporate policies
- Production code issues
- Debug statements
- TODO comments

## ⚡ Оптимизация производительности

Внесенные улучшения:
- ✅ Автоматический запуск локальных MCP серверов
- ✅ Уменьшены таймауты (60→30→15 сек)
- ✅ Параллельный запуск серверов
- ✅ Уменьшено количество попыток переподключения
- ✅ Автоматический перезапуск упавших серверов

## 🛠️ Устранение проблем

**Если серверы не запускаются:**
```bash
# Проверить окружение
source venv_gradio/bin/activate
python test_system.py

# Перезапустить вручную
python main_gradio.py
```

**Если анализ долго выполняется:**
- Уменьшен размер файла для анализа
- Выберите меньше инструментов
- Используйте специфические проверки

## 📁 Структура проекта:

```
agent/
├── main_gradio.py          # Основное приложение ⭐
├── test_vulnerable_code.py # Тестовый файл с уязвимостями 🧪
├── test_system.py          # Скрипт тестирования системы 🔍
├── mcp/                    # Локальные MCP серверы 📡
├── venv_gradio/           # Виртуальное окружение 🐍
└── .env                   # API ключи 🔑
```

## 🎯 Рекомендуемый workflow:

1. `python main_gradio.py` - запуск системы
2. Загрузка `test_vulnerable_code.py` в интерфейс
3. "🔍 Test Server Connections" - проверка серверов
4. "🔍 Run Security Scan" - полный анализ
5. Просмотр результатов и исправлений
6. Скачивание исправленного кода

---
**Время полного анализа:** ~30-60 секунд (оптимизировано)  
**Поддерживаемые языки:** Python, JavaScript, Java, Go, Ruby 
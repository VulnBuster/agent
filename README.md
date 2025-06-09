# 🔒 Security Tools MCP Agent

Универсальный агент безопасности, объединяющий возможности нескольких инструментов статического анализа кода через MCP (Model Context Protocol).

## 🌟 Возможности

- **Множественные инструменты безопасности:**
  - Bandit: Анализ безопасности Python кода
  - Detect Secrets: Поиск секретов в коде
  - Pip Audit: Сканирование уязвимостей в зависимостях
  - Circle Test: Проверка соответствия политикам безопасности
  - Semgrep: Продвинутый статический анализ кода

- **Удобный веб-интерфейс:**
  - Загрузка файлов для анализа
  - Выбор инструментов безопасности
  - Детальные отчеты
  - Предложения по исправлению
  - Скачивание исправленного кода

## 🚀 Установка

1. Установите Node.js и npm:
   - Скачайте и установите Node.js с официального сайта: https://nodejs.org/
   - Убедитесь, что установка прошла успешно, выполнив в терминале:
     ```bash
     node --version
     npm --version
     ```
  – если нет, то установите
    ```bash
    brew install node
    ```

2. Клонируйте репозиторий:
```bash
git clone <repository-url>
cd agent
```

3. Создайте виртуальное окружение:
```bash
python -m venv venv
source venv/bin/activate  # для Linux/Mac
# или
venv\Scripts\activate  # для Windows
```

4. Установите зависимости:
```bash
pip install -r requirements.txt
```

5. Установите необходимые инструменты безопасности:
```bash
# Bandit
pip install bandit

# Detect Secrets
pip install detect-secrets

# Pip Audit
pip install pip-audit

# Semgrep
pip install semgrep

# Circle Test зависимости
pip install aiohttp python-dotenv
```

## 🏃‍♂️ Запуск

1. Запустите все MCP серверы в отдельных терминалах:

```bash
# Терминал 1 - Bandit MCP
python ../MCP-Hackathon/bandit_mcp.py

# Терминал 2 - Detect Secrets MCP
python ../MCP-Hackathon/detect_secrets_mcp.py

# Терминал 3 - Pip Audit MCP
python ../MCP-Hackathon/pip_audit_mcp.py

# Терминал 4 - Circle Test MCP
python ../MCP-Hackathon/circle_test_mcp.py

# Терминал 5 - Semgrep MCP
python ../MCP-Hackathon/semgrep_mcp.py
```

2. Запустите агента:
```bash
python main_gradio.py
```

3. Откройте веб-интерфейс:
```
http://localhost:8501
```

## 🎯 Использование

1. Введите ваш Nebius API ключ в боковой панели
2. Выберите инструменты безопасности для использования
3. Загрузите файл для анализа
4. (Опционально) Укажите конкретные проверки
5. Нажмите "Run Security Analysis"
6. Просмотрите отчет и предложенные исправления
7. Скачайте исправленную версию кода

## 🔧 Конфигурация

### Порты MCP серверов:
- Bandit: 7860
- Detect Secrets: 7861
- Pip Audit: 7862
- Circle Test: 7863
- Semgrep: 7864

### Переменные окружения:
- `NEBIUS_API_KEY`: Ваш API ключ Nebius

## 📝 Примеры использования

### Базовое сканирование:
1. Загрузите Python файл
2. Выберите все инструменты
3. Нажмите "Run Security Analysis"

### Специфические проверки:
1. Загрузите файл
2. Введите "SQL injection, shell injection"
3. Выберите нужные инструменты
4. Запустите анализ

## ⚠️ Примечания

- Убедитесь, что все MCP серверы запущены перед использованием агента
- Для полного анализа рекомендуется использовать все инструменты
- Некоторые инструменты могут требовать дополнительной конфигурации
- Результаты анализа могут отличаться в зависимости от выбранных инструментов

## 🔗 Полезные ссылки

- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Detect Secrets Documentation](https://github.com/Yelp/detect-secrets)
- [Pip Audit Documentation](https://pypi.org/project/pip-audit/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MCP Specification](https://spec.modelcontextprotocol.io/) 
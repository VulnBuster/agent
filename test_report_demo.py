#!/usr/bin/env python3
"""
Демонстрационный файл для тестирования отчета безопасности
Содержит различные типы уязвимостей для проверки всех анализаторов
"""

import os
import subprocess
import sqlite3
import hashlib
import random

# КРИТИЧНЫЕ уязвимости
def execute_user_command(user_input):
    """Критичная уязвимость: Command Injection"""
    # НЕБЕЗОПАСНО: выполнение пользовательского ввода как команды
    result = subprocess.run(user_input, shell=True, capture_output=True)
    return result.stdout

def sql_query(user_id):
    """Критичная уязвимость: SQL Injection"""
    conn = sqlite3.connect('users.db')
    # НЕБЕЗОПАСНО: прямая вставка пользовательского ввода в SQL
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = conn.execute(query)
    return cursor.fetchall()

# ВЫСОКИЕ уязвимости
API_KEY = "sk-1234567890abcdef"  # Hardcoded API key
DATABASE_PASSWORD = "admin123"   # Hardcoded password
OAUTH_TOKEN = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZwFK"  # OAuth token

def unsafe_file_access(filename):
    """Высокая уязвимость: Path Traversal"""
    # НЕБЕЗОПАСНО: позволяет доступ к любым файлам
    with open(f"/uploads/{filename}", 'r') as f:
        return f.read()

# СРЕДНИЕ уязвимости  
def weak_hash(password):
    """Средняя уязвимость: Weak cryptography"""
    # НЕБЕЗОПАСНО: использование слабого алгоритма хеширования
    return hashlib.md5(password.encode()).hexdigest()

def insecure_random():
    """Средняя уязвимость: Insecure random"""
    # НЕБЕЗОПАСНО: небезопасный генератор случайных чисел для криптографии
    return random.randint(1000, 9999)

# TODO: добавить аутентификацию для этой функции
def admin_function():
    """Средняя уязвимость: TODO в продакшн коде"""
    return "Admin access granted"

# НИЗКИЕ уязвимости
import sys  # unused import

def deprecated_function():
    """Низкая уязвимость: Deprecated function"""
    # FIXME: обновить на новый API
    return os.tempnam()

if __name__ == "__main__":
    print("🧪 Тестовый файл для анализа безопасности")
    print("🔍 Содержит уязвимости всех уровней:")
    print("   🚨 Критичные: Command injection, SQL injection")  
    print("   ⚠️ Высокие: Hardcoded secrets, Path traversal")
    print("   🔶 Средние: Weak crypto, Insecure random, TODO")
    print("   📋 Низкие: Unused imports, Deprecated functions") 
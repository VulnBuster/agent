#!/usr/bin/env python3
"""
Тестовый файл с различными уязвимостями безопасности
для демонстрации работы Security Tools MCP Agent
"""

import os
import subprocess
import sqlite3
import hashlib
import pickle
import yaml
import requests

# 🚨 HARDCODED SECRETS - для detect_secrets
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-1234567890abcdef1234567890abcdef"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2btnjx
-----END RSA PRIVATE KEY-----"""

# 🚨 SQL INJECTION - для bandit и semgrep
def unsafe_database_query(user_input):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Уязвимый SQL запрос
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()

# 🚨 COMMAND INJECTION - для bandit и semgrep  
def unsafe_system_command(filename):
    # Прямое выполнение команды с пользовательским вводом
    os.system(f"cat {filename}")
    subprocess.call(f"ls -la {filename}", shell=True)

# 🚨 INSECURE DESERIALIZATION - для bandit
def unsafe_pickle_load(data):
    return pickle.loads(data)

# 🚨 WEAK CRYPTOGRAPHY - для bandit
def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

# 🚨 YAML LOAD VULNERABILITY - для bandit
def unsafe_yaml_load(yaml_string):
    return yaml.load(yaml_string, Loader=yaml.Loader)

# 🚨 INSECURE HTTP REQUESTS - для bandit и semgrep
def insecure_http_request(url):
    # Отключение проверки SSL
    response = requests.get(url, verify=False)
    return response.text

# 🚨 PATH TRAVERSAL - для semgrep
def unsafe_file_read(filename):
    with open(f"/var/www/uploads/{filename}", 'r') as f:
        return f.read()

# 🚨 XSS VULNERABILITY - для semgrep
def unsafe_html_render(user_input):
    html = f"<div>Hello {user_input}</div>"
    return html

# 🚨 RANDOM NUMBER GENERATION - для bandit
import random
def weak_random():
    return random.random()

# 🚨 INSECURE TEMP FILE - для bandit
import tempfile
def insecure_temp_file():
    temp = tempfile.mktemp()
    with open(temp, 'w') as f:
        f.write("sensitive data")

# 🚨 DEBUG MODE IN PRODUCTION - для circle_test
DEBUG = True
SECRET_KEY = "development_key_not_for_prod"

# 🚨 TODO IN PRODUCTION CODE - для circle_test
def process_payment(amount):
    # TODO: implement proper validation
    return True

# 🚨 HARDCODED IP ADDRESSES - для circle_test
PRODUCTION_SERVER = "192.168.1.100"
DATABASE_HOST = "10.0.0.5"

if __name__ == "__main__":
    # Демонстрация уязвимостей
    print("🔥 Running vulnerable code examples...")
    
    # SQL Injection
    result = unsafe_database_query("admin' OR '1'='1")
    
    # Command Injection
    unsafe_system_command("../../etc/passwd")
    
    # Weak cryptography
    weak_password_hash = weak_hash("password123")
    
    # Insecure HTTP request
    try:
        insecure_http_request("https://example.com")
    except:
        pass
    
    print("✅ Vulnerable code execution completed") 
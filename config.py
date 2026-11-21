"""Конфигурация и константы для менеджера паролей."""

import os

# Директория приложения (папка, в которой находится этот файл)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Путь к файлу базы данных SQLite
DB_NAME = os.path.join(BASE_DIR, "passwords.db")

# Путь к файлу с ключом шифрования Fernet
KEY_FILE = os.path.join(BASE_DIR, ".key")

# Название таблицы для записей паролios
ENTRIES_TABLE = "entries"

# Название таблицы для служебных данных ( хеш мастер-пароля )
META_TABLE = "meta"
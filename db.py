"""Функции для работы с базой данных SQLite3."""

import sqlite3
import hashlib
from typing import Optional, List, Tuple

from config import DB_NAME, ENTRIES_TABLE, META_TABLE


def get_connection() -> sqlite3.Connection:
    """Создать и вернуть соединение с базой данных.

    Returns:
        sqlite3.Connection: Соединение с БД.
    """
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Инициализировать базу данных: создать таблицы, если они не существуют."""
    conn = get_connection()
    cursor = conn.cursor()

    # Таблица для хранения записей паролей
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {ENTRIES_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            login TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Таблица для служебных метаданных (хеш мастер-пароля)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {META_TABLE} (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    """Вычислить хеш SHA-256 от пароля.

    Args:
        password: Пароль в открытом виде.

    Returns:
        str: Хеш в шестнадцатеричном формате.
    """
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def set_master_password(password: str) -> None:
    """Сохранить хеш мастер-пароля в базе данных.

    Args:
        password: Мастер-пароль в открытом виде.
    """
    conn = get_connection()
    cursor = conn.cursor()
    hashed = hash_password(password)
    cursor.execute(
        f"INSERT OR REPLACE INTO {META_TABLE} (key, value) VALUES (?, ?)",
        ("master_password_hash", hashed),
    )
    conn.commit()
    conn.close()


def get_master_password_hash() -> Optional[str]:
    """Получить сохранённый хеш мастер-пароля.

    Returns:
        Optional[str]: Хеш мастер-пароля или None, если не установлен.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT value FROM {META_TABLE} WHERE key = ?",
        ("master_password_hash",),
    )
    row = cursor.fetchone()
    conn.close()
    return row["value"] if row else None


def verify_master_password(password: str) -> bool:
    """Проверить мастер-пароль против сохранённого хеша.

    Args:
        password: Пароль для проверки.

    Returns:
        bool: True, если пароль совпадает, иначе False.
    """
    stored_hash = get_master_password_hash()
    if stored_hash is None:
        return False
    return hash_password(password) == stored_hash


def master_password_exists() -> bool:
    """Проверить, установлен ли мастер-пароль в базе данных.

    Returns:
        bool: True, если мастер-пароль уже задан.
    """
    return get_master_password_hash() is not None


def add_entry(name: str, login: str, encrypted_password: str) -> None:
    """Добавить новую запись в базу данных.

    Args:
        name: Название / источник (например, "Google").
        login: Логин.
        encrypted_password: Зашифрованный пароль.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"""
        INSERT INTO {ENTRIES_TABLE} (name, login, encrypted_password)
        VALUES (?, ?, ?)
        """,
        (name, login, encrypted_password),
    )
    conn.commit()
    conn.close()


def get_entry(name: str) -> Optional[Tuple[str, str]]:
    """Получить запись по названию.

    Args:
        name: Название записи.

    Returns:
        Optional[Tuple[str, str]]: Кортеж (login, encrypted_password) или None.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT login, encrypted_password FROM {ENTRIES_TABLE} WHERE name = ?",
        (name,),
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return row["login"], row["encrypted_password"]
    return None


def list_entries() -> List[Tuple[str, str]]:
    """Получить список всех записей (названия и логины).

    Returns:
        List[Tuple[str, str]]: Список кортежей (name, login).
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT name, login FROM {ENTRIES_TABLE} ORDER BY name")
    rows = cursor.fetchall()
    conn.close()
    return [(row["name"], row["login"]) for row in rows]


def delete_entry(name: str) -> bool:
    """Удалить запись по названию.

    Args:
        name: Название записи для удаления.

    Returns:
        bool: True, если запись была удалена, иначе False.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {ENTRIES_TABLE} WHERE name = ?", (name,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted
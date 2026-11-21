"""
CLI-менеджер паролей с шифрованием.

Классы:
- DatabaseManager: работа с SQLite3 (таблицы паролей и мастер-пароля)
- EncryptionManager: шифрование/дешифрование через Fernet
- PasswordGenerator: основной класс взаимодействия с пользователем

Запуск:
    python .\\password_manager.py

При первом запуске требуется установить мастер-пароль.
При последующих запусках - ввести мастер-пароль.
"""

import hashlib
import os
import random
import sqlite3
import string
import sys
from getpass import getpass

from cryptography.fernet import Fernet


class DatabaseManager:
    """Отвечает за взаимодействие с базой данных SQLite3."""

    def __init__(self, db_name: str = "password.db"):
        """
        Создаёт/подключается к файлу базы данных.

        Args:
            db_name: Имя файла базы данных.
        """
        self.db_name = db_name
        self.conn = sqlite3.connect(db_name)
        self.conn.row_factory = sqlite3.Row

    def init_database(self) -> None:
        """Инициализирует таблицы базы данных, если они не существуют."""
        cursor = self.conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                login TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        self.conn.commit()

    def set_master_password(self, password: str) -> None:
        """Сохраняет хеш мастер-пароля в базе данных.

        Args:
            password: Мастер-пароль в открытом виде.
        """
        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO master_password (id, password_hash) VALUES (1, ?)",
            (password_hash,),
        )
        self.conn.commit()

    def verify_master_password(self, password: str) -> bool:
        """Проверяет мастер-пароль против сохранённого хеша.

        Args:
            password: Пароль для проверки.

        Returns:
            True, если пароль совпадает, иначе False.
        """
        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        cursor = self.conn.cursor()
        cursor.execute("SELECT password_hash FROM master_password WHERE id = 1")
        row = cursor.fetchone()
        if row is None:
            return False
        return row["password_hash"] == password_hash

    def master_password_exists(self) -> bool:
        """Проверяет, установлен ли мастер-пароль.

        Returns:
            True, если мастер-пароль уже задан.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT 1 FROM master_password WHERE id = 1")
        return cursor.fetchone() is not None

    def add_password(self, name: str, login: str, encrypted_password: str) -> None:
        """Добавляет новую запись пароля.

        Args:
            name: Название / источник (например, "Google").
            login: Логин.
            encrypted_password: Зашифрованный пароль.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO passwords (name, login, encrypted_password)
            VALUES (?, ?, ?)
            """,
            (name, login, encrypted_password),
        )
        self.conn.commit()

    def get_password(self, name: str):
        """Возвращает запись пароля по названию.

        Args:
            name: Название записи.

        Returns:
            Объект Row с полями login и encrypted_password, или None.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT login, encrypted_password FROM passwords WHERE name = ?",
            (name,),
        )
        return cursor.fetchone()

    def list_passwords(self):
        """Возвращает список всех записей (название и логин).

        Returns:
            Список объектов Row с полями name и login.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT name, login FROM passwords ORDER BY name")
        return cursor.fetchall()

    def delete_password(self, name: str) -> bool:
        """Удаляет запись пароля по названию.

        Args:
            name: Название записи.

        Returns:
            True, если запись была удалена, иначе False.
        """
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM passwords WHERE name = ?", (name,))
        self.conn.commit()
        return cursor.rowcount > 0
    def close(self) -> None:
        """Закрывает соединение с базой данных."""
        self.conn.close()


class EncryptionManager:
    """Управляет шифрованием и дешифрованием данных через Fernet."""

    def __init__(self, key_file: str = ".key"):
        """
        Проверяет наличие файла ключа. Если есть - считывает,
        если нет - создаёт новый ключ.

        Args:
            key_file: Путь к файлу с ключом шифрования.
        """
        self.key_file = key_file
        self.key = self._load_or_generate_key()
        self.fernet = Fernet(self.key)

    def _load_or_generate_key(self) -> bytes:
        """Загружает ключ из файла или генерирует новый.

        Returns:
            байты ключа Fernet.
        """
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        key = Fernet.generate_key()
        with open(self.key_file, "wb") as f:
            f.write(key)
        return key

    def encrypt(self, data: str) -> str:
        """Шифрует строку данных.

        Args:
            data: Открытый текст для шифрования.

        Returns:
            Зашифрованная строка в base64.
        """
        token = self.fernet.encrypt(data.encode("utf-8"))
        return token.decode("utf-8")

    def decrypt(self, encrypted_data: str) -> str:
        """Расшифровывает строку данных.

        Args:
            encrypted_data: Зашифрованная строка в base64.

        Returns:
            Расшифрованный текст.
        """
        token = self.fernet.decrypt(encrypted_data.encode("utf-8"))
        return token.decode("utf-8")

    def get_password(self, name: str):
        """Возвращает запись пароля по названию.

        Args:
            name: Название записи.

        Returns:
            Объект Row с полями login и encrypted_password, или None.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT login, encrypted_password FROM passwords WHERE name = ?",
            (name,),
        )
        return cursor.fetchone()

    def list_passwords(self):
        """Возвращает список всех записей (название и логин).

        Returns:
            Список объектов Row с полями name и login.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT name, login FROM passwords ORDER BY name")
        return cursor.fetchall()

    def delete_password(self, name: str) -> bool:
        """Удаляет запись пароля по названию.

        Args:
            name: Название записи.

        Returns:
            True, если запись была удалена, иначе False.
        """
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM passwords WHERE name = ?", (name,))
        self.conn.commit()
        return cursor.rowcount > 0

    def close(self) -> None:
        """Закрывает соединение с базой данных."""
        self.conn.close()


class PasswordGenerator:
    """Основной класс взаимодействия с приложением."""

    def __init__(
        self,
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
    ):
        """
        Инициализирует генератор и менеджеры базы/шифрования.

        Args:
            length: Длина пароля по умолчанию (максимум 64).
            use_uppercase: Использовать заглавные буквы.
            use_lowercase: Использовать строчные буквы.
            use_digits: Использовать цифры.
            use_special: Использовать спецсимволы.
        """
        self.length = max(1, min(length, 64))
        self.use_uppercase = use_uppercase
        self.use_lowercase = use_lowercase
        self.use_digits = use_digits
        self.use_special = use_special

        self.db = DatabaseManager("password.db")
        self.db.init_database()
        self.enc = EncryptionManager(".key")

    # ------------------------------------------------------------------
    # Мастер-пароль и аутентификация
    # ------------------------------------------------------------------
    def setup_master_password(self) -> None:
        """Устанавливает мастер-пароль, если он ещё не задан."""
        if self.db.master_password_exists():
            return

        print("=== Первый запуск: настройка мастер-пароля ===")
        while True:
            p1 = getpass("Придумайте мастер-пароль: ")
            p2 = getpass("Повторите мастер-пароль: ")
            if p1 == p2:
                if len(p1) == 0:
                    print("Пароль не может быть пустым. Попробуйте снова.")
                    continue
                self.db.set_master_password(p1)
                print("Мастер-пароль установлен.\n")
                return
            print("Пароли не совпадают. Попробуйте снова.")

    def authenticate(self) -> bool:
        """Запрашивает мастер-пароль и проверяет его.

        Returns:
            True, если аутентикация прошла успешно.
        """
        if not self.db.master_password_exists():
            self.setup_master_password()
            return True

        password = getpass("Введите мастер-пароль: ")
        if self.db.verify_master_password(password):
            return True
        print("Неверный мастер-пароль. Доступ запрещён.")
        return False

    # ------------------------------------------------------------------
    # Генерация пароля
    # ------------------------------------------------------------------
    def _build_alphabet(self) -> str:
        """Формирует строку доступных символов на основе флагов."""
        alphabet = ""
        if self.use_uppercase:
            alphabet += string.ascii_uppercase
        if self.use_lowercase:
            alphabet += string.ascii_lowercase
        if self.use_digits:
            alphabet += string.digits
        if self.use_special:
            alphabet += string.punctuation
        return alphabet

    def generate_password(self) -> str:
        """Генерирует пароль с текущими настройками без интерактива.

        Returns:
            Сгенерированный пароль.
        """
        alphabet = self._build_alphabet()
        if not alphabet:
            alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(random.choice(alphabet) for _ in range(self.length))

    def generate_password_interactive(self) -> str:
        """Интерактивно генерирует пароль с выбором параметров.

        Returns:
            Сгенерированный пароль.
        """
        print("\n=== Генерация пароля ===")

        try:
            length_input = input(f"Длина пароля (1-64, по умолчанию {self.length}): ").strip()
            if length_input:
                length = int(length_input)
                length = max(1, min(length, 64))
            else:
                length = self.length
        except ValueError:
            length = self.length
            print(f"Некорректное значение, используется длина по умолчанию: {length}")

        use_upper = input("Использовать заглавные буквы? (д/н, по умолчанию д): ").strip().lower()
        use_upper = use_upper in ("", "д", "да", "y", "yes")

        use_lower = input("Использовать строчные буквы? (д/н, по умолчанию д): ").strip().lower()
        use_lower = use_lower in ("", "д", "да", "y", "yes")

        use_digits = input("Использовать цифры? (д/н, по умолчанию д): ").strip().lower()
        use_digits = use_digits in ("", "д", "да", "y", "yes")

        use_special = input("Использовать спецсимволы? (д/н, по умолчанию д): ").strip().lower()
        use_special = use_special in ("", "д", "да", "y", "yes")

        alphabet = ""
        if use_upper:
            alphabet += string.ascii_uppercase
        if use_lower:
            alphabet += string.ascii_lowercase
        if use_digits:
            alphabet += string.digits
        if use_special:
            alphabet += string.punctuation

        if not alphabet:
            print("Не выбран ни один тип символов. Используются все по умолчанию.")
            alphabet = string.ascii_letters + string.digits + string.punctuation

        password = "".join(random.choice(alphabet) for _ in range(length))
        print(f"\nСгенерированный пароль: {password}\n")
        return password

    # ------------------------------------------------------------------
    # Работа с записями паролей
    # ------------------------------------------------------------------
    def add_password(self) -> None:
        """Добавляет новую запись пароля через интерактивный ввод."""
        if not self.authenticate():
            return

        name = input("Название / источник (например, Google): ").strip()
        if not name:
            print("Название не может быть пустым.")
            return

        existing = self.db.get_password(name)
        if existing:
            print(f"Запись с названием '{name}' уже существует.")
            return

        login = input("Логин: ").strip()
        if not login:
            print("Логин не может быть пустым.")
            return

        print("\nПароль будет сгенерирован автоматически.")
        generated = self.generate_password_interactive()

        copy_choice = input("Скопировать пароль в буфер обмена? (д/н): ").strip().lower()
        if copy_choice in ("д", "да", "y", "yes"):
            self._copy_to_clipboard(generated)

        encrypted = self.enc.encrypt(generated)
        self.db.add_password(name, login, encrypted)
        print(f"Запись '{name}' успешно добавлена.\n")

    def get_password(self) -> None:
        """Получает и выводит пароль по названию записи."""
        if not self.authenticate():
            return

        name = input("Название записи: ").strip()
        if not name:
            print("Название не может быть пустым.")
            return

        record = self.db.get_password(name)
        if record is None:
            print(f"Запись с названием '{name}' не найдена.\n")
            return

        login = record["login"]
        encrypted_password = record["encrypted_password"]
        password = self.enc.decrypt(encrypted_password)

        print(f"\nЗапись: {name}")
        print(f"Логин:  {login}")
        print(f"Пароль: {password}\n")

        copy_choice = input("Скопировать пароль в буфер обмена? (д/н): ").strip().lower()
        if copy_choice in ("д", "да", "y", "yes"):
            self._copy_to_clipboard(password)

    def list_passwords(self) -> None:
        """Показывает список всех записей (названия и логины)."""
        records = self.db.list_passwords()
        if not records:
            print("Записей не найдено.\n")
            return

        print("\nСохранённые записи:")
        print("-" * 40)
        for record in records:
            print(f"  {record['name']:20} | {record['login']}")
        print("-" * 40)
        print(f"Всего записей: {len(records)}\n")

    def delete_password(self) -> None:
        """Удаляет запись пароля по названию."""
        if not self.authenticate():
            return

        name = input("Название записи для удаления: ").strip()
        if not name:
            print("Название не может быть пустым.")
            return

        confirm = input(f"Удалить запись '{name}'? (д/н): ").strip().lower()
        if confirm not in ("д", "да", "y", "yes"):
            print("Удаление отменено.\n")
            return

        if self.db.delete_password(name):
            print(f"Запись '{name}' удалена.\n")
        else:
            print(f"Запись с названием '{name}' не найдена.\n")

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    @staticmethod
    def _copy_to_clipboard(text: str) -> None:
        """Копирует текст в буфер обмена (если доступна библиотека pyperclip).

        Args:
            text: Текст для копирования.
        """
        try:
            import pyperclip

            pyperclip.copy(text)
            print("Пароль скопирован в буфер обмена.")
        except ImportError:
            print(
                "Библиотека pyperclip не установлена. "
                "Установите её командой: pip install pyperclip"
            )
        except Exception as exc:
            print(f"Не удалось скопировать в буфер обмена: {exc}")

    # ------------------------------------------------------------------
    # Меню
    # ------------------------------------------------------------------
    def show_menu(self) -> None:
        """Отображает главное меню."""
        print("\n=== Менеджер паролей ===")
        print("1. Добавить запись")
        print("2. Получить пароль по названию")
        print("3. Показать все записи")
        print("4. Удалить запись")
        print("5. Сгенерировать пароль")
        print("0. Выход")

    def run(self) -> None:
        """Запускает главный цикл приложения."""
        self.setup_master_password()
        while True:
            self.show_menu()
            choice = input("Выберите действие: ").strip()

            if choice == "1":
                self.add_password()
            elif choice == "2":
                self.get_password()
            elif choice == "3":
                self.list_passwords()
            elif choice == "4":
                self.delete_password()
            elif choice == "5":
                if not self.authenticate():
                    continue
                password = self.generate_password_interactive()
                copy_choice = input("Скопировать пароль в буфер обмена? (д/н): ").strip().lower()
                if copy_choice in ("д", "да", "y", "yes"):
                    self._copy_to_clipboard(password)
            elif choice == "0":
                print("До свидания!")
                self.db.close()
                sys.exit(0)
            else:
                print("Неверный выбор. Попробуйте снова.\n")


def main() -> None:
    """Точка входа в приложение."""
    app = PasswordGenerator()
    app.run()


if __name__ == "__main__":
    main()

    def generate_password(self) -> str:
        """Генерирует пароль с текущими настройками без интерактива.

        Returns:
            Сгенерированный пароль.
        """
        alphabet = self._build_alphabet()
        if not alphabet:
            alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(random.choice(alphabet) for _ in range(self.length))
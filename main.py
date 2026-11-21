"""Основной CLI-обработчик менеджера паролей."""

import argparse
import getpass
import sys
import string
import random

from config import DB_NAME
from db import (
    init_db,
    master_password_exists,
    set_master_password,
    verify_master_password,
    add_entry,
    get_entry,
    list_entries,
    delete_entry,
)
from crypto import encrypt_password, decrypt_password, load_or_generate_key


def prompt_master_password(set_new: bool = False) -> str:
    """Запросить у пользователя мастер-пароль.

    Args:
        set_new: Если True, запрашивает подтверждение нового пароля.

    Returns:
        str: Введённый пароль.
    """
    if set_new:
        print("=== Настройка мастер-пароля (первый запуск) ===")
        while True:
            p1 = getpass.getpass("Придумайте мастер-пароль: ")
            p2 = getpass.getpass("Повторите мастер-пароль: ")
            if p1 == p2:
                if len(p1) == 0:
                    print("Пароль не может быть пустым. Попробуйте снова.")
                    continue
                return p1
            print("Пароли не совпадают. Попробуйте снова.")
    else:
        return getpass.getpass("Введите мастер-пароль: ")


def require_auth() -> bool:
    """Пропустить пользователя через аутентификацию по мастер-паролю.

    Возвращает True, если аутентикация прошла успешно.
    """
    if not master_password_exists():
        print("Мастер-пароль не установлен. Это первый запуск.")
        password = prompt_master_password(set_new=True)
        set_master_password(password)
        load_or_generate_key()
        print("Мастер-пароль установлен и ключ шифрования создан.\n")
        return True

    password = prompt_master_password()
    if verify_master_password(password):
        return True
    print("Неверный мастер-пароль. Доступ запрещён.")
    return False


def generate_password(length: int = 16) -> str:
    """Сгенерировать случайный надёжный пароль.

    Args:
        length: Длина пароля.

    Returns:
        str: Сгенерированный пароль.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(alphabet) for _ in range(length))

def cmd_add(args: argparse.Namespace) -> None:
    """Обработать команду add — добавить новую запись."""
    if not require_auth():
        return

    name = input("Название / источник (например, Google): ").strip()
    if not name:
        print("Название не может быть пустым.")
        return

    existing = get_entry(name)
    if existing:
        print(f"Запись с названием '{name}' уже существует.")
        return

    login = input("Логин: ").strip()
    if not login:
        print("Логин не может быть пустым.")
        return

    password = getpass.getpass("Пароль: ")
    if not password:
        print("Пароль не может быть пустым.")
        return

    encrypted = encrypt_password(password)
    add_entry(name, login, encrypted)
    print(f"Запись '{name}' успешно добавлена.")


def cmd_get(args: argparse.Namespace) -> None:
    """Обработать команду get — получить пароль по названию."""
    if not require_auth():
        return

    name = args.name
    if not name:
        name = input("Название записи: ").strip()

    result = get_entry(name)
    if result is None:
        print(f"Запись с названием '{name}' не найдена.")
        return

    login, encrypted_password = result
    password = decrypt_password(encrypted_password)
    print(f"\nЗапись: {name}")
    print(f"Логин:  {login}")
    print(f"Пароль: {password}\n")


def cmd_list(args: argparse.Namespace) -> None:
    """Обработать команду list — показать все записи."""
    entries = list_entries()
    if not entries:
        print("Записей не найдено.")
        return

    print("\nСохранённые записи:")
    print("-" * 40)
    for name, login in entries:
        print(f"  {name:20} | {login}")
    print("-" * 40)
    print(f"Всего записей: {len(entries)}\n")


def cmd_delete(args: argparse.Namespace) -> None:
    """Обработать команду delete — удалить запись по названию."""
    if not require_auth():
        return

    name = args.name
    if not name:
        name = input("Название записи для удаления: ").strip()

    if not name:
        print("Название не может быть пустым.")
        return

    confirm = input(f"Удалить запись '{name}'? (y/n): ").strip().lower()
    if confirm != "y":
        print("Удаление отменено.")
        return

    if delete_entry(name):
        print(f"Запись '{name}' удалена.")
    else:
        print(f"Запись с названием '{name}' не найдена.")


def cmd_new(args: argparse.Namespace) -> None:
    """Обработать команду new — сгенерировать новый пароль."""
    length = args.length if args.length else 16
    password = generate_password(length)
    print(f"\nСгенерированный пароль (длина {length}):")
    print(f"  {password}\n")

    save = input("Сохранить этот пароль в базе? (y/n): ").strip().lower()
    if save == "y":
        if not require_auth():
            return
        name = input("Название / источник: ").strip()
        login = input("Логин: ").strip()
        if not name or not login:
            print("Название и логин обязательны. Пароль не сохранён.")
            return
        encrypted = encrypt_password(password)
        add_entry(name, login, encrypted)
        print(f"Запись '{name}' успешно сохранена.")


def build_parser() -> argparse.ArgumentParser:
    """Построить парсер аргументов командной строки.

    Returns:
        argparse.ArgumentParser: Настроенный парсер.
    """
    parser = argparse.ArgumentParser(
        description="CLI менеджер паролей с шифрованием (SQLite3 + Fernet)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Доступные команды")

    add_parser = subparsers.add_parser("add", help="Добавить новую запись")
    add_parser.set_defaults(func=cmd_add)

    get_parser = subparsers.add_parser("get", help="Получить пароль по названию")
    get_parser.add_argument("name", nargs="?", help="Название записи")
    get_parser.set_defaults(func=cmd_get)

    list_parser = subparsers.add_parser("list", help="Показать все записи")
    list_parser.set_defaults(func=cmd_list)

    delete_parser = subparsers.add_parser("delete", help="Удалить запись по названию")
    delete_parser.add_argument("name", nargs="?", help="Название записи")
    delete_parser.set_defaults(func=cmd_delete)

    new_parser = subparsers.add_parser("new", help="Сгенерировать новый пароль")
    new_parser.add_argument(
        "-l", "--length", type=int, default=16, help="Длина пароля (по умолчанию 16)"
    )
    new_parser.set_defaults(func=cmd_new)

    return parser


def main() -> None:
    """Точка входа в приложение."""
    init_db()

    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()

"""Функции для шифрования и дешифрования паролей с использованием Fernet."""

import os
from cryptography.fernet import Fernet

from config import KEY_FILE


def load_or_generate_key() -> bytes:
    """Загрузить ключ из файла .key или сгенерировать новый, если файла нет.

    Returns:
        bytes: Ключ Fernet.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        # Прячем файл ключа (опционально, только на Windows)
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(KEY_FILE, 2)  # FILE_ATTRIBUTE_HIDDEN
        except Exception:
            pass
    return key


def get_fernet() -> Fernet:
    """Вернуть экземпляр Fernet с загруженным ключом.

    Returns:
        Fernet: Объект для шифрования/дешифрования.
    """
    key = load_or_generate_key()
    return Fernet(key)


def encrypt_password(plaintext: str) -> str:
    """Зашифровать строку пароля.

    Args:
        plaintext: Открытый текст пароля.

    Returns:
        str: Зашифрованная строка в base64.
    """
    fernet = get_fernet()
    token = fernet.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_password(encrypted: str) -> str:
    """Расшифровать строку пароля.

    Args:
        encrypted: Зашифрованная строка в base64.

    Returns:
        str: Расшифрованный пароль.
    """
    fernet = get_fernet()
    token = fernet.decrypt(encrypted.encode("utf-8"))
    return token.decode("utf-8")
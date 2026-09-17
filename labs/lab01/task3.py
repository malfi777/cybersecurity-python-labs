import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from functools import wraps

# додаємо шлях для імпорту даних студента
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 14
# створюємо 5-символьну сіль з нулями зліва (для 4 варіанту -> "00004")
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")


class ValidationError(Exception):
    """власний виняток для валідації паролів."""

def generate_hash(password: str, salt: str = "00000") -> str:
    # генерує хеш від пароля та солі
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль надто короткий. Мінімум {MIN_PASSWORD_LENGTH} символів."
        )

    # використання sha512 згідно з варіантом 4
    combined = password + salt
    return hashlib.sha512(combined.encode()).hexdigest()


def log_event(func):
    # декоратор для логування подій авторизації у JSON

    @wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "unknown")
        try:
            result_val = func(*args, **kwargs)
            res_str = "success" if result_val else "failure"
        except (ValueError, ValidationError):
            res_str = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": res_str,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "args": [str(a) for a in args],
                "kwargs": {k: str(v) for k, v in kwargs.items()},
            }

            try:
                logs = []
                if os.path.exists(LOG_JSON_PATH):
                    with open(LOG_JSON_PATH, "r", encoding="utf-8") as f:
                        try:
                            logs = json.load(f)
                        except json.JSONDecodeError:
                            logs = []
                logs.append(log_entry)
                with open(LOG_JSON_PATH, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except (OSError, PermissionError):
                pass  # пропускаємо запис, якщо файл недоступний

        return result_val

    return wrapper


def create_user(username, password):
    # хешує пароль і повертає кортеж (логін, хеш)
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list):
    # cтворює базу даних у форматі CSV
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(USERS_CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["login", "password_hash"])
        for user in users_list:
            try:
                record = create_user(user[0], user[1])
                writer.writerow(record)
            except (ValueError, ValidationError) as e:
                print(f"[-] Помилка при створенні {user[0]}: {e}")


@log_event
def login(username: str, password: str) -> bool:
    # перевіряє, чи існує користувач і чи збігається хеш
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми.")

    with open(USERS_CSV_PATH, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        # використання list() замість циклу
        users_db = list(reader)

    input_hash = generate_hash(password, PERSONAL_SALT)
    for db_user in users_db:
        if db_user["login"] == username and db_user["password_hash"] == input_hash:
            return True
    return False


def main():
    # головна функція для демонстрації роботи
    print("--- Безпечне хешування, CSV-база та JSON-логування ---\n")

    # кортеж із 10 користувачів (деякі паролі коротші за 14 символів для перевірки помилки)
    users_to_register = (
        ("admin01", "SuperSecurePass1234"),
        ("dev_ops", "PasswordMustBe14Chars"),
        ("guest01", "Short"),
        ("analyst", "DataAnalyst2026Secure"),
        ("ceo_acc", "ExecutivePass2026!"),
        ("manager", "ManagerPass!14Chars"),
        ("student", "LvivPolytechnic2026"),
        ("tester1", "TestTesting123456"),
        ("sys_bot", "BotAutoPassw0rd99"),
        ("auditor", "AuditPassSecur1ty"),
    )

    try:
        print("[1] Створення бази користувачів CSV...")
        create_users(users_to_register)

        print("\n[2] Вміст CSV бази даних:")
        with open(USERS_CSV_PATH, mode="r", encoding="utf-8") as file:
            reader = csv.reader(file)
            headers = next(reader)
            print(f"{headers[0]:<12} | {headers[1]}")
            print("-" * 140)
            for row in reader:
                print(f"{row[0]:<12} | {row[1]}")

        print("\n[3] Тестування автентифікації та логування:")
        test_cases = [
            ("admin01", "SuperSecurePass1234"),
            ("student", "WrongPassword14Char"),
            ("unknown", "SomePass14Chars123"),
            ("", "PasswordMustBe14Chars"),
        ]

        for u, p in test_cases:
            try:
                is_valid = login(u, p)
                status = "УСПІХ" if is_valid else "ВІДМОВА"
                print(f" Вхід '{u}': {status}")
            except (ValueError, ValidationError) as e:
                print(f" Вхід '{u}': ПОМИЛКА -> {e}")

        print("\n[4] Усі спроби входу були записані у log.json[cite: 4]")

    except (OSError, FileNotFoundError, PermissionError) as e:
        print(f"Системна помилка під час роботи з файлами: {e}")


if __name__ == "__main__":
    main()

import os
import random
import sys

# додаємо шлях до системного пошуку для імпорту спільного модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import STUDENT_NAME, VARIANT_NUMBER


def analyze_passwords():
    # аналізує надійність паролів
    print("--- Аналізатор паролів ---")
    print(f"Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER}\n")

    passwords = [
        "Security@2023",
        "pass",
        "MyStr0ng#Key",
        "root",
        "Advanc3d@Pass",
        "user",
        "Protec7!Pass",
        "1234",
        "Elite@Secur1ty",
        "admin123",
    ]
    criteria = {
        "min_length": 7,
        "require_digits": True,
        "require_upper": True,
        "require_special": True,
    }
    forbidden_passwords = {"pass", "root", "user", "1234", "admin123", "password"}
    # генеруємо 3 випадкові індекси та додаємо дублікати
    random_indices = random.choices(range(len(passwords)), k=3)
    for idx in random_indices:
        passwords.append(passwords[idx])

    # вивід заголовку таблиці
    print(f"{'Пароль':<20} | {'Статус':<15}")
    print("-" * 38)

    # аналіз кожного пароля
    for pwd in passwords:
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_special = any(not c.isalnum() for c in pwd)

        is_forbidden = pwd in forbidden_passwords or len(pwd) < criteria["min_length"]

        # перевірка на виконання всіх обов'язкових критеріїв
        meets_all = has_digit and has_upper and has_special

        # підрахунок кількості виконаних груп символів
        groups_count = sum([has_lower, has_upper, has_digit, has_special])

        is_unique = passwords.count(pwd) == 1

        # оцінка надійності за алгоритмом
        if is_forbidden:
            status = "Заборонений"
        elif meets_all and len(pwd) >= criteria["min_length"] + 4 and is_unique:
            status = "Дуже сильний"
        elif meets_all:
            status = "Сильний"
        elif groups_count >= 2:
            status = "Середній"
        else:
            status = "Слабкий"

        print(f"{pwd:<20} | {status:<15}")


if __name__ == "__main__":
    analyze_passwords()

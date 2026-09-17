import os
import sys

# Додаємо шлях до системного пошуку для імпорту спільного модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))


def check_access():
    """Реалізує перевірку доступу користувачів до ресурсів."""
    print("--- Система контролю доступу ---\n")

    # Вхідні дані для Варіанту 4[cite: 3]
    users = {
        "ciso_office": {
            "role": "ciso",
            "clearance": 4,
            "department": "Executive",
            "active": True,
        },
        "threat_hunter": {
            "role": "threat_analyst",
            "clearance": 3,
            "department": "Threat Intel",
            "active": True,
        },
        "junior_dev": {
            "role": "junior_developer",
            "clearance": 2,
            "department": "Development",
            "active": True,
        },
        "visitor_acc": {
            "role": "visitor",
            "clearance": 1,
            "department": "Guest",
            "active": True,
        },
        "legacy_sys": {
            "role": "legacy",
            "clearance": 2,
            "department": "Legacy",
            "active": False,
        },
    }

    resources = [
        ("threat_intelligence", 4),
        ("malware_samples", 3),
        ("coding_guidelines", 2),
        ("visitor_wifi", 1),
        ("strategic_plans", 4),
        ("demo_environment", 1),
        ("risk_assessments", 3),
        ("crypto_keys", 4),
        ("api_documentation", 2),
        ("guest_portal", 1),
    ]

    security_levels = ("Guest", "Employee", "Privileged", "Executive")
    blocked_users = {"legacy_sys", "malicious_user", "expired_guest"}

    # Вивід списку ресурсів із текстовим рівнем безпеки[cite: 3]
    print("Доступні ресурси системи:")
    for res_name, res_level in resources:
        # Індексація кортежу починається з 0, тому res_level - 1
        level_name = security_levels[res_level - 1]
        print(f" - {res_name}: {level_name} (Рівень {res_level})")
    print("\n" + "=" * 50 + "\n")

    # Для перевірки алгоритму візьмемо існуючих користувачів та додамо неіснуючого
    test_users = list(users.keys()) + ["non_existent_user"]

    # Перевірка доступу кожного користувача до кожного ресурсу[cite: 3]
    for username in test_users:
        print(f"Перевірка доступу для користувача: {username}")

        for res_name, res_level in resources:
            # Алгоритм перевірки доступу[cite: 3]
            if username not in users:
                status = "DENY (User not found)"
            elif username in blocked_users:
                status = "DENY (User is blocked)"
            elif not users[username]["active"]:
                status = "DENY (Account inactive)"
            elif users[username]["clearance"] >= res_level:
                status = "ALLOW"
            else:
                status = "DENY (Insufficient clearance)"

            print(f"  resource=[{res_name}] -> {status}")
        print("-" * 50)


if __name__ == "__main__":
    check_access()

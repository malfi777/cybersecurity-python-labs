import sys
from datetime import timedelta

# Імпортуємо класи з першого завдання (будівельні блоки)
from labs.lab02.task1 import Admin, AuditLog, User, UserAccount

# Імпортуємо головну функцію з другого завдання (парсер логів)
from labs.lab02.task2 import main as run_task2


def demo():
    # Демонстрація роботи першого завдання (ООП)
    print("--- Демонстрація ООП (Завдання 1) ---\n")

    audit = AuditLog()  # Створюємо журнал подій

    # Створюємо адміністратора і задаємо йому пароль
    admin_user = Admin("root_admin", "admin.01@lpnu.ua", {"read", "write"})
    admin_user.set_password("SuperSecret123!")
    print(admin_user)

    # Додаємо нове право та перевіряємо його наявність
    admin_user.grant_permission("delete")
    print(f"Чи має admin право 'delete'? {admin_user.has_permission('delete')}")

    print("\n--- Тестування валідації Email ---")
    try:
        admin_user.email = "1invalid@domain"  # Спроба встановити некоректну пошту
    except ValueError as e:
        print(f"Очікувана помилка при невірному email: {e}")

    admin_user.email = "valid.admin@lpnu.ua"  # Встановлення правильної пошти
    print(f"Оновлений email: {admin_user.email}")

    # Створюємо обліковий запис (поєднуємо користувача і журнал)
    account = UserAccount(admin_user, audit)

    print("\n--- Тестування входу в систему ---")
    account.login("root_admin", "WrongPassword!", "192.168.1.10")  # Невдала спроба
    account.login("root_admin", "SuperSecret123!", "192.168.1.10")  # Вдала спроба
    print(f"Користувач аутентифікований? {account.is_authenticated()}")

    print(f"\nСесія через account['session'] IP: {account['session'].ip}")

    try:
        # Спроба отримати зашифрований пароль напряму (має бути заблоковано)
        _ = account["password_hash"]
    except KeyError as e:
        print(f"Очікувана відмова у доступі до хешу: {e}")

    print("\n--- Симуляція таймауту ---")
    # Штучно відмотуємо час активності назад, щоб перевірити автоматичний вихід
    account["session"].last_activity -= timedelta(seconds=901)
    print(f"Сесія активна після таймауту? {account.is_authenticated()}")
    account.logout()

    # Перевірки створення користувачів з пустими даними
    print("\n--- Випадок 1: Пустий юзер (без логіна) ---")
    try:
        empty_login_user = User(username="", email="empty.login@lpnu.ua")
        empty_login_user.set_password("SecurePass123")
        account_1 = UserAccount(empty_login_user, audit)
        is_logged_in_1 = account_1.login("", "SecurePass123", "192.168.0.1")
        print(f"Статус входу: {'Успішно' if is_logged_in_1 else 'Провалено'}")
    except ValueError as e:
        print(f"Очікувана помилка створення: {e}")

    print("\n--- Випадок 2: Пустий юзер (без пароля) ---")
    no_pass_user = User(username="user_no_pass", email="nopass@lpnu.ua")
    account_2 = UserAccount(no_pass_user, audit)
    is_logged_in_2 = account_2.login("user_no_pass", "", "192.168.0.2")
    print(f"Статус входу: {'Успішно' if is_logged_in_2 else 'Провалено'}")

    print("\n--- Випадок 3: Пустий адмін (без логіна) ---")
    try:
        empty_login_admin = Admin(username="", email="admin.empty@lpnu.ua")
        empty_login_admin.set_password("AdminPass123")
        account_3 = UserAccount(empty_login_admin, audit)
        is_logged_in_3 = account_3.login("", "AdminPass123", "192.168.0.3")
        print(f"Статус входу: {'Успішно' if is_logged_in_3 else 'Провалено'}")
    except ValueError as e:
        print(f"Очікувана помилка створення: {e}")

    print("\n--- Випадок 4: Пустий адмін (без пароля) ---")
    no_pass_admin = Admin(username="admin_no_pass", email="admin.nopass@lpnu.ua")
    account_4 = UserAccount(no_pass_admin, audit)
    is_logged_in_4 = account_4.login("admin_no_pass", "", "192.168.0.4")
    print(f"Статус входу: {'Успішно' if is_logged_in_4 else 'Провалено'}")

    print("\n")
    audit.show_all()  # Вивід усього журналу подій на екран


# Точка входу в програму
if __name__ == "__main__":
    # Читаємо аргументи з командного рядка (наприклад: python main.py demo)
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "demo":
            demo()  # Запускаємо перше завдання
        elif command == "analyze":
            sys.argv.pop(1)  # Прибираємо слово "analyze", щоб не заважало argparse
            run_task2()  # Запускаємо друге завдання (парсер логів)
        else:
            print("Невідома команда. Використовуйте 'demo' або 'analyze'.")
    else:
        print(
            "Вкажіть команду: python -m labs.lab02.main demo АБО python -m labs.lab02.main analyze [аргументи]"
        )

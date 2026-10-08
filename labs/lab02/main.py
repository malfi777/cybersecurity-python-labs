import sys
from datetime import timedelta

from labs.lab02.task1 import Admin, AuditLog, User, UserAccount
from labs.lab02.task2 import main as run_task2


def demo():
    print("--- Демонстрація ООП (Завдання 1) ---\n")

    audit = AuditLog()
    admin_user = Admin("root_admin", "admin.01@lpnu.ua", {"read", "write"})
    admin_user.set_password("SuperSecret123!")
    print(admin_user)

    admin_user.grant_permission("delete")
    print(f"Чи має admin право 'delete'? {admin_user.has_permission('delete')}")

    print("\n--- Тестування валідації Email ---")
    try:
        admin_user.email = "1invalid@domain"
    except ValueError as e:
        print(f"Очікувана помилка при невірному email: {e}")

    admin_user.email = "valid.admin@lpnu.ua"
    print(f"Оновлений email: {admin_user.email}")

    account = UserAccount(admin_user, audit)

    print("\n--- Тестування входу в систему ---")
    account.login("root_admin", "WrongPassword!", "192.168.1.10")
    account.login("root_admin", "SuperSecret123!", "192.168.1.10")
    print(f"Користувач аутентифікований? {account.is_authenticated()}")

    print(f"\nСесія через account['session'] IP: {account['session'].ip}")

    try:
        # ігноруємо результат змінної через підкреслення
        _ = account["password_hash"]
    except KeyError as e:
        print(f"Очікувана відмова у доступі до хешу: {e}")

    print("\n--- Симуляція таймауту ---")
    account["session"].last_activity -= timedelta(seconds=901)
    print(f"Сесія активна після таймауту? {account.is_authenticated()}")
    account.logout()


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
    audit.show_all()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "demo":
            demo()
        elif command == "analyze":
            sys.argv.pop(1)
            run_task2()
        else:
            print("Невідома команда. Використовуйте 'demo' або 'analyze'.")
    else:
        print(
            "Вкажіть команду: python -m labs.lab02.main demo АБО python -m labs.lab02.main analyze [аргументи]"
        )

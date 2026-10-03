#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Apodex Automation & API Research Toolkit v1.0
Author: greenyarik0505-jpg

DISCLAIMER / LEGAL NOTICE:
Данный проект и код разработаны исключительно в образовательных целях,
для исследования сетевых протоколов аутентификации, тестирования устойчивости
API к автоматизированным запросам и демонстрации концепции passwordless OTP.
Автор не несет ответственности за любое нецелевое использование данного софта
или нарушение правил сторонних сервисов. Лицензия: MIT.
"""

import os
import re
import sys
import time
import json
import random
import string
import logging
import webbrowser
from typing import Optional, Dict, Any, List
import requests

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("ApodexToolkit")

AUTH_BASE = "https://auth.apodex.ai"
PLATFORM_BASE = "https://platform.apodex.ai"
API_BASE = "https://api.apodex.ai/v1"
CLIENT_ID = "apodex-platform-web"

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "https://platform.apodex.ai",
    "Referer": "https://platform.apodex.ai/"
}


def random_string(length: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def normalize_proxy(raw_proxy: str) -> Optional[Dict[str, str]]:
    raw_proxy = raw_proxy.strip()
    if not raw_proxy or raw_proxy.startswith("#"):
        return None

    if "://" not in raw_proxy:
        parts = raw_proxy.split(":")
        if len(parts) == 2:
            proxy_url = f"http://{parts[0]}:{parts[1]}"
        elif len(parts) == 4:
            proxy_url = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
        else:
            proxy_url = f"http://{raw_proxy}"
    else:
        proxy_url = raw_proxy

    return {
        "http": proxy_url,
        "https": proxy_url
    }


def load_proxies(file_path: str = "proxies.txt") -> List[Dict[str, str]]:
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    proxies = []
    for line in lines:
        p = normalize_proxy(line)
        if p:
            proxies.append(p)
    return proxies


class MailTmClient:
    BASE_URL = "https://api.mail.tm"

    def __init__(self, proxies: Optional[Dict[str, str]] = None):
        self.session = requests.Session()
        if proxies:
            self.session.proxies.update(proxies)
        self.session.headers.update({"User-Agent": DEFAULT_HEADERS["User-Agent"]})
        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.token: Optional[str] = None

    def create_account(self) -> str:
        resp = self.session.get(f"{self.BASE_URL}/domains", timeout=10)
        resp.raise_for_status()
        domains = resp.json().get("hydra:member", [])
        if not domains:
            raise RuntimeError("No domains available on mail.tm")

        domain = random.choice(domains)["domain"]
        self.email = f"{random_string(10)}@{domain}"
        self.password = f"SecP@{random_string(8)}!"

        reg_resp = self.session.post(
            f"{self.BASE_URL}/accounts",
            json={"address": self.email, "password": self.password},
            timeout=10
        )
        reg_resp.raise_for_status()

        auth_resp = self.session.post(
            f"{self.BASE_URL}/token",
            json={"address": self.email, "password": self.password},
            timeout=10
        )
        auth_resp.raise_for_status()
        self.token = auth_resp.json()["token"]
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})

        return self.email

    def login_account(self, email: str, password: str):
        self.email = email
        self.password = password
        auth_resp = self.session.post(
            f"{self.BASE_URL}/token",
            json={"address": self.email, "password": self.password},
            timeout=10
        )
        auth_resp.raise_for_status()
        self.token = auth_resp.json()["token"]
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})

    def wait_for_otp(self, timeout_sec: int = 60, poll_interval: int = 4) -> str:
        end_time = time.time() + timeout_sec
        while time.time() < end_time:
            time.sleep(poll_interval)
            try:
                r = self.session.get(f"{self.BASE_URL}/messages", timeout=10)
                if r.status_code != 200:
                    continue
                messages = r.json().get("hydra:member", [])
                for msg in messages:
                    subject = msg.get("subject", "")
                    intro = msg.get("intro", "")
                    code_match = re.search(r"\b(\d{6})\b", subject) or re.search(r"\b(\d{6})\b", intro)
                    if code_match:
                        return code_match.group(1)

                    msg_id = msg.get("id")
                    if msg_id:
                        detail = self.session.get(f"{self.BASE_URL}/messages/{msg_id}", timeout=10).json()
                        text_content = detail.get("text", "")
                        match = re.search(r"\b(\d{6})\b", text_content)
                        if match:
                            return match.group(1)
            except Exception as e:
                logger.debug(f"Polling error: {e}")
        raise TimeoutError(f"OTP code not received within {timeout_sec}s")


class ApodexAutoReg:
    def __init__(self, proxy: Optional[Dict[str, str]] = None):
        self.proxy = proxy
        self.session = requests.Session()
        if proxy:
            self.session.proxies.update(proxy)
        self.session.headers.update(DEFAULT_HEADERS)
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.user_data: Dict[str, Any] = {}

    def send_verification_code(self, email: str) -> bool:
        url = f"{AUTH_BASE}/api/auth/passwordless/send-code"
        resp = self.session.post(url, json={"email": email}, timeout=15)
        if resp.status_code not in (200, 201):
            logger.error(f"Send-code failed ({resp.status_code}): {resp.text}")
            return False
        return True

    def verify_login(self, email: str, code: str) -> Dict[str, Any]:
        url = f"{AUTH_BASE}/api/auth/v2/passwordless/verify-login"
        payload = {
            "email": email,
            "code": code,
            "client_id": CLIENT_ID
        }
        resp = self.session.post(url, json=payload, timeout=15)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        self.access_token = data.get("access_token")
        self.refresh_token = data.get("refresh_token")
        self.user_data = data.get("user", {})
        return data

    def get_account_credits(self) -> Dict[str, Any]:
        if not self.access_token:
            raise RuntimeError("Not authenticated")
        url = f"{PLATFORM_BASE}/v1/user/account"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        resp = self.session.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def create_api_key(self, name: Optional[str] = None, description: str = "Autoreg Key") -> Dict[str, Any]:
        if not self.access_token:
            raise RuntimeError("Not authenticated")
        if not name:
            name = f"Key_{random_string(6)}"
        url = f"{PLATFORM_BASE}/v1/api-keys"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "name": name,
            "description": description
        }
        resp = self.session.post(url, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def test_api_key(self, api_key: str) -> bool:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        try:
            resp = requests.get(f"{API_BASE}/models", headers=headers, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False


def save_account_data(res: Dict[str, Any]):
    # 1. keys.txt
    with open("keys.txt", "a", encoding="utf-8") as f:
        f.write(f"{res['api_key']}\n")

    # 2. accounts.txt
    with open("accounts.txt", "a", encoding="utf-8") as f:
        f.write(f"{res['email']}:{res['api_key']}:${res['credits_usd']:.2f}\n")

    # 3. accounts.json
    all_accs = []
    if os.path.exists("accounts.json"):
        try:
            with open("accounts.json", "r", encoding="utf-8") as f:
                all_accs = json.load(f)
        except Exception:
            all_accs = []
    all_accs.append(res)
    with open("accounts.json", "w", encoding="utf-8") as f:
        json.dump(all_accs, f, indent=2, ensure_ascii=False)


def run_registration(proxy: Optional[Dict[str, str]] = None, verbose: bool = True) -> Optional[Dict[str, Any]]:
    proxy_str = proxy["http"] if proxy else "Прямое подключение (без прокси)"
    if verbose:
        logger.info(f"Запуск регистрации [Прокси: {proxy_str}]")

    # 1. Почта
    try:
        mail = MailTmClient(proxies=proxy)
        email = mail.create_account()
        if verbose:
            logger.info(f"[1/4] Сгенерирован TempMail: {email}")
    except Exception as e:
        logger.error(f"Ошибка создания почты: {e}")
        return None

    # 2. Запрос кода
    autoreg = ApodexAutoReg(proxy=proxy)
    if verbose:
        logger.info("[2/4] Запрос проверочного OTP кода на Apodex...")
    if not autoreg.send_verification_code(email):
        return None

    # 3. Получение OTP
    try:
        if verbose:
            logger.info("Ожидание входящего письма с кодом (до 60 сек)...")
        code = mail.wait_for_otp(timeout_sec=60)
        if verbose:
            logger.info(f"[3/4] Получен OTP-код: {code}")
    except Exception as e:
        logger.error(f"Ошибка получения OTP-кода: {e}")
        return None

    # 4. Верификация сессии
    try:
        autoreg.verify_login(email, code)
        if verbose:
            logger.info("Успешная аутентификация в Passport API.")
    except Exception as e:
        logger.error(f"Ошибка верификации: {e}")
        return None

    # 5. Кредиты и создание ключа
    try:
        account_info = autoreg.get_account_credits()
        credits_cents = account_info.get("credits", {}).get("active_cents", 0)
        credits_usd = credits_cents / 100.0
        if verbose:
            logger.info(f"Стартовый баланс: ${credits_usd:.2f} USD")

        key_data = autoreg.create_api_key(name=f"Key_{random_string(6)}")
        api_key = key_data.get("key")
        if verbose:
            logger.info(f"[4/4] Создан боевой API-ключ: {api_key}")

        is_valid = autoreg.test_api_key(api_key)
        if verbose:
            logger.info(f"Валидация ключа (/v1/models): {'200 OK (Активен)' if is_valid else 'Ошибка'}")

        result = {
            "email": email,
            "api_key": api_key,
            "key_id": key_data.get("id"),
            "credits_usd": credits_usd,
            "access_token": autoreg.access_token,
            "refresh_token": autoreg.refresh_token,
            "mail_password": mail.password,
            "proxy": proxy_str,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        save_account_data(result)
        return result
    except Exception as e:
        logger.error(f"Ошибка создания API ключа: {e}")
        return None


# --- МЕНЮ ДЕЙСТВИЙ ---

def menu_autoreg():
    print("\n--- [1] 🚀 Запуск авторегера ---")
    try:
        count_str = input("Количество аккаунтов для регистрации [по умолчанию 1]: ").strip()
        count = int(count_str) if count_str else 1
    except ValueError:
        count = 1

    proxies = load_proxies("proxies.txt")
    use_proxy = False
    if proxies:
        ans = input(f"Найдено {len(proxies)} прокси в proxies.txt. Использовать их? (y/n) [y]: ").strip().lower()
        use_proxy = ans != "n"
    else:
        print("Файл proxies.txt пуст или отсутствует. Работаем напрямую без прокси.")

    success = 0
    for i in range(1, count + 1):
        print(f"\n>>> Регистрация {i}/{count}...")
        p = random.choice(proxies) if (use_proxy and proxies) else None
        res = run_registration(proxy=p, verbose=True)
        if res:
            success += 1
            print(f"✔ Готово: {res['email']} | Ключ: {res['api_key']} | Баланс: ${res['credits_usd']:.2f}")
        else:
            print(f"✖ Ошибка на попытке {i}")

        if i < count:
            delay = random.randint(3, 6)
            print(f"Пауза {delay} сек перед следующим аккаунтом...")
            time.sleep(delay)

    print(f"\nИтог: успешно создано {success}/{count} аккаунтов. Сохранено в keys.txt, accounts.txt, accounts.json.")


def menu_quick_test():
    print("\n--- [2] 🧪 Быстрый тест (создать 1 аккаунт с логами) ---")
    proxies = load_proxies("proxies.txt")
    p = random.choice(proxies) if proxies else None
    res = run_registration(proxy=p, verbose=True)
    if res:
        print("\n" + "=" * 60)
        print("🎉 ТЕСТ УСПЕШНО ЗАВЕРШЕН!")
        print(f"Почта:   {res['email']}")
        print(f"API Key: {res['api_key']}")
        print(f"Баланс:  ${res['credits_usd']:.2f} USD")
        print("Ключ сохранен в keys.txt и accounts.txt")
        print("=" * 60)
    else:
        print("\n❌ Тест завершился с ошибкой.")


def menu_open_in_browser():
    print("\n--- [3] 🌐 Открыть аккаунт в консоли Apodex ---")
    if not os.path.exists("accounts.json"):
        print("Файл accounts.json не найден. Сначала зарегистрируйте аккаунт.")
        return

    try:
        with open("accounts.json", "r", encoding="utf-8") as f:
            accounts = json.load(f)
    except Exception:
        print("Не удалось прочитать accounts.json.")
        return

    if not accounts:
        print("Список аккаунтов пуст.")
        return

    print("Выберите аккаунт для входа:")
    for idx, acc in enumerate(accounts[-10:], 1):
        print(f"[{idx}] {acc.get('email')} (Баланс: ${acc.get('credits_usd', 0):.2f})")

    choice = input(f"Номер аккаунта (1-{min(len(accounts), 10)}) [последний]: ").strip()
    idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= min(len(accounts), 10) else -1
    selected = accounts[-10:][idx]

    token = selected.get("access_token")
    refresh_token = selected.get("refresh_token")

    js_code = (
        f"localStorage.setItem('apodex_pp_access_token', '{token}'); "
        f"localStorage.setItem('apodex_pp_refresh_token', '{refresh_token}'); "
        f"localStorage.setItem('apodex_pp_access_expires_at', '{int(time.time() + 3600)*1000}'); "
        f"document.cookie = 'apodex_signed_in=1; path=/; max-age=2592000'; "
        f"location.href = '/console/api-keys';"
    )

    print("\n" + "=" * 70)
    print("ВХОД В КОНСОЛЬ В 1 КЛИК:")
    print("1. Браузер открывается на https://platform.apodex.ai/login")
    print("2. Нажмите F12 (Консоль) и вставьте следующую строчку, затем нажмите Enter:")
    print("-" * 70)
    print(js_code)
    print("=" * 70)

    webbrowser.open("https://platform.apodex.ai/login")


def menu_check_inbox():
    print("\n--- [4] 📬 Проверить почту аккаунта (получить свежий OTP код) ---")
    if not os.path.exists("accounts.json"):
        print("Файл accounts.json не найден.")
        return

    with open("accounts.json", "r", encoding="utf-8") as f:
        accounts = json.load(f)

    if not accounts:
        print("Список аккаунтов пуст.")
        return

    print("Выберите аккаунт:")
    for idx, acc in enumerate(accounts[-10:], 1):
        print(f"[{idx}] {acc.get('email')}")

    choice = input(f"Номер аккаунта (1-{min(len(accounts), 10)}) [последний]: ").strip()
    idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= min(len(accounts), 10) else -1
    selected = accounts[-10:][idx]

    email = selected.get("email")
    pwd = selected.get("mail_password")
    if not pwd:
        print(f"Для {email} нет сохраненного пароля почты.")
        return

    print(f"\nОтправляем новый код на {email}...")
    reg = ApodexAutoReg()
    if reg.send_verification_code(email):
        print("Код запрошен. Подключаемся к ящику и ждем письмо...")
        mail = MailTmClient()
        try:
            mail.login_account(email, pwd)
            code = mail.wait_for_otp(timeout_sec=40)
            print("\n" + "=" * 50)
            print(f"📩 ВАШ 6-ЗНАЧНЫЙ КОД ДЛЯ ВХОДА: {code}")
            print("=" * 50)
        except Exception as e:
            print(f"Ошибка проверки почты: {e}")
    else:
        print("Не удалось отправить код с платформы.")


def menu_clear_database():
    print("\n--- [5] 🗑 Очистить базу аккаунтов ---")
    confirm = input("Вы уверены, что хотите удалить keys.txt, accounts.txt и accounts.json? (yes/no): ").strip().lower()
    if confirm in ("yes", "y", "да"):
        for fname in ["keys.txt", "accounts.txt", "accounts.json"]:
            if os.path.exists(fname):
                os.remove(fname)
                print(f"Удален: {fname}")
        print("База успешно очищена.")
    else:
        print("Отмена очистки.")


def main_menu():
    banner = """
============================================================
  🚀 Apodex Automation & API Research Toolkit v1.0
  Base URL: https://api.apodex.ai/v1/
============================================================
💻 ПУНКТЫ МЕНЮ:
[1] 🚀 Запустить авторегер (настроить параметры и старт)
[2] 🧪 Быстрый тест (создать 1 аккаунт с логами)
[3] 🌐 Открыть аккаунт в браузере (в 1 клик)
[4] 📬 Проверить почту аккаунта (получить свежий OTP код)
[5] 🗑 Очистить базу аккаунтов (accounts.txt / keys.txt / accounts.json)
[0] ❌ Выход
============================================================
"""
    while True:
        print(banner)
        choice = input("Выберите пункт меню [0-5]: ").strip()
        if choice == "1":
            menu_autoreg()
        elif choice == "2":
            menu_quick_test()
        elif choice == "3":
            menu_open_in_browser()
        elif choice == "4":
            menu_check_inbox()
        elif choice == "5":
            menu_clear_database()
        elif choice == "0":
            print("\nВыход из программы. До скорых встреч!")
            break
        else:
            print("Неверный ввод, повторите попытку.")
        input("\nНажмите Enter, чтобы вернуться в меню...")


if __name__ == "__main__":
    main_menu()

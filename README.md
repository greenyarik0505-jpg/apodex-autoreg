# Apodex Platform API Automation & Research Toolkit

> [!WARNING]
> **DISCLAIMER / FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**
> 
> This repository and code are provided strictly for **educational purposes**, **security research**, and **API integration testing**. The goal of this project is to demonstrate and study modern passwordless authentication architectures, OTP verification workflows, and automated proxy-aware client implementations. 
> 
> The author does not condone, promote, or encourage any misuse of this software. Any use of this tool against external services must comply with their respective Terms of Service and local laws. The author assumes no responsibility or liability for any consequences resulting from the execution of this code.

---

## 📌 Overview / Обзор

Скрипт автоматизации для исследования архитектуры авторизации платформы [Apodex Platform](https://platform.apodex.ai/). Проект демонстрирует полный цикл работы с passwordless API: генерацию одноразового почтового ящика, отправку запроса на авторизацию, автоматический поллинг и парсинг 6-значного OTP-кода, обмен кода на JWT Bearer-сессию и выпуск API-ключа.

### Key Features / Возможности
- **Automated TempMail Integration**: Взаимодействие с Mail.tm API без сторонних зависимостей браузера (чистые REST-запросы).
- **Comprehensive Proxy Support**: Поддержка HTTP, HTTPS, SOCKS4, SOCKS5 (с аутентификацией `user:pass` и без).
- **Session & Key Generation**: Автоматическое прохождение верификации, запрос Bearer токена и создание рабочего ключа `sk-...`.
- **Key Health Check**: Валидация работоспособности созданного ключа обращением к `/v1/models`.
- **Clean Persistence**: Сохранение результатов в `keys.txt`, `accounts.txt` и `accounts.json` (исключены из git через `.gitignore`).

---

## 🛠 Installation / Установка

```bash
git clone https://github.com/greenyarik0505-jpg/apodex-autoreg.git
cd apodex-autoreg
pip install -r requirements.txt
```

---

## 🚀 Usage / Использование

### 1. Direct Run (No Proxy) / Без прокси
```bash
python autoreg.py -n 1 --no-proxy
```

### 2. Run with Proxies / С использованием прокси
Добавьте прокси в файл `proxies.txt` (по одному на строку). Поддерживаются форматы:
```text
ip:port
ip:port:user:pass
user:pass@ip:port
http://user:pass@ip:port
socks5://user:pass@ip:port
socks5h://user:pass@ip:port
```

Запуск:
```bash
python autoreg.py -n 5 -p proxies.txt
```

### CLI Arguments / Параметры
- `-n`, `--count`: Количество учетных записей для цикла тестирования (по умолчанию `1`).
- `-p`, `--proxy-file`: Файл со списком прокси (по умолчанию `proxies.txt`).
- `--no-proxy`: Принудительный режим прямого подключения.

---

## 🔬 Protocol & Endpoints Studied

- **Auth Host**: `https://auth.apodex.ai`
  - `POST /api/auth/passwordless/send-code`
  - `POST /api/auth/v2/passwordless/verify-login`
- **Platform Host**: `https://platform.apodex.ai`
  - `GET /v1/user/account`
  - `POST /v1/api-keys`
- **Inference Host**: `https://api.apodex.ai/v1`
  - `GET /v1/models`

---

## 📜 License
MIT License. See [LICENSE](LICENSE) for details.

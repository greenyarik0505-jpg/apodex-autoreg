#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Apodex Platform API Automation & Verification Toolkit
Author: ENI

DISCLAIMER / LEGAL NOTICE:
This software is developed strictly for educational, security auditing,
and API integration testing purposes. It demonstrates automated OAuth/OTP
authentication workflows and resilience testing against passwordless endpoints.
The author assumes no liability and is not responsible for any misuse or
violation of third-party Terms of Service.
"""

import os
import re
import sys
import time
import json
import random
import string
import logging
import argparse
from typing import Optional, Dict, Any, List
import requests

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("ApodexAutoReg")

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
    """
    Parses proxies in various formats:
    - ip:port
    - ip:port:user:pass
    - user:pass@ip:port
    - http://user:pass@ip:port
    - socks5://user:pass@ip:port
    """
    raw_proxy = raw_proxy.strip()
    if not raw_proxy or raw_proxy.startswith("#"):
        return None

    if "://" not in raw_proxy:
        parts = raw_proxy.split(":")
        if len(parts) == 2:
            proxy_url = f"http://{parts[0]}:{parts[1]}"
        elif len(parts) == 4:
            # ip:port:user:pass
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
    """Mail.tm client for receiving disposable emails and OTP codes"""
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
        # 1. Get available domains
        resp = self.session.get(f"{self.BASE_URL}/domains", timeout=10)
        resp.raise_for_status()
        domains = resp.json().get("hydra:member", [])
        if not domains:
            raise RuntimeError("No domains available on mail.tm")

        domain = random.choice(domains)["domain"]
        self.email = f"{random_string(10)}@{domain}"
        self.password = f"SecP@{random_string(8)}!"

        # 2. Register account
        reg_resp = self.session.post(
            f"{self.BASE_URL}/accounts",
            json={"address": self.email, "password": self.password},
            timeout=10
        )
        reg_resp.raise_for_status()

        # 3. Get JWT token
        auth_resp = self.session.post(
            f"{self.BASE_URL}/token",
            json={"address": self.email, "password": self.password},
            timeout=10
        )
        auth_resp.raise_for_status()
        self.token = auth_resp.json()["token"]
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})

        return self.email

    def wait_for_otp(self, timeout_sec: int = 60, poll_interval: int = 4) -> str:
        """Polls inbox for the 6-digit OTP code"""
        end_time = time.time() + timeout_sec
        while time.time() < end_time:
            time.sleep(poll_interval)
            try:
                r = self.session.get(f"{self.BASE_URL}/messages", timeout=10)
                if r.status_code != 200:
                    continue
                messages = r.json().get("hydra:member", [])
                for msg in messages:
                    # Check subject or intro
                    subject = msg.get("subject", "")
                    intro = msg.get("intro", "")
                    # Extract 6 digit code
                    code_match = re.search(r"\b(\d{6})\b", subject) or re.search(r"\b(\d{6})\b", intro)
                    if code_match:
                        return code_match.group(1)

                    # Also fetch message body if needed
                    msg_id = msg.get("id")
                    if msg_id:
                        detail = self.session.get(f"{self.BASE_URL}/messages/{msg_id}", timeout=10).json()
                        text_content = detail.get("text", "")
                        match = re.search(r"\b(\d{6})\b", text_content)
                        if match:
                            return match.group(1)
            except Exception as e:
                logger.debug(f"Polling error: {e}")
        raise TimeoutError(f"OTP code not received within {timeout_sec}s for {self.email}")


class ApodexAutoReg:
    """Apodex registration and key generation engine"""

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


def run_single_registration(proxy: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
    proxy_str = proxy["http"] if proxy else "Direct (no proxy)"
    logger.info(f"Starting registration flow [Proxy: {proxy_str}]")

    # 1. Create TempMail
    try:
        mail_client = MailTmClient(proxies=proxy)
        email = mail_client.create_account()
        logger.info(f"[1/4] TempMail generated: {email}")
    except Exception as e:
        logger.error(f"Failed to generate temp mail: {e}")
        return None

    # 2. Request OTP Code from Apodex
    autoreg = ApodexAutoReg(proxy=proxy)
    logger.info("[2/4] Requesting verification code from Apodex...")
    if not autoreg.send_verification_code(email):
        return None

    # 3. Wait for OTP
    try:
        logger.info("Waiting for OTP email (up to 60s)...")
        code = mail_client.wait_for_otp(timeout_sec=60)
        logger.info(f"[3/4] OTP code received: {code}")
    except Exception as e:
        logger.error(f"Failed to receive OTP: {e}")
        return None

    # 4. Verify login and acquire session
    try:
        login_data = autoreg.verify_login(email, code)
        logger.info("Successfully authenticated! Account initialized.")
    except Exception as e:
        logger.error(f"Failed to verify login: {e}")
        return None

    # 5. Check credits & Create API key
    try:
        account_info = autoreg.get_account_credits()
        credits_cents = account_info.get("credits", {}).get("active_cents", 0)
        credits_usd = credits_cents / 100.0
        logger.info(f"Account bonus credits: ${credits_usd:.2f} USD")

        key_data = autoreg.create_api_key(name=f"Autoreg_{random_string(6)}")
        api_key = key_data.get("key")
        logger.info(f"[4/4] API Key created successfully: {api_key}")

        # Test key validity
        valid = autoreg.test_api_key(api_key)
        logger.info(f"API Key verification on /v1/models: {'VALID (200 OK)' if valid else 'FAILED'}")

        result = {
            "email": email,
            "api_key": api_key,
            "key_id": key_data.get("id"),
            "credits_usd": credits_usd,
            "access_token": autoreg.access_token,
            "refresh_token": autoreg.refresh_token,
            "proxy": proxy_str,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        # Save to disk
        save_result(result)
        return result
    except Exception as e:
        logger.error(f"Failed to create API key: {e}")
        return None


def save_result(res: Dict[str, Any]):
    # 1. Append to keys.txt
    with open("keys.txt", "a", encoding="utf-8") as f:
        f.write(f"{res['api_key']}\n")

    # 2. Append to accounts.txt (email:api_key:credits)
    with open("accounts.txt", "a", encoding="utf-8") as f:
        f.write(f"{res['email']}:{res['api_key']}:${res['credits_usd']:.2f}\n")

    # 3. Append to accounts.json
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


def main():
    parser = argparse.ArgumentParser(description="Apodex Platform AutoReg with TempMail and Proxy Support")
    parser.add_argument("-n", "--count", type=int, default=1, help="Number of accounts to create (default: 1)")
    parser.add_argument("-p", "--proxy-file", type=str, default="proxies.txt", help="Path to proxy list (default: proxies.txt)")
    parser.add_argument("--no-proxy", action="store_true", help="Force direct connection without proxies")
    args = parser.parse_args()

    print("=" * 60)
    print("   APODEX.AI PLATFORM ACCOUNT & API-KEY AUTOREG")
    print("   Base URL: https://api.apodex.ai/v1/")
    print("=" * 60)

    proxies = []
    if not args.no_proxy:
        proxies = load_proxies(args.proxy_file)
        if proxies:
            logger.info(f"Loaded {len(proxies)} proxies from {args.proxy_file}")
        else:
            logger.warning(f"No proxies found in {args.proxy_file}. Continuing with direct connection.")

    success_count = 0
    for i in range(1, args.count + 1):
        print(f"\n--- [Account {i}/{args.count}] ---")
        selected_proxy = random.choice(proxies) if proxies else None
        res = run_single_registration(proxy=selected_proxy)
        if res:
            success_count += 1
            print(f"\n>>> ACCOUNT REGISTERED:")
            print(f"    Email:   {res['email']}")
            print(f"    API Key: {res['api_key']}")
            print(f"    Balance: ${res['credits_usd']:.2f} USD")
            print(f"    Saved:   keys.txt, accounts.txt, accounts.json")
        else:
            print(">>> REGISTRATION FAILED for this attempt.")
        
        if i < args.count:
            delay = random.randint(3, 7)
            logger.info(f"Cooldown {delay}s before next registration...")
            time.sleep(delay)

    print("\n" + "=" * 60)
    print(f"Finished! Successfully registered: {success_count}/{args.count}")
    print("=" * 60)


if __name__ == "__main__":
    main()

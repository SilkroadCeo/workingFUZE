from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request, Response, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
import json
import shutil
from datetime import datetime, timedelta
from typing import Optional
import random
import string
import asyncio
import logging
import hashlib
import hmac
import uuid
from urllib.parse import parse_qs
from dotenv import load_dotenv
import database as db  # Using unified database instead of data.json
import time
import threading

# Определяем current_dir сразу и загружаем .env из backend (чтобы load_dotenv точно нашёл файл)
current_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(current_dir, ".env"))

# Load environment variables
# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Muji - Anonymous Dating", version="15.0.0")

# Разрешаем CORS (включая ngrok и Telegram WebApp)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Разрешаем все origins для ngrok и Telegram WebApp
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    expose_headers=["Set-Cookie"],
)

# Пути
frontend_dir = os.path.join(current_dir, "../frontend")
DATA_FILE = os.path.join(current_dir, "data.json")  # Legacy data file
UPLOAD_DIR = os.path.join(current_dir, "uploads")

# Создаем папку для загрузок если её нет
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize database
db.init_database()

print("🚀 Запускаем сервер Muji на порту 8001...")

# ============= TELEGRAM WEBAPP AUTHENTICATION =============

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
# Fallback: hardcoded token if .env not found
if not TELEGRAM_BOT_TOKEN:
    TELEGRAM_BOT_TOKEN = "8082508231:AAH7t5hMSczHjLEmIDmZR2L5aOiNELejiEk"
    logger.warning("⚠️ Using hardcoded TELEGRAM_BOT_TOKEN (fallback from .env)")

# Флаг для локальной разработки (если DEV=1 — не ставим secure cookie)
_is_dev = os.getenv("DEV", "0").lower() in ("1", "true", "yes")
_secure_cookie = not _is_dev

if not TELEGRAM_BOT_TOKEN:
    logger.warning("⚠️ TELEGRAM_BOT_TOKEN not available")

# Session storage moved to database (no longer in-memory)


def verify_telegram_auth(init_data: str, max_age_seconds: int = 86400) -> bool:
    """
    Проверка подлинности данных от Telegram Web App

    Args:
        init_data: Строка initData от Telegram WebApp
        max_age_seconds: Максимальный возраст данных в секундах (по умолчанию 24 часа)

    Returns:
        True если данные валидны и не устарели, иначе False
    """
    if not TELEGRAM_BOT_TOKEN:
        logger.error("⚠️ TELEGRAM_BOT_TOKEN not configured")
        return False

    try:
        parsed_data = parse_qs(init_data)
        received_hash = parsed_data.get('hash', [''])[0]

        if not received_hash:
            logger.warning("⚠️ Missing hash in Telegram auth data")
            return False

        # Формируем строку для проверки
        data_check_arr = []
        for key, value in sorted(parsed_data.items()):
            if key != 'hash':
                data_check_arr.append(f"{key}={value[0]}")

        data_check_string = '\n'.join(data_check_arr)

        # Вычисляем hash согласно официальной документации Telegram
        # Step 1: secret_key = HMAC-SHA256("WebAppData", bot_token)
        secret_key = hmac.new(
            "WebAppData".encode(),
            TELEGRAM_BOT_TOKEN.encode(),
            hashlib.sha256
        ).digest()

        # Step 2: hash = HMAC-SHA256(data_check_string, secret_key)
        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode(),
            hashlib.sha256
        ).hexdigest()

        # Проверка подлинности хеша (защита от атак по времени)
        if not hmac.compare_digest(calculated_hash, received_hash):
            logger.warning("⚠️ Invalid hash in Telegram auth data")
            return False

        # Проверка свежести данных (защита от повторных атак)
        auth_date = parsed_data.get('auth_date', ['0'])[0]
        try:
            auth_timestamp = int(auth_date)
            current_timestamp = int(datetime.now().timestamp())

            if current_timestamp - auth_timestamp > max_age_seconds:
                logger.warning(f"⚠️ Telegram auth data too old: {current_timestamp - auth_timestamp} seconds")
                return False
        except (ValueError, TypeError):
            logger.warning("⚠️ Invalid auth_date in Telegram auth data")
            return False

        return True
    except Exception as e:
        logger.error(f"Telegram auth verification error: {e}")
        return False


def create_telegram_session(user_data: dict) -> str:
    """Create new Telegram user session in database"""
    session_id = str(uuid.uuid4())
    expires_at = (datetime.now() + timedelta(days=30)).isoformat()
    
    db.create_session(
        session_id=session_id,
        telegram_id=user_data.get("telegram_id"),
        user_data=user_data,
        expires_at=expires_at
    )
    
    return session_id


def verify_telegram_session(session_id: str) -> bool:
    """Verify Telegram session validity (checks database)"""
    if not session_id:
        return False
    user_data = db.get_session(session_id)
    return user_data is not None


def get_telegram_session_user(session_id: str) -> Optional[dict]:
    """Get Telegram user data from session (from database)"""
    return db.get_session(session_id)


def destroy_telegram_session(session_id: str):
    """Destroy Telegram session in database"""
    db.delete_session(session_id)


async def get_telegram_user(request: Request):
    """
    Get current Telegram user from session
    This dependency is used for Telegram Mini App endpoints
    """
    session_id = request.cookies.get("telegram_session")

    if not session_id or not verify_telegram_session(session_id):
        raise HTTPException(status_code=401, detail="Telegram authentication required")

    user_data = get_telegram_session_user(session_id)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid Telegram session")

    return user_data


async def get_telegram_user_optional(request: Request) -> Optional[dict]:
    """
    Get Telegram user if authenticated, None otherwise
    For endpoints that work with or without authentication
    """
    session_id = request.cookies.get("telegram_session")
    if session_id and verify_telegram_session(session_id):
        return get_telegram_session_user(session_id)
    return None


# ============= END TELEGRAM AUTHENTICATION =============

# Генерация случайного 18-значного кода для ордеров
def generate_order_code():
    """Генерирует случайный 18-значный код из букв и цифр"""
    characters = string.ascii_letters + string.digits  # a-z, A-Z, 0-9
    return ''.join(random.choice(characters) for _ in range(18))

# Фоновая задача для удаления просроченных заказов
async def cleanup_expired_orders():
    """Удаляет заказы, которые не оплачены в течение 1 часа"""
    while True:
        try:
            data = load_data()
            now = datetime.now()

            # Фильтруем только непросроченные или оплаченные заказы
            initial_count = len(data.get("orders", []))
            data["orders"] = [
                o for o in data.get("orders", [])
                if o.get("status") != "unpaid" or
                   (o.get("expires_at") and datetime.fromisoformat(o["expires_at"]) > now)
            ]

            deleted_count = initial_count - len(data["orders"])
            if deleted_count > 0:
                save_data(data)
                logger.info(f"🗑️ Cleaned up {deleted_count} expired unpaid orders")

            # Проверяем каждые 60 секунд
            await asyncio.sleep(60)
        except Exception as e:
            logger.error(f"❌ Error cleaning up expired orders: {e}")
            await asyncio.sleep(60)

# Запуск фоновых задач при старте
@app.on_event("startup")
async def startup_event():
    """Запуск фоновых задач при старте приложения"""
    logger.info("🧹 Starting cleanup tasks...")
    
    # Очищаем истекшие сессии
    db.cleanup_expired_sessions()
    
    asyncio.create_task(cleanup_expired_orders())

# Раздаем статические файлы
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")
    # Mount icons directory for PWA icons
    icons_dir = os.path.join(frontend_dir, "icons")
    if os.path.exists(icons_dir):
        app.mount("/icons", StaticFiles(directory=icons_dir), name="icons")

# Раздаем загруженные файлы
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Глобальный кэш данных и блокировка для синхронизации доступа
_data_cache = None
_cache_lock = threading.RLock()
_cache_timestamp = 0
_cache_ttl = 5  # Кэш действителен 5 секунд

def load_data():
    """Load data with caching to prevent concurrent access issues"""
    global _data_cache, _cache_timestamp
    
    current_time = time.time()
    
    # Быстрая проверка без блокировки (double-check locking)
    if _data_cache is not None and (current_time - _cache_timestamp) < _cache_ttl:
        return _data_cache.copy() if isinstance(_data_cache, dict) else _data_cache
    
    with _cache_lock:
        # Двойная проверка после получения блокировки
        current_time_check = time.time()
        if _data_cache is not None and (current_time_check - _cache_timestamp) < _cache_ttl:
            return _data_cache.copy() if isinstance(_data_cache, dict) else _data_cache
        
        # Загружаем из файла
        if not os.path.exists(DATA_FILE):
            default_data = {
                "profiles": [],
                "vip_profiles": [],
                "chats": [],
                "messages": [],
                "comments": [],
                "promocodes": [],
                "orders": [],
                "settings": {
                    "app": {
                        "app_name": "Muji",
                        "default_age": 25,
                        "default_city": "Moscow",
                        "vip_blurred_count": 3,
                        "extra_vip_blurred_count": 3,
                        "secret_blurred_count": 3
                    },
                    "crypto_wallets": {
                        "trc20": "TY76gU8J9o8j7U6tY5r4E3W2Q1",
                        "erc20": "0x8a9C6e5D8b0E2a1F3c4B6E7D8C9A0B1C2D3E4F5",
                        "bnb": "bnb1q3e5r7t9y1u3i5o7p9l1k3j5h7g9f2d4s6q8w0"
                    },
                    "banner": {
                        "text": "Special Offer: 15% discount with promo code WELCOME15",
                        "visible": True,
                        "link": "https://t.me/yourchannel",
                        "link_text": "Join Channel"
                    },
                    "vip_catalogs": {
                        "vip": {
                            "name": "VIP Catalog",
                            "price": 199,
                            "redirect_url": "https://t.me/vip_channel",
                            "visible": True,
                            "preview_count": 3,
                            "preview_profiles": [
                                {"name": "Anna", "age": 23, "city": "Moscow", "photo": ""},
                                {"name": "Sofia", "age": 21, "city": "Saint Petersburg", "photo": ""},
                                {"name": "Maria", "age": 25, "city": "Kazan", "photo": ""}
                            ]
                        },
                        "extra_vip": {
                            "name": "Extra VIP",
                            "price": 699,
                            "redirect_url": "https://t.me/extra_vip_channel",
                            "visible": True,
                            "preview_count": 3,
                            "preview_profiles": [
                                {"name": "Elena", "age": 22, "city": "Novosibirsk", "photo": ""},
                                {"name": "Victoria", "age": 24, "city": "Yekaterinburg", "photo": ""},
                                {"name": "Daria", "age": 20, "city": "Krasnoyarsk", "photo": ""}
                            ]
                        },
                        "secret": {
                            "name": "Secret Catalog",
                            "price": 2499,
                            "redirect_url": "https://t.me/secret_channel",
                            "visible": True,
                            "preview_count": 3,
                            "preview_profiles": [
                                {"name": "Anastasia", "age": 26, "city": "Vladivostok", "photo": ""},
                                {"name": "Polina", "age": 23, "city": "Rostov", "photo": ""},
                                {"name": "Alina", "age": 21, "city": "Sochi", "photo": ""}
                            ]
                        }
                    }
                }
            }
            _data_cache = default_data
            _cache_timestamp = current_time_check
            return default_data.copy()
        
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)
                _cache_timestamp = current_time_check
                
                # Убедитесь что все секции существуют
                if "settings" not in loaded_data:
                    loaded_data["settings"] = {}
                if "crypto_wallets" not in loaded_data.get("settings", {}):
                    loaded_data["settings"]["crypto_wallets"] = {
                        "trc20": "TY76gU8J9o8j7U6tY5r4E3W2Q1",
                        "erc20": "0x8a9C6e5D8b0E2a1F3c4B6E7D8C9A0B1C2D3E4F5",
                        "bnb": "bnb1q3e5r7t9y1u3i5o7p9l1k3j5h7g9f2d4s6q8w0"
                    }
                if "orders" not in loaded_data:
                    loaded_data["orders"] = []
                if "chats" not in loaded_data:
                    loaded_data["chats"] = []
                if "messages" not in loaded_data:
                    loaded_data["messages"] = []
                if "comments" not in loaded_data:
                    loaded_data["comments"] = []
                if "vip_profiles" not in loaded_data:
                    loaded_data["vip_profiles"] = []
                    
                _data_cache = loaded_data
                return loaded_data.copy()
                
        except Exception as e:
            logger.error(f"❌ Error loading data: {e}")
            error_data = {
                "profiles": [],
                "chats": [],
                "messages": [],
                "orders": [],
                "comments": [],
                "vip_profiles": [],
                "promocodes": [],
                "settings": {
                    "crypto_wallets": {}
                }
            }
            _data_cache = error_data
            _cache_timestamp = current_time_check
            return error_data.copy()

def save_data(data):
    """Save data with locking to prevent concurrent writes"""
    try:
        with _cache_lock:
            # Записываем в файл атомарно (с временным файлом)
            temp_file = DATA_FILE + '.tmp'
            
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            # Атомарный обмен файлов
            if os.path.exists(DATA_FILE):
                os.remove(DATA_FILE)
            os.rename(temp_file, DATA_FILE)
            
            # Инвалидируем кэш
            global _data_cache, _cache_timestamp
            _data_cache = data.copy()
            _cache_timestamp = time.time()
            
            logger.debug("✅ Data saved successfully")
            return True
            
    except Exception as e:
        logger.error(f"❌ Error saving data: {e}")
        return False

# Загрузка данных
def load_data_legacy():
    if not os.path.exists(DATA_FILE):
        return {
            "profiles": [],
            "vip_profiles": [],
            "chats": [],
            "messages": [],
            "comments": [],
            "promocodes": [],
            "settings": {
                "app": {
                    "app_name": "Muji",
                    "default_age": 25,
                    "default_city": "Moscow",
                    "vip_blurred_count": 3,
                    "extra_vip_blurred_count": 3,
                    "secret_blurred_count": 3
                },
                "crypto_wallets": {
                    "trc20": "TY76gU8J9o8j7U6tY5r4E3W2Q1",
                    "erc20": "0x8a9C6e5D8b0E2a1F3c4B6E7D8C9A0B1C2D3E4F5",
                    "bnb": "bnb1q3e5r7t9y1u3i5o7p9l1k3j5h7g9f2d4s6q8w0"
                },
                "banner": {
                    "text": "Special Offer: 15% discount with promo code WELCOME15",
                    "visible": True,
                    "link": "https://t.me/yourchannel",
                    "link_text": "Join Channel"
                },
                "vip_catalogs": {
                    "vip": {
                        "name": "VIP Catalog",
                        "price": 199,
                        "redirect_url": "https://t.me/vip_channel",
                        "visible": True,
                        "preview_count": 3,
                        "preview_profiles": [
                            {"name": "Anna", "age": 23, "city": "Moscow", "photo": ""},
                            {"name": "Sofia", "age": 21, "city": "Saint Petersburg", "photo": ""},
                            {"name": "Maria", "age": 25, "city": "Kazan", "photo": ""}
                        ]
                    },
                    "extra_vip": {
                        "name": "Extra VIP",
                        "price": 699,
                        "redirect_url": "https://t.me/extra_vip_channel",
                        "visible": True,
                        "preview_count": 3,
                        "preview_profiles": [
                            {"name": "Elena", "age": 22, "city": "Novosibirsk", "photo": ""},
                            {"name": "Victoria", "age": 24, "city": "Yekaterinburg", "photo": ""},
                            {"name": "Daria", "age": 20, "city": "Krasnoyarsk", "photo": ""}
                        ]
                    },
                    "secret": {
                        "name": "Secret Catalog",
                        "price": 2499,
                        "redirect_url": "https://t.me/secret_channel",
                        "visible": True,
                        "preview_count": 3,
                        "preview_profiles": [
                            {"name": "Anastasia", "age": 26, "city": "Vladivostok", "photo": ""},
                            {"name": "Polina", "age": 23, "city": "Rostov", "photo": ""},
                            {"name": "Alina", "age": 21, "city": "Sochi", "photo": ""}
                        ]
                    }
                }
            }
        }
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.loads(f.read())
            # Ensure settings exist
            if "settings" not in data:
                data["settings"] = {
                    "crypto_wallets": {
                        "trc20": "TY76gU8J9o8j7U6tY5r4E3W2Q1",
                        "erc20": "0x8a9C6e5D8b0E2a1F3c4B6E7D8C9A0B1C2D3E4F5",
                        "bnb": "bnb1q3e5r7t9y1u3i5o7p9l1k3j5h7g9f2d4s6q8w0"
                    },
                    "banner": {
                        "text": "Special Offer: 15% discount with promo code WELCOME15",
                        "visible": True,
                        "link": "https://t.me/yourchannel",
                        "link_text": "Join Channel"
                    },
                    "vip_catalogs": {
                        "vip": {
                            "name": "VIP Catalog",
                            "price": 100,
                            "redirect_url": "https://t.me/vip_channel",
                            "visible": True,
                            "preview_count": 3
                        },
                        "extra_vip": {
                            "name": "Extra VIP",
                            "price": 200,
                            "redirect_url": "https://t.me/extra_vip_channel",
                            "visible": True,
                            "preview_count": 3
                        },
                        "secret": {
                            "name": "Secret Catalog",
                            "price": 300,
                            "redirect_url": "https://t.me/secret_channel",
                            "visible": True,
                            "preview_count": 3
                        }
                    }
                }
            if "promocodes" not in data:
                data["promocodes"] = []
            if "comments" not in data:
                data["comments"] = []
            if "vip_profiles" not in data:
                data["vip_profiles"] = []
            return data
    except Exception as e:
        print(f"Error loading data: {e}")
        return {
            "profiles": [],
            "vip_profiles": [],
            "chats": [],
            "messages": [],
            "comments": [],
            "promocodes": [],
            "settings": {
                "app": {
                    "app_name": "Muji",
                    "default_age": 25,
                    "default_city": "Moscow",
                    "vip_blurred_count": 3,
                    "extra_vip_blurred_count": 3,
                    "secret_blurred_count": 3
                },
                "crypto_wallets": {
                    "trc20": "TY76gU8J9o8j7U6tY5r4E3W2Q1",
                    "erc20": "0x8a9C6e5D8b0E2a1F3c4B6E7D8C9A0B1C2D3E4F5",
                    "bnb": "bnb1q3e5r7t9y1u3i5o7p9l1k3j5h7g9f2d4s6q8w0"
                },
                "banner": {
                    "text": "Special Offer: 15% discount with promo code WELCOME15",
                    "visible": True,
                    "link": "https://t.me/yourchannel",
                    "link_text": "Join Channel"
                },
                "vip_catalogs": {
                    "vip": {
                        "name": "VIP Catalog",
                        "price": 199,
                        "redirect_url": "https://t.me/vip_channel",
                        "visible": True,
                        "preview_count": 3,
                        "preview_profiles": [
                            {"name": "Anna", "age": 23, "city": "Moscow", "photo": ""},
                            {"name": "Sofia", "age": 21, "city": "Saint Petersburg", "photo": ""},
                            {"name": "Maria", "age": 25, "city": "Kazan", "photo": ""}
                        ]
                    },
                    "extra_vip": {
                        "name": "Extra VIP",
                        "price": 699,
                        "redirect_url": "https://t.me/extra_vip_channel",
                        "visible": True,
                        "preview_count": 3,
                        "preview_profiles": [
                            {"name": "Elena", "age": 22, "city": "Novosibirsk", "photo": ""},
                            {"name": "Victoria", "age": 24, "city": "Yekaterinburg", "photo": ""},
                            {"name": "Daria", "age": 20, "city": "Krasnoyarsk", "photo": ""}
                        ]
                    },
                    "secret": {
                        "name": "Secret Catalog",
                        "price": 2499,
                        "redirect_url": "https://t.me/secret_channel",
                        "visible": True,
                        "preview_count": 3,
                        "preview_profiles": [
                            {"name": "Anastasia", "age": 26, "city": "Vladivostok", "photo": ""},
                            {"name": "Polina", "age": 23, "city": "Rostov", "photo": ""},
                            {"name": "Alina", "age": 21, "city": "Sochi", "photo": ""}
                        ]
                    }
                }
            }
        }

# Сохранение файла
def save_uploaded_file(file: UploadFile) -> str:
    """Сохраняет загруженный файл и возвращает путь к нему"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{timestamp}_{file.filename}"
        file_path = os.path.join(UPLOAD_DIR, filename)

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        return f"/uploads/{filename}"
    except Exception as e:
        print(f"Error saving file: {e}")
        return ""

# Определяем тип файла по расширению
def get_file_type(filename: str) -> str:
    extension = filename.lower().split('.')[-1]
    image_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp']
    video_extensions = ['mp4', 'avi', 'mov', 'mkv', 'webm']

    if extension in image_extensions:
        return 'image'
    elif extension in video_extensions:
        return 'video'
    else:
        return 'file'

# API endpoints
@app.get("/")
async def main():
    # Возвращаем index.html если есть, иначе простой JSON для проверки работы бекенда.
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    logger.info("ℹ️ Frontend index.html not found, returning status JSON")
    return {"status": "ok", "message": "Muji backend is running", "frontend_found": False}

@app.get("/manifest.json")
async def get_manifest():
    """Serve PWA manifest file"""
    manifest_path = os.path.join(frontend_dir, "manifest.json")
    if os.path.exists(manifest_path):
        return FileResponse(manifest_path)
    # Если манифеста нет — вернуть 404 с коротким сообщением (меньше падений в логах nginx/ngrok)
    raise HTTPException(status_code=404, detail="manifest.json not found")


# ============= TELEGRAM AUTHENTICATION ENDPOINTS =============

@app.post("/api/telegram/auth")
async def telegram_auth(request: Request, response: Response):
    """
    Telegram Web App Authentication with HMAC verification
    Creates user session for Telegram Mini App
    """
    try:
        body = await request.json()
        init_data = body.get("initData")

        if not init_data:
            raise HTTPException(status_code=400, detail="Missing initData")

        # SECURITY: Verify Telegram data authenticity
        if not verify_telegram_auth(init_data):
            logger.warning("⚠️ Invalid Telegram authentication attempt")
            raise HTTPException(status_code=401, detail="Invalid Telegram authentication")

        # Parse user data from Telegram
        parsed_data = parse_qs(init_data)
        user_json = parsed_data.get('user', ['{}'])[0]
        user_data = json.loads(user_json) if user_json != '{}' else {}

        telegram_id = user_data.get('id')
        if not telegram_id:
            raise HTTPException(status_code=400, detail="Missing Telegram user ID")

        first_name = user_data.get('first_name', '')
        last_name = user_data.get('last_name', '')
        username = user_data.get('username', '')
        language_code = user_data.get('language_code', 'en')
        is_premium = user_data.get('is_premium', False)

        # Create session with user data
        session_user_data = {
            "telegram_id": telegram_id,
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "language_code": language_code,
            "is_premium": is_premium
        }

        session_id = create_telegram_session(session_user_data)

        # Set secure session cookie
        # В dev: secure=False и samesite='lax' чтобы cookie ставились на http локально.
        response.set_cookie(
            key="telegram_session",
            value=session_id,
            httponly=True,
            max_age=86400 * 30,  # 30 days
            samesite="none" if _secure_cookie else "lax",
            secure=_secure_cookie
        )

        logger.info(f"✅ Telegram user authenticated: {telegram_id} ({first_name} {last_name})")

        return {
            "status": "success",
            "user": {
                "telegram_id": telegram_id,
                "first_name": first_name,
                "last_name": last_name,
                "username": username,
                "language_code": language_code,
                "is_premium": is_premium
            }
        }
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON data")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Telegram auth error: {e}")
        raise HTTPException(status_code=500, detail="Authentication error")


@app.get("/api/telegram/me")
async def get_current_telegram_user_endpoint(user: dict = Depends(get_telegram_user)):
    """
    Get current authenticated Telegram user information
    This endpoint can be used to check if user is authenticated and get their data
    """
    return {
        "status": "success",
        "user": {
            "telegram_id": user["telegram_id"],
            "first_name": user["first_name"],
            "last_name": user["last_name"],
            "username": user.get("username", ""),
            "language_code": user.get("language_code", "en"),
            "is_premium": user.get("is_premium", False)
        }
    }


@app.post("/api/telegram/logout")
async def telegram_logout(request: Request, response: Response):
    """
    Logout Telegram user by destroying session
    """
    try:
        session_id = request.cookies.get("telegram_session")
        if session_id:
            destroy_telegram_session(session_id)
            response.delete_cookie(key="telegram_session")
            logger.info(f"✅ Telegram user logged out: session {session_id}")

        return {"status": "success", "message": "Logged out successfully"}
    except Exception as e:
        logger.error(f"❌ Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout error")


# ============= END TELEGRAM AUTHENTICATION ENDPOINTS =============

@app.get("/api/profiles")
async def get_profiles(
    page: int = 0,
    limit: int = 12,
    city: str = None,
    nationality: str = None,
    travel_city: str = None,
    age_min: int = None,
    age_max: int = None,
    height_min: int = None,
    height_max: int = None,
    weight_min: int = None,
    weight_max: int = None,
    chest_min: int = None,
    chest_max: int = None,
    gender: str = None
):
    data = load_data()
    profiles = [p for p in data["profiles"] if p.get("visible", True)]

    # Фильтрация по городу
    if city and city != "all":
        profiles = [p for p in profiles if p.get("city", "").lower() == city.lower()]

    # Фильтрация по национальности
    if nationality and nationality != "all":
        profiles = [p for p in profiles if p.get("nationality", "").lower() == nationality.lower()]

    # Фильтрация по городу вылета
    if travel_city and travel_city != "all":
        profiles = [p for p in profiles if travel_city.lower() in [c.lower() for c in p.get("travel_cities", [])]]

    # Фильтрация по возрасту
    if age_min:
        profiles = [p for p in profiles if p.get("age", 0) >= age_min]
    if age_max:
        profiles = [p for p in profiles if p.get("age", 100) <= age_max]

    # Фильтрация по росту
    if height_min:
        profiles = [p for p in profiles if p.get("height", 0) >= height_min]
    if height_max:
        profiles = [p for p in profiles if p.get("height", 250) <= height_max]

    # Фильтрация по весу
    if weight_min:
        profiles = [p for p in profiles if p.get("weight", 0) >= weight_min]
    if weight_max:
        profiles = [p for p in profiles if p.get("weight", 200) <= weight_max]

    # Фильтрация по груди
    if chest_min:
        profiles = [p for p in profiles if p.get("chest", 0) >= chest_min]
    if chest_max:
        profiles = [p for p in profiles if p.get("chest", 12) <= chest_max]

    # Фильтрация по полу
    if gender and gender != "all":
        profiles = [p for p in profiles if p.get("gender", "").lower() == gender.lower()]

    # Пагинация
    start = page * limit
    end = start + limit
    paginated_profiles = profiles[start:end]

    return {
        "profiles": paginated_profiles,
        "has_more": end < len(profiles),
        "total": len(profiles)
    }

@app.get("/api/vip-profiles")
async def get_vip_profiles():
    """Получить VIP анкеты для каталогов"""
    data = load_data()
    vip_profiles = data.get("vip_profiles", [])

    # Перемешиваем для рандомного отображения
    import random
    random.shuffle(vip_profiles)

    return {"profiles": vip_profiles}

@app.get("/api/vip-catalogs")
async def get_vip_catalogs():
    """Получить настройки VIP каталогов"""
    data = load_data()
    return data.get("settings", {}).get("vip_catalogs", {})

@app.get("/api/filters/cities")
async def get_cities():
    """Получить список всех городов для фильтра"""
    data = load_data()
    cities = list(set([p.get("city", "") for p in data["profiles"] if p.get("city")]))
    return {"cities": sorted(cities)}

@app.get("/api/filters/nationalities")
async def get_nationalities():
    """Получить список всех национальностей для фильтра"""
    data = load_data()
    nationalities = list(set([p.get("nationality", "") for p in data["profiles"] if p.get("nationality")]))
    return {"nationalities": sorted(nationalities)}

@app.get("/api/filters/travel_cities")
async def get_travel_cities():
    """Получить список всех городов вылета"""
    data = load_data()
    travel_cities = set()
    for profile in data["profiles"]:
        if "travel_cities" in profile:
            travel_cities.update(profile["travel_cities"])
    return {"travel_cities": sorted(list(travel_cities))}

@app.get("/api/filters/genders")
async def get_genders():
    """Получить список всех полов"""
    return {"genders": ["male", "female", "transgender"]}

@app.get("/api/profiles/{profile_id}")
async def get_profile(profile_id: int):
    data = load_data()
    profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Загружаем комментарии для этого профиля
    comments = [c for c in data.get("comments", []) if c["profile_id"] == profile_id]
    profile["comments"] = comments

    return profile

@app.post("/api/chats/{profile_id}/messages")
async def send_message(
    profile_id: int,
    request: Request,
    user: dict = Depends(get_telegram_user)
):
    """
    Отправка сообщения с возможностью прикрепления файла

    USER ISOLATION: Требуется авторизация. Сообщения привязаны к telegram_user_id.
    Парсим Form/multipart данные вручную для избежания 422 ошибок.
    """
    try:
        data = load_data()

        # Находим профиль для имени
        profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")

        # USER ISOLATION: Получаем telegram_user_id только из cookie
        actual_telegram_user_id = user.get("telegram_id")

        # Парсим Form данные вручную
        form_data = await request.form()
        text = form_data.get("text", "").strip() if form_data.get("text") else None
        file = form_data.get("file")

        # Проверяем тип file - может быть строка или UploadFile
        if isinstance(file, str) or (file and not hasattr(file, 'filename')):
            file = None

        # Валидируем: нужен либо текст, либо файл
        if not text and not file:
            raise HTTPException(status_code=400, detail="Text or file is required")

        # Находим или создаем чат для этого пользователя
        chat = next((c for c in data["chats"]
                    if c["profile_id"] == profile_id
                    and c.get("telegram_user_id") == actual_telegram_user_id), None)

        if not chat:
            chat = {
                "id": len(data["chats"]) + 1,
                "profile_id": profile_id,
                "profile_name": profile["name"],
                "created_at": datetime.now().isoformat(),
                "telegram_user_id": actual_telegram_user_id
            }
            data["chats"].append(chat)

        # Подготавливаем данные сообщения
        message_data = {
            "id": len(data["messages"]) + 1,
            "chat_id": chat["id"],
            "is_from_user": True,
            "created_at": datetime.now().isoformat()
        }

        # Если есть файл
        if file and hasattr(file, 'filename') and file.filename:
            file_url = save_uploaded_file(file)
            file_type = get_file_type(file.filename)

            message_data.update({
                "file_url": file_url,
                "file_type": file_type,
                "file_name": file.filename,
                "text": text or ""
            })
        else:
            # Только текст
            message_data["text"] = text

        data["messages"].append(message_data)
        save_data(data)
        logger.info(f"✅ Message sent: chat_id={chat['id']}, user_id={actual_telegram_user_id}, has_file={bool(file and hasattr(file, 'filename'))}")
        return {"status": "sent", "message_id": message_data["id"]}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error sending message: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Message send error: {str(e)}")

@app.get("/api/chats/{profile_id}/messages")
async def get_chat_messages(profile_id: int, user: dict = Depends(get_telegram_user)):
    """
    Получить сообщения чата

    ⚠️ ВАЖНО: Не передавайте telegram_user_id в URL параметрах!
    """
    try:
        data = load_data()
        telegram_user_id = user.get("telegram_id")

        # USER ISOLATION: Ищем чат этого пользователя с профилем
        chat = next((c for c in data["chats"]
                    if c["profile_id"] == profile_id
                    and c.get("telegram_user_id") == telegram_user_id), None)

        if not chat:
            return {"messages": []}

        messages = [m for m in data["messages"] if m["chat_id"] == chat["id"]]
        logger.debug(f"✅ Retrieved {len(messages)} messages for chat {profile_id}")
        return {"messages": messages}
    
    except Exception as e:
        logger.error(f"❌ Error retrieving messages: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Message retrieval error")


@app.get("/api/chats/{profile_id}/updates")
async def get_chat_updates(profile_id: int, last_message_id: int = 0, user: dict = Depends(get_telegram_user)):
    """
    Получить обновления чата (новые сообщения)

    ⚠️ ВАЖНО: Не передавайте telegram_user_id в URL параметрах!
    """
    try:
        data = load_data()
        telegram_user_id = user.get("telegram_id")

        # USER ISOLATION: Ищем чат этого пользователя с профилем
        chat = next((c for c in data["chats"]
                    if c["profile_id"] == profile_id
                    and c.get("telegram_user_id") == telegram_user_id), None)

        if not chat:
            return {"messages": [], "last_message_id": 0}

        messages = [m for m in data["messages"] if m["chat_id"] == chat["id"] and m["id"] > last_message_id]
        max_id = max([m["id"] for m in data["messages"]]) if data["messages"] else 0

        return {"messages": messages, "last_message_id": max_id}
    
    except Exception as e:
        logger.error(f"❌ Error retrieving chat updates: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Chat updates error")


@app.get("/api/user/chats")
async def get_user_chats(user: dict = Depends(get_telegram_user)):
    """
    Получить список всех чатов пользователя

    ⚠️ ВАЖНО: Не передавайте telegram_user_id в URL параметрах!
    """
    try:
        data = load_data()
        telegram_user_id = user.get("telegram_id")

        # USER ISOLATION: Фильтруем чаты по telegram_user_id
        chats = [c for c in data.get("chats", []) if c.get("telegram_user_id") == telegram_user_id]

        chat_list = []
        for chat in chats:
            # Получаем профиль
            profile = next((p for p in data["profiles"] if p["id"] == chat["profile_id"]), None)
            if not profile:
                continue

            # Получаем последнее сообщение
            chat_messages = [m for m in data["messages"] if m["chat_id"] == chat["id"]]
            last_message = None
            last_message_time = None

            if chat_messages:
                # Сортируем по времени создания или id
                chat_messages.sort(key=lambda x: x.get("created_at", ""), reverse=True)
                last_msg = chat_messages[0]

                # Формируем текст последнего сообщения
                if last_msg.get("file_url"):
                    if last_msg.get("file_type") == "image":
                        last_message = "📷 Image"
                    elif last_msg.get("file_type") == "video":
                        last_message = "🎥 Video"
                    else:
                        last_message = "📎 File"
                else:
                    last_message = last_msg.get("text", "")

                last_message_time = last_msg.get("created_at")
            else:
                last_message = "No messages yet"
                last_message_time = chat.get("created_at")

            # Считаем непрочитанные сообщения (от модели, после последнего прочитанного)
            last_read_id = chat.get("last_read_message_id", 0)
            unread_count = len([m for m in chat_messages
                               if not m.get("is_from_user", False)
                               and not m.get("is_system", False)
                               and m.get("id", 0) > last_read_id])

            chat_item = {
                "chat_id": chat["id"],
                "profile_id": chat["profile_id"],
                "profile_name": profile.get("name", "Unknown"),
                "profile_photo": profile.get("photos", [None])[0] if profile.get("photos") else None,
                "last_message": last_message,
                "last_message_time": last_message_time,
                "unread_count": unread_count
            }

            chat_list.append(chat_item)

        # Сортируем по времени последнего сообщения
        chat_list.sort(key=lambda x: x.get("last_message_time", ""), reverse=True)

        return {"chats": chat_list}
    
    except Exception as e:
        logger.error(f"❌ Error retrieving user chats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Chats retrieval error")


@app.post("/api/chats/{profile_id}/mark_read")
async def mark_chat_read(profile_id: int, user: dict = Depends(get_telegram_user)):
    """
    Пометить все сообщения чата как прочитанные

    ⚠️ ВАЖНО: Не передавайте telegram_user_id в URL параметрах!
    """
    try:
        data = load_data()
        telegram_user_id = user.get("telegram_id")

        # USER ISOLATION: Ищем чат этого пользователя
        chat = next((c for c in data["chats"]
                    if c["profile_id"] == profile_id
                    and c.get("telegram_user_id") == telegram_user_id), None)

        if not chat:
            return {"status": "chat_not_found"}

        # Находим максимальный ID сообщения в чате
        chat_messages = [m for m in data["messages"] if m["chat_id"] == chat["id"]]
        if chat_messages:
            max_message_id = max(m["id"] for m in chat_messages)
            chat["last_read_message_id"] = max_message_id
            save_data(data)

        return {"status": "marked_read"}
    
    except Exception as e:
        logger.error(f"❌ Error marking chat read: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Mark read error")


# Комментарии к профилям
@app.get("/api/profiles/{profile_id}/comments")
async def get_profile_comments(profile_id: int):
    data = load_data()
    comments = [c for c in data.get("comments", []) if c["profile_id"] == profile_id]
    return {"comments": comments}

@app.post("/api/profiles/{profile_id}/comments")
async def add_profile_comment(profile_id: int, comment_data: dict, user: dict = Depends(get_telegram_user)):
    """
    Добавить комментарий к профилю

    USER ISOLATION: Пользователь может оставить комментарий только если завершил транзакцию
    в своем собственном чате с этим профилем
    """
    data = load_data()

    telegram_user_id = user.get("telegram_id")

    # Проверяем существование профиля
    profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    # USER ISOLATION: Проверяем, есть ли у ЭТОГО пользователя чат с профилем
    chat = next((c for c in data["chats"]
                if c["profile_id"] == profile_id
                and c.get("telegram_user_id") == telegram_user_id), None)

    if not chat:
        raise HTTPException(
            status_code=403,
            detail="You need to complete a transaction to leave comments"
        )

    # Проверяем, завершил ли пользователь транзакцию в СВОЕМ чате
    messages = [m for m in data["messages"] if m["chat_id"] == chat["id"]]
    has_transaction_completed = any(
        m.get("is_system") and "transaction successful" in m.get("text", "").lower()
        for m in messages
    )

    if not has_transaction_completed:
        raise HTTPException(
            status_code=403,
            detail="You need to complete a transaction to leave comments"
        )

    # Get user information
    username = user.get("username") or user.get("first_name", "Anonymous")

    # Get promo code if used (from user's completed order for this profile)
    promo_code = None
    user_orders = [o for o in data.get("orders", [])
                   if o.get("telegram_user_id") == telegram_user_id
                   and o.get("profile_id") == profile_id
                   and o.get("status") == "booked"]
    if user_orders:
        # Get the most recent order's promo code if it exists
        promo_code = user_orders[-1].get("promo_code", None)

    new_comment = {
        "id": len(data.get("comments", [])) + 1,
        "profile_id": profile_id,
        "user_name": username,
        "telegram_username": user.get("username", ""),
        "promo_code": promo_code,
        "telegram_user_id": telegram_user_id,
        "text": comment_data["text"],
        "created_at": datetime.now().isoformat()
    }

    if "comments" not in data:
        data["comments"] = []
    data["comments"].append(new_comment)
    save_data(data)

    logger.info(f"✅ Comment added by user {telegram_user_id} to profile {profile_id}")
    return {"status": "added", "comment": new_comment}

@app.get("/api/settings/crypto_wallets")
async def get_crypto_wallets():
    """Получить настройки крипто-кошельков"""
    data = load_data()
    return data.get("settings", {}).get("crypto_wallets", {})

@app.get("/api/settings/banner")
async def get_banner():
    """Получить настройки баннера"""
    data = load_data()
    return data.get("settings", {}).get("banner", {})

@app.get("/api/settings/app")
async def get_app_settings():
    """Получить настройки приложения"""
    data = load_data()
    default_settings = {
        "app_name": "Muji",
        "default_age": 25,
        "default_city": "Moscow",
        "vip_blurred_count": 3,
        "extra_vip_blurred_count": 3,
        "secret_blurred_count": 3
    }
    return data.get("settings", {}).get("app", default_settings)

# Промокоды
@app.get("/api/promocodes")
async def get_promocodes():
    """Получить все промокоды"""
    data = load_data()
    return {"promocodes": data.get("promocodes", [])}

@app.post("/api/promocodes/validate")
async def validate_promocode(validation: dict):
    """Проверить промокод"""
    data = load_data()
    code = validation["code"].upper()

    promocode = next((p for p in data["promocodes"] if p["code"] == code), None)

    if not promocode:
        return {"valid": False, "message": "Promocode not found"}

    if not promocode["is_active"]:
        return {"valid": False, "message": "Promocode is inactive"}

    return {
        "valid": True,
        "discount": promocode["discount"],
        "message": f"Promocode activated! {promocode['discount']}% discount applied"
    }

# Система оплаты
@app.post("/api/payment/crypto")
async def process_crypto_payment(payment_data: dict, user: dict = Depends(get_telegram_user)):
    """
    Обработка крипто-платежа - создает заказ в orders

    USER ISOLATION: Требуется авторизация. Заказы привязаны к telegram_user_id.
    """
    data = load_data()

    profile_id = payment_data["profile_id"]
    amount = float(payment_data["amount"])
    currency = payment_data.get("currency", "USD")
    wallet_type = payment_data.get("wallet")

    if not profile_id or amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid payment data")

    # USER ISOLATION: Получаем telegram_user_id
    telegram_user_id = user.get("telegram_id")

    # Применяем бонус 5%
    bonus_percentage = data.get("settings", {}).get("bonus_percentage", 5)
    bonus_amount = amount * (bonus_percentage / 100)
    total_amount = amount + bonus_amount

    if "orders" not in data:
        data["orders"] = []

    # USER ISOLATION: Ищем существующий unpaid order для этого пользователя и профиля
    existing_order = next((o for o in data["orders"]
                          if o.get("profile_id") == profile_id
                          and o.get("status") == "unpaid"
                          and o.get("telegram_user_id") == telegram_user_id), None)

    if existing_order:
        # Обновляем существующий order
        existing_order["amount"] = amount
        existing_order["bonus_amount"] = bonus_amount
        existing_order["total_amount"] = total_amount
        existing_order["crypto_type"] = wallet_type
        existing_order["currency"] = currency
        existing_order["expires_at"] = (datetime.now() + timedelta(hours=1)).isoformat()
        order = existing_order
        logger.info(f"💰 Updated existing order #{order['id']}: ${amount} + {bonus_percentage}% bonus = ${total_amount}")
    else:
        # Создаем новый order с числовым ID и 18-значным order_number
        max_id = max([o.get("id", 0) for o in data["orders"]], default=0)
        order_number = generate_order_code()
        order = {
            "id": max_id + 1,
            "order_number": order_number,
            "profile_id": profile_id,
            "amount": amount,
            "bonus_amount": bonus_amount,
            "total_amount": total_amount,
            "crypto_type": wallet_type,
            "currency": currency,
            "status": "unpaid",
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=1)).isoformat(),
            "telegram_user_id": telegram_user_id
        }
        data["orders"].append(order)
        logger.info(f"💰 New payment order created #{order['order_number']}: ${amount} + {bonus_percentage}% bonus = ${total_amount}")

    save_data(data)

    return {
        "status": "success",
        "order_id": order["id"],
        "order_number": order.get("order_number", str(order["id"])),
        "amount": amount,
        "bonus_amount": bonus_amount,
        "total_amount": total_amount,
        "wallet_address": data.get("settings", {}).get("crypto_wallets", {}).get(wallet_type, ""),
        "expires_in": 3600
    }

@app.get("/api/user/orders")
async def get_user_orders(status: str = "all", user: dict = Depends(get_telegram_user)):
    """
    Получить список заказов пользователя (booked/unpaid/all)

    USER ISOLATION: Требуется авторизация. Возвращает только заказы этого пользователя.
    """
    data = load_data()

    telegram_user_id = user.get("telegram_id")

    # USER ISOLATION: Фильтруем заказы по telegram_user_id
    all_orders = [o for o in data.get("orders", []) if o.get("telegram_user_id") == telegram_user_id]

    # Фильтруем ордера по статусу
    if status == "booked":
        filtered_orders = [o for o in all_orders if o.get("status") == "booked"]
    elif status == "unpaid":
        filtered_orders = [o for o in all_orders if o.get("status") == "unpaid"]
    else:
        filtered_orders = all_orders

    orders = []
    for order in filtered_orders:
        # Получаем профиль
        profile = next((p for p in data["profiles"] if p["id"] == order["profile_id"]), None)
        if not profile:
            continue

        order_item = {
            "id": order["id"],
            "order_number": order.get("order_number", str(order["id"])),
            "profile_id": order["profile_id"],
            "profile_name": profile.get("name", "Unknown"),
            "profile_photo": profile.get("photos", [None])[0] if profile.get("photos") else None,
            "amount": order.get("total_amount", order.get("amount", 0)),
            "currency": order.get("currency", "USD"),
            "crypto_type": order.get("crypto_type"),
            "status": order.get("status"),
            "created_at": order.get("created_at"),
            "booked_at": order.get("booked_at"),
            "expires_at": order.get("expires_at")
        }

        orders.append(order_item)

    # Сортируем по времени создания (новые первыми)
    orders.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    return {"orders": orders}

@app.delete("/api/orders/{order_id}")
async def delete_order(order_id: int, user: dict = Depends(get_telegram_user)):
    """
    Удалить истекший ордер с проверкой владельца

    USER ISOLATION: Пользователь может удалить только свой заказ
    """
    data = load_data()

    telegram_user_id = user.get("telegram_id")

    # Находим ордер и проверяем владельца
    order = next((o for o in data.get("orders", [])
                  if o.get("id") == order_id
                  and o.get("telegram_user_id") == telegram_user_id), None)

    if not order:
        raise HTTPException(status_code=404, detail="Order not found or unauthorized")

    # Удаляем ордер
    initial_count = len(data.get("orders", []))
    data["orders"] = [o for o in data.get("orders", []) if o.get("id") != order_id]

    if len(data["orders"]) < initial_count:
        save_data(data)
        logger.info(f"✅ Order {order_id} deleted by user {telegram_user_id}")
        return {"status": "deleted", "order_id": order_id}
    else:
        raise HTTPException(status_code=404, detail="Order not found")

@app.get("/api/translations/{lang}")
async def get_translations(lang: str):
    """Получить переводы для указанного языка"""
    translations = {
        "en": {
            "app_name": "Muji",
            "subtitle": "100% Anonymous Dating",
            "premium_profiles": "Premium Profiles",
            "online_now": "Online Now",
            "anonymous_dating": "Anonymous Dating",
            "filters": "Filters",
            "city": "City",
            "nationality": "Nationality",
            "travel_city": "Travel City",
            "all_cities": "All cities",
            "all_nationalities": "All nationalities",
            "age": "Age",
            "height": "Height (cm)",
            "weight": "Weight (kg)",
            "chest": "Chest",
            "gender": "Gender",
            "all_genders": "All genders",
            "male": "Male",
            "female": "Female",
            "transgender": "Transgender",
            "chest_sizes": {
                "1": "1 chest",
                "2": "2 chest",
                "3": "3 chest",
                "4": "4 chest",
                "5": "5 chest",
                "6": "6 chest",
                "7": "7 chest",
                "8": "8 chest",
                "9": "9 chest",
                "10": "10 chest",
                "11": "11 chest",
                "12": "12 chest"
            },
            "reset": "Reset",
            "apply": "Apply",
            "loading": "Loading profiles...",
            "loading_more": "Loading more profiles...",
            "view_profile": "View Profile",
            "write_message": "Write Message",
            "book_with_crypto": "Book with Crypto",
            "more": "More",
            "share": "Share",
            "chat_with": "Chat with",
            "type_message": "Type a message...",
            "send": "➤",
            "no_chats": "No active chats",
            "no_profiles": "No profiles found",
            "new": "NEW",
            "years": "years",
            "cm": "cm",
            "kg": "kg",
            "download": "Download",
            "pay_with_crypto": "Pay with Crypto",
            "crypto_payment": "Crypto Payment",
            "select_network": "Select Network",
            "wallet_address": "Wallet Address",
            "copy": "Copy",
            "copied": "Copied!",
            "close": "Close",
            "payment_awaiting": "Awaiting Confirmation",
            "payment_processing": "Your reservation will be confirmed in chat, you can close this page.",
            "timer_label": "Time remaining",
            "travel_cities": "Travel Cities",
            "description": "Description",
            "welcome_message": "Hello! Write me a message",
            "error_sending": "Error sending message",
            "promocode": "Promo Code",
            "enter_promocode": "Enter promo code",
            "apply_promocode": "Apply",
            "promocode_applied": "Promo code applied!",
            "promocode_invalid": "Invalid promo code",
            "discount": "Discount",
            "banner_join": "Join Channel",
            "attach_file": "📎",
            "file": "File",
            "photo": "Photo",
            "video": "Video",
            "add_comment": "Add Comment",
            "comments": "Comments",
            "no_comments": "No comments yet",
            "your_comment": "Your comment",
            "post_comment": "Post Comment",
            "rating": "Rating",
            "payment_processing": "Processing payment...",
            "select_crypto": "Select Cryptocurrency",
            "amount": "Amount",
            "usd": "USD",
            "pay_now": "Pay",
            "booking_profile": "Booking Profile",
            "vip_catalog": "VIP Catalog",
            "extra_vip_catalog": "Extra VIP",
            "secret_catalog": "Secret Catalog",
            "unlock_access": "Unlock Access",
            "premium_profiles_count": "premium profiles",
            "blurred_preview": "Blurred Preview",
            "access_denied": "Access Denied",
            "pay_to_unlock": "Pay to unlock full access",
            "view_all_profiles": "View All Profiles",
            "from_age": "from",
            "years_short": "y.o",
            "comment_permission_required": "To leave comments, you need to use our services first",
            "complete_transaction_to_comment": "Complete a transaction to unlock comments"
        },
        "ja": {
            "app_name": "Muji",
            "subtitle": "100% 匿名デート",
            "premium_profiles": "プレミアムプロフィール",
            "online_now": "オンライン",
            "anonymous_dating": "匿名デート",
            "filters": "フィルター",
            "city": "都市",
            "nationality": "国籍",
            "travel_city": "旅行先都市",
            "all_cities": "すべての都市",
            "all_nationalities": "すべての国籍",
            "age": "年齢",
            "height": "身長 (cm)",
            "weight": "体重 (kg)",
            "chest": "バスト",
            "gender": "性別",
            "all_genders": "すべての性別",
            "male": "男性",
            "female": "女性",
            "transgender": "トランスジェンダー",
            "chest_sizes": {
                "1": "1 バスト",
                "2": "2 バスト",
                "3": "3 バスト",
                "4": "4 バスト",
                "5": "5 バスト",
                "6": "6 バスト",
                "7": "7 バスト",
                "8": "8 バスト",
                "9": "9 バスト",
                "10": "10 バスト",
                "11": "11 バスト",
                "12": "12 バスト"
            },
            "reset": "リセット",
            "apply": "適用",
            "loading": "プロフィールを読み込み中...",
            "loading_more": "さらに読み込み中...",
            "view_profile": "プロフィールを見る",
            "write_message": "メッセージを送る",
            "book_with_crypto": "暗号通貨で予約",
            "more": "もっと見る",
            "share": "共有",
            "chat_with": "とのチャット",
            "type_message": "メッセージを入力...",
            "send": "➤",
            "no_chats": "アクティブなチャットはありません",
            "no_profiles": "プロフィールが見つかりません",
            "new": "新着",
            "years": "歳",
            "cm": "cm",
            "kg": "kg",
            "download": "ダウンロード",
            "pay_with_crypto": "暗号通貨で支払う",
            "crypto_payment": "暗号通貨決済",
            "select_network": "ネットワークを選択",
            "wallet_address": "ウォレットアドレス",
            "copy": "コピー",
            "copied": "コピーしました！",
            "close": "閉じる",
            "payment_awaiting": "確認待ち",
            "payment_processing": "予約はチャットで確認されます。このページを閉じてください。",
            "timer_label": "残り時間",
            "travel_cities": "旅行先都市",
            "description": "説明",
            "welcome_message": "こんにちは！メッセージをお待ちしています",
            "error_sending": "メッセージ送信エラー",
            "promocode": "プロモコード",
            "enter_promocode": "プロモコードを入力",
            "apply_promocode": "適用",
            "promocode_applied": "プロモコードが適用されました！",
            "promocode_invalid": "無効なプロモコード",
            "discount": "割引",
            "banner_join": "チャンネルに参加",
            "attach_file": "📎",
            "file": "ファイル",
            "photo": "写真",
            "video": "ビデオ",
            "add_comment": "コメントを追加",
            "comments": "コメント",
            "no_comments": "まだコメントはありません",
            "your_comment": "コメントを入力",
            "post_comment": "コメントを投稿",
            "rating": "評価",
            "payment_processing": "支払いを処理中...",
            "select_crypto": "暗号通貨を選択",
            "amount": "金額",
            "usd": "USD",
            "pay_now": "支払う",
            "booking_profile": "予約プロフィール",
            "vip_catalog": "VIPカタログ",
            "extra_vip_catalog": "エクストラVIP",
            "secret_catalog": "シークレットカタログ",
            "unlock_access": "アクセスを解除",
            "premium_profiles_count": "プレミアムプロフィール",
            "blurred_preview": "ぼかしプレビュー",
            "access_denied": "アクセス拒否",
            "pay_to_unlock": "フルアクセスを解除するには支払いが必要です",
            "view_all_profiles": "すべてのプロフィールを見る",
            "from_age": "から",
            "years_short": "歳",
            "comment_permission_required": "コメントを投稿するには、まずサービスをご利用ください",
            "complete_transaction_to_comment": "取引を完了してコメントを解除してください"
        },
        "ko": {
            "app_name": "Muji",
            "subtitle": "100% 익명 데이트",
            "premium_profiles": "프리미엄 프로필",
            "online_now": "온라인",
            "anonymous_dating": "익명 데이트",
            "filters": "필터",
            "city": "도시",
            "nationality": "국적",
            "travel_city": "여행 도시",
            "all_cities": "모든 도시",
            "all_nationalities": "모든 국적",
            "age": "나이",
            "height": "키 (cm)",
            "weight": "체중 (kg)",
            "chest": "가슴",
            "gender": "성별",
            "all_genders": "모든 성별",
            "male": "남성",
            "female": "여성",
            "transgender": "트랜스젠더",
            "chest_sizes": {
                "1": "1 가슴",
                "2": "2 가슴",
                "3": "3 가슴",
                "4": "4 가슴",
                "5": "5 가슴",
                "6": "6 가슴",
                "7": "7 가슴",
                "8": "8 가슴",
                "9": "9 가슴",
                "10": "10 가슴",
                "11": "11 가슴",
                "12": "12 가슴"
            },
            "reset": "초기화",
            "apply": "적용",
            "loading": "프로필 로딩 중...",
            "loading_more": "더 불러오는 중...",
            "view_profile": "프로필 보기",
            "write_message": "메시지 보내기",
            "book_with_crypto": "암호화폐로 예약",
            "more": "더보기",
            "share": "공유",
            "chat_with": "와의 채팅",
            "type_message": "메시지를 입력하세요...",
            "send": "➤",
            "no_chats": "활성화된 채팅이 없습니다",
            "no_profiles": "프로필을 찾을 수 없습니다",
            "new": "새로운",
            "years": "세",
            "cm": "cm",
            "kg": "kg",
            "download": "다운로드",
            "pay_with_crypto": "암호화폐로 결제",
            "crypto_payment": "암호화폐 결제",
            "select_network": "네트워크 선택",
            "wallet_address": "지갑 주소",
            "copy": "복사",
            "copied": "복사되었습니다!",
            "close": "닫기",
            "payment_awaiting": "확인 대기 중",
            "payment_processing": "예약은 채팅에서 확인됩니다. 이 페이지를 닫으셔도 됩니다.",
            "timer_label": "남은 시간",
            "travel_cities": "여행 도시",
            "description": "설명",
            "welcome_message": "안녕하세요! 메시지를 보내주세요",
            "error_sending": "메시지 전송 오류",
            "promocode": "프로모 코드",
            "enter_promocode": "프로모 코드 입력",
            "apply_promocode": "적용",
            "promocode_applied": "프로모 코드가 적용되었습니다!",
            "promocode_invalid": "유효하지 않은 프로모 코드",
            "discount": "할인",
            "banner_join": "채널 참여",
            "attach_file": "📎",
            "file": "파일",
            "photo": "사진",
            "video": "동영상",
            "add_comment": "댓글 추가",
            "comments": "댓글",
            "no_comments": "아직 댓글이 없습니다",
            "your_comment": "댓글 입력",
            "post_comment": "댓글 작성",
            "rating": "평점",
            "payment_processing": "결제 처리 중...",
            "select_crypto": "암호화폐 선택",
            "amount": "금액",
            "usd": "USD",
            "pay_now": "결제",
            "booking_profile": "예약 프로필",
            "vip_catalog": "VIP 카탈로그",
            "extra_vip_catalog": "익스트라 VIP",
            "secret_catalog": "시크릿 카탈로그",
            "unlock_access": "액세스 잠금 해제",
            "premium_profiles_count": "프리미엄 프로필",
            "blurred_preview": "흐릿한 미리보기",
            "access_denied": "액세스 거부",
            "pay_to_unlock": "전체 액세스를 해제하려면 결제가 필요합니다",
            "view_all_profiles": "모든 프로필 보기",
            "from_age": "부터",
            "years_short": "세",
            "comment_permission_required": "댓글을 남기려면 먼저 서비스를 이용해야 합니다",
            "complete_transaction_to_comment": "거래를 완료하여 댓글을 잠금 해제하세요"
        },
        "zh": {
            "app_name": "Muji",
            "subtitle": "100% 匿名约会",
            "premium_profiles": "高级资料",
            "online_now": "在线",
            "anonymous_dating": "匿名约会",
            "filters": "筛选",
            "city": "城市",
            "nationality": "国籍",
            "travel_city": "旅行城市",
            "all_cities": "所有城市",
            "all_nationalities": "所有国籍",
            "age": "年龄",
            "height": "身高 (厘米)",
            "weight": "体重 (公斤)",
            "chest": "胸围",
            "gender": "性别",
            "all_genders": "所有性别",
            "male": "男性",
            "female": "女性",
            "transgender": "跨性别",
            "chest_sizes": {
                "1": "1 胸围",
                "2": "2 胸围",
                "3": "3 胸围",
                "4": "4 胸围",
                "5": "5 胸围",
                "6": "6 胸围",
                "7": "7 胸围",
                "8": "8 胸围",
                "9": "9 胸围",
                "10": "10 胸围",
                "11": "11 胸围",
                "12": "12 胸围"
            },
            "reset": "重置",
            "apply": "应用",
            "loading": "正在加载资料...",
            "loading_more": "正在加载更多资料...",
            "view_profile": "查看资料",
            "write_message": "发送消息",
            "book_with_crypto": "用加密货币预订",
            "more": "更多",
            "share": "分享",
            "chat_with": "与聊天",
            "type_message": "输入消息...",
            "send": "➤",
            "no_chats": "没有活跃聊天",
            "no_profiles": "未找到资料",
            "new": "新",
            "years": "岁",
            "cm": "厘米",
            "kg": "公斤",
            "download": "下载",
            "pay_with_crypto": "用加密货币支付",
            "crypto_payment": "加密货币支付",
            "select_network": "选择网络",
            "wallet_address": "钱包地址",
            "copy": "复制",
            "copied": "已复制！",
            "close": "关闭",
            "payment_awaiting": "等待确认",
            "payment_processing": "您的预订将在聊天中确认，您可以关闭此页面。",
            "timer_label": "剩余时间",
            "travel_cities": "旅行城市",
            "description": "描述",
            "welcome_message": "你好！给我发消息",
            "error_sending": "发送消息错误",
            "promocode": "优惠码",
            "enter_promocode": "输入优惠码",
            "apply_promocode": "应用",
            "promocode_applied": "优惠码已应用！",
            "promocode_invalid": "无效的优惠码",
            "discount": "折扣",
            "banner_join": "加入频道",
            "attach_file": "📎",
            "file": "文件",
            "photo": "照片",
            "video": "视频",
            "add_comment": "添加评论",
            "comments": "评论",
            "no_comments": "暂无评论",
            "your_comment": "您的评论",
            "post_comment": "发表评论",
            "rating": "评分",
            "payment_processing": "处理付款中...",
            "select_crypto": "选择加密货币",
            "amount": "金额",
            "usd": "美元",
            "pay_now": "支付",
            "booking_profile": "预订资料",
            "vip_catalog": "VIP目录",
            "extra_vip_catalog": "额外VIP",
            "secret_catalog": "秘密目录",
            "unlock_access": "解锁访问",
            "premium_profiles_count": "高级资料",
            "blurred_preview": "模糊预览",
            "access_denied": "访问被拒绝",
            "pay_to_unlock": "支付以解锁完整访问",
            "view_all_profiles": "查看所有资料",
            "from_age": "从",
            "years_short": "岁",
            "comment_permission_required": "要发表评论，您需要先使用我们的服务",
            "complete_transaction_to_comment": "完成交易以解锁评论"
        },
        "ar": {
            "app_name": "Muji",
            "subtitle": "مواعدة مجهولة 100%",
            "premium_profiles": "الملفات المميزة",
            "online_now": "متصل الآن",
            "anonymous_dating": "مواعدة مجهولة",
            "filters": "الفلاتر",
            "city": "المدينة",
            "nationality": "الجنسية",
            "travel_city": "مدينة السفر",
            "all_cities": "جميع المدن",
            "all_nationalities": "جميع الجنسيات",
            "age": "العمر",
            "height": "الطول (سم)",
            "weight": "الوزن (كجم)",
            "chest": "الصدر",
            "gender": "الجنس",
            "all_genders": "جميع الأجناس",
            "male": "ذكر",
            "female": "أنثى",
            "transgender": "متحول جنسي",
            "chest_sizes": {
                "1": "1 صدر",
                "2": "2 صدر",
                "3": "3 صدر",
                "4": "4 صدر",
                "5": "5 صدر",
                "6": "6 صدر",
                "7": "7 صدر",
                "8": "8 صدر",
                "9": "9 صدر",
                "10": "10 صدر",
                "11": "11 صدر",
                "12": "12 صدر"
            },
            "reset": "إعادة تعيين",
            "apply": "تطبيق",
            "loading": "جاري تحميل الملفات...",
            "loading_more": "جاري تحميل المزيد...",
            "view_profile": "عرض الملف",
            "write_message": "كتابة رسالة",
            "book_with_crypto": "حجز بالعملة المشفرة",
            "more": "المزيد",
            "share": "مشاركة",
            "chat_with": "الدردشة مع",
            "type_message": "اكتب رسالة...",
            "send": "➤",
            "no_chats": "لا توجد دردشات نشطة",
            "no_profiles": "لم يتم العثور على ملفات",
            "new": "جديد",
            "years": "سنة",
            "cm": "سم",
            "kg": "كجم",
            "download": "تحميل",
            "pay_with_crypto": "الدفع بالعملة المشفرة",
            "crypto_payment": "دفع بالعملة المشفرة",
            "select_network": "اختر الشبكة",
            "wallet_address": "عنوان المحفظة",
            "copy": "نسخ",
            "copied": "تم النسخ!",
            "close": "إغلاق",
            "payment_awaiting": "بانتظار التأكيد",
            "payment_processing": "سيتم تأكيد حجزك في الدردشة، يمكنك إغلاق هذه الصفحة.",
            "timer_label": "الوقت المتبقي",
            "travel_cities": "مدن السفر",
            "description": "الوصف",
            "welcome_message": "مرحباً! اكتب لي رسالة",
            "error_sending": "خطأ في إرسال الرسالة",
            "promocode": "كود الخصم",
            "enter_promocode": "أدخل كود الخصم",
            "apply_promocode": "تطبيق",
            "promocode_applied": "تم تطبيق كود الخصم!",
            "promocode_invalid": "كود خصم غير صالح",
            "discount": "خصم",
            "banner_join": "انضم إلى القناة",
            "attach_file": "📎",
            "file": "ملف",
            "photo": "صورة",
            "video": "فيديو",
            "add_comment": "إضافة تعليق",
            "comments": "التعليقات",
            "no_comments": "لا توجد تعليقات بعد",
            "your_comment": "تعليقك",
            "post_comment": "نشر التعليق",
            "rating": "التقييم",
            "payment_processing": "جاري معالجة الدفع...",
            "select_crypto": "اختر العملة المشفرة",
            "amount": "المبلغ",
            "usd": "دولار",
            "pay_now": "ادفع",
            "booking_profile": "حجز الملف",
            "vip_catalog": "كتالوج VIP",
            "extra_vip_catalog": "VIP الإضافي",
            "secret_catalog": "الكتالوج السري",
            "unlock_access": "فتح الوصول",
            "premium_profiles_count": "الملفات المميزة",
            "blurred_preview": "معاينة ضبابية",
            "access_denied": "تم رفض الوصول",
            "pay_to_unlock": "ادفع لفتح الوصول الكامل",
            "view_all_profiles": "عرض جميع الملفات",
            "from_age": "من",
            "years_short": "سنة",
            "comment_permission_required": "لترك تعليقات، تحتاج إلى استخدام خدماتنا أولاً",
                       "complete_transaction_to_comment": "أكمل معاملة لفتح التعليقات"
        },
        "de": {
            "app_name": "Muji",
            "subtitle": "100% Anonymes Dating",
            "premium_profiles": "Premium Profile",
            "online_now": "Jetzt online",
            "anonymous_dating": "Anonymes Dating",
            "filters": "Filter",
            "city": "Stadt",
            "nationality": "Nationalität",
            "travel_city": "Reisestadt",
            "all_cities": "Alle Städte",
            "all_nationalities": "Alle Nationalitäten",
            "age": "Alter",
            "height": "Größe (cm)",
            "weight": "Gewicht (kg)",
            "chest": "Brust",
            "gender": "Geschlecht",
            "all_genders": "Alle Geschlechter",
            "male": "Männlich",
            "female": "Weiblich",
            "transgender": "Transgender",
            "chest_sizes": {
                "1": "1 Brust",
                "2": "2 Brust",
                "3": "3 Brust",
                "4": "4 Brust",
                "5": "5 Brust",
                "6": "6 Brust",
                "7": "7 Brust",
                "8": "8 Brust",
                "9": "9 Brust",
                "10": "10 Brust",
                "11": "11 Brust",
                "12": "12 Brust"
            },
            "reset": "Zurücksetzen",
            "apply": "Anwenden",
            "loading": "Profile werden geladen...",
            "loading_more": "Weitere Profile werden geladen...",
            "view_profile": "Profil anzeigen",
            "write_message": "Nachricht schreiben",
            "book_with_crypto": "Mit Krypto buchen",
            "more": "Mehr",
            "share": "Teilen",
            "chat_with": "Chat mit",
            "type_message": "Nachricht eingeben...",
            "send": "➤",
            "no_chats": "Keine aktiven Chats",
            "no_profiles": "Keine Profile gefunden",
            "new": "NEU",
            "years": "Jahre",
            "cm": "cm",
            "kg": "kg",
            "download": "Herunterladen",
            "pay_with_crypto": "Mit Krypto bezahlen",
            "crypto_payment": "Krypto-Zahlung",
            "select_network": "Netzwerk auswählen",
            "wallet_address": "Wallet-Adresse",
            "copy": "Kopieren",
            "copied": "Kopiert!",
            "close": "Schließen",
            "payment_awaiting": "Warte auf Bestätigung",
            "payment_processing": "Ihre Buchung wird im Chat bestätigt, Sie können diese Seite schließen.",
            "timer_label": "Verbleibende Zeit",
            "travel_cities": "Reisestädte",
            "description": "Beschreibung",
            "welcome_message": "Hallo! Schreiben Sie mir eine Nachricht",
            "error_sending": "Fehler beim Senden der Nachricht",
            "promocode": "Promo-Code",
            "enter_promocode": "Promo-Code eingeben",
            "apply_promocode": "Anwenden",
            "promocode_applied": "Promo-Code angewendet!",
            "promocode_invalid": "Ungültiger Promo-Code",
            "discount": "Rabatt",
            "banner_join": "Kanal beitreten",
            "attach_file": "📎",
            "file": "Datei",
            "photo": "Foto",
            "video": "Video",
            "add_comment": "Kommentar hinzufügen",
            "comments": "Kommentare",
            "no_comments": "Noch keine Kommentare",
            "your_comment": "Ihr Kommentar",
            "post_comment": "Kommentar posten",
            "rating": "Bewertung",
            "payment_processing": "Zahlung wird verarbeitet...",
            "select_crypto": "Kryptowährung auswählen",
            "amount": "Betrag",
            "usd": "USD",
            "pay_now": "Bezahlen",
            "booking_profile": "Profil buchen",
            "vip_catalog": "VIP-Katalog",
            "extra_vip_catalog": "Extra VIP",
            "secret_catalog": "Geheimer Katalog",
            "unlock_access": "Zugang freischalten",
            "premium_profiles_count": "Premium-Profile",
            "blurred_preview": "Verschwommene Vorschau",
            "access_denied": "Zugriff verweigert",
            "pay_to_unlock": "Bezahlen Sie, um vollen Zugriff zu erhalten",
            "view_all_profiles": "Alle Profile anzeigen",
            "from_age": "von",
            "years_short": "Jahre",
            "comment_permission_required": "Um Kommentare zu hinterlassen, müssen Sie zuerst unsere Dienste nutzen",
            "complete_transaction_to_comment": "Schließen Sie eine Transaktion ab, um Kommentare freizuschalten"
        },
        "es": {
            "app_name": "Muji",
            "subtitle": "Citas 100% Anónimas",
            "premium_profiles": "Perfiles Premium",
            "online_now": "En Línea",
            "anonymous_dating": "Citas Anónimas",
            "filters": "Filtros",
            "city": "Ciudad",
            "nationality": "Nacionalidad",
            "travel_city": "Ciudad de Viaje",
            "all_cities": "Todas las ciudades",
            "all_nationalities": "Todas las nacionalidades",
            "age": "Edad",
            "height": "Altura (cm)",
            "weight": "Peso (kg)",
            "chest": "Pecho",
            "gender": "Género",
            "all_genders": "Todos los géneros",
            "male": "Masculino",
            "female": "Femenino",
            "transgender": "Transgénero",
            "chest_sizes": {
                "1": "1 pecho",
                "2": "2 pecho",
                "3": "3 pecho",
                "4": "4 pecho",
                "5": "5 pecho",
                "6": "6 pecho",
                "7": "7 pecho",
                "8": "8 pecho",
                "9": "9 pecho",
                "10": "10 pecho",
                "11": "11 pecho",
                "12": "12 pecho"
            },
            "reset": "Restablecer",
            "apply": "Aplicar",
            "loading": "Cargando perfiles...",
            "loading_more": "Cargando más perfiles...",
            "view_profile": "Ver Perfil",
            "write_message": "Escribir Mensaje",
            "book_with_crypto": "Reservar con Cripto",
            "more": "Más",
            "share": "Compartir",
            "chat_with": "Chat con",
            "type_message": "Escribe un mensaje...",
            "send": "➤",
            "no_chats": "No hay chats activos",
            "no_profiles": "No se encontraron perfiles",
            "new": "NUEVO",
            "years": "años",
            "cm": "cm",
            "kg": "kg",
            "download": "Descargar",
            "pay_with_crypto": "Pagar con Cripto",
            "crypto_payment": "Pago con Cripto",
            "select_network": "Seleccionar Red",
            "wallet_address": "Dirección de Wallet",
            "copy": "Copiar",
            "copied": "¡Copiado!",
            "close": "Cerrar",
            "payment_awaiting": "Esperando Confirmación",
            "payment_processing": "Su reserva será confirmada en el chat, puede cerrar esta página.",
            "timer_label": "Tiempo restante",
            "travel_cities": "Ciudades de Viaje",
            "description": "Descripción",
            "welcome_message": "¡Hola! Escríbeme un mensaje",
            "error_sending": "Error al enviar mensaje",
            "promocode": "Código Promocional",
            "enter_promocode": "Ingresar código promocional",
            "apply_promocode": "Aplicar",
            "promocode_applied": "¡Código promocional aplicado!",
            "promocode_invalid": "Código promocional inválido",
            "discount": "Descuento",
            "banner_join": "Unirse al Canal",
            "attach_file": "📎",
            "file": "Archivo",
            "photo": "Foto",
            "video": "Video",
            "add_comment": "Agregar Comentario",
            "comments": "Comentarios",
            "no_comments": "Aún no hay comentarios",
            "your_comment": "Tu comentario",
            "post_comment": "Publicar Comentario",
            "rating": "Calificación",
            "payment_processing": "Procesando pago...",
            "select_crypto": "Seleccionar Criptomoneda",
            "amount": "Cantidad",
            "usd": "USD",
            "pay_now": "Pagar",
            "booking_profile": "Reservar Perfil",
            "vip_catalog": "Catálogo VIP",
            "extra_vip_catalog": "Extra VIP",
            "secret_catalog": "Catálogo Secreto",
            "unlock_access": "Desbloquear Acceso",
            "premium_profiles_count": "perfiles premium",
            "blurred_preview": "Vista Previa Difuminada",
            "access_denied": "Acceso Denegado",
            "pay_to_unlock": "Pague para desbloquear el acceso completo",
            "view_all_profiles": "Ver Todos los Perfiles",
            "from_age": "de",
            "years_short": "años",
            "comment_permission_required": "Para dejar comentarios, primero debe usar nuestros servicios",
            "complete_transaction_to_comment": "Complete una transacción para desbloquear comentarios"
        }
    }

    return translations.get(lang, translations["en"])

@app.get("/api/test")
async def test():
    return {"status": "ok", "message": "Сервер Muji работает!"}

if __name__ == "__main__":
    print("🚀 Сервер Muji запущен на http://localhost:8001")
    print("📱 Основной сайт: http://localhost:8001")
    print("⚠️  Внимание: Для админ панели запустите admin.py на порту 8002!")
    uvicorn.run(app, host="0.0.0.0", port=8001, access_log=False)

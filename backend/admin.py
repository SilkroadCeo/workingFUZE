from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request, Response, Cookie, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import os
import json
import shutil
from datetime import datetime, timedelta
from typing import Optional, List
import logging
import hashlib
import hmac
import secrets
import uuid
import random
import string
from urllib.parse import parse_qs
import asyncio
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.error import TelegramError
from dotenv import load_dotenv
import magic
import bleach
from pydantic import BaseModel, Field, validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Load environment variables
load_dotenv()

# Import database module for user authentication and file management
import database as db

# Генерация случайного 18-значного кода для ордеров
def generate_order_code():
    """Генерирует случайный 18-значный код из букв и цифр"""
    characters = string.ascii_letters + string.digits  # a-z, A-Z, 0-9
    return ''.join(random.choice(characters) for _ in range(18))

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============= SECURITY CONFIGURATION =============
# Load configuration from environment variables

# File Upload Security
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "10"))
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
ALLOWED_IMAGE_EXTENSIONS = set(os.getenv("ALLOWED_IMAGE_EXTENSIONS", "jpg,jpeg,png,webp,gif").split(","))
ALLOWED_VIDEO_EXTENSIONS = set(os.getenv("ALLOWED_VIDEO_EXTENSIONS", "mp4,webm").split(","))
ALLOWED_MIME_TYPES = {
    'image/jpeg', 'image/png', 'image/webp', 'image/gif',
    'video/mp4', 'video/webm'
}

# Rate Limiting Configuration
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_RATE_LIMIT_WINDOW = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_MINUTES", "15"))

# Admin Authentication
ADMIN_CREDENTIALS = {
    "username": os.getenv("ADMIN_USERNAME", "admin"),
    "password": os.getenv("ADMIN_PASSWORD", "admin123")  # Change this in production!
}

# Session storage
active_sessions = {}  # Admin sessions
telegram_sessions = {}  # Telegram user sessions: {session_id: {user_data, created_at}}
# Rate limiting storage for login attempts
login_attempts = {}

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
ADMIN_TELEGRAM_IDS_STR = os.getenv("ADMIN_TELEGRAM_IDS", "")
ADMIN_TELEGRAM_IDS = [int(id.strip()) for id in ADMIN_TELEGRAM_IDS_STR.split(",") if id.strip()]

# CORS Configuration
ALLOWED_ORIGINS_STR = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8002")
ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_STR.split(",") if origin.strip()]

# Хранилище для сопоставления Telegram сообщений с чатами
# Ключ: message_id в Telegram, Значение: profile_id
telegram_message_mapping = {}

# Хранилище для активных диалогов (когда админ в режиме ответа)
# Ключ: admin_telegram_id, Значение: profile_id
active_reply_sessions = {}

# Инициализация Telegram бота
telegram_bot = None
telegram_updates_task = None  # Отслеживание задачи обновлений
is_shutting_down = False  # Флаг для graceful shutdown

if TELEGRAM_BOT_TOKEN and TELEGRAM_BOT_TOKEN != "YOUR_BOT_TOKEN_HERE":
    try:
        telegram_bot = Bot(token=TELEGRAM_BOT_TOKEN)
        logger.info("✅ Telegram bot initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize Telegram bot: {e}")
        telegram_bot = None


def verify_telegram_auth(init_data: str, max_age_seconds: int = 86400) -> bool:
    """
    Проверка подлинности данных от Telegram Web App

    Args:
        init_data: Строка initData от Telegram WebApp
        max_age_seconds: Максимальный возраст данных в секундах (по умолчанию 24 часа)

    Returns:
        True если данные валидны и не устарели, иначе False
    """
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


def create_session(username: str) -> str:
    """Создать новую сессию"""
    session_id = str(uuid.uuid4())
    active_sessions[session_id] = {
        "username": username,
        "created_at": datetime.now()
    }
    return session_id


def verify_session(session_id: str) -> bool:
    """Проверить валидность сессии"""
    if not session_id:
        return False
    return session_id in active_sessions


def get_session_user(session_id: str) -> Optional[str]:
    """Получить пользователя из сессии"""
    if session_id in active_sessions:
        return active_sessions[session_id]["username"]
    return None


# ============= TELEGRAM SESSION MANAGEMENT =============

def create_telegram_session(user_data: dict) -> str:
    """Create new Telegram user session"""
    session_id = str(uuid.uuid4())
    telegram_sessions[session_id] = {
        "user_data": user_data,
        "created_at": datetime.now()
    }
    return session_id


def verify_telegram_session(session_id: str) -> bool:
    """Verify Telegram session validity"""
    if not session_id:
        return False
    return session_id in telegram_sessions


def get_telegram_session_user(session_id: str) -> Optional[dict]:
    """Get Telegram user data from session"""
    if session_id in telegram_sessions:
        return telegram_sessions[session_id]["user_data"]
    return None


def destroy_telegram_session(session_id: str):
    """Destroy Telegram session"""
    if session_id in telegram_sessions:
        del telegram_sessions[session_id]


# ============= AUTHENTICATION DEPENDENCIES =============

async def get_current_user(request: Request):
    """Get current admin user (for admin panel)"""
    session_id = request.cookies.get("admin_session")

    if not session_id or not verify_session(session_id):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = get_session_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session")

    return user


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


# ============= INPUT VALIDATION MODELS =============
# Pydantic models for input validation

class ProfileCreateModel(BaseModel):
    """Validation model for profile creation"""
    name: str = Field(..., min_length=1, max_length=100)
    age: int = Field(..., ge=18, le=100)
    gender: str = Field(..., pattern="^(male|female|other)$")
    nationality: str = Field(..., min_length=1, max_length=100)
    city: str = Field(..., min_length=1, max_length=100)
    travel_cities: str = Field(..., max_length=500)
    description: str = Field(..., min_length=1, max_length=2000)
    height: int = Field(..., ge=100, le=250)
    weight: int = Field(..., ge=30, le=200)
    chest: int = Field(..., ge=1, le=10)

    @validator('name', 'nationality', 'city', 'description')
    def sanitize_html(cls, v):
        """Remove any HTML tags from text fields"""
        if v:
            return bleach.clean(v, tags=[], strip=True)
        return v


class CommentModel(BaseModel):
    """Validation model for comments"""
    text: str = Field(..., min_length=1, max_length=1000)
    rating: int = Field(..., ge=1, le=5)

    @validator('text')
    def sanitize_text(cls, v):
        """Remove any HTML tags from comment text"""
        return bleach.clean(v, tags=[], strip=True)


class PromoCodeModel(BaseModel):
    """Validation model for promo codes"""
    code: str = Field(..., min_length=3, max_length=50, pattern="^[A-Z0-9_-]+$")
    discount: int = Field(..., ge=1, le=100)
    expires_at: Optional[str] = None

    @validator('code')
    def sanitize_code(cls, v):
        """Ensure code is uppercase alphanumeric"""
        return v.upper()


class ChatMessageModel(BaseModel):
    """Validation model for chat messages"""
    text: str = Field(..., min_length=1, max_length=5000)

    @validator('text')
    def sanitize_message(cls, v):
        """Remove dangerous HTML but allow basic formatting"""
        allowed_tags = ['b', 'i', 'u', 'br', 'p']
        return bleach.clean(v, tags=allowed_tags, strip=True)


class BannerModel(BaseModel):
    """Validation model for banner settings"""
    text: str = Field(default="", max_length=500)
    link: str = Field(default="", max_length=500)
    link_text: str = Field(default="", max_length=100)
    visible: bool = Field(default=False)


async def send_telegram_notification(message: str, profile_id: int = None, profile_name: str = None, message_text: str = None, file_url: str = None, telegram_user_id: str = None):
    """
    Отправка уведомления администратору в Telegram

    Args:
        message: Основное сообщение уведомления
        profile_id: ID профиля (для сопоставления ответов)
        profile_name: Имя профиля, от которого пришло сообщение
        message_text: Текст сообщения от пользователя
        file_url: URL файла, если есть
        telegram_user_id: ID пользователя в Telegram (для изоляции чатов)
    """
    if not telegram_bot:
        logger.warning("⚠️ Telegram bot not initialized, skipping notification")
        return

    if not ADMIN_TELEGRAM_IDS:
        logger.warning("⚠️ No admin Telegram IDS configured, skipping notification")
        return

    try:
        # Формируем красивое сообщение
        notification = f"🔔 <b>{message}</b>\n\n"

        if profile_name:
            notification += f"👤 <b>Профиль:</b> {profile_name}\n"

        if message_text:
            notification += f"💬 <b>Сообщение:</b> {message_text}\n"

        if file_url:
            notification += f"📎 <b>Файл:</b> Прикреплен\n"

        notification += f"\n⏰ <b>Время:</b> {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}"

        # Создаем inline-кнопки для быстрого ответа
        keyboard = None
        if profile_id:
            # Include telegram_user_id in callback data for proper message routing
            reply_data = f"reply_{profile_id}_{telegram_user_id}" if telegram_user_id else f"reply_{profile_id}"
            payment_data = f"payment_{profile_id}_{telegram_user_id}" if telegram_user_id else f"payment_{profile_id}"

            keyboard = InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("✉️ Ответить", callback_data=reply_data),
                    InlineKeyboardButton("✅ Payment OK", callback_data=payment_data)
                ],
                [
                    InlineKeyboardButton("📋 Все чаты", callback_data="list_chats")
                ]
            ])

        # Отправляем уведомление всем администраторам
        for admin_id in ADMIN_TELEGRAM_IDS:
            try:
                sent_message = await telegram_bot.send_message(
                    chat_id=admin_id,
                    text=notification,
                    parse_mode='HTML',
                    reply_markup=keyboard
                )

                # Сохраняем mapping для возможности ответа
                if profile_id and sent_message:
                    # Store both profile_id and telegram_user_id for proper reply routing
                    telegram_message_mapping[sent_message.message_id] = {
                        "profile_id": profile_id,
                        "telegram_user_id": telegram_user_id
                    }
                    logger.info(f"📝 Mapped Telegram message {sent_message.message_id} to profile {profile_id}, user {telegram_user_id}")

                logger.info(f"✅ Notification sent to admin {admin_id}")
            except TelegramError as e:
                logger.error(f"❌ Failed to send notification to admin {admin_id}: {e}")

    except Exception as e:
        logger.error(f"❌ Error sending Telegram notification: {e}")


async def handle_command(message, admin_id):
    """Обработка команд от администратора"""
    command = message.text.split()[0].lower()

    if command == '/start' or command == '/help':
        help_text = """
🤖 <b>Бот для управления чатами</b>

<b>Команды:</b>
/chats - Показать все активные чаты
/cancel - Отменить режим ответа

<b>Как отвечать пользователям:</b>
1️⃣ Нажмите кнопку "✉️ Ответить" под уведомлением
2️⃣ Напишите сообщение - оно отправится пользователю
3️⃣ Или просто ответьте (Reply) на уведомление

<b>Быстрые действия:</b>
• "✅ Payment OK" - подтвердить оплату
• "📋 Все чаты" - список всех чатов
        """
        await telegram_bot.send_message(
            chat_id=admin_id,
            text=help_text,
            parse_mode='HTML'
        )

    elif command == '/chats':
        await show_chats_list(admin_id)

    elif command == '/cancel':
        if admin_id in active_reply_sessions:
            del active_reply_sessions[admin_id]
            await telegram_bot.send_message(
                chat_id=admin_id,
                text="✅ Режим ответа отменен"
            )
        else:
            await telegram_bot.send_message(
                chat_id=admin_id,
                text="ℹ️ Вы не в режиме ответа"
            )


async def handle_callback_query(callback_query, admin_id):
    """Обработка нажатий на inline-кнопки"""
    data = callback_query.data

    try:
        # Подтверждаем получение callback
        await telegram_bot.answer_callback_query(callback_query.id)

        if data.startswith('reply_'):
            # Активируем режим ответа
            parts = data.split('_')
            profile_id = int(parts[1])
            telegram_user_id = parts[2] if len(parts) > 2 else None

            # Store both profile_id and telegram_user_id
            active_reply_sessions[admin_id] = {
                "profile_id": profile_id,
                "telegram_user_id": telegram_user_id
            }

            # Получаем информацию о профиле
            app_data = load_data()
            profile = next((p for p in app_data["profiles"] if p["id"] == profile_id), None)
            profile_name = profile["name"] if profile else "Unknown"

            user_info = f" (User: {telegram_user_id})" if telegram_user_id else ""
            await telegram_bot.send_message(
                chat_id=admin_id,
                text=f"✍️ Режим ответа активирован для: <b>{profile_name}</b>{user_info}\n\nНапишите сообщение, и оно будет отправлено пользователю.\nДля отмены используйте /cancel",
                parse_mode='HTML'
            )

        elif data.startswith('payment_'):
            # Отправляем "payment successful"
            parts = data.split('_')
            profile_id = int(parts[1])
            telegram_user_id = parts[2] if len(parts) > 2 else None

            await send_admin_reply_from_telegram(profile_id, "payment successful", telegram_user_id)
            await telegram_bot.send_message(
                chat_id=admin_id,
                text="✅ Подтверждение оплаты отправлено! Статус заказа обновлен на 'Booked'."
            )

        elif data == 'list_chats':
            await show_chats_list(admin_id)

    except Exception as e:
        logger.error(f"❌ Error handling callback query: {e}")
        await telegram_bot.send_message(
            chat_id=admin_id,
            text=f"❌ Ошибка: {str(e)}"
        )


async def show_chats_list(admin_id):
    """Показать список всех активных чатов"""
    try:
        data = load_data()
        chats = data.get("chats", [])

        if not chats:
            await telegram_bot.send_message(
                chat_id=admin_id,
                text="📭 Нет активных чатов"
            )
            return

        # Формируем список чатов с кнопками
        for chat in chats[-10:]:  # Показываем последние 10 чатов
            profile_id = chat.get("profile_id")
            profile_name = chat.get("profile_name", "Unknown")
            telegram_user_id = chat.get("telegram_user_id")

            # Получаем последнее сообщение
            messages = [m for m in data.get("messages", []) if m.get("chat_id") == chat.get("id")]
            last_message = messages[-1] if messages else None
            last_text = last_message.get("text", "No messages")[:50] if last_message else "No messages"

            user_info = f"\n👤 User: {telegram_user_id}" if telegram_user_id else ""
            chat_info = f"👤 <b>{profile_name}</b>{user_info}\n💬 {last_text}"

            # Include telegram_user_id in callback data
            reply_data = f"reply_{profile_id}_{telegram_user_id}" if telegram_user_id else f"reply_{profile_id}"
            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("✉️ Ответить", callback_data=reply_data)]
            ])

            await telegram_bot.send_message(
                chat_id=admin_id,
                text=chat_info,
                parse_mode='HTML',
                reply_markup=keyboard
            )

        await telegram_bot.send_message(
            chat_id=admin_id,
            text=f"📊 Всего чатов: {len(chats)}"
        )

    except Exception as e:
        logger.error(f"❌ Error showing chats list: {e}")
        await telegram_bot.send_message(
            chat_id=admin_id,
            text=f"❌ Ошибка при загрузке чатов: {str(e)}"
        )


async def process_telegram_updates():
    """
    Обработка входящих сообщений от администратора в Telegram
    """
    global is_shutting_down

    if not telegram_bot:
        return

    try:
        from telegram import Update

        # Получаем последние обновления
        offset = 0
        logger.info("📱 Telegram updates processor started")

        while not is_shutting_down:
            try:
                updates = await telegram_bot.get_updates(offset=offset, timeout=30)

                for update in updates:
                    offset = update.update_id + 1

                    # Проверяем что это от администратора
                    admin_id = None
                    if update.message and update.message.from_user.id in ADMIN_TELEGRAM_IDS:
                        admin_id = update.message.from_user.id
                    elif update.callback_query and update.callback_query.from_user.id in ADMIN_TELEGRAM_IDS:
                        admin_id = update.callback_query.from_user.id

                    if not admin_id:
                        continue

                    # Обработка callback queries (нажатия на кнопки)
                    if update.callback_query:
                        await handle_callback_query(update.callback_query, admin_id)
                        continue

                    # Обработка команд
                    if update.message.text and update.message.text.startswith('/'):
                        await handle_command(update.message, admin_id)
                        continue

                    # Обработка ответов на сообщения (reply)
                    if update.message.reply_to_message:
                        replied_message_id = update.message.reply_to_message.message_id
                        if replied_message_id in telegram_message_mapping:
                            mapping = telegram_message_mapping[replied_message_id]
                            profile_id = mapping["profile_id"]
                            telegram_user_id = mapping.get("telegram_user_id")
                            await send_admin_reply_from_telegram(profile_id, update.message.text, telegram_user_id)
                            await telegram_bot.send_message(
                                chat_id=admin_id,
                                text="✅ Ответ отправлен пользователю!"
                            )
                            continue

                    # Обработка обычных сообщений (если админ в режиме ответа)
                    if admin_id in active_reply_sessions:
                        session = active_reply_sessions[admin_id]
                        profile_id = session["profile_id"]
                        telegram_user_id = session.get("telegram_user_id")
                        await send_admin_reply_from_telegram(profile_id, update.message.text, telegram_user_id)
                        await telegram_bot.send_message(
                            chat_id=admin_id,
                            text="✅ Ответ отправлен! Отправьте еще сообщение или /cancel для выхода."
                        )
                        continue

                await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"❌ Error processing Telegram updates: {e}")
                await asyncio.sleep(5)

        logger.info("📴 Telegram updates processor stopped gracefully")

    except Exception as e:
        logger.error(f"❌ Error in Telegram updates processor: {e}")


async def send_admin_reply_from_telegram(profile_id: int, text: str, telegram_user_id: str = None):
    """
    Отправка ответа администратора из Telegram в чат с пользователем

    Args:
        profile_id: ID профиля
        text: Текст ответа от администратора
        telegram_user_id: ID пользователя в Telegram (для изоляции чатов)
    """
    try:
        data = load_data()

        # Находим профиль
        profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
        if not profile:
            logger.error(f"❌ Profile {profile_id} not found")
            return

        # Находим или создаем чат - ВАЖНО: фильтруем по profile_id И telegram_user_id
        if telegram_user_id:
            chat = next((c for c in data["chats"]
                        if c["profile_id"] == profile_id and c.get("telegram_user_id") == telegram_user_id), None)
        else:
            # Fallback for legacy messages without telegram_user_id
            chat = next((c for c in data["chats"]
                        if c["profile_id"] == profile_id and not c.get("telegram_user_id")), None)

        if not chat:
            chat = {
                "id": len(data["chats"]) + 1,
                "profile_id": profile_id,
                "profile_name": profile["name"],
                "telegram_user_id": telegram_user_id,
                "created_at": datetime.now().isoformat()
            }
            data["chats"].append(chat)

        # Создаем сообщение от администратора
        message_data = {
            "id": len(data["messages"]) + 1,
            "chat_id": chat["id"],
            "text": text,
            "is_from_user": False,
            "created_at": datetime.now().isoformat()
        }
        data["messages"].append(message_data)

        # Проверяем если это подтверждение оплаты
        if text and "payment successful" in text.lower():
            # Находим последний unpaid ордер для этого профиля и пользователя
            profile_orders = [o for o in data.get("orders", [])
                            if o.get("profile_id") == profile_id
                            and o.get("status") == "unpaid"
                            and (not telegram_user_id or o.get("telegram_user_id") == telegram_user_id)]
            if profile_orders:
                # Обновляем статус последнего ордера
                last_order = profile_orders[-1]
                last_order["status"] = "booked"
                last_order["booked_at"] = datetime.now().isoformat()
                logger.info(f"Order #{last_order['id']} marked as booked for profile {profile_id}, user {telegram_user_id} (from Telegram)")

        # Сохраняем данные
        save_data(data)
        logger.info(f"Admin reply from Telegram sent to profile {profile_id}")

        # Отправляем подтверждение админу в Telegram
        for admin_id in ADMIN_TELEGRAM_IDS:
            try:
                await telegram_bot.send_message(
                    chat_id=admin_id,
                    text=f"✅ Ваш ответ отправлен пользователю (профиль: {profile['name']})",
                    parse_mode='HTML'
                )
            except:
                pass

    except Exception as e:
        logger.error(f"❌ Error sending admin reply from Telegram: {e}")


app = FastAPI(title="Admin Panel - Muji")

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS настройки - SECURE: Only allow specific origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Content-Type", "Authorization"],
)


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

# Запуск обработчика Telegram updates в фоновом режиме
@app.on_event("startup")
async def startup_event():
    """Запуск фоновых задач при старте приложения"""
    global telegram_updates_task, is_shutting_down

    # Сбрасываем флаг остановки при старте
    is_shutting_down = False

    if telegram_bot and ADMIN_TELEGRAM_IDS:
        # Проверяем, не запущена ли уже задача
        if telegram_updates_task is None or telegram_updates_task.done():
            logger.info("🚀 Starting Telegram updates processor...")
            telegram_updates_task = asyncio.create_task(process_telegram_updates())
        else:
            logger.warning("⚠️ Telegram updates processor already running, skipping")
    else:
        logger.warning("⚠️ Telegram bot not configured, skipping updates processor")

    # Запуск задачи очистки просроченных заказов
    logger.info("🧹 Starting expired orders cleanup task...")
    asyncio.create_task(cleanup_expired_orders())


@app.on_event("shutdown")
async def shutdown_event():
    """Graceful shutdown для фоновых задач"""
    global is_shutting_down, telegram_updates_task

    logger.info("🛑 Shutting down background tasks...")
    is_shutting_down = True

    # Ждем завершения задачи обновлений Telegram
    if telegram_updates_task and not telegram_updates_task.done():
        logger.info("⏳ Waiting for Telegram updates task to finish...")
        try:
            await asyncio.wait_for(telegram_updates_task, timeout=5.0)
            logger.info("✅ Telegram updates task stopped")
        except asyncio.TimeoutError:
            logger.warning("⚠️ Telegram updates task did not stop in time, cancelling...")
            telegram_updates_task.cancel()
            try:
                await telegram_updates_task
            except asyncio.CancelledError:
                logger.info("✅ Telegram updates task cancelled")

    logger.info("✅ Shutdown complete")


current_dir = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(current_dir, "data.json")
UPLOAD_DIR = os.path.join(current_dir, "uploads")

os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


def get_crypto_wallets_from_env():
    """Load crypto wallet addresses from environment variables"""
    return {
        "trc20": os.getenv("CRYPTO_WALLET_TRC20", ""),
        "erc20": os.getenv("CRYPTO_WALLET_ERC20", ""),
        "bnb": os.getenv("CRYPTO_WALLET_BNB", ""),
        "btc": os.getenv("CRYPTO_WALLET_BTC", ""),
        "zetcash": os.getenv("CRYPTO_WALLET_ZETCASH", ""),
        "doge": os.getenv("CRYPTO_WALLET_DOGE", ""),
        "dash": os.getenv("CRYPTO_WALLET_DASH", ""),
        "ltc": os.getenv("CRYPTO_WALLET_LTC", ""),
        "usdt_bep20": os.getenv("CRYPTO_WALLET_USDT_BEP20", ""),
        "eth": os.getenv("CRYPTO_WALLET_ETH", ""),
        "usdc_erc20": os.getenv("CRYPTO_WALLET_USDC_ERC20", "")
    }


def load_data():
    """Загрузка данных из JSON файла"""
    if not os.path.exists(DATA_FILE):
        return {
            "profiles": [],
            "vip_profiles": [],
            "chats": [],
            "messages": [],
            "comments": [],
            "promocodes": [],
            "orders": [],
            "settings": {
                "crypto_wallets": get_crypto_wallets_from_env(),
                "bonus_percentage": 5,
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
            data = json.load(f)

        # Ensure all required sections exist
        if "settings" not in data:
            data["settings"] = {}
        if "crypto_wallets" not in data["settings"]:
            data["settings"]["crypto_wallets"] = {
                "trc20": "TY76gU8J9o8j7U6tY5r4E3W2Q1",
                "erc20": "0x8a9C6e5D8b0E2a1F3c4B6E7D8C9A0B1C2D3E4F5",
                "bnb": "bnb1q3e5r7t9y1u3i5o7p9l1k3j5h7g9f2d4s6q8w0",
                "btc": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                "zetcash": "ZET1234567890abcdefghijklmnopqrstuvwxyz",
                "doge": "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L",
                "dash": "XnPBzXq3bRhQKjVqZvXmG5jKqVmPdWZgFj",
                "ltc": "LhK3pXq2BvRsQmNp7TyUjGkLmPqRsXwZyF",
                "usdt_bep20": "0x8b9C7e5D9b1E3a2F4c5B7E8D9C0A1B2C3D4E5F6",
                "eth": "0x7a8B6d4C8e0D2b1F3a4C5E6D7F8A9B0C1D2E3F4",
                "usdc_erc20": "0x6a7B5c3D7e9C1a0F2b3D4F5E6A7B8C9D0E1F2A3"
            }
        if "bonus_percentage" not in data["settings"]:
            data["settings"]["bonus_percentage"] = 5
        if "banner" not in data["settings"]:
            data["settings"]["banner"] = {
                "text": "Special Offer: 15% discount with promo code WELCOME15",
                "visible": True,
                "link": "https://t.me/yourchannel",
                "link_text": "Join Channel"
            }
        if "vip_catalogs" not in data["settings"]:
            data["settings"]["vip_catalogs"] = {
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
        if "promocodes" not in data:
            data["promocodes"] = []
        if "comments" not in data:
            data["comments"] = []
        if "vip_profiles" not in data:
            data["vip_profiles"] = []
        if "orders" not in data:
            data["orders"] = []

        return data
    except Exception as e:
        logger.error(f"Error loading data: {e}")
        return {
            "profiles": [],
            "vip_profiles": [],
            "chats": [],
            "messages": [],
            "comments": [],
            "promocodes": [],
            "settings": {
                "crypto_wallets": {
                    "trc20": "TY76gU8J9o8j7U6tY5r4E3W2Q1",
                    "erc20": "0x8a9C6e5D8b0E2a1F3c4B6E7D8C9A0B1C2D3E4F5",
                    "bnb": "bnb1q3e5r7t9y1u3i5o7p9l1k3j5h7g9f2d4s6q8w0",
                    "btc": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                    "zetcash": "ZET1234567890abcdefghijklmnopqrstuvwxyz",
                    "doge": "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L",
                    "dash": "XnPBzXq3bRhQKjVqZvXmG5jKqVmPdWZgFj",
                    "ltc": "LhK3pXq2BvRsQmNp7TyUjGkLmPqRsXwZyF",
                    "usdt_bep20": "0x8b9C7e5D9b1E3a2F4c5B7E8D9C0A1B2C3D4E5F6",
                    "eth": "0x7a8B6d4C8e0D2b1F3a4C5E6D7F8A9B0C1D2E3F4",
                    "usdc_erc20": "0x6a7B5c3D7e9C1a0F2b3D4F5E6A7B8C9D0E1F2A3"
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


def save_data(data):
    """Сохранение данных в JSON файл"""
    try:
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving data: {e}")
        return False


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal attacks"""
    # Remove any directory path components
    filename = os.path.basename(filename)
    # Remove any non-alphanumeric characters except dots, underscores, and hyphens
    filename = "".join(c for c in filename if c.isalnum() or c in "._-")
    # Limit filename length
    if len(filename) > 100:
        name, ext = os.path.splitext(filename)
        filename = name[:95] + ext
    return filename


def validate_file_security(file: UploadFile) -> tuple[bool, str]:
    """
    Validate file security: size, extension, and MIME type
    Returns: (is_valid, error_message)
    """
    # Check file size
    file.file.seek(0, 2)  # Seek to end
    file_size = file.file.tell()
    file.file.seek(0)  # Reset to beginning

    if file_size > MAX_FILE_SIZE_BYTES:
        return False, f"File size exceeds maximum allowed size of {MAX_FILE_SIZE_MB}MB"

    if file_size == 0:
        return False, "File is empty"

    # Get file extension
    file_extension = file.filename.lower().split('.')[-1] if '.' in file.filename else ''

    # Check extension whitelist
    allowed_extensions = ALLOWED_IMAGE_EXTENSIONS.union(ALLOWED_VIDEO_EXTENSIONS)
    if file_extension not in allowed_extensions:
        return False, f"File type .{file_extension} not allowed. Allowed: {', '.join(allowed_extensions)}"

    # Validate MIME type using python-magic
    try:
        # Read first 2048 bytes for MIME detection
        file_content = file.file.read(2048)
        file.file.seek(0)  # Reset to beginning

        mime = magic.from_buffer(file_content, mime=True)

        if mime not in ALLOWED_MIME_TYPES:
            return False, f"Invalid file type detected: {mime}"
    except Exception as e:
        logger.error(f"Error detecting MIME type: {e}")
        return False, "Could not validate file type"

    return True, ""


def save_uploaded_file(file: UploadFile, telegram_user_id: int = None) -> tuple[str, str, int, str]:
    """
    Securely save uploaded file with validation and user isolation

    Args:
        file: UploadFile to save
        telegram_user_id: Telegram user ID for user-specific directory

    Returns:
        tuple: (file_url, full_file_path, file_size, mime_type)
    """
    try:
        # Validate file security
        is_valid, error_msg = validate_file_security(file)
        if not is_valid:
            logger.error(f"File validation failed: {error_msg}")
            raise HTTPException(status_code=400, detail=error_msg)

        # Sanitize filename
        safe_filename = sanitize_filename(file.filename)

        # Add timestamp to prevent collisions
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{timestamp}_{safe_filename}"

        # Create user-specific directory if telegram_user_id provided
        if telegram_user_id:
            user_upload_dir = os.path.join(UPLOAD_DIR, f"user_{telegram_user_id}")
            os.makedirs(user_upload_dir, exist_ok=True)
            file_path = os.path.join(user_upload_dir, filename)
            file_url = f"/uploads/user_{telegram_user_id}/{filename}"
        else:
            # Fallback to general uploads directory
            os.makedirs(UPLOAD_DIR, exist_ok=True)
            file_path = os.path.join(UPLOAD_DIR, filename)
            file_url = f"/uploads/{filename}"

        # Get file size
        file.file.seek(0, 2)
        file_size = file.file.tell()
        file.file.seek(0)

        # Get MIME type
        file_content = file.file.read(2048)
        file.file.seek(0)
        mime_type = magic.from_buffer(file_content, mime=True)

        # Save file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        logger.info(f"✅ File saved securely: {filename} (user: {telegram_user_id or 'general'})")
        return file_url, file_path, file_size, mime_type

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error saving file: {e}")
        raise HTTPException(status_code=500, detail="Failed to save file")


def get_file_type(filename: str) -> str:
    """Определяет тип файла по расширению"""
    extension = filename.lower().split('.')[-1]
    image_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp']
    video_extensions = ['mp4', 'avi', 'mov', 'mkv', 'webm']

    if extension in image_extensions:
        return 'image'
    elif extension in video_extensions:
        return 'video'
    else:
        return 'file'


# ====== ЭНДПОИНТЫ ДЛЯ АУТЕНТИФИКАЦИИ ======

@app.get("/login")
async def login_page():
    """Страница логина"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Вход в админ панель - Muji</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }
            .login-container {
                background: rgba(255, 255, 255, 0.95);
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                width: 100%;
                max-width: 400px;
            }
            .login-header {
                text-align: center;
                margin-bottom: 30px;
            }
            .login-header h1 {
                color: #667eea;
                font-size: 28px;
                margin-bottom: 10px;
            }
            .login-header p {
                color: #666;
                font-size: 14px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .form-group label {
                display: block;
                color: #333;
                font-size: 14px;
                font-weight: 500;
                margin-bottom: 8px;
            }
            .form-group input {
                width: 100%;
                padding: 12px 15px;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                font-size: 14px;
                transition: all 0.3s;
            }
            .form-group input:focus {
                outline: none;
                border-color: #667eea;
            }
            .login-button {
                width: 100%;
                padding: 14px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s;
            }
            .login-button:hover {
                transform: translateY(-2px);
            }
            .login-button:active {
                transform: translateY(0);
            }
            .error-message {
                background: #fee;
                color: #c33;
                padding: 12px;
                border-radius: 10px;
                margin-bottom: 20px;
                font-size: 14px;
                display: none;
            }
            .error-message.show {
                display: block;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <h1>🔐 Вход в админ панель</h1>
                <p>Muji - Admin Dashboard</p>
            </div>
            <div id="error-message" class="error-message"></div>
            <form id="login-form">
                <div class="form-group">
                    <label for="username">Логин</label>
                    <input type="text" id="username" name="username" required autocomplete="username">
                </div>
                <div class="form-group">
                    <label for="password">Пароль</label>
                    <input type="password" id="password" name="password" required autocomplete="current-password">
                </div>
                <button type="submit" class="login-button">Войти</button>
            </form>
        </div>

        <script>
            document.getElementById('login-form').addEventListener('submit', async (e) => {
                e.preventDefault();

                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const errorDiv = document.getElementById('error-message');

                try {
                    const response = await fetch('/api/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password }),
                        credentials: 'include'
                    });

                    if (response.ok) {
                        window.location.href = '/';
                    } else {
                        const data = await response.json();
                        errorDiv.textContent = data.detail || 'Неверный логин или пароль';
                        errorDiv.classList.add('show');
                    }
                } catch (error) {
                    errorDiv.textContent = 'Ошибка подключения к серверу';
                    errorDiv.classList.add('show');
                }
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


def check_login_rate_limit(ip_address: str) -> bool:
    """
    Check if login attempts from IP exceed rate limit
    Returns: True if allowed, False if rate limited
    """
    now = datetime.now()

    # Clean up old attempts
    if ip_address in login_attempts:
        login_attempts[ip_address] = [
            attempt_time for attempt_time in login_attempts[ip_address]
            if now - attempt_time < timedelta(minutes=LOGIN_RATE_LIMIT_WINDOW)
        ]

    # Check if rate limit exceeded
    if ip_address in login_attempts and len(login_attempts[ip_address]) >= MAX_LOGIN_ATTEMPTS:
        return False

    return True


def record_login_attempt(ip_address: str):
    """Record a failed login attempt"""
    if ip_address not in login_attempts:
        login_attempts[ip_address] = []
    login_attempts[ip_address].append(datetime.now())


@app.post("/api/login")
@limiter.limit("10/minute")
async def login(request: Request, response: Response):
    """API эндпоинт для логина с защитой от brute-force"""
    try:
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"

        # Check rate limit
        if not check_login_rate_limit(client_ip):
            logger.warning(f"⚠️ Rate limit exceeded for IP: {client_ip}")
            raise HTTPException(
                status_code=429,
                detail=f"Too many login attempts. Please try again in {LOGIN_RATE_LIMIT_WINDOW} minutes."
            )

        body = await request.json()
        username = body.get("username")
        password = body.get("password")

        if not username or not password:
            raise HTTPException(status_code=400, detail="Логин и пароль обязательны")

        # Проверяем учетные данные
        if username == ADMIN_CREDENTIALS["username"] and password == ADMIN_CREDENTIALS["password"]:
            # Clear failed attempts on successful login
            if client_ip in login_attempts:
                login_attempts[client_ip] = []

            # Создаем сессию
            session_id = create_session(username)

            # Устанавливаем cookie с secure настройками
            response.set_cookie(
                key="admin_session",
                value=session_id,
                httponly=True,
                max_age=86400 * 7,  # 7 дней
                samesite="lax",
                secure=True  # HTTPS only in production
            )

            logger.info(f"✅ Successful login for user: {username} from IP: {client_ip}")
            return {"status": "success", "message": "Успешный вход"}
        else:
            # Record failed attempt
            record_login_attempt(client_ip)
            logger.warning(f"⚠️ Failed login attempt for user: {username} from IP: {client_ip}")
            raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Login error: {e}")
        raise HTTPException(status_code=400, detail="Ошибка входа")


@app.post("/api/telegram/auth")
async def telegram_auth(request: Request, response: Response):
    """
    Telegram Web App Authentication with HMAC verification
    Creates or updates user in database and establishes session
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

        # Create or update user in database
        db_user = db.get_or_create_user(
            telegram_id=telegram_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
            language_code=language_code,
            is_premium=is_premium
        )

        # Create session with complete user data
        session_user_data = {
            "id": db_user["id"],  # Database user ID
            "telegram_id": telegram_id,
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "language_code": language_code,
            "is_premium": is_premium
        }

        session_id = create_telegram_session(session_user_data)

        # Set secure session cookie
        response.set_cookie(
            key="telegram_session",
            value=session_id,
            httponly=True,
            max_age=86400 * 30,  # 30 days
            samesite="lax",
            secure=True  # HTTPS only in production
        )

        logger.info(f"✅ Telegram user authenticated: {telegram_id} ({first_name} {last_name}) - User ID: {db_user['id']}")

        return {
            "status": "success",
            "user": {
                "id": db_user["id"],
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
            "id": user["id"],
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


@app.post("/api/payment/crypto")
async def crypto_payment(request: Request):
    """Обработка крипто-платежа"""
    try:
        data = load_data()
        body = await request.json()

        profile_id = body.get("profile_id")
        amount = float(body.get("amount", 0))
        currency = body.get("currency", "USD")
        wallet_type = body.get("wallet")
        telegram_user_id = body.get("telegram_user_id")

        if not profile_id or amount <= 0:
            raise HTTPException(status_code=400, detail="Invalid payment data")

        logger.info(f"💰 Processing payment for profile {profile_id}, telegram_user_id: {telegram_user_id}")

        # Применяем бонус 5%
        bonus_percentage = data["settings"].get("bonus_percentage", 5)
        bonus_amount = amount * (bonus_percentage / 100)
        total_amount = amount + bonus_amount

        if "orders" not in data:
            data["orders"] = []

        # Ищем существующий unpaid order для этого пользователя и профиля
        existing_order = next((o for o in data["orders"]
                              if o.get("profile_id") == profile_id
                              and o.get("telegram_user_id") == telegram_user_id
                              and o.get("status") == "unpaid"), None)

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
            # Создаем новый order
            order = {
                "id": len(data["orders"]) + 1,
                "profile_id": profile_id,
                "telegram_user_id": telegram_user_id,
                "amount": amount,
                "bonus_amount": bonus_amount,
                "total_amount": total_amount,
                "crypto_type": wallet_type,
                "currency": currency,
                "status": "unpaid",
                "created_at": datetime.now().isoformat(),
                "expires_at": (datetime.now() + timedelta(hours=1)).isoformat()
            }
            data["orders"].append(order)
            logger.info(f"💰 New payment order created: ${amount} + {bonus_percentage}% bonus = ${total_amount}")

        save_data(data)

        return {
            "status": "success",
            "order_id": order["id"],
            "amount": amount,
            "bonus_amount": bonus_amount,
            "total_amount": total_amount,
            "wallet_address": data["settings"]["crypto_wallets"].get(wallet_type, ""),
            "expires_in": 3600
        }
    except Exception as e:
        logger.error(f"❌ Payment error: {e}")
        raise HTTPException(status_code=500, detail=f"Payment processing error: {str(e)}")


@app.post("/api/logout")
async def logout(response: Response, current_user: str = Depends(get_current_user)):
    """API эндпоинт для выхода"""
    # Находим и удаляем сессию
    session_id = None
    for key, value in active_sessions.items():
        if value["username"] == current_user:
            session_id = key
            break

    if session_id:
        del active_sessions[session_id]

    response.delete_cookie("admin_session")
    return {"status": "success", "message": "Вы вышли из системы"}


@app.get("/")
async def admin_dashboard(request: Request):
    """Главная страница админ-панели"""
    # Проверяем авторизацию
    try:
        current_user = await get_current_user(request)
    except HTTPException:
        return RedirectResponse(url="/login")

    # Полный HTML контент админ-панели
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel - Muji</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
            body { background: #1a1a1a; color: #ffffff; padding: 20px; min-height: 100vh; }
            .container { max-width: 1400px; margin: 0 auto; }

            header { 
                text-align: center; margin-bottom: 30px; padding: 30px; 
                background: linear-gradient(135deg, #ff6b9d 0%, #8b225e 100%); 
                border-radius: 15px; border: 1px solid #ff6b9d;
            }

            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .stat-card { background: rgba(255, 107, 157, 0.2); padding: 25px; border-radius: 15px; text-align: center; border: 1px solid #ff6b9d; }

            .tabs { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
            .tab { padding: 15px 25px; background: #ff6b9d; border: none; color: white; border-radius: 10px; cursor: pointer; font-weight: 600; transition: all 0.3s ease; }
            .tab:hover { background: #ff8fab; transform: translateY(-2px); }
            .tab.active { background: #ff8fab; box-shadow: 0 5px 15px rgba(255, 143, 171, 0.4); }

            .content { display: none; background: rgba(255, 107, 157, 0.1); padding: 30px; border-radius: 15px; margin-bottom: 20px; border: 1px solid #ff6b9d; }
            .content.active { display: block; }

            .profile-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 20px; }
            .profile-card { background: rgba(255, 107, 157, 0.1); padding: 20px; border-radius: 15px; border: 1px solid #ff6b9d; }

            .profile-header { display: flex; align-items: center; gap: 15px; margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid rgba(255, 107, 157, 0.3); }
            .profile-id { background: #ff6b9d; color: white; padding: 5px 10px; border-radius: 8px; font-weight: 600; font-size: 14px; }
            .profile-name { font-size: 18px; font-weight: 700; color: #ff6b9d; }
            .unread-badge { background: #28a745; color: white; padding: 5px 12px; border-radius: 12px; font-size: 12px; font-weight: 700; margin-left: auto; animation: pulse 2s infinite; }
            .unread-badge-button {
                position: absolute;
                top: -8px;
                right: -8px;
                background: #dc3545;
                color: white;
                width: 24px;
                height: 24px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 11px;
                font-weight: 700;
                animation: pulse 2s infinite;
                box-shadow: 0 2px 8px rgba(220, 53, 69, 0.4);
            }
            @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }

            .btn { padding: 12px 20px; border: none; border-radius: 8px; cursor: pointer; margin: 5px 2px; font-size: 14px; font-weight: 600; transition: all 0.3s ease; }
            .btn-primary { background: #ff6b9d; color: white; }
            .btn-primary:hover { background: #ff8fab; transform: translateY(-2px); }
            .btn-danger { background: #dc3545; color: white; }
            .btn-danger:hover { background: #e74c3c; transform: translateY(-2px); }
            .btn-success { background: #28a745; color: white; }
            .btn-success:hover { background: #2ecc71; transform: translateY(-2px); }
            .btn-warning { background: #ff8c00; color: white; }
            .btn-warning:hover { background: #ffa500; transform: translateY(-2px); }
            .btn-system { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
            .btn-system:hover { background: linear-gradient(135deg, #764ba2 0%, #667eea 100%); transform: translateY(-2px); }

            .form-group { margin-bottom: 20px; }
            .form-group label { display: block; margin-bottom: 8px; color: #ff6b9d; font-weight: 600; }
            .form-group input, .form-group textarea, .form-group select { 
                width: 100%; padding: 12px; background: rgba(255, 107, 157, 0.1); 
                border: 1px solid #ff6b9d; border-radius: 8px; color: #fff; font-size: 14px; outline: none; 
            }
            .form-group textarea { min-height: 80px; resize: vertical; }

            .photo-preview { display: flex; gap: 10px; margin: 10px 0; flex-wrap: wrap; }
            .photo-preview img { width: 80px; height: 80px; object-fit: cover; border-radius: 8px; border: 1px solid #ff6b9d; }

            .profile-stats { display: flex; gap: 10px; margin: 10px 0; flex-wrap: wrap; }
            .stat-badge { background: rgba(255, 107, 157, 0.2); padding: 6px 12px; border-radius: 8px; font-size: 12px; border: 1px solid #ff6b9d; color: #ff6b9d; }

            .file-upload {
                margin: 15px 0; padding: 15px;
                background: linear-gradient(135deg, #8b225e 0%, #1a1a1a 50%, #000000 100%);
                border: 2px dashed #ff6b9d; border-radius: 10px; text-align: center; cursor: pointer;
                position: relative; overflow: hidden;
            }

            .uploaded-photos { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 10px; margin: 15px 0; }
            .uploaded-photo { position: relative; width: 100px; height: 100px; border-radius: 8px; overflow: hidden; border: 1px solid #ff6b9d; }
            .uploaded-photo img { width: 100%; height: 100%; object-fit: cover; }
            .remove-photo { position: absolute; top: 5px; right: 5px; background: rgba(220, 53, 69, 0.8); color: white; border: none; border-radius: 50%; width: 20px; height: 20px; font-size: 12px; cursor: pointer; }

            .chat-file-upload { margin: 10px 0; padding: 15px; background: rgba(255, 107, 157, 0.05); border: 2px dashed #ff6b9d; border-radius: 8px; text-align: center; }
            .chat-file-list { margin-top: 10px; }
            .file-item { display: flex; align-items: center; gap: 10px; padding: 8px; background: rgba(255, 107, 157, 0.1); border-radius: 6px; margin: 5px 0; font-size: 14px; color: #ff6b9d; }
            .remove-file { color: #ff6b9d; cursor: pointer; font-weight: bold; margin-left: auto; }

            .chat-message { padding: 15px; margin: 10px 0; border-radius: 10px; border: 1px solid #ff6b9d; }
            .user-message { background: rgba(255, 107, 157, 0.1); margin-left: 20px; border-left: 3px solid #ff6b9d; }
            .admin-message { background: rgba(255, 107, 157, 0.2); margin-right: 20px; border-right: 3px solid #ff8fab; }
            .new-user-message {
                border-left: 4px solid #ffd700 !important;
                background: rgba(255, 215, 0, 0.15) !important;
                box-shadow: 0 0 10px rgba(255, 215, 0, 0.3);
                animation: pulse-glow 2s infinite;
            }
            @keyframes pulse-glow {
                0%, 100% { box-shadow: 0 0 10px rgba(255, 215, 0, 0.3); }
                50% { box-shadow: 0 0 20px rgba(255, 215, 0, 0.5); }
            }
            .message-sender { font-weight: bold; margin-bottom: 8px; color: #ff6b9d; }
            .back-btn { background: #6c757d; color: white; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; margin-bottom: 20px; transition: all 0.3s ease; }
            .back-btn:hover { background: #5a6268; transform: translateY(-2px); }
            .chat-attachment { display: flex; gap: 15px; align-items: flex-start; margin: 15px 0; flex-wrap: wrap; }
            .attachment-preview { max-width: 120px; max-height: 120px; border-radius: 8px; border: 1px solid #ff6b9d; }

            .system-message { text-align: center; margin: 20px 0; }
            .system-bubble { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                color: white; padding: 15px 25px; border-radius: 25px; 
                display: inline-block; max-width: 80%; font-size: 14px; font-weight: 500; 
                border: 1px solid rgba(255,255,255,0.2); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
            }

            .promocode-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
            .promocode-card { background: rgba(255, 107, 157, 0.1); padding: 20px; border-radius: 15px; border: 1px solid #ff6b9d; }
            .promocode-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
            .promocode-code { font-size: 20px; font-weight: 700; color: #ff6b9d; letter-spacing: 2px; }
            .promocode-discount { background: #28a745; color: white; padding: 5px 10px; border-radius: 8px; font-weight: 600; }
            .promocode-status { display: inline-block; padding: 5px 10px; border-radius: 8px; font-size: 12px; font-weight: 600; }
            .status-active { background: #28a745; color: white; }
            .status-inactive { background: #dc3545; color: white; }

            .banner-settings { background: rgba(255, 107, 157, 0.1); padding: 20px; border-radius: 15px; border: 1px solid #ff6b9d; margin-bottom: 20px; }
            .banner-preview { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; margin: 15px 0; color: white; }
            .banner-text { font-size: 16px; margin-bottom: 10px; }
            .banner-link { color: white; text-decoration: underline; font-weight: 600; }
            .switch { position: relative; display: inline-block; width: 60px; height: 34px; margin-left: 15px; }
            .switch input { opacity: 0; width: 0; height: 0; }
            .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px; }
            .slider:before { position: absolute; content: ""; height: 26px; width: 26px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }
            input:checked + .slider { background-color: #ff6b9d; }
            input:checked + .slider:before { transform: translateX(26px); }

            .comments-management { margin-top: 30px; }
            .comment-management-item { background: rgba(255, 107, 157, 0.05); padding: 15px; border-radius: 10px; margin-bottom: 15px; border: 1px solid rgba(255, 107, 157, 0.2); }
            .comment-management-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
            .comment-profile { font-weight: 600; color: #ff6b9d; }
            .comment-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
            .comment-promo { background: #28a745; color: white; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }

            .vip-catalogs-settings { background: rgba(255, 107, 157, 0.1); padding: 20px; border-radius: 15px; border: 1px solid #ff6b9d; margin-bottom: 20px; }
            .catalog-item { background: rgba(255, 107, 157, 0.05); padding: 20px; border-radius: 12px; margin-bottom: 15px; border: 1px solid rgba(255, 107, 157, 0.2); }
            .catalog-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
            .catalog-name { font-size: 18px; font-weight: 700; color: #ff6b9d; }
            .catalog-price { background: #28a745; color: white; padding: 5px 10px; border-radius: 8px; font-weight: 600; }

            .logout-btn {
                position: absolute;
                top: 20px;
                right: 20px;
                padding: 10px 20px;
                background: rgba(255, 255, 255, 0.2);
                color: white;
                border: 2px solid rgba(255, 255, 255, 0.3);
                border-radius: 10px;
                cursor: pointer;
                font-weight: 600;
                transition: all 0.3s;
            }
            .logout-btn:hover {
                background: rgba(255, 255, 255, 0.3);
                border-color: rgba(255, 255, 255, 0.5);
            }
            header {
                position: relative;
            }
            /* Notification badge for Chats button */
            .tab {
                position: relative;
            }
            .notification-badge {
                position: absolute;
                top: -5px;
                right: -5px;
                background: #ff0000;
                color: white;
                border-radius: 50%;
                width: 18px;
                height: 18px;
                font-size: 11px;
                font-weight: bold;
                display: flex;
                align-items: center;
                justify-content: center;
                box-shadow: 0 2px 6px rgba(255, 0, 0, 0.5);
            }
            .notification-badge.hidden {
                display: none;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <button class="logout-btn" onclick="logout()">Выход</button>
                <h1>Admin Panel - Muji</h1>
                <p>App Configuration | Crypto Wallets | Bookings</p>
            </header>

            <div class="stats">
                <div class="stat-card"><h3>Profiles</h3><p id="profiles-count">0</p></div>
                <div class="stat-card"><h3>Chats</h3><p id="chats-count">0</p></div>
                <div class="stat-card"><h3>Messages</h3><p id="messages-count">0</p></div>
                <div class="stat-card"><h3>Comments</h3><p id="comments-count">0</p></div>
                <div class="stat-card"><h3>Promocodes</h3><p id="promocodes-count">0</p></div>
            </div>

            <div class="tabs">
                <button class="tab active" onclick="showTab('profiles')">Profiles</button>
                <button class="tab" id="chats-tab" onclick="showTab('chats')">
                    Chats
                    <span id="chats-badge" class="notification-badge hidden">0</span>
                </button>
                <button class="tab" onclick="showTab('comments')">Comments</button>
                <button class="tab" onclick="showTab('add-profile')">Add Profile</button>
                <button class="tab" onclick="showTab('promocodes')">Promocodes</button>
                <button class="tab" onclick="showTab('bookings')">Bookings</button>
                <button class="tab" onclick="showTab('banner-settings')">Banner Settings</button>
                <button class="tab" onclick="showTab('crypto-settings')">Crypto Settings</button>
                <!-- VIP Catalogs removed -->
            </div>

            <div id="profiles" class="content active">
                <h3>Manage Profiles</h3>
                <div id="profiles-list" class="profile-grid"></div>
            </div>

            <div id="chats" class="content">
                <h3>Manage Chats</h3>
                <div id="chats-list"></div>
            </div>

            <div id="comments" class="content">
                <h3>Manage Comments</h3>
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; text-align: center; font-weight: bold; font-size: 16px;">
                    ✅ NEW SYSTEM: Admin Can Add Comments to Any Profile
                </div>
                <div class="comments-management">
                    <div id="profiles-list-comments" style="margin-bottom: 20px;"></div>
                    <div id="add-comment-form" style="display: none; background: rgba(102, 126, 234, 0.05); padding: 20px; border-radius: 10px; margin-top: 20px;">
                        <h4 id="selected-profile-name" style="margin-bottom: 15px;"></h4>
                        <div class="form-group">
                            <label>Author Name:</label>
                            <input type="text" id="comment-author-name" placeholder="Enter author name" required style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                        </div>
                        <div class="form-group" style="margin-top: 15px;">
                            <label>Comment:</label>
                            <textarea id="comment-text" placeholder="Enter comment" required style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; min-height: 100px;"></textarea>
                        </div>
                        <button type="button" onclick="saveCommentAdmin()" style="margin-top: 15px; padding: 10px 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 5px; cursor: pointer;">Save Comment</button>
                        <button type="button" onclick="cancelAddComment()" style="margin-top: 15px; margin-left: 10px; padding: 10px 20px; background: #999; color: white; border: none; border-radius: 5px; cursor: pointer;">Cancel</button>
                    </div>
                </div>
            </div>

            <div id="add-profile" class="content">
                <h3>Add New Profile</h3>
                <form id="add-profile-form" enctype="multipart/form-data">
                    <div class="form-group">
                        <label>Name:</label>
                        <input type="text" id="name" required>
                    </div>

                    <div class="form-group">
                        <label>Age:</label>
                        <input type="number" id="age" required min="18" max="100">
                    </div>

                    <div class="form-group">
                        <label>Gender:</label>
                        <select id="gender" required>
                            <option value="female">Female</option>
                            <option value="male">Male</option>
                            <option value="transgender">Transgender</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Nationality:</label>
                        <input type="text" id="nationality" required placeholder="e.g., Russian, Japanese, Korean">
                    </div>

                    <div class="form-group">
                        <label>City:</label>
                        <input type="text" id="city" required placeholder="e.g., Moscow">
                    </div>

                    <div class="form-group">
                        <label>Travel Cities (comma separated):</label>
                        <input type="text" id="travel-cities" placeholder="Moscow, Saint Petersburg, London">
                        <small style="color: #ff6b9d;">Cities where the profile can travel to</small>
                    </div>

                    <div class="form-group">
                        <label>Height (cm):</label>
                        <input type="number" id="height" required min="120" max="220" value="165">
                    </div>

                    <div class="form-group">
                        <label>Weight (kg):</label>
                        <input type="number" id="weight" required min="35" max="120" value="55">
                    </div>

                    <div class="form-group">
                        <label>Chest size:</label>
                        <select id="chest" required>
                            <option value="1">1 chest</option>
                            <option value="2">2 chest</option>
                            <option value="3" selected>3 chest</option>
                            <option value="4">4 chest</option>
                            <option value="5">5 chest</option>
                            <option value="6">6 chest</option>
                            <option value="7">7 chest</option>
                            <option value="8">8 chest</option>
                            <option value="9">9 chest</option>
                            <option value="10">10 chest</option>
                            <option value="11">11 chest</option>
                            <option value="12">12 chest</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Description:</label>
                        <textarea id="description" required placeholder="Enter profile description..."></textarea>
                    </div>

                    <div class="form-group">
                        <label>Upload Photos:</label>
                        <div class="file-upload">
                            <input type="file" id="photo-upload" accept="image/*" multiple style="display: none;">
                            <button type="button" class="btn btn-primary" onclick="document.getElementById('photo-upload').click()">
                                Select Photos (Multiple)
                            </button>
                            <div class="uploaded-photos" id="uploaded-photos"></div>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-success">Add Profile</button>
                </form>
            </div>

            <div id="promocodes" class="content">
                <h3>Manage Promocodes</h3>
                <div class="form-group">
                    <label>Create New Promocode:</label>
                    <div style="display: flex; gap: 10px;">
                        <input type="text" id="promocode-code" placeholder="Enter promocode (e.g., WELCOME15)" style="flex: 1;">
                        <input type="number" id="promocode-discount" placeholder="Discount %" min="1" max="100" value="15" style="width: 120px;">
                        <button class="btn btn-success" onclick="createPromocode()">Create</button>
                    </div>
                </div>
                <div id="promocodes-list" class="promocode-grid"></div>
            </div>

            <div id="bookings" class="content">
                <h3>Manage Bookings (Orders)</h3>
                <div id="bookings-list"></div>
            </div>

            <div id="banner-settings" class="content">
                <h3>Banner Settings</h3>
                <div class="banner-settings">
                    <div class="form-group">
                        <label>Banner Text:</label>
                        <input type="text" id="banner-text" placeholder="Enter banner text...">
                    </div>
                    <div class="form-group">
                        <label>Banner Link:</label>
                        <input type="text" id="banner-link" placeholder="https://t.me/yourchannel">
                    </div>
                    <div class="form-group">
                        <label>Link Text:</label>
                        <input type="text" id="banner-link-text" placeholder="Join Channel">
                    </div>
                    <div class="form-group">
                        <label style="display: flex; align-items: center;">
                            Show Banner:
                            <label class="switch">
                                <input type="checkbox" id="banner-visible">
                                <span class="slider"></span>
                            </label>
                        </label>
                    </div>
                    <div class="banner-preview" id="banner-preview">
                        <div class="banner-text" id="preview-text">Banner preview text</div>
                        <a href="#" class="banner-link" id="preview-link">Preview Link</a>
                    </div>
                    <button class="btn btn-primary" onclick="saveBannerSettings()">Save Banner Settings</button>
                </div>
            </div>

            <div id="crypto-settings" class="content">
                <h3>Crypto Wallet Settings</h3>
                <div class="crypto-settings">
                    <div class="form-group">
                        <label>TRC20 Wallet Address:</label>
                        <input type="text" id="trc20-wallet" class="wallet-address" value="TY76gU8J9o8j7U6tY5r4E3W2Q1">
                    </div>
                    <div class="form-group">
                        <label>ERC20 Wallet Address:</label>
                        <input type="text" id="erc20-wallet" class="wallet-address" value="0x8a9C6e5D8b0E2a1F3c4B6E7D8C9A0B1C2D3E4F5">
                    </div>
                    <div class="form-group">
                        <label>BNB Wallet Address:</label>
                        <input type="text" id="bnb-wallet" class="wallet-address" value="bnb1q3e5r7t9y1u3i5o7p9l1k3j5h7g9f2d4s6q8w0">
                    </div>
                    <div class="form-group">
                        <label>BTC Wallet Address:</label>
                        <input type="text" id="btc-wallet" class="wallet-address" value="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh">
                    </div>
                    <div class="form-group">
                        <label>ZetCash Wallet Address:</label>
                        <input type="text" id="zetcash-wallet" class="wallet-address" value="t1Z9C7k5tCQZ8eQh7zVn9vJfGz1hYz2wQ3P">
                    </div>
                    <div class="form-group">
                        <label>DOGE Wallet Address:</label>
                        <input type="text" id="doge-wallet" class="wallet-address" value="D7Y3K5z1vJfCqZh9rTgL2sWp4xNm8eB3aQ">
                    </div>
                    <div class="form-group">
                        <label>DASH Wallet Address:</label>
                        <input type="text" id="dash-wallet" class="wallet-address" value="Xk7vR3z9tQm1cWp5yL8nH4fGx2sT6eJ9dP">
                    </div>
                    <div class="form-group">
                        <label>LTC Wallet Address:</label>
                        <input type="text" id="ltc-wallet" class="wallet-address" value="LZh8vT3k9mQp5wR2nF7cY4gX6sL1eJ9dP">
                    </div>
                    <div class="form-group">
                        <label>USDT BEP20 Wallet Address:</label>
                        <input type="text" id="usdt_bep20-wallet" class="wallet-address" value="0x1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R9s0T">
                    </div>
                    <div class="form-group">
                        <label>ETH Wallet Address:</label>
                        <input type="text" id="eth-wallet" class="wallet-address" value="0x2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R9s0T1u">
                    </div>
                    <div class="form-group">
                        <label>USDC ERC20 Wallet Address:</label>
                        <input type="text" id="usdc_erc20-wallet" class="wallet-address" value="0x3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q8r9S0t1U2v">
                    </div>
                    <button class="btn btn-primary" onclick="saveCryptoWallets()">Save Wallet Addresses</button>
                </div>
            </div>

            <!-- VIP Catalogs section - REMOVED -->
            <!--
            <div id="vip-catalogs" class="content">
                <h3>VIP Catalogs Settings</h3>
                <div class="vip-catalogs-settings">
                    <div class="catalog-item">
                        <div class="catalog-header">
                            <span class="catalog-name">VIP Catalog</span>
                            <span class="catalog-price">$199</span>
                        </div>
                        <div class="form-group">
                            <label>Catalog Name:</label>
                            <input type="text" id="vip-catalog-name" value="VIP Catalog">
                        </div>
                        <div class="form-group">
                            <label>Price ($):</label>
                            <input type="number" id="vip-catalog-price" value="199" min="1">
                        </div>
                        <div class="form-group">
                            <label>Redirect URL:</label>
                            <input type="text" id="vip-catalog-url" value="https://t.me/vip_channel">
                        </div>
                        <div class="form-group">
                            <label style="display: flex; align-items: center;">
                                Visible:
                                <label class="switch">
                                    <input type="checkbox" id="vip-catalog-visible" checked>
                                    <span class="slider"></span>
                                </label>
                            </label>
                        </div>
                    </div>

                    <div class="catalog-item">
                        <div class="catalog-header">
                            <span class="catalog-name">Extra VIP Catalog</span>
                            <span class="catalog-price">$699</span>
                        </div>
                        <div class="form-group">
                            <label>Catalog Name:</label>
                            <input type="text" id="extra-vip-catalog-name" value="Extra VIP">
                        </div>
                        <div class="form-group">
                            <label>Price ($):</label>
                            <input type="number" id="extra-vip-catalog-price" value="699" min="1">
                        </div>
                        <div class="form-group">
                            <label>Redirect URL:</label>
                            <input type="text" id="extra-vip-catalog-url" value="https://t.me/extra_vip_channel">
                        </div>
                        <div class="form-group">
                            <label style="display: flex; align-items: center;">
                                Visible:
                                <label class="switch">
                                    <input type="checkbox" id="extra-vip-catalog-visible" checked>
                                    <span class="slider"></span>
                                </label>
                            </label>
                        </div>
                    </div>

                    <div class="catalog-item">
                        <div class="catalog-header">
                            <span class="catalog-name">Secret Catalog</span>
                            <span class="catalog-price">$2499</span>
                        </div>
                        <div class="form-group">
                            <label>Catalog Name:</label>
                            <input type="text" id="secret-catalog-name" value="Secret Catalog">
                        </div>
                        <div class="form-group">
                            <label>Price ($):</label>
                            <input type="number" id="secret-catalog-price" value="2499" min="1">
                        </div>
                        <div class="form-group">
                            <label>Redirect URL:</label>
                            <input type="text" id="secret-catalog-url" value="https://t.me/secret_channel">
                        </div>
                        <div class="form-group">
                            <label style="display: flex; align-items: center;">
                                Visible:
                                <label class="switch">
                                    <input type="checkbox" id="secret-catalog-visible" checked>
                                    <span class="slider"></span>
                                </label>
                            </label>
                        </div>
                    </div>

                    <button class="btn btn-primary" onclick="saveVipCatalogs()">Save VIP Catalogs</button>
                </div>
            </div>
            -->

        </div>

        <script>
            let uploadedPhotoFiles = [];
            let uploadedVipPhotoFiles = [];
            let currentChatId = null;  // Track current chat for replies

            // Вспомогательная функция для fetch с credentials
            const authFetch = (url, options = {}) => {
                return fetch(url, {
                    ...options,
                    credentials: 'include'
                });
            };

            // Функции для переключения вкладок
            // Хранение интервала для автообновления bookings
            let bookingsRefreshInterval = null;

            function showTab(tabName) {
                document.querySelectorAll('.content').forEach(tab => tab.classList.remove('active'));
                document.querySelectorAll('.tab').forEach(btn => btn.classList.remove('active'));
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');

                // Останавливаем автообновление bookings при переключении
                if (bookingsRefreshInterval) {
                    clearInterval(bookingsRefreshInterval);
                    bookingsRefreshInterval = null;
                }

                if (tabName === 'profiles') loadProfiles();
                if (tabName === 'chats') loadChats();
                if (tabName === 'comments') loadCommentsAdmin();
                if (tabName === 'promocodes') loadPromocodes();
                if (tabName === 'bookings') {
                    loadBookings();
                    // Автообновление каждые 5 секунд
                    bookingsRefreshInterval = setInterval(loadBookings, 5000);
                }
                if (tabName === 'banner-settings') loadBannerSettings();
                if (tabName === 'crypto-settings') loadCryptoWallets();
                // if (tabName === 'vip-catalogs') loadVipCatalogs(); // Removed
            }

            // Загрузка статистики
            async function loadStats() {
                try {
                    const response = await authFetch('/api/stats');
                    const stats = await response.json();
                    document.getElementById('profiles-count').textContent = stats.profiles_count;
                    document.getElementById('chats-count').textContent = stats.chats_count;
                    document.getElementById('messages-count').textContent = stats.messages_count;
                    document.getElementById('comments-count').textContent = stats.comments_count;
                    document.getElementById('promocodes-count').textContent = stats.promocodes_count;

                    // Обновление badge непрочитанных сообщений
                    const badge = document.getElementById('chats-badge');
                    const unreadCount = stats.unread_messages_count || 0;
                    if (unreadCount > 0) {
                        badge.textContent = unreadCount;
                        badge.classList.remove('hidden');
                    } else {
                        badge.classList.add('hidden');
                    }
                } catch (error) {
                    console.error('Error loading stats:', error);
                }
            }

            // Загрузка анкет
            async function loadProfiles() {
                try {
                    const response = await authFetch('/api/admin/profiles');
                    const data = await response.json();
                    const list = document.getElementById('profiles-list');
                    list.innerHTML = '';

                    data.profiles.forEach(profile => {
                        const travelCities = profile.travel_cities ? profile.travel_cities.join(', ') : 'None';
                        const photosHtml = profile.photos.map(photo => 
                            `<img src="http://localhost:8002${photo}" alt="Profile photo" style="width: 60px; height: 60px; object-fit: cover; border-radius: 8px; border: 1px solid #ff6b9d;">`
                        ).join('');

                        const profileDiv = document.createElement('div');
                        profileDiv.className = 'profile-card';
                        profileDiv.innerHTML = `
                            <div class="profile-header">
                                <span class="profile-id">ID: ${profile.id}</span>
                                <span class="profile-name">${profile.name}</span>
                            </div>
                            <p><strong>Gender:</strong> ${profile.gender || 'Not specified'}</p>
                            <p><strong>Nationality:</strong> ${profile.nationality || 'Not specified'}</p>
                            <p><strong>City:</strong> ${profile.city}</p>
                            <p><strong>Travel Cities:</strong> ${travelCities}</p>
                            <div class="profile-stats">
                                <span class="stat-badge">Height: ${profile.height} cm</span>
                                <span class="stat-badge">Weight: ${profile.weight} kg</span>
                                <span class="stat-badge">Chest: ${profile.chest}</span>
                            </div>
                            <p><strong>Description:</strong> ${profile.description}</p>
                            <p><strong>Status:</strong> ${profile.visible ? 'Visible' : 'Hidden'}</p>
                            <p><strong>Photos:</strong></p>
                            <div class="photo-preview">
                                ${photosHtml}
                            </div>
                            <div style="margin-top: 15px;">
                                <button class="btn btn-warning" onclick="toggleProfile(${profile.id}, ${!profile.visible})">
                                    ${profile.visible ? 'Hide' : 'Show'}
                                </button>
                                <button class="btn btn-danger" onclick="deleteProfile(${profile.id})">
                                    Delete
                                </button>
                            </div>
                        `;
                        list.appendChild(profileDiv);
                    });

                    loadStats();
                } catch (error) {
                    console.error('Error loading profiles:', error);
                }
            }

            // Переключение видимости анкеты
            async function toggleProfile(profileId, visible) {
                if (!confirm(visible ? 'Show profile?' : 'Hide profile?')) return;

                try {
                    await authFetch(`/api/admin/profiles/${profileId}/toggle`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ visible: visible })
                    });
                    loadProfiles();
                } catch (error) {
                    console.error('Error toggling profile:', error);
                    alert('Error updating profile');
                }
            }

            // Удаление анкеты
            async function deleteProfile(profileId) {
                if (!confirm('Delete profile? This action cannot be undone!')) return;

                try {
                    const response = await authFetch(`/api/admin/profiles/${profileId}`, {method: 'DELETE'});
                    if (response.ok) {
                        alert('Profile deleted!');
                        loadProfiles();
                    } else {
                        alert('Error deleting profile');
                    }
                } catch (error) {
                    console.error('Error deleting profile:', error);
                    alert('Error deleting profile');
                }
            }

            // Загрузка чатов
            async function loadChats() {
                try {
                    const response = await authFetch('/api/admin/chats');
                    const data = await response.json();
                    const list = document.getElementById('chats-list');
                    list.innerHTML = '';

                    if (data.chats.length === 0) {
                        list.innerHTML = '<p>No active chats</p>';
                        return;
                    }

                    data.chats.forEach(chat => {
                        const chatDiv = document.createElement('div');
                        chatDiv.className = 'profile-card';

                        // Display username instead of telegram_user_id
                        let userLabel = '';
                        if (chat.user_username) {
                            userLabel = `<p><strong>User:</strong> @${chat.user_username}</p>`;
                        } else if (chat.user_first_name) {
                            const fullName = chat.user_last_name
                                ? `${chat.user_first_name} ${chat.user_last_name}`
                                : chat.user_first_name;
                            userLabel = `<p><strong>User:</strong> ${fullName}</p>`;
                        } else if (chat.telegram_user_id) {
                            userLabel = `<p><strong>User:</strong> ${chat.telegram_user_id}</p>`;
                        }

                        // Notification badge for Open Chat button
                        const buttonBadge = chat.unread_count > 0
                            ? `<span class="unread-badge-button">${chat.unread_count}</span>`
                            : '';

                        chatDiv.innerHTML = `
                            <div class="profile-header">
                                <span class="profile-id">Chat #${chat.id}</span>
                                <span class="profile-name">${chat.profile_name}</span>
                            </div>
                            ${userLabel}
                            <p><strong>Created:</strong> ${new Date(chat.created_at).toLocaleString()}</p>
                            <button class="btn btn-primary" onclick="openChat(${chat.id}, ${chat.profile_id})" style="position: relative;">
                                Open Chat
                                ${buttonBadge}
                            </button>
                        `;
                        list.appendChild(chatDiv);
                    });
                } catch (error) {
                    console.error('Error loading chats:', error);
                }
            }

            // Открытие чата
            async function openChat(chatId, profileId) {
                currentChatId = chatId;  // Store for replies
                try {
                    // Mark messages as read
                    await authFetch(`/api/admin/chats/${chatId}/mark-read`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'}
                    });

                    // Update stats to refresh badge on Chats button
                    loadStats();

                    // Fetch messages
                    const response = await authFetch(`/api/admin/chats/${profileId}/messages?chat_id=${chatId}`);
                    const messages = await response.json();

                    // Fetch chat data to get user info
                    const chatsResponse = await authFetch('/api/admin/chats');
                    const chatsData = await chatsResponse.json();
                    const currentChat = chatsData.chats.find(c => c.id === chatId);

                    const list = document.getElementById('chats-list');

                    let messagesHtml = '';

                    messages.messages.forEach(msg => {
                        if (msg.is_system) {
                            // Системное сообщение
                            messagesHtml += `
                                <div class="system-message">
                                    <div class="system-bubble">${msg.text}</div>
                                </div>
                            `;
                        } else if (msg.file_url) {
                            // Сообщение с файлом
                            if (msg.file_type === 'image') {
                                messagesHtml += `
                                    <div class="chat-message ${msg.is_from_user ? 'user-message' : 'admin-message'}">
                                        <div class="message-sender">
                                            ${msg.is_from_user ? 'User' : 'Admin'}:
                                        </div>
                                        <div class="chat-attachment">
                                            <img src="http://localhost:8002${msg.file_url}" alt="Image" class="attachment-preview">
                                            <div>
                                                <div>${msg.text || ''}</div>
                                            </div>
                                        </div>
                                        <small style="color: #ff6b9d; font-size: 12px;">
                                            ${new Date(msg.created_at).toLocaleString()}
                                        </small>
                                    </div>
                                `;
                            } else if (msg.file_type === 'video') {
                                messagesHtml += `
                                    <div class="chat-message ${msg.is_from_user ? 'user-message' : 'admin-message'}">
                                        <div class="message-sender">
                                            ${msg.is_from_user ? 'User' : 'Admin'}:
                                        </div>
                                        <div class="chat-attachment">
                                            <video controls class="attachment-preview">
                                                <source src="http://localhost:8002${msg.file_url}" type="video/mp4">
                                                Your browser does not support video.
                                            </video>
                                            <div>
                                                <div>${msg.text || ''}</div>
                                            </div>
                                        </div>
                                        <small style="color: #ff6b9d; font-size: 12px;">
                                            ${new Date(msg.created_at).toLocaleString()}
                                        </small>
                                    </div>
                                `;
                            } else {
                                messagesHtml += `
                                    <div class="chat-message ${msg.is_from_user ? 'user-message' : 'admin-message'}">
                                        <div class="message-sender">
                                            ${msg.is_from_user ? 'User' : 'Admin'}:
                                        </div>
                                        <div class="file-message">
                                            <strong>File: ${msg.file_name}</strong>
                                            <div>${msg.text || ''}</div>
                                            <a href="http://localhost:8002${msg.file_url}" target="_blank" style="color: #ff6b9d;">Download file</a>
                                        </div>
                                        <small style="color: #ff6b9d; font-size: 12px;">
                                            ${new Date(msg.created_at).toLocaleString()}
                                        </small>
                                    </div>
                                `;
                            }
                        } else {
                            // Текстовое сообщение
                            messagesHtml += `
                                <div class="chat-message ${msg.is_from_user ? 'user-message' : 'admin-message'}">
                                    <div class="message-sender">
                                        ${msg.is_from_user ? 'User' : 'Admin'}:
                                    </div>
                                    <div>${msg.text}</div>
                                    <small style="color: #ff6b9d; font-size: 12px;">
                                        ${new Date(msg.created_at).toLocaleString()}
                                    </small>
                                </div>
                            `;
                        }
                    });

                    // Build user info display
                    let userInfoHtml = '';
                    if (currentChat) {
                        if (currentChat.user_username) {
                            userInfoHtml = `<p><strong>User:</strong> @${currentChat.user_username}</p>`;
                        } else if (currentChat.user_first_name) {
                            const fullName = currentChat.user_last_name
                                ? `${currentChat.user_first_name} ${currentChat.user_last_name}`
                                : currentChat.user_first_name;
                            userInfoHtml = `<p><strong>User:</strong> ${fullName}</p>`;
                        } else if (currentChat.telegram_user_id) {
                            userInfoHtml = `<p><strong>User:</strong> ${currentChat.telegram_user_id}</p>`;
                        }
                    }

                    list.innerHTML = `
                        <button class="back-btn" onclick="loadChats()">Back to chats</button>
                        <div class="profile-card">
                            <h3>Chat #${chatId}</h3>
                            ${userInfoHtml}
                            <p><strong>Created:</strong> ${currentChat ? new Date(currentChat.created_at).toLocaleString() : 'N/A'}</p>
                            <div style="margin: 15px 0;">
                                <button class="btn btn-system" onclick="sendSystemMessage(${chatId}, ${profileId})">
                                    Send Transaction Success Message
                                </button>
                            </div>
                            <div id="chat-messages" style="max-height: 500px; overflow-y: auto; margin: 20px 0;">
                                ${messagesHtml}
                            </div>
                            <div>
                                <h4>Reply:</h4>
                                <div class="chat-file-upload">
                                    <input type="file" id="admin-chat-file" accept="image/*,video/*,.pdf,.doc,.docx" multiple style="display: none;">
                                    <button type="button" class="btn btn-primary" onclick="document.getElementById('admin-chat-file').click()">
                                        Attach Files
                                    </button>
                                    <div class="chat-file-list" id="chat-file-list"></div>
                                </div>
                                <textarea id="reply-text" rows="3" style="width: 100%; margin: 15px 0; padding: 12px; background: rgba(255, 107, 157, 0.1); color: white; border: 1px solid #ff6b9d; border-radius: 8px;" placeholder="Type your message..."></textarea>
                                <button class="btn btn-primary" onclick="sendAdminReply(${chatId}, ${profileId})">
                                    Send Reply
                                </button>
                            </div>
                        </div>
                    `;

                    // Настройка загрузки файлов для чата
                    setupChatFileUpload();

                    // Прокрутка вниз
                    const chatMessages = document.getElementById('chat-messages');
                    if (chatMessages) {
                        chatMessages.scrollTop = chatMessages.scrollHeight;
                    }
                } catch (error) {
                    console.error('Error opening chat:', error);
                    alert('Error opening chat: ' + error.message);
                }
            }

            // Настройка загрузки файлов для чата
            function setupChatFileUpload() {
                const fileInput = document.getElementById('admin-chat-file');
                const fileList = document.getElementById('chat-file-list');
                let selectedFiles = [];

                fileInput.addEventListener('change', function(e) {
                    const files = Array.from(e.target.files);
                    selectedFiles = [...selectedFiles, ...files];
                    updateChatFileList();
                });

                function updateChatFileList() {
                    fileList.innerHTML = '';
                    selectedFiles.forEach((file, index) => {
                        const fileItem = document.createElement('div');
                        fileItem.className = 'file-item';
                        fileItem.innerHTML = `
                            <span>${file.name}</span>
                            <span class="remove-file" onclick="removeChatFile(${index})">×</span>
                        `;
                        fileList.appendChild(fileItem);
                    });
                }

                window.removeChatFile = function(index) {
                    selectedFiles.splice(index, 1);
                    updateChatFileList();
                    fileInput.value = '';
                };

                window.getSelectedChatFiles = function() {
                    return selectedFiles;
                };

                window.clearChatFiles = function() {
                    selectedFiles = [];
                    updateChatFileList();
                    fileInput.value = '';
                };
            }

            // Отправка ответа с файлами
            async function sendAdminReply(chatId, profileId) {
                const text = document.getElementById('reply-text').value.trim();
                const files = window.getSelectedChatFiles();

                if (!text && files.length === 0) {
                    alert('Please enter message text or attach files');
                    return;
                }

                try {
                    const formData = new FormData();
                    if (text) {
                        formData.append('text', text);
                    }

                    // Добавляем все файлы
                    files.forEach(file => {
                        formData.append('files', file);
                    });

                    const response = await authFetch(`/api/admin/chats/${profileId}/reply?chat_id=${chatId}`, {
                        method: 'POST',
                        body: formData
                    });

                    if (response.ok) {
                        document.getElementById('reply-text').value = '';
                        window.clearChatFiles();
                        openChat(chatId, profileId); // Перезагружаем чат
                    } else {
                        const errorData = await response.json();
                        alert('Error sending message: ' + (errorData.detail || 'Unknown error'));
                    }

                } catch (error) {
                    console.error('Error sending reply:', error);
                    alert('Error sending message: ' + error.message);
                }
            }

            // Отправка системного сообщения
            async function sendSystemMessage(chatId, profileId) {
                if (!confirm('Send transaction success message?')) return;

                try {
                    const response = await authFetch(`/api/admin/chats/${profileId}/system-message?chat_id=${chatId}`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            text: 'Transaction successful, your booking has been confirmed'
                        })
                    });

                    if (response.ok) {
                        openChat(chatId, profileId); // Перезагружаем чат
                    } else {
                        alert('Error sending system message');
                    }
                } catch (error) {
                    console.error('Error sending system message:', error);
                    alert('Error sending system message');
                }
            }

            // Управление комментариями
            let selectedProfileForComment = null;

            async function loadCommentsAdmin() {
                try {
                    const response = await authFetch('/api/admin/profiles');
                    const data = await response.json();
                    const list = document.getElementById('profiles-list-comments');
                    list.innerHTML = '<h4 style="margin-bottom: 15px;">Select Profile to Add Comment:</h4>';

                    if (!data.profiles || data.profiles.length === 0) {
                        list.innerHTML += '<p>No profiles available</p>';
                        return;
                    }

                    data.profiles.forEach(profile => {
                        const profileCard = document.createElement('div');
                        profileCard.className = 'profile-card-comment';
                        profileCard.style.cssText = 'background: white; padding: 15px; margin: 10px 0; border-radius: 8px; cursor: pointer; border: 2px solid transparent; transition: all 0.3s;';
                        profileCard.innerHTML = `
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <strong style="font-size: 16px;">${profile.name}</strong>
                                    <span style="color: #666; margin-left: 10px;">ID: ${profile.id}</span>
                                </div>
                                <button onclick="openAddCommentForm(${profile.id}, '${profile.name.replace(/'/g, "\\'")}'); event.stopPropagation();"
                                    style="padding: 8px 15px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 5px; cursor: pointer;">
                                    Add Comment
                                </button>
                            </div>
                        `;
                        list.appendChild(profileCard);
                    });

                    loadStats();
                } catch (error) {
                    console.error('Error loading profiles for comments:', error);
                }
            }

            function openAddCommentForm(profileId, profileName) {
                selectedProfileForComment = profileId;
                document.getElementById('selected-profile-name').textContent = `Adding comment for: ${profileName}`;
                document.getElementById('add-comment-form').style.display = 'block';
                document.getElementById('comment-author-name').value = '';
                document.getElementById('comment-text').value = '';
            }

            function cancelAddComment() {
                selectedProfileForComment = null;
                document.getElementById('add-comment-form').style.display = 'none';
            }

            async function saveCommentAdmin() {
                const authorName = document.getElementById('comment-author-name').value.trim();
                const commentText = document.getElementById('comment-text').value.trim();

                if (!authorName || !commentText) {
                    alert('Please fill in all fields');
                    return;
                }

                if (!selectedProfileForComment) {
                    alert('No profile selected');
                    return;
                }

                try {
                    const response = await authFetch('/api/admin/comments/add', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            profile_id: selectedProfileForComment,
                            author_name: authorName,
                            comment: commentText
                        })
                    });

                    if (response.ok) {
                        alert('Comment added successfully!');
                        cancelAddComment();
                        loadStats();
                    } else {
                        const error = await response.json();
                        alert('Error adding comment: ' + (error.detail || 'Unknown error'));
                    }
                } catch (error) {
                    console.error('Error saving comment:', error);
                    alert('Error saving comment');
                }
            }

            // Удаление комментария
            async function deleteComment(profileId, commentId) {
                if (!confirm('Delete this comment?')) return;

                try {
                    const response = await authFetch(`/api/admin/comments/${profileId}/${commentId}`, {
                        method: 'DELETE'
                    });

                    if (response.ok) {
                        alert('Comment deleted!');
                        loadCommentsAdmin();
                    } else {
                        alert('Error deleting comment');
                    }
                } catch (error) {
                    console.error('Error deleting comment:', error);
                    alert('Error deleting comment');
                }
            }

            // Промокоды
            async function loadPromocodes() {
                try {
                    const response = await authFetch('/api/admin/promocodes');
                    const data = await response.json();
                    const list = document.getElementById('promocodes-list');
                    list.innerHTML = '';

                    data.promocodes.forEach(promo => {
                        // Генерация списка пользователей
                        let usersListHtml = '';
                        if (promo.used_by && promo.used_by.length > 0) {
                            usersListHtml = `
                                <div style="margin-top: 15px; padding: 15px; background: rgba(255, 107, 157, 0.05); border-radius: 10px;">
                                    <h4 style="color: #ff6b9d; margin-bottom: 10px;">Users who activated (${promo.used_by.length}):</h4>
                                    <div style="display: flex; flex-direction: column; gap: 8px;">
                                        ${promo.used_by.map(usage => {
                                            const displayName = usage.username
                                                ? `@${usage.username}`
                                                : (usage.first_name
                                                    ? `${usage.first_name}${usage.last_name ? ' ' + usage.last_name : ''}`
                                                    : `User ${usage.telegram_user_id}`);
                                            const usedDate = usage.used_at ? new Date(usage.used_at).toLocaleString() : 'N/A';
                                            return `
                                                <div style="padding: 10px; background: rgba(255, 107, 157, 0.1); border-radius: 8px; border: 1px solid rgba(255, 107, 157, 0.3);">
                                                    <div style="font-weight: 600; color: #ff6b9d; margin-bottom: 5px;">${displayName}</div>
                                                    <div style="font-size: 12px; color: rgba(255, 255, 255, 0.7);">Used: ${usedDate}</div>
                                                </div>
                                            `;
                                        }).join('')}
                                    </div>
                                </div>
                            `;
                        }

                        const promoDiv = document.createElement('div');
                        promoDiv.className = 'promocode-card';
                        promoDiv.innerHTML = `
                            <div class="promocode-header">
                                <span class="promocode-code">${promo.code}</span>
                                <span class="promocode-discount">${promo.discount}% OFF</span>
                            </div>
                            <p><strong>Created:</strong> ${new Date(promo.created_at).toLocaleString()}</p>
                            <p><strong>Status:</strong>
                                <span class="promocode-status ${promo.is_active ? 'status-active' : 'status-inactive'}">
                                    ${promo.is_active ? 'ACTIVE' : 'INACTIVE'}
                                </span>
                            </p>
                            <p><strong>Used:</strong> ${promo.used_by ? promo.used_by.length : 0} times</p>
                            ${usersListHtml}
                            <div style="margin-top: 15px;">
                                <button class="btn btn-warning" onclick="togglePromocode(${promo.id}, ${!promo.is_active})">
                                    ${promo.is_active ? 'Deactivate' : 'Activate'}
                                </button>
                                <button class="btn btn-danger" onclick="deletePromocode(${promo.id})">
                                    Delete
                                </button>
                            </div>
                        `;
                        list.appendChild(promoDiv);
                    });

                    loadStats();
                } catch (error) {
                    console.error('Error loading promocodes:', error);
                }
            }

            async function createPromocode() {
                const code = document.getElementById('promocode-code').value.trim();
                const discount = parseInt(document.getElementById('promocode-discount').value);

                if (!code) {
                    alert('Please enter promocode');
                    return;
                }

                if (discount < 1 || discount > 100) {
                    alert('Discount must be between 1 and 100%');
                    return;
                }

                try {
                    const response = await authFetch('/api/admin/promocodes', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            code: code,
                            discount: discount
                        })
                    });

                    if (response.ok) {
                        alert('Promocode created!');
                        document.getElementById('promocode-code').value = '';
                        loadPromocodes();
                    } else {
                        alert('Error creating promocode');
                    }
                } catch (error) {
                    console.error('Error creating promocode:', error);
                    alert('Error creating promocode');
                }
            }

            async function togglePromocode(promocodeId, active) {
                try {
                    await authFetch(`/api/admin/promocodes/${promocodeId}/toggle`, {
                        method: 'POST'
                    });
                    loadPromocodes();
                } catch (error) {
                    console.error('Error toggling promocode:', error);
                    alert('Error updating promocode');
                }
            }

            async function deletePromocode(promocodeId) {
                if (!confirm('Delete promocode? This action cannot be undone!')) return;

                try {
                    const response = await authFetch(`/api/admin/promocodes/${promocodeId}`, {method: 'DELETE'});
                    if (response.ok) {
                        alert('Promocode deleted!');
                        loadPromocodes();
                    } else {
                        alert('Error deleting promocode');
                    }
                } catch (error) {
                    console.error('Error deleting promocode:', error);
                    alert('Error deleting promocode');
                }
            }

            // Bookings (Orders)
            async function loadBookings() {
                try {
                    const response = await authFetch('/api/admin/bookings');
                    const data = await response.json();
                    const list = document.getElementById('bookings-list');
                    list.innerHTML = '';

                    if (!data || !data.orders || data.orders.length === 0) {
                        list.innerHTML = '<p>No orders yet</p>';
                        return;
                    }

                    // Подсчитываем pending ордера
                    const pendingCount = data.orders.filter(o => o.status === 'unpaid').length;
                    const confirmedCount = data.orders.filter(o => o.status === 'booked').length;

                    // Добавляем заголовок со статистикой
                    const headerDiv = document.createElement('div');
                    headerDiv.style.cssText = 'margin-bottom: 20px; padding: 15px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 12px; color: white;';
                    headerDiv.innerHTML = `
                        <div style="display: flex; justify-content: space-around; text-align: center;">
                            <div>
                                <div style="font-size: 32px; font-weight: bold;">${pendingCount}</div>
                                <div style="font-size: 14px; opacity: 0.9;">Pending Orders</div>
                            </div>
                            <div>
                                <div style="font-size: 32px; font-weight: bold;">${confirmedCount}</div>
                                <div style="font-size: 14px; opacity: 0.9;">Confirmed Orders</div>
                            </div>
                            <div>
                                <div style="font-size: 32px; font-weight: bold;">${data.orders.length}</div>
                                <div style="font-size: 14px; opacity: 0.9;">Total Orders</div>
                            </div>
                        </div>
                    `;
                    list.appendChild(headerDiv);

                    data.orders.forEach(order => {
                        const orderDiv = document.createElement('div');
                        orderDiv.className = 'profile-card';

                        // Добавляем специальное оформление для pending
                        if (order.status === 'unpaid') {
                            orderDiv.style.border = '2px solid #ff6b9d';
                            orderDiv.style.background = 'linear-gradient(135deg, rgba(255, 107, 157, 0.05), rgba(255, 107, 157, 0.1))';
                        } else {
                            orderDiv.style.border = '2px solid #4CAF50';
                            orderDiv.style.background = 'linear-gradient(135deg, rgba(76, 175, 80, 0.05), rgba(76, 175, 80, 0.1))';
                        }

                        const statusBadge = order.status === 'unpaid'
                            ? '<span style="background: #ff6b9d; color: white; padding: 6px 14px; border-radius: 12px; font-size: 12px; font-weight: bold; animation: pulse 2s infinite;">⏳ PENDING</span>'
                            : '<span style="background: #4CAF50; color: white; padding: 6px 14px; border-radius: 12px; font-size: 12px; font-weight: bold;">✓ CONFIRMED</span>';

                        const cryptoTypeDisplay = {
                            'trc20': 'USDT (TRC20)',
                            'erc20': 'USDT (ERC20)',
                            'bnb': 'BNB (BEP20)',
                            'btc': 'Bitcoin'
                        };

                        // Вычисляем оставшееся время для pending
                        let timerHtml = '';
                        if (order.status === 'unpaid' && order.expires_at) {
                            const expiresTime = new Date(order.expires_at).getTime();
                            const now = Date.now();
                            const remainingMs = expiresTime - now;

                            if (remainingMs > 0) {
                                const minutes = Math.floor(remainingMs / 60000);
                                const seconds = Math.floor((remainingMs % 60000) / 1000);
                                timerHtml = `<p style="color: #ff6b9d; font-weight: bold; font-size: 16px;"><strong>⏰ Expires in:</strong> ${minutes}m ${seconds}s</p>`;
                            } else {
                                timerHtml = `<p style="color: #dc3545; font-weight: bold;"><strong>❌ Expired</strong></p>`;
                            }
                        }

                        // Создаем фото если есть
                        const borderColor = order.status === 'unpaid' ? '#ff6b9d' : '#4CAF50';
                        const photoHtml = order.profile_photo
                            ? '<img src="' + order.profile_photo + '" style="width: 60px; height: 60px; border-radius: 50%; object-fit: cover; border: 3px solid ' + borderColor + ';">'
                            : '';

                        const confirmedDateHtml = (order.status === 'booked' && order.booked_at)
                            ? '<p style="font-size: 13px; color: #4CAF50;"><strong>✅ Confirmed:</strong> ' + new Date(order.booked_at).toLocaleString() + '</p>'
                            : '';

                        const confirmButtonHtml = order.status === 'unpaid'
                            ? '<div style="margin-top: 15px;"><button class="btn btn-success" onclick="confirmPayment(' + order.id + ')" style="width: 100%; padding: 12px; font-size: 16px; font-weight: bold;">✓ Confirm Payment</button></div>'
                            : '';

                        orderDiv.innerHTML = `
                            <div class="profile-header" style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px;">
                                ${photoHtml}
                                <div style="flex: 1;">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <span class="profile-id" style="font-size: 12px; font-weight: bold; word-break: break-all;">Order #${order.order_number || order.id}</span>
                                        ${statusBadge}
                                    </div>
                                    <div style="font-size: 18px; font-weight: 600; margin-top: 5px;">${order.profile_name || 'Unknown'}</div>
                                    <div style="font-size: 13px; color: #666; margin-top: 2px;">📍 ${order.profile_city || 'Unknown'}</div>
                                </div>
                            </div>
                            ${timerHtml}
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 15px 0;">
                                <p><strong>💎 Crypto:</strong> ${cryptoTypeDisplay[order.crypto_type] || order.crypto_type || 'N/A'}</p>
                                <p><strong>💰 Amount:</strong> $${order.amount || 0}</p>
                                <p><strong>🎁 Bonus:</strong> $${order.bonus_amount || 0}</p>
                                <p><strong>💵 Total:</strong> $${order.total_amount || 0}</p>
                            </div>
                            <p style="font-size: 13px; color: #666;"><strong>📅 Created:</strong> ${new Date(order.created_at).toLocaleString()}</p>
                            ${confirmedDateHtml}
                            ${confirmButtonHtml}
                        `;
                        list.appendChild(orderDiv);
                    });

                } catch (error) {
                    console.error('Error loading bookings:', error);
                    const list = document.getElementById('bookings-list');
                    list.innerHTML = '<div style="color: red; padding: 20px;">Error loading bookings. Check console for details.</div>';
                }
            }

            async function confirmPayment(orderId) {
                if (!confirm('Confirm payment for this order?')) return;

                // Показываем индикатор загрузки
                const list = document.getElementById('bookings-list');
                const originalContent = list.innerHTML;
                list.innerHTML = '<div style="text-align: center; padding: 40px; font-size: 18px; color: #667eea;"><div style="display: inline-block; animation: pulse 1s infinite;">⏳ Confirming payment...</div></div>';

                try {
                    const response = await authFetch(`/api/admin/bookings/${orderId}/confirm`, {
                        method: 'POST'
                    });

                    if (response.ok) {
                        // Мгновенно обновляем список
                        await loadBookings();

                        // Показываем уведомление об успехе
                        const notification = document.createElement('div');
                        notification.style.cssText = 'position: fixed; top: 20px; right: 20px; background: #4CAF50; color: white; padding: 20px 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); z-index: 10000; font-size: 16px; font-weight: bold;';
                        notification.innerHTML = '✅ Payment confirmed! Order moved to user bookings';
                        document.body.appendChild(notification);

                        // Удаляем уведомление через 3 секунды
                        setTimeout(() => {
                            notification.style.transition = 'opacity 0.5s';
                            notification.style.opacity = '0';
                            setTimeout(() => notification.remove(), 500);
                        }, 3000);
                    } else {
                        list.innerHTML = originalContent;
                        alert('Error confirming payment');
                    }
                } catch (error) {
                    console.error('Error confirming payment:', error);
                    list.innerHTML = originalContent;
                    alert('Error confirming payment');
                }
            }

            // Баннер
            async function loadBannerSettings() {
                try {
                    const response = await authFetch('/api/admin/banner');
                    const banner = await response.json();

                    document.getElementById('banner-text').value = banner.text || '';
                    document.getElementById('banner-link').value = banner.link || '';
                    document.getElementById('banner-link-text').value = banner.link_text || '';
                    document.getElementById('banner-visible').checked = banner.visible !== false;

                    updateBannerPreview();
                } catch (error) {
                    console.error('Error loading banner settings:', error);
                }
            }

            function updateBannerPreview() {
                const text = document.getElementById('banner-text').value || 'Banner preview text';
                const link = document.getElementById('banner-link').value || '#';
                const linkText = document.getElementById('banner-link-text').value || 'Preview Link';

                document.getElementById('preview-text').textContent = text;
                document.getElementById('preview-link').textContent = linkText;
                document.getElementById('preview-link').href = link;
            }

            async function saveBannerSettings() {
                try {
                    const banner = {
                        text: document.getElementById('banner-text').value,
                        link: document.getElementById('banner-link').value,
                        link_text: document.getElementById('banner-link-text').value,
                        visible: document.getElementById('banner-visible').checked
                    };

                    const response = await authFetch('/api/admin/banner', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(banner)
                    });

                    if (response.ok) {
                        alert('Banner settings saved!');
                        updateBannerPreview();
                    } else {
                        alert('Error saving banner settings');
                    }
                } catch (error) {
                    console.error('Error saving banner settings:', error);
                    alert('Error saving banner settings');
                }
            }

            // VIP каталоги - REMOVED
            /*
            async function loadVipCatalogs() {
                try {
                    const response = await authFetch('/api/admin/vip-catalogs');
                    const catalogs = await response.json();

                    document.getElementById('vip-catalog-name').value = catalogs.vip?.name || 'VIP Catalog';
                    document.getElementById('vip-catalog-price').value = catalogs.vip?.price || 199;
                    document.getElementById('vip-catalog-url').value = catalogs.vip?.redirect_url || 'https://t.me/vip_channel';
                    document.getElementById('vip-catalog-visible').checked = catalogs.vip?.visible !== false;

                    document.getElementById('extra-vip-catalog-name').value = catalogs.extra_vip?.name || 'Extra VIP';
                    document.getElementById('extra-vip-catalog-price').value = catalogs.extra_vip?.price || 699;
                    document.getElementById('extra-vip-catalog-url').value = catalogs.extra_vip?.redirect_url || 'https://t.me/extra_vip_channel';
                    document.getElementById('extra-vip-catalog-visible').checked = catalogs.extra_vip?.visible !== false;

                    document.getElementById('secret-catalog-name').value = catalogs.secret?.name || 'Secret Catalog';
                    document.getElementById('secret-catalog-price').value = catalogs.secret?.price || 2499;
                    document.getElementById('secret-catalog-url').value = catalogs.secret?.redirect_url || 'https://t.me/secret_channel';
                    document.getElementById('secret-catalog-visible').checked = catalogs.secret?.visible !== false;
                } catch (error) {
                    console.error('Error loading VIP catalogs:', error);
                }
            }

            async function saveVipCatalogs() {
                try {
                    const catalogs = {
                        vip: {
                            name: document.getElementById('vip-catalog-name').value,
                            price: parseInt(document.getElementById('vip-catalog-price').value),
                            redirect_url: document.getElementById('vip-catalog-url').value,
                            visible: document.getElementById('vip-catalog-visible').checked
                        },
                        extra_vip: {
                            name: document.getElementById('extra-vip-catalog-name').value,
                            price: parseInt(document.getElementById('extra-vip-catalog-price').value),
                            redirect_url: document.getElementById('extra-vip-catalog-url').value,
                            visible: document.getElementById('extra-vip-catalog-visible').checked
                        },
                        secret: {
                            name: document.getElementById('secret-catalog-name').value,
                            price: parseInt(document.getElementById('secret-catalog-price').value),
                            redirect_url: document.getElementById('secret-catalog-url').value,
                            visible: document.getElementById('secret-catalog-visible').checked
                        }
                    };

                    const response = await authFetch('/api/admin/vip-catalogs', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(catalogs)
                    });

                    if (response.ok) {
                        alert('VIP catalogs settings saved!');
                    } else {
                        alert('Error saving VIP catalogs settings');
                    }
                } catch (error) {
                    console.error('Error saving VIP catalogs:', error);
                    alert('Error saving VIP catalogs settings');
                }
            }
            */

            // Загрузка фото для профиля
            document.getElementById('photo-upload').addEventListener('change', function(e) {
                const files = Array.from(e.target.files);
                const uploadedPhotosContainer = document.getElementById('uploaded-photos');

                files.forEach(file => {
                    if (file.type.startsWith('image/')) {
                        const reader = new FileReader();
                        reader.onload = function(e) {
                            const photoData = e.target.result;
                            uploadedPhotoFiles.push(file);

                            const photoDiv = document.createElement('div');
                            photoDiv.className = 'uploaded-photo';
                            photoDiv.innerHTML = `
                                <img src="${photoData}" alt="Uploaded photo">
                                <button type="button" class="remove-photo" onclick="removeUploadedPhoto(${uploadedPhotoFiles.length - 1})">×</button>
                            `;
                            uploadedPhotosContainer.appendChild(photoDiv);
                        };
                        reader.readAsDataURL(file);
                    }
                });

                this.value = '';
            });

            // Удаление загруженного фото
            window.removeUploadedPhoto = function(index) {
                uploadedPhotoFiles.splice(index, 1);
                updateUploadedPhotosDisplay();
            };

            // Обновление отображения загруженных фото
            function updateUploadedPhotosDisplay() {
                const uploadedPhotosContainer = document.getElementById('uploaded-photos');
                uploadedPhotosContainer.innerHTML = '';

                uploadedPhotoFiles.forEach((file, index) => {
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        const photoDiv = document.createElement('div');
                        photoDiv.className = 'uploaded-photo';
                        photoDiv.innerHTML = `
                            <img src="${e.target.result}" alt="Uploaded photo">
                            <button type="button" class="remove-photo" onclick="removeUploadedPhoto(${index})">×</button>
                        `;
                        uploadedPhotosContainer.appendChild(photoDiv);
                    };
                    reader.readAsDataURL(file);
                });
            }

            // Обработчик формы добавления анкеты
            document.getElementById('add-profile-form').addEventListener('submit', async function(e) {
                e.preventDefault();

                if (uploadedPhotoFiles.length === 0) {
                    alert('Please upload at least one photo');
                    return;
                }

                const travelCities = document.getElementById('travel-cities').value
                    .split(',')
                    .map(city => city.trim())
                    .filter(city => city);

                // Создаем FormData для отправки файлов
                const formData = new FormData();
                formData.append('name', document.getElementById('name').value);
                formData.append('age', document.getElementById('age').value);
                formData.append('gender', document.getElementById('gender').value);
                formData.append('nationality', document.getElementById('nationality').value);
                formData.append('city', document.getElementById('city').value);
                formData.append('travel_cities', JSON.stringify(travelCities));
                formData.append('description', document.getElementById('description').value);
                formData.append('height', document.getElementById('height').value);
                formData.append('weight', document.getElementById('weight').value);
                formData.append('chest', document.getElementById('chest').value);

                // Добавляем фото
                uploadedPhotoFiles.forEach(file => {
                    formData.append('photos', file);
                });

                try {
                    const response = await authFetch('/api/admin/profiles', {
                        method: 'POST',
                        body: formData
                    });

                    if (response.ok) {
                        alert('Profile added successfully!');
                        this.reset();
                        uploadedPhotoFiles = [];
                        updateUploadedPhotosDisplay();
                        showTab('profiles');
                    } else {
                        const errorData = await response.json();
                        alert('Error adding profile: ' + (errorData.detail || 'Unknown error'));
                    }
                } catch (error) {
                    console.error('Error adding profile:', error);
                    alert('Error adding profile: ' + error.message);
                }
            });

            // Загрузка крипто-кошельков
            async function loadCryptoWallets() {
                try {
                    const response = await authFetch('/api/admin/crypto_wallets');
                    const wallets = await response.json();

                    document.getElementById('trc20-wallet').value = wallets.trc20 || '';
                    document.getElementById('erc20-wallet').value = wallets.erc20 || '';
                    document.getElementById('bnb-wallet').value = wallets.bnb || '';
                    document.getElementById('btc-wallet').value = wallets.btc || '';
                    document.getElementById('zetcash-wallet').value = wallets.zetcash || '';
                    document.getElementById('doge-wallet').value = wallets.doge || '';
                    document.getElementById('dash-wallet').value = wallets.dash || '';
                    document.getElementById('ltc-wallet').value = wallets.ltc || '';
                    document.getElementById('usdt_bep20-wallet').value = wallets.usdt_bep20 || '';
                    document.getElementById('eth-wallet').value = wallets.eth || '';
                    document.getElementById('usdc_erc20-wallet').value = wallets.usdc_erc20 || '';
                } catch (error) {
                    console.error('Error loading crypto wallets:', error);
                }
            }

            // Сохранение крипто-кошельков
            async function saveCryptoWallets() {
                try {
                    const wallets = {
                        trc20: document.getElementById('trc20-wallet').value,
                        erc20: document.getElementById('erc20-wallet').value,
                        bnb: document.getElementById('bnb-wallet').value,
                        btc: document.getElementById('btc-wallet').value,
                        zetcash: document.getElementById('zetcash-wallet').value,
                        doge: document.getElementById('doge-wallet').value,
                        dash: document.getElementById('dash-wallet').value,
                        ltc: document.getElementById('ltc-wallet').value,
                        usdt_bep20: document.getElementById('usdt_bep20-wallet').value,
                        eth: document.getElementById('eth-wallet').value,
                        usdc_erc20: document.getElementById('usdc_erc20-wallet').value
                    };

                    const response = await authFetch('/api/admin/crypto_wallets', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(wallets)
                    });

                    if (response.ok) {
                        alert('Wallet addresses saved successfully!');
                    } else {
                        alert('Error saving wallet addresses');
                    }
                } catch (error) {
                    console.error('Error saving crypto wallets:', error);
                    alert('Error saving wallet addresses');
                }
            }

            // Загружаем анкеты при старте
            loadProfiles();

            // Обновляем превью баннера при изменении
            document.getElementById('banner-text').addEventListener('input', updateBannerPreview);
            document.getElementById('banner-link').addEventListener('input', updateBannerPreview);
            document.getElementById('banner-link-text').addEventListener('input', updateBannerPreview);

            // Функция выхода
            async function logout() {
                try {
                    await authFetch('/api/logout', { method: 'POST' });
                    window.location.href = '/login';
                } catch (error) {
                    console.error('Ошибка при выходе:', error);
                    window.location.href = '/login';
                }
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


# API endpoints
@app.get("/api/stats")
async def get_stats(current_user: str = Depends(get_current_user)):
    data = load_data()

    # Подсчет непрочитанных сообщений (только НЕПРОЧИТАННЫЕ сообщения от пользователей)
    unread_count = sum(1 for m in data.get("messages", [])
                      if m.get("is_from_user", False) and not m.get("is_read", False))

    return {
        "profiles_count": len(data["profiles"]),
        "vip_profiles_count": len(data.get("vip_profiles", [])),
        "chats_count": len(data["chats"]),
        "messages_count": len(data["messages"]),
        "comments_count": len(data.get("comments", [])),
        "promocodes_count": len(data.get("promocodes", [])),
        "unread_messages_count": unread_count
    }


@app.get("/api/admin/profiles")
async def get_admin_profiles(current_user: str = Depends(get_current_user)):
    data = load_data()
    return {"profiles": data["profiles"]}


@app.post("/api/admin/profiles")
async def create_profile(
        current_user: str = Depends(get_current_user),
        name: str = Form(...),
        age: int = Form(...),
        gender: str = Form(...),
        nationality: str = Form(...),
        city: str = Form(...),
        travel_cities: str = Form(...),
        description: str = Form(...),
        height: int = Form(...),
        weight: int = Form(...),
        chest: int = Form(...),
        photos: list[UploadFile] = File(...)
):
    data = load_data()

    # Находим максимальный ID
    max_id = max([p["id"] for p in data["profiles"]]) if data["profiles"] else 0

    # Сохраняем загруженные фото
    photo_urls = []
    for photo in photos:
        if photo.filename:
            photo_url, _, _, _ = save_uploaded_file(photo)
            if photo_url:
                photo_urls.append(photo_url)

    if not photo_urls:
        raise HTTPException(status_code=400, detail="At least one photo is required")

    # Парсим travel cities
    try:
        travel_cities_list = json.loads(travel_cities)
    except:
        travel_cities_list = [city.strip() for city in travel_cities.split(',') if city.strip()]

    new_profile = {
        "id": max_id + 1,
        "name": name,
        "age": age,
        "gender": gender,
        "nationality": nationality,
        "city": city,
        "travel_cities": travel_cities_list,
        "description": description,
        "photos": photo_urls,
        "height": height,
        "weight": weight,
        "chest": chest,
        "visible": True,
        "created_at": datetime.now().isoformat()
    }

    data["profiles"].append(new_profile)
    save_data(data)
    return {"status": "created", "profile": new_profile}


@app.post("/api/admin/profiles/{profile_id}/toggle")
async def toggle_profile(profile_id: int, visible_data: dict, current_user: str = Depends(get_current_user)):
    data = load_data()
    profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
    if profile:
        profile["visible"] = visible_data["visible"]
        save_data(data)
    return {"status": "updated"}


@app.delete("/api/admin/profiles/{profile_id}")
async def delete_profile(profile_id: int, current_user: str = Depends(get_current_user)):
    data = load_data()

    # Удаляем анкету
    data["profiles"] = [p for p in data["profiles"] if p["id"] != profile_id]

    # Находим чаты связанные с этой анкетой
    profile_chats = [c for c in data["chats"] if c["profile_id"] == profile_id]
    chat_ids = [c["id"] for c in profile_chats]

    # Удаляем чаты
    data["chats"] = [c for c in data["chats"] if c["profile_id"] != profile_id]

    # Удаляем сообщения из этих чатов
    data["messages"] = [m for m in data["messages"] if m["chat_id"] not in chat_ids]

    # Удаляем комментарии к этой анкете
    data["comments"] = [c for c in data.get("comments", []) if c["profile_id"] != profile_id]

    save_data(data)
    return {"status": "deleted"}


@app.get("/api/admin/chats")
async def get_admin_chats(current_user: str = Depends(get_current_user)):
    data = load_data()

    # Добавляем счетчик непрочитанных сообщений для каждого чата
    chats_with_unread = []
    for chat in data["chats"]:
        # Считаем только НЕПРОЧИТАННЫЕ сообщения от пользователя
        unread_count = sum(1 for m in data["messages"]
                          if m["chat_id"] == chat["id"]
                          and m.get("is_from_user", False)
                          and not m.get("is_read", False))

        chat_copy = chat.copy()
        chat_copy["unread_count"] = unread_count

        # Use stored username from chat, or fetch from database for old chats
        if not chat.get("user_username") and chat.get("telegram_user_id"):
            user_data = db.get_user_by_telegram_id(int(chat["telegram_user_id"]))
            if user_data:
                chat_copy["user_username"] = user_data.get("username", "")
                chat_copy["user_first_name"] = user_data.get("first_name", "")
                chat_copy["user_last_name"] = user_data.get("last_name", "")

        chats_with_unread.append(chat_copy)

    return {"chats": chats_with_unread}


@app.get("/api/admin/chats/{profile_id}/messages")
async def get_chat_messages_admin(profile_id: int, current_user: str = Depends(get_current_user),
                                   chat_id: Optional[int] = None, telegram_user_id: Optional[str] = None):
    data = load_data()

    # Если указан chat_id, ищем по нему
    if chat_id:
        chat = next((c for c in data["chats"] if c["id"] == chat_id), None)
    # Если указан telegram_user_id, ищем чат для конкретного пользователя
    elif telegram_user_id:
        chat = next((c for c in data["chats"]
                     if c["profile_id"] == profile_id and c.get("telegram_user_id") == telegram_user_id), None)
    else:
        # Для обратной совместимости: если параметры не указаны, ищем любой чат для profile_id
        chat = next((c for c in data["chats"] if c["profile_id"] == profile_id), None)

    if not chat:
        return {"messages": [], "chat_id": None, "telegram_user_id": None}

    messages = [m for m in data["messages"] if m["chat_id"] == chat["id"]]
    return {
        "messages": messages,
        "chat_id": chat["id"],
        "telegram_user_id": chat.get("telegram_user_id")
    }


@app.post("/api/admin/chats/{profile_id}/reply")
async def send_admin_reply(
        profile_id: int,
        request: Request,
        current_user: str = Depends(get_current_user),
        chat_id: Optional[int] = None,
        telegram_user_id: Optional[str] = None
):
    data = load_data()

    logger.info(f"📨 Sending reply to profile {profile_id}, chat_id: {chat_id}, telegram_user_id: {telegram_user_id}")

    # Находим профиль для имени
    profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Ищем чат по chat_id, telegram_user_id или profile_id
    if chat_id:
        chat = next((c for c in data["chats"] if c["id"] == chat_id), None)
    elif telegram_user_id:
        chat = next((c for c in data["chats"]
                     if c["profile_id"] == profile_id and c.get("telegram_user_id") == telegram_user_id), None)
    else:
        # Для обратной совместимости: ищем любой чат для profile_id
        chat = next((c for c in data["chats"] if c["profile_id"] == profile_id), None)

    if not chat:
        # Создаем чат только если указан telegram_user_id
        chat = {
            "id": len(data["chats"]) + 1,
            "profile_id": profile_id,
            "profile_name": profile["name"],
            "telegram_user_id": telegram_user_id,
            "created_at": datetime.now().isoformat()
        }
        data["chats"].append(chat)

    try:
        # Получаем форму с файлами и текстом
        form = await request.form()
        text = form.get("text", "").strip()
        files = form.getlist("files")

        logger.info(f"📝 Text: '{text}'")
        logger.info(f"📎 Files count: {len(files)}")

        has_files = False
        has_text = bool(text)

        # Обрабатываем файлы
        if files and any(hasattr(f, 'filename') and f.filename for f in files):
            for file in files:
                if hasattr(file, 'filename') and file.filename:
                    file_url, _, _, _ = save_uploaded_file(file)
                    if file_url:
                        file_type = get_file_type(file.filename)

                        message_data = {
                            "id": len(data["messages"]) + 1,
                            "chat_id": chat["id"],
                            "file_url": file_url,
                            "file_type": file_type,
                            "file_name": file.filename,
                            "text": text or "",  # Убираем автоматический текст
                            "is_from_user": False,
                            "created_at": datetime.now().isoformat()
                        }
                        data["messages"].append(message_data)
                        has_files = True
                        logger.info(f"✅ File message added: {file.filename}")

        # Если только текст (без файлов)
        if not has_files and has_text:
            message_data = {
                "id": len(data["messages"]) + 1,
                "chat_id": chat["id"],
                "text": text,
                "is_from_user": False,
                "created_at": datetime.now().isoformat()
            }
            data["messages"].append(message_data)
            logger.info("✅ Text message added")

        # Если ничего не отправлено
        if not has_files and not has_text:
            raise HTTPException(status_code=400, detail="Text or files is required")

        # Проверяем если это подтверждение оплаты
        if text and "payment successful" in text.lower():
            # Находим последний unpaid ордер для этого профиля
            profile_orders = [o for o in data.get("orders", [])
                            if o.get("profile_id") == profile_id and o.get("status") == "unpaid"]
            if profile_orders:
                # Обновляем статус последнего ордера
                last_order = profile_orders[-1]
                last_order["status"] = "booked"
                last_order["booked_at"] = datetime.now().isoformat()
                logger.info(f"Order #{last_order['id']} marked as booked for profile {profile_id}")

        save_data(data)
        logger.info("Data saved successfully")
        return {"status": "sent"}

    except Exception as e:
        logger.error(f"❌ Error sending reply: {e}")
        raise HTTPException(status_code=500, detail=f"Error sending message: {str(e)}")


@app.get("/api/chats/{profile_id}/messages")
async def get_chat_messages(profile_id: int, telegram_user_id: Optional[str] = None):
    """Получить все сообщения чата для пользователя"""
    # SECURITY: telegram_user_id is required to prevent users from seeing other users' messages
    if not telegram_user_id:
        raise HTTPException(
            status_code=400,
            detail="telegram_user_id is required for message isolation. Please ensure Telegram WebApp is properly initialized."
        )

    data = load_data()

    # Ищем чат для конкретного пользователя и профиля
    chat = next((c for c in data["chats"]
                 if c["profile_id"] == profile_id and c.get("telegram_user_id") == telegram_user_id), None)
    if not chat:
        return {"messages": [], "last_message_id": 0}

    messages = [m for m in data["messages"] if m["chat_id"] == chat["id"]]
    last_id = messages[-1]["id"] if messages else 0

    return {
        "messages": messages,
        "last_message_id": last_id
    }


@app.get("/api/chats/{profile_id}/updates")
async def get_chat_updates(profile_id: int, last_message_id: int = 0, telegram_user_id: Optional[str] = None):
    """Получить только новые сообщения после указанного ID"""
    # SECURITY: telegram_user_id is required to prevent users from seeing other users' messages
    if not telegram_user_id:
        raise HTTPException(
            status_code=400,
            detail="telegram_user_id is required for message isolation. Please ensure Telegram WebApp is properly initialized."
        )

    data = load_data()

    # Ищем чат для конкретного пользователя и профиля
    chat = next((c for c in data["chats"]
                 if c["profile_id"] == profile_id and c.get("telegram_user_id") == telegram_user_id), None)
    if not chat:
        return {"messages": [], "last_message_id": 0}

    # Get only new messages
    all_messages = [m for m in data["messages"] if m["chat_id"] == chat["id"]]
    new_messages = [m for m in all_messages if m["id"] > last_message_id]
    last_id = all_messages[-1]["id"] if all_messages else 0

    return {
        "messages": new_messages,
        "last_message_id": last_id
    }


@app.post("/api/chats/{profile_id}/messages")
async def send_user_message(profile_id: int, request: Request, telegram_user_id: Optional[str] = None):
    """Отправка сообщения от пользователя"""
    # SECURITY: telegram_user_id is required to prevent message mixing between users
    if not telegram_user_id:
        raise HTTPException(
            status_code=400,
            detail="telegram_user_id is required for message isolation. Please ensure Telegram WebApp is properly initialized."
        )

    data = load_data()

    logger.info(f"📨 User sending message to profile {profile_id}, telegram_user_id: {telegram_user_id}")

    # Находим профиль
    profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Находим или создаем чат для конкретного пользователя и профиля
    # Чат уникален для комбинации (profile_id, telegram_user_id)
    chat = next((c for c in data["chats"]
                 if c["profile_id"] == profile_id and c.get("telegram_user_id") == telegram_user_id), None)
    if not chat:
        chat = {
            "id": len(data["chats"]) + 1,
            "profile_id": profile_id,
            "profile_name": profile["name"],
            "telegram_user_id": telegram_user_id,
            "created_at": datetime.now().isoformat()
        }
        data["chats"].append(chat)

    # Создаем unpaid order, если это первое взаимодействие пользователя с профилем
    if "orders" not in data:
        data["orders"] = []

    # Проверяем, есть ли уже ордера для этого пользователя и профиля
    profile_orders = [o for o in data["orders"]
                      if o.get("profile_id") == profile_id and o.get("telegram_user_id") == telegram_user_id]
    if not profile_orders:
        # Создаем unpaid order
        order = {
            "id": len(data["orders"]) + 1,
            "profile_id": profile_id,
            "telegram_user_id": telegram_user_id,
            "amount": 0,
            "bonus_amount": 0,
            "total_amount": 0,
            "crypto_type": "",
            "currency": "USD",
            "status": "unpaid",
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=1)).isoformat()
        }
        data["orders"].append(order)
        logger.info(f"📝 Created unpaid order #{order['id']} for profile {profile_id}, telegram_user_id: {telegram_user_id}")

    try:
        # Получаем форму с файлами и текстом
        form = await request.form()
        text = form.get("text", "").strip()
        file = form.get("file")

        logger.info(f"📝 Text: '{text}'")
        logger.info(f"📎 File: {file.filename if file and hasattr(file, 'filename') else 'None'}")

        # Обрабатываем файл
        if file and hasattr(file, 'filename') and file.filename:
            file_url, _, _, _ = save_uploaded_file(file)
            if file_url:
                file_type = get_file_type(file.filename)

                message_data = {
                    "id": len(data["messages"]) + 1,
                    "chat_id": chat["id"],
                    "file_url": file_url,
                    "file_type": file_type,
                    "file_name": file.filename,
                    "text": text or "",
                    "is_from_user": True,
                    "created_at": datetime.now().isoformat()
                }
                data["messages"].append(message_data)
                logger.info(f"✅ File message added from user: {file.filename}")
        elif text:
            # Если только текст
            message_data = {
                "id": len(data["messages"]) + 1,
                "chat_id": chat["id"],
                "text": text,
                "is_from_user": True,
                "created_at": datetime.now().isoformat()
            }
            data["messages"].append(message_data)
            logger.info("✅ Text message added from user")
        else:
            raise HTTPException(status_code=400, detail="Text or file is required")

        save_data(data)
        logger.info("💾 Data saved successfully")

        # Отправляем уведомление администратору в Telegram
        try:
            await send_telegram_notification(
                message="Новое сообщение от пользователя",
                profile_id=profile_id,
                profile_name=profile["name"],
                message_text=message_data.get("text", ""),
                file_url=message_data.get("file_url"),
                telegram_user_id=telegram_user_id
            )
        except Exception as e:
            logger.error(f"❌ Failed to send Telegram notification: {e}")

        return {
            "status": "sent",
            "message_id": message_data["id"]
        }

    except Exception as e:
        logger.error(f"❌ Error sending user message: {e}")
        raise HTTPException(status_code=500, detail=f"Error sending message: {str(e)}")


@app.get("/api/user/chats")
async def get_user_chats(telegram_user_id: Optional[str] = None):
    """Получить все чаты пользователя с последним сообщением и количеством непрочитанных"""
    # SECURITY: telegram_user_id is required to prevent users from seeing other users' chats
    if not telegram_user_id:
        raise HTTPException(
            status_code=400,
            detail="telegram_user_id is required. Please ensure Telegram WebApp is properly initialized."
        )

    data = load_data()

    chats_list = []
    # Фильтруем чаты по telegram_user_id
    user_chats = [c for c in data["chats"] if c.get("telegram_user_id") == telegram_user_id]

    for chat in user_chats:
        # Find profile
        profile = next((p for p in data["profiles"] if p["id"] == chat["profile_id"]), None)
        if not profile:
            continue

        # Get messages for this chat
        chat_messages = [m for m in data["messages"] if m["chat_id"] == chat["id"]]

        # Get last message
        last_message = chat_messages[-1] if chat_messages else None

        # Count unread (messages from admin not read by user)
        unread_count = sum(1 for m in chat_messages if not m.get("is_from_user", False))

        chats_list.append({
            "profile_id": chat["profile_id"],
            "profile_name": chat["profile_name"],
            "profile_photo": profile["photos"][0] if profile.get("photos") else None,
            "last_message": last_message.get("text", "") if last_message else None,
            "last_message_time": last_message.get("created_at") if last_message else None,
            "unread_count": unread_count
        })

    # Sort by last message time (most recent first)
    chats_list.sort(key=lambda x: x["last_message_time"] or "", reverse=True)

    return {"chats": chats_list}


@app.get("/api/user/orders")
async def get_user_orders(status: str = "all", telegram_user_id: Optional[str] = None):
    """Получить заказы пользователя (booked/unpaid)"""
    # SECURITY: telegram_user_id is required to prevent users from seeing other users' orders
    if not telegram_user_id:
        raise HTTPException(
            status_code=400,
            detail="telegram_user_id is required. Please ensure Telegram WebApp is properly initialized."
        )

    data = load_data()

    # Фильтруем заказы по telegram_user_id
    user_orders = [o for o in data.get("orders", []) if o.get("telegram_user_id") == telegram_user_id]

    # Filter orders by status
    if status == "booked":
        orders = [o for o in user_orders if o.get("status") == "booked"]
    elif status == "unpaid":
        orders = [o for o in user_orders if o.get("status") == "unpaid"]
    else:
        orders = user_orders

    # Enrich orders with profile data
    enriched_orders = []
    for order in orders:
        profile = next((p for p in data["profiles"] if p["id"] == order.get("profile_id")), None)
        if profile:
            enriched_orders.append({
                "id": order["id"],
                "profile_id": order["profile_id"],
                "profile_name": profile["name"],
                "profile_photo": profile["photos"][0] if profile.get("photos") else None,
                "profile_city": profile.get("city", "Unknown"),
                "amount": order.get("amount", 0),
                "crypto_type": order.get("crypto_type", "USDT"),
                "created_at": order.get("created_at"),
                "expires_at": order.get("expires_at"),
                "status": order.get("status")
            })

    # Sort by creation time (most recent first)
    enriched_orders.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    return {"orders": enriched_orders}


@app.post("/api/admin/chats/{profile_id}/system-message")
async def send_system_message(profile_id: int, message_data: dict, current_user: str = Depends(get_current_user),
                              chat_id: Optional[int] = None):
    """Отправка системного сообщения"""
    data = load_data()

    # Находим профиль для имени
    profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Ищем чат по chat_id или profile_id
    if chat_id:
        chat = next((c for c in data["chats"] if c["id"] == chat_id), None)
    else:
        chat = next((c for c in data["chats"] if c["profile_id"] == profile_id), None)

    if not chat:
        chat = {
            "id": len(data["chats"]) + 1,
            "profile_id": profile_id,
            "profile_name": profile["name"],
            "created_at": datetime.now().isoformat()
        }
        data["chats"].append(chat)

    # Создаем системное сообщение
    system_message = {
        "id": len(data["messages"]) + 1,
        "chat_id": chat["id"],
        "text": message_data["text"],
        "is_system": True,
        "created_at": datetime.now().isoformat()
    }

    data["messages"].append(system_message)

    # Если это сообщение об успешной транзакции, меняем статус платежа на "booked"
    if "transaction successful" in message_data["text"].lower() or "booking has been confirmed" in message_data["text"].lower():
        # Находим pending платеж для этого профиля
        pending_payment = next((p for p in data.get("payments", []) if p["profile_id"] == profile_id and p.get("status") == "pending"), None)
        if pending_payment:
            pending_payment["status"] = "booked"
            pending_payment["confirmed_at"] = datetime.now().isoformat()

    save_data(data)

    return {"status": "sent", "message_id": system_message["id"]}


@app.post("/api/admin/chats/{chat_id}/mark-read")
async def mark_chat_messages_read(chat_id: int, current_user: str = Depends(get_current_user)):
    """Пометить все сообщения в чате как прочитанные"""
    data = load_data()

    # Найти все сообщения от пользователя в этом чате и пометить как прочитанные
    for message in data["messages"]:
        if message["chat_id"] == chat_id and message.get("is_from_user", False):
            message["is_read"] = True

    save_data(data)
    return {"status": "marked_read"}


# Комментарии API для админки
@app.get("/api/admin/comments")
async def get_admin_comments(current_user: str = Depends(get_current_user)):
    data = load_data()
    return {"comments": data.get("comments", [])}


@app.post("/api/admin/comments/add")
async def add_admin_comment(comment_data: dict, current_user: str = Depends(get_current_user)):
    """Добавить комментарий от админа"""
    data = load_data()

    if "comments" not in data:
        data["comments"] = []

    # Создаем новый комментарий с правильной структурой
    new_comment = {
        "id": len(data["comments"]) + 1,
        "profile_id": comment_data.get("profile_id"),
        "user_name": comment_data.get("author_name"),  # Используем user_name для совместимости
        "telegram_username": "",  # Пустое для админских комментариев
        "promo_code": None,
        "telegram_user_id": None,
        "text": comment_data.get("comment"),  # Используем text вместо comment
        "created_at": datetime.now().isoformat()
    }

    data["comments"].append(new_comment)
    save_data(data)

    logger.info(f"Admin {current_user} added comment for profile {comment_data.get('profile_id')}")
    return {"status": "success", "comment_id": new_comment["id"]}


# Промокоды API
@app.get("/api/admin/promocodes")
async def get_admin_promocodes(current_user: str = Depends(get_current_user)):
    data = load_data()
    return {"promocodes": data.get("promocodes", [])}


@app.post("/api/admin/promocodes")
async def create_admin_promocode(promocode: dict, current_user: str = Depends(get_current_user)):
    data = load_data()

    # Проверяем, существует ли уже такой промокод
    existing = next((p for p in data["promocodes"] if p["code"] == promocode["code"].upper()), None)
    if existing:
        raise HTTPException(status_code=400, detail="Promocode already exists")

    new_promocode = {
        "id": len(data["promocodes"]) + 1,
        "code": promocode["code"].upper(),
        "discount": promocode["discount"],
        "is_active": True,
        "used_by": [],
        "created_at": datetime.now().isoformat()
    }

    data["promocodes"].append(new_promocode)
    save_data(data)
    return {"status": "created", "promocode": new_promocode}


@app.post("/api/admin/promocodes/{promocode_id}/toggle")
async def toggle_admin_promocode(promocode_id: int, current_user: str = Depends(get_current_user)):
    data = load_data()
    promocode = next((p for p in data["promocodes"] if p["id"] == promocode_id), None)
    if promocode:
        promocode["is_active"] = not promocode["is_active"]
        save_data(data)
    return {"status": "updated"}


@app.delete("/api/admin/promocodes/{promocode_id}")
async def delete_admin_promocode(promocode_id: int, current_user: str = Depends(get_current_user)):
    data = load_data()
    data["promocodes"] = [p for p in data["promocodes"] if p["id"] != promocode_id]
    save_data(data)
    return {"status": "deleted"}


# Bookings (Orders) API
@app.get("/api/admin/bookings")
async def get_admin_bookings(current_user: str = Depends(get_current_user)):
    """Получить все заказы (bookings)"""
    data = load_data()
    orders = data.get("orders", [])

    # Добавляем информацию о профиле к каждому заказу
    enriched_orders = []
    for order in orders:
        profile = next((p for p in data["profiles"] if p["id"] == order.get("profile_id")), None)
        order_copy = order.copy()
        # Убедимся что order_number есть
        if "order_number" not in order_copy or not order_copy.get("order_number"):
            order_copy["order_number"] = str(order_copy.get("id", ""))
        if profile:
            order_copy["profile_name"] = profile["name"]
            order_copy["profile_photo"] = profile["photos"][0] if profile.get("photos") else None
            order_copy["profile_city"] = profile.get("city", "Unknown")
        else:
            order_copy["profile_name"] = "Unknown"
            order_copy["profile_photo"] = None
            order_copy["profile_city"] = "Unknown"
        enriched_orders.append(order_copy)

    # Сортируем: pending первыми, потом по дате создания (новые первыми)
    enriched_orders.sort(key=lambda x: (
        0 if x.get("status") == "unpaid" else 1,
        -1 * int(datetime.fromisoformat(x.get("created_at", "2000-01-01T00:00:00")).timestamp())
    ))

    return {"orders": enriched_orders}


@app.post("/api/admin/bookings/{order_id}/confirm")
async def confirm_booking_payment(order_id: int, current_user: str = Depends(get_current_user)):
    """Подтвердить оплату заказа"""
    data = load_data()

    # Находим заказ
    order = next((o for o in data.get("orders", []) if o.get("id") == order_id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # Обновляем статус
    order["status"] = "booked"
    order["booked_at"] = datetime.now().isoformat()

    # Отправляем системное сообщение пользователю
    profile_id = order.get("profile_id")
    telegram_user_id = order.get("telegram_user_id")

    if profile_id and telegram_user_id:
        profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
        if profile:
            # Находим или создаем чат для конкретного пользователя
            chat = next((c for c in data["chats"]
                        if c["profile_id"] == profile_id and c.get("telegram_user_id") == telegram_user_id), None)
            if not chat:
                chat = {
                    "id": len(data["chats"]) + 1,
                    "profile_id": profile_id,
                    "telegram_user_id": telegram_user_id,
                    "profile_name": profile["name"],
                    "created_at": datetime.now().isoformat()
                }
                data["chats"].append(chat)

            # Создаем системное сообщение
            system_message = {
                "id": len(data["messages"]) + 1,
                "chat_id": chat["id"],
                "text": "Transaction successful, your booking has been confirmed",
                "is_system": True,
                "created_at": datetime.now().isoformat()
            }
            data["messages"].append(system_message)

    save_data(data)
    return {"status": "confirmed", "order_id": order_id}


# Баннер API
@app.get("/api/admin/banner")
async def get_admin_banner(current_user: str = Depends(get_current_user)):
    data = load_data()
    return data.get("settings", {}).get("banner", {})


@app.post("/api/admin/banner")
async def update_admin_banner(banner: BannerModel, current_user: str = Depends(get_current_user)):
    data = load_data()
    if "settings" not in data:
        data["settings"] = {}
    data["settings"]["banner"] = banner.dict()
    save_data(data)
    return {"status": "updated"}


@app.get("/api/admin/crypto_wallets")
async def get_admin_crypto_wallets(current_user: str = Depends(get_current_user)):
    data = load_data()
    return data.get("settings", {}).get("crypto_wallets", {})


@app.post("/api/admin/crypto_wallets")
async def update_admin_crypto_wallets(wallets: dict, current_user: str = Depends(get_current_user)):
    data = load_data()
    if "settings" not in data:
        data["settings"] = {}
    data["settings"]["crypto_wallets"] = wallets
    save_data(data)
    return {"status": "updated"}


# VIP Профили API
@app.get("/api/admin/vip-profiles")
async def get_admin_vip_profiles(current_user: str = Depends(get_current_user)):
    """Получить все VIP профили"""
    data = load_data()
    return {"profiles": data.get("vip_profiles", [])}


@app.post("/api/admin/vip-profiles")
async def create_vip_profile(
        current_user: str = Depends(get_current_user),
        name: str = Form(...),
        age: int = Form(...),
        city: str = Form(...),
        gender: str = Form("female"),
        photos: list[UploadFile] = File(...)
):
    """Создать новый VIP профиль"""
    data = load_data()

    # Находим максимальный ID
    max_id = max([p["id"] for p in data.get("vip_profiles", [])]) if data.get("vip_profiles") else 0

    # Сохраняем загруженные фото
    photo_urls = []
    for photo in photos:
        if photo.filename:
            photo_url, _, _, _ = save_uploaded_file(photo)
            if photo_url:
                photo_urls.append(photo_url)

    if not photo_urls:
        raise HTTPException(status_code=400, detail="At least one photo is required")

    new_profile = {
        "id": max_id + 1,
        "name": name,
        "age": age,
        "city": city,
        "gender": gender,
        "photos": photo_urls,
        "created_at": datetime.now().isoformat()
    }

    if "vip_profiles" not in data:
        data["vip_profiles"] = []
    data["vip_profiles"].append(new_profile)
    save_data(data)
    return {"status": "created", "profile": new_profile}


@app.delete("/api/admin/vip-profiles/{profile_id}")
async def delete_vip_profile(profile_id: int, current_user: str = Depends(get_current_user)):
    """Удалить VIP профиль"""
    data = load_data()
    data["vip_profiles"] = [p for p in data.get("vip_profiles", []) if p["id"] != profile_id]
    save_data(data)
    return {"status": "deleted"}


# VIP Каталоги API
@app.get("/api/admin/vip-catalogs")
async def get_admin_vip_catalogs(current_user: str = Depends(get_current_user)):
    """Получить настройки VIP каталогов"""
    data = load_data()
    return data.get("settings", {}).get("vip_catalogs", {})


@app.post("/api/admin/vip-catalogs")
async def update_vip_catalogs(catalogs: dict, current_user: str = Depends(get_current_user)):
    """Обновить настройки VIP каталогов"""
    data = load_data()
    if "settings" not in data:
        data["settings"] = {}
    data["settings"]["vip_catalogs"] = catalogs
    save_data(data)
    return {"status": "updated"}


# Удаление комментариев
@app.delete("/api/admin/comments/{profile_id}/{comment_id}")
async def delete_comment(profile_id: int, comment_id: int, current_user: str = Depends(get_current_user)):
    """Удалить комментарий"""
    data = load_data()

    if "comments" not in data:
        raise HTTPException(status_code=404, detail="No comments found")

    # Находим комментарий
    comment_index = next(
        (i for i, c in enumerate(data["comments"]) if c["id"] == comment_id and c["profile_id"] == profile_id), None)

    if comment_index is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Удаляем комментарий
    deleted_comment = data["comments"].pop(comment_index)
    save_data(data)

    return {"status": "deleted", "comment": deleted_comment}


# ==================== PAYMENTS API ====================
# API для работы с payments (платежами) - дополнительно к orders (заказам)

@app.get("/api/admin/payments")
async def api_admin_payments(current_user: str = Depends(get_current_user)):
    """Получить список всех платежей (enriched с информацией о профиле)"""
    data = load_data()
    payments = data.get("payments", [])

    # Добавляем имя профиля для удобства
    profiles = {p.get("id"): p for p in data.get("profiles", [])}
    enriched = []
    for p in payments:
        pr = profiles.get(p.get("profile_id"))
        enriched.append({
            "id": p.get("id"),
            "order_number": p.get("order_number"),
            "profile_id": p.get("profile_id"),
            "profile_name": pr.get("name") if pr else None,
            "profile_photo": pr.get("photos", [None])[0] if pr and pr.get("photos") else None,
            "amount": p.get("amount"),
            "currency": p.get("currency"),
            "wallet": p.get("wallet"),
            "status": p.get("status"),
            "created_at": p.get("created_at"),
            "confirmed_at": p.get("confirmed_at", None)
        })

    # Сортируем: pending первыми, потом по дате (новые первыми)
    enriched.sort(key=lambda x: (
        0 if x.get("status") == "pending" else 1,
        -(datetime.fromisoformat(x.get("created_at", "2000-01-01T00:00:00")).timestamp() if x.get("created_at") else 0)
    ))
    return {"payments": enriched}


@app.post("/api/admin/payments/{payment_id}/confirm")
async def api_confirm_payment(payment_id: str, current_user: str = Depends(get_current_user)):
    """
    Подтвердить платеж: переводит статус из 'pending' в 'booked'.
    Также создает соответствующий order в массиве orders.
    """
    data = load_data()
    payments = data.get("payments", [])

    # Найдём платеж по id (строковый/числовой)
    target = None
    for p in payments:
        if str(p.get("id")) == str(payment_id) or str(p.get("order_number")) == str(payment_id):
            target = p
            break

    if not target:
        raise HTTPException(status_code=404, detail="Payment not found")

    if target.get("status") == "booked":
        return {"detail": "Already booked", "payment": target}

    # Меняем статус
    target["status"] = "booked"
    target["confirmed_at"] = datetime.now().isoformat()

    # Генерируем order_number если его нет
    if "order_number" not in target or target.get("order_number") in (None, ""):
        existing_numbers = []
        for p in payments:
            on = p.get("order_number")
            if isinstance(on, int):
                existing_numbers.append(on)
            elif isinstance(on, str) and on.isdigit():
                existing_numbers.append(int(on))
        next_num = (max(existing_numbers) + 1) if existing_numbers else 1
        target["order_number"] = next_num

    # Создаём order объект и добавляем в orders если его там нет
    if "orders" not in data:
        data["orders"] = []

    order_obj = {
        "id": target.get("id"),
        "order_number": target.get("order_number"),
        "profile_id": target.get("profile_id"),
        "amount": target.get("amount"),
        "total_amount": target.get("amount"),  # Для совместимости с frontend
        "currency": target.get("currency"),
        "crypto_type": target.get("wallet"),  # wallet -> crypto_type для совместимости
        "status": "booked",
        "created_at": target.get("created_at"),
        "booked_at": target.get("confirmed_at"),
        "confirmed_at": target.get("confirmed_at")
    }

    # Избегаем дубликатов
    existing_order = next(
        (o for o in data.get("orders", []) if str(o.get("id")) == str(order_obj["id"])),
        None
    )
    if not existing_order:
        data["orders"].append(order_obj)
    else:
        # Обновляем существующий order
        existing_order["status"] = "booked"
        existing_order["booked_at"] = target.get("confirmed_at")
        existing_order["confirmed_at"] = target.get("confirmed_at")

    # Отправляем системное сообщение в чат
    profile_id = target.get("profile_id")
    if profile_id:
        profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
        if profile:
            # Находим или создаем чат
            chat = next((c for c in data["chats"] if c["profile_id"] == profile_id), None)
            if not chat:
                chat = {
                    "id": len(data["chats"]) + 1,
                    "profile_id": profile_id,
                    "profile_name": profile["name"],
                    "created_at": datetime.now().isoformat()
                }
                data["chats"].append(chat)

            # Создаем системное сообщение
            system_message = {
                "id": len(data["messages"]) + 1,
                "chat_id": chat["id"],
                "text": "Transaction successful, your booking has been confirmed",
                "is_system": True,
                "created_at": datetime.now().isoformat()
            }
            data["messages"].append(system_message)

    save_data(data)
    logger.info(f"Admin {current_user} confirmed payment {payment_id}")

    return {"detail": "confirmed", "payment": target}


@app.post("/api/admin/notify_transaction")
async def api_notify_transaction(request: Request):
    """
    Автоматическая обработка подтверждения транзакции.
    Вызывается когда система получает текст подтверждения.
    Если текст содержит ключевые слова, находит последний pending payment и подтверждает его.
    """
    body = await request.json()
    text = body.get("text", "")
    profile_id = body.get("profile_id")

    data = load_data()
    t = text.lower()

    keywords = [
        "transaction successful",
        "booking has been confirmed",
        "transaction успешный",
        "оплата подтверждена",
        "транзакция успешна",
        "payment confirmed"
    ]

    if any(k in t for k in keywords):
        payments = data.get("payments", [])
        pending = None

        if profile_id is not None:
            # Ищем последний pending платёж для профиля
            pending_list = [p for p in payments if p.get("profile_id") == profile_id and p.get("status") == "pending"]
            pending_list.sort(key=lambda x: x.get("created_at") or "", reverse=True)
            pending = pending_list[0] if pending_list else None
        else:
            pending = next((p for p in payments if p.get("status") == "pending"), None)

        if pending:
            pending["status"] = "booked"
            pending["confirmed_at"] = datetime.now().isoformat()

            # Генерируем order_number если нет
            if "order_number" not in pending or pending.get("order_number") in (None, ""):
                existing_numbers = []
                for p in payments:
                    on = p.get("order_number")
                    if isinstance(on, int):
                        existing_numbers.append(on)
                    elif isinstance(on, str) and on.isdigit():
                        existing_numbers.append(int(on))
                next_num = (max(existing_numbers) + 1) if existing_numbers else 1
                pending["order_number"] = next_num

            # Добавляем в orders
            if "orders" not in data:
                data["orders"] = []

            order_obj = {
                "id": pending.get("id"),
                "order_number": pending.get("order_number"),
                "profile_id": pending.get("profile_id"),
                "amount": pending.get("amount"),
                "total_amount": pending.get("amount"),
                "currency": pending.get("currency"),
                "crypto_type": pending.get("wallet"),
                "status": "booked",
                "created_at": pending.get("created_at"),
                "booked_at": pending.get("confirmed_at"),
                "confirmed_at": pending.get("confirmed_at")
            }

            # Избегаем дублей
            exists = next(
                (o for o in data["orders"] if str(o.get("id")) == str(order_obj["id"])),
                None
            )
            if not exists:
                data["orders"].append(order_obj)
            else:
                exists["status"] = "booked"
                exists["booked_at"] = pending.get("confirmed_at")

            save_data(data)
            logger.info(f"Auto-confirmed pending payment id={pending.get('id')} for profile {pending.get('profile_id')}")
            return {"detail": "auto confirmed", "payment": pending}
        else:
            return {"detail": "no pending payment found"}

    return {"detail": "text did not match confirmation keywords", "text": text}


@app.get("/api/admin/orders_list")
async def api_admin_orders_list(current_user: str = Depends(get_current_user)):
    """Получить список всех orders (альтернативный endpoint)"""
    data = load_data()
    orders = data.get("orders", [])

    # Enrich with profile name
    profiles = {p.get("id"): p for p in data.get("profiles", [])}
    enriched = []
    for o in orders:
        pr = profiles.get(o.get("profile_id"))
        enriched.append({
            "id": o.get("id"),
            "order_number": o.get("order_number"),
            "profile_id": o.get("profile_id"),
            "profile_name": pr.get("name") if pr else None,
            "profile_photo": pr.get("photos", [None])[0] if pr and pr.get("photos") else None,
            "amount": o.get("amount"),
            "total_amount": o.get("total_amount", o.get("amount")),
            "currency": o.get("currency"),
            "crypto_type": o.get("crypto_type"),
            "status": o.get("status"),
            "created_at": o.get("created_at"),
            "booked_at": o.get("booked_at"),
            "confirmed_at": o.get("confirmed_at")
        })

    # Сортируем: unpaid первыми, потом по дате
    enriched.sort(key=lambda x: (
        0 if x.get("status") == "unpaid" else 1,
        -(datetime.fromisoformat(x.get("created_at", "2000-01-01T00:00:00")).timestamp() if x.get("created_at") else 0)
    ))
    return {"orders": enriched}


# ============= FILE MANAGEMENT API (TELEGRAM USERS) =============

@app.post("/api/user/files/upload")
async def upload_user_file(
    file: UploadFile = File(...),
    user: dict = Depends(get_telegram_user)
):
    """
    Upload file for authenticated Telegram user
    Files are stored in user-specific directories with ownership tracking
    """
    try:
        telegram_user_id = user["telegram_id"]
        user_id = user["id"]

        # Save file to user-specific directory
        file_url, file_path, file_size, mime_type = save_uploaded_file(
            file,
            telegram_user_id=telegram_user_id
        )

        # Add file to database
        file_id = db.add_file(
            user_id=user_id,
            telegram_user_id=telegram_user_id,
            filename=os.path.basename(file_path),
            original_filename=file.filename,
            file_path=file_path,
            file_size=file_size,
            mime_type=mime_type
        )

        logger.info(f"✅ File uploaded: {file.filename} by user {telegram_user_id}")

        return {
            "status": "success",
            "file": {
                "id": file_id,
                "filename": os.path.basename(file_path),
                "original_filename": file.filename,
                "file_url": file_url,
                "file_size": file_size,
                "mime_type": mime_type
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ File upload error: {e}")
        raise HTTPException(status_code=500, detail="File upload failed")


@app.get("/api/user/files")
async def get_user_files(user: dict = Depends(get_telegram_user)):
    """
    Get all files for authenticated Telegram user
    Only returns files owned by the current user
    """
    try:
        telegram_user_id = user["telegram_id"]

        files = db.get_user_files(telegram_user_id)

        return {
            "status": "success",
            "files": files,
            "count": len(files)
        }

    except Exception as e:
        logger.error(f"❌ Error fetching user files: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch files")


@app.delete("/api/user/files/{file_id}")
async def delete_user_file(file_id: int, user: dict = Depends(get_telegram_user)):
    """
    Delete file with ownership verification
    Only allows deletion of files owned by current user
    """
    try:
        telegram_user_id = user["telegram_id"]

        # Attempt to delete file (includes ownership check)
        success = db.delete_file(file_id, telegram_user_id)

        if not success:
            raise HTTPException(
                status_code=404,
                detail="File not found or you don't have permission to delete it"
            )

        logger.info(f"✅ File {file_id} deleted by user {telegram_user_id}")

        return {
            "status": "success",
            "message": "File deleted successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ File deletion error: {e}")
        raise HTTPException(status_code=500, detail="File deletion failed")


@app.get("/api/user/files/{file_id}/download")
async def download_user_file(file_id: int, user: dict = Depends(get_telegram_user)):
    """
    Download file with ownership verification
    Returns file only if it belongs to current user
    """
    try:
        telegram_user_id = user["telegram_id"]

        # Get file with ownership check
        file_data = db.get_file_by_id(file_id, telegram_user_id)

        if not file_data:
            raise HTTPException(
                status_code=404,
                detail="File not found or you don't have permission to access it"
            )

        file_path = file_data["file_path"]

        if not os.path.exists(file_path):
            logger.error(f"❌ File not found on disk: {file_path}")
            raise HTTPException(status_code=404, detail="File not found on server")

        from fastapi.responses import FileResponse
        return FileResponse(
            path=file_path,
            filename=file_data["original_filename"],
            media_type=file_data["mime_type"]
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ File download error: {e}")
        raise HTTPException(status_code=500, detail="File download failed")


@app.get("/api/user/storage/stats")
async def get_user_storage_stats(user: dict = Depends(get_telegram_user)):
    """Get storage statistics for current user"""
    try:
        telegram_user_id = user["telegram_id"]
        stats = db.get_user_storage_stats(telegram_user_id)

        return {
            "status": "success",
            "stats": stats
        }

    except Exception as e:
        logger.error(f"❌ Error fetching storage stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch storage stats")


@app.get("/api/user/profile")
async def get_user_profile(user: dict = Depends(get_telegram_user)):
    """Get current user profile information"""
    return {
        "status": "success",
        "user": {
            "id": user["id"],
            "telegram_id": user["telegram_id"],
            "first_name": user["first_name"],
            "last_name": user["last_name"],
            "username": user.get("username"),
            "language_code": user.get("language_code", "en"),
            "is_premium": user.get("is_premium", False)
        }
    }


@app.post("/api/telegram/logout")
async def telegram_logout(request: Request, response: Response):
    """Logout Telegram user and destroy session"""
    try:
        session_id = request.cookies.get("telegram_session")

        if session_id:
            destroy_telegram_session(session_id)
            response.delete_cookie("telegram_session")
            logger.info(f"✅ Telegram user logged out")

        return {"status": "success", "message": "Logged out successfully"}

    except Exception as e:
        logger.error(f"❌ Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")


if __name__ == "__main__":
    print("🚀 Admin panel Muji запущена: http://localhost:8002")
    print("🔑 Логин: admin | Пароль: admin123")
    print("✅ Админ-панель с полным функционалом готова к работе!")
    uvicorn.run(app, host="0.0.0.0", port=8002, access_log=False)

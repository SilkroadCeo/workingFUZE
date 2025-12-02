# 🔐 Telegram WebApp Authentication Guide

Полное руководство по реализации привязки аккаунта Telegram для вашего Mini App (как в TON Dating).

## 🔍 Где реализовано?

Telegram WebApp аутентификация доступна в **обоих** приложениях:

### 1. **`backend/main`** - Основное пользовательское приложение
- Порт: **8001**
- Хранение: In-memory sessions (без базы данных)
- Использование: Для пользовательского Mini App интерфейса
- Легковесное решение для быстрого развертывания

### 2. **`backend/admin.py`** - Административная панель
- Порт: **8002**
- Хранение: SQLite база данных через `database.py`
- Использование: Для административной панели с persistent storage
- Полная интеграция с системой управления пользователями и файлами

**Оба приложения используют идентичные API endpoints и методы верификации.**

## 📋 Содержание

1. [Основная идея](#основная-идея)
2. [Архитектура решения](#архитектура-решения)
3. [Бэкенд (FastAPI)](#бэкенд-fastapi)
4. [Фронтенд (Mini App)](#фронтенд-mini-app)
5. [Безопасность](#безопасность)
6. [API Endpoints](#api-endpoints)
7. [Примеры использования](#примеры-использования)

---

## Основная идея

Механизм основан на функции `Telegram.WebApp.initData`. При запуске Mini App Telegram передает специальные данные, которые содержат:
- Информацию о пользователе (ID, имя, username, язык и т.д.)
- Временную метку (auth_date)
- HMAC-SHA256 подпись для проверки подлинности

Ваша задача — верифицировать эти данные на бэкенде, используя секретный ключ, полученный из токена вашего бота.

---

## Архитектура решения

```
┌─────────────────┐      1. Open Mini App       ┌──────────────────┐
│  Telegram User  │ ──────────────────────────> │  Telegram Server │
└─────────────────┘                             └──────────────────┘
         │                                               │
         │                                               │ 2. Generate initData
         │                                               │    with HMAC signature
         │                                               ▼
         │                                       ┌──────────────────┐
         │  3. Receive initData                  │   Your Mini App  │
         │ <─────────────────────────────────────│   (Frontend)     │
         │                                       └──────────────────┘
         │                                               │
         │                                               │ 4. Send initData
         │                                               │    to backend
         │                                               ▼
         │                                       ┌──────────────────┐
         │  6. Session cookie                    │   Your Backend   │
         │ <─────────────────────────────────────│   (FastAPI)      │
         │                                       └──────────────────┘
         │                                               │
         │                                               │ 5. Verify HMAC
         │                                               │    Create user in DB
         │                                               │    Create session
         │                                               ▼
         │                                       ┌──────────────────┐
         │                                       │    Database      │
         │                                       └──────────────────┘
```

---

## Бэкенд (FastAPI)

### 1. Функция верификации

Улучшенная функция с проверкой свежести данных:

```python
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
            return False

        # Формируем строку для проверки
        data_check_arr = []
        for key, value in sorted(parsed_data.items()):
            if key != 'hash':
                data_check_arr.append(f"{key}={value[0]}")

        data_check_string = '\n'.join(data_check_arr)

        # Вычисляем HMAC-SHA256 согласно официальной документации Telegram
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
            return False

        # Проверка свежести данных (защита от повторных атак)
        auth_date = parsed_data.get('auth_date', ['0'])[0]
        auth_timestamp = int(auth_date)
        current_timestamp = int(datetime.now().timestamp())

        if current_timestamp - auth_timestamp > max_age_seconds:
            return False

        return True
    except Exception as e:
        logger.error(f"Telegram auth verification error: {e}")
        return False
```

### 2. Endpoint для авторизации

```python
@app.post("/api/telegram/auth")
async def telegram_auth(request: Request, response: Response):
    """
    Telegram Web App Authentication with HMAC verification
    Creates or updates user in database and establishes session
    """
    body = await request.json()
    init_data = body.get("initData")

    if not init_data:
        raise HTTPException(status_code=400, detail="Missing initData")

    # SECURITY: Verify Telegram data authenticity
    if not verify_telegram_auth(init_data):
        raise HTTPException(status_code=401, detail="Invalid Telegram authentication")

    # Parse user data from Telegram
    parsed_data = parse_qs(init_data)
    user_json = parsed_data.get('user', ['{}'])[0]
    user_data = json.loads(user_json)

    telegram_id = user_data.get('id')
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

    # Create session
    session_user_data = {
        "id": db_user["id"],
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
```

### 3. Dependency для защиты endpoints

```python
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
```

### 4. Использование в защищенных endpoints

```python
@app.get("/api/user/profile")
async def get_user_profile(user: dict = Depends(get_telegram_user)):
    """
    Get current user profile
    Requires Telegram authentication
    """
    return {
        "status": "success",
        "user": user
    }

@app.get("/api/user/files")
async def get_user_files(user: dict = Depends(get_telegram_user)):
    """
    Get files for current user
    Files are automatically filtered by telegram_user_id
    """
    files = db.get_user_files(user["telegram_id"])
    return {
        "status": "success",
        "files": files
    }
```

---

## Фронтенд (Mini App)

### 1. Подключение Telegram WebApp SDK

```html
<!DOCTYPE html>
<html>
<head>
    <script src="https://telegram.org/js/telegram-web-app.js"></script>
</head>
<body>
    <script>
        // Инициализация Telegram WebApp
        const tg = window.Telegram.WebApp;
        tg.expand();
        tg.ready();
    </script>
</body>
</html>
```

### 2. Функция авторизации

```javascript
async function authenticateWithTelegram() {
    const initData = Telegram.WebApp.initData;

    if (!initData) {
        console.error('initData не доступен');
        return;
    }

    try {
        const response = await fetch('/api/telegram/auth', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                initData: initData
            }),
            credentials: 'include'  // Важно для cookies
        });

        const data = await response.json();

        if (response.ok && data.status === 'success') {
            console.log('Авторизация успешна!', data.user);
            // Обновить UI, показать приветствие и т.д.
            showWelcomeMessage(data.user);
        } else {
            console.error('Ошибка авторизации:', data.detail);
        }
    } catch (error) {
        console.error('Network error:', error);
    }
}
```

### 3. Проверка текущего пользователя

```javascript
async function checkCurrentUser() {
    try {
        const response = await fetch('/api/telegram/me', {
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            if (data.status === 'success') {
                return data.user;
            }
        }
        return null;
    } catch (error) {
        console.error('Check user error:', error);
        return null;
    }
}
```

### 4. Автоматическая авторизация при запуске

```javascript
// При загрузке приложения
window.addEventListener('DOMContentLoaded', async () => {
    // Сначала проверяем существующую сессию
    const currentUser = await checkCurrentUser();

    if (currentUser) {
        // Пользователь уже авторизован
        showMainApp(currentUser);
    } else {
        // Авторизуем автоматически
        await authenticateWithTelegram();
    }
});
```

### 5. Работа с защищенными API

```javascript
async function getUserFiles() {
    try {
        const response = await fetch('/api/user/files', {
            credentials: 'include'  // Отправляем cookies с сессией
        });

        if (response.ok) {
            const data = await response.json();
            return data.files;
        } else if (response.status === 401) {
            // Не авторизован - перенаправляем на авторизацию
            await authenticateWithTelegram();
        }
    } catch (error) {
        console.error('Error fetching files:', error);
    }
}
```

---

## Безопасность

### ✅ Реализованные меры безопасности:

1. **HMAC-SHA256 верификация**
   - Проверка подлинности данных от Telegram
   - Использование `hmac.compare_digest()` для защиты от timing attacks

2. **Проверка свежести данных (auth_date)**
   - По умолчанию данные действительны 24 часа
   - Защита от replay атак

3. **Secure Session Cookies**
   - `httponly=True` - защита от XSS атак
   - `secure=True` - только HTTPS (в production)
   - `samesite="lax"` - защита от CSRF

4. **Изоляция данных пользователей**
   - Файлы фильтруются по `telegram_user_id`
   - Dependency injection для автоматической проверки прав

### 🔒 Best Practices:

1. **Никогда не доверяйте данным на фронтенде**
   - Всегда проверяйте HMAC на бэкенде
   - Не используйте `initDataUnsafe` для критических операций

2. **Храните токен бота в безопасности**
   ```bash
   # .env файл (НЕ коммитить в git!)
   TELEGRAM_BOT_TOKEN=your_bot_token_here
   ```

3. **Используйте HTTPS в production**
   - Обязательно для защиты cookies и данных

4. **Логируйте попытки авторизации**
   - Мониторинг подозрительной активности
   - Анализ неудачных попыток входа

---

## API Endpoints

### POST /api/telegram/auth
Авторизация пользователя через Telegram WebApp

**Request:**
```json
{
  "initData": "query_id=...&user=%7B...%7D&auth_date=...&hash=..."
}
```

**Response (200 OK):**
```json
{
  "status": "success",
  "user": {
    "id": 123,
    "telegram_id": 279058397,
    "first_name": "John",
    "last_name": "Doe",
    "username": "johndoe",
    "language_code": "en",
    "is_premium": false
  }
}
```

**Errors:**
- `400` - Missing initData
- `401` - Invalid Telegram authentication (неверный HMAC или устаревшие данные)

---

### GET /api/telegram/me
Получить информацию о текущем авторизованном пользователе

**Response (200 OK):**
```json
{
  "status": "success",
  "user": {
    "id": 123,
    "telegram_id": 279058397,
    "first_name": "John",
    "last_name": "Doe",
    "username": "johndoe",
    "language_code": "en",
    "is_premium": false
  }
}
```

**Errors:**
- `401` - Not authenticated

---

### POST /api/telegram/logout
Выход из системы (уничтожение сессии)

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "Logged out successfully"
}
```

---

## Примеры использования

### Пример 1: Простая авторизация при запуске

```html
<!DOCTYPE html>
<html>
<head>
    <script src="https://telegram.org/js/telegram-web-app.js"></script>
</head>
<body>
    <div id="app">Загрузка...</div>

    <script>
        const tg = window.Telegram.WebApp;
        tg.ready();

        async function init() {
            try {
                // Отправляем initData на бэкенд
                const response = await fetch('/api/telegram/auth', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ initData: tg.initData }),
                    credentials: 'include'
                });

                const data = await response.json();

                if (data.status === 'success') {
                    document.getElementById('app').innerHTML =
                        `<h1>Привет, ${data.user.first_name}!</h1>`;
                }
            } catch (error) {
                console.error('Auth error:', error);
            }
        }

        init();
    </script>
</body>
</html>
```

### Пример 2: Deep Linking для реферальной системы

```javascript
// Получить startapp параметр из URL
const startParam = Telegram.WebApp.initDataUnsafe.start_param;

if (startParam && startParam.startsWith('ref_')) {
    const referrerId = startParam.replace('ref_', '');
    // Сохранить реферера в базе данных
    await saveReferral(referrerId);
}

// Создать реферальную ссылку
function createReferralLink(userId) {
    return `https://t.me/your_bot_name?startapp=ref_${userId}`;
}

// Поделиться ссылкой
function shareProfile(userId) {
    const url = createReferralLink(userId);
    Telegram.WebApp.openTelegramLink(`https://t.me/share/url?url=${encodeURIComponent(url)}`);
}
```

### Пример 3: Отображение профиля

```javascript
async function loadUserProfile() {
    try {
        const response = await fetch('/api/telegram/me', {
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            const user = data.user;

            document.getElementById('profile').innerHTML = `
                <div class="profile-card">
                    <h2>${user.first_name} ${user.last_name}</h2>
                    <p>@${user.username || 'нет username'}</p>
                    <p>ID: ${user.telegram_id}</p>
                    ${user.is_premium ? '<span class="badge">⭐️ Premium</span>' : ''}
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading profile:', error);
    }
}
```

---

## Тестирование

### 1. Локальное тестирование через ngrok

```bash
# Запустите бэкенд
cd backend
python admin.py

# В другом терминале запустите ngrok
./ngrok http 8002

# Настройте ваш Mini App в @BotFather с URL от ngrok
```

### 2. Проверка initData

Откройте консоль браузера в вашем Mini App:
```javascript
console.log('initData:', Telegram.WebApp.initData);
console.log('User:', Telegram.WebApp.initDataUnsafe.user);
```

### 3. Тестирование API endpoints

```bash
# Тест авторизации (замените INIT_DATA на реальные данные)
curl -X POST http://localhost:8002/api/telegram/auth \
  -H "Content-Type: application/json" \
  -d '{"initData": "INIT_DATA_HERE"}' \
  -c cookies.txt

# Тест получения профиля
curl http://localhost:8002/api/telegram/me \
  -b cookies.txt
```

---

## Часто задаваемые вопросы (FAQ)

### Q: Как получить фото профиля пользователя?
A: Telegram WebApp не предоставляет фото напрямую. Используйте Telegram Bot API:
```python
from telegram import Bot

bot = Bot(token=TELEGRAM_BOT_TOKEN)
photos = await bot.get_user_profile_photos(user_id=telegram_id)
```

### Q: Можно ли использовать JWT вместо cookies?
A: Да, можно вернуть JWT токен вместо установки cookie:
```python
# В endpoint /api/telegram/auth
token = create_jwt_token(user_data)
return {"status": "success", "token": token, "user": user_data}
```

### Q: Что делать, если initData пустой?
A: initData будет пустым, если приложение открыто не через Telegram. Для разработки можно добавить mock данные, но в production показывайте ошибку.

### Q: Как обновить данные пользователя?
A: Данные обновляются автоматически при каждой авторизации в функции `get_or_create_user()`.

---

## Дополнительные ресурсы

- [Telegram WebApp Documentation](https://core.telegram.org/bots/webapps)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)

---

## Поддержка

Если у вас возникли вопросы или проблемы:
1. Проверьте логи бэкенда
2. Убедитесь, что `TELEGRAM_BOT_TOKEN` правильно настроен
3. Проверьте, что Mini App открывается через Telegram
4. Используйте пример `frontend/telegram-auth-example.html` для отладки

---

**Создано для проекта FESGR** | *Последнее обновление: 2025-11-26*

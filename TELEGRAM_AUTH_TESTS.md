# 🧪 Telegram WebApp Authentication Tests

Примеры тестирования Telegram аутентификации с помощью curl и HTTP клиентов.

## 📋 Содержание

1. [Setup](#setup)
2. [Test 1: Unauthenticated Request](#test-1-unauthenticated-request-should-be-rejected)
3. [Test 2: Invalid initData](#test-2-invalid-initdata-should-be-rejected)
4. [Test 3: Valid Authentication](#test-3-valid-authentication)
5. [Test 4: Get Current User](#test-4-get-current-user)
6. [Test 5: Logout](#test-5-logout)
7. [Test 6: User Isolation](#test-6-user-isolation)

---

## Setup

### Environment Variables

Создайте файл `backend/.env`:

```env
# Required
TELEGRAM_BOT_TOKEN=your_bot_token_from_botfather

# Optional (defaults shown)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8001
```

### Start Server

```bash
cd backend
python main  # Starts on port 8001
```

---

## Test 1: Unauthenticated Request (should be rejected)

Попытка доступа к защищенному endpoint без аутентификации:

```bash
curl -v http://localhost:8001/api/telegram/me
```

**Expected Response:**
```json
HTTP/1.1 401 Unauthorized
{
  "detail": "Telegram authentication required"
}
```

✅ **Pass**: Запрос отклонен с 401 статусом

---

## Test 2: Invalid initData (should be rejected)

Попытка авторизации с поддельными данными:

```bash
curl -X POST http://localhost:8001/api/telegram/auth \
  -H "Content-Type: application/json" \
  -d '{
    "initData": "user=%7B%22id%22%3A12345%7D&hash=fakehash123"
  }' \
  -v
```

**Expected Response:**
```json
HTTP/1.1 401 Unauthorized
{
  "detail": "Invalid Telegram authentication"
}
```

✅ **Pass**: HMAC верификация отклонила поддельные данные

---

## Test 3: Valid Authentication

### Получение Real initData

Для получения настоящих initData нужно открыть Mini App через Telegram:

1. Откройте браузер в Telegram Mini App
2. В консоли выполните:
   ```javascript
   console.log(window.Telegram.WebApp.initData);
   ```
3. Скопируйте полученную строку

Или используйте пример `frontend/telegram-auth-example.html`.

### Аутентификация

```bash
# Замените INIT_DATA_HERE на реальные данные от Telegram
curl -X POST http://localhost:8001/api/telegram/auth \
  -H "Content-Type: application/json" \
  -d '{
    "initData": "INIT_DATA_HERE"
  }' \
  -c cookies.txt \
  -v
```

**Expected Response:**
```json
HTTP/1.1 200 OK
Set-Cookie: telegram_session=<uuid>; HttpOnly; Max-Age=2592000; Path=/; SameSite=lax

{
  "status": "success",
  "user": {
    "telegram_id": 123456789,
    "first_name": "John",
    "last_name": "Doe",
    "username": "johndoe",
    "language_code": "en",
    "is_premium": false
  }
}
```

✅ **Pass**:
- 200 OK статус
- Session cookie установлен (HttpOnly, SameSite=lax)
- Возвращены данные пользователя

---

## Test 4: Get Current User

Проверка текущей сессии (используем cookies из предыдущего теста):

```bash
curl http://localhost:8001/api/telegram/me \
  -b cookies.txt \
  -v
```

**Expected Response:**
```json
HTTP/1.1 200 OK

{
  "status": "success",
  "user": {
    "telegram_id": 123456789,
    "first_name": "John",
    "last_name": "Doe",
    "username": "johndoe",
    "language_code": "en",
    "is_premium": false
  }
}
```

✅ **Pass**: Сессия валидна, данные пользователя возвращены

---

## Test 5: Logout

Выход из системы:

```bash
curl -X POST http://localhost:8001/api/telegram/logout \
  -b cookies.txt \
  -c cookies_after_logout.txt \
  -v
```

**Expected Response:**
```json
HTTP/1.1 200 OK
Set-Cookie: telegram_session=; Max-Age=0

{
  "status": "success",
  "message": "Logged out successfully"
}
```

Проверка что сессия уничтожена:

```bash
curl http://localhost:8001/api/telegram/me \
  -b cookies_after_logout.txt \
  -v
```

**Expected Response:**
```json
HTTP/1.1 401 Unauthorized
{
  "detail": "Telegram authentication required"
}
```

✅ **Pass**: Сессия уничтожена, доступ запрещен

---

## Test 6: User Isolation

Проверка изоляции данных между пользователями.

### Setup: Create Two User Sessions

**User A:**
```bash
# Получите initData для User A через Telegram
curl -X POST http://localhost:8001/api/telegram/auth \
  -H "Content-Type: application/json" \
  -d '{"initData": "USER_A_INIT_DATA"}' \
  -c cookies_user_a.txt
```

**User B:**
```bash
# Получите initData для User B через Telegram
curl -X POST http://localhost:8001/api/telegram/auth \
  -H "Content-Type: application/json" \
  -d '{"initData": "USER_B_INIT_DATA"}' \
  -c cookies_user_b.txt
```

### Test: Verify Data Isolation

**Note:** В текущей версии `backend/main` endpoints для chats и orders **не реализуют** изоляцию пользователей. Это известная проблема, которая будет исправлена.

Для полной изоляции используйте `backend/admin.py` (порт 8002) с интеграцией базы данных:

```bash
# User A - получить свои файлы
curl http://localhost:8002/api/user/files \
  -b cookies_user_a.txt

# User B - получить свои файлы
curl http://localhost:8002/api/user/files \
  -b cookies_user_b.txt
```

**Expected Behavior:**
- User A видит только свои файлы
- User B видит только свои файлы
- Пересечений нет

✅ **Pass**: Данные изолированы по telegram_user_id

---

## 🔐 Security Verification Checklist

### ✅ HMAC-SHA256 Verification
```bash
# Test с измененным hash
curl -X POST http://localhost:8001/api/telegram/auth \
  -H "Content-Type: application/json" \
  -d '{
    "initData": "user=%7B%22id%22%3A123%7D&auth_date=1234567890&hash=wronghash"
  }'

# Expected: 401 Unauthorized
```

### ✅ auth_date Validation
```bash
# Test с устаревшими данными (> 24 часа)
curl -X POST http://localhost:8001/api/telegram/auth \
  -H "Content-Type: application/json" \
  -d '{
    "initData": "user=%7B%22id%22%3A123%7D&auth_date=1000000000&hash=..."
  }'

# Expected: 401 Unauthorized ("auth data too old")
```

### ✅ Cookie Security
```bash
# Проверка что cookie HttpOnly
curl -X POST http://localhost:8001/api/telegram/auth \
  -d '{"initData": "VALID_INIT_DATA"}' \
  -v | grep "Set-Cookie"

# Expected: HttpOnly flag present
# Expected: SameSite=lax
# Expected: Max-Age=2592000 (30 days)
```

### ✅ Session Validity
```bash
# Test с невалидным session ID
curl http://localhost:8001/api/telegram/me \
  -H "Cookie: telegram_session=invalid-uuid-here"

# Expected: 401 Unauthorized
```

---

## 🚀 Automated Test Script

Создайте файл `test_auth.sh`:

```bash
#!/bin/bash

BASE_URL="http://localhost:8001"
COOKIES="test_cookies.txt"

echo "🧪 Running Telegram Auth Tests..."

# Test 1: Unauthenticated access
echo "\n[Test 1] Unauthenticated request..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/api/telegram/me)
if [ "$STATUS" = "401" ]; then
    echo "✅ PASS: Unauthenticated request rejected"
else
    echo "❌ FAIL: Expected 401, got $STATUS"
fi

# Test 2: Invalid initData
echo "\n[Test 2] Invalid initData..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST $BASE_URL/api/telegram/auth \
    -H "Content-Type: application/json" \
    -d '{"initData":"user=%7B%22id%22%3A123%7D&hash=fake"}')
if [ "$STATUS" = "401" ]; then
    echo "✅ PASS: Invalid initData rejected"
else
    echo "❌ FAIL: Expected 401, got $STATUS"
fi

# Test 3: Missing initData
echo "\n[Test 3] Missing initData..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST $BASE_URL/api/telegram/auth \
    -H "Content-Type: application/json" \
    -d '{}')
if [ "$STATUS" = "400" ]; then
    echo "✅ PASS: Missing initData rejected with 400"
else
    echo "❌ FAIL: Expected 400, got $STATUS"
fi

echo "\n✨ Tests complete!"
```

Запуск:
```bash
chmod +x test_auth.sh
./test_auth.sh
```

---

## 📝 Manual Testing with Telegram

### 1. Setup Bot
1. Создайте бота через @BotFather
2. Получите Bot Token
3. Добавьте в `.env`: `TELEGRAM_BOT_TOKEN=your_token`

### 2. Create Mini App
1. Отправьте `/newapp` в @BotFather
2. Выберите своего бота
3. Введите название и description
4. URL: `https://your-ngrok-url/telegram-auth-example.html` (используйте ngrok для локальной разработки)

### 3. Test Flow
1. Откройте Mini App через Telegram
2. Проверьте что автоматическая авторизация работает
3. Откройте DevTools → Console
4. Проверьте логи аутентификации

---

## 🐛 Troubleshooting

### "⚠️ TELEGRAM_BOT_TOKEN not configured"
**Solution:** Добавьте токен в `.env` файл

### "Invalid Telegram authentication" with valid data
**Causes:**
1. Неверный BOT_TOKEN
2. initData старше 24 часов
3. initData был изменен

**Solution:**
- Проверьте BOT_TOKEN
- Получите свежие initData
- Не модифицируйте initData вручную

### Session cookie not set
**Causes:**
1. `credentials: 'include'` не указан в fetch
2. CORS настройки блокируют cookies

**Solution:**
```javascript
fetch('/api/telegram/auth', {
    credentials: 'include'  // Обязательно!
});
```

### "Telegram authentication required" несмотря на авторизацию
**Causes:**
1. Cookie не передается
2. Сессия истекла (перезапуск сервера)
3. Другой домен/порт

**Solution:**
- Используйте `credentials: 'include'`
- Повторите авторизацию
- Проверьте что домен совпадает

---

## 📚 Related Documentation

- [TELEGRAM_AUTH_QUICKSTART.md](./TELEGRAM_AUTH_QUICKSTART.md) - Быстрый старт
- [TELEGRAM_WEBAPP_AUTH_GUIDE.md](./TELEGRAM_WEBAPP_AUTH_GUIDE.md) - Полное руководство
- [Telegram WebApp Documentation](https://core.telegram.org/bots/webapps)

---

**Last Updated:** 2025-11-26

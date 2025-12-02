# 🚀 Telegram WebApp Authentication - Setup Instructions

Пошаговое руководство по настройке Telegram аутентификации для локальной разработки и production deployment.

## 📋 Содержание

1. [Prerequisites](#prerequisites)
2. [Quick Start (5 minutes)](#quick-start-5-minutes)
3. [Detailed Setup](#detailed-setup)
4. [Configuration](#configuration)
5. [Testing](#testing)
6. [Production Deployment](#production-deployment)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required:
- Python 3.8+
- Telegram account
- Text editor

### Optional:
- ngrok (для локального тестирования Mini App)
- Git

---

## Quick Start (5 minutes)

### 1. Создайте Telegram Bot

```bash
# 1. Откройте Telegram
# 2. Найдите @BotFather
# 3. Отправьте: /newbot
# 4. Следуйте инструкциям
# 5. Скопируйте Bot Token
```

### 2. Настройте Environment Variables

```bash
cd backend
cp .env.example .env
```

Откройте `backend/.env` и замените:
```env
TELEGRAM_BOT_TOKEN=your_bot_token_here  # ← Вставьте ваш токен
```

### 3. Установите зависимости

```bash
pip install -r requirements.txt
```

### 4. Запустите сервер

```bash
# Основное приложение (порт 8001)
python main

# ИЛИ Админ-панель с БД (порт 8002)
python admin.py
```

### 5. Проверьте что работает

```bash
curl http://localhost:8001/api/test
# Expected: {"status": "ok"}
```

✅ **Done!** Сервер запущен и готов к использованию.

---

## Detailed Setup

### Step 1: Clone Repository

```bash
git clone https://github.com/SilkroadCeo/fesgr.git
cd fesgr
```

### Step 2: Create Telegram Bot

1. Откройте Telegram
2. Найдите **@BotFather**
3. Отправьте команду: `/newbot`
4. Введите имя бота (например: "My Dating Bot")
5. Введите username бота (должен заканчиваться на 'bot', например: "mydating_bot")
6. **Скопируйте Bot Token** (выглядит как: `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`)

### Step 3: Create Mini App (Optional, для тестирования)

1. В @BotFather отправьте: `/newapp`
2. Выберите своего бота из списка
3. Введите название приложения (например: "Dating App")
4. Введите description
5. Загрузите фото (512x512 PNG)
6. Запустите ngrok: `ngrok http 8001`
7. URL приложения: `https://your-ngrok-url.ngrok.io/` (или путь к telegram-auth-example.html)
8. Выберите платформу: Web

### Step 4: Environment Configuration

Создайте файл `backend/.env`:

```env
# ============= REQUIRED =============

# Telegram Bot Token from @BotFather
TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11

# ============= OPTIONAL =============

# CORS - разрешенные origins (comma-separated)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8001,http://localhost:8002

# Admin Credentials (только для admin.py)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password

# Admin Telegram IDs (только для admin.py, comma-separated)
ADMIN_TELEGRAM_IDS=123456789,987654321

# File Upload Limits
MAX_FILE_SIZE_MB=10
ALLOWED_IMAGE_EXTENSIONS=jpg,jpeg,png,webp,gif
ALLOWED_VIDEO_EXTENSIONS=mp4,webm

# Rate Limiting
MAX_LOGIN_ATTEMPTS=5
LOGIN_RATE_LIMIT_WINDOW_MINUTES=15
```

### Step 5: Install Dependencies

```bash
cd backend

# Check Python version
python --version  # Should be 3.8+

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -c "import fastapi, uvicorn; print('✅ Dependencies OK')"
```

### Step 6: Initialize Database (for admin.py only)

```bash
# Database будет создана автоматически при первом запуске admin.py
python admin.py
# Ctrl+C to stop

# Check database was created
ls -la app_database.db
# Expected: app_database.db exists
```

### Step 7: Start Server

```bash
# Option A: Main application (lightweight, in-memory sessions)
python main
# Server starts on http://localhost:8001

# Option B: Admin panel (with database)
python admin.py
# Server starts on http://localhost:8002
```

---

## Configuration

### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TELEGRAM_BOT_TOKEN` | ✅ Yes | - | Token from @BotFather |
| `ALLOWED_ORIGINS` | ❌ No | `localhost:8001,localhost:8002` | CORS allowed origins |
| `ADMIN_USERNAME` | ❌ No | `admin` | Admin panel username |
| `ADMIN_PASSWORD` | ❌ No | `admin123` | Admin panel password |
| `ADMIN_TELEGRAM_IDS` | ❌ No | `` | Comma-separated admin IDs |
| `MAX_FILE_SIZE_MB` | ❌ No | `10` | Max upload file size |

### Security Best Practices

#### 🔒 Secrets Management

**Development:**
```bash
# Use .env file (already in .gitignore)
echo "TELEGRAM_BOT_TOKEN=your_token" >> backend/.env
```

**Production:**
```bash
# Use environment variables (не .env файл!)
export TELEGRAM_BOT_TOKEN=your_token
export ADMIN_PASSWORD=strong_password_here
```

**Docker:**
```yaml
# docker-compose.yml
services:
  backend:
    environment:
      - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
```

#### 🔐 HTTPS in Production

Всегда используйте HTTPS в production:

```python
# backend/main (line ~528)
response.set_cookie(
    key="telegram_session",
    value=session_id,
    httponly=True,
    secure=True,  # ← Включите в production
    samesite="lax"
)
```

---

## Testing

### Local Testing (без Telegram)

```bash
# Start server
python main

# Test health endpoint
curl http://localhost:8001/api/test
# Expected: {"status": "ok"}

# Test unauthenticated access
curl http://localhost:8001/api/telegram/me
# Expected: 401 Unauthorized
```

### Testing with Telegram Mini App

#### Option 1: Using ngrok

```bash
# Terminal 1: Start server
cd backend
python main

# Terminal 2: Start ngrok
ngrok http 8001

# Output:
# Forwarding  https://abc123.ngrok.io -> http://localhost:8001
```

1. Copy ngrok URL: `https://abc123.ngrok.io`
2. Open `frontend/telegram-auth-example.html`
3. Change `API_BASE_URL` to your ngrok URL
4. Upload to web hosting or use ngrok static files
5. Set as Mini App URL in @BotFather
6. Open Mini App from Telegram

#### Option 2: Using Example HTML

```bash
# 1. Open frontend/telegram-auth-example.html in browser
# 2. Open through Telegram Web App
# 3. Check DevTools Console for logs
```

### Automated Tests

```bash
# Run test script
chmod +x test_auth.sh
./test_auth.sh

# Expected output:
# ✅ PASS: Unauthenticated request rejected
# ✅ PASS: Invalid initData rejected
# ✅ PASS: Missing initData rejected
```

См. [TELEGRAM_AUTH_TESTS.md](./TELEGRAM_AUTH_TESTS.md) для подробных тестов.

---

## Production Deployment

### 1. Server Requirements

- Python 3.8+
- 512MB RAM minimum (1GB+ recommended)
- HTTPS certificate (Let's Encrypt recommended)
- Domain name

### 2. Environment Setup

```bash
# Production server
export TELEGRAM_BOT_TOKEN=your_production_token
export ALLOWED_ORIGINS=https://yourdomain.com
export ADMIN_PASSWORD=strong_password_here

# Verify
echo $TELEGRAM_BOT_TOKEN
```

### 3. Run with Gunicorn (recommended)

```bash
# Install gunicorn
pip install gunicorn

# Run main application
gunicorn main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8001 \
  --access-logfile - \
  --error-logfile -

# OR run admin panel
gunicorn admin:app \
  --workers 2 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8002
```

### 4. Systemd Service (Linux)

Create `/etc/systemd/system/fesgr.service`:

```ini
[Unit]
Description=FESGR Dating App
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/var/www/fesgr/backend
Environment="TELEGRAM_BOT_TOKEN=your_token"
Environment="ALLOWED_ORIGINS=https://yourdomain.com"
ExecStart=/usr/bin/gunicorn main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 127.0.0.1:8001

Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl enable fesgr
sudo systemctl start fesgr
sudo systemctl status fesgr
```

### 5. Nginx Reverse Proxy

Create `/etc/nginx/sites-available/fesgr`:

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/fesgr /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 6. Docker Deployment

`Dockerfile`:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

EXPOSE 8001

CMD ["gunicorn", "main:app", \
     "--workers", "4", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8001"]
```

`docker-compose.yml`:
```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8001:8001"
    environment:
      - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
      - ALLOWED_ORIGINS=https://yourdomain.com
    volumes:
      - ./backend:/app
    restart: unless-stopped
```

```bash
# Deploy
docker-compose up -d

# Check logs
docker-compose logs -f
```

---

## Troubleshooting

### ❌ "TELEGRAM_BOT_TOKEN not configured"

**Problem:** Token отсутствует или не загружен

**Solutions:**
```bash
# Check .env file exists
ls -la backend/.env

# Check token is set
grep TELEGRAM_BOT_TOKEN backend/.env

# Verify dotenv is loaded
python -c "from dotenv import load_dotenv; import os; load_dotenv(); print(os.getenv('TELEGRAM_BOT_TOKEN'))"
```

### ❌ "ModuleNotFoundError: No module named 'fastapi'"

**Problem:** Dependencies не установлены

**Solution:**
```bash
cd backend
pip install -r requirements.txt
```

### ❌ "Address already in use"

**Problem:** Порт 8001/8002 уже занят

**Solutions:**
```bash
# Find process using port
lsof -i :8001

# Kill process
kill -9 <PID>

# OR use different port
uvicorn main:app --port 8003
```

### ❌ "Invalid Telegram authentication" с валидными данными

**Causes:**
1. Неверный BOT_TOKEN
2. initData старше 24 часов
3. Временная рассинхронизация сервера

**Solutions:**
```bash
# Check BOT_TOKEN
echo $TELEGRAM_BOT_TOKEN

# Check server time
date
timedatectl  # Linux

# Get fresh initData from Telegram Mini App
```

### ❌ CORS errors in browser

**Problem:** Frontend на другом домене

**Solution:**
```env
# Add frontend domain to ALLOWED_ORIGINS
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
```

### ❌ "Database is locked" (admin.py)

**Problem:** Concurrent write access to SQLite

**Solutions:**
```bash
# Check if another process is using DB
lsof backend/app_database.db

# For production, use PostgreSQL instead of SQLite
```

---

## Next Steps

1. ✅ Setup complete → [Test Authentication](./TELEGRAM_AUTH_TESTS.md)
2. 📚 Learn more → [Full Guide](./TELEGRAM_WEBAPP_AUTH_GUIDE.md)
3. 🚀 Quick reference → [Quick Start](./TELEGRAM_AUTH_QUICKSTART.md)
4. 💻 See example → `frontend/telegram-auth-example.html`

---

## Support

### Documentation
- [TELEGRAM_AUTH_QUICKSTART.md](./TELEGRAM_AUTH_QUICKSTART.md)
- [TELEGRAM_WEBAPP_AUTH_GUIDE.md](./TELEGRAM_WEBAPP_AUTH_GUIDE.md)
- [TELEGRAM_AUTH_TESTS.md](./TELEGRAM_AUTH_TESTS.md)

### External Resources
- [Telegram WebApp Docs](https://core.telegram.org/bots/webapps)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Ngrok Documentation](https://ngrok.com/docs)

---

**Last Updated:** 2025-11-26

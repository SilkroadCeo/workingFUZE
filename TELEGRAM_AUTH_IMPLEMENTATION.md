# Telegram Mini App Authentication Implementation

## Overview

This document describes the complete Telegram Mini App authentication system implemented for the file management application. The system provides secure user authentication, user isolation, and file ownership tracking.

---

## 🎯 Features Implemented

### 1. **Telegram Web App Authentication**
- ✅ HMAC-SHA-256 signature verification
- ✅ Automatic user registration and login
- ✅ Secure session management with HttpOnly cookies
- ✅ User profile management

### 2. **Database-Driven User Management**
- ✅ SQLite database for user and file storage
- ✅ Automatic user creation on first login
- ✅ User profile tracking (Telegram ID, username, name, etc.)
- ✅ Last login timestamp tracking

### 3. **User-Specific File Isolation**
- ✅ Files stored in user-specific directories (`uploads/user_XXXXX/`)
- ✅ Ownership checks on all file operations
- ✅ Database tracking of file ownership
- ✅ Secure file upload with validation

### 4. **Secure File Operations**
- ✅ Upload: Only authenticated users
- ✅ Download: Ownership verification required
- ✅ Delete: Ownership verification required
- ✅ List: Shows only user's own files

---

## 📊 Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER UNIQUE NOT NULL,
    username TEXT,
    first_name TEXT,
    last_name TEXT,
    language_code TEXT DEFAULT 'en',
    is_premium INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Files Table
```sql
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    telegram_user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER,
    mime_type TEXT,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## 🔐 Authentication Flow

### 1. User Opens Telegram Mini App

```javascript
// Frontend (index.html)
if (window.Telegram && window.Telegram.WebApp) {
    tg = window.Telegram.WebApp;
    tg.ready();
    telegramUser = tg.initDataUnsafe?.user;
}
```

### 2. Authentication Request

```javascript
// Send authentication request
const response = await fetch('/api/telegram/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        initData: tg.initData  // Telegram's signed data
    }),
    credentials: 'include'  // Important for cookies
});
```

### 3. Server Verification

```python
# Backend (admin.py)
@app.post("/api/telegram/auth")
async def telegram_auth(request: Request, response: Response):
    # 1. Parse Telegram data
    init_data = body.get("initData")

    # 2. VERIFY SIGNATURE (HMAC-SHA-256)
    if not verify_telegram_auth(init_data):
        raise HTTPException(status_code=401, detail="Invalid authentication")

    # 3. Create/update user in database
    db_user = db.get_or_create_user(
        telegram_id=telegram_id,
        username=username,
        first_name=first_name,
        last_name=last_name
    )

    # 4. Create session
    session_id = create_telegram_session(user_data)

    # 5. Set secure cookie
    response.set_cookie(
        key="telegram_session",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax"
    )
```

### 4. Signature Verification Details

```python
def verify_telegram_auth(init_data: str) -> bool:
    """
    Verifies Telegram Web App data using HMAC-SHA-256

    Process:
    1. Parse initData query string
    2. Extract hash from data
    3. Sort remaining key-value pairs
    4. Create verification string
    5. Compute HMAC-SHA-256 with secret key
    6. Compare hashes
    """
    parsed_data = parse_qs(init_data)
    received_hash = parsed_data.get('hash', [''])[0]

    # Build data check string
    data_check_arr = []
    for key, value in sorted(parsed_data.items()):
        if key != 'hash':
            data_check_arr.append(f"{key}={value[0]}")

    data_check_string = '\n'.join(data_check_arr)

    # Compute HMAC согласно официальной документации Telegram
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

    return calculated_hash == received_hash
```

---

## 📁 File Management API

### Upload File
```http
POST /api/user/files/upload
Authorization: Cookie (telegram_session)
Content-Type: multipart/form-data

file: <binary file data>
```

**Response:**
```json
{
    "status": "success",
    "file": {
        "id": 1,
        "filename": "20231125_120000_document.pdf",
        "original_filename": "document.pdf",
        "file_url": "/uploads/user_123456789/20231125_120000_document.pdf",
        "file_size": 524288,
        "mime_type": "application/pdf"
    }
}
```

### List User Files
```http
GET /api/user/files
Authorization: Cookie (telegram_session)
```

**Response:**
```json
{
    "status": "success",
    "files": [
        {
            "id": 1,
            "filename": "20231125_120000_document.pdf",
            "original_filename": "document.pdf",
            "file_path": "/path/to/uploads/user_123456789/...",
            "file_size": 524288,
            "mime_type": "application/pdf",
            "uploaded_at": "2023-11-25 12:00:00"
        }
    ],
    "count": 1
}
```

### Download File
```http
GET /api/user/files/{file_id}/download
Authorization: Cookie (telegram_session)
```

**Returns:** File binary data with appropriate headers

### Delete File
```http
DELETE /api/user/files/{file_id}
Authorization: Cookie (telegram_session)
```

**Response:**
```json
{
    "status": "success",
    "message": "File deleted successfully"
}
```

### Get Storage Stats
```http
GET /api/user/storage/stats
Authorization: Cookie (telegram_session)
```

**Response:**
```json
{
    "status": "success",
    "stats": {
        "file_count": 5,
        "total_size": 2621440,
        "total_size_mb": 2.5
    }
}
```

### Get User Profile
```http
GET /api/user/profile
Authorization: Cookie (telegram_session)
```

**Response:**
```json
{
    "status": "success",
    "user": {
        "id": 1,
        "telegram_id": 123456789,
        "first_name": "John",
        "last_name": "Doe",
        "username": "johndoe",
        "language_code": "en",
        "is_premium": false
    }
}
```

### Logout
```http
POST /api/telegram/logout
Authorization: Cookie (telegram_session)
```

---

## 🔒 Security Features

### 1. **Authentication Security**
- HMAC-SHA-256 signature verification prevents unauthorized access
- Only requests from official Telegram app are accepted
- Bot token used as secret key for verification

### 2. **Session Security**
- HttpOnly cookies prevent JavaScript access
- Secure flag ensures HTTPS-only transmission in production
- SameSite=Lax prevents CSRF attacks
- 30-day session expiration

### 3. **File Security**
- File type validation (extension + MIME type)
- File size limits (10MB default, configurable)
- Path traversal protection
- Filename sanitization
- User-specific directories prevent cross-user access

### 4. **Authorization**
- All file operations check ownership
- Database-level foreign key constraints
- Session-based authentication required for all user endpoints

---

## 🚀 Setup Instructions

### 1. Configure Environment Variables

Create `backend/.env`:
```bash
# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN=your_bot_token_here

# CORS Configuration
ALLOWED_ORIGINS=https://yourdomain.com

# File Upload Configuration
MAX_FILE_SIZE_MB=10
ALLOWED_IMAGE_EXTENSIONS=jpg,jpeg,png,webp,gif
ALLOWED_VIDEO_EXTENSIONS=mp4,webm
```

### 2. Initialize Database

```bash
cd backend
python migrate_to_database.py
```

This will:
- Create SQLite database (`app_database.db`)
- Set up tables and indexes
- Display current statistics

### 3. Configure Telegram Bot

1. Create bot with @BotFather
2. Enable Web App:
   ```
   /newapp
   Select your bot
   App title: File Manager
   Description: Secure file management
   Photo: (upload icon)
   Demo GIF: (optional)
   Web App URL: https://yourdomain.com
   Short name: filemanager
   ```

3. Set bot token in `.env` file

### 4. Start Server

```bash
cd backend
python admin.py
```

Server runs on `http://localhost:8002`

---

## 📱 Frontend Integration

### Check Authentication Status

```javascript
async function checkAuth() {
    try {
        const response = await fetch('/api/user/profile', {
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            console.log('User:', data.user);
            return data.user;
        } else {
            // Not authenticated, show login
            return null;
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        return null;
    }
}
```

### Upload File Example

```javascript
async function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('/api/user/files/upload', {
        method: 'POST',
        body: formData,
        credentials: 'include'
    });

    if (response.ok) {
        const data = await response.json();
        console.log('File uploaded:', data.file);
        return data.file;
    } else {
        throw new Error('Upload failed');
    }
}
```

### List Files Example

```javascript
async function listFiles() {
    const response = await fetch('/api/user/files', {
        credentials: 'include'
    });

    if (response.ok) {
        const data = await response.json();
        return data.files;
    } else {
        throw new Error('Failed to fetch files');
    }
}
```

---

## 🧪 Testing

### Test Authentication

```bash
# This will fail without valid Telegram signature
curl -X POST http://localhost:8002/api/telegram/auth \
  -H "Content-Type: application/json" \
  -d '{"initData": "invalid_data"}'
# Response: 401 Unauthorized
```

### Test File Upload (requires valid session)

```bash
curl -X POST http://localhost:8002/api/user/files/upload \
  -H "Cookie: telegram_session=your_session_id" \
  -F "file=@test.pdf"
```

### Test Ownership Protection

```bash
# Try to access another user's file (will fail)
curl http://localhost:8002/api/user/files/999/download \
  -H "Cookie: telegram_session=your_session_id"
# Response: 404 Not Found (if file exists but belongs to different user)
```

---

## 📂 Directory Structure

```
backend/
├── admin.py                    # Main FastAPI application
├── database.py                 # Database management module
├── migrate_to_database.py      # Migration script
├── app_database.db            # SQLite database
├── .env                        # Environment variables (create this)
├── .env.example               # Environment template
├── .gitignore                 # Git ignore rules
└── uploads/                    # File storage
    ├── user_123456789/        # User-specific directories
    ├── user_987654321/
    └── ...
```

---

## 🐛 Troubleshooting

### Issue: "Invalid Telegram authentication"

**Cause:** Signature verification failed

**Solutions:**
1. Verify `TELEGRAM_BOT_TOKEN` is correct in `.env`
2. Ensure request comes from actual Telegram Web App
3. Check that `initData` is being sent correctly
4. Verify bot token hasn't been regenerated

### Issue: "Telegram authentication required"

**Cause:** No valid session cookie

**Solutions:**
1. Call `/api/telegram/auth` first to authenticate
2. Ensure `credentials: 'include'` in fetch requests
3. Check cookie is being set (browser DevTools → Application → Cookies)
4. Verify cookie domain matches your domain

### Issue: "File not found or you don't have permission"

**Cause:** Trying to access file that doesn't belong to user

**Solutions:**
1. Verify file ID is correct
2. Check you're authenticated as the correct user
3. Confirm file wasn't deleted
4. Check database: `SELECT * FROM files WHERE id = X`

---

## 🔧 Advanced Configuration

### Custom Storage Location

```python
# In admin.py
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/custom/path/uploads")
```

### File Size Limits

```bash
# In .env
MAX_FILE_SIZE_MB=50  # 50MB limit
```

### Session Duration

```python
# In admin.py telegram_auth function
response.set_cookie(
    max_age=86400 * 7,  # 7 days instead of 30
    ...
)
```

---

## ✅ Checklist

Before deploying to production:

- [ ] Set strong `TELEGRAM_BOT_TOKEN` in `.env`
- [ ] Configure `ALLOWED_ORIGINS` with production domain
- [ ] Set `secure=True` for cookies (requires HTTPS)
- [ ] Enable HTTPS on server
- [ ] Test authentication flow
- [ ] Test file upload/download/delete
- [ ] Verify ownership protection works
- [ ] Check database backups are configured
- [ ] Review server logs for errors
- [ ] Test from actual Telegram app (not just browser)

---

## 📊 Database Management

### View Users

```sql
sqlite3 app_database.db
SELECT * FROM users;
```

### View Files for User

```sql
SELECT * FROM files WHERE telegram_user_id = 123456789;
```

### Get Storage Usage

```sql
SELECT
    telegram_user_id,
    COUNT(*) as file_count,
    SUM(file_size) / 1024.0 / 1024.0 as total_mb
FROM files
GROUP BY telegram_user_id;
```

### Backup Database

```bash
cp app_database.db app_database.db.backup
```

---

## 🎓 Summary

This implementation provides a complete, production-ready Telegram Mini App authentication system with:

✅ Secure HMAC-SHA-256 verification
✅ SQLite database for persistent storage
✅ User isolation and ownership tracking
✅ Comprehensive file management API
✅ Security best practices throughout
✅ Easy setup and deployment

All user data is isolated, all file operations are ownership-checked, and all authentication is cryptographically verified.

For questions or issues, refer to the FastAPI logs and check the database state using the SQL queries provided above.

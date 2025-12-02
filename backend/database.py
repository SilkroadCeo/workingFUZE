"""
Database management for Telegram Mini App File Management System
Handles user authentication, file storage, and user data isolation
"""

import sqlite3
import os
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Database configuration
current_dir = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(current_dir, "app_database.db")


@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Enable column access by name
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        conn.close()


def init_database():
    """Initialize database with schema"""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER UNIQUE NOT NULL,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                language_code TEXT DEFAULT 'en',
                is_premium INTEGER DEFAULT 0,
                user_type TEXT DEFAULT 'telegram' CHECK(user_type IN ('telegram', 'web')),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Files table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
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
            )
        """)

        # Create indexes for performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_files_user_id
            ON files(user_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_files_telegram_user_id
            ON files(telegram_user_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_telegram_id
            ON users(telegram_id)
        """)

        # Profiles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                avatar TEXT,
                bio TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_profiles_user_id
            ON profiles(user_id)
        """)

        # Dating profiles table (for dating app functionality)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dating_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                age INTEGER NOT NULL,
                gender TEXT NOT NULL,
                nationality TEXT,
                city TEXT,
                travel_cities TEXT,  -- JSON array stored as text
                description TEXT,
                photos TEXT,  -- JSON array stored as text
                visible INTEGER DEFAULT 1,
                created_at TEXT,
                height INTEGER,
                weight INTEGER,
                chest INTEGER
            )
        """)

        # VIP profiles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vip_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                age INTEGER NOT NULL,
                gender TEXT NOT NULL,
                nationality TEXT,
                city TEXT,
                travel_cities TEXT,  -- JSON array
                description TEXT,
                photos TEXT,  -- JSON array
                visible INTEGER DEFAULT 1,
                created_at TEXT,
                height INTEGER,
                weight INTEGER,
                chest INTEGER,
                is_vip INTEGER DEFAULT 1
            )
        """)

        # Chats table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL,
                telegram_user_id INTEGER,
                created_at TEXT,
                last_message_at TEXT
            )
        """)

        # Messages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                profile_id INTEGER NOT NULL,
                telegram_user_id INTEGER,
                sender_type TEXT NOT NULL,  -- 'user' or 'profile' or 'admin'
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE
            )
        """)

        # Orders table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_user_id INTEGER,
                profile_id INTEGER NOT NULL,
                service_type TEXT NOT NULL,
                amount REAL NOT NULL,
                currency TEXT DEFAULT 'USD',
                payment_method TEXT,
                payment_wallet TEXT,
                status TEXT DEFAULT 'pending',  -- pending, paid, confirmed, cancelled
                created_at TEXT,
                confirmed_at TEXT,
                details TEXT  -- JSON stored as text
            )
        """)

        # Comments table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL,
                telegram_user_id INTEGER,
                author_name TEXT,
                rating INTEGER NOT NULL,
                comment TEXT,
                created_at TEXT,
                visible INTEGER DEFAULT 1
            )
        """)

        # Promocodes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS promocodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                discount_percent INTEGER NOT NULL,
                max_uses INTEGER DEFAULT NULL,
                current_uses INTEGER DEFAULT 0,
                valid_until TEXT,
                active INTEGER DEFAULT 1,
                created_at TEXT
            )
        """)

        # App settings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT
            )
        """)

        # Sessions table (для Telegram WebApp сессий)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                telegram_id INTEGER NOT NULL,
                user_data TEXT NOT NULL,  -- JSON
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_telegram_id
            ON sessions(telegram_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
            ON sessions(expires_at)
        """)

        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dating_profiles_visible ON dating_profiles(visible)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dating_profiles_city ON dating_profiles(city)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vip_profiles_visible ON vip_profiles(visible)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chats_profile_id ON chats(profile_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chats_telegram_user_id ON chats(telegram_user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_telegram_user_id ON messages(telegram_user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_telegram_user_id ON orders(telegram_user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_comments_profile_id ON comments(profile_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_promocodes_code ON promocodes(code)")

        logger.info("✅ Database initialized successfully")


# ==================== USER MANAGEMENT ====================

def get_or_create_user(telegram_id: int, username: str = None,
                       first_name: str = None, last_name: str = None,
                       language_code: str = 'en', is_premium: bool = False,
                       user_type: str = 'telegram') -> Dict[str, Any]:
    """
    Get existing user or create new one from Telegram data
    Returns user dictionary with id, telegram_id, etc.

    Security: Validates telegram_id to prevent invalid data
    """
    # SECURITY: Validate telegram_id format
    if not isinstance(telegram_id, int) or telegram_id <= 0:
        raise ValueError(f"Invalid telegram_id: {telegram_id}. Must be a positive integer.")

    # Validate user_type
    if user_type not in ('telegram', 'web'):
        raise ValueError(f"Invalid user_type: {user_type}. Must be 'telegram' or 'web'.")

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Try to get existing user
        cursor.execute("""
            SELECT id, telegram_id, username, first_name, last_name,
                   language_code, is_premium, user_type, created_at, last_login
            FROM users
            WHERE telegram_id = ?
        """, (telegram_id,))

        user = cursor.fetchone()

        if user:
            # Update last login and user info
            cursor.execute("""
                UPDATE users
                SET last_login = CURRENT_TIMESTAMP,
                    username = ?,
                    first_name = ?,
                    last_name = ?,
                    language_code = ?,
                    is_premium = ?,
                    user_type = ?
                WHERE telegram_id = ?
            """, (username, first_name, last_name, language_code,
                  1 if is_premium else 0, user_type, telegram_id))

            logger.info(f"✅ User logged in: {telegram_id} ({first_name} {last_name})")

            # Fetch updated user
            cursor.execute("""
                SELECT id, telegram_id, username, first_name, last_name,
                       language_code, is_premium, user_type, created_at, last_login
                FROM users
                WHERE telegram_id = ?
            """, (telegram_id,))
            user = cursor.fetchone()
        else:
            # Create new user
            cursor.execute("""
                INSERT INTO users (telegram_id, username, first_name, last_name,
                                   language_code, is_premium, user_type)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (telegram_id, username, first_name, last_name, language_code,
                  1 if is_premium else 0, user_type))

            user_id = cursor.lastrowid
            logger.info(f"✅ New user created: {telegram_id} ({first_name} {last_name})")

            # Create profile for new user
            cursor.execute("""
                INSERT INTO profiles (user_id, bio)
                VALUES (?, ?)
            """, (user_id, ''))
            logger.info(f"✅ Profile created for user_id: {user_id}")

            # Fetch created user
            cursor.execute("""
                SELECT id, telegram_id, username, first_name, last_name,
                       language_code, is_premium, user_type, created_at, last_login
                FROM users
                WHERE id = ?
            """, (user_id,))
            user = cursor.fetchone()

        return dict(user)


def get_user_by_telegram_id(telegram_id: int) -> Optional[Dict[str, Any]]:
    """Get user by Telegram ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, telegram_id, username, first_name, last_name,
                   language_code, is_premium, user_type, created_at, last_login
            FROM users
            WHERE telegram_id = ?
        """, (telegram_id,))

        user = cursor.fetchone()
        return dict(user) if user else None


# ==================== FILE MANAGEMENT ====================

def add_file(user_id: int, telegram_user_id: int, filename: str,
             original_filename: str, file_path: str, file_size: int,
             mime_type: str) -> int:
    """
    Add file to database with ownership validation

    Security: Validates that user_id corresponds to telegram_user_id
    """
    # SECURITY: Validate inputs
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValueError(f"Invalid user_id: {user_id}")

    if not isinstance(telegram_user_id, int) or telegram_user_id <= 0:
        raise ValueError(f"Invalid telegram_user_id: {telegram_user_id}")

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # SECURITY: Verify user_id belongs to telegram_user_id
        cursor.execute("""
            SELECT telegram_id FROM users WHERE id = ?
        """, (user_id,))
        user = cursor.fetchone()

        if not user:
            raise ValueError(f"User ID {user_id} not found")

        if user['telegram_id'] != telegram_user_id:
            raise ValueError(
                f"User ID mismatch: user_id {user_id} has telegram_id {user['telegram_id']}, "
                f"but {telegram_user_id} was provided"
            )

        cursor.execute("""
            INSERT INTO files (user_id, telegram_user_id, filename, original_filename,
                              file_path, file_size, mime_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, telegram_user_id, filename, original_filename,
              file_path, file_size, mime_type))

        file_id = cursor.lastrowid
        logger.info(f"✅ File added to database: {filename} (user_id: {user_id}, telegram_id: {telegram_user_id})")
        return file_id


def get_user_files(telegram_user_id: int) -> List[Dict[str, Any]]:
    """Get all files for a specific user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, filename, original_filename, file_path, file_size,
                   mime_type, uploaded_at
            FROM files
            WHERE telegram_user_id = ?
            ORDER BY uploaded_at DESC
        """, (telegram_user_id,))

        files = cursor.fetchall()
        return [dict(file) for file in files]


def get_file_by_id(file_id: int, telegram_user_id: int) -> Optional[Dict[str, Any]]:
    """
    Get file by ID with ownership verification
    Returns None if file doesn't exist or doesn't belong to user

    Security: Critical function for preventing unauthorized file access
    """
    # SECURITY: Validate inputs
    if not isinstance(telegram_user_id, int) or telegram_user_id <= 0:
        logger.error(f"Invalid telegram_user_id in get_file_by_id: {telegram_user_id}")
        return None

    if not isinstance(file_id, int) or file_id <= 0:
        logger.error(f"Invalid file_id in get_file_by_id: {file_id}")
        return None

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, user_id, telegram_user_id, filename, original_filename,
                   file_path, file_size, mime_type, uploaded_at
            FROM files
            WHERE id = ? AND telegram_user_id = ?
        """, (file_id, telegram_user_id))

        file = cursor.fetchone()

        # SECURITY: Log access attempts for auditing
        if file:
            logger.debug(f"File {file_id} accessed by telegram_user_id {telegram_user_id}")
        else:
            logger.warning(f"Unauthorized file access attempt: file_id={file_id}, telegram_user_id={telegram_user_id}")

        return dict(file) if file else None


def get_file_by_filename(filename: str, telegram_user_id: int) -> Optional[Dict[str, Any]]:
    """Get file by filename with ownership verification"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, user_id, telegram_user_id, filename, original_filename,
                   file_path, file_size, mime_type, uploaded_at
            FROM files
            WHERE filename = ? AND telegram_user_id = ?
        """, (filename, telegram_user_id))

        file = cursor.fetchone()
        return dict(file) if file else None


def delete_file(file_id: int, telegram_user_id: int) -> bool:
    """
    Delete file with ownership verification
    Returns True if deleted, False if not found or unauthorized

    Security: Critical function for preventing unauthorized file deletion
    """
    # SECURITY: Validate inputs
    if not isinstance(telegram_user_id, int) or telegram_user_id <= 0:
        logger.error(f"Invalid telegram_user_id in delete_file: {telegram_user_id}")
        return False

    if not isinstance(file_id, int) or file_id <= 0:
        logger.error(f"Invalid file_id in delete_file: {file_id}")
        return False

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # SECURITY: Check if file exists and belongs to user
        cursor.execute("""
            SELECT file_path FROM files
            WHERE id = ? AND telegram_user_id = ?
        """, (file_id, telegram_user_id))

        file = cursor.fetchone()
        if not file:
            logger.warning(f"Unauthorized delete attempt: file_id={file_id}, telegram_user_id={telegram_user_id}")
            return False

        file_path = file['file_path']

        # Delete from database
        cursor.execute("""
            DELETE FROM files
            WHERE id = ? AND telegram_user_id = ?
        """, (file_id, telegram_user_id))

        # Delete physical file
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                logger.info(f"✅ File deleted: {file_path}")
            except Exception as e:
                logger.error(f"❌ Error deleting file: {e}")

        return cursor.rowcount > 0


def delete_file_by_filename(filename: str, telegram_user_id: int) -> bool:
    """Delete file by filename with ownership verification"""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Get file info
        cursor.execute("""
            SELECT id, file_path FROM files
            WHERE filename = ? AND telegram_user_id = ?
        """, (filename, telegram_user_id))

        file = cursor.fetchone()
        if not file:
            return False

        file_path = file['file_path']

        # Delete from database
        cursor.execute("""
            DELETE FROM files
            WHERE filename = ? AND telegram_user_id = ?
        """, (filename, telegram_user_id))

        # Delete physical file
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                logger.info(f"✅ File deleted: {file_path}")
            except Exception as e:
                logger.error(f"❌ Error deleting file: {e}")

        return cursor.rowcount > 0


def get_user_storage_stats(telegram_user_id: int) -> Dict[str, Any]:
    """Get storage statistics for user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                COUNT(*) as file_count,
                COALESCE(SUM(file_size), 0) as total_size
            FROM files
            WHERE telegram_user_id = ?
        """, (telegram_user_id,))

        stats = cursor.fetchone()
        return {
            'file_count': stats['file_count'],
            'total_size': stats['total_size'],
            'total_size_mb': round(stats['total_size'] / (1024 * 1024), 2)
        }


# ==================== UTILITY FUNCTIONS ====================

def get_database_stats() -> Dict[str, Any]:
    """Get overall database statistics"""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as count FROM users")
        user_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM files")
        file_count = cursor.fetchone()['count']

        cursor.execute("SELECT COALESCE(SUM(file_size), 0) as total FROM files")
        total_size = cursor.fetchone()['total']

        return {
            'total_users': user_count,
            'total_files': file_count,
            'total_storage_bytes': total_size,
            'total_storage_mb': round(total_size / (1024 * 1024), 2)
        }


# ==================== PROFILE MANAGEMENT ====================

def get_or_create_profile(user_id: int) -> Dict[str, Any]:
    """
    Get existing profile or create new one for user
    Returns profile dictionary with id, user_id, avatar, bio
    """
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValueError(f"Invalid user_id: {user_id}. Must be a positive integer.")

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Try to get existing profile
        cursor.execute("""
            SELECT id, user_id, avatar, bio, created_at, updated_at
            FROM profiles
            WHERE user_id = ?
        """, (user_id,))

        profile = cursor.fetchone()

        if not profile:
            # Create new profile
            cursor.execute("""
                INSERT INTO profiles (user_id, bio)
                VALUES (?, ?)
            """, (user_id, ''))

            profile_id = cursor.lastrowid
            logger.info(f"✅ Profile created for user_id: {user_id}")

            # Fetch created profile
            cursor.execute("""
                SELECT id, user_id, avatar, bio, created_at, updated_at
                FROM profiles
                WHERE id = ?
            """, (profile_id,))
            profile = cursor.fetchone()

        return dict(profile) if profile else None


def update_profile(user_id: int, avatar: str = None, bio: str = None) -> bool:
    """
    Update user profile
    Returns True if updated, False otherwise
    """
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValueError(f"Invalid user_id: {user_id}. Must be a positive integer.")

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Build update query dynamically based on provided fields
        update_fields = []
        params = []

        if avatar is not None:
            update_fields.append("avatar = ?")
            params.append(avatar)

        if bio is not None:
            update_fields.append("bio = ?")
            params.append(bio)

        if not update_fields:
            return False

        # Always update updated_at
        update_fields.append("updated_at = CURRENT_TIMESTAMP")
        params.append(user_id)

        query = f"""
            UPDATE profiles
            SET {', '.join(update_fields)}
            WHERE user_id = ?
        """

        cursor.execute(query, params)

        if cursor.rowcount > 0:
            logger.info(f"✅ Profile updated for user_id: {user_id}")
            return True

        return False


def get_profile_by_user_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Get profile by user ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, user_id, avatar, bio, created_at, updated_at
            FROM profiles
            WHERE user_id = ?
        """, (user_id,))

        profile = cursor.fetchone()
        return dict(profile) if profile else None


# ==================== DATING APP FUNCTIONS ====================

def get_all_dating_profiles(filters: Dict = None) -> List[Dict]:
    """Get all dating profiles with optional filters"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM dating_profiles WHERE visible = 1"
        params = []

        if filters:
            if filters.get('city'):
                query += " AND city = ?"
                params.append(filters['city'])
            if filters.get('gender'):
                query += " AND gender = ?"
                params.append(filters['gender'])

        cursor.execute(query, params)
        profiles = cursor.fetchall()
        return [dict(p) for p in profiles]


def get_dating_profile_by_id(profile_id: int) -> Optional[Dict]:
    """Get dating profile by ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM dating_profiles WHERE id = ?", (profile_id,))
        profile = cursor.fetchone()
        return dict(profile) if profile else None


def add_dating_profile(profile_data: Dict) -> int:
    """Add new dating profile"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO dating_profiles (name, age, gender, nationality, city,
                                         travel_cities, description, photos, visible,
                                         created_at, height, weight, chest)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            profile_data['name'], profile_data['age'], profile_data['gender'],
            profile_data.get('nationality'), profile_data.get('city'),
            profile_data.get('travel_cities'), profile_data.get('description'),
            profile_data.get('photos'), profile_data.get('visible', 1),
            profile_data.get('created_at'), profile_data.get('height'),
            profile_data.get('weight'), profile_data.get('chest')
        ))
        return cursor.lastrowid


def get_all_vip_profiles() -> List[Dict]:
    """Get all VIP profiles"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vip_profiles WHERE visible = 1")
        profiles = cursor.fetchall()
        return [dict(p) for p in profiles]


def get_chat_by_profile_and_user(profile_id: int, telegram_user_id: int) -> Optional[Dict]:
    """Get or create chat between profile and user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM chats
            WHERE profile_id = ? AND telegram_user_id = ?
        """, (profile_id, telegram_user_id))
        chat = cursor.fetchone()

        if not chat:
            # Create new chat
            from datetime import datetime
            now = datetime.now().isoformat()
            cursor.execute("""
                INSERT INTO chats (profile_id, telegram_user_id, created_at, last_message_at)
                VALUES (?, ?, ?, ?)
            """, (profile_id, telegram_user_id, now, now))
            chat_id = cursor.lastrowid
            return {'id': chat_id, 'profile_id': profile_id, 'telegram_user_id': telegram_user_id}

        return dict(chat)


def add_message(chat_id: int, profile_id: int, telegram_user_id: Optional[int],
                sender_type: str, content: str) -> int:
    """Add message to chat"""
    from datetime import datetime
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO messages (chat_id, profile_id, telegram_user_id, sender_type, content, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (chat_id, profile_id, telegram_user_id, sender_type, content, datetime.now().isoformat()))

        # Update last_message_at in chats
        cursor.execute("""
            UPDATE chats SET last_message_at = ? WHERE id = ?
        """, (datetime.now().isoformat(), chat_id))

        return cursor.lastrowid


def get_messages_by_chat(chat_id: int, limit: int = 100) -> List[Dict]:
    """Get messages for a chat"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM messages
            WHERE chat_id = ?
            ORDER BY timestamp ASC
            LIMIT ?
        """, (chat_id, limit))
        messages = cursor.fetchall()
        return [dict(m) for m in messages]


def get_user_chats(telegram_user_id: int) -> List[Dict]:
    """Get all chats for a user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.*, dp.name as profile_name, dp.photos as profile_photos
            FROM chats c
            LEFT JOIN dating_profiles dp ON c.profile_id = dp.id
            WHERE c.telegram_user_id = ?
            ORDER BY c.last_message_at DESC
        """, (telegram_user_id,))
        chats = cursor.fetchall()
        return [dict(c) for c in chats]


def add_order(order_data: Dict) -> int:
    """Add new order"""
    from datetime import datetime
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO orders (telegram_user_id, profile_id, service_type, amount,
                               currency, payment_method, payment_wallet, status, created_at, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            order_data.get('telegram_user_id'), order_data['profile_id'],
            order_data['service_type'], order_data['amount'], order_data.get('currency', 'USD'),
            order_data.get('payment_method'), order_data.get('payment_wallet'),
            order_data.get('status', 'pending'), datetime.now().isoformat(),
            order_data.get('details')
        ))
        return cursor.lastrowid


def get_user_orders(telegram_user_id: int) -> List[Dict]:
    """Get all orders for a user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT o.*, dp.name as profile_name
            FROM orders o
            LEFT JOIN dating_profiles dp ON o.profile_id = dp.id
            WHERE o.telegram_user_id = ?
            ORDER BY o.created_at DESC
        """, (telegram_user_id,))
        orders = cursor.fetchall()
        return [dict(o) for o in orders]


def add_comment(comment_data: Dict) -> int:
    """Add new comment"""
    from datetime import datetime
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO comments (profile_id, telegram_user_id, author_name, rating, comment, created_at, visible)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            comment_data['profile_id'], comment_data.get('telegram_user_id'),
            comment_data.get('author_name'), comment_data['rating'],
            comment_data.get('comment'), datetime.now().isoformat(),
            comment_data.get('visible', 1)
        ))
        return cursor.lastrowid


def get_profile_comments(profile_id: int) -> List[Dict]:
    """Get comments for a profile"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM comments
            WHERE profile_id = ? AND visible = 1
            ORDER BY created_at DESC
        """, (profile_id,))
        comments = cursor.fetchall()
        return [dict(c) for c in comments]


def get_promocode_by_code(code: str) -> Optional[Dict]:
    """Get promocode by code"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM promocodes WHERE code = ? AND active = 1", (code,))
        promo = cursor.fetchone()
        return dict(promo) if promo else None


def get_app_setting(key: str) -> Optional[str]:
    """Get app setting by key"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM app_settings WHERE key = ?", (key,))
        result = cursor.fetchone()
        return result['value'] if result else None


def set_app_setting(key: str, value: str):
    """Set app setting"""
    from datetime import datetime
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO app_settings (key, value, updated_at)
            VALUES (?, ?, ?)
        """, (key, value, datetime.now().isoformat()))


# ==================== SESSION MANAGEMENT ====================

def create_session(session_id: str, telegram_id: int, user_data: dict, expires_at: str) -> bool:
    """
    Create new session in database
    Returns True on success
    """
    import json
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO sessions (session_id, telegram_id, user_data, expires_at)
                VALUES (?, ?, ?, ?)
            """, (session_id, telegram_id, json.dumps(user_data), expires_at))
            logger.info(f"✅ Session created: {session_id} (user: {telegram_id})")
            return True
        except Exception as e:
            logger.error(f"❌ Error creating session: {e}")
            return False


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """
    Get session from database
    Returns user_data dict or None if not found/expired
    """
    import json
    from datetime import datetime
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_data, expires_at FROM sessions
            WHERE session_id = ?
        """, (session_id,))
        
        result = cursor.fetchone()
        if not result:
            return None
        
        # Проверяем истечение
        expires_at = datetime.fromisoformat(result['expires_at'])
        if datetime.now() > expires_at:
            # Удаляем истекшую сессию
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            logger.info(f"🗑️ Expired session deleted: {session_id}")
            return None
        
        # Обновляем last_activity
        cursor.execute("""
            UPDATE sessions SET last_activity = CURRENT_TIMESTAMP
            WHERE session_id = ?
        """, (session_id,))
        
        user_data = json.loads(result['user_data'])
        return user_data


def delete_session(session_id: str) -> bool:
    """
    Delete session from database
    Returns True if deleted
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        if cursor.rowcount > 0:
            logger.info(f"✅ Session deleted: {session_id}")
            return True
        return False


def cleanup_expired_sessions():
    """
    Delete all expired sessions (можно вызывать периодически)
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP")
        if cursor.rowcount > 0:
            logger.info(f"🗑️ Cleaned up {cursor.rowcount} expired sessions")


# Initialize database on module import
if not os.path.exists(DATABASE_PATH):
    logger.info("📦 Creating new database...")
    init_database()
else:
    logger.info("✅ Database already exists")

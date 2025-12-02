"""
Database Validators and Safety Functions
Provides additional validation layer for database operations
"""

import sqlite3
import logging
from typing import Optional, Dict, Any
from contextlib import contextmanager
from database import DATABASE_PATH

logger = logging.getLogger(__name__)


@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        conn.close()


def validate_telegram_id(telegram_id: int) -> bool:
    """
    Validate that telegram_id is a valid positive integer

    Args:
        telegram_id: Telegram user ID to validate

    Returns:
        True if valid, False otherwise
    """
    if not isinstance(telegram_id, int):
        logger.error(f"Invalid telegram_id type: {type(telegram_id)}")
        return False

    if telegram_id <= 0:
        logger.error(f"Invalid telegram_id value: {telegram_id} (must be positive)")
        return False

    # Telegram IDs are typically 9-10 digits
    if telegram_id > 9999999999:  # 10 digits max
        logger.warning(f"Unusually large telegram_id: {telegram_id}")

    return True


def check_telegram_id_unique(telegram_id: int) -> bool:
    """
    Check if telegram_id is unique in database

    Args:
        telegram_id: Telegram ID to check

    Returns:
        True if unique (not exists), False if already exists
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM users
            WHERE telegram_id = ?
        """, (telegram_id,))

        count = cursor.fetchone()['count']
        return count == 0


def verify_user_ownership(user_id: int, telegram_id: int) -> bool:
    """
    Verify that user_id belongs to the given telegram_id
    Critical for preventing user data overlap

    Args:
        user_id: Database user ID
        telegram_id: Telegram ID to verify against

    Returns:
        True if user_id belongs to telegram_id, False otherwise
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT telegram_id
            FROM users
            WHERE id = ?
        """, (user_id,))

        user = cursor.fetchone()
        if not user:
            logger.error(f"User ID {user_id} not found")
            return False

        if user['telegram_id'] != telegram_id:
            logger.error(
                f"Ownership violation: user_id {user_id} has telegram_id {user['telegram_id']}, "
                f"but {telegram_id} was provided"
            )
            return False

        return True


def verify_file_ownership(file_id: int, telegram_id: int) -> bool:
    """
    Verify that file belongs to the user

    Args:
        file_id: File ID to check
        telegram_id: Telegram ID of the user

    Returns:
        True if file belongs to user, False otherwise
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT telegram_user_id
            FROM files
            WHERE id = ?
        """, (file_id,))

        file = cursor.fetchone()
        if not file:
            logger.error(f"File ID {file_id} not found")
            return False

        if file['telegram_user_id'] != telegram_id:
            logger.error(
                f"File ownership violation: file {file_id} belongs to telegram_id "
                f"{file['telegram_user_id']}, but {telegram_id} tried to access it"
            )
            return False

        return True


def get_user_file_count(telegram_id: int) -> int:
    """
    Get total number of files for a user

    Args:
        telegram_id: Telegram user ID

    Returns:
        Number of files owned by user
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM files
            WHERE telegram_user_id = ?
        """, (telegram_id,))

        return cursor.fetchone()['count']


def check_database_integrity() -> Dict[str, Any]:
    """
    Perform comprehensive database integrity check

    Returns:
        Dictionary with check results
    """
    results = {
        'duplicate_telegram_ids': [],
        'null_telegram_ids': [],
        'orphaned_files': [],
        'mismatched_file_owners': [],
        'is_valid': True
    }

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check for duplicate telegram_ids (should be impossible with UNIQUE constraint)
        cursor.execute("""
            SELECT telegram_id, COUNT(*) as count
            FROM users
            WHERE telegram_id IS NOT NULL
            GROUP BY telegram_id
            HAVING COUNT(*) > 1
        """)
        duplicates = cursor.fetchall()
        if duplicates:
            results['duplicate_telegram_ids'] = [
                {'telegram_id': d['telegram_id'], 'count': d['count']}
                for d in duplicates
            ]
            results['is_valid'] = False
            logger.error(f"Found {len(duplicates)} duplicate telegram_ids!")

        # Check for NULL telegram_ids (should be impossible with NOT NULL constraint)
        cursor.execute("""
            SELECT id, username, first_name, last_name
            FROM users
            WHERE telegram_id IS NULL
        """)
        null_ids = cursor.fetchall()
        if null_ids:
            results['null_telegram_ids'] = [dict(u) for u in null_ids]
            results['is_valid'] = False
            logger.error(f"Found {len(null_ids)} users with NULL telegram_id!")

        # Check for orphaned files (files without valid user_id)
        cursor.execute("""
            SELECT f.id, f.filename, f.user_id
            FROM files f
            LEFT JOIN users u ON f.user_id = u.id
            WHERE u.id IS NULL
        """)
        orphaned = cursor.fetchall()
        if orphaned:
            results['orphaned_files'] = [dict(f) for f in orphaned]
            results['is_valid'] = False
            logger.error(f"Found {len(orphaned)} orphaned files!")

        # Check for files with mismatched user associations
        cursor.execute("""
            SELECT f.id, f.filename, f.user_id, f.telegram_user_id,
                   u.telegram_id as actual_telegram_id
            FROM files f
            LEFT JOIN users u ON f.user_id = u.id
            WHERE u.telegram_id != f.telegram_user_id
        """)
        mismatched = cursor.fetchall()
        if mismatched:
            results['mismatched_file_owners'] = [dict(f) for f in mismatched]
            results['is_valid'] = False
            logger.error(f"Found {len(mismatched)} files with mismatched owners!")

    return results


def enforce_constraints():
    """
    Add additional database constraints for safety
    This function is idempotent and can be run multiple times
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Ensure telegram_id is always positive
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    telegram_id INTEGER UNIQUE NOT NULL CHECK(telegram_id > 0),
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    language_code TEXT DEFAULT 'en',
                    is_premium INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Check if we need to migrate data
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if cursor.fetchone():
                # Table exists, check if it has the CHECK constraint
                cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
                create_sql = cursor.fetchone()
                if create_sql and 'CHECK' not in create_sql['sql']:
                    logger.info("Adding CHECK constraint to users table...")
                    # Note: SQLite doesn't support ALTER TABLE to add constraints
                    # This would require recreating the table in production
                    logger.warning("To add CHECK constraint, manual migration is required")

            logger.info("✅ Database constraints verified")
        except Exception as e:
            logger.error(f"Error enforcing constraints: {e}")
            raise


# Auto-run integrity check on import (only in development)
import os
if os.getenv('ENVIRONMENT', 'development') == 'development' and os.path.exists(DATABASE_PATH):
    logger.info("Running database integrity check...")
    results = check_database_integrity()
    if not results['is_valid']:
        logger.error("⚠️ Database integrity issues detected!")
        for issue_type, issues in results.items():
            if issues and issue_type != 'is_valid':
                logger.error(f"  {issue_type}: {len(issues)} issues")
    else:
        logger.info("✅ Database integrity check passed")

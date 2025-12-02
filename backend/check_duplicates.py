"""
Script to check for duplicate telegram_id entries in users table
This helps identify data integrity issues with Telegram user authentication
"""

import sqlite3
import os
import logging
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database path
current_dir = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(current_dir, "app_database.db")


def check_telegram_duplicates() -> List[Dict[str, Any]]:
    """
    Check for duplicate telegram_id entries
    Returns list of telegram_ids that appear more than once
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Find duplicate telegram_ids
        cursor.execute("""
            SELECT telegram_id, COUNT(*) as count
            FROM users
            WHERE telegram_id IS NOT NULL
            GROUP BY telegram_id
            HAVING count > 1
            ORDER BY count DESC
        """)

        duplicates = cursor.fetchall()

        if duplicates:
            logger.warning(f"⚠️  Found {len(duplicates)} duplicate telegram_id entries!")

            for dup in duplicates:
                telegram_id = dup['telegram_id']
                count = dup['count']

                logger.warning(f"\n❌ Telegram ID {telegram_id} appears {count} times")

                # Get details of duplicate users
                cursor.execute("""
                    SELECT id, telegram_id, username, first_name, last_name,
                           user_type, created_at, last_login
                    FROM users
                    WHERE telegram_id = ?
                    ORDER BY created_at
                """, (telegram_id,))

                users = cursor.fetchall()

                for idx, user in enumerate(users, 1):
                    logger.warning(
                        f"   {idx}. User ID: {user['id']}, "
                        f"Username: {user['username']}, "
                        f"Name: {user['first_name']} {user['last_name']}, "
                        f"Type: {user.get('user_type', 'N/A')}, "
                        f"Created: {user['created_at']}"
                    )

            return [dict(d) for d in duplicates]
        else:
            logger.info("✅ No duplicate telegram_id entries found!")
            return []

    finally:
        conn.close()


def check_null_telegram_users() -> int:
    """
    Check for users without telegram_id
    Returns count of users with NULL telegram_id
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM users
            WHERE telegram_id IS NULL
        """)

        count = cursor.fetchone()['count']

        if count > 0:
            logger.info(f"\n📊 Found {count} users without telegram_id")

            # Show some examples
            cursor.execute("""
                SELECT id, username, first_name, last_name, user_type, created_at
                FROM users
                WHERE telegram_id IS NULL
                LIMIT 5
            """)

            users = cursor.fetchall()

            logger.info("   Sample users without telegram_id:")
            for user in users:
                logger.info(
                    f"   - User ID: {user['id']}, "
                    f"Username: {user['username']}, "
                    f"Name: {user['first_name']} {user['last_name']}, "
                    f"Type: {user.get('user_type', 'N/A')}"
                )
        else:
            logger.info("\n✅ All users have telegram_id")

        return count

    finally:
        conn.close()


def check_users_by_type() -> Dict[str, int]:
    """
    Check distribution of users by type (telegram vs web)
    Returns dictionary with counts by user_type
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Check if user_type column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]

        if 'user_type' not in columns:
            logger.warning("\n⚠️  user_type column does not exist yet")
            logger.info("   Run migration: python migrate_add_user_type_and_profiles.py")
            return {}

        cursor.execute("""
            SELECT
                COALESCE(user_type, 'NULL') as user_type,
                COUNT(*) as count
            FROM users
            GROUP BY user_type
            ORDER BY count DESC
        """)

        user_types = cursor.fetchall()

        result = {}
        logger.info("\n📊 Users by type:")

        for ut in user_types:
            user_type = ut['user_type']
            count = ut['count']
            result[user_type] = count
            logger.info(f"   {user_type}: {count} users")

        return result

    finally:
        conn.close()


def check_profiles_status() -> Dict[str, int]:
    """
    Check status of profiles table
    Returns statistics about profiles
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Check if profiles table exists
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='profiles'
        """)

        if not cursor.fetchone():
            logger.warning("\n⚠️  profiles table does not exist yet")
            logger.info("   Run migration: python migrate_add_user_type_and_profiles.py")
            return {}

        # Get total profiles
        cursor.execute("SELECT COUNT(*) as count FROM profiles")
        total_profiles = cursor.fetchone()['count']

        # Get total users
        cursor.execute("SELECT COUNT(*) as count FROM users")
        total_users = cursor.fetchone()['count']

        # Get users without profiles
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM users
            WHERE id NOT IN (SELECT user_id FROM profiles)
        """)
        users_without_profiles = cursor.fetchone()['count']

        result = {
            'total_profiles': total_profiles,
            'total_users': total_users,
            'users_without_profiles': users_without_profiles
        }

        logger.info("\n📊 Profile statistics:")
        logger.info(f"   Total users: {total_users}")
        logger.info(f"   Total profiles: {total_profiles}")
        logger.info(f"   Users without profiles: {users_without_profiles}")

        if users_without_profiles > 0:
            logger.warning("   ⚠️  Some users don't have profiles!")
            logger.info("   You can create them by calling db.get_or_create_profile(user_id)")

        return result

    finally:
        conn.close()


def run_all_checks():
    """Run all duplicate and integrity checks"""
    logger.info("🔍 Running database integrity checks...\n")

    logger.info("=" * 60)
    logger.info("CHECK 1: Duplicate telegram_id entries")
    logger.info("=" * 60)
    duplicates = check_telegram_duplicates()

    logger.info("\n" + "=" * 60)
    logger.info("CHECK 2: Users without telegram_id")
    logger.info("=" * 60)
    null_count = check_null_telegram_users()

    logger.info("\n" + "=" * 60)
    logger.info("CHECK 3: User type distribution")
    logger.info("=" * 60)
    user_types = check_users_by_type()

    logger.info("\n" + "=" * 60)
    logger.info("CHECK 4: Profile status")
    logger.info("=" * 60)
    profile_stats = check_profiles_status()

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("SUMMARY")
    logger.info("=" * 60)

    if duplicates:
        logger.error(f"❌ Found {len(duplicates)} duplicate telegram_id entries - ACTION REQUIRED!")
    else:
        logger.info("✅ No duplicate telegram_id entries")

    if null_count > 0:
        logger.info(f"ℹ️  {null_count} users without telegram_id (might be web users)")

    if profile_stats and profile_stats.get('users_without_profiles', 0) > 0:
        logger.warning(f"⚠️  {profile_stats['users_without_profiles']} users without profiles")
    elif profile_stats:
        logger.info("✅ All users have profiles")

    logger.info("\n✅ Integrity checks completed!")


if __name__ == "__main__":
    run_all_checks()

"""
Database migration: Add user_type field and profiles table
This migration adds:
1. user_type field to users table (telegram/web)
2. profiles table for user profiles (avatar, bio)
"""

import sqlite3
import os
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database path
current_dir = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(current_dir, "app_database.db")


def run_migration():
    """Run database migration"""
    logger.info("🚀 Starting migration: Add user_type and profiles")

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    try:
        # Step 1: Check if user_type column already exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]

        if 'user_type' not in columns:
            logger.info("➕ Adding user_type column to users table...")
            cursor.execute("""
                ALTER TABLE users
                ADD COLUMN user_type TEXT DEFAULT 'telegram'
                CHECK(user_type IN ('telegram', 'web'))
            """)
            logger.info("✅ user_type column added")
        else:
            logger.info("⏭️  user_type column already exists, skipping")

        # Step 2: Update existing users to have user_type = 'telegram'
        logger.info("🔄 Updating existing users to user_type='telegram'...")
        cursor.execute("""
            UPDATE users
            SET user_type = 'telegram'
            WHERE user_type IS NULL OR user_type = ''
        """)
        updated_count = cursor.rowcount
        logger.info(f"✅ Updated {updated_count} users")

        # Step 3: Create profiles table
        logger.info("➕ Creating profiles table...")
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
        logger.info("✅ Profiles table created")

        # Step 4: Create index on user_id for performance
        logger.info("➕ Creating index on profiles.user_id...")
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_profiles_user_id
            ON profiles(user_id)
        """)
        logger.info("✅ Index created")

        # Step 5: Create profiles for existing users
        logger.info("➕ Creating profiles for existing users...")
        cursor.execute("""
            INSERT OR IGNORE INTO profiles (user_id, bio)
            SELECT id, '' FROM users
        """)
        profile_count = cursor.rowcount
        logger.info(f"✅ Created {profile_count} profiles")

        # Commit changes
        conn.commit()
        logger.info("✅ Migration completed successfully!")

        # Show statistics
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM profiles")
        profile_count = cursor.fetchone()[0]

        cursor.execute("SELECT user_type, COUNT(*) FROM users GROUP BY user_type")
        user_types = cursor.fetchall()

        logger.info("\n📊 Database Statistics:")
        logger.info(f"   Total users: {user_count}")
        logger.info(f"   Total profiles: {profile_count}")
        logger.info("   Users by type:")
        for user_type, count in user_types:
            logger.info(f"      {user_type}: {count}")

    except Exception as e:
        conn.rollback()
        logger.error(f"❌ Migration failed: {e}")
        raise
    finally:
        conn.close()


def rollback_migration():
    """Rollback migration (remove user_type and profiles table)"""
    logger.info("⏮️  Rolling back migration...")

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    try:
        # Note: SQLite doesn't support DROP COLUMN directly
        # We would need to recreate the table without the column
        logger.info("⚠️  WARNING: SQLite doesn't support DROP COLUMN")
        logger.info("    To rollback, you would need to restore from backup")

        # We can drop the profiles table
        logger.info("🗑️  Dropping profiles table...")
        cursor.execute("DROP TABLE IF EXISTS profiles")

        conn.commit()
        logger.info("✅ Profiles table dropped")
        logger.info("⚠️  user_type column remains (SQLite limitation)")

    except Exception as e:
        conn.rollback()
        logger.error(f"❌ Rollback failed: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "rollback":
        rollback_migration()
    else:
        run_migration()

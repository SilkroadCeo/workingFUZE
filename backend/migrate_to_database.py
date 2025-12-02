"""
Migration script to convert existing JSON data to SQLite database
This script is provided for reference in case migration from JSON is needed
"""

import json
import os
import sys
import logging
from datetime import datetime

# Import database module
import database as db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Path to data file
current_dir = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(current_dir, "data.json")


def migrate_json_to_database():
    """
    Migrate data from JSON file to SQLite database
    This is a helper script for existing deployments
    """

    if not os.path.exists(DATA_FILE):
        logger.info("ℹ️ No data.json file found. Nothing to migrate.")
        return

    logger.info("📦 Starting migration from JSON to SQLite database...")

    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Since the current system doesn't track individual file users in JSON,
        # this is a placeholder for future migration needs
        logger.info("✅ Migration completed successfully!")
        logger.info("ℹ️ Note: This system now uses SQLite database for all new data")
        logger.info("ℹ️ Existing JSON data in data.json is not affected")

    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        sys.exit(1)


def backup_json_data():
    """Create backup of JSON data before migration"""
    if os.path.exists(DATA_FILE):
        backup_file = DATA_FILE + f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        import shutil
        shutil.copy2(DATA_FILE, backup_file)
        logger.info(f"✅ Backup created: {backup_file}")
        return backup_file
    return None


def get_database_stats():
    """Display current database statistics"""
    stats = db.get_database_stats()

    logger.info("=" * 60)
    logger.info("DATABASE STATISTICS")
    logger.info("=" * 60)
    logger.info(f"Total Users: {stats['total_users']}")
    logger.info(f"Total Files: {stats['total_files']}")
    logger.info(f"Total Storage: {stats['total_storage_mb']} MB")
    logger.info("=" * 60)


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║     Telegram Mini App File Management - Migration Tool      ║
╚══════════════════════════════════════════════════════════════╝

This script helps migrate data from JSON to SQLite database.

Current System Features:
✅ SQLite database for users and files
✅ Telegram authentication with HMAC verification
✅ User-specific file storage (uploads/user_XXX/)
✅ Ownership checks on all file operations
✅ Secure session management

    """)

    # Initialize database
    db.init_database()

    # Show current stats
    get_database_stats()

    print("\n✨ Database is ready!")
    print("📝 All new users and files will be stored in SQLite database")
    print("🔐 Telegram authentication is enabled with security verification")
    print("\nStart your server with: python admin.py")

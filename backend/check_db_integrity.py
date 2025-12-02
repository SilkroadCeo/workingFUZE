#!/usr/bin/env python3
"""
Database Integrity Checker for Telegram User Overlap Issues
Checks for potential user data isolation problems
"""

import sqlite3
import os
import sys
from datetime import datetime
from typing import List, Dict, Any

# Database path
DATABASE_PATH = os.path.join(os.path.dirname(__file__), "app_database.db")


def get_connection():
    """Get database connection"""
    if not os.path.exists(DATABASE_PATH):
        print(f"❌ Database not found at {DATABASE_PATH}")
        print("ℹ️  Database will be created when the application first runs")
        return None

    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def check_schema():
    """Check database schema for security issues"""
    print("\n" + "="*60)
    print("📋 CHECKING DATABASE SCHEMA")
    print("="*60)

    conn = get_connection()
    if not conn:
        return

    try:
        cursor = conn.cursor()

        # Get users table schema
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()

        print("\n✅ Users Table Schema:")
        print("-" * 60)
        for col in columns:
            col_dict = dict(col)
            nullable = "NULL" if col_dict['notnull'] == 0 else "NOT NULL"
            pk = "PRIMARY KEY" if col_dict['pk'] else ""
            print(f"  {col_dict['name']:20} {col_dict['type']:15} {nullable:10} {pk}")

        # Check for UNIQUE constraints
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
        create_sql = cursor.fetchone()
        if create_sql:
            print("\n📝 Table Definition:")
            print("-" * 60)
            print(create_sql['sql'])

        # Check indexes
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='users'")
        indexes = cursor.fetchall()
        if indexes:
            print("\n🔍 Indexes on users table:")
            print("-" * 60)
            for idx in indexes:
                print(f"  {idx['name']}: {idx['sql']}")

    finally:
        conn.close()


def check_duplicate_telegram_ids():
    """Check for duplicate telegram_id values"""
    print("\n" + "="*60)
    print("🔍 CHECKING FOR DUPLICATE TELEGRAM IDs")
    print("="*60)

    conn = get_connection()
    if not conn:
        return

    try:
        cursor = conn.cursor()

        # Check for duplicate telegram_ids
        cursor.execute("""
            SELECT telegram_id, COUNT(*) as count
            FROM users
            WHERE telegram_id IS NOT NULL
            GROUP BY telegram_id
            HAVING COUNT(*) > 1
        """)

        duplicates = cursor.fetchall()

        if duplicates:
            print("\n❌ CRITICAL: Found duplicate telegram_ids:")
            for dup in duplicates:
                print(f"  telegram_id {dup['telegram_id']}: {dup['count']} users")

                # Show affected users
                cursor.execute("""
                    SELECT id, username, first_name, last_name, created_at
                    FROM users
                    WHERE telegram_id = ?
                """, (dup['telegram_id'],))
                users = cursor.fetchall()

                for user in users:
                    print(f"    - User ID {user['id']}: {user['first_name']} {user['last_name']} "
                          f"(@{user['username']}) created {user['created_at']}")
        else:
            print("\n✅ No duplicate telegram_ids found")

        # Check for NULL telegram_ids (should not exist with NOT NULL constraint)
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE telegram_id IS NULL")
        null_count = cursor.fetchone()['count']

        if null_count > 0:
            print(f"\n⚠️  WARNING: Found {null_count} users with NULL telegram_id")
            cursor.execute("""
                SELECT id, username, first_name, last_name, created_at
                FROM users
                WHERE telegram_id IS NULL
                LIMIT 5
            """)
            null_users = cursor.fetchall()
            for user in null_users:
                print(f"  - User ID {user['id']}: {user['first_name']} {user['last_name']} "
                      f"(@{user['username']}) created {user['created_at']}")
        else:
            print("✅ No NULL telegram_ids found")

    finally:
        conn.close()


def check_user_file_isolation():
    """Check if files are properly isolated by user"""
    print("\n" + "="*60)
    print("🔒 CHECKING USER-FILE ISOLATION")
    print("="*60)

    conn = get_connection()
    if not conn:
        return

    try:
        cursor = conn.cursor()

        # Check if any files have mismatched user_id and telegram_user_id
        cursor.execute("""
            SELECT f.id, f.filename, f.user_id, f.telegram_user_id,
                   u1.telegram_id as user_telegram_id
            FROM files f
            LEFT JOIN users u1 ON f.user_id = u1.id
            WHERE u1.telegram_id != f.telegram_user_id
            LIMIT 10
        """)

        mismatches = cursor.fetchall()

        if mismatches:
            print("\n❌ CRITICAL: Found files with mismatched user associations:")
            for file in mismatches:
                print(f"  File ID {file['id']} ({file['filename']}):")
                print(f"    user_id points to telegram_id: {file['user_telegram_id']}")
                print(f"    telegram_user_id field: {file['telegram_user_id']}")
        else:
            print("\n✅ All files are properly associated with their users")

        # Check for orphaned files (files without valid user_id)
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM files f
            LEFT JOIN users u ON f.user_id = u.id
            WHERE u.id IS NULL
        """)

        orphaned = cursor.fetchone()['count']
        if orphaned > 0:
            print(f"\n⚠️  WARNING: Found {orphaned} orphaned files (no valid user_id)")
        else:
            print("✅ No orphaned files found")

    finally:
        conn.close()


def get_database_stats():
    """Get overall database statistics"""
    print("\n" + "="*60)
    print("📊 DATABASE STATISTICS")
    print("="*60)

    conn = get_connection()
    if not conn:
        return

    try:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as count FROM users")
        user_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM files")
        file_count = cursor.fetchone()['count']

        cursor.execute("SELECT COALESCE(SUM(file_size), 0) as total FROM files")
        total_size = cursor.fetchone()['total']

        print(f"\n  Total Users: {user_count}")
        print(f"  Total Files: {file_count}")
        print(f"  Total Storage: {total_size:,} bytes ({total_size / (1024*1024):.2f} MB)")

        # Get user with most files
        cursor.execute("""
            SELECT u.telegram_id, u.first_name, u.last_name, COUNT(f.id) as file_count
            FROM users u
            LEFT JOIN files f ON u.telegram_id = f.telegram_user_id
            GROUP BY u.id
            ORDER BY file_count DESC
            LIMIT 5
        """)

        top_users = cursor.fetchall()
        if top_users and top_users[0]['file_count'] > 0:
            print("\n  Top 5 users by file count:")
            for user in top_users:
                if user['file_count'] > 0:
                    print(f"    {user['first_name']} {user['last_name']} "
                          f"(telegram_id: {user['telegram_id']}): {user['file_count']} files")

    finally:
        conn.close()


def main():
    """Run all integrity checks"""
    print("\n" + "="*60)
    print("🔐 DATABASE INTEGRITY CHECK")
    print("="*60)
    print(f"Database: {DATABASE_PATH}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if not os.path.exists(DATABASE_PATH):
        print("\n⚠️  Database does not exist yet.")
        print("ℹ️  It will be created when the application first runs.")
        return

    # Run all checks
    check_schema()
    check_duplicate_telegram_ids()
    check_user_file_isolation()
    get_database_stats()

    print("\n" + "="*60)
    print("✅ INTEGRITY CHECK COMPLETE")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()

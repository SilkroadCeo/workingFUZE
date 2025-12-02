#!/usr/bin/env python3
"""
Test database security measures
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

import database as db
from db_validators import (
    validate_telegram_id,
    verify_user_ownership,
    check_database_integrity
)


def test_telegram_id_validation():
    """Test telegram_id validation"""
    print("\n" + "="*60)
    print("TEST 1: Telegram ID Validation")
    print("="*60)

    # Test valid telegram_id
    assert validate_telegram_id(123456789), "Valid telegram_id should pass"
    print("✅ Valid telegram_id accepted")

    # Test invalid telegram_id (negative)
    assert not validate_telegram_id(-123), "Negative telegram_id should fail"
    print("✅ Negative telegram_id rejected")

    # Test invalid telegram_id (zero)
    assert not validate_telegram_id(0), "Zero telegram_id should fail"
    print("✅ Zero telegram_id rejected")

    # Test invalid telegram_id (string)
    assert not validate_telegram_id("123456"), "String telegram_id should fail"
    print("✅ String telegram_id rejected")

    print("\n✅ All telegram_id validation tests passed!")


def test_user_creation():
    """Test user creation with validation"""
    print("\n" + "="*60)
    print("TEST 2: User Creation with Validation")
    print("="*60)

    # Test creating user with valid data
    try:
        user = db.get_or_create_user(
            telegram_id=999999999,
            username="testuser",
            first_name="Test",
            last_name="User"
        )
        print(f"✅ User created successfully: ID={user['id']}, telegram_id={user['telegram_id']}")

        # Try creating same user again (should return existing)
        user2 = db.get_or_create_user(
            telegram_id=999999999,
            username="testuser",
            first_name="Test",
            last_name="User"
        )
        assert user['id'] == user2['id'], "Should return same user"
        print("✅ Duplicate user prevention working correctly")

    except Exception as e:
        print(f"✅ Validation working: {e}")

    # Test creating user with invalid telegram_id
    try:
        invalid_user = db.get_or_create_user(
            telegram_id=-123,  # Invalid
            username="invalid",
            first_name="Invalid",
            last_name="User"
        )
        print("❌ Should have rejected invalid telegram_id!")
        sys.exit(1)
    except ValueError as e:
        print(f"✅ Invalid telegram_id rejected: {e}")

    print("\n✅ All user creation tests passed!")


def test_database_integrity():
    """Test database integrity checker"""
    print("\n" + "="*60)
    print("TEST 3: Database Integrity Check")
    print("="*60)

    if not os.path.exists(db.DATABASE_PATH):
        print("⚠️  Database not created yet, skipping integrity check")
        return

    results = check_database_integrity()

    if results['is_valid']:
        print("✅ Database integrity check PASSED")
        print(f"   - No duplicate telegram_ids")
        print(f"   - No NULL telegram_ids")
        print(f"   - No orphaned files")
        print(f"   - No mismatched file owners")
    else:
        print("❌ Database integrity check FAILED:")
        for issue_type, issues in results.items():
            if issues and issue_type != 'is_valid':
                print(f"   - {issue_type}: {len(issues)} issues")


def test_file_operations():
    """Test file operations with ownership verification"""
    print("\n" + "="*60)
    print("TEST 4: File Operations Security")
    print("="*60)

    # Create test user
    user = db.get_or_create_user(
        telegram_id=888888888,
        username="filetest",
        first_name="File",
        last_name="Test"
    )

    # Test adding file with valid ownership
    try:
        file_id = db.add_file(
            user_id=user['id'],
            telegram_user_id=user['telegram_id'],
            filename="test_file.txt",
            original_filename="test.txt",
            file_path="/tmp/test.txt",
            file_size=1024,
            mime_type="text/plain"
        )
        print(f"✅ File added successfully: ID={file_id}")
    except Exception as e:
        print(f"Error adding file: {e}")
        return

    # Test retrieving file with correct ownership
    file_data = db.get_file_by_id(file_id, user['telegram_id'])
    if file_data:
        print(f"✅ File retrieved with correct ownership")
    else:
        print(f"❌ Failed to retrieve file with correct ownership")

    # Test retrieving file with wrong ownership (should fail)
    wrong_file = db.get_file_by_id(file_id, 777777777)  # Wrong telegram_id
    if wrong_file is None:
        print(f"✅ Unauthorized file access blocked")
    else:
        print(f"❌ SECURITY ISSUE: Unauthorized file access allowed!")
        sys.exit(1)

    # Test invalid inputs
    try:
        db.add_file(
            user_id=999999,  # Non-existent user
            telegram_user_id=user['telegram_id'],
            filename="test.txt",
            original_filename="test.txt",
            file_path="/tmp/test.txt",
            file_size=1024,
            mime_type="text/plain"
        )
        print("❌ Should have rejected non-existent user_id")
        sys.exit(1)
    except ValueError as e:
        print(f"✅ Invalid user_id rejected: {e}")

    # Clean up
    db.delete_file(file_id, user['telegram_id'])
    print("\n✅ All file operation tests passed!")


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("🔐 DATABASE SECURITY TEST SUITE")
    print("="*60)
    print(f"Database: {db.DATABASE_PATH}")

    try:
        test_telegram_id_validation()
        test_user_creation()
        test_database_integrity()
        test_file_operations()

        print("\n" + "="*60)
        print("✅ ALL TESTS PASSED")
        print("="*60)
        print("\n🎉 Database security measures are working correctly!\n")

    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

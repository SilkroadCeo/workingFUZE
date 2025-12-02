#!/usr/bin/env python3
"""
Migrate data from data.json to SQLite database
This script migrates all data from JSON file to the unified database
"""

import json
import os
import logging
import database as db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

current_dir = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(current_dir, "data.json")


def migrate_data():
    """Migrate data from JSON to database"""
    if not os.path.exists(DATA_FILE):
        logger.error(f"❌ {DATA_FILE} not found!")
        return

    logger.info("📦 Loading data from data.json...")
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Initialize database
    db.init_database()

    # Migrate profiles
    logger.info("🔄 Migrating dating profiles...")
    for profile in data.get('profiles', []):
        try:
            profile_data = {
                'name': profile['name'],
                'age': profile['age'],
                'gender': profile['gender'],
                'nationality': profile.get('nationality'),
                'city': profile.get('city'),
                'travel_cities': json.dumps(profile.get('travel_cities', [])),
                'description': profile.get('description'),
                'photos': json.dumps(profile.get('photos', [])),
                'visible': profile.get('visible', True),
                'created_at': profile.get('created_at'),
                'height': profile.get('height'),
                'weight': profile.get('weight'),
                'chest': profile.get('chest')
            }
            db.add_dating_profile(profile_data)
            logger.info(f"✅ Migrated profile: {profile['name']}")
        except Exception as e:
            logger.error(f"❌ Failed to migrate profile {profile.get('name')}: {e}")

    # Migrate VIP profiles
    logger.info("🔄 Migrating VIP profiles...")
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        for vip in data.get('vip_profiles', []):
            try:
                cursor.execute("""
                    INSERT INTO vip_profiles (name, age, gender, nationality, city,
                                             travel_cities, description, photos, visible,
                                             created_at, height, weight, chest)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    vip['name'], vip['age'], vip['gender'],
                    vip.get('nationality'), vip.get('city'),
                    json.dumps(vip.get('travel_cities', [])),
                    vip.get('description'),
                    json.dumps(vip.get('photos', [])),
                    vip.get('visible', True),
                    vip.get('created_at'),
                    vip.get('height'), vip.get('weight'), vip.get('chest')
                ))
                logger.info(f"✅ Migrated VIP profile: {vip['name']}")
            except Exception as e:
                logger.error(f"❌ Failed to migrate VIP profile {vip.get('name')}: {e}")

    # Migrate chats and messages
    logger.info("🔄 Migrating chats and messages...")
    for chat in data.get('chats', []):
        try:
            with db.get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO chats (id, profile_id, telegram_user_id, created_at, last_message_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    chat['id'], chat['profile_id'], chat.get('telegram_user_id'),
                    chat.get('created_at'), chat.get('last_message_at')
                ))
                logger.info(f"✅ Migrated chat: {chat['id']}")
        except Exception as e:
            logger.error(f"❌ Failed to migrate chat {chat.get('id')}: {e}")

    for message in data.get('messages', []):
        try:
            with db.get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO messages (id, chat_id, profile_id, telegram_user_id,
                                        sender_type, content, timestamp, is_read)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    message['id'], message['chat_id'], message['profile_id'],
                    message.get('telegram_user_id'), message['sender_type'],
                    message['content'], message['timestamp'], message.get('is_read', 0)
                ))
        except Exception as e:
            logger.error(f"❌ Failed to migrate message {message.get('id')}: {e}")

    # Migrate orders
    logger.info("🔄 Migrating orders...")
    for order in data.get('orders', []):
        try:
            with db.get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO orders (id, telegram_user_id, profile_id, service_type,
                                      amount, currency, payment_method, payment_wallet,
                                      status, created_at, confirmed_at, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    order['id'], order.get('telegram_user_id'), order['profile_id'],
                    order['service_type'], order['amount'], order.get('currency', 'USD'),
                    order.get('payment_method'), order.get('payment_wallet'),
                    order.get('status', 'pending'), order.get('created_at'),
                    order.get('confirmed_at'), json.dumps(order.get('details', {}))
                ))
                logger.info(f"✅ Migrated order: {order['id']}")
        except Exception as e:
            logger.error(f"❌ Failed to migrate order {order.get('id')}: {e}")

    # Migrate comments
    logger.info("🔄 Migrating comments...")
    for comment in data.get('comments', []):
        try:
            comment_data = {
                'profile_id': comment['profile_id'],
                'telegram_user_id': comment.get('telegram_user_id'),
                'author_name': comment.get('author_name'),
                'rating': comment['rating'],
                'comment': comment.get('comment'),
                'visible': comment.get('visible', True)
            }
            db.add_comment(comment_data)
            logger.info(f"✅ Migrated comment for profile: {comment['profile_id']}")
        except Exception as e:
            logger.error(f"❌ Failed to migrate comment: {e}")

    # Migrate promocodes
    logger.info("🔄 Migrating promocodes...")
    for promo in data.get('promocodes', []):
        try:
            with db.get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO promocodes (code, discount_percent, max_uses,
                                          current_uses, valid_until, active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    promo['code'], promo['discount_percent'], promo.get('max_uses'),
                    promo.get('current_uses', 0), promo.get('valid_until'),
                    promo.get('active', True), promo.get('created_at')
                ))
                logger.info(f"✅ Migrated promocode: {promo['code']}")
        except Exception as e:
            logger.error(f"❌ Failed to migrate promocode {promo.get('code')}: {e}")

    # Migrate settings
    logger.info("🔄 Migrating settings...")
    settings = data.get('settings', {})
    try:
        for category, values in settings.items():
            db.set_app_setting(category, json.dumps(values))
            logger.info(f"✅ Migrated setting category: {category}")
    except Exception as e:
        logger.error(f"❌ Failed to migrate settings: {e}")

    logger.info("✅ Migration completed!")
    logger.info(f"📊 Summary:")
    logger.info(f"   - Profiles: {len(data.get('profiles', []))}")
    logger.info(f"   - VIP Profiles: {len(data.get('vip_profiles', []))}")
    logger.info(f"   - Chats: {len(data.get('chats', []))}")
    logger.info(f"   - Messages: {len(data.get('messages', []))}")
    logger.info(f"   - Orders: {len(data.get('orders', []))}")
    logger.info(f"   - Comments: {len(data.get('comments', []))}")
    logger.info(f"   - Promocodes: {len(data.get('promocodes', []))}")


if __name__ == "__main__":
    logger.info("🚀 Starting data migration from data.json to SQLite...")
    migrate_data()

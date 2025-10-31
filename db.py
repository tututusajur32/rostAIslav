import sqlite3
import time
from typing import Set

DB_PATH = "ai_usage.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # usage table (existing)
    c.execute("""
        CREATE TABLE IF NOT EXISTS usage (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            count INTEGER DEFAULT 0
        )
    """)
    # role editors (who can set roles)
    c.execute("""
        CREATE TABLE IF NOT EXISTS role_editors (
            user_id INTEGER PRIMARY KEY
        )
    """)
    # global settings (key/value)
    c.execute("""
        CREATE TABLE IF NOT EXISTS global_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    # disabled private users (who disabled AI in DM)
    c.execute("""
        CREATE TABLE IF NOT EXISTS disabled_private (
            user_id INTEGER PRIMARY KEY
        )
    """)
    # blacklist (users banned from using AI)
    c.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            user_id INTEGER PRIMARY KEY
        )
    """)
    # balances (currency 'рости')
    c.execute("""
        CREATE TABLE IF NOT EXISTS balances (
            user_id INTEGER PRIMARY KEY,
            amount INTEGER DEFAULT 0
        )
    """)
    # shops (магазины)
    c.execute("""
        CREATE TABLE IF NOT EXISTS shops (
            user_id INTEGER PRIMARY KEY,
            name TEXT DEFAULT 'Безымянный магазин',
            last_collection INTEGER DEFAULT 0
        )
    """)

    # nicknames table: user_id primary key, nickname unique
    c.execute("""
        CREATE TABLE IF NOT EXISTS nicknames (
            user_id INTEGER PRIMARY KEY,
            nickname TEXT UNIQUE
        )
    """)

    conn.commit()
    conn.close()


# role editors DB helpers
def add_role_editor_db(user_id: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT OR IGNORE INTO role_editors(user_id) VALUES (?)", (user_id,))
        conn.commit()
    finally:
        conn.close()


def remove_role_editor_db(user_id: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("DELETE FROM role_editors WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def get_role_editors_db() -> Set[int]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT user_id FROM role_editors")
        rows = c.fetchall()
        return set(r[0] for r in rows)
    finally:
        conn.close()


# global settings
def set_global_role_db(value: str | None) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        if value is None:
            c.execute("DELETE FROM global_settings WHERE key = 'global_role'")
            conn.commit()
        else:
            c.execute("INSERT OR REPLACE INTO global_settings(key, value) VALUES ('global_role', ?)", (value,))
            conn.commit()
    finally:
        conn.close()


def get_global_role_db() -> str | None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT value FROM global_settings WHERE key = 'global_role'")
        row = c.fetchone()
        return row[0] if row and row[0] is not None else None
    finally:
        conn.close()


def set_owners_db(owners: Set[int]) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        value = ",".join(str(int(o)) for o in sorted(owners))
        c.execute("INSERT OR REPLACE INTO global_settings(key, value) VALUES ('owners', ?)", (value,))
        conn.commit()
    finally:
        conn.close()


def get_owners_db() -> Set[int]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT value FROM global_settings WHERE key = 'owners'")
        row = c.fetchone()
        if row and row[0]:
            parts = [p.strip() for p in row[0].split(',') if p.strip()]
            try:
                return set(int(p) for p in parts)
            except Exception:
                return set()
        return set()
    finally:
        conn.close()


def add_owner_db(user_id: int) -> None:
    # read existing, add owner
    owners = get_owners_db()
    owners.add(int(user_id))
    set_owners_db(owners)


# disabled private
def set_disabled_private_db(user_id: int, disabled: bool) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        if disabled:
            c.execute("INSERT OR IGNORE INTO disabled_private(user_id) VALUES (?)", (user_id,))
        else:
            c.execute("DELETE FROM disabled_private WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def get_disabled_private_db() -> Set[int]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT user_id FROM disabled_private")
        rows = c.fetchall()
        return set(r[0] for r in rows)
    finally:
        conn.close()


# blacklist
def add_to_blacklist_db(user_id: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT OR IGNORE INTO blacklist(user_id) VALUES (?)", (user_id,))
        conn.commit()
    finally:
        conn.close()


def remove_from_blacklist_db(user_id: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("DELETE FROM blacklist WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def get_blacklist_db() -> Set[int]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT user_id FROM blacklist")
        rows = c.fetchall()
        return set(r[0] for r in rows)
    finally:
        conn.close()


# balances
def get_balance_db(user_id: int) -> int:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT amount FROM balances WHERE user_id = ?", (user_id,))
        row = c.fetchone()
        if row:
            return int(row[0])
        # initialize with 0
        c.execute("INSERT INTO balances(user_id, amount) VALUES (?, 0)", (user_id,))
        conn.commit()
        return 0
    finally:
        conn.close()


def change_balance_db(user_id: int, delta: int) -> int:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT amount FROM balances WHERE user_id = ?", (user_id,))
        row = c.fetchone()
        if row:
            new = int(row[0]) + delta
            if new < 0:
                new = 0
            c.execute("UPDATE balances SET amount = ? WHERE user_id = ?", (new, user_id))
        else:
            new = max(0, delta)
            c.execute("INSERT INTO balances(user_id, amount) VALUES (?, ?)", (user_id, new))
        conn.commit()
        return new
    finally:
        conn.close()


def get_balances_table():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT user_id, amount FROM balances ORDER BY amount DESC")
        rows = c.fetchall()
    finally:
        conn.close()
    return rows


# usage stats
def increment_usage(user):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Try to update, if not exists then insert
    c.execute("SELECT count FROM usage WHERE user_id = ?", (user.id,))
    row = c.fetchone()
    if row:
        c.execute("UPDATE usage SET count = count + 1 WHERE user_id = ?", (user.id,))
    else:
        c.execute(
            "INSERT INTO usage (user_id, username, first_name, last_name, count) VALUES (?, ?, ?, ?, 1)",
            (user.id, getattr(user, "username", None), getattr(user, "first_name", None), getattr(user, "last_name", None))
        )
    conn.commit()
    conn.close()


def get_usage_table():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, first_name, last_name, count FROM usage ORDER BY count DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def get_usage_count_db(user_id: int) -> int | None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT count FROM usage WHERE user_id = ?", (user_id,))
        row = c.fetchone()
        return int(row[0]) if row else None
    finally:
        conn.close()


# shops
def has_shop_db(user_id: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT user_id FROM shops WHERE user_id = ?", (user_id,))
        return c.fetchone() is not None
    finally:
        conn.close()


def create_shop_db(user_id: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        # set last_collection to now so accumulation starts from creation
        now = int(time.time())
        c.execute("INSERT OR IGNORE INTO shops(user_id, name, last_collection) VALUES (?, 'Безымянный магазин', ?)", (user_id, now))
        conn.commit()
    finally:
        conn.close()


def get_shop_db(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT name, last_collection FROM shops WHERE user_id = ?", (user_id,))
        row = c.fetchone()
        if row:
            return {"name": row[0], "last_collection": row[1]}
        return None
    finally:
        conn.close()


def update_shop_name_db(user_id: int, name: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("UPDATE shops SET name = ? WHERE user_id = ?", (name, user_id))
        conn.commit()
    finally:
        conn.close()


def update_shop_collection_db(user_id: int, timestamp: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("UPDATE shops SET last_collection = ? WHERE user_id = ?", (timestamp, user_id))
        conn.commit()
    finally:
        conn.close()


# nicknames
def get_nickname_db(user_id: int) -> str | None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT nickname FROM nicknames WHERE user_id = ?", (user_id,))
        row = c.fetchone()
        return row[0] if row and row[0] is not None else None
    finally:
        conn.close()


def get_user_by_nickname_db(nickname: str) -> int | None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT user_id FROM nicknames WHERE LOWER(nickname) = LOWER(?)", (nickname,))
        row = c.fetchone()
        return int(row[0]) if row else None
    finally:
        conn.close()


def set_nickname_db(user_id: int, nickname: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT OR REPLACE INTO nicknames(user_id, nickname) VALUES (?, ?)", (user_id, nickname))
        conn.commit()
    finally:
        conn.close()


def remove_nickname_db(user_id: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("DELETE FROM nicknames WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def get_all_nicknames() -> dict:
    """Return dict user_id -> nickname for all stored nicknames."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT user_id, nickname FROM nicknames")
        rows = c.fetchall()
        return {r[0]: r[1] for r in rows}
    finally:
        conn.close()


def set_sdx_flag(enabled: bool) -> None:
    """Set global flag for SDX auto-blacklist in global_settings."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        val = '1' if enabled else '0'
        c.execute("INSERT OR REPLACE INTO global_settings(key, value) VALUES ('sdx_auto', ?)", (val,))
        conn.commit()
    finally:
        conn.close()


def get_sdx_flag() -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT value FROM global_settings WHERE key = 'sdx_auto'")
        row = c.fetchone()
        if row and row[0] == '1':
            return True
        return False
    finally:
        conn.close()

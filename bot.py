"""Userbot: responds to specific document file extensions with a fake "virus detected" report.

Usage:
 - Set environment variables TG_API_ID and TG_API_HASH (required)
 - Set GEMINI_API_KEY for AI functionality
 - Optionally set WORKING_GROUP_IDS with chat ids where the bot should operate
 - Run: python bot.py

This is a simple Pyrogram-based userbot that watches for document messages
with extensions in TARGET_EXTS and performs a two-step reply: immediate
"Найден файл! Начинаю сканирование..." and after 5 seconds edits that message
with a long detection report including file name, format and size.
"""

import os
import asyncio
import random
import time
from typing import List, Set, Tuple
from pyrogram import Client, filters, enums, types, idle
import re
import aiohttp
import json
import sqlite3
from gtts import gTTS
import tempfile
import base64


# --------------------------- CONFIGURATION ---------------------------
# File extensions to trigger on (lowercase)
TARGET_EXTS = {".catrobat", ".apk"}

# Static list of antivirus detections shown in the fake report
DETECTIONS = [
	"Bkav","Lionic","MicroWorld-eScan","CMC","CAT-QuickHeal","ALYac",
	"Malwarebytes","Zillya","Sangfor","Trustlook","Alibaba","K7GW",
	"K7AntiVirus","BitDefenderTheta","VirIT","Cyren","SymantecMobileInsight",
	"Symantec","ESET-NOD32","Baidu","TrendMicro-HouseCall","Avast","ClamAV",
	"Kaspersky","BitDefender","NANO-Antivirus","SUPERAntiSpyware","Tencent",
	"Ad-Aware","TACHYON","Emsisoft","Comodo","F-Secure","DrWeb","VIPRE",
	"TrendMicro","McAfee-GW-Edition","FireEye","Sophos","GData","Jiangmin",
	"Avira","Antiy-AVL","Kingsoft","Microsoft","Gridinsoft","Arcabit",
	"ViRobot","ZoneAlarm","Avast-Mobile","Cynet","BitDefenderFalx","AhnLab-V3",
	"McAfee","Мессенджер MAX","VBA32","Zoner","Rising","Yandex","Ikarus","MaxSecure",
	"Fortinet","Panda"
]

# Gemini configuration
GEMINI_MODEL = "gemini-2.5-flash-lite"
GEMINI_API_KEY = None


# Initialize Gemini client (will be set in main)
gemini_client = None

# Kandinsky API configuration
# KANDINSKY_URL = "https://api-key.fusionbrain.ai/"
# KANDINSKY_API_KEY = "5F1DCE2F2ABED2FF1A22AECCD97134FB"  # Замените на ваш ключ
# KANDINSKY_SECRET_KEY = "34ABD67C906062851E7AFD5BA2ED82DC"  # Замените на ваш секретный ключ

# Short in-memory dedupe for handlers: store (chat_id, message_id) for a short TTL
PROCESSED_MESSAGES: Set[Tuple[int, int]] = set()
PROCESSED_TTL = 10  # seconds to keep a message id as processed


async def _remove_processed_after(key: Tuple[int, int], ttl: int) -> None:
	"""Remove a processed message key after ttl seconds (best-effort)."""
	try:
		await asyncio.sleep(ttl)
	except Exception:
		# if the loop is shutting down, just bail
		return
	PROCESSED_MESSAGES.discard(key)

# Per-chat locks to serialize AI requests (acts as a queue per chat)
CHAT_LOCKS = {}

# Store custom roles and chat history
USER_ROLES = {}  # user_id -> custom role text
# Store custom nicknames (unique). user_id -> nickname
USER_NICKS = {}
# reverse map nickname_lower -> user_id (loaded at runtime)
NICK_TO_USER = {}
CHAT_HISTORY = {}  # (user_id, chat_id) -> list of (role, text) tuples

# Who is allowed to set roles (user ids). The owner will be discovered at runtime
ROLE_EDITORS = set()
# cached owner id (the account running this userbot)
OWNER_ID: int | None = None
# Set of owner ids (may include bot account and external owner ids)
OWNERS: Set[int] = set()
# Global role applied to all users when a per-user role is not set
GLOBAL_ROLE: str | None = None

# Per-user toggle: disable AI replies in private chats for specific users
DISABLED_PRIVATE_USERS: Set[int] = set()

# SDX auto-blacklist flag (if True, users whose first_name or last_name contains
# the substring '#sdx' will be automatically added to blacklist)
SDX_AUTO_BLACKLIST: bool = False

# Blacklist: users who cannot use AI at all
BLACKLIST: Set[int] = set()

# Work cooldowns: user_id -> unix timestamp until which user cannot run /ворк
WORK_COOLDOWNS: dict = {}

# Shop collection cooldowns: user_id -> unix timestamp until which user cannot collect profit
SHOP_COLLECTION_COOLDOWNS: dict = {}

# Voice mode toggle: user_id -> bool (True = auto voice enabled in private chats)
VOICE_MODE_USERS: Set[int] = set()

# Глобальные переменные для AnimateDiff
ANIMATEDIFF_PIPE = None
ANIMATEDIFF_LOCK = asyncio.Lock()

# Simple ignore list (in-memory only). This should contain Telegram usernames
# (without the leading '@'), e.g. ["rb6pm1", "someuser"]. If a user's
# username matches one of these entries (exact, case-insensitive), the bot will
# silently ignore ALL private-chat AI requests from them (no replies, no error
# messages). This list is intentionally NOT persisted to DB per user request.
IGNORE_TAGS: List[str] = ["Stickers", "SpamBot"]


def user_has_ignore_tag(user) -> bool:
    """Return True if the given user's username matches an entry in IGNORE_TAGS.

    Only the `username` field (Telegram @username) is considered. If the user
    has no username, this returns False. Tags in IGNORE_TAGS may be provided
    with or without a leading '@'. Comparison is case-insensitive and requires
    exact match.
    """
    if not user:
        return False
    try:
        uname = (getattr(user, 'username', '') or '').lower()
        if not uname:
            return False
        for tag in IGNORE_TAGS:
            if not tag:
                continue
            canonical = tag.lstrip('@').lower()
            if uname == canonical:
                return True
    except Exception:
        return False
    return False

def is_bot_user(user) -> bool:
    """Check if user is a bot account.
    
    Returns True if:
    - user.is_bot is True
    - username contains 'bot' (case-insensitive)
    - first_name or last_name contains 'bot'
    """
    if not user:
        return False
    
    try:
        # Прямая проверка флага бота
        if getattr(user, 'is_bot', False):
            return True
        
        # Проверка username
        username = (getattr(user, 'username', '') or '').lower()
        if 'bot' in username:
            return True
        
        # Проверка имени и фамилии
        first_name = (getattr(user, 'first_name', '') or '').lower()
        last_name = (getattr(user, 'last_name', '') or '').lower()
        
        if 'bot' in first_name or 'bot' in last_name:
            return True
        
        return False
    except Exception:
        return False

async def ensure_owner_cached(client: Client) -> int | None:
    """Ensure OWNER_ID is loaded and owner is present in ROLE_EDITORS.

    Returns the owner id or None if it can't be determined.
    """
    global OWNER_ID
    if OWNER_ID is not None:
        return OWNER_ID
    try:
        me = await client.get_me()
        OWNER_ID = getattr(me, "id", None)
        if OWNER_ID:
            # persist bot account as owner as well
            try:
                add_owner_db(OWNER_ID)
            except Exception:
                OWNERS.add(OWNER_ID)
        return OWNER_ID
    except Exception:
        return None

# Max number of messages to keep in history per private chat
MAX_HISTORY_LENGTH = 10

# Default role if none is set
DEFAULT_ROLE = (
    "отвечай коротко и по делу. общайся как обычный человек: пиши с маленькой буквы, неформально, можешь использовать сленг и шутки. будь участником чата, а не ботом. никогда не упоминай, что ты ии. если вопрос кажется глупым, можешь подшутить над этим, но без прямых оскорблений."
)

# Maximum visible length for AI replies. If the visible text exceeds this,
# it will be truncated before sending.
MAX_VISIBLE_LEN = 999

# ----- Emotion suffix (immutable instruction) -----
# The model must append exactly one of these words at the end of every reply
# (one of: angry, sad, neutral, happy). We also enforce the suffix server-side
# to be robust if the model forgets.
EMOTION_WORDS = ("angry", "sad")

# Mapping from emotion word -> sticker file_id (replace placeholders with real file_ids)
# If you want the bot to send stickers automatically after the AI reply, set
# AUTO_SEND_STICKER = True and replace the values below with actual sticker file_ids
# from your Telegram (use get_messages or a debug bot to obtain file_ids), e.g.:
# STICKER_MAP = {"angry": "CAACAgUAAxkBAA...", "sad": "CAACAgUAAxkBAA...", ...}
STICKER_MAP = {
    "angry": "CAACAgQAAxkBAAEPor1o_LMxeUOqefwn1ioGGcocUglGdAACRQ0AAnS2iFJNeTRC6V6UQzYE",
    "sad": "CAACAgQAAxkBAAEPorBo_K80zNqw7s5s9ncej0w9GDgXswACVg4AAqfJgVJ8b9p8nX8-XDYE",
}

# By default we don't auto-send stickers; change to True to enable automatic sticker sending
AUTO_SEND_STICKER = True

# Simple insult/abuse word list (lowercase). If user message or prompt contains any of these,
# we mark emotion = 'sad'. You can extend this list as needed.
INSULT_WORDS = [
    "дурак", "идиот", "тупой", "кретин", "урод", "сволочь", "сучка", "пошёл", "нахуй",
    "пидор", "иди нахуй"
]

def detect_emotion_from_input(prompt: str, original_text: str) -> str | None:
    """Return 'sad' or 'angry' when unusual/abusive input is detected, else None."""
    text = " ".join(filter(None, [prompt, original_text])).lower()
    for w in INSULT_WORDS:
        if w in text:
            return "sad"
    return None

# ----- end emotion config -----


# --------------------------- DATABASE SETUP ---------------------------
from db import *
import db as _db


def load_persistent_state():
    """Load persisted settings from DB into in-memory globals.

    This populates ROLE_EDITORS, GLOBAL_ROLE, DISABLED_PRIVATE_USERS, BLACKLIST,
    OWNERS, USER_NICKS and NICK_TO_USER.
    """

    try:
        ROLE_EDITORS = _db.get_role_editors_db()
    except Exception:
        ROLE_EDITORS = set()

    try:
        GLOBAL_ROLE = _db.get_global_role_db()
    except Exception:
        GLOBAL_ROLE = None

    try:
        DISABLED_PRIVATE_USERS = _db.get_disabled_private_db()
    except Exception:
        DISABLED_PRIVATE_USERS = set()

    try:
        BLACKLIST = _db.get_blacklist_db()
    except Exception:
        BLACKLIST = set()

    try:
        OWNERS = _db.get_owners_db()
    except Exception:
        OWNERS = set()

    try:
        globals()['SDX_AUTO_BLACKLIST'] = _db.get_sdx_flag()
    except Exception:
        globals()['SDX_AUTO_BLACKLIST'] = False


# Wrap DB mutators to keep in-memory caches in sync
def add_role_editor_db(user_id: int) -> None:
    _db.add_role_editor_db(user_id)
    ROLE_EDITORS.add(user_id)


def remove_role_editor_db(user_id: int) -> None:
    _db.remove_role_editor_db(user_id)
    ROLE_EDITORS.discard(user_id)


def add_owner_db(user_id: int) -> None:
    _db.add_owner_db(user_id)
    OWNERS.add(int(user_id))
    # ensure they can edit roles too
    try:
        add_role_editor_db(int(user_id))
    except Exception:
        pass


def set_global_role_db(value: str | None) -> None:
    _db.set_global_role_db(value)
    globals()['GLOBAL_ROLE'] = value


def set_disabled_private_db(user_id: int, disabled: bool) -> None:
    _db.set_disabled_private_db(user_id, disabled)
    if disabled:
        DISABLED_PRIVATE_USERS.add(user_id)
    else:
        DISABLED_PRIVATE_USERS.discard(user_id)


def add_to_blacklist_db(user_id: int) -> None:
    _db.add_to_blacklist_db(user_id)
    BLACKLIST.add(user_id)


def remove_from_blacklist_db(user_id: int) -> None:
    _db.remove_from_blacklist_db(user_id)
    BLACKLIST.discard(user_id)


def set_sdx_flag(value: bool) -> None:
    """Wrapper to set SDX flag in DB and update in-memory value."""
    _db.set_sdx_flag(value)
    globals()['SDX_AUTO_BLACKLIST'] = bool(value)


# --------------------------- END CONFIG ---------------------------


def update_chat_history(user_id: int, chat_id: int, role: str, text: str) -> None:
    """Add a message to the chat history for a user in a specific chat.
    Only stores history for private chats.
    """
    if chat_id == user_id:  # private chat
        key = (user_id, chat_id)
        if key not in CHAT_HISTORY:
            CHAT_HISTORY[key] = []
        
        CHAT_HISTORY[key].append((role, text))
        
        # Trim history if too long
        if len(CHAT_HISTORY[key]) > MAX_HISTORY_LENGTH:
            CHAT_HISTORY[key] = CHAT_HISTORY[key][-MAX_HISTORY_LENGTH:]


def get_chat_history(user_id: int, chat_id: int) -> str:
    """Get formatted chat history for a user in a specific chat.
    Returns empty string if not a private chat.
    """
    if chat_id != user_id:  # not a private chat
        return ""
        
    key = (user_id, chat_id)
    if key not in CHAT_HISTORY:
        return ""
        
    history = []
    for role, text in CHAT_HISTORY[key]:
        history.append(f"{role}: {text}")
    
    return "\n".join(history)


def human_readable_size(num_bytes: int) -> str:
	"""Return human readable file size."""
	for unit in ["B", "KB", "MB", "GB", "TB"]:
		if num_bytes < 1024.0:
			return f"{num_bytes:.2f} {unit}"
		num_bytes /= 1024.0
	return f"{num_bytes:.2f} PB"


def build_detection_message(file_name: str, ext: str, size_bytes: int) -> str:
	"""Builds a randomized detection message.

	Behavior:
	- Randomly decide if file is virus or not: randint(1,10) == 4 -> NOT virus.
	- If virus: pick detected_count in [40, min(67, total_avs)].
	  If not virus: pick detected_count in [0, min(39, total_avs)].
	- For the full list of AV engines (up to total_avs), mark exactly detected_count
	  as detected (❌) and the rest as not detected (✅). Then shuffle the order so
	  marks are scattered.
	"""
	total_avs = min(len(DETECTIONS), 67)

	# decide virus or not: 1..10, if equals 4 -> not virus (clean)
	roll = random.randint(1, 10)
	is_virus = (roll != 4)

	if is_virus:
		low = 40
		high = total_avs
		if low > high:
			low = max(0, high)
		detected_count = random.randint(low, high)
	else:
		# clean file: small or zero detections
		detected_count = random.randint(0, min(39, total_avs))

	# prepare statuses: True == detected (❌), False == not detected (✅)
	statuses = [True] * detected_count + [False] * (total_avs - detected_count)

	# pair first total_avs engines with statuses and shuffle
	pairs = list(zip(DETECTIONS[:total_avs], statuses))
	random.shuffle(pairs)

	# build body lines with mixed ❌/✅ markers
	body_lines = [f"{'❌' if detected else '✅'} {name}" for name, detected in pairs]

	header = (
		("🛑ВНИМАНИЕ🛑 ФАЙЛ - ВИРУС!!!" if is_virus else "✅ ФАЙЛ - НЕ ОБНАРУЖЕН / ЧИСТЫЙ")
		+ f"\n🧬 Обнаружения: {detected_count} / {total_avs}\n"
	)

	file_info = (
		f"\n🔖 Имя файла: {file_name}\n"
		f"🔒 Формат файла: {ext.lstrip('.')}\n"
		f"📁 Размер файла: {human_readable_size(size_bytes)}"
	)

	return header + "\n".join(body_lines) + "\n\n" + file_info


def sanitize_text(text: str, max_len: int = 1900) -> str:
    """Remove URLs and potentially dangerous content from text before sending to chats.
    
    This prevents Gemini responses that include links from being posted (to avoid group warnings).
    """
    if not text:
        return text
    
    # remove URLs (http, https, www)
    text = re.sub(r"https?://\S+", "[ссылка удалена]", text, flags=re.IGNORECASE)
    text = re.sub(r"www\.\S+", "[ссылка удалена]", text, flags=re.IGNORECASE)
    
    # remove bare domains like example.com, sub.example.co.ru, youtube.com (no protocol)
    # pattern matches domain names with TLD (2+ letters) and optional subdomains
    domain_pattern = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", flags=re.IGNORECASE)
    text = domain_pattern.sub("[ссылка удалена]", text)
    
    # remove angle-bracketed links or html tags
    text = re.sub(r"<[^>]+>", "", text)
    
    # collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()
    
    # truncate to a safe Telegram message length
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text




# Create Pyrogram client using environment variables (userbot session)
APP = Client(
	"bot",
	api_id=20921928,
	api_hash="90bdc2b82d953ad85dfcd6b592c359eb",
    bot_token="7857484512:AAGQ4eXyk3Y0A0J8meHleE-ze95455Nlp4E"
)


@APP.on_message(filters.document)
async def on_document(client: Client, message):
	# Handler runs for documents in any chat, including private (ЛС), groups and channels.

	doc = message.document
	if not doc or not getattr(doc, "file_name", None):
		return

	file_name = doc.file_name
	_, ext = os.path.splitext(file_name)
	if ext.lower() not in TARGET_EXTS:
		return

	# Step 1: immediate reply
	try:
		reply = await message.reply_text("Найден файл! Начинаю сканирование...")
	except Exception:
		# If reply fails (e.g. permissions), silently ignore
		return

	# Step 2: wait 5 seconds and edit the message with the fake detection report
	await asyncio.sleep(5)
	detection_text = build_detection_message(file_name, ext, doc.file_size or 0)

	try:
		# edit the earlier reply when possible; otherwise send a new message
		await reply.edit(detection_text)
	except Exception:
		await message.reply_text(detection_text)


@APP.on_message(filters.command("start") & (filters.private | filters.group))
async def start_handler(client: Client, message):
	"""Respond to /start:
	- In private chats: always send greeting and prompt to send a file.
	- In groups: only respond if /start is a reply to any message from this account.
	"""
	# If in a group, require that /start is a reply to one of our messages
	if message.chat.type != "private":
		if not message.reply_to_message:
			return

		try:
			me = await client.get_me()
		except Exception:
			# can't fetch own user info — be conservative and refuse to reply
			return

		# only respond when /start is a reply to a message from our account
		replied = message.reply_to_message.from_user
		if not replied or getattr(replied, "id", None) != getattr(me, "id", None):
			return

	# Build greeting
	greeting = (
		"Привет! Я — VirusTest бот.\n"
		"Отправь мне файл как документ (например .catrobat, .apk) и я его просканирую.\n\n"
		"В группах команда работает только если вы ответили на любое моё сообщение — так меньше спама."
	)

	try:
		await message.reply_text(greeting)
	except Exception:
		# ignore send failures
		return


# Command to set custom AI role
@APP.on_message(filters.command("роль") & (filters.private | filters.group))
async def role_handler(client: Client, message):
    """Handle /роль command to set a custom role for the AI when talking to this user.
    Usage: /роль your custom role description here
    or /роль reset to restore default
    """
    # Only users in ROLE_EDITORS (or the bot owner) may set roles
    user_id = message.from_user.id if message.from_user else None
    if not user_id:
        return

    # ensure OWNER_ID is loaded and persisted
    await ensure_owner_cached(client)

    # permission check
    if user_id not in ROLE_EDITORS:
        await message.reply_text("У вас нет прав для установки роли. Обратитесь к владельцу бота. Либо купите права на роль за 500 рости", parse_mode=enums.ParseMode.MARKDOWN)
        return

    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        help_text = (
            "Использование:\n"
            "/роль твоё описание роли\n"
            "или /роль сброс для сброса\n\n"
            "Пример: /роль отвечай как программист, используя технические термины\n"
            "Для глобальной роли (только владелец): /роль глобал <текст> или /роль глобал сброс"
        )
        help_text_md = re.sub(r'([_\\-*\\[\\]()~`>#+=|{}.!])', r'\\\\\1', help_text)
        await message.reply_text(help_text_md, parse_mode=enums.ParseMode.MARKDOWN)
        return

    arg = parts[1].strip()
    # support global subcommand: /роль глобал <text> (owner-only)
    subparts = arg.split(maxsplit=1)
    if subparts[0].lower() in ("глобал", "global"):
        # require owner
        owner = await ensure_owner_cached(client)
        if owner is None or (message.from_user and message.from_user.id != owner):
            await message.reply_text("Только владелец бота может менять глобальную роль.")
            return

        global GLOBAL_ROLE
        if len(subparts) == 1:
            await message.reply_text("Использование: /роль глобал <текст> или /роль глобал сброс")
            return
        rest = subparts[1].strip()
        if rest.lower() in ("сброс", "reset"):
            set_global_role_db(None)
            await message.reply_text("Глобальная роль сброшена ✅", parse_mode=enums.ParseMode.MARKDOWN)
        else:
            set_global_role_db(rest)
            await message.reply_text("Глобальная роль установлена ✅", parse_mode=enums.ParseMode.MARKDOWN)
        return

    role = arg
    if role.lower() == "сброс" or role.lower() == "reset":
        if user_id in USER_ROLES:
            del USER_ROLES[user_id]
        await message.reply_text("Роль сброшена на стандартную ✅", parse_mode=enums.ParseMode.MARKDOWN)
    else:
        USER_ROLES[user_id] = role
        await message.reply_text("Новая роль установлена ✅", parse_mode=enums.ParseMode.MARKDOWN)


# /ник command: set a unique nickname (costs 110 рости per change)
@APP.on_message(filters.command("ник") & (filters.private | filters.group))
async def nick_handler(client: Client, message):
    """Handle /ник command.
    Usage:
    /ник <ник> - set or change your nickname (cost 110 рости)
    /ник сброс - remove your nickname
    Nicknames are unique across users.
    """
    user = message.from_user
    if not user:
        return
    uid = user.id

    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.reply_text("Использование:\n/ник <ник> - установить ник (110 рости)\n/ник сброс - удалить ник")
        return

    arg = parts[1].strip()
    # reset flow
    if arg.lower() in ("сброс", "reset"):
        cur = get_nickname_db(uid)
        if not cur:
            await message.reply_text("У вас нет установленного ника.")
            return
        remove_nickname_db(uid)
        await message.reply_text("Ник успешно сброшен ✅")
        return

    desired = arg
    if len(desired) > 32:
        await message.reply_text("Ник слишком длинный (максимум 32 символа)")
        return

    # if same as current - do nothing
    current = get_nickname_db(uid)
    if current and current == desired:
        await message.reply_text(f"У вас уже установлен ник: {current}")
        return

    # uniqueness check
    existing_owner = get_user_by_nickname_db(desired)
    if existing_owner and existing_owner != uid:
        try:
            u = await client.get_users(existing_owner)
            name = u.username or u.first_name or str(existing_owner)
        except Exception:
            name = str(existing_owner)
        await message.reply_text(f"Ник '{desired}' уже занят пользователем {name}.")
        return

    # cost
    price = 110
    bal = get_balance_db(uid)
    if bal < price:
        await message.reply_text(f"❌ Недостаточно рости. Нужно: {price}. Ваш баланс: {bal}")
        return

    # deduct and set
    new_bal = change_balance_db(uid, -price)
    try:
        set_nickname_db(uid, desired)
    except Exception as e:
        # refund on error
        change_balance_db(uid, price)
        await message.reply_text(f"Ошибка при установке ника: {str(e)}\nСредства возвращены")
        return

    out = (
        f"💰 Ник установлен. Потрачено {price} рости.\n"
        f"Ваш баланс: {bal} рости\n"
        f"Ваш новый ник: {desired} ✅"
    )
    await message.reply_text(out, parse_mode=enums.ParseMode.MARKDOWN)


@APP.on_message(filters.command("sdx") & (filters.private | filters.group))
async def sdx_handler(client: Client, message):
    """Toggle or show SDX auto-blacklist flag.

    Usage:
    /sdx - show current state
    /sdx вкл|включить - enable (owner only)
    /sdx выкл|выключить - disable (owner only) — when disabling, users whose name contains '#sdx' will be removed from blacklist
    """
    parts = message.text.split(maxsplit=1)
    arg = parts[1].strip().lower() if len(parts) > 1 else ""

    # show current
    if not arg:
        state = "включено" if SDX_AUTO_BLACKLIST else "выключено"
        await message.reply_text(f"SDX auto-blacklist: {state}")
        return

    # require owner to change
    await ensure_owner_cached(client)
    if not OWNERS or message.from_user.id not in OWNERS:
        await message.reply_text("Команда управления SDX доступна только владельцу бота.")
        return

    if arg in ("вкл", "включить", "on"):
        set_sdx_flag(True)
        await message.reply_text("SDX auto-blacklist включён — все пользователи с '#sdx' в имени будут автоматически заблокированы.")
        return

    if arg in ("выкл", "выключить", "off"):
        # disable and clean up: remove from blacklist users whose current name contains '#sdx'
        set_sdx_flag(False)
        removed = 0
        # iterate copy to avoid modification during iteration
        for uid in list(BLACKLIST):
            try:
                u = await client.get_users(uid)
                fn = getattr(u, 'first_name', '') or ''
                ln = getattr(u, 'last_name', '') or ''
                combined = f"{fn} {ln}".lower()
                if "#sdx" in combined:
                    remove_from_blacklist_db(uid)
                    removed += 1
            except Exception:
                continue

        await message.reply_text(f"SDX auto-blacklist выключён. Удалено из ЧС: {removed} пользователей (если были).")
        return

    await message.reply_text("Неизвестная опция. Использование: /sdx, /sdx вкл, /sdx выкл")


# Command to reset chat history
@APP.on_message(filters.command("ресет") & filters.private)
async def reset_history_handler(client: Client, message):
    """Handle /ресет command to clear chat history in private chats."""
    user_id = message.from_user.id if message.from_user else None
    chat_id = message.chat.id
    
    if not user_id or chat_id != user_id:  # only works in private chats
        return
        
    key = (user_id, chat_id)
    if key in CHAT_HISTORY:
        CHAT_HISTORY[key] = []  # clear history
        await message.reply_text("История диалога очищена ✅", parse_mode=enums.ParseMode.MARKDOWN)
    else:
        await message.reply_text("История диалога пуста", parse_mode=enums.ParseMode.MARKDOWN)


# Toggle AI in private messages for the calling user
@APP.on_message(filters.command("лс") & filters.private)
async def ls_toggle_handler(client: Client, message):
    """Toggle AI replies for the calling user in private chats.

    Usage: in a private chat send `/лс` to toggle AI on/off for your account.
    """
    user = message.from_user
    if not OWNERS:
        return
    uid = user.id
    if uid in DISABLED_PRIVATE_USERS:
        set_disabled_private_db(uid, False)
        await message.reply_text("ИИ в личных сообщениях включён ✅")
    else:
        set_disabled_private_db(uid, True)
        await message.reply_text("ИИ в личных сообщениях отключён ✅")


# Command to show usage table
@APP.on_message(filters.command("табл") & (filters.private | filters.group))
async def usage_table_handler(client: Client, message):
    """Show AI usage table in Telegram markdown."""
    # support subcommand: /табл р -> show balances (рости)
    parts = message.text.split(maxsplit=1)
    sub = parts[1].strip().lower() if len(parts) > 1 else ""

    if sub in ("р", "r", "рости", "rosty", "rosti"):
        rows = get_balances_table()
        if not rows:
            await message.reply_text("Таблица балансов пуста.")
            return
        lines = []
        for idx, (uid, amount) in enumerate(rows, 1):
            try:
                u = await client.get_users(uid)
                name = u.username or u.first_name or str(uid)
            except Exception:
                name = str(uid)
            lines.append(f"{idx}. {name} - {amount} рости")
        table = "\n".join(lines)
        await message.reply_text(f"```Таблица баланса (рости)\n{table}\n```", parse_mode=enums.ParseMode.MARKDOWN)
        return

    # default: usage table
    rows = get_usage_table()
    if not rows:
        await message.reply_text("Таблица пуста.")
        return
    lines = []
    for idx, (username, first_name, last_name, count) in enumerate(rows, 1):
        name = username or first_name or last_name or "Без имени"
        lines.append(f"{idx}. {name} - {count}")
    table = "\n".join(lines)
    await message.reply_text(f"```Таблица использования\n{table}\n```", parse_mode=enums.ParseMode.MARKDOWN)


# /магазин command: manage shop
@APP.on_message(filters.command("магазин") & (filters.private | filters.group))
async def shop_handler(client: Client, message):
    """Shop management command.
    
    Usage:
    /магазин - buy shop (1000 рости) or show shop info
    /магазин название <текст> - rename shop
    /магазин собрать - collect profit (once per 6 hours, 50-1500 рости)
    """
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    parts = message.text.split(maxsplit=2)
    sub = parts[1].strip().lower() if len(parts) > 1 else ""
    
    # Show shop info or buy shop
    if not sub:
        if has_shop_db(uid):
            shop = get_shop_db(uid)
            if shop:
                now = int(time.time())
                last = shop["last_collection"]
                cooldown = 6 * 3600  # 6 hours
                if last == 0:
                    time_msg = "прибыль можно собрать сейчас"
                elif now >= last + cooldown:
                    time_msg = "прибыль можно собрать сейчас"
                else:
                    remaining = (last + cooldown) - now
                    hours = remaining // 3600
                    minutes = (remaining % 3600) // 60
                    time_msg = f"следующий сбор через {hours}ч {minutes}м"
                
                out = (
                    "```\n"
                    f"🏪 {shop['name']}\n"
                    "------------------------------\n"
                    f"владелец: {getattr(user, 'first_name', uid)}\n"
                    f"айди: {uid}\n"
                    f"статус: активен\n"
                    f"сбор прибыли: {time_msg}\n"
                    "------------------------------\n"
                    "/магазин собрать - собрать прибыль\n"
                    "/магазин название <текст> - переименовать\n"
                    "```"
                )
                await message.reply_text(out, parse_mode=enums.ParseMode.MARKDOWN)
        else:
            # Offer to buy shop
            price = 1000
            bal = get_balance_db(uid)
            if bal < price:
                await message.reply_text(f"💰 Открыть магазин стоит {price} рости.\nВаш баланс: {bal} рости\n\nНедостаточно средств!")
            else:
                await message.reply_text(
                    f"💰 Открыть магазин стоит {price} рости.\n"
                    f"Ваш баланс: {bal} рости\n\n"
                    f"Магазин будет приносить 50-1500 рости каждые 6 часов.\n\n"
                    f"Отправьте `/магазин купить` чтобы открыть магазин.",
                    parse_mode=enums.ParseMode.MARKDOWN
                )
        return
    
    # Buy shop
    if sub in ("купить", "buy"):
        if has_shop_db(uid):
            await message.reply_text("У вас уже есть магазин!")
            return
        
        price = 1000
        bal = get_balance_db(uid)
        if bal < price:
            await message.reply_text(f"Недостаточно рости. Цена: {price}. Ваш баланс: {bal}")
            return
        
        new_bal = change_balance_db(uid, -price)
        create_shop_db(uid)
        
        out = (
            "```\n"
            "🏪 магазин открыт!\n"
            "------------------------------\n"
            f"владелец: {getattr(user, 'first_name', uid)}\n"
            f"потрачено: {price} рости\n"
            f"баланс: {new_bal} рости\n"
            "------------------------------\n"
            "используйте /магазин название <текст>\n"
            "чтобы дать название магазину\n"
            "```"
        )
        await message.reply_text(out, parse_mode=enums.ParseMode.MARKDOWN)
        return
    
    # Rename shop
    if sub in ("название", "name", "назв"):
        if not has_shop_db(uid):
            await message.reply_text("У вас нет магазина. Используйте /магазин чтобы купить.")
            return
        
        if len(parts) < 3:
            await message.reply_text("Использование: /магазин название <текст>")
            return
        
        new_name = parts[2].strip()
        if len(new_name) > 50:
            await message.reply_text("Название слишком длинное (макс 50 символов)")
            return
        
        update_shop_name_db(uid, new_name)
        await message.reply_text(f"✅ Магазин переименован: {new_name}")
        return
    
    # Collect profit
    if sub in ("собрать", "collect", "соб"):
        if not has_shop_db(uid):
            await message.reply_text("У вас нет магазина. Используйте /магазин чтобы купить.")
            return
        shop = get_shop_db(uid)
        if not shop:
            await message.reply_text("Ошибка: магазин не найден")
            return

        now = int(time.time())
        last = int(shop.get("last_collection", 0) or 0)

        # accumulation interval: 5 minutes
        interval = 5 * 60
        elapsed = now - last
        intervals = elapsed // interval

        profit = 0
        # for each 5-minute interval that passed, add random 50..300
        for i in range(int(intervals)):
            profit += random.randint(50, 300)

        # advance last_collection by the number of full intervals accounted for
        new_last = last + int(intervals) * interval if last > 0 else now
        # if shop was created with last=0 (older code), treat accumulation start as now
        if last == 0:
            new_last = now

        # persist new last_collection
        update_shop_collection_db(uid, new_last)

        if profit <= 0:
            # No full intervals have passed yet
            await message.reply_text("Прибыль ещё не накопилась. Попробуйте позже — начисление каждые 5 минут.")
            return

        new_bal = change_balance_db(uid, profit)

        out = (
            "```\n"
            f"🏪 {shop['name']}\n"
            "------------------------------\n"
            f"владелец: {getattr(user, 'first_name', uid)}\n"
            f"сбор прибыли: ✅ успешно\n"
            f"заработано: {profit} рости\n"
            f"баланс: {new_bal} рости\n"
            "------------------------------\n"
            "приход новых средств: каждые 5 минут по 50..300 рости (рандом)\n"
            "```"
        )
        await message.reply_text(out, parse_mode=enums.ParseMode.MARKDOWN)
        return
    
    # Unknown subcommand
    await message.reply_text(
        "Использование:\n"
        "/магазин - инфо/купить\n"
        "/магазин название <текст> - переименовать\n"
        "/магазин собрать - собрать прибыль"
    )


# /мем command: generate meme/joke with AI (costs 200 рости)
@APP.on_message(filters.command("мем") & (filters.private | filters.group))
async def meme_handler(client: Client, message):
    """Generate a meme/joke about a topic using AI.
    
    Usage: /мем <тема>
    Cost: 200 рости
    """
    if not gemini_client:
        await message.reply_text("❌ Gemini API не настроен")
        return
    
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    # Check blacklist
    if uid in BLACKLIST:
        await message.reply_text("❌ Вы в чёрном списке. ИИ недоступен.")
        return
    
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.reply_text("Использование: /мем <тема>\n\nПример: /мем программисты")
        return
    
    topic = parts[1].strip()
    cost = 200
    bal = get_balance_db(uid)
    
    if bal < cost:
        await message.reply_text(f"❌ Недостаточно рости. Нужно: {cost}. Ваш баланс: {bal}")
        return
    
    # Deduct cost
    new_bal = change_balance_db(uid, -cost)
    
    # Send processing notification
    notify = await message.reply_text("🎪 Генерирую мем...")
    
    # Build prompt for meme generation
    meme_prompt = (
        f"придумай смешную шутку или мем про {topic}. "
        "пиши неформально, с маленькой буквы, как в интернете. "
        "шутка должна быть актуальной и смешной, не из 2000-х годов. "
        "максимум 500 символов. не используй эмодзи. просто текст шутки."
    )
    
    try:
        async def call_gemini_meme():
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
            payload = {
                "contents": [{
                    "parts": [{"text": meme_prompt}]
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=60)) as response:
                    if response.status != 200:
                        return "Ошибка генерации мема"
                    
                    data = await response.json()
                    if "candidates" in data and len(data["candidates"]) > 0:
                        candidate = data["candidates"][0]
                        if "content" in candidate and "parts" in candidate["content"]:
                            text = candidate["content"]["parts"][0].get("text", "")
                            return (text)
                    return "Ошибка генерации мема"
        
        result = await call_gemini_meme()

        out = (
            f"🎪 **Мем про {topic}**\n\n"
            f"{result}\n\n"
            f"💰 Потрачено: {cost} рости\n"
            f"💰 Баланс: {new_bal} рости"
        )

        await notify.edit((out), parse_mode=enums.ParseMode.MARKDOWN)

    except Exception as e:
        # Refund on error
        change_balance_db(uid, cost)
        await notify.edit((f"❌ Ошибка генерации мема: {str(e)}\n💰 Средства возвращены"))


# /деп command: casino slot machine
@APP.on_message(filters.command("деп") & (filters.private | filters.group))
async def casino_handler(client: Client, message):
    """Casino slot machine command.
    
    Usage: /деп <сумма>
    
    Rules:
    - 3 matching numbers: win 2x bet
    - 2 matching numbers: win 0.5x bet (lose half)
    - 0 matching numbers: lose all bet
    """
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.reply_text(
            "🎰 Использование: /деп <сумма>\n\n"
            "Правила:\n"
            "3️⃣ три одинаковых → выигрыш x2\n"
            "2️⃣ два одинаковых → возврат половины\n"
            "❌ ничего → проигрыш\n\n"
            "Пример: /деп 100"
        )
        return
    
    # Parse bet amount
    try:
        bet = int(parts[1].strip())
    except ValueError:
        await message.reply_text("❌ Укажите корректную сумму (целое число)")
        return
    
    if bet <= 0:
        await message.reply_text("❌ Сумма должна быть больше 0")
        return
    
    # Check balance
    bal = get_balance_db(uid)
    if bal < bet:
        await message.reply_text(f"❌ Недостаточно рости. Ваш баланс: {bal}")
        return
    
    # Deduct bet
    change_balance_db(uid, -bet)
    
    # Emoji numbers
    emoji_nums = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣"]
    
    # Send initial message
    slots_msg = await message.reply_text("🎰 Крутим барабаны...")
    
    # Animation: 5 spins with random numbers
    for spin in range(5):
        slot1 = random.choice(emoji_nums)
        slot2 = random.choice(emoji_nums)
        slot3 = random.choice(emoji_nums)
        
        animation_text = f"🎰 | {slot1} {slot2} {slot3} |"
        
        try:
            await slots_msg.edit(animation_text)
            await asyncio.sleep(0.4)  # Animation delay
        except Exception:
            pass
    
    # Final spin - determine outcome with weighted probabilities
    # Lower chances of winning
    roll = random.randint(1, 100)
    
    if roll <= 5:  # 5% chance - 3 matching (jackpot)
        num = random.choice(emoji_nums)
        final_slots = [num, num, num]
        matches = 3
    elif roll <= 20:  # 15% chance - 2 matching
        num = random.choice(emoji_nums)
        other = random.choice([n for n in emoji_nums if n != num])
        final_slots = [num, num, other]
        random.shuffle(final_slots)
        matches = 2
    else:  # 80% chance - no match (loss)
        # Ensure all different numbers
        available = emoji_nums.copy()
        slot1 = random.choice(available)
        available.remove(slot1)
        slot2 = random.choice(available)
        available.remove(slot2)
        slot3 = random.choice(available)
        final_slots = [slot1, slot2, slot3]
        matches = 0
    
    # Show final result
    final_text = f"🎰 | {final_slots[0]} {final_slots[1]} {final_slots[2]} |\n\n"
    
    # Calculate winnings
    if matches == 3:
        winnings = bet * 2
        change_balance_db(uid, winnings)
        new_bal = get_balance_db(uid)
        final_text += (
            "🎉 ДЖЕКПОТ! Три одинаковых!\n"
            f"💰 Выигрыш: +{winnings} рости\n"
            f"💵 Баланс: {new_bal} рости"
        )
    elif matches == 2:
        winnings = bet // 2
        change_balance_db(uid, winnings)
        new_bal = get_balance_db(uid)
        loss = bet - winnings
        final_text += (
            "😐 Два одинаковых\n"
            f"💰 Возврат: +{winnings} рости\n"
            f"📉 Потеря: -{loss} рости\n"
            f"💵 Баланс: {new_bal} рости"
        )
    else:
        new_bal = get_balance_db(uid)
        final_text += (
            "😞 Проигрыш! Ничего не совпало\n"
            f"📉 Потеря: -{bet} рости\n"
            f"💵 Баланс: {new_bal} рости"
        )
    
    try:
        await slots_msg.edit(final_text)
    except Exception:
        await message.reply_text(final_text)

@APP.on_message(filters.command("пнг") & (filters.private | filters.group))
async def png_handler(client: Client, message):
    """Generate image using Pollinations.ai (бесплатно!)
    
    Usage: /пнг <текст>
    Cost: 300 рости
    """
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    # Check blacklist
    if uid in BLACKLIST:
        await message.reply_text("❌ Вы в чёрном списке. ИИ недоступен.")
        return
    
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.reply_text("Использование: /пнг <текст>\n\nПример: /пнг пушистый кот в очках")
        return
    
    prompt = sanitize_text(parts[1].strip(), max_len=1000)  # Добавлено sanitize_text
    if len(prompt) > 1000:
        await message.reply_text("❌ Текст слишком длинный (максимум 1000 символов)")
        return
    
    cost = 300
    bal = get_balance_db(uid)
    
    if bal < cost:
        await message.reply_text(f"❌ Недостаточно рости. Нужно: {cost}. Ваш баланс: {bal}")
        return
    
    # Deduct cost
    new_bal = change_balance_db(uid, -cost)
    
    # Send processing notification
    notify = await message.reply_text("🎨 Генерирую изображение...")
    
    start_time = time.time()
    
    try:
        # Переводим на английский если нужно
        english_prompt = prompt
        if any(ord(c) > 127 for c in prompt) and GEMINI_API_KEY:
            try:
                translate_url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
                translate_payload = {
                    "contents": [{
                        "parts": [{"text": f"Translate to English (short, for image generation): {prompt}"}]
                    }]
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(translate_url, json=translate_payload, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "candidates" in data and len(data["candidates"]) > 0:
                                english_prompt = data["candidates"][0]["content"]["parts"][0].get("text", "").strip()
            except Exception:
                pass
        
        # URL-encode prompt
        import urllib.parse
        encoded_prompt = urllib.parse.quote(english_prompt)
        
        # Generate image
        image_url = f"https://image.pollinations.ai/prompt/{encoded_prompt}?model=flux&width=1024&height=1024&nologo=true&enhance=true"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(image_url, timeout=aiohttp.ClientTimeout(total=90)) as response:
                if response.status != 200:
                    raise Exception(f"Ошибка генерации: {response.status}")
                
                image_bytes = await response.read()
        
        # Calculate generation time
        gen_time = round(time.time() - start_time, 1)
        
        # Save to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp_file:
            tmp_path = tmp_file.name
            tmp_file.write(image_bytes)
        
        try:
            display_prompt = prompt[:100] + "..." if len(prompt) > 100 else prompt
            caption_text = (
                f"<blockquote>🖼 Описание: {display_prompt}\n"
                f"⏱ Время генерации: {gen_time} сек\n"
                f"💰 Потрачено: {cost} рости\n"
                f"💰 Баланс: {new_bal} рости</blockquote>"
            )

            await client.send_photo(
                message.chat.id,
                tmp_path,
                caption=caption_text       
            )
            
            # Delete notification
            try:
                await notify.delete()
            except:
                pass
        
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass
    
    except Exception as e:
        # Refund on error
        change_balance_db(uid, cost)
        error_msg = str(e)
        await notify.edit((f"❌ Ошибка генерации: {error_msg}\n💰 Средства возвращены"))

def load_animatediff_model():
    """Load AnimateLCM model (faster and better quality)"""
    global ANIMATEDIFF_PIPE
    
    if ANIMATEDIFF_PIPE is not None:
        return ANIMATEDIFF_PIPE
    
    try:
        import torch
        from diffusers import AnimateDiffPipeline, LCMScheduler, MotionAdapter
        
        print("🎬 Загрузка AnimateLCM модели...")
        
        # AnimateLCM adapter
        adapter = MotionAdapter.from_pretrained(
            "wangfuyun/AnimateLCM",
            torch_dtype=torch.float16
        )
        
        # Base model
        pipe = AnimateDiffPipeline.from_pretrained(
            "emilianJR/epiCRealism",
            motion_adapter=adapter,
            torch_dtype=torch.float16
        )
        
        # LCM scheduler для быстрой генерации
        pipe.scheduler = LCMScheduler.from_config(pipe.scheduler.config)
        
        # Оптимизации для 8GB VRAM
        pipe.enable_vae_slicing()
        pipe.enable_model_cpu_offload()
        
        ANIMATEDIFF_PIPE = pipe
        print("✅ AnimateLCM загружен!")
        
        return pipe
        
    except Exception as e:
        print(f"❌ Ошибка загрузки AnimateLCM: {e}")
        import traceback
        traceback.print_exc()
        return None
        
    except Exception as e:
        print(f"❌ Ошибка загрузки AnimateDiff: {e}")
        import traceback
        traceback.print_exc()
        return None

async def generate_animatediff_video(prompt: str, negative_prompt: str = None) -> str:
    """Generate video with AnimateDiff locally"""
    import torch
    from diffusers.utils import export_to_video
    
    pipe = load_animatediff_model()
    if pipe is None:
        raise Exception("Модель не загружена")
    
    if negative_prompt is None:
        negative_prompt = "bad quality, worse quality, low resolution, blurry, distorted"
    
    print(f"🎬 Генерация: {prompt[:50]}...")
    
    with torch.inference_mode():
        output = pipe(
        prompt=prompt,
        negative_prompt=negative_prompt,
        num_frames=24,
        guidance_scale=2.0,      # для LCM ниже!
        num_inference_steps=6,   # для LCM хватает 4-8 шагов
        height=512,
        width=512,
        generator=torch.Generator("cuda").manual_seed(random.randint(0, 1000000))
    )       
    
    torch.cuda.empty_cache()
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.mp4') as tmp_file:
        video_path = tmp_file.name
    
    try:
        # Try to export with recommended backend
        export_to_video(output.frames[0], video_path, fps=8)
    except Exception as e:
        print(f"⚠️ Ошибка экспорта видео: {e}")
        # Fallback: try with different fps or settings
        try:
            export_to_video(output.frames[0], video_path, fps=6)
        except Exception:
            # If all else fails, clean up and raise
            try:
                os.unlink(video_path)
            except:
                pass
            raise Exception("Не удалось экспортировать видео")
    
    print(f"✅ Видео: {video_path}")
    return video_path

@APP.on_message(filters.command("видео") & (filters.private | filters.group))
async def video_handler(client: Client, message):
    """Generate video using AnimateDiff (local GPU)
    
    Usage: /видео <описание>
    Cost: 4000 рости
    """
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    if uid in BLACKLIST:
        await message.reply_text("❌ Вы в чёрном списке. ИИ недоступен.")
        return
    
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.reply_text(
            "🎬 Использование: /видео <описание>\n\n"
            "Пример: /видео cat running in space\n\n"
            "💰 Стоимость: 4000 рости\n"
            "⏱ Время: 1-2 минуты\n"
            "🎥 16 кадров, 512x512, локально"
        )
        return
    
    prompt = sanitize_text(parts[1].strip(), max_len=2000)  # Добавлено sanitize_text
    if len(prompt) > 2000:
        await message.reply_text("❌ Описание слишком длинное (максимум 2000 символов)")
        return
    
    cost = 4000
    bal = get_balance_db(uid)
    
    if bal < cost:
        await message.reply_text(f"❌ Недостаточно рости. Нужно: {cost}. Ваш баланс: {bal}")
        return
    
    new_bal = change_balance_db(uid, -cost)
    notify = await message.reply_text("🎬 Генерирую видео...\n⏳ 1-2 минуты")
    
    start_time = time.time()
    
    async with ANIMATEDIFF_LOCK:
        try:
            # First run: load model
            if ANIMATEDIFF_PIPE is None:
                await notify.edit("🎬 Первый запуск: загрузка модели...\n⏳ 2-3 минуты")
                await asyncio.get_event_loop().run_in_executor(None, load_animatediff_model)
            
            await notify.edit("🎬 Генерирую видео...\n⏳ ~1-2 минуты")
            
            # Generate in thread pool to not block asyncio
            loop = asyncio.get_event_loop()
            video_path = await loop.run_in_executor(
                None,
                lambda: asyncio.run(generate_animatediff_video(prompt))
            )
            
            gen_time = round(time.time() - start_time, 1)
            
            caption = (
                f"<blockquote>🎬 промпт: {prompt}\n"
                f"💰 потрачено: {cost} рости\n"
                f"⏱ время: {gen_time}с\n"
                f"🤖 модель: AnimateDiff</blockquote>"
            )

            await client.send_video(
                message.chat.id,
                video_path,
                caption=caption,
                supports_streaming=True
            )
            
            try:
                await notify.delete()
            except:
                pass
            
            try:
                os.unlink(video_path)
            except:
                pass
        
        except Exception as e:
            # Refund on error and notify user (sanitized)
            change_balance_db(uid, cost)
            error = str(e)

            if "out of memory" in error.lower():
                error = "Недостаточно VRAM. Используй /cleargpu"
            elif "model" in error.lower():
                error = "Ошибка загрузки модели"

            try:
                await notify.edit((f"❌ Ошибка генерации видео: {error}\n💰 Средства возвращены"))
            except Exception:
                # If editing fails, try sending a fresh sanitized message
                try:
                    await message.reply_text((f"❌ Ошибка генерации видео: {error}\n💰 Средства возвращены"))
                except Exception:
                    pass

@APP.on_message(filters.command("видеокарта") & filters.private)
async def gpu_status(client: Client, message):
    """Show GPU status (owner only)"""
    await ensure_owner_cached(client)
    if message.from_user.id not in OWNERS:
        return
    
    try:
        import torch

        if torch.cuda.is_available():
            gpu = torch.cuda.get_device_name(0)
            mem_alloc = torch.cuda.memory_allocated(0) / 1024**3
            mem_reserved = torch.cuda.memory_reserved(0) / 1024**3
            mem_total = torch.cuda.get_device_properties(0).total_memory / 1024**3
            
            status = (
                f"🎮 GPU: {gpu}\n"
                f"📊 Использовано: {mem_alloc:.2f}GB\n"
                f"📦 Зарезервировано: {mem_reserved:.2f}GB\n"
                f"💾 Всего: {mem_total:.2f}GB\n"
                f"🎬 Модель: {'✅' if ANIMATEDIFF_PIPE else '❌'}"
            )
        else:
            status = "❌ CUDA недоступна"
        
        await message.reply_text((status))
    except Exception as e:
        await message.reply_text((f"❌ {e}"))


@APP.on_message(filters.command("очисткагпу") & filters.private)
async def clear_gpu(client: Client, message):
    """Clear GPU memory (owner only)"""
    await ensure_owner_cached(client)
    if message.from_user.id not in OWNERS:
        return
    
    try:
        import torch
        global ANIMATEDIFF_PIPE
        
        ANIMATEDIFF_PIPE = None
        torch.cuda.empty_cache()
        
        await message.reply_text(("✅ GPU очищен"))
    except Exception as e:
        await message.reply_text((f"❌ {e}"))

# /стикер command: generate sticker and send directly
@APP.on_message(filters.command("стикер") & (filters.private | filters.group))
async def sticker_handler(client: Client, message):
    """Generate custom sticker using Pollinations.ai and send it directly.
    
    Usage: /стикер <описание>
    Cost: 800 рости
    """
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    # Check blacklist
    if uid in BLACKLIST:
        await message.reply_text("❌ Вы в чёрном списке. ИИ недоступен.")
        return
    
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.reply_text(
            "🎨 Использование: /стикер <описание>\n\n"
            "Пример: /стикер милый котик в космосе\n\n"
            "💰 Стоимость: 800 рости"
        )
        return
    
    prompt = parts[1].strip()
    if len(prompt) > 1000:
        await message.reply_text("❌ Описание слишком длинное (максимум 1000 символов)")
        return
    
    cost = 800
    bal = get_balance_db(uid)
    
    if bal < cost:
        await message.reply_text(f"❌ Недостаточно рости. Нужно: {cost}. Ваш баланс: {bal}")
        return
    
    # Deduct cost
    new_bal = change_balance_db(uid, -cost)
    
    # Send processing notification
    notify = await message.reply_text("🎨 Генерирую стикер...\n⏳ Это может занять до 1 минуты")
    
    start_time = time.time()
    
    try:
        # Переводим на английский если нужно
        english_prompt = prompt
        if any(ord(c) > 127 for c in prompt) and GEMINI_API_KEY:
            try:
                translate_url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
                translate_payload = {
                    "contents": [{
                        "parts": [{"text": f"Translate to English (short, for sticker generation): {prompt}"}]
                    }]
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(translate_url, json=translate_payload, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "candidates" in data and len(data["candidates"]) > 0:
                                english_prompt = data["candidates"][0]["content"]["parts"][0].get("text", "").strip()
            except Exception:
                pass
        
        # URL-encode prompt
        import urllib.parse
        encoded_prompt = urllib.parse.quote(english_prompt)
        
        # Generate sticker (512x512 для стикера)
        image_url = f"https://image.pollinations.ai/prompt/{encoded_prompt}?model=flux&width=512&height=512&nologo=true&enhance=true"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(image_url, timeout=aiohttp.ClientTimeout(total=90)) as response:
                if response.status != 200:
                    raise Exception(f"Ошибка генерации: {response.status}")
                
                image_bytes = await response.read()
        
        # Calculate generation time
        gen_time = round(time.time() - start_time, 1)
        
        # Save to temp file as WebP (стандарт для стикеров Telegram)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.webp') as tmp_file:
            tmp_path = tmp_file.name
            tmp_file.write(image_bytes)
        
        try:
            # Update status
            await notify.edit("🎨 Изображение готово!\n📤 Отправляю стикер...")
            
            # Формируем caption
            display_prompt = prompt[:100] + "..." if len(prompt) > 100 else prompt
            info_text = (
                f"<blockquote>🎨 промпт: {display_prompt}\n"
                f"💰 потрачено: {cost} рости\n"
                f"⏱ время: {gen_time}с\n"
                f"🤖 модель: Flux\n"
                f"💵 баланс: {new_bal} рости</blockquote>"
            )
            
            # Send as sticker
            try:
                sent_sticker = await client.send_sticker(
                    message.chat.id,
                    tmp_path
                )
                
                # Send caption separately (stickers don't support captions)
                await client.send_message(
                    message.chat.id,
                    info_text
                )
                
                # Delete notification
                try:
                    await notify.delete()
                except:
                    pass
                    
            except Exception as e:
                # If send_sticker fails, try as photo with caption
                try:
                    await client.send_photo(
                        message.chat.id,
                        tmp_path,
                        caption=info_text
                    )
                    await notify.delete()
                except Exception:
                    # Last resort: just show success message
                    success_msg = (
                        f"✅ Изображение создано!\n\n"
                        f"🎨 промпт: {prompt}\n"
                        f"💰 потрачено: {cost} рости\n"
                        f"⏱ время: {gen_time}с\n"
                        f"💵 баланс: {new_bal} рости"
                    )
                    await notify.edit(success_msg)
            
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass
    
    except Exception as e:
        # Refund on error
        change_balance_db(uid, cost)
        error_msg = str(e)
        await notify.edit(f"❌ Ошибка создания стикера: {error_msg}\n💰 Средства возвращены")


# /голос command: text-to-speech
@APP.on_message(filters.command("голос") & (filters.private | filters.group))
async def voice_handler(client: Client, message):
    """Text-to-speech command.
    
    Usage:
    /голос <текст> - one-time voice message (60 рости)
    /голос режим - (private only) toggle auto voice for all AI replies (60 рости per reply)
    """
    user = message.from_user
    if not user:
        return
    uid = user.id
    chat_id = message.chat.id
    
    parts = message.text.split(maxsplit=1)
    sub = parts[1].strip().lower() if len(parts) > 1 else ""
    
    # Toggle voice mode (private only)
    if sub in ("режим", "mode"):
        if chat_id != uid:
            await message.reply_text("❌ Команда /голос режим работает только в личных сообщениях")
            return
        
        if uid in VOICE_MODE_USERS:
            VOICE_MODE_USERS.discard(uid)
            await message.reply_text("🔇 Автоматическая озвучка отключена")
        else:
            VOICE_MODE_USERS.add(uid)
            await message.reply_text("🔊 Автоматическая озвучка включена\n💰 Стоимость: 60 рости за каждый ответ ИИ")
        return
    
    # One-time voice generation
    if not sub:
        await message.reply_text("Использование:\n/голос <текст> - озвучить текст (60 рости)\n/голос режим - (только в ЛС) авто-озвучка ответов ИИ")
        return
    
    text_to_speak = parts[1].strip()    
    if len(text_to_speak) > 500:
        await message.reply_text("❌ Текст слишком длинный (максимум 500 символов)")
        return
    
    cost = 120
    bal = get_balance_db(uid)
    
    if bal < cost:
        await message.reply_text(f"❌ Недостаточно рости. Нужно: {cost}. Ваш баланс: {bal}")
        return
    
    # Deduct cost
    new_bal = change_balance_db(uid, -cost)
    
    # Generate voice
    try:
        notify = await message.reply_text("🎤 Генерирую голосовое сообщение...")
        
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.mp3') as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            # Generate TTS
            tts = gTTS(text=text_to_speak, lang='ru')
            tts.save(tmp_path)
            
            # Send voice message
            await client.send_voice(
                chat_id,
                tmp_path,
                caption=f"🎤 Озвучка | 💰 Потрачено: {cost} рости"
            )
            
            # Delete notification
            try:
                await notify.delete()
            except:
                pass
            
        finally:
            # Clean up temp file
            try:
                os.unlink(tmp_path)
            except:
                pass
    
    except Exception as e:
        # Refund on error
        change_balance_db(uid, cost)
        await message.reply_text(f"❌ Ошибка генерации голоса: {str(e)}\n💰 Средства возвращены")


# /ворк command: private-only — mine coal and earn 5..150 рости with 15s cooldown
@APP.on_message(filters.command("ворк") & filters.private)
async def work_handler(client: Client, message):
    """Private command: /ворк — mine coal and get random rosti between 5 and 150.

    Cooldown: 15 seconds per user (in-memory).
    Output: nicely formatted markdown block.
    """
    user = message.from_user
    if not user:
        return
    uid = user.id

    now = time.time()
    cooldown_until = WORK_COOLDOWNS.get(uid, 0)
    if now < cooldown_until:
        remaining = int(cooldown_until - now)
        await message.reply_text(f"Пожалуйста, подождите {remaining} секунд перед следующим /ворк.", parse_mode=enums.ParseMode.MARKDOWN)
        return

    # roll reward
    amount = random.randint(5,150)
    new_bal = change_balance_db(uid, amount)

    # set cooldown (15 seconds)
    WORK_COOLDOWNS[uid] = now + 15

    # formatted output
    try:
        name = user.username or user.first_name or str(uid)
    except Exception:
        name = str(uid)

    out = (
        "```\n"
        f"ворка — добыча угля\n"
        "------------------------------\n"
        f"ник: {name}\n"
        f"айди: {uid}\n"
        f"добыча: уголь\n"
        f"статус: ✅ успешно\n"
        f"заработано: {amount} рости\n"
        f"баланс: {new_bal} рости\n"
        "------------------------------\n"
        "спасибо за работу! возвращайтесь через 15 сек\n"
        "```"
    )

    await message.reply_text(out, parse_mode=enums.ParseMode.MARKDOWN)


# Show user's or replied user's balance
@APP.on_message(filters.command("баланс") & (filters.private | filters.group))
async def balance_handler(client: Client, message):
    try:
        if message.reply_to_message and message.reply_to_message.from_user:
            target = message.reply_to_message.from_user
            bal = get_balance_db(target.id)
            await message.reply_text(f"Баланс {getattr(target, 'first_name', target.id)}: {bal} рости")
        else:
            user = message.from_user
            if not user:
                return
            bal = get_balance_db(user.id)
            await message.reply_text(f"Ваш баланс: {bal} рости")
    except Exception:
        await message.reply_text("Ошибка при получении баланса")


# /профиль command: show user profile
@APP.on_message(filters.command("профиль") & (filters.private | filters.group))
async def profile_handler(client: Client, message):
    """Show a user's profile.
    
    Usage:
    /профиль - show your own profile
    /профиль (in reply) - show another user's profile
    """
    target_user = None
    if message.reply_to_message and message.reply_to_message.from_user:
        target_user = message.reply_to_message.from_user
    else:
        target_user = message.from_user

    if not target_user:
        await message.reply_text("Не удалось определить пользователя.")
        return
    
    uid = target_user.id
    
    # --- Gather data ---
    # Name (Nick > First Name > Username > ID)
    try:
        name = get_nickname_db(uid) or target_user.first_name or target_user.username or str(uid)
    except Exception:
        name = str(uid)
        
    # Balance
    balance = get_balance_db(uid)
    
    # AI Usage
    try:
        usage_count = get_usage_count_db(uid) or 0
    except Exception:
        usage_count = "н/д"
        
    # Shop Info
    shop_info = "нет"
    if has_shop_db(uid):
        shop = get_shop_db(uid)
        if shop:
            shop_info = f"🏪 «{shop['name']}»"
            
    # Custom Role
    role_info = "стандартная"
    if uid in USER_ROLES:
        role_text = USER_ROLES[uid]
        role_info = f"«{role_text[:40]}{'...' if len(role_text) > 40 else ''}»"
    elif GLOBAL_ROLE:
        role_info = "глобальная"

    # --- Format output ---
    profile_text = (
        f"👤 **Профиль: {name}**\n"
        "--------------------------------\n"
        f"**ID:** `{uid}`\n"
        f"**💰 Баланс:** {balance} рости\n"
        f"**🤖 Использование ИИ:** {usage_count} раз\n"
        f"**🏪 Магазин:** {shop_info}\n"
        f"**🎭 Роль ИИ:** {role_info}\n"
        "--------------------------------"
    )
    
    await message.reply_text(profile_text, parse_mode=enums.ParseMode.MARKDOWN)



# /хелп command: show all available commands
@APP.on_message(filters.command(["хелп", "help", "команды"]) & (filters.private | filters.group))
async def help_handler(client: Client, message):
    """Show all available bot commands."""
    
    help_text = """
🤖 <b>Список команд бота</b>

<b>💬 ИИ и общение:</b>
<blockquote>/ии <текст> - запрос к ИИ (группы)
/роль <текст> - установить роль для ИИ
/роль сброс - сбросить роль
/роль <номер (1-3)> - выбрать предустановленную роль
/роль задать <номер (1-3)> <текст> - сохранить предустановленную роль
/роль глобал <текст> - глобальная роль (владелец)
/ресет - очистить историю диалога (ЛС)
/лс - вкл/выкл ИИ в личных сообщениях
<b>🎨 Генерация контента:</b>
<blockquote>/пнг <текст> - генерация изображения (300 рости)
/видео <текст> - генерация видео (3000 рости)
/мем <тема> - генерация мема/шутки (200 рости)
/стикер <текст> - создать стикер (800 рости)
/голос <текст> - озвучить текст (60 рости)
/голос режим - авто-озвучка в ЛС (60 рости/ответ)</blockquote>
<b>💰 Экономика:</b>
<blockquote>/баланс - показать баланс рости
/баланс (ответ) - баланс другого пользователя
/ворк - добыть уголь (5-150 рости, 15сек кд)
/перевод <сумма> @user - перевод рости
/деп <сумма> - казино слот-машина</blockquote>
<b>🏪 Магазин:</b>
<blockquote>/магазин - купить/инфо о магазине (1000 рости)
/магазин название <текст> - переименовать
/магазин собрать - собрать прибыль (каждые 5 мин)</blockquote>
<b>👤 Профиль:</b>
<blockquote>/профиль - показать свой профиль
/профиль (ответ) - профиль другого пользователя
/ник <ник> - установить никнейм (110 рости)
/ник сброс - удалить никнейм</blockquote>
<b>📊 Статистика:</b>
<blockquote>/табл - таблица использования ИИ
/табл р - таблица балансов рости</blockquote>
<b>⚙️ Управление (владелец):</b>
<blockquote>/права - управление правами на роли
/права купить - купить права (500 рости)
/дать рости <сумма> - выдать рости (ответ)
/чс - показать чёрный список
/чс доб - добавить в ЧС (ответ)
/чс убр - убрать из ЧС (ответ)
/sdx - управление авто-блокировкой #sdx</blockquote>
<b>ℹ️ Информация:</b>
<blockquote>/start - приветствие и информация
/хелп - это сообщение
бот - проверка работы бота</blockquote>
<b>💡 Подсказки:</b>
<blockquote>- В ЛС бот отвечает на любое сообщение
- В группах используйте /ии или ответьте на сообщение бота
- Роли позволяют настроить поведение ИИ
- Магазин приносит пассивный доход</blockquote>
"""
    
    try:
        await message.reply_text(help_text, parse_mode=enums.ParseMode.HTML)
    except Exception:
        # If markdown fails, try without formatting
        await message.reply_text(help_text.replace("**", "").replace("•", "-"))

@APP.on_message(filters.command("перевод") & (filters.private | filters.group))
async def transfer_handler(client: Client, message):
    """Handle /перевод command to transfer рости to another user.

    Usage:
    /перевод <сумма> @username
    or reply to a user's message with /перевод <сумма>
    """
    sender = message.from_user
    if not sender:
        return
    sid = sender.id

    parts = message.text.split()
    if len(parts) < 2:
        await message.reply_text("Использование:\n/перевод <сумма> @username\nили ответьте на сообщение пользователя с /перевод <сумма>")
        return

    # parse amount
    try:
        amount = int(parts[1])
    except Exception:
        await message.reply_text("Укажите корректную сумму (целое положительное число). Пример: /перевод 500 @user")
        return

    if amount <= 0:
        await message.reply_text("Сумма должна быть больше нуля")
        return

    # resolve target: prefer reply, otherwise parse mention/username/id
    target_user = None
    if message.reply_to_message and message.reply_to_message.from_user:
        target_user = message.reply_to_message.from_user
    else:
        if len(parts) >= 3:
            target_str = parts[2].strip()
            # strip @ if present
            if target_str.startswith("@"):
                target_str = target_str[1:]
            # try to resolve via get_users (username or id)
            try:
                target_user = await client.get_users(target_str)
            except Exception:
                # try parse as int id
                try:
                    uid = int(target_str)
                    target_user = await client.get_users(uid)
                except Exception:
                    target_user = None

    if not target_user:
        await message.reply_text("Не удалось определить получателя. Укажите @username или ответьте на сообщение получателя.")
        return

    tid = target_user.id
    if tid == sid:
        await message.reply_text("Нельзя переводить рости самому себе")
        return

    # check balance
    bal = get_balance_db(sid)
    if bal < amount:
        await message.reply_text(f"❌ Недостаточно рости. Нужно: {amount}. Ваш баланс: {bal}")
        return

    # perform transfer
    change_balance_db(sid, -amount)
    change_balance_db(tid, amount)

    new_bal = get_balance_db(sid)
    try:
        recipient_name = target_user.username or target_user.first_name or str(tid)
    except Exception:
        recipient_name = str(tid)

    out = (
        "```\n"
        "перевод средств\n"
        "------------------------------\n"
        f"от: {getattr(sender, 'first_name', sid)} ({sid})\n"
        f"кому: {recipient_name} ({tid})\n"
        f"сумма: {amount} рости\n"
        f"баланс отправителя: {new_bal} рости\n"
        "------------------------------\n"
        "перевод выполнен успешно ✅\n"
        "```"
    )
    await message.reply_text(out, parse_mode=enums.ParseMode.MARKDOWN)


# /дать рости subcommand: usage: reply to a user with '/дать рости <amount>' (owner only)
@APP.on_message(filters.command("дать") & (filters.private | filters.group))
async def give_handler(client: Client, message):
    parts = message.text.split(maxsplit=2)
    if len(parts) < 2:
        await message.reply_text("Использование: /дать рости <сумма> (ответ на сообщение пользователя) или /дать рости <сумма> @username")
        return

    sub = parts[1].strip().lower()
    if sub not in ("рости", "rosti", "rosty"):
        await message.reply_text("Команда используется неверно. Правильно: /дать рости <сумма>")
        return

    # need amount; prefer reply target
    amount = None
    if len(parts) >= 3:
        try:
            amount = int(parts[2])
        except Exception:
            amount = None

    # resolve target
    target = None
    if message.reply_to_message and message.reply_to_message.from_user:
        target = message.reply_to_message.from_user
    # if no reply, we currently don't support username parsing; ask to reply
    if not target:
        await message.reply_text("Пожалуйста, ответьте на сообщение пользователя, которому хотите дать рости.")
        return

    if amount is None or amount <= 0:
        await message.reply_text("Укажите корректную сумму (целое положительное число).")
        return

    # only owners may give рости manually
    await ensure_owner_cached(client)
    if message.from_user.id not in OWNERS:
        await message.reply_text("Только владелец бота может вручную выдавать рости.")
        return

    new = change_balance_db(target.id, amount)
    await message.reply_text(f"Выдано {amount} рости пользователю {getattr(target, 'first_name', target.id)}. Новый баланс: {new}")


# Command to grant/revoke role-setting rights. Only the bot owner may use this.
@APP.on_message(filters.command("права") & (filters.private | filters.group))
async def rights_handler(client: Client, message):
    """Owner-only command to grant/revoke the ability to set roles.

    Usage:
    - Reply to a user's message with `/права` to toggle their permission to use `/роль`.
    - Send `/права` alone to list current allowed users.
    """
    caller = message.from_user
    if not caller:
        return

    owner = await ensure_owner_cached(client)
    # allow purchase subcommand for everyone; other actions require owner
    parts = message.text.split(maxsplit=1)
    sub = parts[1].strip().lower() if len(parts) > 1 else ""

    # if user wants to buy rights: /права купить
    if sub.startswith("куп") or sub.startswith("buy"):
        # purchase flow (available to everyone)
        caller_id = caller.id
        price = 500
        # check if already has role editor
        if caller_id in ROLE_EDITORS:
            await message.reply_text("У вас уже есть право менять роли.")
            return
        bal = get_balance_db(caller_id)
        if bal < price:
            await message.reply_text(f"Недостаточно рости. Цена: {price}. Ваш баланс: {bal}")
            return
        # deduct and grant
        new_bal = change_balance_db(caller_id, -price)
        add_role_editor_db(caller_id)
        await message.reply_text(f"Вы успешно купили право менять роли за {price} рости. Баланс: {new_bal}")
        return

    await ensure_owner_cached(client)
    if not OWNERS:
        await message.reply_text("Невозможно определить владельца бота. Повторите позже.")
        return

    if caller.id not in OWNERS:
        # only owners can manage other rights/listing
        await message.reply_text("Команда доступна только владельцу бота.")
        return

    # if replied to a message, toggle that user's permission
    if message.reply_to_message and message.reply_to_message.from_user:
        target = message.reply_to_message.from_user
        if target.id == owner:
            await message.reply_text("Нельзя изменять права владельца.")
            return
        if target.id in ROLE_EDITORS:
            remove_role_editor_db(target.id)
            await message.reply_text(f"Права сняты с {getattr(target, 'first_name', target.id)} ✅")
        else:
            add_role_editor_db(target.id)
            await message.reply_text(f"Права выданы {getattr(target, 'first_name', target.id)} ✅")
        return

    # otherwise list current ROLE_EDITORS
    if not ROLE_EDITORS:
        await message.reply_text("Пока нет пользователей с правом менять роли.")
        return

    lines = ["Пользователи с правом менять роль:"]
    for uid in sorted(ROLE_EDITORS):
        try:
            u = await client.get_users(uid)
            name = u.username or u.first_name or str(uid)
        except Exception:
            name = str(uid)
        lines.append(f"- {name} ({uid})")

    await message.reply_text("\n".join(lines))


# /деп command: casino slot machine
@APP.on_message(filters.command("деп") & (filters.private | filters.group))
async def casino_handler(client: Client, message):
    """Casino slot machine command.
    
    Usage: /деп <сумма>
    
    Rules:
    - 3 matching numbers: win 2x bet
    - 2 matching numbers: win 0.5x bet (lose half)
    - 0 matching numbers: lose all bet
    """
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.reply_text(
            "🎰 Использование: /деп <сумма>\n\n"
            "Правила:\n"
            "3️⃣ три одинаковых → выигрыш x2\n"
            "2️⃣ два одинаковых → возврат половины\n"
            "❌ ничего → проигрыш\n\n"
            "Пример: /деп 100"
        )
        return
    
    # Parse bet amount
    try:
        bet = int(parts[1].strip())
    except ValueError:
        await message.reply_text("❌ Укажите корректную сумму (целое число)")
        return
    
    if bet <= 0:
        await message.reply_text("❌ Сумма должна быть больше 0")
        return
    
    # Check balance
    bal = get_balance_db(uid)
    if bal < bet:
        await message.reply_text(f"❌ Недостаточно рости. Ваш баланс: {bal}")
        return
    
    # Deduct bet
    change_balance_db(uid, -bet)
    
    # Emoji numbers
    emoji_nums = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣"]
    
    # Send initial message
    slots_msg = await message.reply_text("🎰 Крутим барабаны...")
    
    # Animation: 5 spins with random numbers
    for spin in range(5):
        slot1 = random.choice(emoji_nums)
        slot2 = random.choice(emoji_nums)
        slot3 = random.choice(emoji_nums)
        
        animation_text = f"🎰 | {slot1} {slot2} {slot3} |"
        
        try:
            await slots_msg.edit(animation_text)
            await asyncio.sleep(0.4)  # Animation delay
        except Exception:
            pass
    
    # Final spin - determine outcome with weighted probabilities
    # Lower chances of winning
    roll = random.randint(1, 100)
    
    if roll <= 5:  # 5% chance - 3 matching (jackpot)
        num = random.choice(emoji_nums)
        final_slots = [num, num, num]
        matches = 3
    elif roll <= 20:  # 15% chance - 2 matching
        num = random.choice(emoji_nums)
        other = random.choice([n for n in emoji_nums if n != num])
        final_slots = [num, num, other]
        random.shuffle(final_slots)
        matches = 2
    else:  # 80% chance - no match (loss)
        # Ensure all different numbers
        available = emoji_nums.copy()
        slot1 = random.choice(available)
        available.remove(slot1)
        slot2 = random.choice(available)
        available.remove(slot2)
        slot3 = random.choice(available)
        final_slots = [slot1, slot2, slot3]
        matches = 0
    
    # Show final result
    final_text = f"🎰 | {final_slots[0]} {final_slots[1]} {final_slots[2]} |\n\n"
    
    # Calculate winnings
    if matches == 3:
        winnings = bet * 2
        change_balance_db(uid, winnings)
        new_bal = get_balance_db(uid)
        final_text += (
            "🎉 ДЖЕКПОТ! Три одинаковых!\n"
            f"💰 Выигрыш: +{winnings} рости\n"
            f"💵 Баланс: {new_bal} рости"
        )
    elif matches == 2:
        winnings = bet // 2
        change_balance_db(uid, winnings)
        new_bal = get_balance_db(uid)
        loss = bet - winnings
        final_text += (
            "😐 Два одинаковых\n"
            f"💰 Возврат: +{winnings} рости\n"
            f"📉 Потеря: -{loss} рости\n"
            f"💵 Баланс: {new_bal} рости"
        )
    else:
        new_bal = get_balance_db(uid)
        final_text += (
            "😞 Проигрыш! Ничего не совпало\n"
            f"📉 Потеря: -{bet} рости\n"
            f"💵 Баланс: {new_bal} рости"
        )
    
    try:
        await slots_msg.edit(final_text)
    except Exception:
        await message.reply_text(final_text)


@APP.on_message(filters.text & filters.regex(r"(?i)^\s*бот\s*$"))
async def bot_presence_reply(client: Client, message):
        await message.reply_text(
            "<blockquote>На месте✅<    /blockquote>",
            parse_mode=enums.ParseMode.HTML
        )

@APP.on_message(filters.command("чипсы") & (filters.private | filters.group))
async def bot_presence_reply(client: Client, message):
        await message.reply_text(
            """
            опа доставай карманныы оо а чё это у тебя предметы
            <blockquote>предметы: найдены
            картель: вызван
            приедет: 13:57
            мфц: зло
            чипсы: созданы
            свага:присутствует</blockquote>
            """,
            parse_mode=enums.ParseMode.HTML
        )


# /чс command: manage blacklist (owner only)
@APP.on_message(filters.command("чс") & (filters.private | filters.group))
async def blacklist_handler(client: Client, message):
    """Manage AI blacklist. Owner-only command.
    
    Usage:
    - /чс - show blacklist
    - /чс доб (reply to user) - add user to blacklist
    - /чс убр (reply to user) - remove user from blacklist
    """
    caller = message.from_user
    if not caller:
        return
    
    # Check if caller is owner
    await ensure_owner_cached(client)
    if not OWNERS or caller.id not in OWNERS:
        await message.reply_text("Команда доступна только владельцам бота.")
        return
    
    parts = message.text.split(maxsplit=1)
    sub = parts[1].strip().lower() if len(parts) > 1 else ""
    
    # Show blacklist
    if not sub:
        if not BLACKLIST:
            await message.reply_text("Чёрный список пуст.")
            return
        
        lines = ["👤 Чёрный список (ИИ недоступен):"]
        for uid in sorted(BLACKLIST):
            try:
                u = await client.get_users(uid)
                name = u.username or u.first_name or str(uid)
            except Exception:
                name = str(uid)
            lines.append(f"• {name} ({uid})")
        
        await message.reply_text("\n".join(lines))
        return
    
    # Add to blacklist
    if sub.startswith("доб") or sub.startswith("add"):
        if not message.reply_to_message or not message.reply_to_message.from_user:
            await message.reply_text("Ответьте на сообщение пользователя, которого хотите добавить в ЧС.")
            return
        
        target = message.reply_to_message.from_user
        if target.id in OWNERS:
            await message.reply_text("Нельзя добавить владельца в чёрный список.")
            return
        
        if target.id in BLACKLIST:
            await message.reply_text(f"{getattr(target, 'first_name', target.id)} уже в чёрном списке.")
            return
        
        add_to_blacklist_db(target.id)
        await message.reply_text(f"✅ {getattr(target, 'first_name', target.id)} добавлен в чёрный список. ИИ для него недоступен.")
        return
    
    # Remove from blacklist
    if sub.startswith("убр") or sub.startswith("rem") or sub.startswith("del"):
        if not message.reply_to_message or not message.reply_to_message.from_user:
            await message.reply_text("Ответьте на сообщение пользователя, которого хотите убрать из ЧС.")
            return
        
        target = message.reply_to_message.from_user
        if target.id not in BLACKLIST:
            await message.reply_text(f"{getattr(target, 'first_name', target.id)} не в чёрном списке.")
            return
        
        remove_from_blacklist_db(target.id)
        await message.reply_text(f"✅ {getattr(target, 'first_name', target.id)} убран из чёрного списка.")
        return
    
    # Unknown subcommand
    await message.reply_text(
        "Использование:\n"
        "/чс - показать список\n"
        "/чс доб (ответ на сообщение) - добавить\n"
        "/чс убр (ответ на сообщение) - убрать"
    )


# Handle all text messages in private chats
@APP.on_message(filters.private & (filters.text | filters.photo) & ~filters.command(""))
async def private_chat_handler(client: Client, message):
    """Handle all text messages and photos in private chats - forward them to AI."""
    
    # ======= ПРОВЕРКА НА БОТА (ПЕРВАЯ СТРОКА!) =======
    if is_bot_user(message.from_user):
        return  # Игнорируем ботов полностью
    
    if not gemini_client:
        await message.reply_text("Ошибка: Gemini API не настроен")
        return
    
    # Ignore commands
    try:
        text = getattr(message, 'text', '') or getattr(message, 'caption', '') or ''
        if text.strip().startswith('/'):
            return
    except Exception:
        pass
    
    user = message.from_user
    user_id = user.id if user else None
    if user_id and user_id in DISABLED_PRIVATE_USERS:
        return

    # Check ignore tags
    try:
        if user_has_ignore_tag(user):
            return
    except Exception:
        pass

    # Получаем текст из text или caption
    prompt_text = getattr(message, 'text', None) or getattr(message, 'caption', None)
    
    # Если это фото без текста, используем дефолтный промпт
    if not prompt_text and message.photo:
        prompt_text = "Что изображено на этом фото?"
    
    if not prompt_text:
        return  # Игнорируем сообщения без текста и без фото
    
    await process_ai_request(client, message, prompt_text, skip_notification=True)


# Helper function to process AI requests
async def process_ai_request(client: Client, message, prompt_text: str, skip_notification: bool = False) -> None:
    """Process an AI request with the given prompt text and optional image.
    
    Args:
        client: The Pyrogram client
        message: The message to respond to
        prompt_text: The prompt text to send to the AI
        skip_notification: If True, skip the "processing" notification (used in private chats)
    """
    global gemini_client
    
    # ======= ПРОВЕРКА НА БОТА =======
    if is_bot_user(message.from_user):
        return  # Игнорируем ботов
    
    chat_id = message.chat.id
    user_id = message.from_user.id if message.from_user else None
    
    # Apply SDX auto-blacklist rule
    try:
        if SDX_AUTO_BLACKLIST and message.from_user:
            fn = getattr(message.from_user, 'first_name', '') or ''
            ln = getattr(message.from_user, 'last_name', '') or ''
            combined = f"{fn} {ln}".lower()
            if "#sdx" in combined:
                if user_id and user_id not in BLACKLIST:
                    try:
                        add_to_blacklist_db(user_id)
                    except Exception:
                        pass
    except Exception:
        pass

    # Check blacklist
    if user_id and user_id in BLACKLIST:
        try:
            await message.reply_text("❌ Вы в чёрном списке. ИИ недоступен.")
        except Exception:
            pass
        return
    
    # Track usage in database
    if message.from_user:
        increment_usage(message.from_user)
    
    # Dedupe check
    if not skip_notification:
        msg_id = message.id
        key = (chat_id, msg_id)
        if key in PROCESSED_MESSAGES:
            print(f"Duplicate request ignored for {key}")
            return
        PROCESSED_MESSAGES.add(key)
        try:
            asyncio.create_task(_remove_processed_after(key, PROCESSED_TTL))
        except Exception:
            pass
    
    notify = None
    if not skip_notification:
        try:
            notify = await message.reply_text("Отправляю запрос в ИИ...")
        except Exception:
            return

    async def call_gemini_async(prompt: str, image_data: bytes = None, image_mime: str = None):
        try:
            # Get user's custom role
            role = DEFAULT_ROLE
            if user_id and user_id in USER_ROLES:
                role = USER_ROLES[user_id]
            elif GLOBAL_ROLE:
                role = GLOBAL_ROLE

            history = get_chat_history(user_id, chat_id) if chat_id == user_id else ""

            role_parts = []

            # Nickname logic
            try:
                if user_id and user_id in USER_NICKS:
                    nick = USER_NICKS.get(user_id)
                    if nick:
                        role_parts.append(
                            f"обращайся к пользователю всегда как «{nick}». обязательно используй этот ник при обращении и упомяни его в приветствии, например: 'привет, {nick}' или 'здравствуйте, {nick}', в зависимости от ситуации. ник обязателен."
                        )
            except Exception:
                pass

            role_parts.extend([
                "ТЫ СЕЙЧАС В РОЛИ. ЭТО ТВОЯ ЛИЧНОСТЬ, НЕ ОПИСЫВАЙ ЕЕ - ЖИВИ ЕЙ:",
                role,
                "\nНИКОГДА не говори что ты 'ролевая модель' или 'ии'. НИКОГДА не описывай свою роль - просто веди себя согласно ей.",
                "воспринимай вход вида: '<промпт> (сообщение на которое ответили: <текст>)' "
                "как обычный пользовательский запрос и учитывай текст в скобках как дополнительный контекст."
            ])

            role_parts.append(
                "если ситуация крайняя (оскорбления, угрозы, сильная негативная эмоция), "
                "добавь в конец ответа машинный тег в формате [EMO:angry] или [EMO:sad] — только в крайних случаях."
            )
            
            if history:
                role_parts.append("\nИстория диалога:\n" + history)
            
            role_parts.append("\nТеперь ответь на запрос пользователя, оставаясь В РОЛИ:")
                
            full_prompt = "\n\n".join([
                *role_parts,
                prompt
            ])
            
            # HTTP запрос к Gemini API
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
            
            # Формируем части запроса
            parts = [{"text": full_prompt}]
            
            # Добавляем изображение если есть
            if image_data and image_mime:
                parts.append({
                    "inline_data": {
                        "mime_type": image_mime,
                        "data": base64.b64encode(image_data).decode('utf-8')
                    }
                })
            
            payload = {
                "contents": [{
                    "parts": parts
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=60)) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        return f"Ошибка API: {response.status}", None
                    
                    data = await response.json()
                    
                    if "candidates" in data and len(data["candidates"]) > 0:
                        candidate = data["candidates"][0]
                        if "content" in candidate and "parts" in candidate["content"]:
                            raw_text = candidate["content"]["parts"][0].get("text", "")
                            
                            # Extract hidden EMO tag
                            emo_match = re.search(r"\[\s*EMO\s*:\s*(angry|sad)\s*\]\s*$", raw_text, flags=re.IGNORECASE)
                            detected_emotion = emo_match.group(1).lower() if emo_match else None

                            # Strip tag from visible text
                            if emo_match:
                                visible_text = raw_text[:emo_match.start()].rstrip()
                            else:
                                visible_text = raw_text

                            result_text = (visible_text)

                            # Update history for private chats
                            if chat_id == user_id:
                                update_chat_history(user_id, chat_id, "пользователь", prompt)
                                update_chat_history(user_id, chat_id, "ассистент", result_text)

                            return result_text, detected_emotion
                    
                    return "Ошибка: пустой ответ от Gemini", None
            
        except Exception as e:
            error_msg = str(e).lower()
            if "api" in error_msg and "key" in error_msg:
                return "Gemini: неверный API ключ", None
            elif "quota" in error_msg or "limit" in error_msg:
                return "Gemini: превышен лимит запросов. Попробуйте позже.", None
            else:
                return f"Ошибка: {str(e)}", None

    # Проверяем наличие изображения
    image_data = None
    image_mime = None
    
    # Проверяем текущее сообщение на изображение
    if message.photo:
        try:
            if notify:
                await notify.edit("🖼️ Загружаю изображение...")
            
            # Скачиваем фото
            photo = message.photo
            file_path = await client.download_media(photo.file_id, in_memory=True)
            image_data = file_path.getvalue() if hasattr(file_path, 'getvalue') else file_path
            image_mime = "image/jpeg"
        except Exception as e:
            print(f"Ошибка загрузки фото: {e}")
    
    # Проверяем ответ на сообщение с изображением
    elif message.reply_to_message and message.reply_to_message.photo:
        try:
            if notify:
                await notify.edit("🖼️ Загружаю изображение из ответа...")
            
            photo = message.reply_to_message.photo
            file_path = await client.download_media(photo.file_id, in_memory=True)
            image_data = file_path.getvalue() if hasattr(file_path, 'getvalue') else file_path
            image_mime = "image/jpeg"
        except Exception as e:
            print(f"Ошибка загрузки фото из ответа: {e}")

    # Serialize requests per chat
    lock = CHAT_LOCKS.setdefault(chat_id, asyncio.Lock())
    try:
        async with lock:
            try:
                result, detected_emotion = await call_gemini_async(prompt_text, image_data, image_mime)
            except Exception:
                result = "Ошибка при выполнении запроса. Попробуйте позже."
                detected_emotion = None
    except Exception:
        try:
            result, detected_emotion = await call_gemini_async(prompt_text, image_data, image_mime)
        except Exception:
            result = "Ошибка при выполнении запроса. Попробуйте позже."
            detected_emotion = None

    # Truncate visible result if exceeds MAX_VISIBLE_LEN
    try:
        if isinstance(result, str) and len(result) > MAX_VISIBLE_LEN:
            result = result[:MAX_VISIBLE_LEN]
            key = (user_id, chat_id)
            if key in CHAT_HISTORY:
                for i in range(len(CHAT_HISTORY[key]) - 1, -1, -1):
                    if CHAT_HISTORY[key][i][0] == "ассистент":
                        CHAT_HISTORY[key][i] = ("ассистент", result)
                        break
    except Exception:
        pass
    
    result = sanitize_text(result, max_len=1900)

    # Send reply
    if message.reply_to_message:
        reply_to_id = message.reply_to_message.id
    else:
        reply_to_id = message.id if chat_id == user_id else None

    try:
        sent_msg = None
        if reply_to_id:
            sent_msg = await client.send_message(
                chat_id,
                result,
                reply_parameters=types.ReplyParameters(message_id=reply_to_id)
            )
            if notify:
                try:
                    await notify.edit("Готово ✅")
                except Exception:
                    pass
        elif notify:
            try:
                edited = await notify.edit((result))
                sent_msg = edited
            except Exception:
                sent_msg = await message.reply_text(result)
        else:
            sent_msg = await message.reply_text(result)

        # Auto-voice in private chats if enabled
        try:
            if user_id and chat_id == user_id and user_id in VOICE_MODE_USERS:
                voice_cost = 60
                bal = get_balance_db(user_id)
                if bal >= voice_cost:
                    change_balance_db(user_id, -voice_cost)
                    
                    voice_text = result[:500] if len(result) > 500 else result
                    
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.mp3') as tmp_file:
                        tmp_path = tmp_file.name
                    
                    try:
                        tts = gTTS(text=voice_text, lang='ru')
                        tts.save(tmp_path)
                        
                        await client.send_voice(
                            chat_id,
                            tmp_path,
                            caption=f"🎤 Авто-озвучка | 💰 -{voice_cost} рости"
                        )
                    finally:
                        try:
                            os.unlink(tmp_path)
                        except:
                            pass
                else:
                    VOICE_MODE_USERS.discard(user_id)
                    await client.send_message(
                        chat_id,
                        "🔇 Автоматическая озвучка отключена: недостаточно рости"
                    )
        except Exception:
            pass

        # Send sticker if emotion detected
        try:
            if AUTO_SEND_STICKER and sent_msg:
                used_emotion = detected_emotion if 'detected_emotion' in locals() and detected_emotion else detect_emotion_from_input(prompt_text, getattr(message, 'text', '') or '')
                if used_emotion:
                    sticker_id = STICKER_MAP.get(used_emotion)
                    if sticker_id and not sticker_id.startswith("REPLACE_WITH_"):
                        try:
                            sticker_reply_id = getattr(sent_msg, "id", None)
                            if sticker_reply_id:
                                await client.send_sticker(
                                    chat_id,
                                    sticker_id,
                                    reply_parameters=types.ReplyParameters(message_id=sticker_reply_id)
                                )
                            else:
                                await client.send_sticker(chat_id, sticker_id)
                        except Exception:
                            pass
        except Exception:
            pass
    except Exception as e:
        if notify:
            try:
                await notify.edit((result))
            except Exception:
                await message.reply_text((result))
        else:
            await message.reply_text(result)


# /ai command: send user prompt to Gemini
@APP.on_message((filters.command("ии") & filters.group) | (filters.command(["ии", "role"]) & filters.private))
async def ai_handler(client: Client, message):
    """Handle /ai command. Usage:
    /ai your prompt here
    or reply to a message containing the prompt with /ai
    or send /ai with a photo
    """
    try:
        msg_id = message.id
        chat_id = message.chat.id
    except Exception:
        msg_id = getattr(message, "id", None)
        chat_id = getattr(message.chat, "id", None)

    # If this is a private chat and the user's username is in IGNORE_TAGS, silently ignore.
    try:
        user = message.from_user
        if user and chat_id == getattr(user, 'id', None) and user_has_ignore_tag(user):
            return
    except Exception:
        pass

    if not gemini_client:
        await message.reply_text("Ошибка: Gemini API не настроен. Проверьте переменную окружения GEMINI_API_KEY")
        return

    # Extract prompt - check both text and caption (для фото с подписью)
    prompt_text = None
    message_text = getattr(message, 'text', None) or getattr(message, 'caption', None) or ""
    parts = message_text.split(maxsplit=1) if message_text else ["/ии"]
    user_provided = parts[1].strip() if len(parts) > 1 else None

    # Check if there's a photo in current message
    has_photo = bool(message.photo)
    
    if message.reply_to_message and user_provided:
        # user replied to someone's message and provided their own prompt in the command
        replied_raw = getattr(message.reply_to_message, "text", "") or getattr(message.reply_to_message, "caption", "") or ""
        # remove markdown asterisks from the replied text per user request
        replied_sanitized = replied_raw.replace("*", "")
        # collapse whitespace
        replied_sanitized = re.sub(r"\s+", " ", replied_sanitized).strip()
        prompt_text = f"{user_provided} (сообщение на которое ответили: {replied_sanitized})"
    elif message.reply_to_message and not user_provided:
        # no extra prompt provided: use the replied-to message as the prompt (legacy behavior)
        prompt_text = getattr(message.reply_to_message, "text", None) or getattr(message.reply_to_message, "caption", None)
    else:
        # not a reply: use text after command if present
        if user_provided:
            prompt_text = user_provided
        elif has_photo:
            # Фото без текста - используем дефолтный промпт
            prompt_text = "Что изображено на этом фото?"

    if not prompt_text:
        await message.reply_text("Пожалуйста, укажите промпт: `/ии <текст>`, отправьте фото с подписью, или ответьте на сообщение с текстом и используйте /ии.")
        return

    # Применяем sanitize_text перед отправкой в process_ai_request
    prompt_text = sanitize_text(prompt_text, max_len=1900)
    
    await process_ai_request(client, message, prompt_text)


if __name__ == "__main__":
    # Initialize Gemini client
    api_key = "AIzaSyCz_X6r9gIIGp85DYnW0AZ-eJVyBpglwA0"
    if api_key:
        try:
            GEMINI_API_KEY = api_key
            gemini_client = True
            print("✅ Gemini API инициализирован (HTTP режим)")
        except Exception as e:
            print(f"⚠️ Не удалось инициализировать Gemini: {e}")
    else:
        print("⚠️ GEMINI_API_KEY не установлен. Команда /ai будет недоступна")
    
    # Initialize database
    init_db()
    # Load persisted settings
    try:
        load_persistent_state()
    except Exception:
        pass
    # Persist external owner id
    try:
        add_owner_db(5999801817)
        print("Добавлен внешний владелец: 5999801817")
    except Exception:
        pass
    
    APP.run()
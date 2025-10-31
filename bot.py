"""Telegram бот на aiogram: AI функционал, экономика, генерация контента.

Usage:
 - Установите зависимости: pip install aiogram aiohttp gtts
 - Укажите BOT_TOKEN и GEMINI_API_KEY
 - Запустите: python bot.py
"""

import os
import asyncio
import random
import time
import re
import aiohttp
import tempfile
import base64
from typing import List, Set, Tuple, Optional
from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.filters import Command, CommandStart, CommandObject
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from gtts import gTTS

# Импортируем все функции БД из оригинального файла
from db import *
import db as _db

# --------------------------- CONFIGURATION ---------------------------
BOT_TOKEN = "7857484512:AAGQ4eXyk3Y0A0J8meHleE-ze95455Nlp4E"
GEMINI_API_KEY = "AIzaSyCz_X6r9gIIGp85DYnW0AZ-eJVyBpglwA0"
GEMINI_MODEL = "gemini-2.0-flash-exp"

TARGET_EXTS = {".catrobat", ".apk"}
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

# Global state (то же самое что в оригинале)
PROCESSED_MESSAGES: Set[Tuple[int, int]] = set()
PROCESSED_TTL = 10
CHAT_LOCKS = {}
USER_ROLES = {}
USER_NICKS = {}
NICK_TO_USER = {}
CHAT_HISTORY = {}
ROLE_EDITORS = set()
OWNER_ID: Optional[int] = None
OWNERS: Set[int] = set()
GLOBAL_ROLE: Optional[str] = None
DISABLED_PRIVATE_USERS: Set[int] = set()
SDX_AUTO_BLACKLIST: bool = False
BLACKLIST: Set[int] = set()
WORK_COOLDOWNS = {}
SHOP_COLLECTION_COOLDOWNS = {}
VOICE_MODE_USERS: Set[int] = set()
IGNORE_TAGS: List[str] = ["Stickers", "SpamBot"]
ANIMATEDIFF_PIPE = None
ANIMATEDIFF_LOCK = asyncio.Lock()

MAX_HISTORY_LENGTH = 10
DEFAULT_ROLE = "отвечай коротко и по делу. общайся как обычный человек: пиши с маленькой буквы, неформально, можешь использовать сленг и шутки. будь участником чата, а не ботом. никогда не упоминай, что ты ии. если вопрос кажется глупым, можешь подшутить над этим, но без прямых оскорблений."
MAX_VISIBLE_LEN = 999

EMOTION_WORDS = ("angry", "sad")
STICKER_MAP = {
    "angry": "CAACAgQAAxkBAAEPor1o_LMxeUOqefwn1ioGGcocUglGdAACRQ0AAnS2iFJNeTRC6V6UQzYE",
    "sad": "CAACAgQAAxkBAAEPorBo_K80zNqw7s5s9ncej0w9GDgXswACVg4AAqfJgVJ8b9p8nX8-XDYE",
}
AUTO_SEND_STICKER = True

INSULT_WORDS = [
    "дурак", "идиот", "тупой", "кретин", "урод", "сволочь", "сучка", "пошёл", "нахуй",
    "пидор", "иди нахуй"
]

gemini_client = None

# Обёртки для синхронизации кэша (из оригинала)
def add_role_editor_db(user_id: int) -> None:
    _db.add_role_editor_db(user_id)
    ROLE_EDITORS.add(user_id)

def remove_role_editor_db(user_id: int) -> None:
    _db.remove_role_editor_db(user_id)
    ROLE_EDITORS.discard(user_id)

def add_owner_db(user_id: int) -> None:
    _db.add_owner_db(user_id)
    OWNERS.add(int(user_id))
    try:
        add_role_editor_db(int(user_id))
    except:
        pass

def set_global_role_db(value: Optional[str]) -> None:
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
    _db.set_sdx_flag(value)
    globals()['SDX_AUTO_BLACKLIST'] = bool(value)

def load_persistent_state():
    global ROLE_EDITORS, GLOBAL_ROLE, DISABLED_PRIVATE_USERS, BLACKLIST, OWNERS, SDX_AUTO_BLACKLIST
    try:
        ROLE_EDITORS = _db.get_role_editors_db()
    except:
        ROLE_EDITORS = set()
    try:
        GLOBAL_ROLE = _db.get_global_role_db()
    except:
        GLOBAL_ROLE = None
    try:
        DISABLED_PRIVATE_USERS = _db.get_disabled_private_db()
    except:
        DISABLED_PRIVATE_USERS = set()
    try:
        BLACKLIST = _db.get_blacklist_db()
    except:
        BLACKLIST = set()
    try:
        OWNERS = _db.get_owners_db()
    except:
        OWNERS = set()
    try:
        globals()['SDX_AUTO_BLACKLIST'] = _db.get_sdx_flag()
    except:
        globals()['SDX_AUTO_BLACKLIST'] = False

# --------------------------- UTILITIES ---------------------------
def human_readable_size(num_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"

def build_detection_message(file_name: str, ext: str, size_bytes: int) -> str:
    total_avs = min(len(DETECTIONS), 67)
    roll = random.randint(1, 10)
    is_virus = (roll != 4)
    
    if is_virus:
        detected_count = random.randint(40, total_avs)
    else:
        detected_count = random.randint(0, min(39, total_avs))
    
    statuses = [True] * detected_count + [False] * (total_avs - detected_count)
    pairs = list(zip(DETECTIONS[:total_avs], statuses))
    random.shuffle(pairs)
    
    body_lines = [f"{'❌' if detected else '✅'} {name}" for name, detected in pairs]
    
    header = (
        ("🛑ВНИМАНИЕ🛑 ФАЙЛ - ВИРУС!!!" if is_virus else "✅ ФАЙЛ - НЕ ОБНАРУЖЕН / ЧИСТЫЙ")
        + f"\n🧬 Обнаружения: {detected_count} / {total_avs}\n"
    )
    
    file_info = (
        f"\n📖 Имя файла: {file_name}\n"
        f"🔒 Формат файла: {ext.lstrip('.')}\n"
        f"📏 Размер файла: {human_readable_size(size_bytes)}"
    )
    
    return header + "\n".join(body_lines) + "\n\n" + file_info

def sanitize_text(text: str, max_len: int = 1900) -> str:
    if not text:
        return text
    
    text = re.sub(r"https?://\S+", "[ссылка удалена]", text, flags=re.IGNORECASE)
    text = re.sub(r"www\.\S+", "[ссылка удалена]", text, flags=re.IGNORECASE)
    domain_pattern = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", flags=re.IGNORECASE)
    text = domain_pattern.sub("[ссылка удалена]", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    
    if len(text) > max_len:
        return text[:max_len - 3] + "..."
    return text

def user_has_ignore_tag(user) -> bool:
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
    except:
        return False
    return False

def is_bot_user(user) -> bool:
    if not user:
        return False
    try:
        if getattr(user, 'is_bot', False):
            return True
        username = (getattr(user, 'username', '') or '').lower()
        if 'bot' in username:
            return True
        first_name = (getattr(user, 'first_name', '') or '').lower()
        last_name = (getattr(user, 'last_name', '') or '').lower()
        if 'bot' in first_name or 'bot' in last_name:
            return True
        return False
    except:
        return False

def update_chat_history(user_id: int, chat_id: int, role: str, text: str):
    if chat_id == user_id:
        key = (user_id, chat_id)
        if key not in CHAT_HISTORY:
            CHAT_HISTORY[key] = []
        CHAT_HISTORY[key].append((role, text))
        if len(CHAT_HISTORY[key]) > MAX_HISTORY_LENGTH:
            CHAT_HISTORY[key] = CHAT_HISTORY[key][-MAX_HISTORY_LENGTH:]

def get_chat_history(user_id: int, chat_id: int) -> str:
    if chat_id != user_id:
        return ""
    key = (user_id, chat_id)
    if key not in CHAT_HISTORY:
        return ""
    history = []
    for role, text in CHAT_HISTORY[key]:
        history.append(f"{role}: {text}")
    return "\n".join(history)

def detect_emotion_from_input(prompt: str, original_text: str) -> Optional[str]:
    text = " ".join(filter(None, [prompt, original_text])).lower()
    for w in INSULT_WORDS:
        if w in text:
            return "sad"
    return None

async def _remove_processed_after(key: Tuple[int, int], ttl: int) -> None:
    try:
        await asyncio.sleep(ttl)
    except:
        return
    PROCESSED_MESSAGES.discard(key)

async def ensure_owner_cached(bot: Bot) -> Optional[int]:
    global OWNER_ID
    if OWNER_ID is not None:
        return OWNER_ID
    try:
        me = await bot.get_me()
        OWNER_ID = me.id
        if OWNER_ID:
            try:
                add_owner_db(OWNER_ID)
            except:
                OWNERS.add(OWNER_ID)
        return OWNER_ID
    except:
        return None

# --------------------------- HANDLERS ---------------------------
router = Router()

@router.message(F.document)
async def on_document(message: types.Message):
    doc = message.document
    if not doc or not doc.file_name:
        return
    
    file_name = doc.file_name
    _, ext = os.path.splitext(file_name)
    if ext.lower() not in TARGET_EXTS:
        return
    
    try:
        reply = await message.reply("Найден файл! Начинаю сканирование...")
    except:
        return
    
    await asyncio.sleep(5)
    detection_text = build_detection_message(file_name, ext, doc.file_size or 0)
    
    try:
        await reply.edit_text(detection_text)
    except:
        await message.reply(detection_text)

@router.message(CommandStart())
async def start_handler(message: types.Message, bot: Bot):
    if message.chat.type != "private":
        if not message.reply_to_message:
            return
        try:
            me = await bot.get_me()
        except:
            return
        replied = message.reply_to_message.from_user
        if not replied or replied.id != me.id:
            return
    
    greeting = (
        "Привет! Я — VirusTest бот.\n"
        "Отправь мне файл как документ (например .catrobat, .apk) и я его просканирую.\n\n"
        "В группах команда работает только если вы ответили на любое моё сообщение — так меньше спама."
    )
    
    try:
        await message.reply(greeting)
    except:
        return

@router.message(Command("роль"))
async def role_handler(message: types.Message, bot: Bot, command: CommandObject):
    user_id = message.from_user.id if message.from_user else None
    if not user_id:
        return
    
    await ensure_owner_cached(bot)
    
    if user_id not in ROLE_EDITORS:
        await message.reply("У вас нет прав для установки роли. Обратитесь к владельцу бота. Либо купите права на роль за 500 рости", parse_mode=ParseMode.MARKDOWN)
        return
    
    args = command.args
    if not args:
        help_text = (
            "Использование:\n"
            "/роль твоё описание роли\n"
            "или /роль сброс для сброса\n\n"
            "Пример: /роль отвечай как программист, используя технические термины\n"
            "Для глобальной роли (только владелец): /роль глобал <текст> или /роль глобал сброс"
        )
        help_text_md = re.sub(r'([_\\-*\[\]()~`>#+=|{}.!])', r'\\\1', help_text)
        await message.reply(help_text_md, parse_mode=ParseMode.MARKDOWN)
        return
    
    subparts = args.split(maxsplit=1)
    if subparts[0].lower() in ("глобал", "global"):
        owner = await ensure_owner_cached(bot)
        if owner is None or (message.from_user and message.from_user.id != owner):
            await message.reply("Только владелец бота может менять глобальную роль.")
            return
        
        if len(subparts) == 1:
            await message.reply("Использование: /роль глобал <текст> или /роль глобал сброс")
            return
        
        rest = subparts[1].strip()
        if rest.lower() in ("сброс", "reset"):
            set_global_role_db(None)
            await message.reply("Глобальная роль сброшена ✅", parse_mode=ParseMode.MARKDOWN)
        else:
            set_global_role_db(rest)
            await message.reply("Глобальная роль установлена ✅", parse_mode=ParseMode.MARKDOWN)
        return
    
    role = args
    if role.lower() in ("сброс", "reset"):
        USER_ROLES.pop(user_id, None)
        await message.reply("Роль сброшена на стандартную ✅", parse_mode=ParseMode.MARKDOWN)
    else:
        USER_ROLES[user_id] = role
        await message.reply("Новая роль установлена ✅", parse_mode=ParseMode.MARKDOWN)

@router.message(Command("ник"))
async def nick_handler(message: types.Message, command: CommandObject):
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    args = command.args
    if not args:
        await message.reply("Использование:\n/ник <ник> - установить ник (110 рости)\n/ник сброс - удалить ник")
        return
    
    arg = args.strip()
    if arg.lower() in ("сброс", "reset"):
        cur = get_nickname_db(uid)
        if not cur:
            await message.reply("У вас нет установленного ника.")
            return
        remove_nickname_db(uid)
        await message.reply("Ник успешно сброшен ✅")
        return
    
    desired = arg
    if len(desired) > 32:
        await message.reply("Ник слишком длинный (максимум 32 символа)")
        return
    
    current = get_nickname_db(uid)
    if current and current == desired:
        await message.reply(f"У вас уже установлен ник: {current}")
        return
    
    existing_owner = get_user_by_nickname_db(desired)
    if existing_owner and existing_owner != uid:
        await message.reply(f"Ник '{desired}' уже занят.")
        return
    
    price = 110
    bal = get_balance_db(uid)
    if bal < price:
        await message.reply(f"❌ Недостаточно рости. Нужно: {price}. Ваш баланс: {bal}")
        return
    
    new_bal = change_balance_db(uid, -price)
    try:
        set_nickname_db(uid, desired)
    except Exception as e:
        change_balance_db(uid, price)
        await message.reply(f"Ошибка при установке ника: {str(e)}\nСредства возвращены")
        return
    
    out = (
        f"💰 Ник установлен. Потрачено {price} рости.\n"
        f"Ваш баланс: {bal} рости\n"
        f"Ваш новый ник: {desired} ✅"
    )
    await message.reply(out, parse_mode=ParseMode.MARKDOWN)

@router.message(Command("sdx"))
async def sdx_handler(message: types.Message, bot: Bot, command: CommandObject):
    args = command.args or ""
    arg = args.strip().lower()
    
    if not arg:
        state = "включено" if SDX_AUTO_BLACKLIST else "выключено"
        await message.reply(f"SDX auto-blacklist: {state}")
        return
    
    await ensure_owner_cached(bot)
    if not OWNERS or message.from_user.id not in OWNERS:
        await message.reply("Команда управления SDX доступна только владельцу бота.")
        return
    
    if arg in ("вкл", "включить", "on"):
        set_sdx_flag(True)
        await message.reply("SDX auto-blacklist включён — все пользователи с '#sdx' в имени будут автоматически заблокированы.")
        return
    
    if arg in ("выкл", "выключить", "off"):
        set_sdx_flag(False)
        removed = 0
        for uid in list(BLACKLIST):
            try:
                # В aiogram нет прямого get_users, используем get_chat
                u = await bot.get_chat(uid)
                fn = getattr(u, 'first_name', '') or ''
                ln = getattr(u, 'last_name', '') or ''
                combined = f"{fn} {ln}".lower()
                if "#sdx" in combined:
                    remove_from_blacklist_db(uid)
                    removed += 1
            except:
                continue
        
        await message.reply(f"SDX auto-blacklist выключён. Удалено из ЧС: {removed} пользователей (если были).")
        return
    
    await message.reply("Неизвестная опция. Использование: /sdx, /sdx вкл, /sdx выкл")

@router.message(Command("ресет"))
async def reset_history_handler(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    chat_id = message.chat.id
    
    if not user_id or chat_id != user_id:
        return
    
    key = (user_id, chat_id)
    if key in CHAT_HISTORY:
        CHAT_HISTORY[key] = []
        await message.reply("История диалога очищена ✅", parse_mode=ParseMode.MARKDOWN)
    else:
        await message.reply("История диалога пуста", parse_mode=ParseMode.MARKDOWN)

@router.message(Command("лс"))
async def ls_toggle_handler(message: types.Message):
    user = message.from_user
    if not OWNERS:
        return
    uid = user.id
    if uid in DISABLED_PRIVATE_USERS:
        set_disabled_private_db(uid, False)
        await message.reply("ИИ в личных сообщениях включён ✅")
    else:
        set_disabled_private_db(uid, True)
        await message.reply("ИИ в личных сообщениях отключён ✅")

@router.message(Command("табл"))
async def usage_table_handler(message: types.Message, bot: Bot, command: CommandObject):
    args = command.args or ""
    sub = args.strip().lower()
    
    if sub in ("р", "r", "рости", "rosty", "rosti"):
        rows = get_balances_table()
        if not rows:
            await message.reply("Таблица балансов пуста.")
            return
        lines = []
        for idx, (uid, amount) in enumerate(rows, 1):
            try:
                u = await bot.get_chat(uid)
                name = u.username or u.first_name or str(uid)
            except:
                name = str(uid)
            lines.append(f"{idx}. {name} - {amount} рости")
        table = "\n".join(lines)
        await message.reply(f"```Таблица баланса (рости)\n{table}\n```", parse_mode=ParseMode.MARKDOWN)
        return
    
    rows = get_usage_table()
    if not rows:
        await message.reply("Таблица пуста.")
        return
    lines = []
    for idx, (username, first_name, last_name, count) in enumerate(rows, 1):
        name = username or first_name or last_name or "Без имени"
        lines.append(f"{idx}. {name} - {count}")
    table = "\n".join(lines)
    await message.reply(f"```Таблица использования\n{table}\n```", parse_mode=ParseMode.MARKDOWN)

@router.message(Command("магазин"))
async def shop_handler(message: types.Message, bot: Bot, command: CommandObject):
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    args = command.args or ""
    parts = args.split(maxsplit=1)
    sub = parts[0].strip().lower() if parts else ""
    
    if not sub:
        if has_shop_db(uid):
            shop = get_shop_db(uid)
            if shop:
                now = int(time.time())
                last = shop["last_collection"]
                cooldown = 6 * 3600
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
                    f"🪐 {shop['name']}\n"
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
                await message.reply(out, parse_mode=ParseMode.MARKDOWN)
        else:
            price = 1000
            bal = get_balance_db(uid)
            if bal < price:
                await message.reply(f"💰 Открыть магазин стоит {price} рости.\nВаш баланс: {bal} рости\n\nНедостаточно средств!")
            else:
                await message.reply(
                    f"💰 Открыть магазин стоит {price} рости.\n"
                    f"Ваш баланс: {bal} рости\n\n"
                    f"Магазин будет приносить 50-1500 рости каждые 6 часов.\n\n"
                    f"Отправьте `/магазин купить` чтобы открыть магазин.",
                    parse_mode=ParseMode.MARKDOWN
                )
        return
    
    if sub in ("купить", "buy"):
        if has_shop_db(uid):
            await message.reply("У вас уже есть магазин!")
            return
        
        price = 1000
        bal = get_balance_db(uid)
        if bal < price:
            await message.reply(f"Недостаточно рости. Цена: {price}. Ваш баланс: {bal}")
            return
        
        new_bal = change_balance_db(uid, -price)
        create_shop_db(uid)
        
        out = (
            "```\n"
            "🪐 магазин открыт!\n"
            "------------------------------\n"
            f"владелец: {getattr(user, 'first_name', uid)}\n"
            f"потрачено: {price} рости\n"
            f"баланс: {new_bal} рости\n"
            "------------------------------\n"
            "используйте /магазин название <текст>\n"
            "чтобы дать название магазину\n"
            "```"
        )
        await message.reply(out, parse_mode=ParseMode.MARKDOWN)
        return
    
    if sub in ("название", "name", "назв"):
        if not has_shop_db(uid):
            await message.reply("У вас нет магазина. Используйте /магазин чтобы купить.")
            return
        
        if len(parts) < 2:
            await message.reply("Использование: /магазин название <текст>")
            return
        
        new_name = parts[1].strip()
        if len(new_name) > 50:
            await message.reply("Название слишком длинное (макс 50 символов)")
            return
        
        update_shop_name_db(uid, new_name)
        await message.reply(f"✅ Магазин переименован: {new_name}")
        return
    
    if sub in ("собрать", "collect", "соб"):
        if not has_shop_db(uid):
            await message.reply("У вас нет магазина. Используйте /магазин чтобы купить.")
            return
        shop = get_shop_db(uid)
        if not shop:
            await message.reply("Ошибка: магазин не найден")
            return

        now = int(time.time())
        last = int(shop.get("last_collection", 0) or 0)

        interval = 5 * 60
        elapsed = now - last
        intervals = elapsed // interval

        profit = 0
        for i in range(int(intervals)):
            profit += random.randint(50, 300)

        new_last = last + int(intervals) * interval if last > 0 else now
        if last == 0:
            new_last = now

        update_shop_collection_db(uid, new_last)

        if profit <= 0:
            await message.reply("Прибыль ещё не накопилась. Попробуйте позже — начисление каждые 5 минут.")
            return

        new_bal = change_balance_db(uid, profit)

        out = (
            "```\n"
            f"🪐 {shop['name']}\n"
            "------------------------------\n"
            f"владелец: {getattr(user, 'first_name', uid)}\n"
            f"сбор прибыли: ✅ успешно\n"
            f"заработано: {profit} рости\n"
            f"баланс: {new_bal} рости\n"
            "------------------------------\n"
            "приход новых средств: каждые 5 минут по 50..300 рости (рандом)\n"
            "```"
        )
        await message.reply(out, parse_mode=ParseMode.MARKDOWN)
        return
    
    await message.reply(
        "Использование:\n"
        "/магазин - инфо/купить\n"
        "/магазин название <текст> - переименовать\n"
        "/магазин собрать - собрать прибыль"
    )

@router.message(Command("мем"))
async def meme_handler(message: types.Message, command: CommandObject):
    if not gemini_client:
        await message.reply("❌ Gemini API не настроен")
        return
    
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    if uid in BLACKLIST:
        await message.reply("❌ Вы в чёрном списке. ИИ недоступен.")
        return
    
    args = command.args
    if not args:
        await message.reply("Использование: /мем <тема>\n\nПример: /мем программисты")
        return
    
    topic = args.strip()
    cost = 200
    bal = get_balance_db(uid)
    
    if bal < cost:
        await message.reply(f"❌ Недостаточно рости. Нужно: {cost}. Ваш баланс: {bal}")
        return
    
    new_bal = change_balance_db(uid, -cost)
    
    notify = await message.reply("🎪 Генерирую мем...")
    
    meme_prompt = (
        f"придумай смешную шутку или мем про {topic}. "
        "пиши неформально, с маленькой буквы, как в интернете. "
        "шутка должна быть актуальной и смешной, не из 2000-х годов. "
        "максимум 500 символов. не используй смодзи. просто текст шутки."
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
                            return text
                    return "Ошибка генерации мема"
        
        result = await call_gemini_meme()

        out = (
            f"🎪 **Мем про {topic}**\n\n"
            f"{result}\n\n"
            f"💰 Потрачено: {cost} рости\n"
            f"💰 Баланс: {new_bal} рости"
        )

        await notify.edit_text(out, parse_mode=ParseMode.MARKDOWN)

    except Exception as e:
        change_balance_db(uid, cost)
        await notify.edit_text(f"❌ Ошибка генерации мема: {str(e)}\n💰 Средства возвращены")

@router.message(Command("деп"))
async def casino_handler(message: types.Message, command: CommandObject):
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    args = command.args
    if not args:
        await message.reply(
            "🎰 Использование: /деп <сумма>\n\n"
            "Правила:\n"
            "3️⃣ три одинаковых → выигрыш x2\n"
            "2️⃣ два одинаковых → возврат половины\n"
            "❌ ничего → проигрыш\n\n"
            "Пример: /деп 100"
        )
        return
    
    try:
        bet = int(args.strip())
    except ValueError:
        await message.reply("❌ Укажите корректную сумму (целое число)")
        return
    
    if bet <= 0:
        await message.reply("❌ Сумма должна быть больше 0")
        return
    
    bal = get_balance_db(uid)
    if bal < bet:
        await message.reply(f"❌ Недостаточно рости. Ваш баланс: {bal}")
        return
    
    change_balance_db(uid, -bet)
    
    emoji_nums = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣"]
    
    slots_msg = await message.reply("🎰 Крутим барабаны...")
    
    for spin in range(5):
        slot1 = random.choice(emoji_nums)
        slot2 = random.choice(emoji_nums)
        slot3 = random.choice(emoji_nums)
        
        animation_text = f"🎰 | {slot1} {slot2} {slot3} |"
        
        try:
            await slots_msg.edit_text(animation_text)
            await asyncio.sleep(0.4)
        except:
            pass
    
    roll = random.randint(1, 100)
    
    if roll <= 5:
        num = random.choice(emoji_nums)
        final_slots = [num, num, num]
        matches = 3
    elif roll <= 20:
        num = random.choice(emoji_nums)
        other = random.choice([n for n in emoji_nums if n != num])
        final_slots = [num, num, other]
        random.shuffle(final_slots)
        matches = 2
    else:
        available = emoji_nums.copy()
        slot1 = random.choice(available)
        available.remove(slot1)
        slot2 = random.choice(available)
        available.remove(slot2)
        slot3 = random.choice(available)
        final_slots = [slot1, slot2, slot3]
        matches = 0
    
    final_text = f"🎰 | {final_slots[0]} {final_slots[1]} {final_slots[2]} |\n\n"
    
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
        await slots_msg.edit_text(final_text)
    except:
        await message.reply(final_text)

@router.message(Command("пнг"))
async def png_handler(message: types.Message, command: CommandObject):
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    if uid in BLACKLIST:
        await message.reply("❌ Вы в чёрном списке. ИИ недоступен.")
        return
    
    args = command.args
    if not args:
        await message.reply("Использование: /пнг <текст>\n\nПример: /пнг пушистый кот в очках")
        return
    
    prompt = sanitize_text(args.strip(), max_len=1000)
    if len(prompt) > 1000:
        await message.reply("❌ Текст слишком длинный (максимум 1000 символов)")
        return
    
    cost = 300
    bal = get_balance_db(uid)
    
    if bal < cost:
        await message.reply(f"❌ Недостаточно рости. Нужно: {cost}. Ваш баланс: {bal}")
        return
    
    new_bal = change_balance_db(uid, -cost)
    
    notify = await message.reply("🎨 Генерирую изображение...")
    
    start_time = time.time()
    
    try:
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
            except:
                pass
        
        import urllib.parse
        encoded_prompt = urllib.parse.quote(english_prompt)
        
        image_url = f"https://image.pollinations.ai/prompt/{encoded_prompt}?model=flux&width=1024&height=1024&nologo=true&enhance=true"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(image_url, timeout=aiohttp.ClientTimeout(total=90)) as response:
                if response.status != 200:
                    raise Exception(f"Ошибка генерации: {response.status}")
                
                image_bytes = await response.read()
        
        gen_time = round(time.time() - start_time, 1)
        
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

            photo = FSInputFile(tmp_path)
            await message.answer_photo(photo=photo, caption=caption_text, parse_mode=ParseMode.HTML)
            
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
        change_balance_db(uid, cost)
        error_msg = str(e)
        await notify.edit_text(f"❌ Ошибка генерации: {error_msg}\n💰 Средства возвращены")

@router.message(Command("стикер"))
async def sticker_handler(message: types.Message, command: CommandObject):
    user = message.from_user
    if not user:
        return
    uid = user.id
    
    if uid in BLACKLIST:
        await message.reply("❌ Вы в чёрном списке. ИИ недоступен.")
        return
    
    args = command.args
    if not args:
        await message.reply(
            "🎨 Использование: /стикер <описание>\n\n"
            "Пример: /стикер милый котик в космосе\n\n"
            "💰 Стоимость: 800 рости"
        )
        return
    
    prompt = args.strip()
    if len(prompt) > 1000:
        await message.reply("❌ Описание слишком длинное (максимум 1000 символов)")
        return
    
    cost = 800
    bal = get_balance_db(uid)
    
    if bal < cost:
        await message.reply(f"❌ Недостаточно рости. Нужно: {cost}. Ваш баланс: {bal}")
        return
    
    new_bal = change_balance_db(uid, -cost)
    
    notify = await message.reply("🎨 Генерирую стикер...\n⏳ Это может занять до 1 минуты")
    
    start_time = time.time()
    
    try:
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
            except:
                pass
        
        import urllib.parse
        encoded_prompt = urllib.parse.quote(english_prompt)
        
        image_url = f"https://image.pollinations.ai/prompt/{encoded_prompt}?model=flux&width=512&height=512&nologo=true&enhance=true"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(image_url, timeout=aiohttp.ClientTimeout(total=90)) as response:
                if response.status != 200:
                    raise Exception(f"Ошибка генерации: {response.status}")
                
                image_bytes = await response.read()
        
        gen_time = round(time.time() - start_time, 1)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.webp') as tmp_file:
            tmp_path = tmp_file.name
            tmp_file.write(image_bytes)
        
        try:
            await notify.edit_text("🎨 Изображение готово!\n📤 Отправляю стикер...")
            
            display_prompt = prompt[:100] + "..." if len(prompt) > 100 else prompt
            info_text = (
                f"<blockquote>🎨 промпт: {display_prompt}\n"
                f"💰 потрачено: {cost} рости\n"
                f"⏱ время: {gen_time}с\n"
                f"🤖 модель: Flux\n"
                f"💵 баланс: {new_bal} рости</blockquote>"
            )
            
            try:
                sticker = FSInputFile(tmp_path)
                await message.answer_sticker(sticker=sticker)
                
                await message.answer(info_text, parse_mode=ParseMode.HTML)
                
                try:
                    await notify.delete()
                except:
                    pass
                    
            except Exception as e:
                try:
                    photo = FSInputFile(tmp_path)
                    await message.answer_photo(photo=photo, caption=info_text, parse_mode=ParseMode.HTML)
                    await notify.delete()
                except:
                    success_msg = (
                        f"✅ Изображение создано!\n\n"
                        f"🎨 промпт: {prompt}\n"
                        f"💰 потрачено: {cost} рости\n"
                        f"⏱ время: {gen_time}с\n"
                        f"💵 баланс: {new_bal} рости"
                    )
                    await notify.edit_text(success_msg)
            
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass
    
    except Exception as e:
        change_balance_db(uid, cost)
        error_msg = str(e)
        await notify.edit_text(f"❌ Ошибка создания стикера: {error_msg}\n💰 Средства возвращены")

@router.message(Command("голос"))
async def voice_handler(message: types.Message, command: CommandObject):
    user = message.from_user
    if not user:
        return
    uid = user.id
    chat_id = message.chat.id
    
    args = command.args or ""
    sub = args.strip().lower()
    
    if sub in ("режим", "mode"):
        if chat_id != uid:
            await message.reply("❌ Команда /голос режим работает только в личных сообщениях")
            return
        
        if uid in VOICE_MODE_USERS:
            VOICE_MODE_USERS.discard(uid)
            await message.reply("🔇 Автоматическая озвучка отключена")
        else:
            VOICE_MODE_USERS.add(uid)
            await message.reply("🔊 Автоматическая озвучка включена\n💰 Стоимость: 60 рости за каждый ответ ИИ")
        return
    
    if not args:
        await message.reply("Использование:\n/голос <текст> - озвучить текст (60 рости)\n/голос режим - (только в ЛС) авто-озвучка ответов ИИ")
        return
    
    text_to_speak = args.strip()
    if len(text_to_speak) > 500:
        await message.reply("❌ Текст слишком длинный (максимум 500 символов)")
        return
    
    cost = 120
    bal = get_balance_db(uid)
    
    if bal < cost:
        await message.reply(f"❌ Недостаточно рости. Нужно: {cost}. Ваш баланс: {bal}")
        return
    
    new_bal = change_balance_db(uid, -cost)
    
    try:
        notify = await message.reply("🎤 Генерирую голосовое сообщение...")
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.mp3') as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            tts = gTTS(text=text_to_speak, lang='ru')
            tts.save(tmp_path)
            
            voice = FSInputFile(tmp_path)
            await message.answer_voice(
                voice=voice,
                caption=f"🎤 Озвучка | 💰 Потрачено: {cost} рости"
            )
            
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
        change_balance_db(uid, cost)
        await message.reply(f"❌ Ошибка генерации голоса: {str(e)}\n💰 Средства возвращены")

@router.message(Command("ворк"))
async def work_handler(message: types.Message):
    user = message.from_user
    if not user:
        return
    uid = user.id

    now = time.time()
    cooldown_until = WORK_COOLDOWNS.get(uid, 0)
    if now < cooldown_until:
        remaining = int(cooldown_until - now)
        await message.reply(f"Пожалуйста, подождите {remaining} секунд перед следующим /ворк.", parse_mode=ParseMode.MARKDOWN)
        return

    amount = random.randint(5, 150)
    new_bal = change_balance_db(uid, amount)

    WORK_COOLDOWNS[uid] = now + 15

    try:
        name = user.username or user.first_name or str(uid)
    except:
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

    await message.reply(out, parse_mode=ParseMode.MARKDOWN)

@router.message(Command("баланс"))
async def balance_handler(message: types.Message, bot: Bot):
    try:
        if message.reply_to_message and message.reply_to_message.from_user:
            target = message.reply_to_message.from_user
            bal = get_balance_db(target.id)
            await message.reply(f"Баланс {getattr(target, 'first_name', target.id)}: {bal} рости")
        else:
            user = message.from_user
            if not user:
                return
            bal = get_balance_db(user.id)
            await message.reply(f"Ваш баланс: {bal} рости")
    except:
        await message.reply("Ошибка при получении баланса")

@router.message(Command("профиль"))
async def profile_handler(message: types.Message):
    target_user = None
    if message.reply_to_message and message.reply_to_message.from_user:
        target_user = message.reply_to_message.from_user
    else:
        target_user = message.from_user

    if not target_user:
        await message.reply("Не удалось определить пользователя.")
        return
    
    uid = target_user.id
    
    try:
        name = get_nickname_db(uid) or target_user.first_name or target_user.username or str(uid)
    except:
        name = str(uid)
        
    balance = get_balance_db(uid)
    
    try:
        usage_count = get_usage_count_db(uid) or 0
    except:
        usage_count = "н/д"
        
    shop_info = "нет"
    if has_shop_db(uid):
        shop = get_shop_db(uid)
        if shop:
            shop_info = f"🪐 «{shop['name']}»"
            
    role_info = "стандартная"
    if uid in USER_ROLES:
        role_text = USER_ROLES[uid]
        role_info = f"«{role_text[:40]}{'...' if len(role_text) > 40 else ''}»"
    elif GLOBAL_ROLE:
        role_info = "глобальная"

    profile_text = (
        f"👤 **Профиль: {name}**\n"
        "--------------------------------\n"
        f"**ID:** `{uid}`\n"
        f"**💰 Баланс:** {balance} рости\n"
        f"**🤖 Использование ИИ:** {usage_count} раз\n"
        f"**🪐 Магазин:** {shop_info}\n"
        f"**🎭 Роль ИИ:** {role_info}\n"
        "--------------------------------"
    )
    
    await message.reply(profile_text, parse_mode=ParseMode.MARKDOWN)

@router.message(Command("help", "хелп", "команды"))
async def help_handler(message: types.Message):
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
/лс - вкл/выкл ИИ в личных сообщениях</blockquote>

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

<b>🪐 Магазин:</b>
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
        await message.reply(help_text, parse_mode=ParseMode.HTML)
    except:
        await message.reply(help_text.replace("**", "").replace("•", "-"))

@router.message(Command("перевод"))
async def transfer_handler(message: types.Message, bot: Bot, command: CommandObject):
    sender = message.from_user
    if not sender:
        return
    sid = sender.id

    args = command.args or ""
    parts = args.split()
    if len(parts) < 2:
        await message.reply("Использование:\n/перевод <сумма> @username\nили ответьте на сообщение пользователя с /перевод <сумма>")
        return

    try:
        amount = int(parts[0])
    except:
        await message.reply("Укажите корректную сумму (целое положительное число). Пример: /перевод 500 @user")
        return

    if amount <= 0:
        await message.reply("Сумма должна быть больше нуля")
        return

    target_user = None
    if message.reply_to_message and message.reply_to_message.from_user:
        target_user = message.reply_to_message.from_user
    else:
        if len(parts) >= 2:
            target_str = parts[1].strip()
            if target_str.startswith("@"):
                target_str = target_str[1:]
            try:
                target_user = await bot.get_chat(target_str)
            except:
                try:
                    uid = int(target_str)
                    target_user = await bot.get_chat(uid)
                except:
                    target_user = None

    if not target_user:
        await message.reply("Не удалось определить получателя. Укажите @username или ответьте на сообщение получателя.")
        return

    tid = target_user.id
    if tid == sid:
        await message.reply("Нельзя переводить рости самому себе")
        return

    bal = get_balance_db(sid)
    if bal < amount:
        await message.reply(f"❌ Недостаточно рости. Нужно: {amount}. Ваш баланс: {bal}")
        return

    change_balance_db(sid, -amount)
    change_balance_db(tid, amount)

    new_bal = get_balance_db(sid)
    try:
        recipient_name = target_user.username or target_user.first_name or str(tid)
    except:
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
    await message.reply(out, parse_mode=ParseMode.MARKDOWN)

@router.message(Command("дать"))
async def give_handler(message: types.Message, bot: Bot, command: CommandObject):
    args = command.args or ""
    parts = args.split(maxsplit=1)
    if len(parts) < 2:
        await message.reply("Использование: /дать рости <сумма> (ответ на сообщение пользователя) или /дать рости <сумма> @username")
        return

    sub = parts[0].strip().lower()
    if sub not in ("рости", "rosti", "rosty"):
        await message.reply("Команда используется неверно. Правильно: /дать рости <сумма>")
        return

    amount = None
    if len(parts) >= 2:
        try:
            amount = int(parts[1])
        except:
            amount = None

    target = None
    if message.reply_to_message and message.reply_to_message.from_user:
        target = message.reply_to_message.from_user
    
    if not target:
        await message.reply("Пожалуйста, ответьте на сообщение пользователя, которому хотите дать рости.")
        return

    if amount is None or amount <= 0:
        await message.reply("Укажите корректную сумму (целое положительное число).")
        return

    await ensure_owner_cached(bot)
    if message.from_user.id not in OWNERS:
        await message.reply("Только владелец бота может вручную выдавать рости.")
        return

    new = change_balance_db(target.id, amount)
    await message.reply(f"Выдано {amount} рости пользователю {getattr(target, 'first_name', target.id)}. Новый баланс: {new}")

@router.message(Command("права"))
async def rights_handler(message: types.Message, bot: Bot, command: CommandObject):
    caller = message.from_user
    if not caller:
        return

    owner = await ensure_owner_cached(bot)
    args = command.args or ""
    sub = args.strip().lower()

    if sub.startswith("куп") or sub.startswith("buy"):
        caller_id = caller.id
        price = 500
        if caller_id in ROLE_EDITORS:
            await message.reply("У вас уже есть право менять роли.")
            return
        bal = get_balance_db(caller_id)
        if bal < price:
            await message.reply(f"Недостаточно рости. Цена: {price}. Ваш баланс: {bal}")
            return
        new_bal = change_balance_db(caller_id, -price)
        add_role_editor_db(caller_id)
        await message.reply(f"Вы успешно купили право менять роли за {price} рости. Баланс: {new_bal}")
        return

    await ensure_owner_cached(bot)
    if not OWNERS:
        await message.reply("Невозможно определить владельца бота. Повторите позже.")
        return

    if caller.id not in OWNERS:
        await message.reply("Команда доступна только владельцу бота.")
        return

    if message.reply_to_message and message.reply_to_message.from_user:
        target = message.reply_to_message.from_user
        if target.id == owner:
            await message.reply("Нельзя изменять права владельца.")
            return
        if target.id in ROLE_EDITORS:
            remove_role_editor_db(target.id)
            await message.reply(f"Права сняты с {getattr(target, 'first_name', target.id)} ✅")
        else:
            add_role_editor_db(target.id)
            await message.reply(f"Права выданы {getattr(target, 'first_name', target.id)} ✅")
        return

    if not ROLE_EDITORS:
        await message.reply("Пока нет пользователей с правом менять роли.")
        return

    lines = ["Пользователи с правом менять роль:"]
    for uid in sorted(ROLE_EDITORS):
        try:
            u = await bot.get_chat(uid)
            name = u.username or u.first_name or str(uid)
        except:
            name = str(uid)
        lines.append(f"- {name} ({uid})")

    await message.reply("\n".join(lines))

@router.message(Command("чс"))
async def blacklist_handler(message: types.Message, bot: Bot, command: CommandObject):
    caller = message.from_user
    if not caller:
        return
    
    await ensure_owner_cached(bot)
    if not OWNERS or caller.id not in OWNERS:
        await message.reply("Команда доступна только владельцам бота.")
        return
    
    args = command.args or ""
    sub = args.strip().lower()
    
    if not sub:
        if not BLACKLIST:
            await message.reply("Чёрный список пуст.")
            return
        
        lines = ["👤 Чёрный список (ИИ недоступен):"]
        for uid in sorted(BLACKLIST):
            try:
                u = await bot.get_chat(uid)
                name = u.username or u.first_name or str(uid)
            except:
                name = str(uid)
            lines.append(f"• {name} ({uid})")
        
        await message.reply("\n".join(lines))
        return
    
    if sub.startswith("доб") or sub.startswith("add"):
        if not message.reply_to_message or not message.reply_to_message.from_user:
            await message.reply("Ответьте на сообщение пользователя, которого хотите добавить в ЧС.")
            return
        
        target = message.reply_to_message.from_user
        if target.id in OWNERS:
            await message.reply("Нельзя добавить владельца в чёрный список.")
            return
        
        if target.id in BLACKLIST:
            await message.reply(f"{getattr(target, 'first_name', target.id)} уже в чёрном списке.")
            return
        
        add_to_blacklist_db(target.id)
        await message.reply(f"✅ {getattr(target, 'first_name', target.id)} добавлен в чёрный список. ИИ для него недоступен.")
        return
    
    if sub.startswith("убр") or sub.startswith("rem") or sub.startswith("del"):
        if not message.reply_to_message or not message.reply_to_message.from_user:
            await message.reply("Ответьте на сообщение пользователя, которого хотите убрать из ЧС.")
            return
        
        target = message.reply_to_message.from_user
        if target.id not in BLACKLIST:
            await message.reply(f"{getattr(target, 'first_name', target.id)} не в чёрном списке.")
            return
        
        remove_from_blacklist_db(target.id)
        await message.reply(f"✅ {getattr(target, 'first_name', target.id)} убран из чёрного списка.")
        return
    
    await message.reply(
        "Использование:\n"
        "/чс - показать список\n"
        "/чс доб (ответ на сообщение) - добавить\n"
        "/чс убр (ответ на сообщение) - убрать"
    )

@router.message(F.text.regexp(r"(?i)^\s*бот\s*$"))
async def bot_presence_reply(message: types.Message):
    await message.reply(
        "<blockquote>На месте✅</blockquote>",
        parse_mode=ParseMode.HTML
    )

@router.message(Command("чипсы"))
async def chips_reply(message: types.Message):
    await message.reply(
        """
        опа доставай карманныы оо а чё это у тебя предметы
        <blockquote>предметы: найдены
        картель: вызван
        приедет: 13:57
        мфц: зло
        чипсы: созданы
        свага:присутствует</blockquote>
        """,
        parse_mode=ParseMode.HTML
    )

# Обработчик текстовых сообщений в личных чатах
@router.message(F.chat.type == "private", F.text | F.photo)
async def private_chat_handler(message: types.Message, bot: Bot):
    """Handle all text messages and photos in private chats - forward them to AI."""
    
    # Проверка на бота
    if is_bot_user(message.from_user):
        return
    
    if not gemini_client:
        await message.reply("Ошибка: Gemini API не настроен")
        return
    
    # Игнорируем команды
    text = message.text or message.caption or ''
    if text.strip().startswith('/'):
        return
    
    user = message.from_user
    user_id = user.id if user else None
    
    if user_id and user_id in DISABLED_PRIVATE_USERS:
        return
    
    # Check ignore tags
    if user_has_ignore_tag(user):
        return
    
    # Получаем текст из text или caption
    prompt_text = message.text or message.caption
    
    # Если это фото без текста, используем дефолтный промпт
    if not prompt_text and message.photo:
        prompt_text = "Что изображено на этом фото?"
    
    if not prompt_text:
        return
    
    await process_ai_request(bot, message, prompt_text, skip_notification=True)

# Helper function для обработки AI запросов
async def process_ai_request(bot: Bot, message: types.Message, prompt_text: str, skip_notification: bool = False) -> None:
    """Process an AI request with the given prompt text and optional image."""
    
    if is_bot_user(message.from_user):
        return
    
    chat_id = message.chat.id
    user_id = message.from_user.id if message.from_user else None
    
    # Apply SDX auto-blacklist rule
    try:
        if SDX_AUTO_BLACKLIST and message.from_user:
            fn = message.from_user.first_name or ''
            ln = message.from_user.last_name or ''
            combined = f"{fn} {ln}".lower()
            if "#sdx" in combined:
                if user_id and user_id not in BLACKLIST:
                    add_to_blacklist_db(user_id)
    except:
        pass
    
    # Check blacklist
    if user_id and user_id in BLACKLIST:
        try:
            await message.reply("❌ Вы в чёрном списке. ИИ недоступен.")
        except:
            pass
        return
    
    # Track usage
    if message.from_user:
        increment_usage(message.from_user)
    
    # Dedupe check
    if not skip_notification:
        msg_id = message.message_id
        key = (chat_id, msg_id)
        if key in PROCESSED_MESSAGES:
            return
        PROCESSED_MESSAGES.add(key)
        asyncio.create_task(_remove_processed_after(key, PROCESSED_TTL))
    
    notify = None
    if not skip_notification:
        try:
            notify = await message.reply("Отправляю запрос в ИИ...")
        except:
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
                nick = get_nickname_db(user_id) if user_id else None
                if nick:
                    role_parts.append(
                        f"обращайся к пользователю всегда как «{nick}». обязательно используй этот ник при обращении."
                    )
            except:
                pass
            
            role_parts.extend([
                "ТЫ СЕЙЧАС В РОЛИ. ЭТО ТВОЯ ЛИЧНОСТЬ, НЕ ОПИСЫВАЙ ЕЁ - ЖИВИ ЕЙ:",
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
            
            full_prompt = "\n\n".join([*role_parts, prompt])
            
            # HTTP запрос к Gemini API
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
            
            parts = [{"text": full_prompt}]
            
            # Добавляем изображение если есть
            if image_data and image_mime:
                parts.append({
                    "inline_data": {
                        "mime_type": image_mime,
                        "data": base64.b64encode(image_data).decode('utf-8')
                    }
                })
            
            payload = {"contents": [{"parts": parts}]}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=60)) as response:
                    if response.status != 200:
                        return "Ошибка API", None
                    
                    data = await response.json()
                    
                    if "candidates" in data and len(data["candidates"]) > 0:
                        candidate = data["candidates"][0]
                        if "content" in candidate and "parts" in candidate["content"]:
                            raw_text = candidate["content"]["parts"][0].get("text", "")
                            
                            # Extract emotion tag
                            emo_match = re.search(r"\[\s*EMO\s*:\s*(angry|sad)\s*\]\s*$", raw_text, flags=re.IGNORECASE)
                            detected_emotion = emo_match.group(1).lower() if emo_match else None
                            
                            if emo_match:
                                visible_text = raw_text[:emo_match.start()].rstrip()
                            else:
                                visible_text = raw_text
                            
                            result_text = visible_text
                            
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
    
    if message.photo:
        try:
            if notify:
                await notify.edit_text("🖼️ Загружаю изображение...")
            
            photo = message.photo[-1]
            file = await bot.get_file(photo.file_id)
            image_data = await bot.download_file(file.file_path)
            image_data = image_data.read()
            image_mime = "image/jpeg"
        except Exception as e:
            print(f"Ошибка загрузки фото: {e}")
    
    elif message.reply_to_message and message.reply_to_message.photo:
        try:
            if notify:
                await notify.edit_text("🖼️ Загружаю изображение из ответа...")
            
            photo = message.reply_to_message.photo[-1]
            file = await bot.get_file(photo.file_id)
            image_data = await bot.download_file(file.file_path)
            image_data = image_data.read()
            image_mime = "image/jpeg"
        except Exception as e:
            print(f"Ошибка загрузки фото из ответа: {e}")
    
    # Serialize requests per chat
    lock = CHAT_LOCKS.setdefault(chat_id, asyncio.Lock())
    try:
        async with lock:
            result, detected_emotion = await call_gemini_async(prompt_text, image_data, image_mime)
    except:
        result, detected_emotion = await call_gemini_async(prompt_text, image_data, image_mime)
    
    # Truncate if needed
    try:
        if isinstance(result, str) and len(result) > MAX_VISIBLE_LEN:
            result = result[:MAX_VISIBLE_LEN]
    except:
        pass
    
    result = sanitize_text(result, max_len=1900)
    
    # Send reply
    try:
        sent_msg = None
        if notify:
            try:
                edited = await notify.edit_text(result)
                sent_msg = edited
            except:
                sent_msg = await message.reply(result)
        else:
            sent_msg = await message.reply(result)
        
        # Auto-voice in private chats
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
                        
                        voice = FSInputFile(tmp_path)
                        await message.answer_voice(
                            voice=voice,
                            caption=f"🎤 Авто-озвучка | 💰 -{voice_cost} рости"
                        )
                    finally:
                        try:
                            os.unlink(tmp_path)
                        except:
                            pass
                else:
                    VOICE_MODE_USERS.discard(user_id)
                    await message.answer("🔇 Автоматическая озвучка отключена: недостаточно рости")
        except:
            pass
        
        # Send sticker if emotion detected
        try:
            if AUTO_SEND_STICKER and sent_msg:
                used_emotion = detected_emotion if detected_emotion else detect_emotion_from_input(prompt_text, message.text or '')
                if used_emotion:
                    sticker_id = STICKER_MAP.get(used_emotion)
                    if sticker_id and not sticker_id.startswith("REPLACE_WITH_"):
                        await message.answer_sticker(sticker_id)
        except:
            pass
    
    except Exception:
        if notify:
            try:
                await notify.edit_text(result)
            except:
                await message.reply(result)
        else:
            await message.reply(result)

# Handler для команды /ии
@router.message(Command("ии"))
async def ai_command_handler(message: types.Message, bot: Bot, command: CommandObject):
    """Handle /ии command in groups and private chats."""
    
    if is_bot_user(message.from_user):
        return
    
    if not gemini_client:
        await message.reply("Ошибка: Gemini API не настроен")
        return
    
    user = message.from_user
    chat_id = message.chat.id
    
    if user and chat_id == user.id and user_has_ignore_tag(user):
        return
    
    # Extract prompt
    prompt_text = None
    args = command.args
    has_photo = bool(message.photo)
    
    if message.reply_to_message and args:
        replied_raw = message.reply_to_message.text or message.reply_to_message.caption or ""
        replied_sanitized = replied_raw.replace("*", "")
        replied_sanitized = re.sub(r"\s+", " ", replied_sanitized).strip()
        prompt_text = f"{args} (сообщение на которое ответили: {replied_sanitized})"
    elif message.reply_to_message and not args:
        prompt_text = message.reply_to_message.text or message.reply_to_message.caption
    else:
        if args:
            prompt_text = args
        elif has_photo:
            prompt_text = "Что изображено на этом фото?"
    
    if not prompt_text:
        await message.reply("Пожалуйста, укажите промпт: `/ии <текст>`, отправьте фото с подписью, или ответьте на сообщение с текстом и используйте /ии.")
        return
    
    prompt_text = sanitize_text(prompt_text, max_len=1900)
    await process_ai_request(bot, message, prompt_text)


# --------------------------- MAIN ---------------------------
async def main():
    """Initialize and start the bot."""
    global gemini_client, GEMINI_API_KEY
    
    # Initialize Gemini
    if GEMINI_API_KEY:
        try:
            gemini_client = True
            print("✅ Gemini API инициализирован (HTTP режим)")
            print("Ya gaga pidoker")
        except Exception as e:
            print(f"⚠️ Не удалось инициализировать Gemini: {e}")
    else:
        print("⚠️ GEMINI_API_KEY не установлен. Команда /ии будет недоступна")
    
    # Initialize database
    init_db()
    
    # Load persistent state
    try:
        load_persistent_state()
    except:
        pass
    
    # Add external owner
    try:
        add_owner_db(5999801817)
        print("Добавлен внешний владелец: 5999801817")
    except:
        pass
    
    # Initialize bot and dispatcher
    bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()
    
    # Register router
    dp.include_router(router)
    
    print("🤖 Бот запущен!")
    
    # Start polling
    await dp.start_polling(bot)

from aiohttp import web

async def health_check(request):
    return web.Response(text="OK")

async def start_web_server():
    app = web.Application()
    app.router.add_get('/kaithheathcheck', health_check)
    app.router.add_get('/', health_check)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8080)
    await site.start()
    print("🌐 HTTP сервер запущен на порту 8080")

if __name__ == "__main__":
    await start_web_server()
    asyncio.run(main())

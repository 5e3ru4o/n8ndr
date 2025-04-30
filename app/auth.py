import os
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError
from loguru import logger
from .config import settings

async def create_client():
    """Create and return a Telegram client instance."""
    session_str = os.getenv("SESSION_STRING")
    if session_str:
        client = TelegramClient(StringSession(session_str), settings.API_ID, settings.API_HASH)
    else:
        # Create sessions directory if it doesn't exist
        if not os.path.exists(settings.SESSION_PATH):
            os.makedirs(settings.SESSION_PATH)
        session_file = os.path.join(settings.SESSION_PATH, settings.SESSION_NAME)
        client = TelegramClient(session_file, settings.API_ID, settings.API_HASH)
    return client

async def check_authorized(client):
    """Check if the client is authorized."""
    if not await client.is_user_authorized():
        return False
    return True

async def login_with_phone(client, phone_number):
    """Start the login process with a phone number."""
    await client.connect()
    
    if await client.is_user_authorized():
        return {"status": "already_authorized"}
    
    # Отправка кода в чат Telegram (по умолчанию)
    try:
        sent_code = await client.send_code_request(phone_number)
        return {
            "status": "code_sent",
            "phone_code_hash": sent_code.phone_code_hash
        }
    except Exception as e:
        logger.error(f"Error sending code: {e}")
        return {"status": "error", "message": str(e)}

async def login_with_code(client, phone_number, code, phone_code_hash):
    """Complete login with the received code."""
    try:
        await client.sign_in(phone_number, code, phone_code_hash=phone_code_hash)
        return {"status": "success"}
    except SessionPasswordNeededError:
        return {"status": "2fa_needed"}
    except Exception as e:
        logger.error(f"Error signing in with code: {e}")
        return {"status": "error", "message": str(e)}

async def login_with_password(client, password):
    """Complete 2FA login with password."""
    try:
        await client.sign_in(password=password)
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error signing in with password: {e}")
        return {"status": "error", "message": str(e)}

async def get_me(client):
    """Get current user information."""
    try:
        me = await client.get_me()
        return {
            "id": me.id,
            "first_name": me.first_name,
            "last_name": me.last_name,
            "username": me.username,
            "phone": me.phone
        }
    except Exception as e:
        logger.error(f"Error getting user info: {e}")
        return {"status": "error", "message": str(e)}

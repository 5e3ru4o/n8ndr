from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, File, UploadFile, Form
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
import os
import re
from telethon import TelegramClient, functions, types, events
from telethon.errors import SessionPasswordNeededError, AuthKeyUnregisteredError
from telethon.tl.types import InputPeerUser, InputPeerChannel
from loguru import logger
from pydantic import BaseModel
from typing import Optional, List, Union
import asyncio
import httpx
from telethon.sessions import StringSession

from .config import settings
from .auth import create_client, check_authorized, login_with_phone, login_with_code, login_with_password, get_me

app = FastAPI(title="Telegram User API", description="API для отправки сообщений через личный аккаунт Telegram")
security = HTTPBasic()

# Хранилище клиентов
clients = {}

def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    """Проверка базовой HTTP аутентификации"""
    is_correct_username = secrets.compare_digest(credentials.username, settings.ADMIN_USERNAME)
    is_correct_password = secrets.compare_digest(credentials.password, settings.ADMIN_PASSWORD)
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверные учетные данные",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

async def get_client():
    """Получить экземпляр клиента Telegram"""
    if "client" not in clients:
        client = await create_client()
        clients["client"] = client
        await client.connect()
    return clients["client"]

# Модели данных
class PhoneNumber(BaseModel):
    phone: str

class VerificationCode(BaseModel):
    phone: str
    code: str
    phone_code_hash: str

class Password(BaseModel):
    password: str

class Message(BaseModel):
    recipient: str  # username, phone или chat_id
    text: str
    parse_mode: Optional[str] = None

class MediaMessage(BaseModel):
    recipient: str
    caption: Optional[str] = None

# Маршруты для авторизации
@app.get("/status", tags=["Auth"])
async def check_status(username: str = Depends(get_current_username)):
    """Проверить статус авторизации в Telegram"""
    client = await get_client()
    authorized = await check_authorized(client)
    if authorized:
        me = await get_me(client)
        return {"authorized": True, "user": me}
    return {"authorized": False}

@app.post("/login/send_code", tags=["Auth"])
async def send_code(phone_data: PhoneNumber, username: str = Depends(get_current_username)):
    """Отправить код подтверждения на телефон"""
    client = await get_client()
    result = await login_with_phone(client, phone_data.phone)
    return result

@app.get("/login/get_code", tags=["Auth"])
async def get_code(username: str = Depends(get_current_username)):
    """Retrieve the latest Telegram login code."""
    client = await get_client()
    try:
        # Получаем entity официального бота Telegram по ID
        entity = await client.get_entity(777000)
        messages = await client.get_messages(entity, limit=10)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch messages: {str(e)}")
    for msg in messages:
        if msg.message:
            match = re.search(r"(\d{5,7})", msg.message)
            if match:
                return {"status": "code_received", "code": match.group(1)}
    raise HTTPException(status_code=404, detail="Code not found")

@app.post("/login/verify_code", tags=["Auth"])
async def verify_code(verification_data: VerificationCode, username: str = Depends(get_current_username)):
    """Подтвердить код из SMS"""
    client = await get_client()
    result = await login_with_code(
        client, 
        verification_data.phone, 
        verification_data.code, 
        verification_data.phone_code_hash
    )
    return result

@app.post("/login/2fa", tags=["Auth"])
async def verify_password(password_data: Password, username: str = Depends(get_current_username)):
    """Подтвердить двухфакторную аутентификацию паролем"""
    client = await get_client()
    result = await login_with_password(client, password_data.password)
    return result

@app.get("/session_string", tags=["Auth"])
async def get_session_string(username: str = Depends(get_current_username)):
    """Retrieve current Telegram StringSession."""
    client = await get_client()
    if not await check_authorized(client):
        raise HTTPException(status_code=401, detail="Не авторизован в Telegram")
    session_str = StringSession.save(client.session)
    return {"session_string": session_str}

# Маршруты для отправки сообщений
@app.post("/send/text", tags=["Messages"])
async def send_text_message(message: Message, username: str = Depends(get_current_username)):
    """Отправить текстовое сообщение"""
    client = await get_client()
    
    if not await check_authorized(client):
        raise HTTPException(status_code=401, detail="Не авторизован в Telegram")
    
    recipient = message.recipient
    if recipient.lstrip('-').isdigit():
        # Отправка по chat_id
        try:
            sent = await client.send_message(int(recipient), message.text, parse_mode=message.parse_mode)
            return {"status": "success", "message_id": sent.id, "date": sent.date.isoformat()}
        except Exception:
            logger.exception("Ошибка при отправке сообщения по chat_id")
            raise HTTPException(status_code=500, detail="Ошибка при отправке сообщения по chat_id")
    # Иначе username или телефон
    try:
        entity = await client.get_entity(recipient)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Ошибка при определении получателя")
        raise HTTPException(status_code=404, detail=f"Получатель '{recipient}' не найден")
    try:
        sent = await client.send_message(entity, message.text, parse_mode=message.parse_mode)
        return {"status": "success", "message_id": sent.id, "date": sent.date.isoformat()}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Ошибка при отправке сообщения")
        raise HTTPException(status_code=500, detail="Ошибка при отправке сообщения")

@app.post("/send/file", tags=["Messages"])
async def send_file(
    recipient: str = Form(...),
    caption: Optional[str] = Form(None),
    file: UploadFile = File(...),
    username: str = Depends(get_current_username)
):
    """Отправить файл или изображение"""
    client = await get_client()
    
    if not await check_authorized(client):
        raise HTTPException(status_code=401, detail="Не авторизован в Telegram")
    
    try:
        # Сохранение временного файла
        temp_file = f"/tmp/{file.filename}"
        with open(temp_file, "wb") as f:
            content = await file.read()
            f.write(content)
        
        # Определение получателя
        entity = None
        if recipient.lstrip('-').isdigit():
            entity = int(recipient)
        elif recipient.startswith("@"):
            entity = recipient
        elif recipient.startswith("+"):
            entity = await client.get_entity(recipient)
        else:
            try:
                entity = await client.get_entity(recipient)
            except Exception:
                raise HTTPException(status_code=404, detail=f"Получатель '{recipient}' не найден")
        
        # Отправка файла
        sent_message = await client.send_file(
            entity=entity,
            file=temp_file,
            caption=caption
        )
        
        # Удаление временного файла
        os.remove(temp_file)
        
        return {
            "status": "success",
            "message_id": sent_message.id,
            "date": sent_message.date.isoformat()
        }
    except Exception as e:
        logger.error(f"Ошибка при отправке файла: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка при отправке файла: {str(e)}")

@app.get("/contacts", tags=["Contacts"])
async def get_contacts(username: str = Depends(get_current_username)):
    """Получить список контактов"""
    client = await get_client()
    
    if not await check_authorized(client):
        raise HTTPException(status_code=401, detail="Не авторизован в Telegram")
    
    try:
        contacts = []
        async for dialog in client.iter_dialogs():
            contact = {
                "id": dialog.id,
                "name": dialog.name,
                "type": "channel" if dialog.is_channel else "group" if dialog.is_group else "user"
            }
            
            if hasattr(dialog.entity, 'username') and dialog.entity.username:
                contact["username"] = dialog.entity.username
                
            contacts.append(contact)
        
        return {"contacts": contacts}
    except Exception as e:
        logger.error(f"Ошибка при получении контактов: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка при получении контактов: {str(e)}")

import httpx
import os
# Basic auth для n8n
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
# Используем DNS-имя сервиса n8n внутри Docker-сети
N8N_WEBHOOK_URL = os.getenv(
    "N8N_WEBHOOK_URL",
    "http://n8n:5678/webhook/telegram"
)
SECOND_N8N_WEBHOOK_URL = os.getenv(
    "SECOND_N8N_WEBHOOK_URL",
    "http://n8n:5678/webhook/05165f1d-c814-4083-8ba8-877fd8ffb47e"
)

@app.on_event("startup")
async def start_listening():
    logger.info("Запуск Telethon listener-а")
    async def _listen():
        client = await get_client()
        logger.info("Telegram client подключен и слушает новые сообщения")
        # Подписка на новые сообщения Telegram
        @client.on(events.NewMessage())
        async def new_message_handler(event):
            logger.info(f"Получено сообщение от {event.sender_id}: {event.message.message}")
            # Добавляем chat_id для воспроизведения контекста
            chat_id = event.chat_id if event.chat_id is not None else event.sender_id
            payload = {"sender": event.sender_id, "chat_id": chat_id, "text": event.message.message, "message_id": event.message.id}
            logger.info(f"Отправка payload в n8n: {payload}")
            try:
                # Используем асинхронный клиент для отправки в оба workflow
                async with httpx.AsyncClient(auth=(ADMIN_USERNAME, ADMIN_PASSWORD)) as async_client:
                    # Первый webhook
                    response1 = await async_client.post(N8N_WEBHOOK_URL, json=payload)
                    logger.info(f"Webhook POST 1 успешен, status={response1.status_code}")
                    # Второй webhook
                    try:
                        response2 = await async_client.post(SECOND_N8N_WEBHOOK_URL, json=payload)
                        logger.info(f"Webhook POST 2 успешен, status={response2.status_code}")
                    except Exception as e:
                        logger.error(f"Webhook POST 2 failed: {e}")
            except Exception as e:
                logger.error(f"Webhook POST failed: {e}")
        # Запуск event loop Telethon до отключения
        try:
            await client.run_until_disconnected()
        except AuthKeyUnregisteredError:
            logger.warning("AuthKeyUnregisteredError: отсутствие сессии, listener пропущен")
    asyncio.create_task(_listen())

@app.on_event("shutdown")
async def shutdown_event():
    """Завершение работы при остановке"""
    if "client" in clients:
        await clients["client"].disconnect()
    logger.info("API сервер остановлен")

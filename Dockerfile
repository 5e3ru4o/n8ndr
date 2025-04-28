FROM python:3.11-slim

WORKDIR /app

# Обновляем pip и устанавливаем wheel перед установкой других пакетов
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port for API
EXPOSE 8000

# Use Railway’s dynamic PORT environment variable if set, fallback to 8000
CMD ["sh", "-c", "uvicorn app.api:app --host 0.0.0.0 --port ${PORT:-8000}"]
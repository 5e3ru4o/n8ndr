FROM python:3.11-slim

WORKDIR /app

# Обновляем pip и устанавливаем wheel перед установкой других пакетов
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Install Node.js and n8n CLI
RUN apt-get update && apt-get install -y curl gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g n8n && \
    rm -rf /var/lib/apt/lists/*

# Expose ports for API and n8n
EXPOSE 8000 5678
ENV N8N_PORT=5678

# Use Railway’s dynamic PORT environment variable if set, fallback to 8000
CMD ["sh", "-c", "n8n start --tunnel & uvicorn app.api:app --host 0.0.0.0 --port ${PORT:-8000}"]
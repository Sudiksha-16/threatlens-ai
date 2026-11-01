FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY yara_rules /app/yara_rules
COPY training /app/training

RUN mkdir -p /app/backend/uploads /app/reports

EXPOSE 8000

ENV PYTHONPATH=/app
ENV MONGODB_URL=mongodb://mongodb:27017
ENV DATABASE_NAME=threatlens_ai

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

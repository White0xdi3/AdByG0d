# AdByG0d API — Dockerfile
# Build context: apps/api/
FROM python:3.14-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only application source (excludes tests/, examples/, scripts/)
COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini ./

RUN mkdir -p /app/data && chown -R appuser:appgroup /app

USER appuser

ENV PYTHONPATH=/app/src

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && exec gunicorn adbygod_api.main:app --worker-class uvicorn.workers.UvicornWorker --workers 2 --bind 0.0.0.0:8000 --timeout 120 --access-logfile - --error-logfile -"]

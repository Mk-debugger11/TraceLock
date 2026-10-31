# CLI image:   docker build -t tracelock . && docker run --rm -v "$PWD:/src" tracelock scan /src --offline
# Server:      docker compose up  (API on :5001, UI on :3000)
FROM python:3.12-slim AS cli
WORKDIR /app
COPY backend/ /app/backend/
RUN pip install --no-cache-dir ./backend[color] && rm -rf /root/.cache
ENTRYPOINT ["tracelock"]
CMD ["--help"]

FROM python:3.12-slim AS api
WORKDIR /app/backend
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY backend/ /app/backend/
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir -e .[color]
ENV TRACELOCK_OFFLINE=0 TRACELOCK_ALLOW_LOCAL_PATHS=0
EXPOSE 5001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5001"]

FROM node:20-alpine AS ui
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

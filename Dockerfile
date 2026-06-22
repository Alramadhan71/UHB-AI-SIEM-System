FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HTTP_PORT=5000 \
    SIEM_DB_FILE=/data/siem.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data
EXPOSE 5000 517/udp 517/tcp 518/udp 518/tcp

CMD ["python", "siem_web.py"]


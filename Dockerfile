# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set environment variables for OpenSSL to work without user interaction
ENV DEBIAN_FRONTEND=noninteractive
ENV OPENSSL_CONF=/app/config.cnf

WORKDIR /app

COPY main.py .
COPY requirements.txt .
COPY config.cnf .

RUN apt-get update && \
    apt-get install -y openssl && \
    pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir uvicorn

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8003"]

ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.19
FROM ${BUILD_FROM}

ENV LANG C.UTF-8

WORKDIR /app

RUN apk add --no-cache \
    python3 \
    py3-pip

COPY app /app
COPY web /web
COPY rootfs /

RUN pip3 install --no-cache-dir \
    fastapi \
    uvicorn \
    python-multipart

RUN chmod +x /etc/services.d/homeii/run

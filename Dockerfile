ARG BUILD_FROM
FROM $BUILD_FROM

WORKDIR /app

RUN apk add --no-cache \
    python3 \
    py3-pip

COPY app /app
COPY web /web
COPY rootfs /

RUN pip3 install --no-cache-dir --break-system-packages \
    fastapi \
    uvicorn \
    python-multipart

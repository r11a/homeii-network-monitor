ARG BUILD_FROM
FROM $BUILD_FROM

WORKDIR /app

RUN apk add --no-cache \
    python3 \
    py3-pip

COPY app /app
COPY web /web

RUN pip3 install --no-cache-dir \
    fastapi \
    uvicorn \
    python-multipart

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8099", "--app-dir", "/app"]

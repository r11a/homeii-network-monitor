ARG BUILD_FROM
FROM $BUILD_FROM

ENV LANG=C.UTF-8

WORKDIR /app

RUN apk add --no-cache \
    python3 \
    py3-pip

COPY app /app
COPY web /web
COPY run.sh /run.sh

RUN pip3 install --no-cache-dir --break-system-packages \
    fastapi \
    uvicorn \
    python-multipart

RUN chmod a+x /run.sh

CMD ["/run.sh"]

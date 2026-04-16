ARG BUILD_FROM=ghcr.io/home-assistant/base:latest
FROM ${BUILD_FROM}
RUN apk add --no-cache python3 py3-pip iputils bind-tools iproute2
WORKDIR /app
COPY app /app/app
COPY web /app/web
COPY run.sh /run.sh
RUN chmod a+x /run.sh && python3 -m venv /opt/venv && . /opt/venv/bin/activate && pip install fastapi uvicorn mac-vendor-lookup python-multipart speedtest-cli
CMD ["/run.sh"]

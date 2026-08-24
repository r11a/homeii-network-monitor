ARG BUILD_FROM=ghcr.io/home-assistant/base:latest

FROM node:22-alpine AS ui-builder
WORKDIR /build
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/index.html ui/vite.config.js ./
COPY ui/src ./src
RUN npm run build

FROM ${BUILD_FROM}
RUN apk add --no-cache python3 py3-pip iputils bind-tools iproute2 tzdata
WORKDIR /app
COPY app /app/app
COPY --from=ui-builder /build/dist /app/web
COPY web/logo.gif /app/web/logo.gif
COPY run.sh /run.sh
RUN chmod a+x /run.sh && python3 -m venv /opt/venv && . /opt/venv/bin/activate && pip install fastapi uvicorn mac-vendor-lookup python-multipart speedtest-cli
CMD ["/run.sh"]

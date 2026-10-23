FROM node:22-bookworm-slim AS ui-builder
WORKDIR /build
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/index.html ui/vite.config.js ui/eslint.config.js ./
COPY ui/public ./public
COPY ui/src ./src
RUN npm run build

FROM debian:bookworm-slim AS engine-builder
ARG ZABBIX_VERSION=7.0.32
ARG ZABBIX_SHA256=ead5b0723ad965eb0e79f98d5d2b89088e7c898ae194eeba767e5d1fb2d50a96
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl build-essential \
    libpq-dev libsnmp-dev libevent-dev libpcre2-dev libcurl4-openssl-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl -fsSL "https://cdn.zabbix.com/zabbix/sources/stable/7.0/zabbix-${ZABBIX_VERSION}.tar.gz" -o zabbix-source.tar.gz \
    && echo "${ZABBIX_SHA256}  zabbix-source.tar.gz" | sha256sum -c - \
    && tar -xzf zabbix-source.tar.gz --strip-components=1 \
    && ./configure --enable-server --with-postgresql --with-net-snmp --with-libcurl --with-openssl \
       --prefix=/usr/local --sysconfdir=/etc/zabbix \
    && make -j2 && make install

# One add-on image; all downloads happen at build time, never during startup.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive HOMEII_DATA_DIR=/data/homeii HOMEII_ENGINE=zabbix HOMEII_BUNDLED_ZABBIX=1
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d \
    && apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip postgresql-15 postgresql-client-15 nginx \
    php8.2-fpm php8.2-pgsql php8.2-bcmath php8.2-mbstring php8.2-xml php8.2-gd php8.2-curl \
    libpq5 libsnmp40 libevent-2.1-7 libevent-pthreads-2.1-7 libpcre2-8-0 libcurl4 libssl3 \
    fping iputils-ping dnsutils iproute2 ca-certificates tzdata tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin zabbix \
    && chmod u+s /usr/bin/fping
WORKDIR /app
COPY --from=engine-builder /usr/local/sbin/zabbix_server /usr/local/sbin/zabbix_server
COPY --from=engine-builder /build/ui /opt/zabbix/ui
COPY --from=engine-builder /build/database/postgresql /opt/zabbix/database
COPY --from=engine-builder /build/templates /opt/zabbix/templates
COPY --from=engine-builder /build/zabbix-source.tar.gz /usr/share/homeii/sources/zabbix-7.0.32.tar.gz
COPY app /app/app
COPY requirements.txt /app/requirements.txt
COPY --from=ui-builder /build/dist /app/web
COPY logo.png /app/web/logo.png
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt \
    && mkdir -p /run/php /etc/zabbix /var/lib/zabbix /var/log/zabbix \
    && chown zabbix:zabbix /var/lib/zabbix /var/log/zabbix
COPY deploy/nginx.conf /etc/nginx/nginx.conf
COPY THIRD_PARTY.md /usr/share/homeii/THIRD_PARTY.md
COPY Dockerfile /usr/share/homeii/sources/Dockerfile
EXPOSE 8384 8444
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/venv/bin/python", "-m", "app.local_stack"]

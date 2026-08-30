#!/usr/bin/with-contenv sh
OPTIONS=/data/options.json
SSL_ENABLED=$(/opt/venv/bin/python -c "import json; print(str(json.load(open('$OPTIONS')).get('ssl', False)).lower())" 2>/dev/null || echo false)
CERTFILE=$(/opt/venv/bin/python -c "import json; print(json.load(open('$OPTIONS')).get('certfile', 'fullchain.pem'))" 2>/dev/null || echo fullchain.pem)
KEYFILE=$(/opt/venv/bin/python -c "import json; print(json.load(open('$OPTIONS')).get('keyfile', 'privkey.pem'))" 2>/dev/null || echo privkey.pem)

if [ "$SSL_ENABLED" = "true" ]; then
  if [ ! -r "/ssl/$CERTFILE" ] || [ ! -r "/ssl/$KEYFILE" ]; then
    echo "HTTPS requested but /ssl/$CERTFILE or /ssl/$KEYFILE is unavailable" >&2
    exit 1
  fi
  /opt/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8443 --ssl-certfile "/ssl/$CERTFILE" --ssl-keyfile "/ssl/$KEYFILE" &
  echo "Direct HTTPS interface enabled on port 8443"
fi

exec /opt/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8383

#!/usr/bin/with-contenv sh
exec /opt/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8108


FROM python:3.11-slim

WORKDIR /app

COPY app /app
COPY web /web

RUN pip install fastapi uvicorn python-multipart

EXPOSE 8099

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8099", "--app-dir", "/app"]

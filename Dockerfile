FROM python:3.11-slim

WORKDIR /app

COPY app /app
COPY web /web

RUN pip install fastapi uvicorn python-multipart

EXPOSE 8099

CMD ["python", "/app/main.py"]

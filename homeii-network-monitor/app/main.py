from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
import sqlite3
import os

app = FastAPI()

DB_PATH = "/data/homeii.db"

os.makedirs("/data", exist_ok=True)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS devices (
id INTEGER PRIMARY KEY,
name TEXT,
ip TEXT,
status TEXT
)
""")

conn.commit()

@app.get("/api/devices")
def devices():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM devices")
    rows = c.fetchall()
    return rows

app.mount("/", StaticFiles(directory="/web", html=True), name="web")

import uvicorn
uvicorn.run(app, host="0.0.0.0", port=8099)

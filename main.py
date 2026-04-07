from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List
import httpx
import os

app = FastAPI(title="Log-Sentinel Cloud API")

# Configuración (Esto irá a variables de entorno en Railway)
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
API_KEY_INTERNA = "sentinel_beta_2026" # Key temporal para tu primer test

class LogEntry(BaseModel):
    message: str
    timestamp: str

async def send_telegram_msg(text: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
    async with httpx.AsyncClient() as client:
        await client.post(url, json=payload)

@app.get("/")
def health_check():
    return {"status": "online", "version": "0.1.0"}

@app.post("/v1/ingest")
async def ingest_logs(
    payload: List[LogEntry], 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    # Seguridad básica inicial
    if x_api_key != API_KEY_INTERNA:
        raise HTTPException(status_code=403, detail="Unauthorized")

    for entry in payload:
        # Lógica de detección ultra-simple para el test
        if "FAILED" in entry.message.upper() or "ERROR" in entry.message.upper():
            msg = f"⚠️ [ALERTA LSC]\nEvento sospechoso detectado:\n{entry.message}"
            background_tasks.add_task(send_telegram_msg, msg)
            
    return {"status": "processed", "count": len(payload)}
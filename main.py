from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List
import httpx
import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# --- CONFIGURACIÓN GENERAL ---
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
API_KEY_INTERNA = "sentinel_beta_2026"

# --- CONFIGURACIÓN DE BASE DE DATOS ---
DATABASE_URL = os.getenv("DATABASE_URL")
# Parche de seguridad: SQLAlchemy necesita que diga postgresql:// en vez de postgres://
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Inicializar motor de base de datos
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Definir la estructura de la tabla
class LogEvent(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True) # Para saber de qué cliente es
    message = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

# Crear la tabla en la base de datos automáticamente si no existe
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Log-Sentinel Cloud API")

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
    return {"status": "online", "db_connected": DATABASE_URL is not None}

@app.post("/v1/ingest")
async def ingest_logs(
    payload: List[LogEntry], 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY_INTERNA:
        raise HTTPException(status_code=403, detail="Unauthorized")

    db = SessionLocal()
    try:
        for entry in payload:
            # 1. GUARDAR EN LA BÓVEDA (PostgreSQL)
            new_event = LogEvent(
                tenant_id="cliente_demo", # Luego lo haremos dinámico
                message=entry.message,
                timestamp=datetime.utcnow()
            )
            db.add(new_event)
            
            # 2. ENVIAR ALARMA (Telegram)
            if "FAILED" in entry.message.upper() or "ERROR" in entry.message.upper():
                msg = f"⚠️ [ALERTA LSC]\nEvento guardado en BD y detectado:\n{entry.message}"
                background_tasks.add_task(send_telegram_msg, msg)
        
        # Confirmar el guardado
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Error guardando en BD")
    finally:
        db.close()
        
    return {"status": "processed and saved", "count": len(payload)}
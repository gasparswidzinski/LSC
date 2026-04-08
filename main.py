from fastapi import FastAPI, Header, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import List
import httpx
import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base

# --- CONFIGURACIÓN GENERAL ---
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# --- BASE DE DATOS ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Tabla de Clientes (Tenancy)
class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    api_key = Column(String, unique=True, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow)
    telegram_chat_id = Column(String, nullable=True) 

# Tabla de Eventos (La Bóveda)
class LogEvent(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True) # <-- CORREGIDO: Vuelve a ser tenant_id
    message = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Log-Sentinel Cloud API")

class LogEntry(BaseModel):
    message: str
    timestamp: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 🛡️ SEGURIDAD
def verify_api_key(x_api_key: str = Header(None), db: Session = Depends(get_db)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API Key faltante")
    client = db.query(Client).filter(Client.api_key == x_api_key).first()
    if not client:
        raise HTTPException(status_code=401, detail="API Key inválida (Error 401)")
    return client

async def send_telegram_msg(chat_id: str, text: str):
    import requests, os
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    try:
        requests.post(url, json=payload)
    except Exception as e:
        print(f"Error enviando telegram: {e}")

@app.get("/setup-demo")
def setup_demo(db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.api_key == "lsc_demo_12345").first()
    if not client:
        new_client = Client(name="Estudio Contable Demo", api_key="lsc_demo_12345")
        db.add(new_client)
        db.commit()
        return {"msg": "Cliente demo creado con la key: lsc_demo_12345"}
    return {"msg": "El cliente ya existe"}

@app.post("/v1/heartbeat")
def heartbeat(client: Client = Depends(verify_api_key), db: Session = Depends(get_db)):
    client.last_seen = datetime.utcnow()
    db.commit()
    return {"status": "alive", "tenant": client.name}

@app.post("/v1/ingest")
async def ingest_logs(
    payload: List[LogEntry], 
    background_tasks: BackgroundTasks,
    client: Client = Depends(verify_api_key), 
    db: Session = Depends(get_db)
):
    try:
        for entry in payload:
            new_event = LogEvent(
                tenant_id=client.name, 
                message=entry.message,
                timestamp=datetime.utcnow()
            )
            db.add(new_event)
            
            if "FAILED" in entry.message.upper() or "ERROR" in entry.message.upper() or "4625" in entry.message:
                msg = f"⚠️ [ALERTA LSC] Empresa: {client.name}\nEvento:\n{entry.message}"
                
                # --- NUEVA LÓGICA DE RUTEO ---
                # Verifica si el cliente tiene un chat_id propio en la base de datos
                # Si no tiene (o da error al buscarlo), usa la variable de entorno global por defecto
                import os
                admin_chat_id = os.getenv("TELEGRAM_CHAT_ID") 
                destino_id = getattr(client, 'telegram_chat_id', admin_chat_id) 
                if not destino_id: 
                    destino_id = admin_chat_id
                
                # Ahora le pasamos DOS parámetros a la tarea: el ID del destino y el mensaje
                background_tasks.add_task(send_telegram_msg, destino_id, msg)
        
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Error de BD")
        
    return {"status": "saved", "tenant": client.name}
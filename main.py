from fastapi import FastAPI, Header, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import List
import httpx
import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from protocols import *

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
    is_active = Column(Boolean, default=True)

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
async def verify_api_key(x_api_key: str = Header(None), db: Session = Depends(get_db)):
    if not x_api_key:
        raise HTTPException(status_code=403, detail="Falta API Key")
        
    client = db.query(Client).filter(Client.api_key == x_api_key).first()
    
    if not client:
        raise HTTPException(status_code=403, detail="API Key inválida")
    
    # EL BLINDAJE: Si el cliente existe pero no está activo, rechazamos el pedido
    if not client.is_active:
        raise HTTPException(status_code=403, detail="Suscripción inactiva. Contacte al administrador.")
        
    return client


async def send_telegram_msg(chat_id: str, text: str):
    import requests, os
    
    # 1. Recuperamos el token (asegurándote de usar el nombre correcto en Railway)
    token = os.getenv("TELEGRAM_TOKEN")
    if not token:
        print("[ERROR] TELEGRAM_BOT_TOKEN no configurado en las variables de entorno.")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}

    try:
        # 2. Enviamos el mensaje con un timeout de 10 segundos
        response = requests.post(url, json=payload, timeout=10)
        
        # 3. Solo imprimimos si hay un error real (para auditoría interna)
        if not response.ok:
            print(f"[Telegram Error] ID: {chat_id} | Status: {response.status_code} | Msg: {response.text}")
            
    except Exception as e:
        # 4. Fallo de red o conexión
        print(f"[Critical Error] Falló el despacho a Telegram: {e}")

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
    # --- IMPORTAMOS EL MANUAL DE FRANQUICIA (SOP) ---
    from protocols import get_protocol 

    try:
        for entry in payload:
            new_event = LogEvent(
                tenant_id=client.name, 
                message=entry.message,
                timestamp=datetime.utcnow()
            )
            db.add(new_event)
            
            # Como el agente V2 ya filtra la basura, todo lo que llega con "ID" es alerta.
            if "ID " in entry.message or "4625" in entry.message:
                
                # 1. El Cerebro: Buscamos qué hacer según el evento
                protocol = get_protocol(entry.message)
                steps_formatted = "\n".join(protocol["action_steps"])
                
                # 2. El Mensaje SSO (Standard Service Offering)
                msg_final = (
                    f"{protocol['title']}\n"
                    f"🏢 Empresa: {client.name}\n"
                    f"⚡ Prioridad: {protocol['urgency']}\n\n"
                    f"🛠️ PASOS A SEGUIR:\n{steps_formatted}\n\n"
                    f"--- Detalles Técnicos ---\n"
                    f"{entry.message[:150]}..."
                )
                
                # 3. Ruteo Automático
                import os
                admin_chat_id = os.getenv("TELEGRAM_CHAT_ID") 
                destino_id = getattr(client, 'telegram_chat_id', admin_chat_id) 
                if not destino_id: 
                    destino_id = admin_chat_id
                
                # 4. Disparo asíncrono
                background_tasks.add_task(send_telegram_msg, destino_id, msg_final)
        
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Error de BD")
        
    return {"status": "saved", "tenant": client.name}
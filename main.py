from fastapi import FastAPI, Header, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
import json
import os
from datetime import datetime

import requests
from fastapi import Request
from sqlalchemy import Boolean, Column, DateTime, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

from protocols import extract_event_id, format_alert


# --- CONFIGURACIÓN GENERAL ---
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL no configurada.")


# --- BASE DE DATOS ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    api_key = Column(String, unique=True, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow)
    telegram_chat_id = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)


class LogEvent(Base):
    """
    Se mantiene el esquema actual para no romper Railway/PostgreSQL sin migración.
    Los eventos estructurados se guardan como JSON dentro de message.
    """

    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True)
    message = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Log-Sentinel Cloud API", version="0.9.2-pilot")


class LogEntry(BaseModel):
    # Compatibilidad con el agente anterior
    message: Optional[str] = None
    timestamp: Optional[str] = None

    # Payload estructurado recomendado desde el agente nuevo
    event_id: Optional[int] = None
    hostname: Optional[str] = None
    event_time: Optional[str] = None
    source: Optional[str] = None
    raw_message: Optional[str] = None
    agent_version: Optional[str] = None
    record_id: Optional[int] = None
    log_name: Optional[str] = None

    # Sprint 4: campos de agregación inteligente para Event ID 4625
    protocol_key: Optional[str] = None
    failed_login_count: Optional[int] = None
    window_seconds: Optional[int] = None
    first_event_time: Optional[str] = None
    last_event_time: Optional[str] = None
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    logon_type: Optional[str] = None
    record_ids: Optional[List[int]] = None

    class Config:
        extra = "allow"


def model_to_dict(entry: LogEntry) -> Dict[str, Any]:
    if hasattr(entry, "model_dump"):
        return entry.model_dump(exclude_none=True)  # Pydantic v2
    return entry.dict(exclude_none=True)  # Pydantic v1


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def verify_api_key(x_api_key: str = Header(None), db: Session = Depends(get_db)):
    if not x_api_key:
        raise HTTPException(status_code=403, detail="Falta API Key")

    client = db.query(Client).filter(Client.api_key == x_api_key).first()

    if not client:
        raise HTTPException(status_code=403, detail="API Key inválida")

    if not client.is_active:
        raise HTTPException(status_code=403, detail="Suscripción inactiva. Contacte al administrador.")

    return client


async def send_telegram_msg(chat_id: str, text: str):
    token = os.getenv("TELEGRAM_TOKEN")
    if not token:
        print("[ERROR] TELEGRAM_TOKEN no configurado en las variables de entorno.")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text[:3900],
        "disable_web_page_preview": True,
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        if not response.ok:
            print(f"[Telegram Error] chat_id={chat_id} status={response.status_code} body={response.text}")
    except Exception as e:
        print(f"[ERROR] Falló el envío a Telegram: {e}")


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
    return {"status": "alive", "tenant": client.name, "last_seen": client.last_seen.isoformat()}


@app.post("/v1/ingest")
async def ingest_logs(
    payload: List[LogEntry],
    background_tasks: BackgroundTasks,
    client: Client = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    received = 0
    alerted = 0

    admin_chat_id = os.getenv("TELEGRAM_CHAT_ID")
    destino_id = client.telegram_chat_id or admin_chat_id

    try:
        for entry in payload:
            data = model_to_dict(entry)
            received += 1

            # Guardamos el evento completo como JSON para auditoría sin requerir migración de tabla.
            stored_message = json.dumps(data, ensure_ascii=False)
            db.add(
                LogEvent(
                    tenant_id=client.name,
                    message=stored_message,
                    timestamp=datetime.utcnow(),
                )
            )

            event_id = extract_event_id(data)
            if event_id and destino_id:
                msg_final = format_alert(data, client.name)
                background_tasks.add_task(send_telegram_msg, destino_id, msg_final)
                alerted += 1

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[ERROR] No se pudo procesar /v1/ingest: {e}")
        raise HTTPException(status_code=500, detail="Error interno al procesar eventos")

    return {"status": "saved", "tenant": client.name, "received": received, "alerted": alerted}


@app.post("/v1/webhooks/mercadopago")
async def mercadopago_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Recibe notificaciones de Mercado Pago y confirma el estado consultando la API de MP.
    Nota: este MVP conserva is_active para no romper el esquema actual. La mejora siguiente
    debería incorporar status/payment_status/subscription_id con migración formal.
    """
    try:
        payload = await request.json()
    except Exception:
        return {"status": "ok"}

    event_type = payload.get("type")
    action = payload.get("action")

    if event_type == "payment" or action == "payment.created":
        payment_id = payload.get("data", {}).get("id")

        if payment_id and MP_ACCESS_TOKEN:
            headers = {"Authorization": f"Bearer {MP_ACCESS_TOKEN}"}
            mp_url = f"https://api.mercadopago.com/v1/payments/{payment_id}"

            try:
                response = requests.get(mp_url, headers=headers, timeout=15)
            except Exception as e:
                print(f"[MercadoPago] No se pudo consultar el pago {payment_id}: {e}")
                return {"status": "ok"}

            if response.status_code == 200:
                payment_data = response.json()
                status = payment_data.get("status")
                api_key_cliente = payment_data.get("external_reference")

                if api_key_cliente:
                    cliente = db.query(Client).filter(Client.api_key == api_key_cliente).first()
                    if cliente:
                        if status == "approved":
                            cliente.is_active = True
                            print(f"[COBRANZA] Pago aprobado. Cliente activado: {cliente.name}")
                        elif status in ["rejected", "cancelled", "refunded"]:
                            cliente.is_active = False
                            print(f"[COBRANZA] Pago fallido/cancelado. Cliente desactivado: {cliente.name}")
                        db.commit()

    return {"status": "ok"}

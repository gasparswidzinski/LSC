from fastapi import FastAPI, Header, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
import json
import os
from datetime import datetime, timedelta

import requests
from fastapi import Request
from sqlalchemy import Boolean, Column, DateTime, Integer, Numeric, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

from protocols import extract_event_id, format_alert, format_agent_offline_alert, format_agent_online_alert


# --- CONFIGURACIÓN GENERAL ---
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")

# Sprint 9 — Monitoreo de agente offline
OFFLINE_THRESHOLD_MINUTES = int(os.getenv("OFFLINE_THRESHOLD_MINUTES", "60"))
OFFLINE_REPEAT_HOURS = int(os.getenv("OFFLINE_REPEAT_HOURS", "6"))
OFFLINE_CHECK_SECRET = os.getenv("OFFLINE_CHECK_SECRET")

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

    # Campos comerciales/operativos agregados por migracion_pagos_lsc_v1.sql.
    # IMPORTANTE: ejecutar la migración antes de desplegar este main.py.
    status = Column(String, nullable=True, default="active")
    plan = Column(String, nullable=True)
    business_type = Column(String, nullable=True)
    email = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    responsible_name = Column(String, nullable=True)
    technician_name = Column(String, nullable=True)
    technician_contact = Column(String, nullable=True)
    server_count = Column(Integer, nullable=True, default=1)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    payment_status = Column(String, nullable=True, default="pending_payment")
    subscription_status = Column(String, nullable=True, default="pending")
    mp_plan_id = Column(String, nullable=True)
    mp_preapproval_id = Column(String, nullable=True)
    mp_last_payment_id = Column(String, nullable=True)
    mp_payer_email = Column(String, nullable=True)
    last_payment_at = Column(DateTime, nullable=True)
    last_payment_status = Column(String, nullable=True)
    paid_until = Column(DateTime, nullable=True)
    payment_amount = Column(Numeric(12, 2), nullable=True)
    payment_currency = Column(String, nullable=True)
    payment_notes = Column(Text, nullable=True)


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


class AgentMonitorState(Base):
    """
    Sprint 9:
    Estado mínimo para evitar spam de alertas offline y poder avisar recuperación.
    No modifica la tabla clients.
    """

    __tablename__ = "agent_monitor_state"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, unique=True, index=True)
    is_offline = Column(Boolean, default=False)
    offline_since = Column(DateTime, nullable=True)
    last_offline_alert_at = Column(DateTime, nullable=True)
    last_online_alert_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)


class TermsAcceptance(Base):
    """
    Constancia remota de aceptación de términos del instalador LSC.
    Se registra cuando el usuario ingresa S en instalar_lsc_v4.bat.
    No reemplaza el contrato principal; sirve como trazabilidad operativa y respaldo contractual.
    """

    __tablename__ = "terms_acceptances"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, index=True, nullable=False)
    client_name = Column(String, nullable=False)
    terms_version = Column(String, nullable=False)
    installer_version = Column(String, nullable=True)
    computer_name = Column(String, nullable=True)
    windows_user = Column(String, nullable=True)
    accepted_value = Column(String, nullable=False, default="S")
    accepted_at_local = Column(String, nullable=True)
    accepted_at_utc = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    raw_payload = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class PaymentWebhookEvent(Base):
    """
    Auditoría de webhooks de Mercado Pago.
    Guarda evento crudo, respuesta consultada a MP y resultado del procesamiento.
    """

    __tablename__ = "payment_webhook_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, nullable=True)
    action = Column(String, nullable=True)
    mp_resource_id = Column(String, index=True, nullable=True)
    client_id = Column(Integer, index=True, nullable=True)
    client_name = Column(String, nullable=True)
    external_reference = Column(String, index=True, nullable=True)
    payment_status = Column(String, nullable=True)
    processed_ok = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    raw_payload = Column(Text, nullable=True)
    mp_response = Column(Text, nullable=True)
    source_ip = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    processed_at = Column(DateTime, nullable=True)


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Log-Sentinel Cloud API", version="0.9.7-pilot-payments-trace")


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


class TermsAcceptancePayload(BaseModel):
    terms_version: str
    installer_version: Optional[str] = None
    computer_name: Optional[str] = None
    windows_user: Optional[str] = None
    accepted_value: str = "S"
    accepted_at_local: Optional[str] = None
    local_terms_file: Optional[str] = None

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


def _event_log(db: Session, tenant_id: str, event_type: str, data: Dict[str, Any]):
    """Guarda eventos operativos internos en la tabla events sin migrar esquema."""
    payload = {"type": event_type, **data}
    db.add(
        LogEvent(
            tenant_id=tenant_id,
            message=json.dumps(payload, ensure_ascii=False, default=str),
            timestamp=datetime.utcnow(),
        )
    )


def _get_or_create_monitor_state(db: Session, client_id: int) -> AgentMonitorState:
    state = db.query(AgentMonitorState).filter(AgentMonitorState.client_id == client_id).first()
    if not state:
        state = AgentMonitorState(client_id=client_id, is_offline=False, updated_at=datetime.utcnow())
        db.add(state)
        db.flush()
    return state


def _admin_secret_valid(x_admin_secret: Optional[str]) -> bool:
    if not OFFLINE_CHECK_SECRET:
        # En producción conviene configurarlo. Para MVP permite prueba manual sin bloquear.
        return True
    return x_admin_secret == OFFLINE_CHECK_SECRET


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
def heartbeat(
    background_tasks: BackgroundTasks,
    client: Client = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    client.last_seen = now

    state = _get_or_create_monitor_state(db, client.id)
    was_offline = bool(state.is_offline)

    if was_offline:
        state.is_offline = False
        state.last_online_alert_at = now
        state.updated_at = now

        destino_id = client.telegram_chat_id or os.getenv("TELEGRAM_CHAT_ID")
        if destino_id:
            msg = format_agent_online_alert(client.name, now, now)
            background_tasks.add_task(send_telegram_msg, destino_id, msg)

        _event_log(
            db,
            client.name,
            "agent_online",
            {"client_id": client.id, "last_seen": now.isoformat()},
        )
    else:
        state.updated_at = now

    db.commit()
    return {"status": "alive", "tenant": client.name, "last_seen": client.last_seen.isoformat()}


@app.post("/v1/terms-acceptance")
async def register_terms_acceptance(
    payload: TermsAcceptancePayload,
    request: Request,
    client: Client = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    """
    Registra en el backend la aceptación remota de términos del instalador.

    El instalador debe enviar este endpoint de forma no bloqueante luego de que
    el usuario ingrese S. La constancia local sigue siendo el respaldo primario
    cuando no haya conectividad.
    """
    data = payload.dict(exclude_none=True)
    accepted_value = (payload.accepted_value or "").strip().upper()

    if accepted_value != "S":
        raise HTTPException(status_code=400, detail="Aceptación inválida")

    source_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    acceptance = TermsAcceptance(
        client_id=client.id,
        client_name=client.name,
        terms_version=payload.terms_version,
        installer_version=payload.installer_version,
        computer_name=payload.computer_name,
        windows_user=payload.windows_user,
        accepted_value=accepted_value,
        accepted_at_local=payload.accepted_at_local,
        accepted_at_utc=datetime.utcnow(),
        source_ip=source_ip,
        user_agent=user_agent,
        raw_payload=json.dumps(data, ensure_ascii=False, default=str),
        created_at=datetime.utcnow(),
    )

    try:
        db.add(acceptance)
        _event_log(
            db,
            client.name,
            "terms_acceptance",
            {
                "client_id": client.id,
                "terms_version": payload.terms_version,
                "installer_version": payload.installer_version,
                "computer_name": payload.computer_name,
                "accepted_value": accepted_value,
                "source_ip": source_ip,
            },
        )
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[ERROR] No se pudo registrar aceptación de términos: {e}")
        raise HTTPException(status_code=500, detail="Error interno al registrar aceptación")

    return {
        "status": "ok",
        "tenant": client.name,
        "terms_version": payload.terms_version,
        "accepted_at_utc": acceptance.accepted_at_utc.isoformat(),
    }


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


@app.post("/admin/check-offline-agents")
def check_offline_agents(
    background_tasks: BackgroundTasks,
    x_admin_secret: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """
    Sprint 9:
    Revisa clientes activos y avisa si no reportan heartbeat dentro del umbral.

    Recomendación:
    - Ejecutar manualmente para pruebas.
    - Luego programar un cron externo cada 10/15 minutos.
    - Proteger con OFFLINE_CHECK_SECRET en Railway.
    """
    if not _admin_secret_valid(x_admin_secret):
        raise HTTPException(status_code=403, detail="Admin secret inválido")

    now = datetime.utcnow()
    threshold_delta = timedelta(minutes=OFFLINE_THRESHOLD_MINUTES)
    repeat_delta = timedelta(hours=OFFLINE_REPEAT_HOURS)

    checked = 0
    offline_detected = 0
    alerts_sent = 0
    skipped_without_last_seen = 0

    active_clients = db.query(Client).filter(Client.is_active == True).all()  # noqa: E712

    for client in active_clients:
        checked += 1

        if not client.last_seen:
            skipped_without_last_seen += 1
            continue

        age = now - client.last_seen
        if age <= threshold_delta:
            continue

        offline_detected += 1
        state = _get_or_create_monitor_state(db, client.id)

        should_alert = False
        if not state.is_offline:
            should_alert = True
            state.offline_since = client.last_seen
        elif not state.last_offline_alert_at:
            should_alert = True
        elif now - state.last_offline_alert_at >= repeat_delta:
            should_alert = True

        state.is_offline = True
        state.updated_at = now

        if should_alert:
            state.last_offline_alert_at = now
            destino_id = client.telegram_chat_id or os.getenv("TELEGRAM_CHAT_ID")
            if destino_id:
                msg = format_agent_offline_alert(
                    client.name,
                    client.last_seen,
                    OFFLINE_THRESHOLD_MINUTES,
                    now,
                )
                background_tasks.add_task(send_telegram_msg, destino_id, msg)
                alerts_sent += 1

            _event_log(
                db,
                client.name,
                "agent_offline",
                {
                    "client_id": client.id,
                    "last_seen": client.last_seen.isoformat(),
                    "threshold_minutes": OFFLINE_THRESHOLD_MINUTES,
                    "age_seconds": int(age.total_seconds()),
                },
            )

    db.commit()

    return {
        "status": "ok",
        "checked": checked,
        "offline_detected": offline_detected,
        "alerts_sent": alerts_sent,
        "threshold_minutes": OFFLINE_THRESHOLD_MINUTES,
        "repeat_hours": OFFLINE_REPEAT_HOURS,
        "skipped_without_last_seen": skipped_without_last_seen,
    }


def _json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def _get_request_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else None


def _parse_mp_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        # Mercado Pago suele devolver ISO con zona horaria. PostgreSQL/SQLAlchemy actual guarda naive UTC.
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return parsed.astimezone().replace(tzinfo=None)
        return parsed
    except Exception:
        return None


def _extract_mp_preapproval_id(payment_data: Dict[str, Any]) -> Optional[str]:
    # La forma exacta puede variar según el tipo de pago/suscripción.
    candidates = [
        payment_data.get("preapproval_id"),
        payment_data.get("subscription_id"),
        payment_data.get("preapproval_plan_id"),
    ]
    metadata = payment_data.get("metadata") or {}
    if isinstance(metadata, dict):
        candidates.extend([
            metadata.get("preapproval_id"),
            metadata.get("subscription_id"),
            metadata.get("preapproval_plan_id"),
        ])
    for value in candidates:
        if value:
            return str(value)
    return None


def _apply_payment_status_to_client(client: Client, payment_id: str, payment_data: Dict[str, Any]) -> None:
    status = str(payment_data.get("status") or "unknown")
    now = datetime.utcnow()

    if status == "approved":
        client.is_active = True
        client.status = "active"
        client.payment_status = "approved"
        client.subscription_status = "active"
    elif status in {"pending", "in_process", "authorized"}:
        client.is_active = False
        client.status = "pending_payment"
        client.payment_status = status
        client.subscription_status = "pending"
    elif status == "rejected":
        client.is_active = False
        client.status = "past_due"
        client.payment_status = "rejected"
        client.subscription_status = "past_due"
    elif status in {"cancelled", "refunded", "charged_back"}:
        client.is_active = False
        client.status = status
        client.payment_status = status
        client.subscription_status = "inactive" if status in {"refunded", "charged_back"} else "cancelled"
    else:
        # Estado no contemplado: por prudencia no se activa el servicio automáticamente.
        client.is_active = False
        client.status = "inactive"
        client.payment_status = status
        client.subscription_status = "inactive"

    client.mp_last_payment_id = str(payment_id)
    client.last_payment_status = status
    client.last_payment_at = (
        _parse_mp_datetime(payment_data.get("date_approved"))
        or _parse_mp_datetime(payment_data.get("money_release_date"))
        or _parse_mp_datetime(payment_data.get("date_created"))
        or now
    )

    preapproval_id = _extract_mp_preapproval_id(payment_data)
    if preapproval_id:
        client.mp_preapproval_id = preapproval_id

    payer = payment_data.get("payer") or {}
    if isinstance(payer, dict) and payer.get("email"):
        client.mp_payer_email = payer.get("email")

    if payment_data.get("transaction_amount") is not None:
        client.payment_amount = payment_data.get("transaction_amount")
    if payment_data.get("currency_id"):
        client.payment_currency = payment_data.get("currency_id")

    client.payment_notes = f"Último evento Mercado Pago: payment_id={payment_id}, status={status}, actualizado={now.isoformat()} UTC"
    client.updated_at = now


@app.post("/v1/webhooks/mercadopago")
async def mercadopago_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Recibe webhooks de Mercado Pago, guarda auditoría y actualiza estado operativo.

    Regla operativa LSC:
    - payment.status == approved  => client.is_active = True
    - rejected/cancelled/refunded/charged_back => client.is_active = False
    - pending/in_process/authorized => client.is_active = False hasta aprobación real
    """
    source_ip = _get_request_ip(request)
    user_agent = request.headers.get("user-agent")

    try:
        payload = await request.json()
    except Exception as exc:
        db.add(PaymentWebhookEvent(
            event_type="invalid_json",
            processed_ok=False,
            error_message=f"JSON inválido: {exc}",
            source_ip=source_ip,
            user_agent=user_agent,
            created_at=datetime.utcnow(),
        ))
        db.commit()
        return {"status": "ok"}

    event_type = payload.get("type")
    action = payload.get("action")
    payment_id = str((payload.get("data") or {}).get("id") or "")

    audit = PaymentWebhookEvent(
        event_type=event_type,
        action=action,
        mp_resource_id=payment_id or None,
        raw_payload=_json_dumps(payload),
        source_ip=source_ip,
        user_agent=user_agent,
        created_at=datetime.utcnow(),
        processed_ok=False,
    )
    db.add(audit)
    db.flush()

    is_payment_event = event_type == "payment" or action in {"payment.created", "payment.updated"}
    if not is_payment_event:
        audit.processed_ok = True
        audit.error_message = "Evento ignorado: no es payment."
        audit.processed_at = datetime.utcnow()
        db.commit()
        return {"status": "ok", "ignored": True}

    if not payment_id:
        audit.error_message = "Webhook payment sin data.id."
        audit.processed_at = datetime.utcnow()
        db.commit()
        return {"status": "ok", "processed": False}

    if not MP_ACCESS_TOKEN:
        audit.error_message = "MP_ACCESS_TOKEN no configurado."
        audit.processed_at = datetime.utcnow()
        db.commit()
        return {"status": "ok", "processed": False}

    headers = {"Authorization": f"Bearer {MP_ACCESS_TOKEN}"}
    mp_url = f"https://api.mercadopago.com/v1/payments/{payment_id}"

    try:
        response = requests.get(mp_url, headers=headers, timeout=15)
    except Exception as exc:
        audit.error_message = f"No se pudo consultar pago MP {payment_id}: {exc}"
        audit.processed_at = datetime.utcnow()
        db.commit()
        print(f"[MercadoPago] {audit.error_message}")
        return {"status": "ok", "processed": False}

    audit.mp_response = response.text[:20000]

    if response.status_code != 200:
        audit.error_message = f"Mercado Pago respondió {response.status_code}."
        audit.processed_at = datetime.utcnow()
        db.commit()
        print(f"[MercadoPago] {audit.error_message} body={response.text[:500]}")
        return {"status": "ok", "processed": False}

    payment_data = response.json()
    payment_status = str(payment_data.get("status") or "unknown")
    external_reference = payment_data.get("external_reference")

    audit.payment_status = payment_status
    audit.external_reference = external_reference

    if not external_reference:
        audit.error_message = "Pago sin external_reference; no se puede vincular a cliente LSC."
        audit.processed_at = datetime.utcnow()
        db.commit()
        return {"status": "ok", "processed": False}

    cliente = db.query(Client).filter(Client.api_key == external_reference).first()
    if not cliente:
        audit.error_message = "No existe cliente con API Key/external_reference informado por MP."
        audit.processed_at = datetime.utcnow()
        db.commit()
        return {"status": "ok", "processed": False}

    try:
        _apply_payment_status_to_client(cliente, payment_id, payment_data)
        audit.client_id = cliente.id
        audit.client_name = cliente.name
        audit.processed_ok = True
        audit.processed_at = datetime.utcnow()

        _event_log(
            db,
            cliente.name,
            "mercadopago_payment",
            {
                "client_id": cliente.id,
                "payment_id": payment_id,
                "payment_status": payment_status,
                "is_active": cliente.is_active,
                "external_reference": external_reference,
            },
        )
        db.commit()
        print(f"[COBRANZA] Cliente={cliente.name} payment_id={payment_id} status={payment_status} is_active={cliente.is_active}")
    except Exception as exc:
        db.rollback()
        print(f"[ERROR] Falló procesamiento de webhook MP {payment_id}: {exc}")
        # Intento de registrar el error en una nueva sesión lógica de esta misma request.
        audit = PaymentWebhookEvent(
            event_type=event_type,
            action=action,
            mp_resource_id=payment_id,
            external_reference=external_reference,
            payment_status=payment_status,
            processed_ok=False,
            error_message=f"Error interno al actualizar cliente: {exc}",
            raw_payload=_json_dumps(payload),
            mp_response=response.text[:20000],
            source_ip=source_ip,
            user_agent=user_agent,
            created_at=datetime.utcnow(),
            processed_at=datetime.utcnow(),
        )
        db.add(audit)
        db.commit()

    return {"status": "ok"}

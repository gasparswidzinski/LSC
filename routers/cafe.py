import json
import os
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker


router = APIRouter()


# --- CONFIGURACIÓN DB AISLADA PARA LSC_CAFE ---
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL no configurada para LSC_Cafe.")


engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


# --- MODELO DB LSC_CAFE ---
class CafeDevice(Base):
    """
    Dispositivo monitoreado por LSC_Cafe.

    Tabla aislada del LSC original.
    No modifica clients, events ni agent_monitor_state.
    """

    __tablename__ = "cafe_devices"

    __table_args__ = (
        UniqueConstraint("branch_id", "device_id", name="uq_cafe_branch_device"),
    )

    id = Column(Integer, primary_key=True, index=True)

    # Identidad comercial / operativa
    client_name = Column(String, index=True, nullable=False)
    branch_name = Column(String, index=True, nullable=False)
    branch_id = Column(String, index=True, nullable=False)

    # Identidad del equipo
    device_id = Column(String, index=True, nullable=False)
    device_alias = Column(String, nullable=False)
    device_role = Column(String, nullable=False)
    hostname = Column(String, index=True, nullable=False)

    # Datos operativos
    api_key = Column(String, index=True, nullable=False)
    technician_name = Column(String, nullable=True)
    telegram_group_name = Column(String, nullable=True)
    agent_version = Column(String, nullable=True)
    status = Column(String, nullable=True, default="online")

    # Heartbeat
    last_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    agent_timestamp_utc = Column(String, nullable=True)

    # Auditoría mínima
    raw_payload = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)

class CafeAlert(Base):
    """
    Alerta registrada por LSC_Cafe.

    Tabla aislada del LSC original.
    No modifica events ni el flujo /v1/ingest.
    """

    __tablename__ = "cafe_alerts"

    id = Column(Integer, primary_key=True, index=True)

    # Identidad comercial / operativa
    client_name = Column(String, index=True, nullable=False)
    branch_name = Column(String, index=True, nullable=False)
    branch_id = Column(String, index=True, nullable=False)

    # Identidad del equipo
    device_id = Column(String, index=True, nullable=False)
    device_alias = Column(String, nullable=False)
    device_role = Column(String, nullable=False)
    hostname = Column(String, index=True, nullable=False)

    # Datos operativos
    api_key = Column(String, index=True, nullable=False)
    technician_name = Column(String, nullable=True)
    telegram_group_name = Column(String, nullable=True)
    agent_version = Column(String, nullable=True)

    # Alerta
    severity = Column(String, index=True, nullable=False)
    event_type = Column(String, index=True, nullable=False)
    event_title = Column(String, nullable=False)
    event_description = Column(Text, nullable=True)
    suggested_action = Column(Text, nullable=True)
    detected_at_utc = Column(String, nullable=True)

    # Estado interno
    status = Column(String, nullable=False, default="received")

    # Auditoría
    raw_payload = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)


# --- PAYLOADS ---
class CafeHeartbeatPayload(BaseModel):
    product_variant: str = Field(..., examples=["LSC_CAFE"])
    api_key: str

    client_name: str
    branch_name: str
    branch_id: str

    device_id: str
    device_alias: str
    device_role: str
    hostname: str

    technician_name: Optional[str] = None
    telegram_group_name: Optional[str] = None

    agent_version: str
    status: str
    timestamp_utc: str

class CafeAlertPayload(BaseModel):
    product_variant: str = Field(..., examples=["LSC_CAFE"])
    api_key: str

    client_name: str
    branch_name: str
    branch_id: str

    device_id: str
    device_alias: str
    device_role: str
    hostname: str

    technician_name: Optional[str] = None
    telegram_group_name: Optional[str] = None
    agent_version: Optional[str] = None

    severity: str
    event_type: str
    event_title: str
    event_description: Optional[str] = None
    detected_at_utc: str
    suggested_action: Optional[str] = None

# --- HELPERS ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def payload_to_dict(payload: BaseModel) -> Dict[str, Any]:
    """
    Compatible con Pydantic v1 y v2.
    """
    if hasattr(payload, "model_dump"):
        return payload.model_dump()
    return payload.dict()


def _utc_now() -> datetime:
    return datetime.utcnow()


def _mask_api_key(api_key: str) -> str:
    """
    Evita devolver la API Key completa en respuestas/logs.
    """
    if not api_key:
        return ""
    if len(api_key) <= 8:
        return "***"
    return f"{api_key[:4]}...{api_key[-4:]}"


def _validate_cafe_payload(payload: CafeHeartbeatPayload) -> None:
    if payload.product_variant != "LSC_CAFE":
        raise HTTPException(
            status_code=400,
            detail="product_variant inválido. Se esperaba LSC_CAFE.",
        )

    if not payload.branch_id.strip():
        raise HTTPException(status_code=400, detail="branch_id es obligatorio.")

    if not payload.device_id.strip():
        raise HTTPException(status_code=400, detail="device_id es obligatorio.")

    if not payload.api_key.strip():
        raise HTTPException(status_code=403, detail="api_key es obligatoria.")

def _validate_cafe_alert_payload(payload: CafeAlertPayload) -> None:
    if payload.product_variant != "LSC_CAFE":
        raise HTTPException(
            status_code=400,
            detail="product_variant inválido. Se esperaba LSC_CAFE.",
        )

    if not payload.branch_id.strip():
        raise HTTPException(status_code=400, detail="branch_id es obligatorio.")

    if not payload.device_id.strip():
        raise HTTPException(status_code=400, detail="device_id es obligatorio.")

    if not payload.api_key.strip():
        raise HTTPException(status_code=403, detail="api_key es obligatoria.")

    allowed_severities = {"info", "warning", "critical"}

    if payload.severity not in allowed_severities:
        raise HTTPException(
            status_code=400,
            detail="severity inválida. Valores permitidos: info, warning, critical.",
        )


# --- ENDPOINTS ---
@router.post("/heartbeat")
def cafe_heartbeat(
    payload: CafeHeartbeatPayload,
    db: Session = Depends(get_db),
):
    """
    Heartbeat LSC_Cafe v0.1.

    Esta versión:
    - recibe heartbeat del agente Cafe;
    - valida product_variant;
    - guarda/actualiza el equipo por branch_id + device_id;
    - no modifica tablas del LSC original;
    - no envía Telegram todavía.
    """

    _validate_cafe_payload(payload)

    now = _utc_now()
    data = payload_to_dict(payload)

    try:
        device = (
            db.query(CafeDevice)
            .filter(
                CafeDevice.branch_id == payload.branch_id,
                CafeDevice.device_id == payload.device_id,
            )
            .first()
        )

        if device:
            db_action = "updated"

            device.client_name = payload.client_name
            device.branch_name = payload.branch_name
            device.device_alias = payload.device_alias
            device.device_role = payload.device_role
            device.hostname = payload.hostname
            device.api_key = payload.api_key
            device.technician_name = payload.technician_name
            device.telegram_group_name = payload.telegram_group_name
            device.agent_version = payload.agent_version
            device.status = payload.status
            device.last_seen_at = now
            device.agent_timestamp_utc = payload.timestamp_utc
            device.raw_payload = json.dumps(data, ensure_ascii=False, default=str)
            device.updated_at = now

        else:
            db_action = "created"

            device = CafeDevice(
                client_name=payload.client_name,
                branch_name=payload.branch_name,
                branch_id=payload.branch_id,
                device_id=payload.device_id,
                device_alias=payload.device_alias,
                device_role=payload.device_role,
                hostname=payload.hostname,
                api_key=payload.api_key,
                technician_name=payload.technician_name,
                telegram_group_name=payload.telegram_group_name,
                agent_version=payload.agent_version,
                status=payload.status,
                last_seen_at=now,
                agent_timestamp_utc=payload.timestamp_utc,
                raw_payload=json.dumps(data, ensure_ascii=False, default=str),
                created_at=now,
                updated_at=now,
            )
            db.add(device)

        db.commit()
        db.refresh(device)

    except Exception as exc:
        db.rollback()
        print(f"[LSC_Cafe] Error guardando heartbeat: {exc}")
        raise HTTPException(
            status_code=500,
            detail="Error interno guardando heartbeat LSC_Cafe.",
        )

    print(
        "[LSC_Cafe] Heartbeat guardado | "
        f"cliente={payload.client_name} | "
        f"sucursal={payload.branch_name} | "
        f"equipo={payload.device_alias} | "
        f"device_id={payload.device_id} | "
        f"action={db_action}"
    )

    return {
        "ok": True,
        "message": "Heartbeat LSC_Cafe recibido y persistido correctamente.",
        "db_action": db_action,
        "product_variant": payload.product_variant,
        "client_name": payload.client_name,
        "branch_name": payload.branch_name,
        "branch_id": payload.branch_id,
        "device_id": payload.device_id,
        "device_alias": payload.device_alias,
        "device_role": payload.device_role,
        "hostname": payload.hostname,
        "agent_version": payload.agent_version,
        "status": payload.status,
        "api_key_masked": _mask_api_key(payload.api_key),
        "last_seen_at_utc": device.last_seen_at.isoformat() + "Z",
    }

@router.post("/alert")
def cafe_alert(
    payload: CafeAlertPayload,
    db: Session = Depends(get_db),
):
    """
    Alerta LSC_Cafe v0.1.

    Esta versión:
    - recibe una alerta del agente Cafe;
    - valida product_variant y severidad;
    - guarda la alerta en cafe_alerts;
    - no modifica tablas del LSC original;
    - no envía Telegram todavía.
    """

    _validate_cafe_alert_payload(payload)

    now = _utc_now()
    data = payload_to_dict(payload)

    try:
        alert = CafeAlert(
            client_name=payload.client_name,
            branch_name=payload.branch_name,
            branch_id=payload.branch_id,
            device_id=payload.device_id,
            device_alias=payload.device_alias,
            device_role=payload.device_role,
            hostname=payload.hostname,
            api_key=payload.api_key,
            technician_name=payload.technician_name,
            telegram_group_name=payload.telegram_group_name,
            agent_version=payload.agent_version,
            severity=payload.severity,
            event_type=payload.event_type,
            event_title=payload.event_title,
            event_description=payload.event_description,
            suggested_action=payload.suggested_action,
            detected_at_utc=payload.detected_at_utc,
            status="received",
            raw_payload=json.dumps(data, ensure_ascii=False, default=str),
            created_at=now,
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

    except Exception as exc:
        db.rollback()
        print(f"[LSC_Cafe] Error guardando alerta: {exc}")
        raise HTTPException(
            status_code=500,
            detail="Error interno guardando alerta LSC_Cafe.",
        )

    print(
        "[LSC_Cafe] Alerta guardada | "
        f"cliente={payload.client_name} | "
        f"sucursal={payload.branch_name} | "
        f"equipo={payload.device_alias} | "
        f"severity={payload.severity} | "
        f"event_type={payload.event_type}"
    )

    return {
        "ok": True,
        "message": "Alerta LSC_Cafe recibida y persistida correctamente.",
        "alert_id": alert.id,
        "product_variant": payload.product_variant,
        "client_name": payload.client_name,
        "branch_name": payload.branch_name,
        "branch_id": payload.branch_id,
        "device_id": payload.device_id,
        "device_alias": payload.device_alias,
        "device_role": payload.device_role,
        "hostname": payload.hostname,
        "severity": payload.severity,
        "event_type": payload.event_type,
        "event_title": payload.event_title,
        "status": alert.status,
        "created_at_utc": alert.created_at.isoformat() + "Z",
    }
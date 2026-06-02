from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


router = APIRouter()


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


def payload_to_dict(payload: BaseModel) -> dict:
    """
    Compatible con Pydantic v1 y v2.
    """
    if hasattr(payload, "model_dump"):
        return payload.model_dump()
    return payload.dict()


@router.post("/heartbeat")
def cafe_heartbeat(payload: CafeHeartbeatPayload):
    """
    Endpoint mínimo de prueba para LSC_Cafe.

    Esta primera versión:
    - recibe heartbeat del agente Cafe;
    - valida que sea product_variant LSC_CAFE;
    - devuelve 200 OK;
    - no guarda todavía en base de datos;
    - no envía Telegram todavía.
    """

    if payload.product_variant != "LSC_CAFE":
        raise HTTPException(
            status_code=400,
            detail="product_variant inválido. Se esperaba LSC_CAFE."
        )

    received_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    print("Heartbeat LSC_Cafe recibido:")
    print(payload_to_dict(payload))

    return {
        "ok": True,
        "message": "Heartbeat LSC_Cafe recibido correctamente.",
        "product_variant": payload.product_variant,
        "client_name": payload.client_name,
        "branch_name": payload.branch_name,
        "branch_id": payload.branch_id,
        "device_id": payload.device_id,
        "device_alias": payload.device_alias,
        "device_role": payload.device_role,
        "hostname": payload.hostname,
        "received_at_utc": received_at,
    }
# protocols.py
"""
Protocolos de respuesta LSC.

Este archivo centraliza el copy técnico-comercial de las alertas.
Regla de producto: LSC monitorea y notifica. No bloquea, no remedia y no modifica
configuración del servidor.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional


EVENT_IDS = {"4625", "1116", "1117", "4720", "1102"}

STANDARD_NOTE = (
    "LSC solo monitoreó y notificó este evento. "
    "No modificó usuarios, archivos, firewall ni configuración del servidor."
)

RESPONSE_PROTOCOLS: Dict[str, Dict[str, Any]] = {
    "4625": {
        "title": "🟨 LSC | ALERTA MEDIA: INICIO DE SESIÓN FALLIDO",
        "urgency": "MEDIA",
        "what_detected": (
            "Windows registró un intento fallido de inicio de sesión. "
            "Un evento aislado puede deberse a una contraseña mal ingresada, "
            "un servicio mal configurado o un intento no autorizado."
        ),
        "action_steps": [
            "Verifique si el intento corresponde a un usuario legítimo.",
            "Si el evento se repite varias veces, contacte a su técnico de confianza.",
            "Revise si el servidor tiene Escritorio Remoto/RDP expuesto a Internet.",
            "No reinicie el equipo ni borre evidencia antes de la revisión técnica.",
        ],
        "technical_detail": "Evento Windows ID 4625: error de inicio de sesión.",
        "note": (
            "LSC solo monitoreó y notificó este evento. "
            "No bloqueó usuarios, IPs ni modificó reglas de firewall."
        ),
    },
    "4625_BURST": {
        "title": "🟥 LSC | ALERTA CRÍTICA: MÚLTIPLES INTENTOS FALLIDOS DE ACCESO",
        "urgency": "CRÍTICA",
        "what_detected": (
            "Se detectaron múltiples intentos fallidos de inicio de sesión en un período corto. "
            "Esta actividad puede ser compatible con fuerza bruta o intento de acceso no autorizado."
        ),
        "action_steps": [
            "Contacte de inmediato a su técnico de confianza.",
            "Verifique si el servidor tiene Escritorio Remoto/RDP expuesto a Internet.",
            "Revise usuario objetivo, IP de origen y horario de los intentos.",
            "Si el acceso no es esperado, evalúe aislar temporalmente el equipo o restringir RDP.",
        ],
        "technical_detail": "Evento Windows ID 4625: múltiples errores de inicio de sesión detectados.",
        "note": (
            "LSC solo monitoreó y notificó este evento. "
            "No bloqueó IPs, usuarios ni modificó el firewall."
        ),
    },
    "1116": {
        "title": "🟥 LSC | ALERTA CRÍTICA: AMENAZA DETECTADA POR MICROSOFT DEFENDER",
        "urgency": "CRÍTICA",
        "what_detected": (
            "Microsoft Defender informó la detección de software potencialmente malicioso "
            "o no deseado en este equipo."
        ),
        "action_steps": [
            "Contacte de inmediato a su técnico de confianza.",
            "Si el equipo no presta un servicio crítico en este momento, aíslelo temporalmente de la red.",
            "Ejecute o solicite un análisis completo con Microsoft Defender.",
            "No borre archivos ni reinicie el equipo sin indicación técnica.",
        ],
        "technical_detail": (
            "Evento Windows ID 1116: Microsoft Defender Antivirus detectó malware "
            "u otro software potencialmente no deseado."
        ),
        "note": (
            "LSC solo monitoreó y notificó este evento. "
            "No eliminó archivos ni modificó la configuración del servidor."
        ),
    },
    "1117": {
        "title": "🟧 LSC | ALERTA ALTA: MICROSOFT DEFENDER TOMÓ ACCIÓN SOBRE UNA AMENAZA",
        "urgency": "ALTA",
        "what_detected": (
            "Microsoft Defender informó que tomó medidas frente a una amenaza detectada previamente. "
            "Esto no necesariamente significa que el incidente esté completamente cerrado."
        ),
        "action_steps": [
            "Revise el historial de protección de Microsoft Defender.",
            "Ejecute o solicite un análisis completo del equipo.",
            "Verifique si hubo nuevos accesos, usuarios creados o eventos sospechosos.",
            "Mantenga precaución con correos, adjuntos y archivos compartidos.",
        ],
        "technical_detail": (
            "Evento Windows ID 1117: Microsoft Defender Antivirus tomó medidas "
            "frente a malware u otro software potencialmente no deseado."
        ),
        "note": (
            "LSC solo monitoreó y notificó este evento. "
            "La acción fue realizada por Microsoft Defender, no por LSC."
        ),
    },
    "4720": {
        "title": "🟧 LSC | ALERTA ALTA: NUEVA CUENTA DE USUARIO CREADA",
        "urgency": "ALTA",
        "what_detected": "Se registró la creación de una nueva cuenta de usuario en el sistema.",
        "action_steps": [
            "Verifique si su técnico o administrador creó esta cuenta.",
            "Si el cambio no fue autorizado, contacte soporte técnico de inmediato.",
            "Revise permisos, grupos de administrador y accesos recientes.",
            "No elimine evidencia antes de que el técnico revise el evento.",
        ],
        "technical_detail": "Evento Windows ID 4720: se creó una cuenta de usuario en Windows.",
        "note": (
            "LSC solo monitoreó y notificó este evento. "
            "No creó, modificó ni eliminó usuarios."
        ),
    },
    "1102": {
        "title": "🟥 LSC | ALERTA CRÍTICA: REGISTRO DE SEGURIDAD ELIMINADO",
        "urgency": "CRÍTICA",
        "what_detected": (
            "Windows informó que el registro de auditoría de seguridad fue eliminado. "
            "Esta acción puede dificultar la investigación de accesos o cambios recientes."
        ),
        "action_steps": [
            "Contacte de inmediato a su técnico de confianza.",
            "Verifique qué usuario realizó la acción y desde qué cuenta.",
            "No reinicie el servidor ni borre archivos antes de la revisión técnica.",
            "Si el cambio no fue autorizado, trate el equipo como potencialmente comprometido.",
        ],
        "technical_detail": "Evento Windows ID 1102: el registro de auditoría de seguridad fue borrado.",
        "note": STANDARD_NOTE,
    },
    "DEFAULT": {
        "title": "🔎 LSC | AVISO: EVENTO DE SEGURIDAD DETECTADO",
        "urgency": "INFORMATIVA",
        "what_detected": "LSC detectó un evento de seguridad relevante en los registros del sistema.",
        "action_steps": [
            "Revise el evento con su técnico de confianza.",
            "Conserve la evidencia y evite reiniciar el equipo si sospecha un incidente.",
        ],
        "technical_detail": "Evento Windows: actividad de seguridad registrada.",
        "note": STANDARD_NOTE,
    },
}


def compact_text(value: Optional[str], max_len: int = 900) -> str:
    """Normaliza saltos de línea/espacios y limita longitud para Telegram."""
    if not value:
        return "Sin detalle técnico adicional."
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if len(text) > max_len:
        return text[: max_len - 3].rstrip() + "..."
    return text


def extract_event_id(value: Any) -> Optional[str]:
    """Extrae un Event ID conocido desde int/string/dict/modelo Pydantic."""
    if value is None:
        return None

    if isinstance(value, dict):
        direct = value.get("event_id") or value.get("Id") or value.get("id")
        if direct:
            return extract_event_id(direct)
        value = value.get("message") or value.get("raw_message") or ""

    if not isinstance(value, str):
        value = str(value)

    value = value.strip()
    if value in EVENT_IDS:
        return value

    patterns = [
        r"\bID\s*(4625|1116|1117|4720|1102)\b",
        r"\bEvent\s*ID\s*(4625|1116|1117|4720|1102)\b",
        r"\b(4625|1116|1117|4720|1102)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, value, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def get_protocol_by_id(event_id: Optional[Any]) -> Dict[str, Any]:
    event_key = extract_event_id(event_id)
    if event_key and event_key in RESPONSE_PROTOCOLS:
        return RESPONSE_PROTOCOLS[event_key]
    return RESPONSE_PROTOCOLS["DEFAULT"]


def get_protocol(event_message: str) -> Dict[str, Any]:
    """
    Compatibilidad con el backend anterior: recibe un mensaje y devuelve el protocolo.
    """
    return get_protocol_by_id(event_message)


def _entry_get(entry: Any, key: str, default: Any = None) -> Any:
    if isinstance(entry, dict):
        return entry.get(key, default)
    return getattr(entry, key, default)


def format_alert(entry: Any, client_name: str) -> str:
    """
    Construye una alerta profesional para Telegram.
    Acepta dict, Pydantic model o cualquier objeto con atributos equivalentes.
    """
    event_id = extract_event_id(_entry_get(entry, "event_id") or _entry_get(entry, "message") or _entry_get(entry, "raw_message"))
    protocol = get_protocol_by_id(event_id)

    hostname = _entry_get(entry, "hostname") or "No informado"
    event_time = _entry_get(entry, "event_time") or _entry_get(entry, "timestamp") or "No informado"
    source = _entry_get(entry, "source") or _entry_get(entry, "log_name") or "Windows Event Log"
    raw_message = _entry_get(entry, "raw_message") or _entry_get(entry, "message") or ""
    record_id = _entry_get(entry, "record_id")

    steps = "\n".join(f"{idx}. {step}" for idx, step in enumerate(protocol["action_steps"], start=1))
    detail_lines = [protocol["technical_detail"]]
    if record_id:
        detail_lines.append(f"Record ID: {record_id}")
    detail_lines.append(f"Origen: {source}")
    detail_lines.append(compact_text(raw_message, max_len=750))

    return (
        f"{protocol['title']}\n\n"
        f"🏢 Empresa: {client_name}\n"
        f"🖥️ Equipo: {hostname}\n"
        f"🕒 Hora del evento: {event_time}\n"
        f"⚡ Prioridad: {protocol['urgency']}\n\n"
        f"📌 Qué detectó LSC:\n"
        f"{protocol['what_detected']}\n\n"
        f"🛠️ Acción recomendada:\n"
        f"{steps}\n\n"
        f"🔎 Detalle técnico:\n"
        f"{' '.join(detail_lines)}\n\n"
        f"ℹ️ Nota:\n"
        f"{protocol['note']}"
    )

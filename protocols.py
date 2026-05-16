# protocols.py
"""
Protocolos de respuesta LSC.

Sprint 4:
- Mantiene alertas profesionales.
- Agrega soporte para agrupación inteligente de Event ID 4625.
- Distingue:
  - 4625 local/aislado = MEDIA
  - 4625 red/RDP = ALTA
  - 5+ intentos en 2 minutos = ALTA agregada
  - 15+ intentos en 5 minutos = CRÍTICA agregada
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


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
            "Si el evento se repite o no reconoce el intento de acceso, contacte a su técnico de confianza.",
            "Revise servicios o credenciales guardadas que puedan estar fallando.",
            "No reinicie el equipo ni borre evidencia antes de la revisión técnica.",
        ],
        "technical_detail": "Evento Windows ID 4625: error de inicio de sesión.",
        "note": (
            "LSC solo monitoreó y notificó este evento. "
            "No bloqueó usuarios, IPs ni modificó reglas de firewall."
        ),
    },
    "4625_NETWORK": {
        "title": "🟧 LSC | ALERTA ALTA: INICIO DE SESIÓN FALLIDO DESDE RED",
        "urgency": "ALTA",
        "what_detected": (
            "Windows registró un intento fallido de inicio de sesión con origen de red. "
            "Esto puede deberse a un acceso legítimo fallido, credenciales guardadas incorrectas "
            "o un intento no autorizado contra el servidor."
        ),
        "action_steps": [
            "Verifique si el acceso corresponde a un usuario o técnico autorizado.",
            "Revise si el servidor tiene Escritorio Remoto/RDP expuesto a Internet.",
            "Controle usuario objetivo, IP de origen y horario del intento.",
            "Si el acceso no es esperado, contacte a su técnico de confianza.",
        ],
        "technical_detail": "Evento Windows ID 4625: error de inicio de sesión con origen de red.",
        "note": (
            "LSC solo monitoreó y notificó este evento. "
            "No bloqueó usuarios, IPs ni modificó reglas de firewall."
        ),
    },
    "4625_BURST_HIGH": {
        "title": "🟧 LSC | ALERTA ALTA: MÚLTIPLES INTENTOS FALLIDOS DE ACCESO",
        "urgency": "ALTA",
        "what_detected": (
            "Se detectaron varios intentos fallidos de inicio de sesión en un período corto. "
            "Esta actividad requiere revisión técnica, especialmente si el origen o la cuenta objetivo "
            "no son reconocidos."
        ),
        "action_steps": [
            "Verifique si los intentos corresponden a un usuario o técnico autorizado.",
            "Revise usuario objetivo, IP de origen y horario de los intentos.",
            "Controle si el servidor tiene Escritorio Remoto/RDP expuesto a Internet.",
            "Si el acceso no es esperado, contacte a su técnico de confianza.",
        ],
        "technical_detail": "Evento Windows ID 4625: múltiples errores de inicio de sesión detectados.",
        "note": (
            "LSC solo monitoreó y notificó estos eventos. "
            "No bloqueó IPs, usuarios ni modificó el firewall."
        ),
    },
    "4625_BURST": {
        "title": "🟥 LSC | ALERTA CRÍTICA: POSIBLE FUERZA BRUTA O ACCESO NO AUTORIZADO",
        "urgency": "CRÍTICA",
        "what_detected": (
            "Se detectó un volumen elevado de intentos fallidos de inicio de sesión en un período corto. "
            "Esta actividad es compatible con fuerza bruta o intento de acceso no autorizado."
        ),
        "action_steps": [
            "Contacte de inmediato a su técnico de confianza.",
            "Verifique si el servidor tiene Escritorio Remoto/RDP expuesto a Internet.",
            "Revise usuario objetivo, IP de origen y horario de los intentos.",
            "Si el acceso no es esperado, evalúe aislar temporalmente el equipo o restringir RDP.",
        ],
        "technical_detail": "Evento Windows ID 4625: volumen elevado de errores de inicio de sesión.",
        "note": (
            "LSC solo monitoreó y notificó estos eventos. "
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


def repair_mojibake(value: Optional[str]) -> str:
    if value is None:
        return ""

    text = str(value)

    replacements = {
        "sesi¢n": "sesión",
        "Sesi¢n": "Sesión",
        "informaci¢n": "información",
        "Informaci¢n": "Información",
        "autenticaci¢n": "autenticación",
        "Autenticaci¢n": "Autenticación",
        "contrase¤a": "contraseña",
        "Contrase¤a": "Contraseña",
        "acci¢n": "acción",
        "Acci¢n": "Acción",
        "creaci¢n": "creación",
        "Creaci¢n": "Creación",
        "m quina": "máquina",
        "M quina": "Máquina",
        "direcci¢n": "dirección",
        "Direcci¢n": "Dirección",
        "t‚cnico": "técnico",
        "T‚cnico": "Técnico",
        "cr¡tico": "crítico",
        "Cr¡tico": "Crítico",
    }

    for bad, good in replacements.items():
        text = text.replace(bad, good)

    return text


def compact_text(value: Optional[str], max_len: int = 450) -> str:
    text = repair_mojibake(value)
    if not text:
        return "Sin detalle técnico adicional."
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if len(text) > max_len:
        return text[: max_len - 3].rstrip() + "..."
    return text


def extract_event_id(value: Any) -> Optional[str]:
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


def _entry_get(entry: Any, key: str, default: Any = None) -> Any:
    if isinstance(entry, dict):
        return entry.get(key, default)
    return getattr(entry, key, default)


def _find_first(patterns: List[str], text: str) -> Optional[str]:
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def _all_account_names(text: str) -> List[str]:
    return re.findall(r"(?:Nombre de cuenta|Account Name)\s*:\s*([^\s]+)", text, flags=re.IGNORECASE)


def _logon_type_description(logon_type: Optional[str]) -> str:
    mapping = {
        "2": "interactivo/local",
        "3": "red",
        "4": "batch",
        "5": "servicio",
        "7": "desbloqueo",
        "8": "red con texto claro",
        "9": "nuevas credenciales",
        "10": "RDP/escritorio remoto",
        "11": "credenciales cacheadas",
    }
    if not logon_type:
        return "no informado"
    return mapping.get(str(logon_type), "tipo no clasificado")


def _is_local_source_ip(source_ip: Optional[str]) -> bool:
    if not source_ip:
        return True
    ip = source_ip.strip().lower()
    return ip in {"-", "::1", "127.0.0.1", "localhost", "0.0.0.0"}


def _parse_4625(raw_message: str) -> Dict[str, Optional[str]]:
    text = compact_text(raw_message, max_len=5000)

    accounts = _all_account_names(text)
    target_user = accounts[1] if len(accounts) > 1 else (accounts[0] if accounts else None)
    subject_user = accounts[0] if accounts else None

    return {
        "logon_type": _find_first(
            [
                r"(?:Tipo de inicio de sesi[oó]n|Tipo de inicio de sesi.n|Logon Type)\s*:\s*([0-9]+)",
            ],
            text,
        ),
        "target_user": target_user,
        "subject_user": subject_user,
        "source_ip": _find_first(
            [
                r"(?:Direcci[oó]n de red de origen|Direcci.n de red de origen|Source Network Address)\s*:\s*([^\s]+)",
            ],
            text,
        ),
        "source_port": _find_first(
            [
                r"(?:Puerto de origen|Source Port)\s*:\s*([^\s]+)",
            ],
            text,
        ),
        "process": _find_first(
            [
                r"(?:Nombre de proceso del autor de la llamada|Caller Process Name)\s*:\s*([^\s]+)",
                r"(?:Nombre de proceso|Process Name)\s*:\s*([^\s]+)",
            ],
            text,
        ),
    }


def _parse_4720(raw_message: str) -> Dict[str, Optional[str]]:
    text = compact_text(raw_message, max_len=5000)
    accounts = _all_account_names(text)

    created_user = _find_first(
        [
            r"(?:Cuenta nueva|New Account).*?(?:Nombre de cuenta|Account Name)\s*:\s*([^\s]+)",
        ],
        text,
    )

    return {
        "created_user": created_user or (accounts[-1] if accounts else None),
        "actor_user": accounts[0] if accounts else None,
    }


def _parse_1102(raw_message: str) -> Dict[str, Optional[str]]:
    text = compact_text(raw_message, max_len=5000)
    accounts = _all_account_names(text)

    return {
        "actor_user": accounts[0] if accounts else None,
    }


def _extract_labeled_value(text: str, labels: List[str]) -> Optional[str]:
    normalized = compact_text(text, max_len=5000)
    label_pattern = "|".join(re.escape(label) for label in labels)
    stop_labels = [
        "Nombre", "Name", "Amenaza", "Threat", "Id", "ID", "Severidad", "Severity",
        "Categoría", "Category", "Ruta", "Path", "Archivo", "File", "Acción", "Action",
        "Estado", "Status", "Usuario", "User", "Proceso", "Process",
    ]
    stop_pattern = "|".join(re.escape(label) for label in stop_labels)

    match = re.search(
        rf"(?:{label_pattern})\s*:\s*(.*?)(?=\s+(?:{stop_pattern})\s*:|$)",
        normalized,
        flags=re.IGNORECASE,
    )
    if not match:
        return None

    value = match.group(1).strip()
    return value if value else None


def _build_4625_protocol(base_key: str, parsed: Dict[str, Optional[str]]) -> Dict[str, Any]:
    if base_key in {"4625_BURST", "4625_BURST_HIGH"}:
        return RESPONSE_PROTOCOLS[base_key]

    logon_type = parsed.get("logon_type")
    source_ip = parsed.get("source_ip")

    if (source_ip and not _is_local_source_ip(source_ip)) or logon_type in {"3", "10"}:
        return RESPONSE_PROTOCOLS["4625_NETWORK"]

    return RESPONSE_PROTOCOLS["4625"]


def _select_protocol(event_id: Optional[str], entry: Any, raw_message: str) -> Dict[str, Any]:
    protocol_key = _entry_get(entry, "protocol_key")
    if protocol_key and protocol_key in RESPONSE_PROTOCOLS:
        return RESPONSE_PROTOCOLS[protocol_key]

    if event_id == "4625":
        parsed = _parse_4625(raw_message)
        return _build_4625_protocol("4625", parsed)

    if event_id and event_id in RESPONSE_PROTOCOLS:
        return RESPONSE_PROTOCOLS[event_id]

    return RESPONSE_PROTOCOLS["DEFAULT"]


def get_protocol_by_id(event_id: Optional[Any]) -> Dict[str, Any]:
    event_key = extract_event_id(event_id)
    if event_key and event_key in RESPONSE_PROTOCOLS:
        return RESPONSE_PROTOCOLS[event_key]
    return RESPONSE_PROTOCOLS["DEFAULT"]


def get_protocol(event_message: str) -> Dict[str, Any]:
    return get_protocol_by_id(event_message)


def _format_count_line(entry: Any) -> Optional[str]:
    count = _entry_get(entry, "failed_login_count")
    if not count:
        return None

    window_seconds = _entry_get(entry, "window_seconds")
    if window_seconds:
        minutes = round(float(window_seconds) / 60, 1)
        if minutes.is_integer():
            minutes_text = f"{int(minutes)} minuto(s)"
        else:
            minutes_text = f"{minutes} minuto(s)"
        return f"Intentos detectados: {count} en {minutes_text}"

    return f"Intentos detectados: {count}"


def _build_technical_summary(event_id: Optional[str], entry: Any, raw_message: str, protocol: Dict[str, Any]) -> List[str]:
    source = _entry_get(entry, "source") or _entry_get(entry, "log_name") or "Windows Event Log"
    record_id = _entry_get(entry, "record_id")
    protocol_key = _entry_get(entry, "protocol_key")

    lines: List[str] = [protocol["technical_detail"]]

    count_line = _format_count_line(entry)
    if count_line:
        lines.append(count_line)

    if _entry_get(entry, "first_event_time"):
        lines.append(f"Primer evento: {_entry_get(entry, 'first_event_time')}")
    if _entry_get(entry, "last_event_time"):
        lines.append(f"Último evento: {_entry_get(entry, 'last_event_time')}")

    if record_id and not protocol_key:
        lines.append(f"Record ID: {record_id}")

    if event_id == "4625":
        if protocol_key in {"4625_BURST", "4625_BURST_HIGH"}:
            logon_type = _entry_get(entry, "logon_type")
            target_user = _entry_get(entry, "target_user")
            source_ip = _entry_get(entry, "source_ip")
            record_ids = _entry_get(entry, "record_ids")

            if logon_type:
                lines.append(f"Tipo de inicio de sesión: {logon_type} ({_logon_type_description(str(logon_type))})")
            if target_user:
                lines.append(f"Cuenta objetivo: {target_user}")
            if source_ip:
                lines.append(f"Origen/IP: {source_ip}")
            if isinstance(record_ids, list) and record_ids:
                sample = ", ".join(str(x) for x in record_ids[:8])
                if len(record_ids) > 8:
                    sample += ", ..."
                lines.append(f"Record IDs: {sample}")

            return lines

        parsed = _parse_4625(raw_message)

        logon_type = parsed.get("logon_type")
        if logon_type:
            lines.append(f"Tipo de inicio de sesión: {logon_type} ({_logon_type_description(logon_type)})")

        target = parsed.get("target_user") or _entry_get(entry, "target_user")
        if target:
            lines.append(f"Cuenta objetivo: {target if target != '-' else 'no informada'}")

        source_ip = parsed.get("source_ip") or _entry_get(entry, "source_ip")
        if source_ip:
            lines.append(f"Origen/IP: {source_ip}")

        if parsed.get("source_port") and parsed["source_port"] != "0":
            lines.append(f"Puerto origen: {parsed['source_port']}")

        if parsed.get("process"):
            lines.append(f"Proceso: {parsed['process']}")

        return lines

    if event_id == "4720":
        parsed = _parse_4720(raw_message)
        if parsed.get("created_user"):
            lines.append(f"Cuenta creada: {parsed['created_user']}")
        if parsed.get("actor_user"):
            lines.append(f"Usuario que realizó la acción: {parsed['actor_user']}")
        lines.append(f"Origen: {source}")
        return lines

    if event_id == "1102":
        parsed = _parse_1102(raw_message)
        if parsed.get("actor_user"):
            lines.append(f"Usuario que realizó la acción: {parsed['actor_user']}")
        lines.append(f"Origen: {source}")
        return lines

    if event_id in {"1116", "1117"}:
        threat = _extract_labeled_value(raw_message, ["Amenaza", "Threat", "Nombre", "Name"])
        path = _extract_labeled_value(raw_message, ["Ruta", "Path", "Archivo", "File"])
        action = _extract_labeled_value(raw_message, ["Acción", "Action", "Estado", "Status"])

        if threat:
            lines.append(f"Amenaza/elemento: {compact_text(threat, max_len=160)}")
        if path:
            lines.append(f"Ruta/archivo: {compact_text(path, max_len=180)}")
        if action:
            lines.append(f"Acción/estado informado: {compact_text(action, max_len=160)}")

        lines.append(f"Origen: {source}")

        if len(lines) <= (3 if record_id else 2):
            lines.append(f"Extracto: {compact_text(raw_message, max_len=300)}")

        return lines

    lines.append(f"Origen: {source}")
    lines.append(f"Extracto: {compact_text(raw_message, max_len=300)}")
    return lines


def _custom_what_detected(event_id: Optional[str], entry: Any, protocol: Dict[str, Any]) -> str:
    protocol_key = _entry_get(entry, "protocol_key")
    count = _entry_get(entry, "failed_login_count")

    if event_id == "4625" and count and not protocol_key:
        return (
            f"Windows registró {count} intento(s) fallido(s) de inicio de sesión. "
            "El volumen no alcanzó el umbral de fuerza bruta, pero conviene verificar "
            "si el acceso fue legítimo o esperado."
        )

    return protocol["what_detected"]


def format_alert(entry: Any, client_name: str) -> str:
    raw_message = repair_mojibake(_entry_get(entry, "raw_message") or _entry_get(entry, "message") or "")
    event_id = extract_event_id(_entry_get(entry, "event_id") or _entry_get(entry, "message") or raw_message)
    protocol = _select_protocol(event_id, entry, raw_message)

    hostname = _entry_get(entry, "hostname") or "No informado"
    event_time = _entry_get(entry, "event_time") or _entry_get(entry, "last_event_time") or _entry_get(entry, "timestamp") or "No informado"

    steps = "\n".join(f"{idx}. {step}" for idx, step in enumerate(protocol["action_steps"], start=1))
    detail_lines = _build_technical_summary(event_id, entry, raw_message, protocol)
    technical_block = "\n".join(detail_lines)
    what_detected = _custom_what_detected(event_id, entry, protocol)

    return (
        f"{protocol['title']}\n\n"
        f"🏢 Empresa: {client_name}\n"
        f"🖥️ Equipo: {hostname}\n"
        f"🕒 Hora del evento: {event_time}\n"
        f"⚡ Prioridad: {protocol['urgency']}\n\n"
        f"📌 Qué detectó LSC:\n"
        f"{what_detected}\n\n"
        f"🛠️ Acción recomendada:\n"
        f"{steps}\n\n"
        f"🔎 Detalle técnico:\n"
        f"{technical_block}\n\n"
        f"ℹ️ Nota:\n"
        f"{protocol['note']}"
    )

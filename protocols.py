# protocols.py

RESPONSE_PROTOCOLS = {
    "4625": {
        "title": "🚨 ALERTA: ATAQUE DE FUERZA BRUTA",
        "urgency": "ALTA",
        "action_steps": [
            "1. Alguien está intentando adivinar contraseñas en su servidor.",
            "2. ACCIÓN: Si el servidor no está en uso, desconecte el cable de red (Internet) físicamente.",
            "3. No reinicie el equipo."
        ]
    },
    "1116": {
        "title": "☣️ ALERTA CRÍTICA: VIRUS/MALWARE DETECTADO",
        "urgency": "MÁXIMA",
        "action_steps": [
            "1. El antivirus interceptó software malicioso.",
            "2. ACCIÓN: Aísle el equipo inmediatamente desconectándolo de la red Wi-Fi o cable.",
            "3. Ejecute un escaneo completo de Windows Defender."
        ]
    },
    "1117": {
        "title": "🛡️ AVISO: VIRUS ELIMINADO",
        "urgency": "MEDIA",
        "action_steps": [
            "1. El sistema de seguridad actuó y limpió una amenaza.",
            "2. ACCIÓN: No requiere acción inmediata, pero mantenga precaución al abrir correos nuevos."
        ]
    },
    "4720": {
        "title": "⚠️ ALERTA: NUEVO USUARIO CREADO",
        "urgency": "ALTA",
        "action_steps": [
            "1. Se ha creado una nueva cuenta de acceso en el sistema.",
            "2. ACCIÓN: Verifique si su técnico de confianza realizó este cambio hoy.",
            "3. Si nadie autorizó esto, avise a soporte técnico urgente."
        ]
    },
    "1102": {
        "title": "💀 ALERTA CRÍTICA: SABOTAJE DE SEGURIDAD",
        "urgency": "MÁXIMA",
        "action_steps": [
            "1. ¡ATENCIÓN! Alguien borró el historial de seguridad para ocultar sus huellas.",
            "2. ACCIÓN: Apague el servidor inmediatamente manteniendo presionado el botón de encendido.",
            "3. Este equipo está comprometido."
        ]
    },
    "DEFAULT": {
        "title": "🔎 AVISO DE ACTIVIDAD SOSPECHOSA",
        "urgency": "INFORMATIVA",
        "action_steps": [
            "1. Se detectó actividad inusual en los registros.",
            "2. ACCIÓN: Revise el estado general del servidor en la próxima hora hábil."
        ]
    }
}

def get_protocol(event_message: str):
    """Busca el ID del evento en el mensaje y devuelve el protocolo correspondiente."""
    for event_id, protocol in RESPONSE_PROTOCOLS.items():
        if f"ID {event_id}" in event_message:
            return protocol
    
    # Manejo de casos especiales si los IDs vienen pegados en el texto
    if "4625" in event_message: return RESPONSE_PROTOCOLS["4625"]
    if "1116" in event_message: return RESPONSE_PROTOCOLS["1116"]
    if "1117" in event_message: return RESPONSE_PROTOCOLS["1117"]
    if "4720" in event_message: return RESPONSE_PROTOCOLS["4720"]
    if "1102" in event_message: return RESPONSE_PROTOCOLS["1102"]

    return RESPONSE_PROTOCOLS["DEFAULT"]
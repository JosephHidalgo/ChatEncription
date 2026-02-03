"""
Utilidades de zona horaria para el sistema.
Configura GMT-5 (America/Lima) como zona horaria predeterminada.
"""
from datetime import datetime, timezone, timedelta

# Zona horaria de Perú (GMT-5)
PERU_TZ = timezone(timedelta(hours=-5))


def now() -> datetime:
    """
    Retorna la hora actual en zona horaria de Perú (GMT-5).
    Usar en lugar de datetime.utcnow() para guardar timestamps.
    """
    return datetime.now(PERU_TZ).replace(tzinfo=None)


def now_aware() -> datetime:
    """
    Retorna la hora actual en zona horaria de Perú con información de zona.
    """
    return datetime.now(PERU_TZ)

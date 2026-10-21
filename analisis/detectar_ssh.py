
from collections import Counter
from pathlib import Path
import re
from datetime import datetime

LOG = Path("evidencias/auth.log")
SALIDA = Path("analisis/resultado_detector_v2.txt")
UMBRAL_FALLOS = 3
ANIO = 2026

fallidos = Counter()
exitosos = Counter()
eventos = []

patron = re.compile(
    r"^(?P<fecha>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd\[\d+\]: (?P<detalle>.*)$"
)

patron_auth = re.compile(
    r"^(?P<evento>Failed password|Accepted password) "
    r"for (?P<usuario>.*?) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

patron_sesion = re.compile(
    r"pam_unix\(sshd:session\): session "
    r"(?P<evento>opened|closed) for user (?P<usuario>\S+)"
)

if not LOG.is_file():
    raise SystemExit(f"Error: no se encontró {LOG}")

with LOG.open(encoding="utf-8") as archivo:
    for numero, linea in enumerate(archivo, start=1):
        coincidencia = patron.search(linea)
        if not coincidencia:
            continue

        datos = coincidencia.groupdict()
        fecha = datetime.strptime(
            f"{ANIO} {datos['fecha']}", "%Y %b %d %H:%M:%S"
        )
        detalle = datos["detalle"]

        auth = patron_auth.search(detalle)
        if auth:
            info = auth.groupdict()
            ip = info["ip"]
            evento = info["evento"]
            usuario = info["usuario"]

            if evento == "Failed password":
                fallidos[ip] += 1
            else:
                exitosos[ip] += 1
        else:
            sesion = patron_sesion.search(detalle)
            if not sesion:
                continue

            info = sesion.groupdict()
            ip = "No indicada"
            evento = f"Sesion {info['evento']}"
            usuario = info["usuario"]

        eventos.append({
            "fecha": fecha,
            "ip": ip,
            "usuario": usuario,
            "evento": evento,
            "linea": numero
        })

lineas_salida = [
    "=== DETECTOR SSH - VERSION 2 ===",
    f"Archivo analizado: {LOG}",
    f"Eventos reconocidos: {len(eventos)}",
    "",
    "=== LINEA DE TIEMPO ==="
]

for item in sorted(eventos, key=lambda e: e["fecha"]):
    lineas_salida.append(
        f'{item["fecha"]:%Y-%m-%d %H:%M:%S} | '
        f'{item["ip"]} | {item["usuario"]} | {item["evento"]}'
    )

lineas_salida.append("\n=== RESUMEN POR IP ===")
ips = sorted(set(fallidos) | set(exitosos))

for ip in ips:
    lineas_salida.append(
        f"{ip}: fallidos={fallidos[ip]}, exitosos={exitosos[ip]}"
    )

lineas_salida.append("\n=== ALERTAS ===")
total_alertas = 0

for ip in ips:
    if fallidos[ip] >= UMBRAL_FALLOS:
        lineas_salida.append(
            f"[ALERTA] {ip}: {fallidos[ip]} intentos fallidos"
        )
        total_alertas += 1

    if fallidos[ip] > 0 and exitosos[ip] > 0:
        lineas_salida.append(
            f"[REVISION] {ip}: fallos y acceso exitoso; "
            "investigar si el acceso fue legítimo"
        )
        total_alertas += 1

if total_alertas == 0:
    lineas_salida.append("No se detectaron alertas según los criterios.")

lineas_salida.append(f"\nTotal de alertas: {total_alertas}")
SALIDA.write_text("\n".join(lineas_salida) + "\n", encoding="utf-8")
print("\n".join(lineas_salida))
print(f"\nInforme guardado en: {SALIDA}")


# Proyecto 01 — Análisis de incidente SSH | SOC / DFIR

## Descripción

Proyecto práctico de ciberseguridad orientado a las tareas iniciales de un analista SOC (Security Operations Center), con foco en DFIR (Digital Forensics and Incident Response).

El objetivo es analizar registros de autenticación SSH, identificar comportamientos sospechosos, construir una línea de tiempo y generar alertas mediante un script desarrollado en Python.

**Tipo de laboratorio:** ejercicio controlado con eventos simulados y algunas evidencias obtenidas de una máquina virtual Kali Linux.

## Objetivos

- Analizar eventos de autenticación SSH.
- Identificar intentos fallidos y accesos exitosos.
- Construir una línea de tiempo de los eventos.
- Agrupar eventos por dirección IP.
- Generar alertas ante patrones que requieren investigación.
- Calcular y verificar hashes SHA-256 para comprobar la integridad de archivos.
- Documentar hallazgos, limitaciones y recomendaciones.

## Herramientas utilizadas

- Kali Linux
- Python 3
- Bash
- Git y GitHub
- SHA-256 (`sha256sum`)
- Registros de autenticación SSH simulados

## Estructura del proyecto

- `evidencias/`: registros simulados y archivos de evidencia de la máquina virtual.
- `analisis/detectar_ssh.py`: script de análisis automatizado.
- `analisis/resultado_detector_v2.txt`: resultado generado por el detector.
- `analisis/hallazgos-iniciales.md`: hallazgos preliminares.
- `analisis/informe_incidente.md`: informe del incidente simulado.

## Escenario analizado

El registro simulado contiene varios intentos fallidos de autenticación SSH y un acceso exitoso posterior desde una misma dirección IP.

El detector identifica:

- Cinco intentos fallidos asociados a `203.0.113.45`.
- Una autenticación exitosa asociada a esa misma dirección.
- Una alerta por múltiples fallos de autenticación.
- Una recomendación de investigar si el acceso exitoso fue legítimo.
- Un intento fallido adicional desde `198.51.100.27`.

Estos resultados requieren análisis contextual: los registros, por sí solos, no permiten confirmar que haya ocurrido una intrusión real.

## Cómo ejecutar el detector

Desde la carpeta raíz del proyecto:

```bash
python3 analisis/detectar_ssh.py
```

El script analiza `evidencias/auth.log` y genera el resultado en `analisis/resultado_detector_v2.txt`.

## Verificación de integridad

Para verificar el hash del registro de autenticación:

```bash
sha256sum -c evidencias/auth.log.sha256
```

Para verificar los archivos del detector y su resultado:

```bash
sha256sum -c analisis/hashes_detector_v2.sha256
```

Una verificación correcta indica que el archivo coincide con el contenido usado para calcular el hash de referencia. No demuestra por sí sola la autenticidad de la evidencia ni descarta alteraciones anteriores.

## Hallazgos y respuesta recomendada

Ante una secuencia de fallos seguida de un acceso exitoso, las acciones recomendadas son:

1. Verificar si la cuenta y el acceso estaban autorizados.
2. Correlacionar los eventos con otros registros disponibles.
3. Revisar el uso de privilegios y la actividad de procesos.
4. Si se confirma un acceso no autorizado, aplicar el procedimiento de contención y recuperación correspondiente.
5. Revisar las medidas de protección de SSH, como autenticación multifactor cuando sea viable, restricción de acceso y control de credenciales.

## Limitaciones

- Los registros del incidente son simulados.
- Las direcciones IP utilizadas pertenecen a rangos reservados para documentación y no representan indicadores reales de atacantes.
- La evidencia de procesos de Kali corresponde a una captura del entorno de laboratorio, no a una prueba de la actividad del incidente simulado.
- El ejercicio no utiliza un SIEM ni demuestra la detección de un ataque real.
- Las alertas del script son indicadores para investigar, no una confirmación automática de compromiso.

## Aprendizajes

Este laboratorio permite practicar análisis de logs, automatización básica con Python, elaboración de líneas de tiempo, verificación de integridad y documentación de incidentes, habilidades introductorias relevantes para SOC y DFIR.

## Uso responsable

Este proyecto tiene fines educativos y de desarrollo de habilidades defensivas. Los eventos de autenticación incluidos se generaron para simular un escenario de análisis.

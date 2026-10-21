
# Informe de análisis de incidente SSH
## Proyecto 01 — Portfolio SOC / Blue Team / DFIR

**Tipo de ejercicio:** análisis de registros y detección de actividad sospechosa  
**Entorno:** laboratorio local Kali Linux  
**Fecha de los eventos simulados:** 20 de octubre de 2026  
**Estado:** ejercicio de entrenamiento; no corresponde a un incidente real confirmado

## 1. Resumen ejecutivo

Se analizaron registros SSH simulados para identificar patrones de autenticación potencialmente sospechosos. Se desarrolló un script en Python que procesa los eventos, genera una línea de tiempo, contabiliza intentos de autenticación y emite alertas según criterios definidos.

El análisis identificó cinco intentos fallidos y una autenticación exitosa asociados a la dirección IP 203.0.113.45. La secuencia justifica una revisión adicional, pero por sí sola no demuestra que se haya producido un acceso no autorizado.

## 2. Alcance y metodología

El análisis se realizó sobre el archivo `evidencias/auth.log`, que contiene nueve líneas de eventos SSH simulados.

Se utilizó el script `analisis/detectar_ssh.py` para identificar autenticaciones fallidas y exitosas, aperturas y cierres de sesión. Los resultados se guardaron en `analisis/resultado_detector_v2.txt`.

También se utilizaron sumas SHA-256 para registrar y comprobar la integridad de los archivos del análisis.

## 3. Hallazgos principales

### Hallazgo 1: múltiples intentos fallidos

La IP 203.0.113.45 generó cinco intentos fallidos de autenticación entre las 09:14:02 y las 09:14:31 del 20 de octubre de 2026.

Los nombres de usuario observados fueron `admin`, `root`, `test` y `analyst`.

**Interpretación:** la secuencia puede ser compatible con intentos repetidos de acceso o prueba de credenciales. Es necesario investigar el contexto antes de atribuir una intención maliciosa.

### Hallazgo 2: autenticación exitosa posterior

A las 09:15:04 se registró una autenticación exitosa del usuario `analyst` desde la misma IP que había generado los cinco fallos anteriores.

A las 09:15:06 se registró la apertura de una sesión para ese usuario y a las 09:18:42 su cierre.

**Interpretación:** la combinación de intentos fallidos y un acceso exitoso requiere verificar si la autenticación fue legítima. Los registros disponibles no permiten confirmar por sí solos una intrusión.

### Hallazgo 3: actividad desde una segunda IP

A las 09:22:10 se observó un intento fallido para el usuario inexistente `guest` desde la IP 198.51.100.27.

Este evento es aislado dentro del conjunto de datos y no alcanza el umbral de tres fallos definido por el detector.

## 4. Resumen de resultados

- Eventos SSH reconocidos: 9.
- Fallos desde 203.0.113.45: 5.
- Autenticaciones exitosas desde 203.0.113.45: 1.
- Fallos desde 198.51.100.27: 1.
- Alertas generadas por el detector: 2.
- Sesiones registradas: una apertura y un cierre.

Las dos alertas corresponden a cinco intentos fallidos desde una misma IP y a la presencia de fallos seguidos de una autenticación exitosa.

## 5. Evaluación de riesgo

**Prioridad de investigación propuesta: alta dentro de este ejercicio.**

La combinación de intentos fallidos y una autenticación exitosa posterior merece revisión prioritaria. Esta clasificación es una recomendación para el escenario de entrenamiento y no equivale a una severidad confirmada en un entorno real.

No se dispone de información suficiente para determinar si hubo acceso no autorizado, extracción de datos o modificación del sistema.

## 6. Acciones recomendadas

1. Verificar con el responsable del sistema si el acceso de `analyst` era esperado.
2. Correlacionar los eventos con otros registros de autenticación, auditoría y actividad del sistema.
3. Revisar el origen de la conexión, el uso de privilegios y los procesos ejecutados durante la sesión.
4. Si se confirma actividad no autorizada, aplicar el procedimiento de respuesta a incidentes: preservar evidencias, contener el acceso y rotar credenciales cuando corresponda.
5. Revisar la configuración SSH y considerar autenticación multifactor, restricciones de acceso y controles contra intentos repetidos.
6. Documentar las decisiones y los resultados de cada acción.

## 7. Integridad y trazabilidad

Se generaron hashes SHA-256 para el script y el informe de resultados del detector. La comprobación con `sha256sum -c` devolvió `OK` para ambos archivos.

Estas comprobaciones permiten detectar cambios posteriores respecto de los hashes registrados. No demuestran por sí solas la autenticidad de los registros ni que estos procedan de un incidente real.

## 8. Limitaciones

Los eventos de autenticación de este caso son simulados. Las direcciones IP 203.0.113.45 y 198.51.100.27 pertenecen a rangos reservados para documentación y no deben tratarse como indicadores reales de amenaza.

El detector aplica reglas simples y no correlaciona eventos con una plataforma SIEM ni con fuentes externas. La ausencia de una IP en las líneas de apertura y cierre de sesión limita la correlación directa entre esos eventos y el origen de la conexión.

## 9. Conclusión

El ejercicio demuestra la aplicación de técnicas iniciales de análisis de registros, creación de líneas de tiempo, detección basada en reglas y verificación de integridad mediante SHA-256.

La principal señal de interés es la autenticación exitosa posterior a varios fallos desde la misma IP. En un entorno real, este patrón debería investigarse junto con otras evidencias antes de concluir que hubo una intrusión.

**Proyecto 01 — Laboratorio de entrenamiento SOC / Blue Team / DFIR.**

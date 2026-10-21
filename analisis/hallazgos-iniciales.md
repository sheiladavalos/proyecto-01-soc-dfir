# Proyecto 01: Investigación de incidente Linux

## 1. Alcance
Análisis didáctico de registros de autenticación SSH y de actividad
del sistema. Las dos fuentes son simuladas.

## 2. Hallazgos de autenticación
- Se observan cinco intentos fallidos desde 203.0.113.45.
- Se registra una autenticación aceptada para analyst desde esa IP.
- Se registra la apertura y el cierre de una sesión.
- La secuencia requiere investigar si el acceso fue autorizado.

## 3. Actividad posterior simulada
- 09:15:42: intento de acceso a /etc/shadow mediante sudo.
- 09:16:03: descarga de un archivo llamado update.sh.
- 09:16:15: cambio de permisos del archivo.
- 09:16:20: registro de ejecución del archivo.

## 4. Evaluación preliminar
La secuencia es compatible con una posible actividad posterior
a un acceso no autorizado. Sin embargo, no confirma por sí sola
un compromiso ni permite determinar el impacto.

## 5. Integridad
El archivo evidencias/auth.log coincidió con el hash SHA-256
registrado al inicio de la práctica.

## 6. Limitaciones
Los registros y las direcciones IP pertenecen a un escenario
didáctico. La actividad complementaria es simulada, no telemetría
real del sistema. No se ha analizado el contenido del supuesto script.

## 7. Próximos pasos
- Buscar evidencia adicional de actividad de procesos.
- Determinar si hubo acceso privilegiado.
- Investigar posibles cambios en archivos y mecanismos de persistencia.
- Documentar las limitaciones y mantener las conclusiones proporcionales
  a la evidencia disponible.

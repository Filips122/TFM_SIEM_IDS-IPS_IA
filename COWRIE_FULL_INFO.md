Hola,
Te envío adjunto el archivo cowrie_full.jsonl.gz, que contiene un dataset generado desde un honeypot T-Pot, concretamente desde el sensor Cowrie.
Cowrie es un honeypot orientado a capturar actividad contra servicios SSH y Telnet, por lo que el dataset contiene eventos reales de conexiones, intentos de acceso y actividad observada contra esos servicios.
El archivo está en formato JSON Lines comprimido (.jsonl.gz). Esto significa que cada línea del archivo es un evento JSON independiente. No es un JSON clásico con un array único.
Ejemplo de eventos que aparecen en el dataset:
{"eventid":"cowrie.session.connect","src_ip":"223.123.43.4","dst_port":23,"protocol":"telnet","timestamp":"2026-05-04T00:00:00.087384Z"}
{"eventid":"cowrie.session.connect","src_ip":"45.148.9.8","dst_port":22,"protocol":"ssh","timestamp":"2026-05-04T00:00:02.070908Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh-0.2","src_ip":"45.148.9.8"}
{"eventid":"cowrie.session.closed","duration":"0.1","src_ip":"45.148.9.8"}
Campos importantes:
eventid: tipo de evento registrado.
src_ip: IP origen del atacante.
src_port: puerto origen del atacante.
dst_ip: IP interna del contenedor de Cowrie.
dst_port: puerto atacado, normalmente 22 para SSH y 23 para Telnet.
protocol: protocolo usado, por ejemplo ssh o telnet.
session: identificador de sesión, útil para reconstruir la secuencia de acciones.
timestamp: fecha y hora del evento en UTC.
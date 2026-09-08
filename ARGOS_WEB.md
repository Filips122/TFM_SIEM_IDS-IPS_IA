# ARGOS-SOC IA — Qué muestra la aplicación

Inventario de cada pantalla, cada métrica y qué representa en el proyecto.
Se indica siempre **de dónde sale el número** y, cuando procede, qué **no**
significa.

> Convención usada en este documento:
> **[real]** calculado sobre datos vivos · **[fijo]** valor escrito en el código,
> no refleja estado · **[derivado]** calculado a partir de otra métrica ·
> **[externo]** viene de un servicio de terceros.

---

## 0. Arquitectura en una frase

La aplicación **no almacena nada**. Lee de Wazuh (API REST del manager +
Indexer/OpenSearch), enriquece con modelos de IA y catálogos externos, y
presenta. Dos rutas independientes:

| Ruta | Qué hace |
|---|---|
| `/` | Panel de mando en vivo. Sondea `/api/argos/live` cada 5 s. |
| `/simulacro` | Reproduce alertas contra el modelo de bloqueo. Sin acciones. |

Un proceso aparte, el **sidecar** (`127.0.0.1:8973`), mantiene los modelos
cargados en memoria. Si no está levantado, la web se repliega a lanzar
subprocesos Python y todo sigue funcionando, solo que más lento (15 s frente
a 4,3 s por refresco).

---

## 1. Barra superior (`CommandTopbar`)

| Indicador | Origen | Qué representa |
|---|---|---|
| `MANAGER` | **[real]** | `ONLINE`/`OFFLINE` según responda `/manager/info`. |
| `INDEXER` | **[real]** | Si la consulta de alertas al Indexer tuvo éxito. |
| `ALERTAS` | **[real]** | Alertas cargadas en este refresco. |
| `AI SCORE` | **[derivado]** | Media del `score` de las alertas cargadas. Es el mismo número que el KPI `AI Risk`; ver § 6.1 para por qué no debe leerse como nivel de riesgo. |
| `THREAT` | **[derivado]** | `HIGH` si hay más de una alerta crítica, si no `ELEVATED`. |

> **Sobre `THREAT`.** El *nivel de amenaza* es una convención de los centros de
> operaciones: un semáforo global para la sala. Aquí su umbral es trivial —más
> de una alerta crítica— y, como el 99,6 % de las críticas son hallazgos de
> inventario (§ 6.4), en la práctica **está siempre en `HIGH`**. Es un
> indicador decorativo heredado; no lo cites como medida.

> Aquí había antes `MCP · 12 AGENTS` y `SURICATA · RUNNING`, ambos escritos a
> mano. Retirados: ni Suricata está integrado, ni el `12 AGENTS` era medido.
> Sustituidos por estado del Indexer y recuento de alertas, que sí se miden.
> (El MCP sí está integrado hoy, pero como asistente conversacional —§ 10—, no
> como una flota de agentes.)

---

## 2. Barra lateral (`CommandSidebar`)

| Elemento | Origen | Qué representa |
|---|---|---|
| **Top targets** | **[real]** | Los cuatro agentes con más alertas, ordenados por volumen. |
| Recuento junto a cada objetivo | **[real]** | Alertas dirigidas a ese agente. Antes eran `96/87/78/69` por posición, decorativos. |
| **Regions** | **[real]** | Filtro por continente, deducido de la latitud/longitud del origen. |
| **Agent Health** | **[real]** | Seis filas de estado, detalladas abajo. |

### Agent Health — las seis filas

| Fila | Qué mide |
|---|---|
| Wazuh Manager | Si responde la API REST. |
| Wazuh Agents | Agentes activos y desconectados según el inventario. |
| Wazuh Indexer | Si la consulta de alertas tuvo éxito, y cuántas se cargaron. |
| GeoIP Enrichment | Coordenadas **reales** frente a **aproximadas**, separadas. |
| Risk Scoring | Si el modelo de IA respondió, con el score medio. |
| Flow Average | Eventos de 24 h dividido entre 1.440 → flujos por minuto. |

**Qué aporta este bloque.** No mide amenazas: mide **si te puedes fiar del
resto del panel**. Cada fila es una fuente que, si cae, deja un hueco que las
demás pantallas no señalan. `GeoIP Enrichment` separa coordenadas reales de
aproximadas precisamente porque el globo pinta ambas igual, y `Flow Average`
—medido ahora en unos 37 eventos por minuto— da la escala que justifica la
automatización.

> Había una séptima fila, `MCP Agents`, permanentemente en `planned`. Retirada
> por no medir nada. La integración MCP que existe hoy es el asistente
> conversacional (§ 10), y su estado se consulta en el propio widget.

---

## 3. Globo 3D (`AttackGlobe`)

**Qué es una representación geoespacial de ataques.** Sitúa cada evento en el
mapa uniendo el origen aparente con el destino. Es un recurso habitual en los
paneles de SOC, y conviene ser franco sobre su papel: **su valor es sobre todo
de comprensión inmediata**, no analítico. Ninguna decisión de seguridad debería
tomarse mirando un globo.

**Qué aporta aquí.** Dos cosas concretas y una advertencia. Aporta la **escala
del caudal** —se ve a simple vista que los ataques no paran— y la
**distribución del origen**, que muestra que no hay un único atacante sino
muchos frentes simultáneos. La advertencia: el país **no es el atacante**, es
la máquina usada, casi siempre alquilada o comprometida.

Solo dibuja las alertas de los **últimos 120 segundos**, para que el globo
respire en vez de saturarse. Esa ventana es de presentación, no de análisis: el
resto del panel sigue trabajando con las 10.000 alertas cargadas.

| Capa | Qué representa |
|---|---|
| **Arcos** | Trayecto origen → agente destino. Color según severidad. |
| **Puntos** | Orígenes geolocalizados y agentes destino. |
| **Anillos** | Pulso sobre el destino. Radio mayor si la severidad es crítica. |

> **Geolocalización de reserva:** si una alerta no trae coordenadas, se le
> asigna un punto de una lista fija mediante un hash de la IP. Esas alertas
> llevan ahora la marca `geoApproximate` y su origen se muestra como
> **«ciudad (aprox.)»** tanto en el globo como en el feed. La fila GeoIP de
> salud separa reales de aproximadas. Medido: **657 de 10.001 (6,6 %)**.

### Tabla de alertas del globo

Ocho columnas, paginadas de diez en diez:

`SEVERIDAD` · `TIPO` · `ORIGEN` · `IP` · `DESTINO` · `REGLA` · `AI SCORE` · `CLASIFICACIÓN`

Al pulsar una fila se abre la **ficha de detalle**, documentada en la sección
3.1.

### 3.1 Ficha de detalle de una alerta

Diecinueve campos. Los ocho primeros son hechos de la alerta; el resto son
salidas de modelos y etiquetas internas.

#### Identificación y contexto

| Campo | Qué representa |
|---|---|
| **Origen** | Ciudad y país de la IP. Lleva `(aprox.)` si las coordenadas son de reserva. |
| **IP origen** | Dirección atacante. `unknown` si la alerta no la trae. |
| **Coordenadas** | Latitud y longitud del origen, con cuatro decimales. |
| **Destino** | Nombre del agente Wazuh que registró la alerta. |
| **Agente** | El mismo agente. Duplicado histórico de «Destino». |
| **Zona** | Ciudad o país usado para agrupar en el filtro de regiones. Medido: 51 valores distintos. |
| **Táctica** | Táctica MITRE ATT&CK. De `rule.mitre.tactic` si existe; si no, se infiere del tipo. Medido: `Credential Access` en el 97 %. |
| **Wazuh rule** | Identificador numérico de la regla que disparó. |

#### Salidas del modelo de ventana (LAB-ALERTS)

| Campo | Qué representa |
|---|---|
| **AI `<n>`** (cabecera) | Score de ventana ×100. **Es del minuto del agente, no de esta alerta.** Ver sección 5. |
| **Modelo IA** | Identificador y versión del modelo que produjo el score. Sirve para trazar qué artefacto decidió. |
| **Predicción IA** | `attack` o `benign`, con la confianza. La confianza es la probabilidad de la clase elegida, no una medida de fiabilidad del modelo. |
| **Predicción taxonómica IA** | Familia de actividad de un segundo modelo multiclase que comparte contrato de características. **Es enriquecimiento, nunca la decisión de ataque.** Medido: `CredentialAccess` en el 99 %. |

#### Bloque CSR-LANL — capa experimental

> **Advertencia previa: estos cuatro campos no son interpretables en ARGOS.**
> Se muestran porque la capa está integrada, pero ver el aviso al final del
> bloque antes de citarlos en ninguna parte.

CSR-LANL es un modelo entrenado sobre un corpus público de registros de
autenticación, flujos de red, DNS y procesos, con actividad de equipo rojo
etiquetada. Trabaja con **209 características sobre ventanas de una hora
agrupadas por entidad**, sobre 13,1 millones de ventanas y 16.155 entidades.

| Campo | Qué representa |
|---|---|
| **CSR-LANL entidad** | La entidad puntuada. En ARGOS se mapea al **identificador del agente** (`025`, `011`…), no a un usuario o equipo como en el corpus original. |
| **CSR-LANL clasificación** | Tres niveles por umbral sobre el score supervisado: `low_signal` (< 0,95), `suspicious_entity` (0,95–0,9893), `high_risk_entity` (≥ 0,9893). Medido en vivo: **el 100 % son `low_signal`**. |
| **CSR-LANL score** | Score supervisado ×100. Probabilidad de que la entidad se parezca a las ventanas con actividad de equipo rojo del corpus. Medido: rango 0,0012–0,9220. |
| **Anomalía entidad** | Score de un IsolationForest auxiliar. Mide **rareza conductual**, no ataque. El propio paquete lo declara «enriquecimiento y explicación, no decisión primaria». |
| **Novedad contexto** | Fracción de indicadores de novedad activos: usuario nuevo, máquina destino nueva, proceso nuevo, par origen-destino nuevo… |

**Por qué no son interpretables aquí.** El paquete requiere las mismas 209
columnas del entrenamiento y trata las ausentes como error de esquema. Wazuh no
produce esas familias de datos, así que el adaptador **rellena con cero** todo
lo que falta. Su propia salida lo declara:

> «CSR-LANL model was trained on auth/flow/dns/proc windows; ARGOS Wazuh adapter
> fills unavailable feature families with zero.»

Un modelo que recibe la mayoría de sus entradas a cero opera fuera de su
dominio. Y sus métricas de origen ya eran modestas: **ROC-AUC 0,940 pero PR-AUC
0,0168**, con precisión entre los cincuenta primeros resultados de 0,040 — dos
aciertos de cada cincuenta revisiones.

Se mantiene visible porque documenta una decisión del trabajo (probar
transferencia entre dominios y medir que no funciona), no porque aporte señal.

#### Etiquetas internas

| Campo | Qué representa | Estado |
|---|---|---|
| **Suricata SID** | Identificador de firma de Suricata. | **Siempre `N/A`.** Suricata no está integrado; medido sobre 10.001 alertas, un único valor. |
| **MCP tool** | Etiqueta de encaminamiento heredada. Tres valores: `auth.window` (95 %), `wazuh.triage` (5 %), `argos.local-simulator`. | Es una **clasificación de tipo de alerta**, no una herramienta MCP. El nombre es engañoso. |
| **Sensores** | Fuentes que contribuyeron. | **Siempre `Wazuh / AI Engine`.** Solo hay una fuente real. |

---

## 4. Feed de alertas (`ThreatFeed`)

Las **siete alertas más recientes**. Cada tarjeta lleva:

**Qué es un feed de alertas.** Es la vista de *triaje*: la cola por la que un
analista de guardia va pasando, ordenada por lo más reciente. Su función no es
analizar sino **decidir rápido si algo merece atención**, así que cada tarjeta
debe caber de un vistazo.

**Qué aporta aquí.** Es la única pantalla donde los cuatro enriquecimientos
aparecen **juntos sobre la misma alerta**: la severidad que dice Wazuh, el
score del modelo, el riesgo de la IP y si el CVE se explota de verdad. Ver los
cuatro a la vez es lo que permite detectar las contradicciones que documenta
§ 6.4 — una alerta CRITICAL con riesgo de IP bajo y sin explotación conocida es
inventario, no ataque.

### Bloque base

| Campo | Origen | Qué es | Qué aporta aquí |
|---|---|---|---|
| Severidad | **[real]** | Gravedad que asigna el autor de la regla | Traducción de `rule.level`: crítica ≥12, alta ≥9, media ≥6, baja el resto. **No mide riesgo real**; ver § 6.1. |
| Tipo | **[derivado]** | La técnica del ataque | Inferido por palabras clave de la descripción, no viene de Wazuh. El 98 % cae en dos categorías genéricas. |
| Origen → destino | **[real]** | Quién ataca a quién | Ciudad/país de la IP y nombre del agente. Lleva `(aprox.)` si la geolocalización es de reserva. |
| `AI <n>` | **[real]** | Score del modelo | Es de la **ventana** de un minuto del agente, no de esta alerta. Ver § 5. |
| `Rule <id>` | **[real]** | Identificador de la regla de Wazuh | Permite ir al origen y comprobar por qué saltó. Es el ancla de trazabilidad. |
| `mcpTool` | **[derivado]** | — | Etiqueta de encaminamiento heredada: `auth.window` (95 %), `wazuh.triage` (5 %), `argos.local-simulator`. **El nombre es engañoso**: no tiene relación con el MCP de § 10. |

### `IP <n>` — riesgo por dirección **[real]**

```
IP 98   45.156.87.93   2c · 1m · /24 100% · bloquearía en aviso 5
```

Probabilidad que da el modelo a que **esa dirección** merezca bloqueo, según
lo que ha hecho: cuentas probadas (`c`), máquinas alcanzadas (`m`), reputación
hostil de su subred /24, y en qué aviso habría cortado.

Aparece solo en alertas con IP de origen. En la muestra medida son el **22,6 %**
de las alertas del panel; el resto (Trivy, syscheck, systemd) no tienen atacante
al que puntuar. De las IPs que sí aparecen, la cobertura es del **100 %**.

### Etiqueta de explotación real **[externo]**

```
EXPLOTADA EN LA VIDA REAL   CVE-2025-27363   EPSS 0.278
```

Tres estados: `EXPLOTADA EN LA VIDA REAL` (en el catálogo KEV de CISA),
`EXPLOTACIÓN PROBABLE` (EPSS ≥ 0,1), `SIN EXPLOTACIÓN CONOCIDA`.

---

## 5. Los dos scores de IA — la distinción que más importa

La aplicación muestra **dos números distintos** que responden a preguntas
distintas. Confundirlos es el error más fácil de cometer al leer el panel.

| | `AI <n>` (ventana) | `IP <n>` (dirección) |
|---|---|---|
| **Pregunta** | ¿Este minuto de este agente parece ataque? | ¿La conducta de esta IP justifica bloquearla? |
| **Unidad** | 1 minuto × agente | Dirección IP |
| **Modelo** | LAB-ALERTS (`models_examples/`) | EarlyBlockScorer (`deploy/argos_scorer/`) |
| **Entradas** | 16 agregados del minuto | 22 variables de conducta de la IP |
| **Usa campos del motor de reglas** | Sí (3 de 16) | **No, por diseño** |
| **Valores distintos sobre 10.000 alertas** | **8–15** | **39–148** |

### Por qué el `AI Score` sale casi siempre igual

**No es un juicio por alerta.** El modelo puntúa el minuto completo del agente
y copia el mismo número a todas las alertas de dentro. Medido: el **100 % de
las ventanas contienen más de una IP distinta**, así que cuatro atacantes
golpeando el mismo servidor en el mismo minuto reciben **el mismo score**.

Además satura: entrenado sobre una tarea donde responder «ataque» siempre ya
acierta el 98,64 %, predice `attack` en el 100 % de las alertas recientes. Y su
etiqueta se derivó del propio motor de reglas de Wazuh, así que mide parecido
con el criterio de Wazuh, no ataque.

Verás tarjetas con `score=100` y `severidad=low`: la IA dice riesgo máximo y
Wazuh dice severidad baja. Las dos «tienen razón» en su marco.

---

## 6. Panel analítico (`MiniDashboard`)

### 6.1 KPIs — las seis tarjetas de cabecera

Cada tarjeta se explica en dos partes: **qué es** el concepto, con
independencia de esta aplicación, y **qué aporta aquí**, con la medición del
momento de escribir esto (10.001 alertas cargadas, modo `live`).

---

#### `Eventos 24h` — 53.201 **[real]**

**Qué es.** El *volumen de eventos* es la métrica más básica de un SOC: cuántos
registros ha generado la infraestructura en una ventana temporal. No dice nada
sobre gravedad; mide caudal. En la industria es el número que dimensiona la
plataforma, porque las licencias de SIEM suelen facturarse por eventos por
segundo o por gigabytes ingeridos.

**Qué aporta aquí.** Es el **denominador de todo lo demás**. Sirve para dos
cosas concretas: detectar que la ingesta se ha parado (si cae a cero, el
problema es de Wazuh, no de que no haya ataques) y dar la escala real del
problema — 53.201 eventos en 24 h son unos **37 por minuto**, un caudal que
ninguna persona puede revisar a mano. Ese hecho es lo que justifica el resto
del trabajo: sin automatización, el 100 % de estas alertas se quedan sin mirar.

Se calcula con una consulta de conteo aparte, no contando la lista cargada,
porque contar es barato en el indexador y traer documentos no lo es.

---

#### `Alertas correladas` — 1.721.416, con 10.001 cargadas **[real]**

**Qué es.** *Correlación* en un SIEM significa unir eventos distintos que por
separado no dicen nada — un fallo de contraseña aquí, otro allá — en un
incidente único con sentido. Es la función que distingue un SIEM de un simple
almacén de registros.

**Qué aporta aquí, y una advertencia sobre el nombre.** El número grande es el
total de alertas de 30 días; el pequeño, cuántas se han traído de verdad. La
pareja existe para que quede claro que **el panel no ve todo**: de 1,72
millones se cargan 10.001, es decir el **0,58 %**. Cualquier porcentaje del
panel se calcula sobre esa muestra, no sobre el total, y la muestra es la más
reciente, no una aleatoria.

**El nombre es heredado y engañoso: ese número no está correlado.** Es un
recuento. La correlación real que sí ocurre en ARGOS se mide en la gráfica
*Correlación por fuente* (§ 6.2), y son cuatro enriquecimientos, no 1,7
millones de incidentes.

---

#### `Anomalías IA` — 4.589, media 47 **[derivado]**

**Qué es.** Una *anomalía*, en detección, es una observación que se aparta del
comportamiento normal aprendido. La palabra implica normalmente un método **no
supervisado**: el modelo aprende qué es normal y marca lo que se sale, sin que
nadie le haya dicho qué es un ataque.

**Qué aporta aquí, y por qué el nombre no es correcto.** Esto **no es una
detección de anomalías**. Es un recuento con umbral: alertas cuyo score de
ventana supera 70. El modelo que lo produce es **supervisado** — se entrenó con
etiquetas de ataque y benigno—, así que lo que cuenta la tarjeta es «cuántas
ventanas clasificó el modelo como ataque con confianza alta», que es otra cosa.

Lo que sí aporta: es la **medida del filtrado**. De 10.001 alertas, 4.589
superan el umbral. Un analista que solo mire esas revisa el 46 % del volumen.
Ese es el ahorro real que ofrece la capa de IA — y también su límite, porque
reducir a la mitad sigue siendo inasumible a 37 alertas por minuto.

---

#### `Críticas` — 843 **[real]**

**Qué es.** La *severidad* de una alerta es la etiqueta de gravedad que le
asigna la regla que la disparó. En Wazuh viene del nivel de la regla (0–15), y
es una decisión **del autor de la regla**, tomada de antemano y sin conocer tu
entorno: no mide el riesgo real que esa alerta supone para ti.

**Qué aporta aquí.** Es el KPI que **mejor demuestra por qué la severidad
declarada no basta**, que es una de las conclusiones del trabajo. Medido ahora:
de las 843 alertas CRITICAL, **840 son hallazgos del escáner de
vulnerabilidades** (inventario de paquetes con CVE conocido, no ataques en
curso) y solo **6** corresponden a CVE con explotación real conocida.

Mientras tanto, la fuerza bruta que sí está ocurriendo vive en severidad LOW.
Si un analista prioriza por esta tarjeta, dedica el día al inventario y no ve
el ataque. El contraste completo está en § 6.4.

---

#### `Agentes activos` — 4 activos, 16 desconectados **[real]**

**Qué es.** Un *agente* es el proceso que Wazuh instala en cada máquina
vigilada y que le envía los registros. Un agente desconectado no genera
alertas, y esa ausencia **no es lo mismo que ausencia de ataques**: es un punto
ciego.

**Qué aporta aquí.** Es la **honestidad sobre la cobertura**. Con 4 de 20
agentes activos, el panel está mirando el 20 % del parque. Cualquier
afirmación del tipo «no hay ataques contra la máquina X» es indefendible si X
está entre las 16 desconectadas. La tarjeta enseña los dos números juntos
precisamente para que no se pueda leer solo el bueno.

---

#### `AI Risk` — 47, `guarded` **[derivado]**

**Qué es.** Un *nivel de riesgo agregado* pretende resumir en un número el
estado general de la plataforma, normalmente promediando los scores
individuales. Es un patrón habitual en paneles comerciales.

**Qué aporta aquí — y por qué hay que citarlo con cuidado.** Es la media
aritmética del score de ventana de las alertas cargadas. El problema está
medido: **el score no es continuo, es prácticamente binario**. Sobre 10.001
alertas hay solo **10 valores distintos**, y se reparten así:

| Score | Alertas | % |
|---|---|---|
| 2 | 5.412 | 54,1 % |
| 100 | 4.482 | 44,8 % |
| resto (8 valores) | 107 | 1,1 % |

La media de una distribución con dos picos en los extremos es un número que
**no describe a ninguna alerta**: no hay casi nada cerca de 47. Decir «el
riesgo medio es 47, nivel guarded» sugiere una plataforma en riesgo moderado,
cuando lo que hay son dos poblaciones separadas: una casi inofensiva y otra que
el modelo da por ataque seguro.

Se mantiene en el panel porque es la métrica que enseña el problema de
saturación descrito en § 5, no porque sirva para decidir. **Para priorizar, usa
el riesgo por IP** (§ 4), que sí discrimina entre atacantes.

### 6.2 Gráficas

#### `Ataques por tipo` **[derivado]**

**Qué es.** Una *taxonomía de ataque* clasifica el evento por su técnica: fuerza
bruta, escaneo, inyección… Permite saber a qué te enfrentas, no solo cuánto.

**Qué aporta aquí.** El tipo **no viene de Wazuh**: se infiere del texto de la
descripción de la regla con reglas de palabras clave propias. Medido:
`Suspicious activity` 5.529, `Suspicious auth burst` 4.341, `SSH brute force`
128, `SQLi probe` 2. Las dos primeras categorías, que son el 98 %, son
genéricas — es decir, la gráfica confirma que **casi todo el tráfico hostil es
del mismo tipo**, pero no lo caracteriza con finura. Es útil como comprobación
de homogeneidad, no como inventario de técnicas.

#### `Distribución por severidad` **[real]**

**Qué es.** El reparto de alertas entre los cuatro niveles de gravedad. En un
SOC sano se espera una pirámide: muchas bajas, pocas críticas.

**Qué aporta aquí.** Es la entrada al hallazgo de § 6.4: la pirámide existe,
pero **está mal poblada**. Lo crítico es inventario y lo bajo son ataques. La
gráfica por sí sola induce a error; solo tiene valor leída junto al contraste
de explotación real.

#### `Alertas vs IA por hora` **[real]**

**Qué es.** Una *serie temporal* reparte los eventos por su marca de tiempo.
Sirve para ver campañas: un pico a una hora concreta sugiere una acción
coordinada, un caudal plano sugiere ruido de fondo automatizado.

**Qué aporta aquí.** Ocho tramos de tres horas, agrupados por la **hora real**
de cada alerta. Superpone el volumen total y el detectado por la IA, para ver
si el modelo sigue al caudal o se dispara en momentos concretos.

> **Cómo leerla sin equivocarse.** Antes agrupaba por la posición en la lista
> (`index % 8`), lo que producía ocho barras casi idénticas con forma de
> distribución horaria que no lo era. Corregido.
>
> Consecuencia esperable de la corrección: como el panel carga las **10.000
> alertas más recientes**, que a caudal actual son unas cinco horas, la gráfica
> muestra datos en tres o cuatro tramos y **cero en el resto**. Eso es correcto
> —antes los ceros se rellenaban con reparto artificial—, pero no es una
> distribución de 24 horas: es la ventana que cabe en 10.000 alertas.

#### `Top países origen` **[derivado]**

**Qué es.** *Geolocalización de IP*: traducir una dirección a una ubicación
aproximada consultando a qué bloque de red pertenece.

**Qué aporta aquí.** Medido: Bulgaria 1.819, `UN` 1.175, Singapur 1.095, EE. UU.
1.093. Dos advertencias que hacen falta para no sobreinterpretarla:

1. `UN` significa **desconocido**, no un país. Es el segundo valor más
   frecuente: más de mil alertas sin geolocalizar.
2. **El país no es el atacante.** Es donde está la máquina usada, casi siempre
   un servidor alquilado o comprometido. Sirve para agrupar y para el globo,
   no para atribuir.

#### `AI risk distribution` **[derivado]**

**Qué es.** Un *histograma* del score: cuántas alertas caen en cada tramo. En un
modelo bien calibrado se espera una curva repartida, con una cola en los
extremos.

**Qué aporta aquí.** Es **la prueba visual de la saturación**. Ocho tramos de
12,5 puntos; medido, 5.412 alertas en el tramo `0-12,5` y 4.482 en `87,5-100`,
con los seis tramos intermedios casi vacíos. Un histograma en forma de U es la
firma de un clasificador que no gradúa: decide sí o no, no «cuánto».

Al pulsar un tramo se abre un **detalle emergente** con los scores exactos que
lo componen y cuántas alertas tiene cada uno. Existe para poder comprobar la
afirmación anterior sin fiarse del dibujo: al abrir el tramo bajo se ve que las
5.412 alertas tienen todas exactamente el mismo score, 2.

#### `MITRE tactics` **[real]**

**Qué es.** **MITRE ATT&CK** es un catálogo público que ordena el
comportamiento de los atacantes en *tácticas* (el objetivo: obtener
credenciales, moverse lateralmente…) y *técnicas* (cómo se consigue). Es el
vocabulario común del sector para describir ataques sin ambigüedad.

**Qué aporta aquí.** Traduce las reglas de Wazuh a ese vocabulario. Medido:
`Initial Access` 5.442, `Credential Access` 4.558. Aporta dos cosas: hace el
panel legible para alguien que no conozca las reglas de Wazuh, y **confirma el
dominio de validez del trabajo** — las dos tácticas presentes son exactamente
las de un atacante ruidoso que intenta entrar por la puerta. No hay
`Persistence`, ni `Exfiltration`, ni `Defense Evasion`. Esa ausencia es la
razón por la que el trabajo no puede afirmar nada sobre atacantes sigilosos.

#### `Correlación por fuente` **[real]**

**Qué es.** Cuántas alertas ha enriquecido cada fuente de información. Un
*enriquecimiento* añade contexto externo a una alerta que llega sin él.

**Qué aporta aquí.** Es el **inventario honesto de lo que ARGOS añade de
verdad** sobre Wazuh. Cuatro filas, medidas ahora sobre 10.001 alertas:

| Fuente | Alertas | Qué añade |
|---|---|---|
| Modelo de ventana | 10.001 | Score de IA. Cubre el 100 %. |
| Riesgo por IP | 4.553 | Solo las que traen IP de origen utilizable. |
| Reputación AbuseIPDB | 4.447 | Reputación externa, servida desde caché. |
| Explotación real (CVE) | 5.399 | Solo las alertas que mencionan un CVE. |

> **Defecto corregido al redactar esta sección.** La fila de AbuseIPDB contaba
> únicamente el estado `checked` (consulta hecha en ese instante) e ignoraba
> `cached`, así que **marcaba 0 con 4.447 alertas realmente enriquecidas**.
> Corregido en `lib/argos-normalizers.ts`: ambos estados cuentan, porque la
> alerta lleva reputación real en los dos casos.
>
> Antes de eso, las filas listaban Suricata y Zeek, que no están integrados y
> valían siempre cero.

> **Sobre la línea temporal.** Antes agrupaba por la posición en la lista
> (`index % 8`), lo que producía ocho barras casi idénticas con forma de
> distribución horaria que no lo era. Corregido: ahora agrupa por la hora real.
>
> Consecuencia esperable: como el panel carga las **10.000 alertas más
> recientes**, que a caudal actual son unas cinco horas, la gráfica muestra
> datos en tres o cuatro tramos y **cero en el resto**. Eso es correcto —antes
> los ceros se rellenaban con reparto artificial—, pero conviene saberlo al
> interpretarla: no es una distribución de 24 horas, es la ventana que cabe en
> 10.000 alertas.
>
> Las filas de `Correlation sources` listaban antes Suricata y Zeek, que no
> están integrados y valían siempre cero.

### 6.3 Criminal Intelligence — AbuseIPDB **[externo]**

**Qué es el concepto.** La *reputación de IP* es inteligencia colaborativa:
miles de organizaciones denuncian las direcciones que las atacan, y el servicio
devuelve una puntuación de abuso de 0 a 100 según cuántas denuncias
independientes acumula esa dirección. Es información que **ninguna instalación
puede generar sola**, porque requiere ver lo que le pasa a mucha gente a la vez.

**Qué aporta en ARGOS.** Responde a una pregunta que los datos propios no
pueden contestar: *¿esta IP es un atacante conocido, o solo alguien que ha
fallado la contraseña?* Es la única fuente del panel que aporta contexto de
**fuera** del laboratorio.

Para no agotar la cuota gratuita, solo consulta direcciones **públicas que se
repiten al menos 10 veces**, con caché en disco de 24 h y un tope por refresco.

| Métrica | Qué es | Medido ahora |
|---|---|---|
| **Eligible IPs** | Públicas que superan el umbral de repetición | 39 de 65 públicas |
| **Checked IPs** | Consultadas de verdad, y cuántas desde caché | 38, todas cacheadas |
| **High Risk IPs** | Con puntuación de abuso ≥ 80 | 36 |
| **Flagged Alerts** | Alertas cuya IP supera ese umbral | — |
| **Reputation donut** | Reparto en tramos 0-39 / 40-79 / 80-100 / desconocida | 2 en 40-79 |
| **Top reported IPs** | Las cinco direcciones con más denuncias acumuladas | 45.148.10.141: 213.259 denuncias, NL |
| **Lookup status** | Por qué no se consultó cada IP | privada, bajo umbral, cuota |

**El dato que más dice:** de 39 IPs elegibles, **36 tienen reputación ≥ 80**.
No son visitantes que se equivocan de contraseña: son direcciones que el resto
de internet ya ha denunciado como hostiles. Y la primera acumula **213.259
denuncias**, lo que confirma el perfil del trabajo — atacantes ruidosos y
masivos, no dirigidos.

**Limitación actual medida:** 5.448 de 10.001 alertas quedan en estado `error`
de consulta (cuota o clave). Es decir, la cobertura real de esta tarjeta es del
44 %, no del 100 %.

### 6.4 Explotación real — CISA KEV + EPSS **[externo]**

**Qué son los conceptos.** Tres piezas del vocabulario de vulnerabilidades:

- **CVE** (*Common Vulnerabilities and Exposures*): el identificador único y
  público de una vulnerabilidad concreta, del tipo `CVE-2026-31431`. Es una
  matrícula, no una medida de gravedad.
- **KEV** (*Known Exploited Vulnerabilities*): catálogo que publica la agencia
  de ciberseguridad estadounidense (CISA) con las vulnerabilidades de las que
  hay **constancia de explotación real en ataques observados**. Estar en KEV no
  es una predicción: es un hecho comprobado.
- **EPSS** (*Exploit Prediction Scoring System*): un modelo estadístico que
  estima la **probabilidad de que una vulnerabilidad sea explotada en los
  próximos 30 días**, de 0 a 1. Responde a «¿va a pasar?», no a «¿cuánto daño
  haría?».

La distinción que importa: la severidad clásica (CVSS, y el nivel de regla de
Wazuh) mide **cuánto daño haría si alguien la explotara**. KEV y EPSS miden
**si alguien la está explotando de verdad**. Son preguntas distintas, y la
segunda es la que decide qué parcheas el lunes.

**Qué aporta en ARGOS.** Contrasta la severidad declarada con la explotación
observada. **No modifica la severidad de Wazuh**: se muestra al lado, como
segunda opinión.

| Métrica | Qué es | Medido ahora |
|---|---|---|
| **CVE detectados** | Vulnerabilidades distintas en las alertas cargadas | 5.193 |
| **Explotados (KEV)** | Con explotación real confirmada por CISA | 2 |
| **Accionables** | En KEV, o con EPSS ≥ 0,1 | 13 |
| **Ruido de inventario** | El resto, con el factor de reducción | ×399 |
| **Reparto por explotación** | Donut: explotados / probables / sin explotación conocida | 2 / 11 / 5.180 |
| **Prioridad real de parcheo** | Los accionables ordenados por EPSS | `CVE-2026-31431`, EPSS 0,999 |

#### El contraste — el bloque que da sentido al panel

```
843  alertas marcadas CRITICAL por el nivel de regla de Wazuh
840  de ellas son hallazgos de escáner, no ataques en curso
  6  corresponden a CVE con explotación real conocida
```

Medido sobre 30 días: de los **28 CVE que Trivy marca CRITICAL, ninguno está
en KEV**; uno etiquetado MEDIUM sí. Y la severidad LOW tiene un EPSS medio
(0,00913) **superior** al de MEDIUM (0,00269).

**Prioridad real de parcheo:** los CVE accionables ordenados por probabilidad
de explotación. De 5.193 vulnerabilidades distintas quedan **13** — una
reducción de **399×**. Ese factor es el argumento entero de esta tarjeta:
convierte una cola de revisión imposible en una lista que cabe en una mañana.

> Las cifras de este bloque se mueven con cada refresco, porque dependen de las
> 10.000 alertas cargadas en ese momento. Una medición anterior daba 222 / 219 /
> 2 y una reducción de 243×. **Lo que no cambia es la relación**: lo crítico es
> casi todo inventario, y la reducción es de dos órdenes de magnitud.

---

## 7. Simulacro (`/simulacro`)

Reproduce alertas reales contra el modelo de bloqueo temprano y enseña a quién
habría bloqueado, en qué aviso y con qué evidencia. **No ejecuta ninguna
acción**: ni firewall, ni escritura en Wazuh.

**Fuente:** intenta datos frescos de Wazuh con una consulta ligera de un solo
disparo; si el servicio no responde, cae automáticamente al fichero exportado
de 30 días y lo advierte en pantalla.

### Cabecera de seguridad

Confirmación explícita de que **ningún veredicto cayó sobre infraestructura
propia** — rangos no enrutables, agentes, honeypot e indexer. Es el primer
criterio de promoción a bloqueo real, y se afirma en positivo en vez de
deducirse del silencio.

### Métricas principales

**El concepto que las une: decisión secuencial con presupuesto.** El modelo de
bloqueo temprano no clasifica una alerta aislada. Va acumulando avisos de una
misma IP y, en cada uno, decide si ya tiene suficiente para cortar o si espera
al siguiente. Es un problema de *parada óptima*: cortar pronto arriesga
bloquear a un inocente; esperar demasiado deja pasar el ataque. El
«presupuesto» es el número de avisos que se permite observar antes de decidir
(K = 1, 2, 3, 5, 10, 20).

Esto es lo que distingue el simulacro del resto del panel: **las demás métricas
describen, esta decide.**

---

#### `Alertas reproducidas`

**Qué es.** El volumen de entrada de la reproducción: cuántos eventos reales se
han hecho pasar por el modelo, en orden temporal, como si llegaran en vivo.

**Qué aporta aquí.** Es el denominador de todo lo demás y, sobre todo, la
garantía de que **no se ha elegido la muestra**: se reproduce una ventana
temporal completa, no una selección de casos favorables.

---

#### `IPs con origen de red`

**Qué es.** Cuántas direcciones distintas hay entre esas alertas. Es la unidad
sobre la que se decide: se bloquean IPs, no alertas.

**Qué aporta aquí.** Marca la diferencia entre las dos poblaciones del panel.
Solo el **22,6 %** de las alertas traen una IP puntuable; el resto —Trivy,
syscheck, systemd— no tienen atacante al que bloquear. Cualquier porcentaje del
simulacro se calcula sobre esta cifra, no sobre el total de alertas.

---

#### `Bloqueadas` y `Tasa de bloqueo`

**Qué es.** Cuántas de esas IPs cruzaron su umbral, y el porcentaje. Una *tasa
de bloqueo* es la proporción de sujetos sobre los que el sistema actuaría.

**Qué aporta aquí, y de dónde sale la banda.** Se muestra con un aviso si sale
de la banda **60–85 %**, que **no es un objetivo, es un detector de avería**:
es el rango que se observó en el entorno de entrenamiento del paquete. Salirse
por abajo sugiere que el modelo llega con datos que no reconoce; salirse por
arriba, que está bloqueando indiscriminadamente. En ambos casos el número que
hay que revisar es el modelo, no el atacante.

Es la métrica más fácil de malinterpretar: una tasa alta **no** significa
buena detección. Significa que muchas IPs cruzaron un umbral, y como casi todo
lo que llega a este laboratorio es hostil, una tasa alta es lo esperable y no
demuestra nada por sí sola.

---

#### `Mediana de corte`

**Qué es.** En qué número de aviso decide el modelo, típicamente. Se usa la
**mediana y no la media** a propósito: unas pocas IPs que se deciden muy tarde
arrastrarían la media y darían una impresión falsa de lentitud.

**Qué aporta aquí — es la métrica que da nombre a «bloqueo temprano».** Toda la
propuesta consiste en cortar *antes* de que el ataque haga daño. La referencia
es el **5.º aviso**: si el modelo decide típicamente ahí, está cortando con
poca evidencia acumulada, que es el objetivo. Si la mediana se fuera al 15.º o
al 20.º, el adjetivo «temprano» dejaría de ser defendible y habría que
retirarlo de la memoria.

---

#### `Alertas suprimidas`

**Qué es.** Cuántas alertas generaron esas IPs **después** del momento del
corte. Es una métrica **contrafactual**: cuenta lo que habría dejado de pasar
si el bloqueo se hubiera aplicado de verdad.

**Qué aporta aquí, y su límite honesto.** Es el argumento de utilidad: traduce
la decisión a algo tangible —«se habrían evitado N alertas»—. Pero es una
**estimación optimista por construcción**, por dos motivos que hay que decir
siempre que se cite:

1. Supone que la IP habría seguido comportándose igual tras el bloqueo, cuando
   un atacante real podría cambiar de dirección.
2. Está **fuertemente concentrada**: medido, entre el **55 y el 67 %** de todo
   lo suprimido lo aportan solo **3 IPs**. La mediana por IP es de **27**
   alertas frente a un máximo de **872**.

Por eso nunca se muestra sola. El desglose que viene a continuación es
obligatorio, no decorativo.

### Desglose — por qué no basta el porcentaje

Un agregado esconde concentración, así que se reparte siempre:

- Qué porcentaje de lo suprimido aportan solo 3 IPs (medido: **55-67 %**).
- Mediana de alertas suprimidas por IP frente al máximo (**27 frente a 872**).
- Bloqueos sin efecto medible.
- Los cinco mayores contribuyentes, con nombre.

> Esta sección existe porque la regla metodológica del trabajo es **«ninguna
> métrica agregada sin su desglose por grupo»**. Un «91 % de ataque evitado»
> puede venir de una sola IP muy ruidosa.

### Calidad de las decisiones

**Evidencia que acompaña a cada bloqueo** — describe *qué hay*, no *por qué
decidió el modelo* (es una función aprendida sobre 22 variables; afirmar
causalidad sería mentir):

| Etiqueta | Significado |
|---|---|
| `ENUMERACIÓN` | Probó dos o más cuentas distintas. |
| `ALCANCE LATERAL` | Alcanzó dos o más máquinas. |
| `REPUTACIÓN DE SUBRED` | **Sin evidencia propia**: su /24 ya produjo hostiles. La más delicada. |
| `VOLUMEN` | Ninguna de las anteriores. |

**Margen sobre el umbral** por veredicto, con las ajustadas (< 0,05) marcadas.
Medido: en torno a **la mitad** de las decisiones están al filo.

### Sesgo de ventana

Las IPs que aparecen al final de la ventana no tienen tiempo de acumular
avisos. Medido en una ejecución: **las 9 de 9 sin bloquear** no llegaron a los
20 avisos del último presupuesto. **No se puede afirmar que sean benignas**, y
por tanto la tasa de bloqueo está sesgada a la baja y no debe leerse como
precisión.

---

## 8. Modos de degradación

La aplicación nunca falla en blanco. Cuenta cuántas de las tres fuentes
respondieron:

| Modo | Condición | Qué se ve |
|---|---|---|
| `live` | Las tres responden | Datos reales. |
| `partial` | Una o dos | Banner de aviso; lo que falte, simulado. |
| `demo` | Ninguna | Ocho alertas de ejemplo (`ARG-1001`…). |

> **Cuidado al hacer capturas para la memoria:** un panel en modo `demo` es
> visualmente idéntico a uno en vivo salvo por el banner. Conviene verificar el
> campo `mode` de la respuesta antes de dar una captura por buena.

---

## 9. Simulador local de alertas benignas

En cada refresco se antepone **una alerta benigna sintética**, rotando entre
diez escenarios (fallos de systemd, logs de Docker, flujos de administración).
Nunca se escribe en Wazuh; solo existe en memoria dentro de la respuesta.

Existe porque el tráfico real es casi todo ataque, y sin ningún contraejemplo
el panel no permite comprobar que el sistema distingue algo. Se identifica con
`argos.local-simulator` en el campo de herramienta.

---

## 10. Endpoints

| Ruta | Para qué |
|---|---|
| `GET /api/argos/live` | Alimenta el panel completo. |
| `GET /api/argos/simulation` | Ejecuta el simulacro. `minutes`, `limit`, `source`. |
| `GET /api/argos/dataset` | Exporta alertas en JSONL para análisis. `format=manifest` da solo el balance de clases. |
| `POST /api/argos/mcp-chat` | Consulta en lenguaje natural sobre las herramientas MCP. |
| `GET /api/argos/mcp-chat` | Sonda: qué motor va a responder y cuántas herramientas hay. |
| `GET /api/wazuh/*` | Acceso directo a agentes, manager y alertas. |

### El asistente conversacional

Tres motores tras el mismo endpoint, con la misma forma de respuesta. Cuál
contesta se decide por disponibilidad, y la respuesta lo declara en el campo
`engine`. Los tres consultan **el mismo servidor MCP**, así que no hay dos
implementaciones de las herramientas que puedan divergir.

| Motor | Credencial | Cuándo |
|---|---|---|
| `cli` | Suscripción de Claude | Preferido, si el CLI de Claude Code está instalado |
| `api` | `ANTHROPIC_API_KEY` | Si no hay CLI, o si el CLI falla |
| `keywords` | Ninguna | Respaldo final; siempre responde |

`ARGOS_CHAT_ENGINE=cli|api|keywords` fuerza uno concreto.

#### Motor `cli` — la suscripción

Invoca el CLI de Claude Code en **modo no interactivo** (`--print`) con el
servidor MCP de ARGOS cargado. No necesita clave de API: usa la sesión ya
iniciada del CLI. Es la única vía por la que una suscripción puede alimentar la
aplicación, porque no expone ninguna credencial programática.

La pregunta viaja por **stdin**, nunca como argumento de línea de órdenes: el
texto del usuario no puede interpretarse como opciones.

**Superficie de ataque.** Este endpoint lanza un agente en la máquina. Se acota
con `--strict-mcp-config` (solo el servidor de ARGOS), `--allowedTools` (solo
las siete de lectura), `--disallowedTools` (se niegan Bash, Write, Edit…) y
`--permission-prompts none` (nadie contesta prompts, luego se deniegan).
Además, un máximo de 2 invocaciones concurrentes, porque cada agente ocupa
300–500 MB. Aun así: **no expongas la aplicación fuera de localhost con este
motor activo.**

Medido de extremo a extremo, pregunta abierta («¿qué IP debería mirar primero y
por qué?»): 27 s, 8 turnos, 6 herramientas encadenadas por decisión del modelo
—`estado_plataforma`, `resumen_amenazas`, `buscar_alertas` y tres
`riesgo_de_ip`—. La respuesta corrigió por su cuenta que la severidad LOW es
donde vive la fuerza bruta real, avisó de que se trata de un atacante ruidoso y
no de un APT, y se negó a bloquear declarándose de solo lectura: las
advertencias del *system prompt* se sostienen en ejecución, no solo sobre el
papel.

#### Motor `api` — la web como host MCP

Si existe `ANTHROPIC_API_KEY`, la aplicación web actúa como **host del Model
Context Protocol**: levanta `deploy/argos_mcp/server.ts` como proceso hijo,
habla con él por stdio y ofrece sus siete herramientas al modelo, que decide
cuáles llamar y en qué orden.

```
navegador → POST /api/argos/mcp-chat → cliente MCP (lib/mcp-host.ts)
                                            ↓ stdio
                                    servidor MCP de ARGOS
                                            ↓ HTTP
                              /api/argos/live · sidecar :8973
```

Es **el mismo servidor y el mismo protocolo** que consume Claude Desktop; lo
único que cambia es quién hace de cliente. No hay una segunda implementación de
las herramientas que pueda divergir de la primera.

| Propiedad | Valor | Por qué |
|---|---|---|
| Modelo | `claude-opus-5` | — |
| Herramientas | 7, solo lectura | Ninguna escribe en Wazuh ni bloquea |
| Tope de iteraciones | 6 | Acota coste y evita bucles de herramientas |
| Historial reenviado | 8 turnos | Permite preguntas de seguimiento («¿y esa IP?») |
| Arranque del proceso hijo | 346 ms, una vez | Se reutiliza entre peticiones |
| Primera herramienta | ~6,3 s | Va contra `/api/argos/live` |
| Siguientes | ~2 ms | Caché de 30 s dentro del servidor MCP |

Las siete advertencias metodológicas del trabajo van en el *system prompt*, no
solo en las descripciones de las herramientas: son propiedades del proyecto, no
de una llamada concreta. Cubren el score de ventana, el dominio de validez
(atacantes ruidosos), la no transferencia a máquinas nuevas, el sesgo de la
severidad CRITICAL hacia Trivy, el bloque CSR-LANL y la concentración del
simulacro.

**La respuesta es auditable.** El panel muestra encima de cada contestación qué
herramientas se invocaron, con qué argumentos y cuánto tardaron. Sin esa traza,
la respuesta de un modelo sobre datos de seguridad es una caja negra.

#### Motor `keywords` — respaldo determinista

Sin credencial, o si los motores de lenguaje natural fallan (CLI no instalado,
agotado su tiempo, clave inválida, sin saldo, servidor MCP caído), responde el
comparador de palabras clave de siempre:
normaliza el texto, busca términos como «severidad» o «reciente», extrae un
número con una expresión regular y rellena una plantilla con datos reales. La
pantalla se degrada, no se rompe, **y lo declara**: la respuesta incluye por qué
falló cada motor anterior, porque un fallo silencioso que responde peor es
indistinguible de que el modelo sepa menos. Verificado forzando un tiempo de
espera de 2 s en el CLI: `engine=keywords`,
`degraded="cli: El CLI no respondio en 2 s"`, respuesta correcta.

---

## 11. Lo que se corrigió, y lo que sigue siendo limitación

### Corregido

| Elemento | Antes | Ahora |
|---|---|---|
| Barra superior | `MCP · 12 AGENTS`, `SURICATA · RUNNING` fijos | `MANAGER`, `INDEXER`, `ALERTAS` medidos |
| Top targets | `96/87/78/69` decorativos | Recuento real de alertas por agente |
| Correlation sources | Suricata y Zeek siempre a cero | Los cuatro enriquecimientos que sí se aplican |
| Línea temporal | Reparto por posición en la lista | Agrupación por hora real |
| Geolocalización | Puntos sintéticos indistinguibles | Marcados `(aprox.)` y separados en salud |
| Fila `MCP Agents` | Permanentemente `planned` | Retirada |
| Chat «MCP» | El nombre sugería una integración MCP que no existía | Integración MCP real: la web hace de host y consulta las siete herramientas |

### Limitaciones que permanecen, por diseño o por alcance

| Elemento | Situación |
|---|---|
| Suricata y Zeek | **No integrados.** Ya no aparecen en ninguna métrica de panel. El campo `Suricata SID` de la ficha de detalle sigue existiendo y vale siempre `N/A`. |
| MCP | **Integrado.** Servidor propio (`deploy/argos_mcp/server.ts`, siete herramientas de solo lectura) consumible desde Claude Desktop, Claude Code o el propio panel. El campo `MCP tool` de la ficha de detalle **no** tiene relación: es una etiqueta de tipo de alerta con nombre heredado y anterior. |
| Campo `Sensores` | Siempre `Wazuh / AI Engine`. Solo hay una fuente real. |
| Campo `Agente` en la ficha | Duplica «Destino». |
| Bloque CSR-LANL | Visible pero **no interpretable**: el adaptador rellena con cero las familias de datos que Wazuh no produce. Ver sección 3.1. |
| Ventana de la gráfica temporal | Solo cubre lo que quepa en 10.000 alertas (~5 h). |
| Geolocalización aproximada | Sigue existiendo, pero ahora está declarada. |
| Chat | El motor de suscripción depende de que el CLI de Claude Code esté instalado y con sesión iniciada; si se desinstala, cae a la API o a reglas. Lanza un agente local, así que el endpoint **no debe exponerse fuera de localhost**. |
| `AI Score` de ventana | Satura y no distingue entre atacantes del mismo minuto. Se mantiene junto al riesgo por IP, que sí discrimina. |

## 12. Cómo levantarlo

```bash
# 1. Sidecar: modelos en memoria. Sin él todo funciona, pero a 15 s por refresco.
.venv/Scripts/python.exe deploy/argos_scorer/service.py

# 2. Web
npm run dev            # desarrollo (webpack)
# o
npx next build && npx next start -p 3000    # producción, 3-4x más rápido
```

Si reinicias, **mata los procesos anteriores por PID**: los huérfanos siguen
ocupando el puerto y el nuevo no llega a arrancar, con lo que seguirías viendo
el código antiguo.

---

*Documento generado el 6 de septiembre de 2026 y actualizado tras corregir
los elementos listados en la sección 11. Las cifras marcadas como
medidas proceden de la exportación de 30 días (1.462.265 alertas) y de
mediciones sobre el despliegue en vivo.*

# ARGOS-SOC IA — Dossier completo del TFM

Documento único: la línea argumental del trabajo, todos sus resultados medidos y
el inventario completo de la aplicación, pantalla a pantalla y métrica a
métrica. Nada remite a otro fichero para entenderse.

> **Convención de procedencia**, usada en todo el documento:
> **[real]** calculado sobre datos vivos · **[fijo]** valor escrito en el
> código, no refleja estado · **[derivado]** calculado a partir de otra
> métrica · **[externo]** viene de un servicio de terceros.

---

## 0. Cómo usar este documento

**Qué es.** La fuente completa para redactar la memoria. Cada cifra lleva su
procedencia y cada concepto se explica antes de usarse.

| Parte | Secciones | Para qué capítulo |
|---|---|---|
| **I · El trabajo** | 1–7 | Planteamiento, método, resultados y discusión |
| **II · La plataforma** | 8–20 | La herramienta construida; limitaciones en 19.2 y 19.3 |
| **III · Cierre** | 21–23 | Trabajo futuro, reproducibilidad y qué no se puede afirmar |

**Es autosuficiente.** No hace falta leer ningún otro fichero del repositorio
para redactar la memoria: el porqué de cada decisión de modelado, el montaje
experimental, los resultados y los límites están aquí. Los ficheros del
repositorio que se citan lo son como **procedencia del dato** —de dónde salió
una cifra, qué comando la reproduce—, nunca como lectura obligatoria.

> **Advertencia que gobierna todo el documento.** La aportación de este trabajo
> son en buena parte **resultados negativos**. Redactarlo como si se hubiera
> construido un detector que funciona sería a la vez falso y más débil: lo que
> se sostiene es haber medido *por qué* las cifras iniciales eran un artefacto.
> La sección 23 lista las frases que no se pueden escribir.

---

# PARTE I · EL TRABAJO DE INVESTIGACIÓN

## 1. El problema, la hipótesis y qué ocurrió

### El problema

Un SOC recibe más alertas de las que puede revisar. Medido en este laboratorio:
**~53.000 eventos en 24 h**, unas **37 alertas por minuto**. Ninguna persona
revisa eso. La pregunta del trabajo es si el aprendizaje automático puede
reducir esa carga sin perder los ataques que importan.

### La hipótesis inicial

Entrenar un clasificador binario «¿esta alerta es un ataque?» sobre las alertas
de Wazuh, y usar su probabilidad para priorizar.

### Qué ocurrió

El clasificador alcanzó **ROC-AUC 0,9990**. Y ese número resultó ser **un
artefacto**, no un logro. La sección 3 explica por qué, y es el hallazgo
central del trabajo.

**La línea argumental de la memoria, en una frase:** se construyó el detector
obvio, se midió que su éxito era circular, se rediseñó la pregunta, y se midió
honestamente cuánto queda — que es bastante menos y bastante más interesante.

---

## 2. Los datos

### La infraestructura

Wazuh desplegado con manager, indexer (OpenSearch) y agentes sobre máquinas
reales expuestas a internet, incluido un honeypot. El tráfico es **real y no
solicitado**: no hay simulación de ataques.

| Magnitud | Valor |
|---|---|
| Alertas exportadas para análisis | **1.462.265** |
| Tamaño del volcado | 1,49 GB (JSONL) |
| Periodo | 30 días |
| Tiempo de exportación | 476 s, 0 registros malformados |
| Agentes en el inventario | 20 (4 activos en el momento de medir) |
| Índice | `wazuh-alerts-*`, ~56,5 M documentos |

Producido por `GET /api/argos/dataset` (ver `lib/dataset-export.ts`).

### 2.1 El montaje experimental

**Qué se desplegó.** Wazuh completo sobre máquinas reales expuestas a internet:

| Componente | Papel |
|---|---|
| **Wazuh Manager** | Recibe la telemetría de los agentes, aplica el motor de reglas y expone una API REST. |
| **Wazuh Indexer** (OpenSearch) | Almacena las alertas indexadas. Índice `wazuh-alerts-*`, ~56,5 M documentos. |
| **Agentes** | 20 en inventario, 4 activos en el momento de medir. Incluyen un **honeypot** (T-Pot/Cowrie) y servidores Linux de servicio. |
| **Escáner de vulnerabilidades** (Trivy) | Inventaría paquetes con CVE conocido. Genera alertas sin atacante. |

**Por qué importa que sean máquinas reales.** El tráfico hostil es **real y no
solicitado**: no hay simulación de ataques ni inyección de tráfico. Eso da
validez externa al fenómeno observado, pero también impone la limitación
central del trabajo — no hay forma de saber qué tráfico *legítimo* hubo, porque
Wazuh solo indexa lo que dispara una regla.

**La heterogeneidad de fuentes es parte del problema.** Conviven en el mismo
índice dos poblaciones que no se parecen:

- **Alertas con atacante**: fuerza bruta SSH, escaneo, spraying. Tienen IP de
  origen, usuario probado, puerto. Son sobre las que se puede decidir un
  bloqueo.
- **Alertas sin atacante**: hallazgos del escáner de vulnerabilidades y eventos
  del sistema. No tienen IP de origen. **Ninguna decisión de bloqueo aplica.**

La proporción entre ambas **oscila mucho** según lo que domine la ventana
observada: medido entre el 2 % y el 82 % sin dirección de origen en distintos
refrescos. Cualquier métrica agregada sobre «las alertas» sin distinguirlas es
engañosa, y esa es una de las razones de la regla de desglose obligatorio
(§6.3).

### 2.2 Consideraciones de seguridad del despliegue

Reglas que se impusieron al construir la aplicación, relevantes porque una
herramienta de seguridad mal construida es una vulnerabilidad más:

1. **Ninguna llamada a Wazuh desde el navegador.** Todo pasa por rutas de
   servidor; las credenciales nunca llegan al cliente.
2. **Credenciales solo en variables de entorno** (`.env.local`, fuera del
   control de versiones). Ni usuario, ni contraseña, ni token, ni IP sensible
   escritos en el código.
3. **Los endpoints internos devuelven datos ya filtrados y normalizados**, no
   la respuesta cruda de Wazuh, que contiene campos que no deben salir.
4. **El sidecar de modelos escucha solo en loopback** y rechaza arrancar con
   `--host 0.0.0.0` (comprobación automatizada en su batería de pruebas). Es un
   proceso que decide bloqueos: no debe ser alcanzable desde la red.
5. **`NODE_TLS_REJECT_UNAUTHORIZED=0` solo en laboratorio** y documentado,
   porque el Wazuh de pruebas usa certificado autofirmado. En producción sería
   inaceptable.
6. **El asistente conversacional lanza un agente local**, acotado a siete
   herramientas de solo lectura con las de escritura denegadas explícitamente.
   Aun así, la aplicación no debe exponerse fuera de localhost con ese motor
   activo (§18.1).

---

### El problema de las etiquetas

**No hay clase benigna.** Wazuh solo indexa lo que dispara una regla, así que
el volcado contiene ataques y hallazgos de inventario, no tráfico normal. Las
etiquetas se derivaron por **etiquetado débil** (*weak labelling*): agrupando
las reglas que dispararon en familias de ataque, benigno y postura.

Esa decisión es el origen de todo lo que viene después.

---

## 3. El hallazgo central: circularidad

### Qué es la circularidad de etiqueta

Cuando la etiqueta que se quiere predecir se deriva de los mismos datos que se
usan como entrada, el modelo no aprende el fenómeno: **reconstruye la regla que
generó la etiqueta**. La métrica sale excelente y no significa nada.

### Cómo se midió

Una sola columna, `mitre_tagged_ratio`, **reproduce la etiqueta con ROC-AUC
0,9990** — idéntico al modelo completo de 98 variables. El «detector» estaba
descubriendo que las alertas etiquetadas por MITRE son las etiquetadas como
ataque, lo cual es una tautología.

**Consecuencia de diseño:** los campos `rule_*`, `mitre_*` y `decoder_name`
quedan **prohibidos** en todos los modelos del paquete. Hay un guardia de tipos
en `lib/argos-scorer-client.ts` que impide reintroducirlos por descuido.

### La severidad también estaba invertida

Se descartó etiquetar por `rule_level` porque sale del mismo motor **y está
invertido en estos datos**: nivel 14 = hallazgo benigno de Trivy; nivel 5 = la
fuerza bruta real. La regla «nivel ≥ 10 ⇒ ataque» **erraría el 70,8 %** de lo
que captura.

### La huella de máquina: un segundo atajo

Con 54 variables de conducta —sin `agent_id` entre ellas— se predice **qué
agente es con 99,75 % de exactitud**. Cada máquina deja una huella repartida de
forma redundante entre variables correlacionadas: el host escáner tiene
`src_ip_present_ratio` 0,075 y 2.072 alertas por ventana; el honeypot, 0 IPs y
1,5.

Quitar una columna no elimina un confundido distribuido. **Consecuencia
medida:** un modelo global entrenado en unos hosts cae a **MCC 0,000** en otro.

---

## 4. El rediseño: cambiar la pregunta

La pregunta pasó de «¿es esto un ataque?» a **«¿la conducta de esta dirección IP
justifica bloquearla?»**.

### La etiqueta nueva

No viene de ninguna regla. Una IP merece bloqueo si su conducta observada lo
justifica:

- **≥ 5 cuentas distintas probadas**, o
- **≥ 2 máquinas alcanzadas**, o
- **≥ 50 intentos en ≥ 3 ventanas**

Computada de forma **causal** (solo con el pasado) a partir de cinco campos de
hechos: `timestamp`, `agent_id`, `src_ip`, `src_port`, `src_user`/`dst_user`.

### Y se auditó con el mismo método que destapó el problema

La mejor sonda de una sola variable llega a **0,6641** (contra 0,9990 de la
etiqueta débil): **no reconstruible, circularidad rota**.

El efecto es medible y es el argumento más fuerte del trabajo:

| Etiqueta | Traslado entre hosts |
|---|---|
| Débil (derivada de reglas) | MCC **0,000** — colapso total |
| Conductual (esta) | retiene el **65–104 %** |

> **El problema nunca fue el modelo: era la pregunta.** Esa frase resume el TFM.

---

### 4.1 Los cuatro servicios que resultaron, y sus garantías medidas

El paquete de modelos expone cuatro servicios. Los tres primeros están en
producción; el cuarto, en modo sombra.

#### `EarlyBlockScorer` — bloqueo temprano de IPs (el principal)

Mantiene el perfil de cada dirección y, con cada aviso, reevalúa. En los
presupuestos **K = 1, 2, 3, 5, 10, 20** avisos puntúa con el modelo de ese K y
**bloquea al primer cruce de umbral**. Convierte un IDS en un IPS: cada acierto
temprano suprime todo lo que esa IP habría generado después.

| Métrica | Interno (mes de test) | Externo (otro entorno, un disparo) |
|---|---|---|
| Recall de IPs bloqueables | **0,990** | **0,994** |
| Precisión | **0,995** (3 falsos al mes) | ≥ 0,898 (suelo por censura de 11 h) |
| Mediana de corte | 5.º aviso | 5.º aviso |
| Volumen de ataque evitado | **89 %** | 91 % |

Devuelve, además del score, la **evidencia**: cuentas probadas, máquinas
alcanzadas y reputación de la subred. El analista ve *por qué*, no solo un
número.

#### `WindowBlockScorer` — probabilidad de bloqueo por ventana

Puntúa un minuto completo de un agente. Medido: **lift 43,5× / 20,0×** dentro
de cada host; transferido a otro host retiene el **65–104 %**; validación
externa **MCC 0,343** en hosts jamás vistos, frente a **0,000** de la
aproximación anterior con etiqueta débil.

#### `ActivityScorer` — familia de actividad con rechazo

Clasifica la ventana en su familia (`CredentialBrute`, `SshOperational`,
`PortChange`, `AgentHealth`…), con **un modelo por host**, probabilidades
calibradas por regresión isotónica y **rechazo de actividad desconocida**: si la
confianza cae bajo el umbral del host devuelve `is_unknown`, que va a cola de
revisión humana. Medido: el rechazo captura hasta el **99,8 %** de una familia
de ataque nunca vista.

#### `AttentionBlockScorer` / `ConsensusBlockScorer` — segunda opinión

Encoder de atención (2 bloques pre-LN, 4 cabezas, d = 32, ~18.369 parámetros
por K), con la secuencia de los primeros K avisos como fichas e inferencia en
**numpy puro** — el paquete sigue sin PyTorch. Cada construcción verifica que
numpy reproduce al modelo entrenado: **máx. |diff| 3,5·10⁻⁷** en 3.595
evaluaciones.

| Política | Recall | Precisión | Legítimas cortadas/mes | Ataque evitado |
|---|---|---|---|---|
| HGB (el principal) | 0,990 | 0,995 | 3 | 89,3 % |
| Atención sola | 0,992 | 0,992 | 5 | 90,2 % |
| Consenso **OR** | 0,995 | 0,990 | 6 | 93,9 % |
| Consenso **AND** | 0,985 | **0,997** | **2** | 85,5 % |

**Todas cortan en la mediana del 5.º aviso.** Test interno, **sin validación
externa**: el presupuesto está gastado (§5).

> **`K = 1` está excluido a propósito.** Ahí el Transformer ordena mejor
> (AUC 0,86 frente a 0,83), pero su umbral **no traslada de validación a test**
> y la política cae a precisión 0,976, por debajo del 0,99 exigido. Se prefiere
> no opinar a opinar mal.

> **No se pueden ejecutar los dos a la vez sobre el mismo estado vivo**: cada
> uno registraría la IP como hostil y la reputación de subred contaría doble.
> Para combinarlos existe `ConsensusBlockScorer`, que comparte perfil y estado.

### 4.2 Por qué la política es secuencial

A presupuesto fijo —decidir con exactamente 5 avisos— el recall era **0,82**. La
mejora **no vino de un modelo mejor sino del planteamiento**: reevaluar con cada
aviso y bloquear al primer cruce lleva el recall a **0,990** manteniendo la
mediana en el 5.º aviso.

La **reputación causal de subred** aporta lo que ningún agregado propio puede:
sospechar de una IP **desde su primer aviso** si su /24 ya produjo hostiles. Las
botnets se agrupan en rangos.

Y los umbrales se fijan a **precisión ≥ 0,99**, no a F1 óptimo, porque bloquear
a un legítimo cuesta más que dejar pasar avisos. **El mando es la precisión.**

### 4.3 Inventario de modelos

| Fichero | Servicio | Entrenamiento |
|---|---|---|
| `early_block_K{1,2,3,5,10,20}.joblib` | EarlyBlockScorer | 3.354 IPs (train), umbral p99 sobre 719 IPs (validación) |
| `window_block.joblib` | WindowBlockScorer | 56.883 ventanas, calibrado isotónico |
| `activity_scorer.joblib` | ActivityScorer | Por host (000/011/030) + global, calibrado y con rechazo |
| `attention_block.npz` | AttentionBlockScorer | 5 transformers (K = 2, 3, 5, 10, 20), mismas 3.354 IPs; 414 KB |
| `config.json` | Todos | Listas de variables (**el orden manda**), umbrales y notas de validación |

**Semilla 42 en todo. Reproducible de extremo a extremo.** Peso total de los
modelos: **6,6 MB**, sin GPU, inferencia en microsegundos.

---

## 5. Metodología de validación

Lo que hace defendible el trabajo no son las cifras, es cómo se obtuvieron.

| Práctica | Qué evita |
|---|---|
| **Particiones temporales**, nunca aleatorias | Una partición aleatoria sobre datos con estructura temporal produce ~0,99 que no se sostiene. Se reprodujo el mismo colapso en **CIC-IDS2017 y UNSW-NB15**. |
| **Validación externa de un solo disparo** | Canalización congelada, una única ejecución contra un segundo entorno, reportada tal cual. Los dos presupuestos están **gastados**. |
| **Contra ground truth real** (CSR-LANL, equipo rojo auténtico) | Comprobar si las variables conductuales sirven fuera del laboratorio. |
| **Ninguna métrica agregada sin desglose por grupo** | Ver §6.3: esta regla nació de un error propio. |
| **MCC además de exactitud** | Con prevalencia del 98,6 %, la exactitud es casi inútil. |

Que el presupuesto de validación externa esté **gastado** es relevante para la
memoria: cualquier afirmación externa nueva exigiría captura nueva. Se dice, no
se esconde.

---

## 6. Resultados medidos

### 6.1 Ablación: cuánto vale el modelo sobre la línea base

Fuente: `experiments/results/shortcut_ablation.json` · 81.589 ventanas,
prevalencia 0,9787, semilla 42.

| Variante | Exactitud | MCC | Ganancia sobre línea base |
|---|---|---|---|
| **A** · 16 variables del modelo activo | 0,9978 | 0,9246 | **+0,0114** |
| **B** · sin identidad de máquina | 0,9978 | 0,9254 | +0,0114 |
| **C** · sin identidad ni motor de reglas | 0,9973 | 0,9092 | +0,0109 |
| **D** · C + sin ventanas de postura | 0,9971 | **0,6813** | **−0,0002** |

**Cómo leerlo, y es incómodo:**

1. La **línea base** —responder siempre «ataque»— acierta el **98,64 %**. El
   modelo llega al 99,78 %: **aporta 1,14 puntos**. Ese es el tamaño real de la
   contribución del aprendizaje automático a esta tarea.
2. **B ≈ A**: quitar la identidad de máquina no cambia nada. Esa variable no
   estaba aportando.
3. **D es el resultado que importa**: al quitar las ventanas de postura, el MCC
   se desploma de 0,909 a **0,681** y la ganancia sobre la línea base pasa a ser
   **negativa**. El modelo deja de ser mejor que responder siempre lo mismo.

### 6.2 Leave-one-agent-out: ¿generaliza a una máquina nueva?

Mismo fichero. Se entrena con todos los agentes menos uno y se prueba en el que
quedó fuera.

| Agente | n test | Prevalencia | Exactitud | MCC | Ganancia |
|---|---|---|---|---|---|
| 000 | 40.958 | 0,9982 | 0,9986 | 0,5874 | +0,0004 |
| 003 | 193 | 0,2176 | 0,9223 | 0,7666 | +0,1399 |
| **011** | 39.279 | 0,9882 | 0,7882 | 0,0904 | **−0,2000** |
| **030** | 1.159 | 0,0958 | 0,9042 | **0,0000** | 0,0000 |

**El modelo no transfiere.** En el agente 011 es **20 puntos peor** que la línea
base. En el 030 el MCC es **exactamente 0**: predice una sola clase.

El único caso bueno (agente 003, +0,14) tiene **193 muestras** — demasiado
pequeño para sostener una afirmación.

### 6.3 El detector de anomalías retirado — y la regla que nació de él

Un autoencoder no supervisado llegó a presentarse como el mejor resultado:
**18,3× sobre el azar**. **Retirado.** Desglosado por agente, cada host estaba
en el azar o por debajo (**0,57×–0,95×**). El agregado venía de que la clase
rara se concentraba en un solo agente: **paradoja de Simpson**. Ajustarlo por
host tampoco funcionó (lift medio 0,73×).

De ese fallo nace la regla que gobierna todo el trabajo y toda la interfaz:
**ninguna métrica agregada sin su desglose por grupo.**

Es material de memoria de primer orden: un error propio, detectado, medido y
convertido en método.

### 6.4 El aprendizaje profundo no aportó ventaja — tres veces

| Arquitectura | Resultado |
|---|---|
| Autoencoder no supervisado | Retirado (§6.3) |
| GRU sobre la secuencia de avisos | **Empate exacto**: AUC 0,9702 vs 0,9703 |
| Transformer de atención (2 bloques, 4 cabezas, ~18.369 parámetros) | **Empate**: recall 0,991 vs 0,990; precisión 0,991 vs 0,993 |

**Tres pruebas, tres empates.** Y en el caso del Transformer la explicación es
interpretable: **la etiqueta cuenta hechos —cuántas cuentas, cuántas máquinas—
y no depende del orden**, que es justo lo que un modelo de secuencia sabría
aprovechar.

Los modelos en producción son **HistGradientBoosting**: igual de buenos, 6,6 MB
en total, sin GPU, inferencia en microsegundos.

> El Transformer se conserva **en modo sombra** por dos motivos que no son la
> detección: da **explicabilidad** (qué avisos pesaron, algo que el modelo
> principal no puede dar) y permite medir el **acuerdo entre dos modelos con
> sesgos inductivos distintos** sobre tráfico real. Acuerdo medido en vivo:
> **79–86 %** según el refresco. **No tiene validación externa.**

### 6.5 El score de ventana satura

Sobre 10.001 alertas cargadas: **13 valores distintos**, con el **96,8 % en
exactamente 100** y media **99,6**. El histograma tenía forma de **U** — la
firma de un clasificador que decide sí o no, no «cuánto».

Consecuencia práctica: promediarlo daba un «nivel de riesgo» que **no describía
a ninguna alerta**. Por eso el panel migró al riesgo por IP (49 valores
distintos, media 91,4).

---

### 6.6 CSR-LANL: la transferencia entre dominios que no funcionó

**Qué se intentó.** Si el laboratorio no tiene clase benigna real, ¿serviría un
modelo entrenado sobre un corpus público que **sí** tiene verdad de campo? Se
integró CSR-LANL: registros de autenticación, flujos de red, DNS y procesos, con
actividad de **equipo rojo auténtico** etiquetada. Trabaja con **209
características sobre ventanas de una hora agrupadas por entidad**, sobre
**13,1 millones de ventanas** y **16.155 entidades**.

**Qué se midió, en dos planos.**

*En su propio dominio*, las variables conductuales dan señal genuina frente a
compromisos reales: **ROC-AUC 0,96**. Pero a prevalencia 10⁻⁵ eso no basta:
**PR-AUC 0,0168** y precisión entre los cincuenta primeros resultados de
**0,040** — dos aciertos por cada cincuenta revisiones. Es el recordatorio de por
qué ROC-AUC engaña con clases muy desbalanceadas.

*Trasladado a ARGOS*, no es interpretable. El paquete exige las mismas 209
columnas y trata las ausentes como error de esquema; Wazuh **no produce** esas
familias de datos, así que el adaptador **rellena con cero** todo lo que falta.
Su propia salida lo declara: *«CSR-LANL model was trained on auth/flow/dns/proc
windows; ARGOS Wazuh adapter fills unavailable feature families with zero»*.

**Un modelo que recibe la mayoría de sus entradas a cero opera fuera de su
dominio.** Medido en vivo: el **100 %** de las entidades salen como
`low_signal`.

**Por qué se conserva visible.** Porque documenta una decisión del trabajo
—probar transferencia entre dominios y **medir que no funciona**— no porque
aporte señal. Es el tercer resultado negativo del trabajo, junto al autoencoder
(§6.3) y a los tres empates del aprendizaje profundo (§6.4). En la memoria vale
más como evidencia de método que como funcionalidad.

> Aviso de redacción: **no presentar CSR-LANL como una capa de detección
> operativa.** Sus cuatro campos aparecen en la ficha de detalle (§11.1) con la
> advertencia correspondiente, y ahí debe quedarse.

---

## 7. La contribución que no lleva aprendizaje automático

Fuente: `experiments/results/kev_epss_filter.json`.

Se cruzaron los CVE que reporta el escáner con dos fuentes públicas: **CISA
KEV** (catálogo de vulnerabilidades con explotación real confirmada) y **EPSS**
(probabilidad estimada de explotación en 30 días).

| Magnitud | Valor |
|---|---|
| Alertas de Trivy | 408.956 |
| CVE distintos | **5.839** |
| Con EPSS | 5.827 (12 sin puntuar) |
| **Accionables** (en KEV o EPSS ≥ 0,1) | **24** |
| **Factor de reducción** | **243×** |

Y el dato que da sentido al panel entero: **de los 28 CVE que Trivy marca
CRITICAL, ninguno está en KEV**; uno etiquetado MEDIUM sí. La severidad LOW
tiene un EPSS medio (0,00913) **superior** al de MEDIUM (0,00269).

> **Por qué esto importa para la tesis.** Es el resultado más útil
> operativamente de todo el trabajo —convierte una cola de revisión imposible en
> una lista de una mañana— y **no usa aprendizaje automático**. Responde a la
> pregunta del TFM de forma directa e incómoda: *en este dominio y a esta
> escala, elegir bien una fuente pública de datos aportó más que el modelo*.

---


---

# PARTE II · LA PLATAFORMA, PANTALLA A PANTALLA

Inventario completo: cada pantalla, cada métrica, cada KPI. Para cada uno se
explica **qué es el concepto** —con independencia de esta aplicación— y **qué
aporta aquí**, con su medición.

## 8. Arquitectura en una frase

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

## 9. Barra superior (`CommandTopbar`)

| Indicador | Origen | Qué representa |
|---|---|---|
| `MANAGER` | **[real]** | `ONLINE`/`OFFLINE` según responda `/manager/info`. |
| `INDEXER` | **[real]** | Si la consulta de alertas al Indexer tuvo éxito. |
| `ALERTAS` | **[real]** | Alertas cargadas en este refresco. |
| `RIESGO IP` | **[derivado]** | Media del **riesgo por IP** de las alertas que tienen dirección de origen. Antes era `AI SCORE`, la media del score de ventana, que saturaba en 99,6. Ver § 14.1. |
| `THREAT` | **[derivado]** | `HIGH` si hay más de una alerta crítica, si no `ELEVATED`. |

> **Sobre `THREAT`.** El *nivel de amenaza* es una convención de los centros de
> operaciones: un semáforo global para la sala. Aquí su umbral es trivial —más
> de una alerta crítica— y, como el 99,6 % de las críticas son hallazgos de
> inventario (§ 14.4), en la práctica **está siempre en `HIGH`**. Es un
> indicador decorativo heredado; no lo cites como medida.

> Aquí había antes `MCP · 12 AGENTS` y `SURICATA · RUNNING`, ambos escritos a
> mano. Retirados: ni Suricata está integrado, ni el `12 AGENTS` era medido.
> Sustituidos por estado del Indexer y recuento de alertas, que sí se miden.
> (El MCP sí está integrado hoy, pero como asistente conversacional —§ 18—, no
> como una flota de agentes.)

---

## 10. Barra lateral (`CommandSidebar`)

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
> conversacional (§ 18), y su estado se consulta en el propio widget.

---

## 11. Globo 3D (`AttackGlobe`)

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

`SEVERIDAD` · `TIPO` · `ORIGEN` · `IP` · `DESTINO` · `REGLA` · `RIESGO IP` · `CLASIFICACIÓN`

> **La columna de puntuación cambió.** Mostraba el `AI Score` de ventana; ahora
> muestra el **riesgo de la IP de origen**. El de ventana puntúa el minuto del
> agente y reparte el mismo número entre todas sus alertas: sobre 10.001
> alertas daba **13 valores distintos**, con el 96,8 % en exactamente 100. El de
> IP da **49**. Una columna en la que casi todas las filas ponen lo mismo no
> ayuda a priorizar, que es para lo que existe una tabla ordenable.
>
> El score de ventana **no se ha eliminado**: vive en la ficha de detalle, donde
> hay sitio para explicar qué es. El **2,0 %** de alertas sin IP de origen
> (Trivy, syscheck) muestran **`—`**, no un cero: no hay dirección a la que
> puntuar, que es distinto de puntuar bajo.

Al pulsar una fila se abre la **ficha de detalle**, documentada en la sección
11.1.

### 11.1 Ficha de detalle de una alerta

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
| **AI `<n>`** (cabecera) | Score de ventana ×100. **Es del minuto del agente, no de esta alerta.** Ver sección 13. |
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

#### Bloque «Segunda opinión (Transformer)»

Aparece debajo de la rejilla, separado, cuando la alerta tiene riesgo por IP.
Está fuera de la rejilla a propósito: es una **anotación**, no un campo más de
la alerta.

| Campo | Qué es | Qué aporta aquí |
|---|---|---|
| **Score** **[real]** | Salida del Transformer, 0–100 | Responde a la misma pregunta que `IP <n>`: ¿merece bloqueo esta dirección? |
| **Umbral (K=n)** **[fijo]** | Umbral del presupuesto en que se evaluó | Fijado a precisión ≥ 0,99 en validación. Hay uno por K |
| **Cruza umbral** **[derivado]** | Si dispararía | Comparado con el principal da el acuerdo de la cabecera |
| **Avisos decisivos** **[real]** | Los tres avisos con más peso de atención, en barras | **Lo único que el modelo principal no puede dar.** Dice dónde miró |

La cabecera marca `coincide` o `discrepa`, y el pie repite que es test interno
sin validación externa y que **el bloqueo lo decide el modelo principal**.

#### Etiquetas internas

| Campo | Qué representa | Estado |
|---|---|---|
| **Suricata SID** | Identificador de firma de Suricata. | **Siempre `N/A`.** Suricata no está integrado; medido sobre 10.001 alertas, un único valor. |
| **MCP tool** | Etiqueta de encaminamiento heredada. Tres valores: `auth.window` (95 %), `wazuh.triage` (5 %), `argos.local-simulator`. | Es una **clasificación de tipo de alerta**, no una herramienta MCP. El nombre es engañoso. |
| **Sensores** | Fuentes que contribuyeron. | **Siempre `Wazuh / AI Engine`.** Solo hay una fuente real. |

---

## 12. Feed de alertas (`ThreatFeed`)

Las **siete alertas más recientes**. Cada tarjeta lleva:

**Qué es un feed de alertas.** Es la vista de *triaje*: la cola por la que un
analista de guardia va pasando, ordenada por lo más reciente. Su función no es
analizar sino **decidir rápido si algo merece atención**, así que cada tarjeta
debe caber de un vistazo.

**Qué aporta aquí.** Es la única pantalla donde los cuatro enriquecimientos
aparecen **juntos sobre la misma alerta**: la severidad que dice Wazuh, el
score del modelo, el riesgo de la IP y si el CVE se explota de verdad. Ver los
cuatro a la vez es lo que permite detectar las contradicciones que documenta
§ 14.4 — una alerta CRITICAL con riesgo de IP bajo y sin explotación conocida es
inventario, no ataque.

### Bloque base

| Campo | Origen | Qué es | Qué aporta aquí |
|---|---|---|---|
| Severidad | **[real]** | Gravedad que asigna el autor de la regla | Traducción de `rule.level`: crítica ≥12, alta ≥9, media ≥6, baja el resto. **No mide riesgo real**; ver § 14.1. |
| Tipo | **[derivado]** | La técnica del ataque | Inferido por palabras clave de la descripción, no viene de Wazuh. El 98 % cae en dos categorías genéricas. |
| Origen → destino | **[real]** | Quién ataca a quién | Ciudad/país de la IP y nombre del agente. Lleva `(aprox.)` si la geolocalización es de reserva. |
| `AI <n>` | **[real]** | Score del modelo | Es de la **ventana** de un minuto del agente, no de esta alerta. Ver § 13. |
| `Rule <id>` | **[real]** | Identificador de la regla de Wazuh | Permite ir al origen y comprobar por qué saltó. Es el ancla de trazabilidad. |
| `mcpTool` | **[derivado]** | — | Etiqueta de encaminamiento heredada: `auth.window` (95 %), `wazuh.triage` (5 %), `argos.local-simulator`. **El nombre es engañoso**: no tiene relación con el MCP de § 18. |

### `IP <n>` — riesgo por dirección **[real]**

```
IP 98   45.156.87.93   2c · 1m · /24 100% · bloquearía en aviso 5 · 2ª opinión: coincide
```

Probabilidad que da el modelo a que **esa dirección** merezca bloqueo, según
lo que ha hecho: cuentas probadas (`c`), máquinas alcanzadas (`m`), reputación
hostil de su subred /24, y en qué aviso habría cortado.

Aparece solo en alertas con IP de origen. En la muestra medida son el **22,6 %**
de las alertas del panel; el resto (Trivy, syscheck, systemd) no tienen atacante
al que puntuar. De las IPs que sí aparecen, la cobertura es del **100 %**.

**El marcador final es la segunda opinión**, y admite tres textos:

| Texto | Origen | Qué significa |
|---|---|---|
| `2ª opinión: coincide` | **[derivado]** | Los dos modelos opinan lo mismo, bloqueen o no |
| `2ª opinión: discrepa` | **[derivado]** | Solo uno cruza su umbral |
| `sin 2ª opinión (1er aviso)` | **[fijo]** | El segundo modelo **no puntúa el primer aviso** |

El tercer caso no es un fallo ni un cero: es una decisión del paquete. El
presupuesto K = 1 se excluyó a propósito porque su umbral no trasladaba de
validación a test (la precisión caía a 0,976). Se dice en vez de callarlo,
porque un hueco silencioso se lee como acuerdo.

### Etiqueta de explotación real **[externo]**

```
EXPLOTADA EN LA VIDA REAL   CVE-2025-27363   EPSS 0.278
```

Tres estados: `EXPLOTADA EN LA VIDA REAL` (en el catálogo KEV de CISA),
`EXPLOTACIÓN PROBABLE` (EPSS ≥ 0,1), `SIN EXPLOTACIÓN CONOCIDA`.

---

## 13. Los tres scores de IA — la distinción que más importa

La aplicación muestra **tres números distintos**. Los dos primeros responden a
**preguntas distintas**, y confundirlos es el error más fácil de cometer al leer
el panel. El tercero responde a **la misma pregunta que el segundo**, con otro
modelo: no es una señal nueva, es una segunda opinión.

| | `AI <n>` (ventana) | `IP <n>` (dirección) | 2ª opinión (atención) |
|---|---|---|---|
| **Pregunta** | ¿Este minuto de este agente parece ataque? | ¿La conducta de esta IP justifica bloquearla? | **La misma que `IP <n>`** |
| **Unidad** | 1 minuto × agente | Dirección IP | Dirección IP |
| **Modelo** | LAB-ALERTS (`models_examples/`) | EarlyBlockScorer, HistGradientBoosting | Transformer de atención, 2 bloques y 4 cabezas |
| **Entradas** | 16 agregados del minuto | 22 variables de conducta de la IP | La **secuencia** de los primeros K avisos |
| **Usa campos del motor de reglas** | Sí (3 de 16) | **No, por diseño** | **No, por diseño** |
| **¿Decide?** | No, informa | **Sí** | **No: solo anota** |
| **Validación externa** | Sí | Sí | **No** |

### Qué es el Transformer de atención, y por qué se probó

**El concepto.** Un *Transformer* es una arquitectura de red neuronal que
procesa una **secuencia** y, en cada posición, aprende **a qué otras posiciones
mirar**. Ese mecanismo es la *atención*: en vez de resumir la secuencia en un
agregado, decide qué elementos pesan para la salida. Es lo que hay debajo de
los modelos de lenguaje actuales, aquí en una versión diminuta.

**Por qué tenía sentido probarlo en este problema.** El modelo principal recibe
**agregados** de la conducta de una IP: cuántas cuentas distintas probó,
cuántas máquinas alcanzó, cada cuánto llegaron los avisos. Ese resumen
**descarta el orden**. La hipótesis razonable era que el orden importa: no es
lo mismo probar tres cuentas en la misma máquina que ir saltando de máquina en
máquina. Un modelo de secuencia debería aprovechar eso.

**Qué se midió.** Dos bloques, cuatro cabezas, dimensión 32, unos 18.369
parámetros por presupuesto K, con la inferencia reescrita en **numpy puro**
—sin PyTorch— y verificada contra el modelo entrenado con una diferencia máxima
de 3,5·10⁻⁷. Cinco modelos, uno por K, que ocupan 414 KB en total.

**El resultado fue un empate**, y eso también es un hallazgo. La explicación es
interpretable y conviene decirla tal cual: **la etiqueta cuenta hechos, no
secuencias**. Si lo que define «atacante» es cuántas cuentas probó y cuántas
máquinas tocó, el orden en que lo hizo no añade información, y un modelo que
sabe aprovechar el orden no tiene de dónde sacar ventaja.

Es el mismo patrón que ya se había medido en el trabajo con otras dos
arquitecturas: un autoencoder no supervisado (retirado) y una GRU sobre la
secuencia de avisos, que empató en la cuarta cifra decimal (AUC 0,9702 frente a
0,9703). **Con datos tabulares agregados a esta escala, el aprendizaje profundo
no aportó ventaja medible en ninguna de las tres pruebas.** Los modelos que
quedan en producción son árboles de gradiente: igual de buenos, 6,6 MB, sin GPU
y con inferencia en microsegundos.

### El tercer score: para qué sirve si empata

Los dos modelos de IP **empatan** sobre tres semillas: recall 0,991 frente a
0,990, precisión 0,991 frente a 0,993, AUC medio por K 0,957 frente a 0,952.
El Transformer **no detecta mejor**, y la razón es interpretable: la etiqueta
cuenta hechos —cuántas cuentas, cuántas máquinas— y no depende del orden en que
ocurrieron, que es justo lo que un modelo de secuencia sabría aprovechar.

Entonces, ¿por qué está? Por dos cosas que el modelo principal no puede dar:

1. **Explicabilidad.** Dice **qué avisos pesaron** (`avisos_decisivos`, con su
   peso de atención). El HistGradientBoosting da un número; este dice dónde
   miró. En la ficha de detalle aparece como barras por aviso.
2. **Una segunda opinión con otro sesgo inductivo.** Medir su acuerdo con el
   modelo principal sobre tráfico real, semana a semana, es **la única
   validación que le queda**: el presupuesto de validación externa de
   LAB-ALERTS está gastado y no se puede volver a gastar.

#### Acuerdo medido en vivo **[real]**

Sobre las 10.001 alertas cargadas en un refresco:

| Métrica | Origen | Valor |
|---|---|---|
| Alertas con riesgo por IP | **[real]** | 8.951 (89,5 %) |
| De ellas, con segunda opinión | **[real]** | 8.935 |
| Sin segunda opinión, por ser primer aviso | **[real]** | 16 |
| IPs distintas evaluadas | **[real]** | 56 |
| Coinciden los dos modelos | **[derivado]** | 47 (84 %) |
| Discrepan | **[derivado]** | 9 (16 %): 7 solo el principal, 2 solo el Transformer |

Ese 84 % es **la métrica que justifica todo este servicio**: es la única forma
que queda de contrastar el Transformer fuera del laboratorio, porque el
presupuesto de validación externa está gastado. Sube o baja con el tráfico, así
que hay que leerlo como una serie que se vigila, no como un resultado cerrado.

#### Coste medido **[real]**

Contra la versión anterior del sidecar, mismo banco de pruebas:

| Ruta | Antes | Después | Por qué |
|---|---|---|---|
| `/ingest`, 300 eventos | 1.504,8 ms | 1.467,8 ms | Dentro del ruido: la atención solo corre en 5 presupuestos y son 18.369 parámetros en numpy |
| `/score`, 300 alertas | 401,7 ms | 438,4 ms | **+9,1 %.** Real y explicado: `/score` llama a `ip_risk`, que ahora calcula una segunda opinión por IP |
| `/simulate`, 400 alertas | 125,3 ms | 131,1 ms | +4,6 %, la matriz de acuerdo |
| `/window` | 18,2 ms | 17,4 ms | Sin cambio: la atención no interviene |

> **[externo]** · **Cifras del paquete, test interno, sin validación externa.** Política
> secuencial: HGB recall 0,990 / precisión 0,995; atención 0,992 / 0,992;
> consenso OR 0,995 / 0,990; consenso AND 0,985 / 0,997. Los cuatro cortan en
> la mediana del 5.º aviso. **No** se puede decir que el Transformer sea mejor,
> más preciso ni que generalice mejor.

### Por qué el primer aviso no tiene segunda opinión

El presupuesto K = 1 se **excluyó a propósito** del paquete: ahí el umbral no
trasladaba de validación a test y la precisión caía a 0,976, por debajo del
0,99 exigido. La interfaz lo declara —«sin 2ª opinión (1er aviso)»— en vez de
mostrar un cero o callarlo, porque un hueco silencioso se lee como acuerdo.

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

## 14. Panel analítico (`MiniDashboard`)

### 14.1 KPIs — las seis tarjetas de cabecera

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
*Correlación por fuente* (§ 14.2), y son cuatro enriquecimientos, no 1,7
millones de incidentes.

---

#### `IPs de riesgo alto` — 52 de 100 direcciones **[derivado]**

**Qué es.** Cuántas de las direcciones vistas superan el umbral de riesgo alto
(≥ 90 sobre 100) según el modelo de bloqueo por IP.

**Qué aporta aquí.** Es la **cola de trabajo real**: no cuántas alertas hay,
sino a cuántos *atacantes distintos* habría que mirar. Medido: **52 de 100**
direcciones. Esa es una lista revisable por una persona; 10.001 alertas no.

> **Qué había antes: `Anomalías IA`.** Contaba las alertas cuyo score de ventana
> superaba 70 — y ese umbral **lo cruzaba el 100 % de ellas**, así que el KPI no
> filtraba nada. El nombre además era incorrecto: una *anomalía* implica un
> método **no supervisado** (aprender lo normal y marcar lo que se sale), y ese
> modelo es supervisado.
>
> Se cuenta por **dirección, no por alerta**. Contando alertas salían 6.451 bajo
> una etiqueta que dice «IPs», cuando hay un centenar de direcciones: unas
> decenas de IPs generan miles de alertas.

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
el ataque. El contraste completo está en § 14.4.

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

#### `Riesgo IP medio` — 91 **[derivado]**

**Qué es.** Un *nivel de riesgo agregado* resume en un número el estado general
de la plataforma promediando los scores individuales. Es un patrón habitual en
paneles comerciales, y solo tiene sentido si el score que se promedia varía.

**Qué aporta aquí.** Media del riesgo por IP sobre las alertas que **tienen
dirección de origen**; el 2,0 % restante se **excluye** del promedio en vez de
contar como cero, porque no hay a quién puntuar y un cero hundiría la media.

Medido: media **91** sobre **49 valores distintos**. Es alto, y es coherente con
el resto del panel: de 100 direcciones vistas, 52 superan el umbral de riesgo
alto. Este laboratorio recibe sobre todo tráfico hostil.

> **Qué había antes: `AI Risk`, la media del score de ventana.** Ese score no es
> continuo, es prácticamente binario: **13 valores distintos** sobre 10.001
> alertas, con el **96,8 % en exactamente 100** y media 99,6. Promediar una
> distribución así da un número que **no describe a ninguna alerta**.
>
> El cambio no es cosmético: sustituye una media saturada por una que sí se
> mueve. Lo que **no** cambia es la advertencia de § 13 sobre el score de ventana,
> que sigue existiendo en la ficha de detalle y sigue saturando.

### 14.2 Gráficas

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

**Qué aporta aquí.** Es la entrada al hallazgo de § 14.4: la pirámide existe,
pero **está mal poblada**. Lo crítico es inventario y lo bajo son ataques. La
gráfica por sí sola induce a error; solo tiene valor leída junto al contraste
de explotación real.

#### `Volumen por tramo y cuánto viene de IPs peligrosas` **[real]**

**Qué es.** Una *serie temporal* reparte los eventos por su marca de tiempo.
Sirve para ver campañas: un pico a una hora concreta sugiere una acción
coordinada, un caudal plano sugiere ruido de fondo automatizado.

**Qué aporta aquí.** Ocho columnas apiladas, una por tramo de tres horas,
agrupadas por la **hora real** de cada alerta. La altura total es el volumen; el
segmento destacado son las alertas cuya **IP tiene riesgo ≥ 0,9**. Responde a
una pregunta que el volumen solo no contesta: *¿este pico es peligroso o es
ruido?*

Medido en una ejecución:

| Tramo | Alertas | De riesgo alto | % | IPs distintas |
|---|---|---|---|---|
| 09h | 2.023 | 1.782 | **88 %** | 42 |
| 12h | 2.790 | 2.012 | 72 % | 51 |
| 15h | 1.406 | 994 | 71 % | 43 |
| 18h | 3.782 | 1.695 | **45 %** | 60 |

**El hallazgo que la versión anterior escondía:** el tramo con más alertas (18h)
es el que **menos** riesgo concentra. Un analista que priorice por altura de
barra atacaría el problema equivocado.

Cada columna con datos lleva su porcentaje encima, y el tramo de mayor
proporción va resaltado en cian. Las columnas vacías **no** llevan etiqueta: un
«0 %» ahí diría que nada fue peligroso, cuando lo que ocurre es que no hay
alertas cargadas en ese tramo.

> **Por qué se cambió, y qué había antes.** La gráfica era de dos líneas:
> alertas totales y alertas con `AI Score ≥ 70`. Ese umbral **lo cruzaba el
> 100 % de las alertas** —el 96,8 % puntúa exactamente 100—, así que las dos
> líneas caían una sobre otra y no aportaban nada más que el volumen. Era otra
> manifestación de la saturación descrita en § 13.
>
> Se descartó poner **IPs distintas** como segunda serie, aunque es informativa
> (31–62 por tramo): obligaría a un segundo eje Y, y dos escalas en un mismo
> plot inventan una correlación que no está en los datos. Va en el tooltip.
>
> El cambio de líneas a columnas no es estético. Una línea **interpola**: dibuja
> una pendiente entre las 12h y las 15h como si hubiera algo en medio, y con
> tramos vacíos trazaba caídas suaves hasta cero que sugerían un descenso
> gradual que no ocurrió — esas alertas simplemente ya no están cargadas.

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

#### `Reparto de riesgo por IP` **[derivado]**

**Qué es.** Un *histograma* del score: cuántas alertas caen en cada tramo. En un
modelo bien calibrado se espera una curva repartida, no dos montones en los
extremos.

**Qué aporta aquí.** Ocho tramos de 12,5 puntos sobre el **riesgo por IP**.
Medido ahora, los ocho tramos tienen población:

| Tramo | Alertas | % |
|---|---|---|
| 0–12,5 | 11 | 0,1 % |
| 12,5–25 | 38 | 0,4 % |
| 25–37,5 | 91 | 0,9 % |
| 37,5–50 | 78 | 0,8 % |
| 50–62,5 | 53 | 0,5 % |
| 62,5–75 | 350 | 3,6 % |
| 75–87,5 | 2.010 | 20,5 % |
| 87,5–100 | 7.168 | **73,2 %** |

La distribución está **cargada hacia arriba** —lo esperable en un laboratorio
que recibe sobre todo tráfico hostil— pero es una curva, no dos picos. Al pulsar
un tramo se abre el detalle con los scores exactos que lo componen.

> **La suma de los tramos NO es el total de alertas cargadas, y la gráfica lo
> declara.** Solo entran las que tienen IP de origen. Los hallazgos del escáner
> de vulnerabilidades y los eventos del sistema **no tienen atacante al que
> puntuar**, así que quedan fuera.
>
> Esa proporción **oscila muchísimo** entre refrescos, según qué domine la
> ventana de 10.000 alertas: medido, entre el **2 % y el 82 %** sin dirección.
> Una ráfaga del escáner puede dejar el reparto sobre menos de 2.000 alertas.
> Por eso la cobertura va escrita debajo del reparto: sin ella, quien sume los
> ocho tramos encuentra un agujero sin explicación.
>
> **Consecuencia para la lectura:** el `Riesgo IP medio` y las `IPs de riesgo
> alto` se calculan sobre esa misma base variable. Son cifras sobre el tráfico
> con atacante identificable, no sobre todas las alertas.

> **Qué había antes.** El mismo histograma sobre el score de **ventana**, y
> tenía forma de **U**: 5.412 alertas en el primer tramo y 4.482 en el último,
> con los seis intermedios casi vacíos. Esa forma es la firma de un clasificador
> que **no gradúa**: decide sí o no, no «cuánto». Era la prueba visual de la
> saturación, y por eso se cambió la serie en toda la aplicación.

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

### 14.3 Criminal Intelligence — AbuseIPDB **[externo]**

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

### 14.4 Explotación real — CISA KEV + EPSS **[externo]**

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

## 15. Simulacro (`/simulacro`)

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

### Selector de política y matriz de acuerdo

**Qué es.** El simulacro es un **banco de pruebas**, así que permite elegir qué
modelo decide dentro de él. Cuatro opciones:

| Política | Quién decide | Test interno (recall / precisión) **[externo]** |
|---|---|---|
| **Principal (HGB)** — por defecto | El modelo que decide hoy | 0,990 / 0,995 |
| **Transformer solo** | La segunda opinión, sola | 0,992 / 0,992 |
| **Consenso OR** | Cualquiera que cruce su umbral | 0,995 / 0,990 |
| **Consenso AND** | Solo si cruzan los dos | 0,985 / 0,997 |

**Qué aporta, y qué NO cambia.** Cambiar esto **no cambia quién decide en la
plataforma**: en la ingesta real bloquea siempre el modelo principal, que es el
único con validación externa. El selector existe para poder ver el efecto de
cada política antes de proponer ninguna, con la relación esperada: `AND` corta
menos y más fino, `OR` corta más y admite más error.

**La matriz de acuerdo** reparte las IPs con ≥ 2 avisos en cuatro casillas:
ambos bloquearían, solo el principal, solo el Transformer, ninguno. Se evalúa
en el mayor presupuesto común alcanzado por cada IP.

Va con **desglose por agente destino**, como exige la convención. Aviso
necesario: una IP que alcanza varias máquinas cuenta en cada fila, así que
**las filas suman más que el total** — es un reparto, no una partición.

Medido **[real]** sobre una ventana de 6 h y 3.000 alertas (18 IPs con origen
de red, 14 evaluables):

| Política | Bloqueos | ambos | solo principal | solo Transformer | ninguno |
|---|---|---|---|---|---|
| Principal | 9 | 7 | 1 | 1 | 5 |
| Transformer | 10 | 6 | 0 | 4 | 5 |
| OR | 10 | 5 | 2 | 3 | 5 |
| AND | 9 | 9 | 0 | 1 | 5 |

Cada veredicto muestra además sus **avisos decisivos enlazados** con la alerta
concreta del lote reproducido (`aviso #5 → alerta 53`), para poder ir a
mirarla. Con la política por defecto se anotan sobre el veredicto del HGB, que
por sí solo no los produce.

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

### 15.1 Modo sombra — y por qué no es lo mismo que el simulacro

**Qué es el modo sombra.** Es la práctica estándar antes de dar poder a un
sistema automático: se le deja **decidir de verdad, sobre tráfico real y en
tiempo real**, pero sus decisiones **no se ejecutan**. Se anotan. Después se
revisa qué habría hecho, y solo si el registro convence se le da el control.

Es la diferencia entre *«el modelo acierta en mis pruebas»* y *«el modelo
acierta sobre lo que llega de verdad, y aquí está la lista de lo que habría
hecho durante tres semanas»*. Lo segundo es lo que se puede defender.

**Qué aporta aquí, y por qué hay dos cosas distintas que se confunden.** ARGOS
tiene **dos mecanismos separados** que suenan parecido:

| | Simulacro (`/simulacro`) | Ingesta en sombra |
|---|---|---|
| **Qué hace** | Reproduce un lote pasado | Procesa alertas según llegan |
| **Estado** | **Efímero**, sembrado y descartado | **Persistente**, es el estado vivo |
| **Repetible** | Sí, misma entrada → mismo resultado | No: el estado avanza |
| **Deja rastro** | No | Sí, en el ledger |
| **Para qué sirve** | Enseñar el mecanismo y comparar políticas | **Acumular la evidencia** para decidir si se promociona a bloqueo real |

El simulacro es una demostración; la ingesta en sombra es el experimento. Solo
el segundo produce el registro que justificaría activar el bloqueo automático.

#### El ledger — el registro de decisiones **[real]**

**Qué es.** Un fichero donde se anota, línea a línea, cada decisión de bloqueo
tomada. Es la **única fuente de verdad** sobre a quién se ha decidido bloquear:
el estado en memoria del sidecar es decisión *en curso* y no sobrevive a un
reinicio.

**Qué guarda cada línea:**

| Campo | Qué es |
|---|---|
| `mode` | **Siempre `shadow`.** Es lo que marca que no se ejecutó nada. |
| `action`, `score`, `threshold`, `decided_at_alert` | La decisión del **modelo principal**. |
| `evidence` | Cuentas probadas, máquinas alcanzadas, reputación de la /24. |
| `exclusion` | Si la IP cayó en la lista de infraestructura propia, con el motivo. |
| `duplicate_of` | Si esa IP ya tenía decisión previa. **La primera vez gana**; una reemisión se anota pero no vuelve a actuar. |
| `second_opinion` | La anotación del Transformer **en el momento de la decisión**. |

Ese último campo es el que permite reconstruir la serie de acuerdo con el
tiempo, que es la única validación que le queda al segundo modelo. El contador
en memoria de `/health` sirve para mirar ahora; el ledger, para mirar atrás.

**El criterio de promoción a bloqueo real** no es una tasa de acierto: es que
el ledger muestre **cero veredictos sobre infraestructura propia** durante el
periodo de sombra, y que esa lista de exclusiones esté declarada completa. Se
afirma en positivo en la cabecera del simulacro, en vez de deducirse del
silencio.

---

## 16. Modos de degradación

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

## 17. Simulador local de alertas benignas

En cada refresco se antepone **una alerta benigna sintética**, rotando entre
diez escenarios (fallos de systemd, logs de Docker, flujos de administración).
Nunca se escribe en Wazuh; solo existe en memoria dentro de la respuesta.

Existe porque el tráfico real es casi todo ataque, y sin ningún contraejemplo
el panel no permite comprobar que el sistema distingue algo. Se identifica con
`argos.local-simulator` en el campo de herramienta.

---

## 18. Endpoints

| Ruta | Para qué |
|---|---|
| `GET /api/argos/live` | Alimenta el panel completo. |
| `GET /api/argos/simulation` | Ejecuta el simulacro. `minutes`, `limit`, `source`, `policy` (`hgb` por defecto, o `attention`, `or`, `and`). |
| `GET /api/argos/dataset` | Exporta alertas en JSONL para análisis. `format=manifest` da solo el balance de clases. |
| `POST /api/argos/mcp-chat` | Consulta en lenguaje natural sobre las herramientas MCP. |
| `GET /api/argos/mcp-chat` | Sonda: qué motor va a responder y cuántas herramientas hay. |
| `GET /api/wazuh/*` | Acceso directo a agentes, manager y alertas. |

### 18.1 Endpoints del sidecar (`127.0.0.1:8973`)

**Qué es un sidecar.** Un proceso auxiliar que corre **al lado** de la
aplicación principal, en la misma máquina, y le presta un servicio que sería
caro montar dentro. Aquí presta uno concreto: mantener los modelos **cargados
en memoria**. Sin él, la web tendría que lanzar un intérprete de Python y
recargar los modelos en cada petición.

**Qué aporta aquí.** Está medido: por subproceso, 9,34 s + 6,60 s **en cada
refresco**; en el proceso vivo, 1,53 s + 2,36 s. Con el panel sondeando cada
5 s, la diferencia es que las peticiones dejen de solaparse. Además es el
**dueño único del estado**: el cursor de ingesta y la reputación de subredes
viven ahí, y no podrían vivir en un proceso que muere tras cada petición.

| Ruta | Método | Para qué |
|---|---|---|
| `/health` | GET | Estado, contadores y bloque de la segunda opinión. |
| `/cursor` | GET | Por dónde va la ingesta y en qué generación de estado. |
| `/ingest` | POST | Ingesta con decisión. Devuelve veredictos del modelo principal más las anotaciones de sombra. |
| `/score` | POST | Puntúa alertas para el panel. Devuelve `argos`, `csr_lanl` e `ip_risk`. |
| `/simulate` | POST | Reproduce un lote con un puntuador efímero. Acepta `policy`. |
| `/window` | POST | Score de ventana de un agente. |

> **Por qué `localhost:8973/ingest` no se abre en el navegador.** Escribir una
> URL en la barra hace un `GET`, y esas cuatro rutas **solo aceptan `POST`**:
> reciben lotes de alertas en el cuerpo de la petición. Un `GET` devuelve
> `404 {"error": "ruta desconocida"}`. Las únicas abribles son `/health` y
> `/cursor`. Y en el puerto **3000 no existen en absoluto**: son del sidecar,
> no de la web.
>
> **El sidecar solo escucha en loopback, y eso es deliberado.** Arrancarlo con
> `--host 0.0.0.0` **falla con código de salida 1**; es una de las
> comprobaciones de `test_service.py`. No es una carencia: mantiene fuera de la
> red un proceso que decide bloqueos.

#### Lo que devuelve `/ingest`, y qué es decisión y qué no

| Campo | Qué es | ¿Decide? |
|---|---|---|
| `verdicts` | Bloqueos del modelo principal | **Sí** |
| `cursor`, `state_generation` | Punto de reanudación y versión del estado | — |
| `accepted`, `duplicates`, `late_behind_cursor` | Contabilidad de la deduplicación | — |
| `second_opinions` | Anotación del Transformer sobre cada aviso evaluado | **No** |
| `attention_only` | IPs donde **solo** el Transformer cruzaría su umbral | **No: son discrepancias** |
| `agreement` | Acuerdo acumulado desde que arrancó el proceso | **No** |

La separación es el punto entero del diseño. `attention_only` es lo más fácil
de malinterpretar: **no son bloqueos que se hayan hecho ni que se vayan a
hacer**. Son casos donde los dos modelos no coinciden, y existen para poder
medirlo, no para actuar.

> El contador `agreement` de `/health` **vive en memoria y se pierde al
> reiniciar** el sidecar. Para la serie larga hay que leer el ledger, que sí
> guarda la anotación con cada decisión.

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

## 19. Lo que se corrigió, y lo que sigue siendo limitación

Una parte del proyecto consistió en **auditar el propio panel** y retirar lo que
engañaba. Es contribución, no mantenimiento: el patrón que se repite es
**métricas que parecían informar y no informaban**.

### 19.1 Correcciones sobre la interfaz

| Elemento | Qué pasaba | Ahora |
|---|---|---|
| `MCP · 12 AGENTS`, `SURICATA · RUNNING` | Escritos a mano, nada medido | Retirados |
| Top targets `96/87/78/69` | Decorativos | Recuento real |
| Línea temporal | Agrupaba por posición en la lista (`index % 8`) | Por hora real |
| Geolocalización | Puntos sintéticos indistinguibles de los reales | Marcados `(aprox.)`; medido: 6,6 % |
| `Correlation sources` | Listaba Suricata y Zeek, siempre a cero | Los cuatro enriquecimientos reales |
| Fila AbuseIPDB | Contaba solo `checked`, marcaba 0 | Cuenta también `cached`: 4.447 |
| KPI `Anomalías IA` | Umbral que cruzaba el 100 % de las alertas | `IPs de riesgo alto`, por dirección |
| Gráfica `Alertas vs IA` | Dos líneas superpuestas idénticas | Columnas apiladas con serie que sí varía |
| Reparto de riesgo | La suma no cuadraba, sin explicación | Declara su cobertura |

Y las corregidas en la primera pasada de auditoría:

| Elemento | Antes | Ahora |
|---|---|---|
| Barra superior | `MCP · 12 AGENTS`, `SURICATA · RUNNING` fijos | `MANAGER`, `INDEXER`, `ALERTAS` medidos |
| Top targets | `96/87/78/69` decorativos | Recuento real de alertas por agente |
| Correlation sources | Suricata y Zeek siempre a cero | Los cuatro enriquecimientos que sí se aplican |
| Línea temporal | Reparto por posición en la lista | Agrupación por hora real |
| Geolocalización | Puntos sintéticos indistinguibles | Marcados `(aprox.)` y separados en salud |
| Fila `MCP Agents` | Permanentemente `planned` | Retirada |
| Chat «MCP» | El nombre sugería una integración MCP que no existía | Integración MCP real: la web hace de host y consulta las siete herramientas |
| Segunda opinión | No existía: un solo modelo decidía sin contraste | Transformer de atención en sombra, con acuerdo medible y avisos decisivos |

### 19.2 Limitaciones que permanecen en la plataforma

| Elemento | Situación |
|---|---|
| Suricata y Zeek | **No integrados.** Ya no aparecen en ninguna métrica de panel. El campo `Suricata SID` de la ficha de detalle sigue existiendo y vale siempre `N/A`. |
| MCP | **Integrado.** Servidor propio (`deploy/argos_mcp/server.ts`, siete herramientas de solo lectura) consumible desde Claude Desktop, Claude Code o el propio panel. El campo `MCP tool` de la ficha de detalle **no** tiene relación: es una etiqueta de tipo de alerta con nombre heredado y anterior. |
| Campo `Sensores` | Siempre `Wazuh / AI Engine`. Solo hay una fuente real. |
| Campo `Agente` en la ficha | Duplica «Destino». |
| Bloque CSR-LANL | Visible pero **no interpretable**: el adaptador rellena con cero las familias de datos que Wazuh no produce. Ver sección 11.1. |
| Ventana de la gráfica temporal | Solo cubre lo que quepa en 10.000 alertas (~5 h). |
| Geolocalización aproximada | Sigue existiendo, pero ahora está declarada. |
| Chat | El motor de suscripción depende de que el CLI de Claude Code esté instalado y con sesión iniciada; si se desinstala, cae a la API o a reglas. Lanza un agente local, así que el endpoint **no debe exponerse fuera de localhost**. |
| `AI Score` de ventana | Satura y no distingue entre atacantes del mismo minuto. Se mantiene junto al riesgo por IP, que sí discrimina. |
| Segunda opinión (Transformer) | **Sin validación externa.** Sus cifras son de test interno sobre la misma partición temporal que el modelo principal; el presupuesto de validación externa de LAB-ALERTS está gastado y no puede volver a gastarse. Por eso está en **modo sombra**: no decide, y medir su acuerdo en vivo es la única validación que le queda. Tampoco puntúa el primer aviso (K=1 excluido). |

### 19.3 Limitaciones del trabajo de investigación

Ordenadas por gravedad. La primera es estructural y condiciona a las demás.

**Limitaciones propias del paquete de modelos**, además de las de la lista:

- **La etiqueta es conducta, no verdad absoluta.** Los criterios de bloqueo
  (§4) son una heurística razonable y auditada, no un juicio humano.
- **Entrenado en una sola instalación**: 4 hosts Linux, 30 días. La validación
  externa cubre un segundo entorno de **11 horas**; más allá de eso, habría que
  reentrenar con datos propios.
- **La precisión externa 0,898 es un suelo, no una medida.** De los 38
  «falsos» del cruce externo, **29 eran atacantes a uno o dos usuarios de
  cumplir los criterios** cuando la captura terminó. La cifra real está entre
  0,898 y ~1,0, y no se puede estrechar sin captura nueva.
- **La demo del paquete puntúa alertas del periodo de entrenamiento**: sus
  scores son ilustrativos, no una métrica.

1. **No hay clase benigna real.** Wazuh solo indexa lo que dispara una regla.
   El negativo sale de etiquetado débil más un simulador sintético. **Sin
   benignos reales no se puede afirmar nada sobre falsos positivos**, y un SOC
   se juzga por falsos positivos. Es la precondición de casi todo lo demás.
2. **El modelo no transfiere** a máquinas nuevas (§6.2).
3. **Dominio de validez estrecho:** atacantes **ruidosos** — fuerza bruta,
   escaneo, spraying. **No** detecta a un atacante sigiloso con credenciales
   válidas, y eso está medido, no supuesto.
4. **Presupuesto de validación externa gastado.**
5. **El modo sombra nunca se ha ejecutado.** El corredor existe
   (`deploy/argos_scorer/shadow-run.ts`) pero nada lo lanza y
   `var/argos-scorer/verdicts.jsonl` no existe. Las cifras de acuerdo entre
   modelos son **fotos sueltas, no una serie**.
6. **El Transformer no tiene validación externa.**
7. **Cobertura variable:** la proporción de alertas con IP de origen oscila
   entre el **2 % y el 82 %** según el refresco. Las métricas de riesgo se
   calculan sobre esa base variable.
8. **CSR-LANL no es interpretable en ARGOS:** el adaptador rellena con ceros
   las familias de datos que Wazuh no produce. Se conserva porque documenta un
   intento de transferencia entre dominios que se midió y no funcionó.

---

---

## 20. Cómo levantarlo

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
el código antiguo. Ha pasado varias veces durante el desarrollo y el síntoma
engaña: la aplicación responde, pero con el binario viejo.

### Qué se puede abrir en el navegador

| URL | Qué es |
|---|---|
| `http://localhost:3000` | El panel |
| `http://localhost:3000/simulacro` | El simulacro |
| `http://localhost:8973/health` | Estado del sidecar, con el bloque de la segunda opinión |
| `http://localhost:8973/cursor` | Por dónde va la ingesta |

**Nada más.** `/ingest`, `/score`, `/simulate` y `/window` solo aceptan `POST`
y devuelven `404` a un navegador; en el puerto 3000 ni siquiera existen. Ver
§ 18.1.

### Comprobar que la segunda opinión está viva

```bash
curl http://localhost:8973/health        # -> attention.loaded: true, budgets [2,3,5,10,20]
.venv/Scripts/python.exe deploy/argos_scorer/test_service.py   # 11 secciones
```

---

*Documento generado el 6 de septiembre de 2026, actualizado tras corregir los
elementos de la sección 19 y ampliado el 7 de septiembre con la segunda opinión
del Transformer (secciones 3.1, 5, 7, 7.1, 10.1 y 11). Las cifras marcadas como
medidas proceden de la exportación de 30 días (1.462.265 alertas) y de
mediciones sobre el despliegue en vivo; las del test interno del paquete de
modelos vienen del repositorio de investigación y están marcadas
**[externo]**.*

---

# PARTE III · CIERRE

## 21. Trabajo futuro

### 21.1 Lo que se llegó a proponer, y por qué debe recortarse

Durante el proyecto se diseñó una arquitectura ambiciosa: **cinco modelos
especialistas** —LAB-ALERTS binario, LAB-ALERTS multiclase, Cowrie para
honeypot, CSR-LANL para anomalía de entidad y modelos de flujo de red sobre
CIC-IDS / UNSW-NB15 / UGR-16— coronados por un **meta-modelo de fusión** que
combinase sus salidas en un `final_soc_risk`, y a más largo plazo un
`TabTransformer` o `FT-Transformer` sobre secuencias de ventanas.

El razonamiento que la sostenía es correcto y merece figurar en la memoria:
**los datasets tienen naturalezas distintas** —alertas SIEM, honeypot SSH,
flujos de red, comportamiento por entidad— y mezclarlos directamente produciría
un modelo incoherente, porque las variables no representan lo mismo ni las
etiquetas significan lo mismo. De ahí la idea de especialistas por dominio más
una capa de fusión.

**Pero esa propuesta debe recortarse**, y decirlo es más fuerte que mantenerla.
Tres razones medidas en este mismo trabajo:

1. **La clase negativa no existe** (§19.3). Una capa de fusión sobre modelos
   cuya precisión no se puede medir multiplica lo inmedible.
2. **El aprendizaje profundo empató tres veces** (§6.4). Proponer un cuarto
   intento con `TabTransformer` sin haber cambiado la naturaleza de los datos
   ignora la propia evidencia del trabajo.
3. **Los modelos de red no tienen datos.** Requieren `src_port`, `duration`,
   `bytes`, `packets`, `flags`, `connection_state`… que exigirían integrar
   Suricata, Zeek o NetFlow. **Ninguno está desplegado.**

Un tribunal preguntará por qué se diseña el tejado antes que los cimientos.

### 21.2 El orden defendible

1. **Recuperar la clase benigna.** Activar `logall_json`, indexar
   `wazuh-archives-*` y generar actividad administrativa real —inicios de sesión
   correctos, `sudo`, copias de seguridad, actualizaciones de paquetes,
   mantenimiento programado— durante al menos una semana. **Es la precondición
   de todo lo demás**, y es barato: un cambio de configuración más tiempo de
   recogida.
2. **Repetir la ablación y el LOAO** con esos benignos, y **medir falsos
   positivos por primera vez**. Solo entonces se puede afirmar algo sobre
   precisión operativa.
3. **Ejecutar el modo sombra** durante semanas (§19.3, limitación 5) para
   convertir el acuerdo entre los dos modelos en una **serie temporal** en vez
   de fotos sueltas. Es además la única validación que le queda al Transformer.
4. **Reentrenar por agente** los hosts que hoy no tienen modelo propio: se
   necesitan ≥ 200 ventanas por agente.
5. **Solo entonces**, plantear la fusión — y con una primera versión simple
   (regresión logística o HistGradientBoosting sobre las salidas), no un
   Transformer.

### 21.3 Extensiones que sí están listas para plantearse

- **Cowrie / honeypot**: activación condicional cuando la alerta venga
  claramente de honeypot (`decoder.name`, `location` o descripción). Sería
  enriquecimiento del detalle, **nunca** detector general.
- **Umbral adaptativo a la prevalencia del destino**, sin etiquetas: validado
  en el paquete (K = 5: recall 0,846 → 0,900). Disponible como ajuste si la
  mezcla de tráfico difiere mucho de la captura de entrenamiento.
- **Promoción del bloqueo a real**: requiere el ledger del modo sombra con cero
  veredictos sobre infraestructura propia durante el periodo, y aprobación
  humana explícita.

---

## 22. Reproducibilidad: qué comando produce qué cifra

| Cifra | Origen |
|---|---|
| Ablación y LOAO (§6.1, §6.2) | `python experiments/shortcut_ablation.py` → `experiments/results/shortcut_ablation.json` |
| KEV/EPSS, 243× (§7) | `python experiments/kev_epss_filter.py` → `experiments/results/kev_epss_filter.json` |
| Volcado de 1.462.265 alertas (§2) | `GET /api/argos/dataset` |
| Métricas del paquete (§4.1–4.3, §5) | Ya están transcritas en este documento. Procedencia original: secciones 2 y 4 de `deploy/argos_scorer/README.md` y el registro R1–R13 del repositorio de investigación |
| Cifras del panel en vivo (§6.5, §14, §19.1) | `GET /api/argos/live` |
| Simulacro y políticas | `GET /api/argos/simulation?policy=hgb\|attention\|or\|and` |
| Estado de los modelos | `GET http://127.0.0.1:8973/health` |
| Pruebas del sidecar | `python deploy/argos_scorer/test_service.py` (11 secciones) |
| Inventario de pantallas (Parte II) | `npm run dev` y el panel en `http://localhost:3000` |

Las cifras del panel **cambian con cada refresco** porque dependen de las 10.000
alertas cargadas en ese momento. Para la memoria conviene **fijar una captura y
fecharla**.

---

## 23. Afirmaciones que NO se pueden escribir

Lista de guardarraíles para quien redacte. Todas están respaldadas por
mediciones de este documento.

| ❌ No escribir | ✅ Escribir en su lugar |
|---|---|
| «El sistema detecta ataques con un 99 % de exactitud» | «Alcanza 99,78 % frente a una línea base de 98,64 %: aporta 1,14 puntos» |
| «El modelo generaliza» | «Se midió que no transfiere: MCC 0,09 y 0,00 en dos de cuatro agentes» |
| «Detecta amenazas avanzadas / APT» | «Dominio medido: atacantes ruidosos —fuerza bruta, escaneo, spraying—» |
| «El Transformer mejora la detección» | «Empata con el modelo principal; aporta explicabilidad, no precisión» |
| «Precisión / pocos falsos positivos» | Nada: **sin clase benigna real no se puede afirmar** |
| «Valida en producción» | «Validación externa de un solo disparo, presupuesto gastado» |
| «Bloquea automáticamente» | «Modo sombra: anota, no ejecuta. El bloqueo real requiere aprobación» |
| «Las alertas CRITICAL son los ataques» | «El 99,6 % de las CRITICAL son hallazgos de inventario; la fuerza bruta vive en LOW» |
| «El AI Score mide si la alerta es un ataque» | «Puntúa un minuto de un agente y satura: 13 valores distintos, 96,8 % en 100» |
| Citar un porcentaje agregado a secas | Citarlo **con su desglose por grupo** — es la regla que gobierna el trabajo |

---

*Documento generado el 8 de septiembre de 2026. Las cifras marcadas con fuente
proceden de los ficheros citados; las del panel en vivo, de mediciones sobre el
despliegue en la fecha indicada.*

---

*Documento generado el 8 de septiembre de 2026, unificando el inventario de la
plataforma y el dossier de investigación. Las cifras marcadas con fuente
proceden de los ficheros citados; las del panel en vivo, de mediciones sobre el
despliegue en la fecha indicada. Los valores del panel **cambian con cada
refresco**: para la memoria conviene fijar una captura y fecharla.*

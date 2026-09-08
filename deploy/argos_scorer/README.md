# ARGOS Scorer — paquete de despliegue

Modelos entrenados y puntuadores listos para integrar en la web: se le pasan
alertas de Wazuh y devuelve **score de ataque, decisión de bloqueo y familia de
actividad**, con la evidencia que los justifica. Autocontenido: no depende del
repositorio de investigación.

Este documento recoge **toda** la información del trabajo: qué hace cada
servicio, qué garantías tiene medidas, y — sección 4 — el camino completo de
decisiones: qué se probó, qué falló, qué se retiró y **por qué nos quedamos con
lo que hay aquí**.

```
argos_scorer/
├── argos_scorer/          # paquete Python (features en vivo + puntuadores)
├── models/                # 8 modelos HGB + attention_block,npz (5 transformers) + config,json (7,0 MB)
├── state/live_state.json  # arranque en caliente (reputación + líneas base)
├── example.py             # demo funcional con alertas reales
├── example_attention.py   # demo del Transformer y del consenso HGB+atención
├── sample_alerts.jsonl
└── requirements.txt       # joblib, numpy, pandas, scikit-learn
```

## 1 · Inicio rápido

```bash
pip install -r requirements.txt
python example.py
```

```python
from argos_scorer import EarlyBlockScorer

scorer = EarlyBlockScorer.load("models")        # una vez, al arrancar la web

def on_wazuh_alert(alert: dict):                # por cada alerta entrante
    verdict = scorer.ingest(alert)
    if verdict and verdict["action"] == "BLOCK":
        aplicar_firewall_drop(verdict["ip"])    # tu integración
        registrar(verdict)                      # score + evidencia

# periódicamente (p. ej. cada 5 min): persistir lo aprendido
scorer.save_state("state/live_state.json")
```

Formato de entrada: el **esquema plano ARGOS** (el de `argos-alerts_30d.jsonl`).
Campos que consumen los puntuadores: `timestamp`, `src_ip`, `src_user`,
`dst_user`, `src_port`, `agent_id`, `window_start` y, para el de ventanas,
también `geo_*`. Los campos del motor de reglas (`rule_*`, `mitre_*`,
`decoder_name`) **no se usan** — ver §4.1 para el porqué.

## 2 · Los servicios: tres principales y uno opcional

### 2.1 `EarlyBlockScorer` — bloqueo temprano de IPs (EL PRINCIPAL)

Streaming. Mantiene el perfil de cada dirección de origen y, con cada aviso,
reevalúa: en los presupuestos K = 1, 2, 3, 5, 10, 20 avisos puntúa con el
modelo de ese K y **bloquea al primer cruce de umbral** (umbral por K, fijado a
precisión ≥ 0,99 en validación). Convierte el IDS en IPS: cada acierto temprano
suprime todo lo que esa IP habría generado después.

**Garantías medidas** (protocolo en §4.6–4.7):

| Métrica | Interno (mes de test) | Externo (otro entorno, un disparo) |
|---|---|---|
| Recall de IPs bloqueables | **0,990** | **0,994** |
| Precisión | **0,995** (3 falsos/mes) | ≥ 0,898 (suelo por censura de 11 h) |
| Mediana de corte | 5º aviso | 5º aviso |
| Volumen de ataque evitado | **89 %** | 91 % |

Salida de `ingest(alert)`: `None` o un veredicto con `ip`, `score`,
`decided_at_alert`, `threshold` y `evidence` (usuarios probados, máquinas
alcanzadas, reputación de la subred) — el analista ve **por qué**, no sólo un
número.

### 2.2 `WindowBlockScorer` — P(BLOCK) por ventana

Puntúa un minuto completo de un agente: `score(alertas_de_la_ventana,
agent_id)` → probabilidad de que la ventana contenga tráfico de orígenes que
merecen bloqueo. Medido: lift 43,5×/20,0× dentro de cada host; transferido a
otro host retiene el 65–104 % del rendimiento nativo; validación externa MCC
0,343 en hosts jamás vistos (contra 0,000 de la aproximación anterior).

### 2.3 `ActivityScorer` — familia de actividad + rechazo

Clasifica la ventana en su familia (`CredentialBrute`, `SshOperational`,
`PortChange`, `AgentHealth`…) con **un modelo por host** conocido, probabilidades
calibradas (isotónica) y **rechazo de actividad desconocida**: si la confianza
cae bajo el umbral del host, devuelve `is_unknown=True` → cola de revisión
humana. `attack_score` = probabilidad acumulada de las familias hostiles.
Medido: el mecanismo de rechazo captura hasta el 99,8 % de una familia de
ataque nunca vista (mando `reject_quantile`, §5.4).

### 2.4 `AttentionBlockScorer` y `ConsensusBlockScorer` — segunda opinión con Transformer (opcional)

Mismo servicio que §2.1 (misma unidad, misma etiqueta, misma política
secuencial, umbrales a precisión ≥ 0,99 fijados en validación), pero el modelo
es un **encoder de atención** (2 bloques pre-LN, 4 cabezas, d = 32, ~18k
parámetros por K) que ve la **secuencia** de los primeros K avisos como fichas
(hueco, usuario nuevo, root, cuenta de sistema, puerto, agente nuevo, ventana
nueva) y el contexto causal de subred como ficha inicial. Un modelo por
K ∈ {2, 3, 5, 10, 20}; **K = 1 excluido a propósito**: ahí el Transformer
ordena mejor (AUC 0,86 frente a 0,83) pero su umbral no traslada de validación
a test y la política cae a precisión 0,976. Inferencia en **numpy puro**
(`attention_block.npz`, 414 KB): el paquete sigue sin torch, y cada
construcción verifica que numpy reproduce al modelo entrenado (máx. |diff|
3,5·10⁻⁷ en 3.595 evaluaciones).

**Medido** (test interno, la misma partición que §2.1; sin validación externa,
el presupuesto de LAB-ALERTS está gastado — §4.7):

| Política | Recall | Precisión | Legítimas cortadas/mes | Mediana de corte | Ataque evitado |
|---|---|---|---|---|---|
| HGB (§2.1, el principal) | 0,990 | 0,995 | 3 | 5º aviso | 89,3 % |
| Atención solo | 0,992 | 0,992 | 5 | 5º aviso | 90,2 % |
| Consenso **OR** (cualquiera dispara) | 0,995 | 0,990 | 6 | 5º aviso | 93,9 % |
| Consenso **AND** (ambos disparan) | 0,985 | **0,997** | **2** | 5º aviso | 85,5 % |

Sobre tres semillas (R13) atención y HGB **empatan**: recall 0,991 frente a
0,990, precisión 0,991 frente a 0,993. Lectura honesta: no hay ganancia de
detección — la etiqueta cuenta hechos (cuentas, máquinas, avisos) y no depende
del orden, así que la atención no tiene nada que explotar que los agregados no
capten. Lo que aporta es otra cosa: (a) una **segunda opinión** con distinto
sesgo inductivo, que da al operador dos mandos nuevos — `AND` es la política
más estricta medida (2 falsos al mes) y `OR` la de más recall al límite del
objetivo de precisión — y (b) **evidencia**: `evidence.avisos_decisivos` y
`atencion_por_aviso` dicen qué avisos pesaron en la decisión (en la práctica,
los que introducen un usuario nuevo y los últimos de la rampa).

```python
from argos_scorer import AttentionBlockScorer, ConsensusBlockScorer

att  = AttentionBlockScorer.load("models")                 # solo atención
both = ConsensusBlockScorer.load("models", mode="and")     # o mode="or"
verdict = both.ingest(alert)   # None o {'action':'BLOCK','fired':['hgb','attention'], ...}
```

No ejecutes `EarlyBlockScorer` y `AttentionBlockScorer` **a la vez sobre el
mismo estado vivo**: cada uno registraría la IP como hostil y la reputación de
subred contaría doble. Para combinar ambos usa `ConsensusBlockScorer`, que
comparte perfil y estado y actualiza la reputación una sola vez. Se regenera
con `build_deploy_attention.py` (repo de investigación) tras
`build_deploy_bundle.py`.

## 3 · Estado vivo (`LiveState`)

Los servicios comparten memoria causal — lo que hace que las variables de
novedad y reputación signifiquen algo:

- **Reputación de subred** (/24 y /16): cuántas IPs se han visto y cuántas
  resultaron hostiles. Es la variable que permite bloquear al **primer** aviso
  a una IP de un rango ya conocido (AUC a K=1: 0,83 frente a 0,52 sin ella).
- **Frecuencias globales de IP/usuario** (novedad causal de ventanas).
- **Línea base por agente** (media/desviación móviles de sus ventanas).

Se entrega **precargado** con la captura de 30 días (4.792 IPs, 4.123 subredes
/24) — arranque en caliente. Sin él, todo parece "nuevo" y los puntuadores de
ventana trabajan fuera de su distribución (medido en la demo: P(BLOCK) 0,05 en
frío frente a 0,99 en caliente sobre la misma ventana). Persistir con
`save_state()` y recargar al arrancar.

## 4 · Por qué el paquete es así — el camino completo de decisiones

Cada pieza de este paquete existe por un experimento. Registro canónico con
runs y cifras: `src/models/ARGOS_LAB/RESULTADOS.md` (R1–R12, X1–X3) del
repositorio de investigación.

### 4.1 Por qué NO hay un clasificador «¿es ataque?» (R1, X2)

Fue lo primero que se construyó y lo primero que se retiró. La etiqueta
ATTACK/BENIGN del export la genera el propio motor de reglas de Wazuh: **una
sola columna** (`mitre_tagged_ratio`) la reproduce con ROC-AUC 0,9990 —
idéntico al modelo de 98 variables. Un clasificador así no detecta: reconstruye
la regla que lo etiquetó (circularidad). Por eso los campos `rule_*`, `mitre_*`
y `decoder_name` **no entran en ningún modelo de este paquete**. También se
descartó etiquetar por `rule_level`: sale del mismo motor y está invertido en
estos datos (nivel 14 = hallazgo Trivy benigno; nivel 5 = la fuerza bruta real;
«nivel ≥ 10 ⇒ ataque» erraría el 70,8 % de lo que captura).

### 4.2 Por qué un modelo POR HOST (R2)

Con las 54 variables conductuales — sin `agent_id` entre ellas — se predice
**qué agente es con 99,75 % de exactitud**: cada máquina tiene una huella
repartida de forma redundante entre variables correlacionadas (el host escáner:
`src_ip_present_ratio` 0,075 y 2.072 alertas/ventana; el honeypot: 0 IPs y
1,5). Quitar una columna no elimina un confundido distribuido. Consecuencia
medida: un modelo global entrenado en unos hosts cae a MCC 0,000 en otro.
Dentro de un host la huella es constante — no informa — y el modelo se ve
forzado a aprender conducta. Por eso `ActivityScorer` lleva un modelo por
agente, y un agente nuevo debe acumular historial y reentrenarse (la reserva
global es orientativa, no equivalente).

### 4.3 Por qué NO hay detector de anomalías (X1)

Un autoencoder llegó a presentarse como el mejor resultado no supervisado:
18,3× sobre el azar. **Retirado**: desglosado por agente, cada host estaba en
el azar o por debajo (0,57×–0,95×). El agregado venía de que la clase rara se
concentraba en un agente — paradoja de Simpson. Ajustarlo por host tampoco
funcionó (lift medio 0,73×). De ese fallo nace la regla que gobierna todo el
trabajo: **ninguna métrica agregada sin su desglose por grupo**, y el motivo de
que las garantías de la §2 se reporten por host.

### 4.4 Por qué la etiqueta de BLOQUEO POR CONDUCTA (R4)

La etiqueta que entrena estos modelos no viene de ninguna regla: una IP merece
bloqueo si su conducta observada lo justifica — **≥ 5 cuentas probadas, o ≥ 2
máquinas alcanzadas, o ≥ 50 intentos en ≥ 3 ventanas** — computado de forma
causal (sólo pasado) desde cinco campos de hechos. Auditada con la misma
metodología que destapó la circularidad: la mejor sonda de una variable llega a
0,6641 (contra 0,9990 de la etiqueta débil) — no reconstruible, circularidad
rota. Y el efecto es medible: con la etiqueta débil el traslado entre hosts
colapsaba (MCC 0,000); con ésta retiene el 65–104 % (el problema nunca fue el
modelo, era la pregunta).

### 4.5 Por qué la política es SECUENCIAL y con reputación de subred (R7, R9)

A presupuesto fijo (decidir con exactamente 5 avisos) el recall era 0,82. La
mejora no vino de un modelo mejor sino del planteamiento: en despliegue se
reevalúa **con cada aviso** — bloquear al primer cruce lleva el recall a 0,990
manteniendo la mediana en el 5º aviso. La reputación causal de subred aporta lo
que ningún agregado propio puede: sospechar de una IP **desde su primer aviso**
si su /24 ya produjo hostiles (las botnets se agrupan en rangos). Y los
umbrales van a precisión ≥ 0,99 fijada en validación porque bloquear a un
legítimo cuesta más que dejar pasar avisos: el mando es la precisión, no el F1.
Complemento validado: umbral adaptativo a la prevalencia del destino, sin
etiquetas (K=5: recall 0,846 → 0,900) — disponible como ajuste si la mezcla de
tráfico de la web difiere mucho de la captura.

### 4.6 Por qué HGB y no deep learning (R10)

Se probó en tres formas: MLP tabular (pierde contra HGB, 0,9664 vs 0,9776),
autoencoder no supervisado (retirado, §4.3) y GRU sobre la secuencia de avisos
de cada IP (empate exacto: AUC 0,9702 vs 0,9703). Con datos tabulares agregados
de esta escala, el deep learning no aportó ventaja medible en ninguna tarea.
Los modelos del paquete son HistGradientBoosting: igual de buenos, ligeros
(6,6 MB en total), sin GPU y con inferencia en microsegundos.

Cuarta forma, añadida el 2026-09-07 (R13): un **Transformer de atención**
sobre la misma secuencia, con tres semillas para separar mejora de ruido.
AUC medio por K 0,957 frente a 0,952 del HGB — sin ventaja clara — y empate
en la política secuencial (0,991 / 0,991 frente a 0,990 / 0,993). El único
punto donde gana con consistencia (K = 1) no es aprovechable porque su umbral
no traslada. Se incluye igualmente como servicio **opcional** (§2.4) por su
valor como segunda opinión para el consenso y por la evidencia de atención,
no por métrica; el principal sigue siendo el HGB.

### 4.7 Cómo se validó — y qué significa «validado» aquí

- **Particiones temporales**, nunca aleatorias (una partición aleatoria sobre
  datos con estructura temporal produce cifras ~0,99 que no se sostienen; se
  reprodujo el mismo colapso en CIC-IDS2017 y UNSW-NB15).
- **Validación externa de un solo disparo**: canalización congelada y una única
  ejecución contra un segundo entorno (LAB-ALERTS, 9 hosts, incluye Windows),
  reportada tal cual. El recall externo 0,994 sale de ahí. Los dos presupuestos
  de disparo único están **gastados**: nuevas afirmaciones externas requieren
  captura nueva.
- **Contra ground truth real** (CSR-LANL, red team auténtico): las mismas
  variables conductuales dan señal genuina (ROC-AUC 0,96) frente a compromisos
  reales, pero a prevalencia 1e-05 no alcanzan utilidad operativa. **Dominio de
  validez medido**: este paquete es eficaz contra atacantes *ruidosos* (fuerza
  bruta, escaneo, spraying — lo que llega de internet); NO pretende detectar a
  un atacante *sigiloso* con credenciales válidas.

## 5 · Operación

### 5.1 Cold start y persistencia
Cargar siempre con el `state/live_state.json` entregado; persistirlo
periódicamente y al apagar. El estado sólo crece con el pasado (causal): no hay
fuga por mantenerlo.

### 5.2 Agentes nuevos
`ActivityScorer` los atiende con la reserva global (orientativa). Para servicio
pleno: acumular ≥ 200 ventanas del agente y reentrenar su modelo
(`build_deploy_bundle.py` del repo regenera el paquete completo). El
`EarlyBlockScorer` no depende del agente: funciona desde el primer día.

### 5.3 Reentrenado
Recomendado mensual o al cambiar la flota. Todo el paquete se regenera con un
comando en el repo de investigación (semilla fija, reproducible):
`python src/models/ARGOS_LAB/build_deploy_bundle.py`.

### 5.4 Mandos de ajuste (en `models/config.json`)
- `early_block.thresholds`: subir → menos falsos bloqueos, más lentos; bajar →
  al revés. Los entregados = precisión ≥ 0,99 validada.
- `activity.reject_quantile` (0,25): fracción de tráfico conocido que se marca
  para revisión. A 0,50 captura el 99,8 % de familias nunca vistas a cambio de
  revisar ~1/3 del tráfico.

### 5.5 Qué registrar en la web
El veredicto completo (score + evidencia + umbral), no sólo la acción: es lo
que permite auditar falsos positivos y lo que da confianza al analista.

## 6 · Limitaciones (léelas antes de prometer nada en la web)

1. **Etiqueta de conducta, no verdad absoluta**: los criterios de bloqueo son
   una heurística razonable y auditada, no un juicio humano.
2. **Dominio**: atacantes ruidosos. Un APT con credenciales robadas y paciencia
   no cruza estos umbrales (medido contra red team real, §4.7).
3. **Entrenado en una instalación** (4 hosts Linux, 30 días). La validación
   externa cubre un segundo entorno de 11 h; más allá, reentrenar con datos
   propios.
4. **Precisión externa 0,898 es un suelo**: de los 38 «falsos» del cruce
   externo, 29 eran atacantes a 1–2 usuarios de cumplir los criterios cuando la
   captura terminó.
5. La demo (`example.py`) puntúa alertas del **periodo de entrenamiento**: sus
   scores son ilustrativos, no una métrica.

## 7 · Inventario de modelos

| Fichero | Servicio | Entrenamiento |
|---|---|---|
| `early_block_K{1,2,3,5,10,20}.joblib` | EarlyBlockScorer | 3.354 IPs (train), umbral p99 sobre 719 IPs (val) |
| `window_block.joblib` | WindowBlockScorer | 56.883 ventanas, calibrado isotónico |
| `activity_scorer.joblib` | ActivityScorer | por host (000/011/030) + global, calibrado + rechazo |
| `attention_block.npz` | AttentionBlockScorer / ConsensusBlockScorer | 5 transformers (K = 2, 3, 5, 10, 20), mismos 3.354 IPs de train, umbral p99 sobre 719 IPs (val); pesos en numpy, 414 KB |
| `config.json` | todos | listas de variables (el orden manda), umbrales, notas de validación; sección `attention_block` con hiperparámetros, normalización y métricas del test interno |

Semilla 42 en todo. Reproducible de extremo a extremo desde el repositorio.

---
*Paquete generado el 2026-09-02 desde el TFM «SIEM IDS/IPS con IA»; servicio de atención añadido el 2026-09-07 (R13). Historia
completa, experimentos y resultados retirados: `src/models/ARGOS_LAB/RESULTADOS.md`
y la memoria técnica publicada.*

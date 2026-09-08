# ARGOS-SOC IA — Dossier de investigación: datos, preprocesado, modelos y resultados

Documento hermano de `DOSSIER_TFM.md`. Aquel recoge la línea argumental del
trabajo y el inventario de la plataforma web pantalla a pantalla; **este recoge
el trabajo de investigación módulo a módulo**: cada conjunto de datos que se
tocó, cómo se preprocesó, qué modelos se entrenaron con qué hiperparámetros,
qué métricas salieron y de qué fichero sale cada número, qué se descubrió y qué
se retiró. Está pensado para redactar los capítulos de datos, metodología,
experimentos y resultados de la memoria sin tener que abrir el repositorio.

> **Convención de procedencia**, usada en todo el documento:
> **[medido]** número que sale de un artefacto reproducible del repositorio (se
> cita la ruta y, cuando hay varios, el `run_id`) · **[documentado]** decisión o
> descripción que consta en el código, en un `STRATEGY_*.md` o en un docstring ·
> **[externo]** medido sobre un segundo entorno (LAB-ALERTS) con la canalización
> congelada · **[retirado]** resultado que no sobrevivió a auditoría y se conserva
> como advertencia · **[no citable]** cifra producida por un defecto conocido de
> la canalización.

---

## 0. Cómo usar este documento

| Parte | Secciones | Contenido | Para qué capítulo de la memoria |
|---|---|---|---|
| **I · Marco común** | 1–3 | Mapa de los conjuntos de datos, el contrato que comparten los módulos, glosario | Metodología general |
| **II · ARGOS-LAB** | 4–16 | El corpus principal: 1,46 M de alertas Wazuh propias. Datos, features, auditoría, todos los modelos y experimentos, paquete de despliegue | Datos, experimentos, resultados |
| **III · LAB-ALERTS** | 17 | El segundo entorno Wazuh: pipeline propio y validación externa de un solo disparo | Validación |
| **IV · Datasets públicos** | 18–22 | CIC-IDS2017, UNSW-NB15, UGR'16, CSR-LANL y los no explotados (CTU-13, TON_IoT, Unit 42) | Estado del arte aplicado, contraste |
| **V · Síntesis** | 23–31 | Patrones transversales, registro de resultados, limitaciones, reproducibilidad, frases prohibidas, deuda, bitácora de cierre | Discusión y conclusiones |

**Regla de lectura.** Ninguna cifra agregada de este documento debe citarse sin
el desglose por grupo que la acompaña (por agente, por host, por fold, por K).
Es la regla metodológica que gobierna el trabajo desde que un resultado
agregado favorable —el autoencoder «18,3×»— se desmontó al desglosarlo (§9).

**Relación con `DOSSIER_TFM.md`.** Las secciones 1–7 de aquel documento
resumen la línea argumental con los mismos números que aquí se detallan. Cuando
ambos citan una cifra, la fuente es la misma (los artefactos del repositorio de
investigación); este documento añade el contexto de cada experimento, las
tablas completas y los resultados de los módulos que allí solo se mencionan
(CIC-IDS2017, UNSW-NB15, UGR'16, LAB-ALERTS).

---

# PARTE I · MARCO COMÚN

## 1. Mapa de los conjuntos de datos y su papel

### 1.1 Lo que se planificó y lo que se hizo

El plan inicial del proyecto (`AGENTS.md`) preveía cinco fases con datasets
públicos distintos por fase —CIC-IDS2017 para prototipo y *streaming*, TON_IoT
para correlación multi-fuente, UGR'16 para deriva de concepto, CTU-13 y PCAPs de
Unit 42 para validación final— y, como fase E, «un pequeño dataset propio de
laboratorio», descrito como el de mayor valor para la tesis. **Ocurrió lo
contrario de lo previsto en volumen de esfuerzo**: el dataset propio (ARGOS-LAB)
se convirtió en el corpus principal y absorbió la mayor parte del trabajo,
porque fue el único donde apareció el hallazgo central —la circularidad de la
etiqueta— y el único con una acción operativa que medir (bloquear una IP). Los
públicos quedaron como contraste metodológico: reproducir en referencias
independientes el patrón «partición laxa ≈ perfecto, partición rigurosa ≈
azar».

| Conjunto | Naturaleza | Volumen bruto | Profundidad alcanzada | Papel en la tesis |
|---|---|---|---|---|
| **ARGOS-LAB** | Alertas Wazuh propias, 31 días, 4 agentes | 1.462.265 alertas · 1,49 GB JSONL | Pipeline completo, 13 resultados validados (R1–R13), 3 retirados (X1–X3), paquete de despliegue | **Corpus principal** |
| **LAB-ALERTS** | Alertas Wazuh de un segundo servidor, 10,8 h, 9 hosts (un Windows, sin origen de red) | 59.855 alertas · 48 MB | Pipeline propio sin artefactos + **validación externa de un solo disparo** de los modelos de ARGOS | Validación externa |
| **CIC-IDS2017** | Flujos de red etiquetados (referencia académica) | 2,83 M flujos · 2,0 GB | 13 runs en tres particiones, en régimen de desarrollo (5 iteraciones) | Contraste: colapso por partición |
| **UNSW-NB15** | Flujos de red etiquetados (referencia académica) | 2,54 M flujos · 634 MB | Particiones regeneradas tras corregir un bug de cabecera (R11); fuga por `id` detectada en la oficial | Contraste: laxo 0,984 vs oficial ≈ 0,89 |
| **UGR'16** | NetFlow real de un ISP, con ataques sintéticos inyectados | 457 GiB | Validación semántica y preparación diseñada; **sin entrenar** | Escala; exploración documentada |
| **CSR-LANL** | Eventos de autenticación/proceso/flujo/DNS de Los Alamos con **equipo rojo real** | 11 GB · 1.051 M eventos | Celdas (máquina, hora) contra verdad de campo (R12) | **Dominio de validez** del método |
| **CTU-13** | Capturas de botnet | 1,9 GB | Descargado, no explotado | Descartado |
| TON_IoT, Unit 42, Bot-IoT | Previstos en el plan | — | No descargados ni procesados | Trabajo futuro |

Las cifras de volumen de los módulos públicos se detallan, con su procedencia,
en la Parte IV.

### 1.2 Cronología del trabajo de modelado

Reconstruida de los `run_id` de los artefactos (formato `AAAAMMDD_HHMMSS`) y de
los sellos de `RESULTADOS.md`.

| Fecha | Hito |
|---|---|
| mayo 2026 | Último commit en el repositorio compartido (`3c887bf`, 2026-05-13): UGR16, UNSW-NB15, CIC-IDS2017 y LAB-ALERTS ya tenían módulo |
| 2026-07-28 → 08-27 | Captura de los 31 días de ARGOS-LAB |
| 2026-08-27 | Export (`argos-alerts_30d.manifest.json`, 14:11 UTC) y ejecución de la canalización completa de ARGOS-LAB: auditoría de fuga, binario, multiclase, LOAO, anomalías, GRU (runs `20260827_16xxxx`) |
| 2026-09-01 | Puntuador de actividad por host y puntuador de bloqueo por conducta (`20260901_23xxxx`) |
| 2026-09-02 | Transferencia entre hosts, adaptación de dominio, bloqueo temprano v1/v2, GRU secuencial, umbral adaptativo, validación externa (R5–R10); corrección de UNSW-NB15 (R11); CSR-LANL contra red team (R12); paquete de despliegue |
| 2026-09-07 | Transformer de atención (R13) y su inclusión en el paquete |

---

## 2. El contrato común de los módulos

Cada dataset vive en `src/models/<DATASET>/` y **todos implementan el mismo
contrato**: mismos nombres de script, misma estructura de salida, mismos
metadatos. Un módulo nuevo se incorpora implementando ese contrato. Es lo que
permite comparar resultados entre datasets sin atribuir diferencias al
andamiaje.

### 2.1 Scripts homónimos

| Script | Responsabilidad | Presente en |
|---|---|---|
| `prepare_dataset.py` | Datos crudos → filas de entrenamiento → Parquet particionado, con `feature_columns.json` y `split_spec.json` | Todos |
| `feature_spec.py` | Fuente única de verdad: grupos de variables, regímenes, política de clases | ARGOS-LAB (los demás llevan la especificación dentro de `prepare_dataset.py`) |
| `data_loader.py` | Carga con filtrado obligatorio por régimen de features; falla si una clase de test no existía en train | Todos |
| `validate_datasets.py` | Comprueba particiones: columnas, clases, solapamientos | UNSW-NB15, UGR16 |
| `train_ml_binary_hgb.py` / `train_ml_multiclass_hgb.py` | HistGradientBoosting binario y multiclase | Todos |
| `train_ml_binary_mlp.py` | Perceptrón multicapa (PyTorch) | ARGOS, CIC, UNSW, UGR |
| `train_anomaly_isoforest.py` | Isolation Forest no supervisado, políticas de ajuste | Todos |
| `train_anomaly_autoencoder.py` | Autoencoder tabular | ARGOS |
| `prepare_sequence_dataset.py` + `train_seq_gru.py` / `train_seq_tl_gru.py` | Secuencias por entidad y modelo recurrente | ARGOS, CIC |
| `metrics.py`, `reporting.py`, `train_utils.py`, `models_torch.py` | Métricas, curvas, matrices de confusión, importancia por permutación, desglose por grupo, semillas, estandarización | Todos |
| `compare_models.py` | Recopila todos los runs de `artifacts/` en `comparison.csv` | Todos |

### 2.2 Artefactos

Cada ejecución escribe en
`artifacts/<modelo>/<partición>/<dataset>__<régimen>[__<variante>]/<run_id>/`:
`metrics_{train,val,test}.json`, `results.json`, matriz de confusión, curvas PR
y ROC, importancia por permutación, `label_map.json`, `scaler.json` y el
modelo serializado. La ruta incluye el régimen de variables porque **el mismo
modelo bajo dos regímenes es un experimento distinto** y no debe sobrescribirse.

### 2.3 Regímenes de información (ARGOS-LAB y LAB-ALERTS)

Las variables sospechosas de fuga **no se eliminan: se aíslan**, para que todo
experimento declare con qué información se le permitió entrenar y la fuga se
convierta en magnitud medible.

| Régimen | Nº variables | Contenido | Función |
|---|---|---|---|
| `behavioral` | 54 | Volumen, diversidad de origen, entropía, geografía, novedad causal, línea base temporal por agente | **La estimación honesta** |
| `nosignature` | 61 | `behavioral` + identidad de agente y calendario | Mide el confundido host/cron |
| `full` | 98 | Todo, incluida la firma del motor de reglas | Techo de recuperabilidad de la etiqueta, **no un resultado** |
| `shape` | 29 | Solo adimensionales de `behavioral` (ratios, entropías, cuotas, puntuaciones z) | Transferencia entre máquinas de escala distinta |

### 2.4 Protocolos de partición

| Protocolo | Construcción | Pregunta que responde | Rigor |
|---|---|---|---|
| `random` | Muestreo aleatorio estratificado | ¿Interpola dentro de la misma distribución? | Bajo: sobre datos temporales **filtra información** |
| `date` | 70/15/15 por orden cronológico | ¿Generaliza a instantes futuros? | Medio |
| `day` (CIC-IDS2017) | Días completos distintos en train y test | Idem, con escenarios de ataque distintos por día | Medio-alto |
| `groupkfold` | *Leave-one-group-out* (agente, IP de origen, fold oficial) | ¿Generaliza a una entidad nunca vista? | Alto |
| `official` (UNSW-NB15) | Los CSV de train/test que publican los autores | ¿Se sostiene la cifra publicada? | Alto (distribuciones deliberadamente distintas) |

Regla del proyecto: **split temporal por defecto**; `prepare_sequence_dataset.py`
rechaza directamente `--split_mode random` porque secuencias consecutivas
filtrarían entre train y test.

### 2.5 Métricas y por qué esas

| Métrica | Uso | Motivo |
|---|---|---|
| **MCC** | Principal en binario | Vale 0 en el azar; la más robusta bajo desbalance severo (98 % de una clase en ARGOS) |
| **Macro-F1** y balanced accuracy | Multiclase y comparación entre módulos | Las clases raras pesan igual que las frecuentes |
| **PR-AUC de la clase minoritaria** con su línea base | Anomalías y clases raras | Su referencia no es 0,5 sino la prevalencia; se reporta siempre junto a ella y como **lift** (PR-AUC / prevalencia) |
| **ROC-AUC** | Ranking | Engaña con clases muy desbalanceadas (véase CSR-LANL: 0,96 de ROC con PR-AUC 0,017) |
| **Precisión@k** | Colas de revisión | Lo que un analista experimenta al revisar el k % mejor puntuado |
| **Recall a precisión ≥ 0,99** | Bloqueo | El mando operativo es la precisión, no el F1: bloquear a un legítimo cuesta más que dejar pasar avisos |
| **Exactitud** | Solo por completitud | Con prevalencia 0,98, responder siempre «ataque» acierta el 98 % |

### 2.6 Reglas metodológicas del proyecto

1. **Umbral fijado en validación, nunca `argmax`**: con un 2 % de clase minoritaria, `argmax` colapsa a la mayoritaria.
2. **Toda métrica agregada con su desglose por grupo** (`reporting.py::per_group_metrics`), con aviso automático cuando todos los grupos están en el azar. Nació del fallo del autoencoder (§9).
3. **Variables causales**: novedad y líneas base solo consultan el pasado.
4. **Ponderación de clases** activada por defecto en todos los clasificadores.
5. **Semilla 42** en todo; estandarización ajustada solo en train.
6. **Trabajo nuevo = ficheros nuevos** (`experiment_*.py`): ningún experimento modifica los scripts anteriores, para que los resultados registrados sigan siendo reproducibles.
7. **Validación externa de un solo disparo**: la canalización se congela antes y se ejecuta una vez; cada uso adicional degrada el conjunto externo a conjunto de desarrollo y debe declararse.
8. **Registro acumulativo** de resultados validados y retirados en `src/models/ARGOS_LAB/RESULTADOS.md` (R1–R13, X1–X3); lo retirado permanece listado como advertencia.

---

## 3. Glosario operativo

| Término | Significado en este trabajo |
|---|---|
| **Etiqueta débil** | Etiqueta generada por una heurística sobre reglas del SIEM, no por un analista. Barata y abundante; su calidad acota lo que cualquier modelo supervisado puede alcanzar. |
| **Circularidad** | La etiqueta se derivó de las mismas variables que se ofrecen como entrada; el modelo reconstruye la regla de etiquetado. |
| **Confundido de host** | Variables que codifican *qué máquina es* en lugar de *qué ocurre*; permiten predecir el agente con 99,75 % sin que su identificador esté entre ellas. |
| **Ventana** | Unidad de análisis: agregación de eventos por intervalo (1 min) y máquina. |
| **Presupuesto K** | En bloqueo temprano, número de avisos observados de una IP antes de decidir. |
| **Política secuencial** | Reevaluar con cada aviso y bloquear al primer cruce de umbral (umbral por K). |
| **Reputación causal de subred** | Cuántas IPs de la misma /24 o /16 llegaron antes y ya cumplían criterios de bloqueo en ese instante. |
| **Lift** | PR-AUC de la clase rara dividida por su prevalencia; 1× es el azar. |
| **Paradoja de Simpson** | Métrica agregada favorable sobre grupos donde todos fallan; la clase rara se concentra en un grupo. |
| **Prior shift** | Cambio de prevalencia entre validación y destino; obliga a mover el umbral. |
| **Censura** | En LAB-ALERTS (11 h) muchas IPs no tuvieron tiempo de completar su conducta; sus «falsos positivos» son en realidad atacantes cortados por el fin de la captura. |

---

# PARTE II · ARGOS-LAB, EL CORPUS PRINCIPAL

Módulo `src/models/ARGOS_LAB/` (34 scripts). Registro canónico de resultados:
`src/models/ARGOS_LAB/RESULTADOS.md`. Documentación del módulo:
`src/models/ARGOS_LAB/README.md`.

## 4. Los datos

### 4.1 Origen y volumen **[medido]**

Fuente: `src/models/ARGOS_LAB/argos-alerts_30d.manifest.json` (generado
2026-08-27 14:11 UTC por el export de la web, `GET /api/argos/dataset`).

| Magnitud | Valor |
|---|---|
| Alertas | **1.462.265** |
| Fichero | `argos-alerts_30d.jsonl`, 1,42 GB (1.424 MB en disco) |
| Rango | 2026-07-28 14:02:01 → 2026-08-27 14:08:31 UTC (31 días) |
| Ventanas (1 min × `agent_id`) | **88.384** |
| Agentes con alertas | 4 |
| Registros malformados | 0 |

Distribución por agente y su rol funcional (el rol es determinante en todos los
resultados de generalización):

| Agente | Rol | Alertas | Telemetría dominante |
|---|---|---|---|
| `000` | Manager Wazuh (host `wazuh`) | 815.051 | Fuerza bruta SSH entrante |
| `003` | Host del escáner de vulnerabilidades | 411.065 | Hallazgos Trivy (cron a horas fijas) |
| `011` | Servidor web (`clockworksolutions.es`) | 224.251 | Fuerza bruta SSH entrante |
| `030` | Honeypot T-Pot | 11.898 | **Solo ruido operativo del señuelo, 0 IPs de origen** |

> **Hallazgo sobre el honeypot.** Todo lo que llega a un honeypot es hostil por
> definición, pero Wazuh solo recogió el sistema operativo del señuelo: 6.955
> cambios de puertos a la escucha y 4.209 avisos de saturación de la cola del
> agente, sin una sola IP de origen. Las capturas de Cowrie/Dionaea residen en
> el Elasticsearch propio de T-Pot, no conservado. El agente 030 no aporta
> telemetría de seguridad explotable y distorsiona toda partición por host.

Reglas más frecuentes (manifest, `top_rules`):

| `rule_id` | Descripción | Alertas |
|---|---|---|
| 5710 | sshd: intento de acceso con usuario inexistente | 611.827 |
| 100204 | Trivy [MEDIUM] CVE en `curl` (imagen `clockwork-store`) | 246.446 |
| 5503 | PAM: fallo de inicio de sesión | 229.302 |
| 5718 | sshd: intento con usuario denegado (`AllowUsers`) | 152.768 |
| 100203 | Trivy [HIGH] CVE en `c-ares` | 78.447 |
| 100205 | Trivy [LOW] CVE en `libcrypto3` | 76.014 |
| 5551 | PAM: múltiples fallos en poco tiempo | 12.338 |

Solo hay **48 `rule_id` distintos**; `rule_description` tiene 9.228 valores
porque incrusta identificadores de CVE.

### 4.2 Las etiquetas y de dónde salen **[documentado]**

No existe clase benigna real: Wazuh solo indexa lo que dispara una regla, así
que el volcado contiene ataques y hallazgos de inventario, no tráfico normal.
La etiqueta débil la produce la política `lab_alerts_weak_label_v1` con
precedencia `rule.groups > rule.mitre.tactic > regex de descripción > grupos de
postura > grupos operativos > suelo de severidad`.

| Nivel | ATTACK | BENIGN | UNKNOWN |
|---|---|---|---|
| Alerta | 1.029.526 | 424.743 | 7.996 |
| Ventana (1 min × agente) | **79.851** | **1.738** | 6.795 |

Motivos de la etiqueta (manifest, `weak_label_reason_distribution`, alertas):
`attack_group:authentication_failed` 849.049 · `posture_group:trivy` 410.611 ·
`attack_group:invalid_login` 159.463 · `attack_group:authentication_failures`
20.536 · `operational_group:syslog` 9.353 · `no_policy_match` 7.996 ·
`posture_group:agent_flooding` 4.495 · `mitre_tactic:impact` 253 ·
`posture_group:sca` 169 · `attack_group:rootcheck` 163 · resto < 100 cada uno.

Taxonomía que trae el export (`taxonomy_label`): `CredentialAccess` 1.028.914 ·
`SystemAlert` 433.164 · `AuthenticationFailure` 135 · `OtherAlert` 39 ·
`ServiceFailure` 13. Es **degenerada**: dos clases cubren el 99,99 %, por lo que
el módulo construye su propia taxonomía de actividad (§5.4).

**La clase minoritaria a nivel ventana es el 2,1 % y, contra la intuición, es
BENIGN**: el 98,64 % de las ventanas con etiqueta son ATTACK (ruido de fuerza
bruta procedente de internet). Responder siempre «ataque» acierta el 98,64 %.

### 4.3 Columnas útiles, inútiles y tóxicas **[documentado]**

Decidido a partir del perfilado completo del fichero (`feature_spec.py` fija el
criterio, `prepare_dataset.py` lo aplica).

**Descartadas, sin señal alguna**

| Columna | Motivo |
|---|---|
| `alert_id` | Identificador único por fila |
| `is_simulated` | Constante 0 en las 1.462.265 filas |
| `dst_port` | Vacía en el 100 % de las filas |
| `agent_name`, `agent_ip` | Redundantes 1:1 con `agent_id`; se conservan como metadatos |
| `full_log` | Texto libre, ~70 % del tamaño del fichero, redundante con `rule_id` |
| `weak_label_reason` | Es la derivación de la etiqueta: usarla es tautológico |

**Alta cardinalidad: nunca *one-hot*, siempre agregadas**

| Columna | Valores distintos | Tratamiento |
|---|---|---|
| `src_port` | 38.203 | Solo presencia y entropía |
| `src_user` | 13.211 | Nº distintos, entropía, cuota del más frecuente, ratio de cuentas de sistema |
| `rule_description` | 9.228 | Metadato (inflada por CVEs; `rule_id` solo tiene 48) |
| `src_ip` | 4.792 | Nº distintos, entropía, cuota del top, tasa de IPs nuevas |
| `geo_city` | 723 | Nº distintos |

**Tóxicas: entradas de la propia regla de etiquetado.** No se eliminan: se
aíslan en el grupo `signature` para medir cuánto aportan.

```
rule_groups=authentication_failed → 100,00 % ATTACK   (849.049 filas)
rule_groups=invalid_login         → 100,00 % ATTACK   (771.290 filas)
rule_groups=trivy                 → 100,00 % BENIGN   (410.611 filas)
decoder_name=trivy-decoder        → 100,00 % BENIGN   (410.611 filas)
agent_id=003                      →  99,96 % BENIGN   (410.737 filas)
hora ∈ {06, 07, 18, 19}           →  ~70 %   BENIGN   (cron de Trivy)
```

Las dos últimas filas son el motivo de que `agent_id` y el calendario formen su
propio grupo (`context`): son variables operativas legítimas en producción,
pero **confundidas** en esta captura (un agente es el escáner y el escáner corre
a horas fijas).

**La severidad también está invertida.** Se descartó etiquetar por
`rule_level`: sale del mismo motor y en estos datos los hallazgos de Trivy son
nivel 12–14 mientras la fuerza bruta real es nivel 5. La regla «nivel ≥ 10 ⇒
ataque» **erraría el 70,8 %** de lo que captura **[medido]** (docstring de
`build_block_labels.py`).

---

## 5. Preprocesado

### 5.1 Ventaneo **[documentado]**

`prepare_dataset.py` recorre el JSONL una sola vez en *streaming* plegando
alertas en acumuladores por (ventana de 1 min, `agent_id`): la memoria escala
con el número de ventanas (~88.000), no de alertas (1,46 M). El recuento
reproduce exactamente el del manifest (79.851 / 1.738 / 6.795), lo que valida
la implementación. Duración: ~4 min sobre el fichero completo. Salida:
`datasets/{date,random,groupkfold}/ARGOS-LAB/{binary,multiclass,taxonomy}/{train,val,test}/*.parquet`
(118 ficheros Parquet en la ejecución completa).

Variante `--exclude_posture --dataset ARGOS-LAB-NOPOSTURE`: elimina las alertas
de postura (grupos `trivy`, `sca`, `vulnerability-detector`, `syscheck*`,
`rootcheck` y sus decoders), que son el 97,8 % de las filas BENIGN, para exponer
la tarea genuinamente difícil.

Las ventanas UNKNOWN (6.795: cambios de `netstat` y paquetes `dpkg` que la
política no supo clasificar) quedan **fuera del entrenamiento supervisado** y
se conservan para la evaluación no supervisada.

### 5.2 Las 98 variables, por grupo **[documentado]** (`feature_spec.py`)

**`behavioral` (54)**

| Familia | Variables |
|---|---|
| Volumen y ritmo (8) | `alert_count`, `log_alert_count`, `span_seconds`, `alerts_per_second`, `mean_interarrival`, `std_interarrival`, `min_interarrival`, `burstiness_index` |
| Diversidad de origen (11) | `unique_src_ip`, `unique_src_user`, `unique_dst_user`, `unique_src_port`, `src_ip_entropy`, `src_ip_entropy_norm`, `top_src_ip_share`, `src_user_entropy`, `src_user_entropy_norm`, `top_src_user_share`, `src_port_entropy_norm` |
| Ratios combinados (7) | `alerts_per_src_ip`, `users_per_src_ip`, `ports_per_src_ip`, `alerts_per_src_user`, `src_ip_present_ratio`, `src_port_present_ratio`, `dst_user_present_ratio` |
| Geografía (10) | `unique_country`, `unique_city`, `country_entropy_norm`, `top_country_share`, `geo_missing_ratio`, `geo_lat_mean`, `geo_lon_mean`, `geo_lat_std`, `geo_lon_std`, `geo_spread` |
| Novedad y persistencia, causales (7) | `new_src_ip_count`, `new_src_ip_ratio`, `repeat_src_ip_ratio`, `new_src_user_count`, `new_src_user_ratio`, `mean_src_ip_seen_before`, `max_src_ip_seen_before` |
| Objetivo de credenciales (2) | `root_user_ratio`, `system_user_ratio` |
| Línea base temporal por agente, causal (9) | `agent_gap_seconds`, `agent_count_lag1`, `agent_count_lag2`, `agent_count_roll_mean`, `agent_count_roll_std`, `agent_count_z`, `agent_uniqip_roll_mean`, `agent_uniqip_z`, `agent_window_index` |

**`context` (7)**: `agent_id_code`, `event_hour`, `hour_sin`, `hour_cos`,
`day_of_week`, `is_weekend`, `is_night`.

**`signature` (37)**: estadísticos de `rule_level` (media, máx., mín., desv.,
suma, rango, recuentos y ratios ≥ 7/10/12), `unique_rule_count`,
`rule_entropy_norm`, `top_rule_share`, `rule_firedtimes_{mean,max,sum}`,
`mitre_tagged_ratio`, `credential_tactic_ratio`, `lateral_tactic_ratio`,
`impact_tactic_count`, `evasion_tactic_count`, once ratios `grp_*` (auth_failed,
invalid_login, sshd, pam, trivy, agent_flooding, syscheck, sca, ossec, dpkg,
syslog), `unique_decoder_count`, `unique_location_count`, `decoder_code`,
`program_code`, `location_code`.

**`shape` (29)**: el subconjunto adimensional de `behavioral` (ratios,
entropías normalizadas, cuotas, `burstiness_index`, los tres interarrival,
`geo_spread`, `geo_lat_std`, `geo_lon_std`, `agent_count_z`, `agent_uniqip_z`).

### 5.3 Variables derivadas: qué fenómeno capturan

| Variable | Fórmula | Qué detecta |
|---|---|---|
| `alerts_per_src_ip` | alertas / IPs distintas | Intensidad por origen: fuerza bruta concentrada |
| `users_per_src_ip` | usuarios / IPs distintas | *Credential spraying* frente a ataque dirigido |
| `src_ip_entropy_norm` | H(IPs) / log k | Un atacante vs. botnet distribuida |
| `new_src_ip_ratio` | IPs nunca vistas / IPs de la ventana | Novedad (causal) |
| `mean_src_ip_seen_before` | frecuencia histórica acumulada | Reincidencia del origen |
| `burstiness_index` | σ(Δt) / μ(Δt) | Ráfaga automatizada vs. tráfico regular |
| `agent_count_z` | (n − μ₁₅) / σ₁₅ del propio agente | Desviación sobre la línea base propia del host |
| `root_user_ratio`, `system_user_ratio` | mezcla `src_user` + `dst_user` contra una lista de 22 cuentas de servicio | Objetivo de credenciales privilegiadas |
| `geo_spread` | √(σ²lat + σ²lon) | Dispersión geográfica del origen |

### 5.4 Taxonomía de actividad propia (9 clases) **[documentado]**

Derivada de `rule_groups`/`rule_id` por alerta (`feature_spec.activity_class`)
y agregada a la ventana por mayoría: `CredentialBrute`, `PamAuth`,
`SshOperational`, `PostureVuln`, `PostureSCA`, `AgentHealth`, `IntegrityChange`,
`PackageChange`, `PortChange`, `Other`. Familias **hostiles** (suman el
`attack_score` del puntuador de actividad): `CredentialBrute`, `PamAuth`,
`IntegrityChange`. Las demás son operativas o de postura.

### 5.5 Secuencias por agente **[documentado]**

`prepare_sequence_dataset.py`: las últimas 12 ventanas consecutivas de un mismo
agente (`--seq_len 12`, paso 1), etiqueta de la última; nunca se cruza un
agente ni un hueco > 60 min. Se cortan de los Parquet ya particionados, así que
la separación train/val/test se preserva exactamente. El script rechaza
`--split_mode random`.

### 5.6 Particiones

`date` (70/15/15 cronológico; test = 11.711 ventanas con etiqueta binaria),
`random` (solo para medir el colapso) y `groupkfold` (*leave-one-agent-out*, 4
folds).

---

## 6. Auditoría de fuga (R1) — se ejecuta antes que nada

`leakage_audit.py` ajusta clasificadores deliberadamente triviales —una
variable, un grupo, un régimen— sobre la etiqueta débil binaria. Si un modelo de
una variable alcanza la puntuación del modelo completo, la tarea es
reconstrucción de etiqueta, no detección.

**Partición temporal, 11.711 ventanas de test** **[medido]**
(`artifacts/leakage_audit/date/`; la ejecución `random` del run
`20260827_164804` da cifras equivalentes: `mitre_tagged_ratio` 0,9987,
`grp_invalid_login_ratio` 0,9981, grupo `signature` 1,0000):

| Sonda | Nº variables | ROC-AUC | Lectura |
|---|---|---|---|
| `mitre_tagged_ratio` sola | 1 | **0,9990** | Una columna reproduce el modelo completo |
| `grp_invalid_login_ratio` sola | 1 | 0,9984 | Grupo de regla |
| `rule_level_max` sola | 1 | 0,9920 | Nivel de regla |
| `decoder_code` sola | 1 | 0,9411 | Identidad del decoder |
| `agent_id_code` sola | 1 | ~0,91 | Identidad del host |
| `event_hour` sola | 1 | ~0,56 | El cron, débil por sí solo |
| grupo `signature` | 37 | **1,0000** | Separación perfecta |
| grupo `behavioral` | 54 | 0,9998 | Fuga estructural, no de regla (ver abajo) |
| grupo `context` | 7 | ~0,96 | Host + hora |
| régimen `full` | 98 | 1,0000 | |

**Importancia por permutación** (barajar una sola columna y medir la caída de
PR-AUC de la clase minoritaria) **[medido]**:

| Régimen | Columna | Caída de PR-AUC |
|---|---|---|
| `full` | `mitre_tagged_ratio` | **−0,486** |
| `behavioral` | `src_ip_present_ratio` | **−0,827** |

Las 97 columnas restantes suman menos que la primera: ambos regímenes son, de
hecho, modelos de una sola variable.

**El segundo hallazgo es más sutil.** Incluso `behavioral` llega a 0,9998 porque
las ventanas BENIGN **son estructuralmente otro tipo de alerta**: los hallazgos
de Trivy no tienen origen de red, así que `src_ip_present_ratio = 0` delata la
clase sin intervención de la regla. No es circularidad, sino que ambas clases
son fenómenos distintos. Por eso la variante sin postura no es opcional.

**Consecuencia de diseño:** los campos `rule_*`, `mitre_*` y `decoder_name` no
entran en ningún modelo del paquete de despliegue.

---

## 7. Tareas supervisadas sobre la etiqueta débil

### 7.1 Binario **[medido]** (`artifacts/comparison.csv`, runs `20260827_16xxxx`, partición `date`)

| Modelo | Régimen | Balanced acc. | Macro-F1 | MCC | PR-AUC minoría | ROC-AUC | Exactitud |
|---|---|---|---|---|---|---|---|
| HGB | `full` | 0,9975 | 0,9975 | 0,9950 | 1,0000 | 1,0000 | 0,9998 |
| HGB | `nosignature` | 0,9751 | 0,9774 | 0,9549 | 0,9945 | 0,9999 | 0,9985 |
| HGB | `behavioral` | 0,9776 | 0,9776 | **0,9551** | 0,9930 | 0,9999 | 0,9985 |
| HGB sin postura | `behavioral` | 0,9779 | 0,9805 | 0,9609 | 0,9961 | 0,9999 | 0,9988 |
| HGB sin postura | `full` | 1,0000 | 0,9986 | 0,9972 | 1,0000 | 1,0000 | 0,9999 |
| MLP (DL) | `full` | 0,9926 | 0,9962 | 0,9925 | 1,0000 | 1,0000 | 0,9997 |
| MLP (DL) | `nosignature` | 0,9702 | 0,9736 | 0,9473 | 0,9837 | 0,9998 | 0,9982 |
| MLP (DL) | `behavioral` | 0,9507 | 0,9664 | 0,9335 | 0,9778 | 0,9997 | 0,9978 |
| GRU (L = 12) | `behavioral` | 0,8225 | 0,8771 | 0,7653 | 0,8962 | 0,9995 | 0,9989 |

Hiperparámetros **[documentado]**: HGB `max_iter` 300, `learning_rate` 0,08,
profundidad 6, L2 1,0, parada temprana 15, ponderación de clases; MLP 256 × 3
capas con BatchNorm, dropout 0,3, AdamW 1e-3, `ReduceLROnPlateau`, selección por
macro-F1 en validación; GRU 128 unidades, 1 capa, LayerNorm, dropout 0,2.

**Lectura.** La tarea está **saturada en todo régimen**, incluso sin postura:
las clases se separan por volumen bruto de actividad. El binario a un minuto no
es un problema informativo y **ninguna de estas cifras debe presentarse como
detección** (X2). El aprendizaje profundo no supera al gradient boosting en
tabular (0,9664 frente a 0,9776 de macro-F1 en `behavioral`).

### 7.2 Multiclase por familia de actividad (R3) — la única tarea no saturada **[medido]**

| Modelo | Régimen | Balanced acc. | Macro-F1 | ROC-AUC (OvR) |
|---|---|---|---|---|
| HGB | `full` | 0,9993 | **0,9911** | 0,9996 |
| HGB | `behavioral` | 0,8057 | **0,7738** | 0,9727 |
| GRU (L = 12) | `behavioral` | 0,6796 | 0,5950 | 0,9204 |
| `agent_id` solo (referencia) | — | — | 0,2579 | — |

Macro-F1 0,7738 con información exclusivamente conductual sobre nueve clases es
un resultado real y no trivial, **no explicado por el agente** (0,2579 con
`agent_id` solo). El salto a 0,9911 al añadir la firma **cuantifica limpiamente
la fuga**. Variables dominantes, interpretables: `agent_gap_seconds` (0,244),
`src_ip_present_ratio` (0,216), `alert_count` (0,152), `burstiness_index`
(0,082). Las clases raras siguen siendo difíciles: `IntegrityChange` F1 = 0,42
con 15 muestras de test.

---

## 8. Generalización entre máquinas (leave-one-agent-out) y huella de host (R2)

### 8.1 LOAO **[medido]** (`ml_binary_hgb/groupkfold/ARGOS-LAB__behavioral/20260827_164946`, `dl_binary_mlp/.../20260827_164954`)

| Fold | Test = agente | Rol | Balanced acc. | MCC | ROC-AUC | Lectura |
|---|---|---|---|---|---|---|
| 0 | `000` | Manager | 0,8732 | 0,8080 | 0,9998 | Funciona |
| 1 | `003` | Escáner | 0,8763 | 0,7809 | 0,9234 | Funciona |
| 2 | `011` | **Servidor web** | 0,5000 | **0,0000** | 0,9268 | **Fallo total** |
| 3 | `030` | Honeypot | 0,4855 | −0,0314 | 0,3375 | No evaluable (sin telemetría útil) |
| **Media HGB** | | | **0,6838** | **0,3894** | 0,7969 | |
| Media MLP | | | 0,5867 | **0,1221** | 0,7828 | Peor aún |

Dentro del mismo periodo el modelo alcanza MCC 0,955; en la máquina más parecida
a producción cae a **0,0000**: rendimiento idéntico al azar. Excluyendo el
honeypot del promedio (no mide generalización) la media queda en 0,7498 /
0,5296 / 0,9500; incluirlo *exagera* el hallazgo negativo. **Consecuencia
operativa: hay que reentrenar por host** y las métricas de un host no predicen
las de otro.

### 8.2 La huella de máquina **[medido]** (demostrado en sesión, base del diseño por host)

Con las 54 variables `behavioral` —sin `agent_id_code`— se predice **qué agente
es con 99,75 % de exactitud**. La identidad está repartida de forma redundante
entre variables correlacionadas:

| Agente | `src_ip_present_ratio` | `geo_missing_ratio` | `alert_count` medio |
|---|---|---|---|
| `000` | 0,995 | 0,028 | 19,7 |
| `003` | 0,075 | 0,925 | 2.072 |
| `011` | 0,983 | 0,043 | 6,0 |
| `030` | 0,000 | 1,000 | 1,5 |

Quitar una columna no elimina un confundido distribuido. Un ensayo con
variables exclusivamente adimensionales (`shape`) mejora la transferencia solo
+0,017 de MCC: **la normalización no compensa un cambio de rol** (los cuatro
agentes no son cuatro muestras de «un host» sino cuatro roles distintos).

---

## 9. Detección de anomalías no supervisada — resultado retirado (X1)

**[medido]** (`anomaly_isoforest/date/ARGOS-LAB__behavioral__*`,
`dl_anomaly_autoencoder/date/ARGOS-LAB__behavioral__*`, runs `20260827_1650xx`–`1651xx`;
clase rara evaluada: BENIGN, prevalencia 0,0174 en test)

| Modelo | Política de ajuste | ROC-AUC | PR-AUC rara | Lift agregado | Precisión@1 % | Lift por agente |
|---|---|---|---|---|---|---|
| Isolation Forest (400 árboles, `max_samples` 65.536) | `quiet` (ventanas rutinarias) | 0,5403 | 0,0232 | 1,33× | 0,060 | ≤ 1,0× |
| Isolation Forest | `all` | 0,5465 | 0,0266 | 1,53× | 0,068 | ≤ 1,0× |
| Autoencoder (latente 12, oculto 96) | `quiet` | 0,6984 | 0,1148 | 6,59× | 0,282 | — |
| Autoencoder | `all` | 0,7164 | 0,3182 | **18,26×** | 0,650 | **0,57×–0,95×** |
| Isolation Forest / Autoencoder | `benign` | 0,983 / 0,988 | 0,882 / 0,826 | 50,7× / 47,4× | 0,897 / 0,880 | sin desglose en el artefacto → no citable por la regla del proyecto |

**Desglose del autoencoder `all` por agente**, que es lo que lo retira:

| Agente | n test | BENIGN | PR-AUC | Línea base | Lift |
|---|---|---|---|---|---|
| `000` | 6.075 | 12 | 0,0017 | 0,0020 | **0,84×** |
| `003` | 30 | 23 | 0,7318 | 0,7667 | **0,95×** |
| `011` | 5.437 | 17 | 0,0018 | 0,0031 | **0,57×** |
| `030` | 169 | 152 | 0,7810 | 0,8994 | **0,87×** |
| Global (engañoso) | 11.711 | 204 | 0,3182 | 0,0174 | 18,26× |

Dentro de cada agente el detector está **en el azar o por debajo**. El 18,26×
global procede de que la clase BENIGN se concentra al 74,5 % en el agente 030
(prevalencia 89,9 %) y al 76,7 % en el 003, mientras 000 y 011 son 99,8 % ATTACK:
el autoencoder ordena «esto es del agente 030», no «esto es anómalo».
**Paradoja de Simpson** medida sobre datos propios. Ajustar el detector por host
tampoco lo arregla (lift medio 0,73× frente a 1,07× del global). De este fallo
nace la regla de desglose obligatorio instrumentada en `reporting.py`.

---

## 10. Puntuador de actividad por host — el resultado supervisado que sobrevive

`train_activity_scorer.py` **[documentado]**: sustituye la tarea binaria
circular por clasificación de familia de actividad (§5.4) con **un modelo por
host**, probabilidades **calibradas** (isotónica) y **rechazo** de actividad
desconocida cuando la probabilidad máxima cae bajo un cuantil fijado en
validación. El `attack_score` es la suma de probabilidades de las familias
hostiles.

**Por agente sobre test** **[medido]** (`artifacts/activity_scorer/date/ARGOS-LAB__behavioral/`):

| Agente | n | % hostil | ROC-AUC del `attack_score` | Lift |
|---|---|---|---|---|
| `000` | 6.075 | 99,7 % | 0,9909 | 1,00× |
| `003` | 33 | 12,1 % | 0,8362 | **3,08×** |
| `011` | 5.438 | 99,5 % | 0,9997 | 1,00× |
| `030` | 1.156 | **0,78 %** | 0,9785 | **46,18×** |

A diferencia del autoencoder, **funciona dentro de cada agente**: en el 030
localiza 9 ventanas hostiles entre 1.156 sin salir del host. Macro-F1 por
agente sobre el conjunto completo de clases: 0,42–0,57 (un 0,9654 citado antes
correspondía a un subconjunto de 3 clases y no es comparable).

**Modelos ajustados en el run `20260901_231641`** (`holdout_family PortChange`,
`reject_quantile` 0,5): host 000, 28.550 ventanas de train, clases
`CredentialBrute`/`SshOperational`; host 011, 28.327, clases `AgentHealth`/
`CredentialBrute`/`SshOperational`; host 030, 894, clases `AgentHealth`/
`IntegrityChange`/`Other`/`PostureSCA`; host 003 (133 ventanas) sin modelo
propio → reserva global (57.928 ventanas, 8 clases). Test: `attack_score`
ROC-AUC 0,9993, macro-F1 de familia 0,4465 (con `PortChange` oculta).

**Rechazo de actividad desconocida**, ocultando por completo `PortChange` del
entrenamiento **[medido]**:

| `reject_quantile` | Rechaza la familia no vista | Rechaza actividad conocida | Razón |
|---|---|---|---|
| 0,05 | 3,7 % | 4,3 % | 0,85× (inútil) |
| 0,25 (por defecto) | 39,5 % | 20,8 % | 1,90× |
| 0,50 | **99,8 %** | 34,4 % | 2,90× |

Es el mando de coste operativo: a 0,50 se captura casi toda la actividad
novedosa a cambio de revisar un tercio del tráfico conocido. Se prefiere al
detector de anomalías porque este, medido por agente, no supera el azar.

---

## 11. La etiqueta de bloqueo por conducta (R4) — rompe la circularidad

`build_block_labels.py` **[documentado]** construye una etiqueta **independiente
del motor de reglas**: si una dirección de origen debe bloquearse, juzgado
únicamente por lo que hizo. Campos empleados: `src_ip`, `src_user`, `dst_user`,
`agent_id`, `timestamp` (hechos extraídos por el decoder, no veredictos).

| Criterio | Condición | Intuición |
|---|---|---|
| **Enumeración** | ≥ 5 cuentas distintas probadas | Ningún usuario legítimo prueba cinco cuentas |
| **Amplitud** | ≥ 2 máquinas alcanzadas | Propiedad del atacante, no del host |
| **Persistencia** | ≥ 50 intentos en ≥ 3 ventanas distintas | Insistencia automatizada |

Cualquiera basta. El perfil de cada IP se acumula **solo con el pasado**: una
ventana en T se etiqueta con lo que sus IPs habían hecho hasta T. Solo se
etiquetan ventanas **con origen de red** (sin `src_ip` no hay nada que
bloquear), lo que excluye por construcción los hallazgos de escáner y el ruido
del honeypot.

**Resultado** **[medido]** (`datasets/block_labels/block_labels_summary.json`):

| Magnitud | Valor |
|---|---|
| Ventanas con origen de red | **80.221** |
| BLOCK / ALLOW | 78.216 / **2.005** |
| Por agente | `000`: 40.123 / 826 · `011`: 38.093 / 1.164 · `003`: 0 / 15 |
| Motivo dominante (ventanas) | enumeración 65.269 · persistencia 7.244 · amplitud 5.703 |
| IPs perfiladas | 4.792 |

**Auditoría de circularidad**, misma metodología de sondas de una variable que
destapó la fuga **[medido]** (`artifacts/block_scorer/date/ARGOS-LAB__shape/20260901_234359`):

| Sonda (ROC-AUC sobre la nueva etiqueta) | |
|---|---|
| `root_user_ratio` | **0,6641** (la mejor) |
| `burstiness_index` | 0,6619 |
| `src_user_entropy_norm` | 0,6599 |
| `new_src_ip_ratio` / `repeat_src_ip_ratio` | 0,6478 |
| `top_src_user_share` | 0,6392 |
| `users_per_src_ip` | 0,5959 |
| `new_src_user_ratio` | 0,5041 |

Frente a 0,9990 de la etiqueta débil: **no reconstruible desde una variable,
circularidad rota**. Y el efecto es medible (§12): con la etiqueta débil el
traslado entre hosts colapsaba a MCC 0,000; con esta retiene el 65–104 %. *El
problema nunca fue el modelo, era la pregunta.*

---

## 12. Puntuador de bloqueo por ventana (R5) y su transferencia

### 12.1 Rendimiento nativo y transferido **[medido]** (`artifacts/exp_block_transfer/date/ARGOS-LAB/20260902_120300`)

Solo dos agentes tienen origen de red (000 y 011). Se entrena en el split
`train` del host origen y se evalúa en el split `test` del destino; la
referencia es entrenar y evaluar en el destino (nativo). Clase rara: ALLOW
(prevalencia 1,1 % en 000, 2,8 % en 011).

| Régimen | Dirección | n test | ROC-AUC | MCC | PR-AUC ALLOW | Lift ALLOW | MCC retenido vs nativo |
|---|---|---|---|---|---|---|---|
| `behavioral` (54) | 000 → 000 (nativo) | 6.073 | 0,9230 | 0,3405 | 0,4940 | **43,48×** | — |
| | 011 → 011 (nativo) | 5.435 | 0,9317 | 0,5712 | 0,5517 | **19,99×** | — |
| | 000 → 011 (transferido) | 5.435 | 0,9107 | 0,3739 | 0,5385 | 19,51× | **65,5 %** |
| | 011 → 000 (transferido) | 6.073 | 0,8640 | 0,3473 | 0,2810 | 24,73× | **102,0 %** |
| `shape` (29) | 000 → 000 (nativo) | 6.073 | 0,8301 | 0,4858 | 0,3665 | 32,26× | — |
| | 011 → 011 (nativo) | 5.435 | 0,8092 | 0,4135 | 0,3474 | 12,59× | — |
| | 000 → 011 (transferido) | 5.435 | 0,7608 | 0,4287 | 0,2913 | 10,55× | 103,7 % |
| | 011 → 000 (transferido) | 6.073 | 0,7143 | 0,3531 | 0,2865 | 25,22× | 72,7 % |

Referencia contra la que se compara: **MCC 0,000** del agente 011 con la
etiqueta débil (LOAO). El puntuador de bloqueo, transferido a un host que nunca
vio, retiene entre el 65 % y el 104 % del MCC nativo. Recall por motivo de
bloqueo ≥ 0,996 en los tres criterios (`block_scorer`, test).

Modelo del paquete de despliegue (`window_block.joblib`): HGB `behavioral`
entrenado sobre 56.883 ventanas, calibrado isotónico.

### 12.2 Adaptación de dominio sin etiquetas — perjudicial (X3) **[medido]** (`artifacts/exp_domain_adaptation/date/ARGOS-LAB/20260902_125614`)

Antes de puntuar, cada host reexpresa sus variables con estadísticas de sus
propias ventanas de train: `zhost` (z-score por host) o `rank` (ECDF por host).

| Régimen | Dirección | raw MCC | zhost MCC | rank MCC |
|---|---|---|---|---|
| `behavioral` | 000 → 011 | 0,3739 | **0,1851** | 0,3885 |
| | 011 → 000 | 0,3473 | **0,0879** | 0,4229 |
| `shape` | 000 → 011 | 0,4287 | 0,3533 | 0,3681 |
| | 011 → 000 | 0,3531 | 0,3138 | **0,4391** |

El z-score por host resta entre **0,08 y 0,26 de MCC**. Regla aprendida:
normalizar por host ayuda cuando la etiqueta es relativa al host y estorba
cuando es absoluta (probar ocho cuentas es hostil en cualquier máquina). La
transformación de rango es mixta (mejor caso 0,4391, no consistente). Ninguna
se adopta.

---

## 13. Bloqueo temprano por IP: de detección a prevención (R7, R9, R10, R13)

### 13.1 Planteamiento **[documentado]** (`experiment_early_blocking.py`)

La acción operativa —bloquear— se aplica a una IP, no a un minuto. Se cambia la
unidad: puntuar la dirección con **solo sus primeros K avisos** y predecir si su
historial completo acabará cumpliendo los criterios de bloqueo de §11. Cada
acierto temprano suprime todos los avisos que ese origen habría generado
después. Partición **temporal por primera aparición de la IP** (70/15/15): sin
solapamiento de IPs entre particiones.

| Magnitud | Valor **[medido]** |
|---|---|
| IPs con origen de red | 4.792 → train 3.354 / val 719 / test 719 |
| Bloqueables al final de su historial | 3.550 (74,1 %); en val 58 %, en test **84,8 %** (prior shift) |
| Longitud del historial (avisos) | mediana 39; percentiles 10/25/75/90/99: 1 / 6 / 136 / 346 / 3.819; máx. 32.292 |
| Mediana de longitud de las bloqueables / no bloqueables | 72 / 1 |

Variables v1 (13, solo sobre los primeros K avisos): `n_alerts`, `n_users`,
`n_agents`, `n_windows`, `span_seconds`, `mean_interarrival`, `min_interarrival`,
`alerts_per_user`, `users_per_alert`, `root_ratio`, `system_user_ratio`,
`port_present_ratio`, `alerts_first_minute`. Umbral por K fijado en validación
para **precisión ≥ 0,99**.

### 13.2 Presupuesto fijo (v1) **[medido]** (`artifacts/exp_early_blocking/date/ARGOS-LAB/20260902_125434`)

| K | ROC-AUC | PR-AUC | Umbral p99 (val) | Precisión test | Recall test | IPs legítimas cortadas | Avisos evitados |
|---|---|---|---|---|---|---|---|
| 1 | 0,5204 | 0,8613 | 0,749 | 0,979 | 0,077 | 1 | 6,5 % |
| 2 | 0,9252 | 0,9823 | 0,830 | 1,000 | 0,364 | 0 | 16,3 % |
| 3 | 0,9603 | 0,9912 | 0,892 | 0,990 | 0,479 | 3 | 25,8 % |
| 5 | 0,9950 | 0,9990 | 0,969 | 0,998 | **0,820** | 1 | 52,5 % |
| 10 | 0,9985 | 0,9997 | 0,855 | 0,998 | 0,961 | 1 | 84,0 % |
| 20 | 0,9999 | 1,0000 | 0,519 | 0,998 | 0,995 | 1 | 96,7 % |

### 13.3 Política secuencial y reputación de subred (v2, R7) **[medido]** (`artifacts/exp_early_blocking_v2/date/ARGOS-LAB/20260902_130816`)

Tres mejoras, cada una contra una pérdida identificada:

1. **Política secuencial.** En despliegue se reevalúa con **cada** aviso y se
   bloquea al primer cruce de umbral (K = 1, 2, 3, 5, 10, 20).
2. **Reputación causal de subred** (7 variables: `sub24_seen`, `sub24_hostile`,
   `sub24_hostile_ratio`, `sub16_*`, `fleet_new_ips_last_hour`): al llegar la IP
   X en t, solo cuentan las IPs de su /24 y /16 llegadas antes de t y que **ya**
   cumplían criterios antes de t. Más `std_interarrival` y `cv_interarrival`.
   Total v2: 22 variables.
3. **Diagnóstico de umbral**: se reporta el recall con umbral-oráculo sobre test
   para separar la pérdida por *prior shift* (58 % → 85 %) del límite del modelo.

| K | AUC v1 | AUC v2 | Recall v1 | Recall v2 | Recall oráculo v2 |
|---|---|---|---|---|---|
| 1 | 0,5204 | **0,8257** | 0,077 | 0,008 | 0,023 |
| 2 | 0,9252 | 0,9277 | 0,364 | 0,402 | 0,469 |
| 3 | 0,9603 | 0,9602 | 0,479 | 0,448 | 0,626 |
| 5 | 0,9950 | 0,9949 | 0,820 | 0,846 | 0,987 |
| 10 | 0,9985 | 0,9986 | 0,961 | 0,962 | 0,998 |
| 20 | 0,9999 | 0,9999 | 0,995 | 0,990 | 1,000 |

La reputación de subred es lo único que permite ordenar al **primer aviso**
(AUC 0,52 → 0,83): las botnets se agrupan en rangos.

**Política secuencial sobre las 719 IPs de test — el resultado estrella:**

| Métrica | Valor |
|---|---|
| Recall acumulado | **0,990** (frente a 0,820 a K = 5 fijo) |
| Precisión | **0,995** (3 legítimas cortadas en el mes de test) |
| Aviso mediano de corte | **5º** |
| Avisos evitados | **44.315 de 49.628 = 89,3 %** |
| Reparto de bloqueos por K | 1: 5 · 2: 241 · 3: 43 · 5: 230 · 10: 69 · 20: 16 |

Mecanismo honesto: es detección rápida más **anticipación parcial** — a K = 5, de
las IPs que aún no cumplían criterios se anticipa el 21,6 %; a K = 10, el 74,4 %.

### 13.4 Umbral adaptativo a la prevalencia (R9) **[medido]** (`artifacts/exp_adaptive_threshold/date/ARGOS-LAB/20260902_135124`)

Corrección de *prior shift* sin etiquetas del destino: calibración isotónica en
validación, prevalencia estimada como media de los scores calibrados del
destino, y el menor umbral cuya precisión esperada bajo esa prevalencia sea
≥ 0,99.

| K | π real test | π̂ estimada | Recall base (umbral val) | Recall adaptativo | Precisión adaptativa | FP | Recall oráculo |
|---|---|---|---|---|---|---|---|
| 2 | 0,848 | 0,799 | 0,402 | 0,402 (sin cambio) | 0,996 | 1 | 0,469 |
| 3 | 0,848 | 0,819 | 0,448 | **0,638** | 0,990 | 4 | 0,626 |
| 5 | 0,848 | 0,840 | 0,846 | **0,900** | 0,996 | 2 | 0,987 |

Todo lo que usa del destino es la distribución de scores, observable en
despliegue sin etiquetar nada. Disponible como ajuste en el paquete si la mezcla
de tráfico difiere mucho de la captura.

### 13.5 GRU sobre la secuencia de avisos (R10) — sin ventaja **[medido]** (`artifacts/exp_early_blocking_gru/date/ARGOS-LAB/20260902_140644`)

Ficha por aviso (7 dims): log1p(hueco), usuario nuevo, es root, es cuenta de
sistema, trae puerto, agente nuevo, ventana nueva; contexto de subred
concatenado al estado final; GRU de 48 unidades; mismas condiciones que el HGB
v2.

| K | AUC HGB | AUC GRU | AUC ensamblado por rangos | Recall p99 HGB | Recall p99 GRU | Recall p99 ens. |
|---|---|---|---|---|---|---|
| 2 | 0,9277 | 0,9331 | 0,9334 | 0,402 | 0,370 | 0,023 |
| 3 | 0,9602 | 0,9613 | 0,9639 | 0,448 | 0,456 | 0,252 |
| 5 | 0,9949 | 0,9891 | 0,9924 | 0,846 | 0,849 | 0,444 |
| 10 | 0,9986 | 0,9973 | 0,9982 | 0,962 | 0,970 | 0,692 |
| **Media** | **0,9703** | **0,9702** | | | | |

Empate exacto. El ensamblado por rangos mantiene el AUC pero **rompe el traslado
del umbral p99** (los rangos no son comparables entre validación y test): no
usar.

### 13.6 Transformer de atención (R13) — empate; entra en el paquete como segunda opinión **[medido]**

`experiment_early_blocking_transformer.py`
(`artifacts/exp_early_blocking_transformer/date/ARGOS-LAB__{base,rich}/`, 2026-09-07).
Encoder de 2 bloques pre-LN, 4 cabezas, d = 32, FFN 64, ~18.400 parámetros,
sobre las mismas fichas del GRU (variante `rich` con +3 dims acumuladas,
equivalente) y el contexto de subred como ficha inicial (CLS). **Tres semillas**
(42, 43, 44) para distinguir mejora de ruido. Dos formas: un modelo por K y un
modelo compartido para todas las longitudes.

**ROC-AUC en test por K, media ± desviación sobre 3 semillas** (fichas `base`):

| K | HGB v2 | Transformer por K | Transformer compartido | GRU |
|---|---|---|---|---|
| 1 | 0,8268 ± 0,012 | **0,8573 ± 0,014** | 0,8423 ± 0,005 | 0,8359 ± 0,011 |
| 2 | 0,9326 ± 0,004 | 0,9380 ± 0,008 | 0,8877 ± 0,004 | 0,9333 ± 0,001 |
| 3 | 0,9609 ± 0,001 | 0,9588 ± 0,002 | 0,9070 ± 0,009 | 0,9620 ± 0,001 |
| 5 | 0,9943 ± 0,000 | 0,9908 ± 0,000 | 0,9602 ± 0,005 | 0,9910 ± 0,002 |
| 10 | 0,9985 ± 0,000 | 0,9973 ± 0,000 | 0,9808 ± 0,004 | 0,9971 ± 0,000 |
| 20 | 0,9999 ± 0,000 | 0,9993 ± 0,000 | 0,9855 ± 0,002 | 0,9991 ± 0,000 |
| **Media por K** | **0,9522** | **0,9569** | 0,9289 | 0,9531 |

Con fichas `rich`: Transformer por K 0,9565, compartido 0,9289 — equivalente.
Veredicto por la regla ±0,005: **sin ventaja clara**.

**Política secuencial (media sobre 3 semillas):**

| Modelo / política | Presupuestos | Recall | Precisión | Legítimas cortadas | Mediana K | Ataque evitado |
|---|---|---|---|---|---|---|
| HGB v2 | 1–20 | 0,990 | 0,993 | 4,3 | 4 | 89,6 % |
| Transformer por K | 1–20 | 0,990 | **0,982** | **11,3** | 2 | 90,5 % |
| Transformer por K | **2–20** | **0,991** | **0,991** | 5,7 | 4 | 90,3 % |
| Transformer compartido | 1–20 | 0,951 | 0,997 | 2,0 | 5 | 71,2 % |
| GRU | 1–20 | 0,984 | 0,988 | 7,0 | 4,3 | 88,6 % |
| Media de probabilidades HGB + TR | 2–20 | 0,988 | 0,994 | 3,7 | 4,3 | 87,9 % |
| HGB **AND** TR | 2–20 | 0,954 | **0,997** | **2,0** | 5 | 69,9 % |
| HGB **OR** TR | 2–20 | 0,990 | 0,990 | 6,0 | 4 | 89,8 % |

**Lectura.** El Transformer ordena mejor en K = 1 con consistencia (0,857–0,864
frente a 0,827 en tres semillas), pero ahí su umbral p99 **no traslada** de
validación a test: con K = 1 la política cae a precisión 0,976–0,982 (11–15
falsos), por debajo del 0,99 exigido. Sin K = 1 empata exactamente con el HGB.
El modelo compartido es peor. El motivo es estructural: **la etiqueta cuenta
hechos (cuentas, máquinas, avisos) y no depende del orden**, así que la atención
no tiene nada que explotar que los agregados no capten. Desglose por agente del
primer aviso (Transformer por K, K ≥ 2, semilla 42): agente 000 recall 0,993 /
FP 2; agente 011 recall 0,991 / FP 3 (HGB: 0,986 / 1 y 0,994 / 2). Sin paradoja
de agregación.

**Lo que aporta y por qué se empaqueta igualmente:** (a) una segunda opinión con
otro sesgo inductivo, que da dos mandos nuevos al operador — consenso AND
(política más estricta medida, 2 falsos al mes) y OR (más recall al límite del
objetivo de precisión); (b) **explicabilidad**: la atención de la ficha de
contexto sobre los avisos dice qué avisos pesaron (en la práctica, los que
introducen un usuario nuevo y los últimos de la rampa). Modelos empaquetados
(semilla 42, K ∈ {2, 3, 5, 10, 20}) sobre el test interno: recall 0,992 /
precisión 0,992 / 5 FP; consenso OR 0,995 / 0,990; AND 0,985 / 0,997 / 2 FP.
Inferencia en **numpy puro**, verificada contra torch (diferencia máxima
3,5·10⁻⁷ en 3.595 evaluaciones). **Sin validación externa**: el presupuesto de
LAB-ALERTS está gastado.

**Veredicto DL del corpus, cerrado con cuatro arquitecturas:** MLP tabular
(pierde), autoencoder (retirado), GRU (empate), Transformer (empate). El avance
vino de cambiar la pregunta, no el modelo.

---

## 14. Validación externa de un solo disparo (R6, R8) **[externo]**

Canalización congelada, una única ejecución contra LAB-ALERTS (otro servidor,
10,8 h, 9 hosts de los que tres son genuinamente nuevos; el único Windows no
tiene direcciones de origen y no es evaluable), misma política de etiquetado a
ambos lados. Detalle del conjunto y de ambos experimentos en la Parte III.

| Experimento | Resultado externo | Referencia interna |
|---|---|---|
| Puntuador de ventanas (R6), régimen `shape` sin geo | **MCC medio 0,3426** en los tres hosts nuevos: server1-principal 0,4613 · romero-AWS 0,3764 · biblioteca 0,1902. En server1-principal supera al modelo entrenado con el historial local (0,251) | Etiqueta débil transferida: 0,000 |
| Bloqueo secuencial por IP (R8), umbrales congelados de ARGOS sobre 561 IPs | **Recall 0,994** (325/327), precisión medida **0,898** (325/362): **37** IPs no bloqueables cortadas, suelo por censura de 10,8 h; mediana al 5º aviso, **91,4 %** de avisos evitados. El registro cita 38 y un análisis de 29 censuradas que no está persistido | Interno 0,990 / 0,995 / 89 % |

Ambos presupuestos de disparo único quedan **gastados** a 2026-09-02. Cualquier
afirmación externa nueva exige una captura nueva (idealmente > 24 h y con los
hosts Windows activos).

---

## 15. El paquete de despliegue (`deploy/argos_scorer/`)

Autocontenido, sin dependencia del repositorio de investigación, generado con
`build_deploy_bundle.py` (2026-09-02) y ampliado con `build_deploy_attention.py`
(2026-09-07). Requisitos: joblib, numpy, pandas, scikit-learn. **Sin torch.**

| Fichero | Servicio | Entrenamiento | Tamaño |
|---|---|---|---|
| `early_block_K{1,2,3,5,10,20}.joblib` | `EarlyBlockScorer` (principal) | HGB v2 sobre 3.354 IPs de train, umbral p99 sobre 719 IPs de val | 95–201 KB cada uno |
| `window_block.joblib` | `WindowBlockScorer` | HGB `behavioral`, 56.883 ventanas, calibrado isotónico | 0,95 MB |
| `activity_scorer.joblib` | `ActivityScorer` | Un modelo por host (000/011/030) + reserva global, calibrado, con rechazo | 4,6 MB |
| `attention_block.npz` | `AttentionBlockScorer` / `ConsensusBlockScorer` | 5 transformers (K = 2, 3, 5, 10, 20), mismas 3.354 IPs, pesos en numpy | 414 KB |
| `config.json` | Todos | Listas de variables (el orden manda), umbrales, normalización, métricas del test interno | 12 KB |
| `state/live_state.json` | `LiveState` compartido | Reputación de subred (4.123 /24, 2.597 /16), frecuencias de 4.792 IPs y 12.990 usuarios: **arranque en caliente** | 416 KB |

Total de modelos: **7,0 MB**. Sin el estado caliente todo parece «nuevo» y el
puntuador de ventanas trabaja fuera de su distribución (medido en la demo:
P(BLOCK) 0,05 en frío frente a 0,99 en caliente sobre la misma ventana).
Semilla 42 en todo; reproducible de extremo a extremo.

Umbrales entregados (precisión ≥ 0,99 en validación): HGB K1 0,928 · K2 0,908 ·
K3 0,933 · K5 0,969 · K10 0,800 · K20 0,640; atención K2 0,920 · K3 0,923 ·
K5 0,920 · K10 0,689 · K20 0,441.

---

## 16. Inventario del módulo y reproducción

### 16.1 Ficheros (`src/models/ARGOS_LAB/`)

| Fichero | Función |
|---|---|
| `feature_spec.py` | Fuente única de verdad: grupos, regímenes, taxonomía de actividad, familias hostiles, cuentas de sistema |
| `prepare_dataset.py` | JSONL → ventanas → Parquet, un solo recorrido en streaming |
| `prepare_sequence_dataset.py` | Ventanas → secuencias por agente (L = 12) |
| `data_loader.py` | Carga con filtrado por régimen |
| `leakage_audit.py` | Sondas de una variable, por grupo y por régimen (R1) |
| `train_ml_binary_hgb.py`, `train_ml_multiclass_hgb.py` | Gradient boosting binario y multiclase (X2, R3) |
| `train_ml_binary_mlp.py` | MLP denso (PyTorch) |
| `train_anomaly_isoforest.py`, `train_anomaly_autoencoder.py` | No supervisados (X1) |
| `train_seq_gru.py`, `models_torch.py` | GRU sobre secuencias de ventanas; arquitecturas MLP/AE/GRU |
| `train_activity_scorer.py` | Puntuador por host calibrado con rechazo |
| `build_block_labels.py` | Etiqueta de bloqueo por conducta (R4) |
| `train_block_scorer.py` | Puntuador de bloqueo por ventana, con auditoría previa (R5) |
| `experiment_block_transfer.py` | Transferencia 000 ↔ 011 (R5) |
| `experiment_domain_adaptation.py` | z-score y rango por host (X3) |
| `prepare_lab_alerts_crosstest.py`, `experiment_external_validation.py` | Validación externa del puntuador de ventanas (R6) |
| `experiment_early_blocking.py`, `experiment_early_blocking_v2.py` | Bloqueo temprano v1 y v2 secuencial (R7) |
| `experiment_early_blocking_external.py` | Bloqueo secuencial sobre LAB-ALERTS (R8) |
| `experiment_adaptive_threshold.py` | Umbral adaptativo por prior shift (R9) |
| `experiment_early_blocking_gru.py` | GRU secuencial (R10) |
| `experiment_early_blocking_transformer.py` | Transformer por K y compartido, 3 semillas (R13) |
| `build_deploy_bundle.py`, `build_deploy_attention.py` | Generación y verificación del paquete de despliegue |
| `compare_models.py`, `metrics.py`, `reporting.py`, `train_utils.py` | Infraestructura compartida |
| `run_all_experiments.sh` | Canalización completa: 20 experimentos, 118 Parquet, 164 gráficas |
| `README.md`, `RESULTADOS.md` | Documentación y registro canónico R1–R13 / X1–X3 |

Artefactos por familia (nº de runs con métricas): `ml_binary_hgb` 18 ·
`dl_binary_mlp` 14 · `activity_scorer` 7 · `ml_multiclass_hgb` 4 · `dl_seq_gru` 4 ·
`exp_early_blocking_transformer` 4 · `anomaly_isoforest` 3 · `dl_anomaly_autoencoder` 3 ·
`block_scorer` 3 · `leakage_audit` 2 · un run cada uno de los experimentos R5–R10.

### 16.2 Qué comando produce qué cifra

```bash
cd src/models/ARGOS_LAB
python prepare_dataset.py --split_mode date,random,groupkfold --all_folds        # §5
python prepare_dataset.py --exclude_posture --dataset ARGOS-LAB-NOPOSTURE --split_mode date,random
python leakage_audit.py --split_mode date                                        # §6 (R1)
python train_ml_binary_hgb.py --split_mode date --feature_set behavioral         # §7.1
python train_ml_multiclass_hgb.py --split_mode date --feature_set behavioral     # §7.2 (R3)
python train_ml_binary_hgb.py --split_mode groupkfold --all_folds --feature_set behavioral   # §8.1
python train_anomaly_autoencoder.py --split_mode date --train_policy all         # §9 (X1)
python train_activity_scorer.py --split_mode date --holdout_family PortChange --reject_quantile 0.50   # §10
python build_block_labels.py                                                     # §11 (R4)
python train_block_scorer.py --feature_set shape                                 # §11 auditoría, §12
python experiment_block_transfer.py                                              # §12.1 (R5)
python experiment_domain_adaptation.py                                           # §12.2 (X3)
python experiment_early_blocking.py                                              # §13.2
python experiment_early_blocking_v2.py                                           # §13.3 (R7)
python experiment_adaptive_threshold.py                                          # §13.4 (R9)
python experiment_early_blocking_gru.py                                          # §13.5 (R10)
python experiment_early_blocking_transformer.py --token_set base                 # §13.6 (R13)
python experiment_external_validation.py                                         # §14 (R6) — presupuesto gastado
python experiment_early_blocking_external.py                                     # §14 (R8) — presupuesto gastado
python build_deploy_bundle.py && python build_deploy_attention.py                # §15
python compare_models.py --metric macro_f1                                       # artifacts/comparison.csv
```

---

# PARTE III · LAB-ALERTS, EL SEGUNDO ENTORNO

## 17. LAB-ALERTS

Módulo `src/models/LAB-ALERTS/` (9 scripts), estrategia
`STRATEGY_LAB-ALERTS.md`, checklist `TODO_LAB-ALERTS.md`, export
`out/LAB-ALERTS/alerts.json`. Su función efectiva en la tesis es **conjunto de
validación externa** de los modelos de ARGOS-LAB (R6 y R8); su pipeline propio
está implementado pero sin artefactos conservados.

### 17.1 Dataset **[medido]**

| Magnitud | Valor | Fuente |
|---|---|---|
| Alertas | **59.855** (0 líneas inválidas, 0 sin timestamp) | `datasets/crosstest/date/LAB-ALERTS-X/prepare_dataset_summary.json` |
| Fichero | `out/LAB-ALERTS/alerts.json`, 48,1 MB NDJSON | mtime 2026-03-10 |
| Cobertura | 2026-03-09 23:00 → 2026-03-10 09:50 UTC: **10,8 h**, un solo día | recalculado sobre el fichero |
| Ventanas (1 min × agente) | 3.446 | idem |
| Agentes | 9 | idem |
| IPs de origen únicas | **561** (59 también vistas en ARGOS) | `exp_early_blocking_external/.../results.json` |
| Alertas con `srcip` | 26.539 (44,3 %) | recalculado |

| Agente | Nombre | Alertas | Actividad | Telemetría dominante |
|---|---|---|---|---|
| 025 | Server-Web-Top-Secret | 24.073 | toda la captura | systemd 24.023 (servicio en bucle de fallo) |
| 022 | biblioteca | 12.819 | toda | sshd 8.107 · pam 4.144 · web 527 |
| 018 | server1-principal | 9.760 | toda | systemd 7.854 · sshd 1.542 |
| 000 | wazuh (manager) | 8.494 | toda | sshd 5.939 · pam 2.554 |
| 011 | clockworksolutions.es | 3.058 | toda | sshd 3.053 |
| 023 | MARCOSPC (**Windows**) | 718 | **86 min** (08:22–09:48) | syscheck de registro, eventchannel; **sin IP de origen** |
| 017 | romero-AWS-WebBus | 654 | 23:01–08:11 | sshd 654 |
| 026 | Server-Correo-Top-Secret | 252 | casi toda | docker, json, sshd |
| 003 | clockworksolutions | 27 | 02:14–06:38 | dpkg, pam |

Tres agentes (000, 003, 011) comparten identificador y nombre con ARGOS-LAB,
capturado cinco meses después; por eso la validación externa solo cuenta como
«hosts nuevos» a 017, 018 y 022. **Hay un único host Windows**, activo 86
minutos y sin direcciones de origen: no interviene en ninguna métrica externa
(las descripciones que hablan de «hosts Windows» en plural deben corregirse).

Composición: el 98,0 % de las alertas son nivel 5; la regla dominante es
40704 «Systemd: Service exited due to a failure» (31.879, 53,3 %), seguida de
la fuerza bruta SSH (5710: 14.961; 5503: 6.940). Tácticas MITRE: Credential
Access 26.031, Lateral Movement 17.721. **Cobertura geográfica 0 %** (frente al
67,6 % de ARGOS): las alertas no traen `GeoLocation`.

**Coexisten tres políticas de etiqueta**, y conviene saber cuál sostiene cada
número:

| Política | Dónde | Resultado a nivel ventana |
|---|---|---|
| Propia del módulo (`sshd`/`pam` cuentan como ataque) | `src/models/LAB-ALERTS/prepare_dataset.py` | ATTACK 2.203 / BENIGN 1.243; multiclase CredentialAccess 2.072 · ServiceFailure 1.301 · OtherAlert 73 |
| Débil de ARGOS reaplicada (`lab_alerts_weak_label_v1`) | `prepare_lab_alerts_crosstest.py` | ATTACK 2.104 / BENIGN 1.323 / UNKNOWN 19 |
| **Bloqueo por conducta** (la que se valida) | `build_block_labels.py` sobre el crosstest | 2.323 ventanas con origen: **BLOCK 1.870 / ALLOW 453**; por agente 000: 532/97 · 011: 505/120 · 017: 56/58 · 018: 155/98 · 022: 621/30 · 025: 0/18 · 026: 1/32; motivos: enumeración 1.776 · amplitud 68 · persistencia 26 |

### 17.2 Preprocesado propio y «crosstest» desde ARGOS **[documentado]**

**Pipeline propio** (`prepare_dataset.py`, 713 líneas): ventana de 1 min ×
agente, **43 features** (recuentos, estadísticos de nivel y `firedtimes`,
MITRE, recuentos por grupo de regla, presencia de IP/puerto, novedad de IP y
regla, hora/minuto/día, códigos categóricos de agente/decoder/programa/
localización). Nótese que, a diferencia de ARGOS, **mezcla en un solo conjunto
variables de firma y de conducta**: no aplica el aislamiento por regímenes.
Particiones `random` 70/15/15 estratificada, `date` 70/15/15 por ventanas
ordenadas (train 2.399 ventanas 23:00–06:35; val 530; test 517, donde el agente
Windows aparece solo en test), `groupkfold` por `agent_id` (5 folds; la
estrategia pedía `(src_ip, agent_id)`). Anomalía: train solo BENIGN (846
ventanas).

**Crosstest** (`src/models/ARGOS_LAB/prepare_lab_alerts_crosstest.py`,
2026-09-02): convierte el export anidado al esquema plano de ARGOS
(`lab-alerts_flat.jsonl`, 51 MB), deriva `window_start`, deja los campos geo
vacíos, aplica la política débil de ARGOS y ejecuta el `prepare_dataset.py` de
ARGOS con sus **98 features** y `build_block_labels.py` con los mismos criterios.
Lo que se **congela** antes de tocar LAB-ALERTS: variables, criterios de
bloqueo, hiperparámetros, semilla y umbral 0,5. **Régimen `shape` sin geo**: de
las 29 variables adimensionales se retiran las 6 geográficas (23 restantes),
porque en LAB-ALERTS serían una constante distinta a la de ARGOS: un
desplazamiento de distribución que no procede de la conducta.

### 17.3 Modelos propios: código sin artefactos **[documentado]**

`train_ml_binary_hgb.py` (HGB 200 iteraciones, lr 0,08, profundidad 3),
`train_ml_multiclass_hgb.py` (profundidad 4), `train_anomaly_isoforest.py` (300
árboles), `compare_models.py` y el orquestador `lab_alerts_run_all_models.ps1`
están completos y versionados (commit `cc9f15f`, 2026-05-03). El `TODO` marca
como hechas las ejecuciones `date` y la primera comparativa, pero
`src/models/LAB-ALERTS/{datasets,artifacts}/` están **vacíos** en esta máquina y
nunca se versionaron. **Métricas de los modelos propios: no constan.** El
«modelo LAB-ALERTS» que puntúa ventanas en la web (`models_examples/`, 16
agregados, 3 de ellos del motor de reglas, saturado en `attack`) vive en el
repositorio de la web, no en este.

### 17.4 Validación externa: los dos disparos **[externo]**

**R6 — puntuador de bloqueo por ventana**
(`artifacts/exp_external_validation/date/ARGOS_a_LAB-ALERTS/20260902_120613/results.json`).
Modelo: HGB (250 iteraciones, lr 0,08, profundidad 6, L2 1,0, ponderación de
clases) con calibración isotónica, entrenado en el `train` de ARGOS (hosts 000
y 011) sobre las 23 variables `shape` sin geo; umbral 0,5. Se evalúan los hosts
con ≥ 60 ventanas y ≥ 10 de la clase minoritaria.

| Host | n | ROC-AUC | **MCC** | Clase rara | PR-AUC rara | Base | Lift | Nativo local (70 % del host) |
|---|---|---|---|---|---|---|---|---|
| Referencia ARGOS 000 | — | 0,8203 | 0,4572 | ALLOW | 0,3928 | 0,0114 | 34,6× | — |
| Referencia ARGOS 011 | — | 0,8131 | 0,4109 | ALLOW | 0,3597 | 0,0276 | 13,0× | — |
| **018 server1-principal** (nuevo) | 253 | 0,7458 | **0,4613** | ALLOW | 0,7495 | 0,3874 | 1,93× | MCC 0,2510 → el transferido lo supera (184 %) |
| **017 romero-AWS-WebBus** (nuevo) | 114 | 0,7714 | **0,3764** | BLOCK | 0,7414 | 0,4912 | 1,51× | — |
| **022 biblioteca** (nuevo) | 651 | 0,6826 | **0,1902** | ALLOW | 0,2281 | 0,0461 | 4,95× | MCC 0,0000 |
| 000 wazuh (también en ARGOS) | 629 | 0,6869 | 0,3993 | ALLOW | 0,4745 | 0,1542 | 3,08× | 0,4880 |
| 011 clockworksolutions.es (también en ARGOS) | 625 | 0,7920 | 0,3068 | ALLOW | 0,5738 | 0,1920 | 2,99× | 0,4617 |
| 026, 025 | 33, 18 | omitidos: muestras insuficientes | | | | | | |

**MCC medio sobre los tres hosts nuevos: 0,3426**, frente a 0,000 de la
etiqueta débil transferida. En server1-principal los 31 días de patrones de
ARGOS valen más que las 11 horas de historial propio.

**R8 — bloqueo secuencial por IP**
(`artifacts/exp_early_blocking_external/date/ARGOS_a_LAB-ALERTS/20260902_134936/results.json`).
Los seis HGB v2 de ARGOS (22 variables) con sus umbrales p99 congelados,
política «bloquear al primer cruce», contexto de subred computado causalmente
sobre el propio LAB-ALERTS.

| Magnitud | Valor |
|---|---|
| IPs evaluadas | **561** (59 compartidas con ARGOS) |
| Bloqueables al final de la captura (prevalencia censurada) | 327 (58,3 %) |
| **Recall** | **0,9939** (325 / 327) |
| **Precisión medida** | **0,8978** (325 / 362) → **37** IPs no bloqueables cortadas |
| Aviso mediano de corte | **5º** |
| Avisos evitados | **22.429 / 24.553 = 91,4 %** |
| Reparto de bloqueos por K | 1: 7 · 2: 9 · 3: 37 · 5: 135 · 10: 131 · 20: 6 |
| Umbrales aplicados (de ARGOS) | K1 0,928 · K2 0,908 · K3 0,933 · K5 0,969 · K10 0,800 · K20 0,640 |

La precisión es un **suelo por censura**: la captura dura 10,8 h y muchas IPs
no tuvieron tiempo de completar su conducta. `RESULTADOS.md` cita 38 cortes
erróneos de los que 29 estaban a 1–2 usuarios de cumplir criterios o superaban
25 avisos; el artefacto registra **37**, y el análisis de esos 29 no está
persistido en ningún fichero. Debe corregirse la cifra en el registro y, si se
quiere citar el 29, reconstruirlo desde `results.json` y el crosstest.

### 17.5 Hallazgos

1. **Ambos presupuestos de un disparo están gastados** (2026-09-02). Por eso el
   Transformer (R13) se despliega sin validación externa y cualquier
   afirmación externa nueva exige captura nueva (> 24 h, con el host Windows
   activo y, si es posible, con la geolocalización habilitada).
2. **Externalidad parcial**: tres agentes y 59 IPs son comunes con ARGOS; el
   código lo trata correctamente excluyéndolos del MCC medio, y la memoria debe
   decirlo.
3. **La composición difiere de ARGOS en todo**: un día frente a 31, 9 hosts
   frente a 4, BENIGN dominado por fallos de systemd en vez de por Trivy, sin
   geo. Que el puntuador de bloqueo retenga MCC 0,19–0,46 en ese entorno es la
   evidencia más fuerte de que la etiqueta de conducta transfiere.
4. **Desvíos código-estrategia** en el pipeline propio: `groupkfold` por agente
   en vez de por (IP, agente); novedad `has_new_*` acumulada antes de partir
   (fuga leve en `random`); política de etiqueta más agresiva que la de ARGOS
   (`sshd`/`pam` = ataque).

### 17.6 Estado e inventario

Pendiente (`TODO_LAB-ALERTS.md`): ejecuciones `random` y `groupkfold` de los
tres modelos propios, toda la fase de validación (fuga en el split por grupo,
orden temporal, estabilidad de `label_map`), README, extensiones opcionales
(MLP, FT-Transformer, ventanas de 5 min).

| Fichero | Función |
|---|---|
| `STRATEGY_LAB-ALERTS.md`, `TODO_LAB-ALERTS.md` | Estrategia v1 y checklist |
| `lab_alerts_run_all_models.ps1` | Orquestación preprocesado → 3 modelos → comparativa |
| `src/models/LAB-ALERTS/prepare_dataset.py` | Parseo, ventanas, tres políticas de split, Parquet |
| `data_loader.py`, `train_utils.py`, `metrics.py`, `reporting.py`, `compare_models.py` | Infraestructura |
| `train_ml_binary_hgb.py`, `train_ml_multiclass_hgb.py`, `train_anomaly_isoforest.py` | Entrenadores (sin artefactos) |
| `out/LAB-ALERTS/alerts.json` | Export crudo (48 MB) |
| En ARGOS_LAB: `prepare_lab_alerts_crosstest.py`, `experiment_external_validation.py`, `experiment_early_blocking_external.py`; `datasets/crosstest/**` (JSONL plano, 16 Parquet, etiquetas de bloqueo); los dos `results.json` de R6 y R8 | Validación externa |

---

# PARTE IV · DATASETS PÚBLICOS

## 18. CIC-IDS2017 — el colapso reproducido en una referencia académica

Módulo `src/models/CIC-IDS2017/` (17 scripts), estrategia
`STRATEGY_CIC-IDS2017.md`, orquestación `cic_run_all_models.ps1`, inspección
`out/CIC-IDS2017/`. Todos los entrenamientos son de un único lote (2026-03-05 y
2026-03-06) consolidado en
`src/models/CIC-IDS2017/artifacts/compare_models/20260306_205242/comparison.csv`.

> **Aviso que gobierna toda la sección.** El orquestador fija `epochs = 5` para
> **todos** los scripts, y los modelos de scikit-learn reutilizan ese valor:
> el HistGradientBoosting se entrenó con **5 iteraciones** (por defecto 200/250)
> y el Isolation Forest con **5 árboles** (por defecto 300). Ningún modelo de
> este módulo se ejecutó con sus hiperparámetros por defecto. Las cifras son
> válidas como comparación **entre protocolos de partición** bajo el mismo
> régimen de desarrollo, no como rendimiento alcanzable del modelo.

### 18.1 Dataset **[medido]** (`out/CIC-IDS2017/deep_summary.json`, 2026-03-04)

Flujos de red bidireccionales con estadísticas CICFlowMeter (Canadian
Institute for Cybersecurity, 2017): cinco días laborables, un ataque por
bloque horario. Dos vistas oficiales en `src/datasets/CIC-IDS2017/`:

| Vista | CSV | Tamaño | Columnas | Filas brutas | Uso |
|---|---|---|---|---|---|
| `MachineLearningCVE` (ML) | 8 | 844 MB | 79 (78 features + `Label`) | 2.830.743 | Modelos `offline_ML_*` |
| `TrafficLabelling` (TL) | 8 | 1.147 MB | 85 (+ `Flow ID`, IPs, puertos, protocolo, `Timestamp`) | 3.119.345 (288.602 filas vacías) | Modelos `online_TL_*`, secuencias, Isolation Forest |

Las 79 columnas comunes coinciden exactamente entre vistas. **En este módulo
«TL» significa TrafficLabelling, no *transfer learning***: ningún script carga
pesos preentrenados ni transfiere entre datasets.

| Día / fichero | Filas | Etiquetas |
|---|---|---|
| Monday | 529.918 | BENIGN 529.918 |
| Tuesday | 445.909 | BENIGN 432.074 · FTP-Patator 7.938 · SSH-Patator 5.897 |
| Wednesday | 692.703 | BENIGN 440.031 · DoS Hulk 231.073 · DoS GoldenEye 10.293 · DoS slowloris 5.796 · DoS Slowhttptest 5.499 · Heartbleed 11 |
| Thursday morning (WebAttacks) | 170.366 | BENIGN 168.186 · Web Brute Force 1.507 · XSS 652 · SQL Injection 21 |
| Thursday afternoon (Infiltration) | 288.602 | BENIGN 288.566 · **Infiltration 36** |
| Friday morning | 191.033 | BENIGN 189.067 · Bot 1.966 |
| Friday afternoon (PortScan) | 286.467 | PortScan 158.930 · BENIGN 127.537 |
| Friday afternoon (DDoS) | 225.745 | DDoS 128.027 · BENIGN 97.718 |

Binario: **BENIGN 2.273.097 (80,3 %) · ATTACK 557.646 (19,7 %)**. Quince clases
con desbalance extremo: DoS Hulk 8,16 %, PortScan 5,61 %, DDoS 4,52 %, DoS
GoldenEye 0,36 %, FTP-Patator 0,28 %, SSH-Patator 0,21 %, DoS slowloris 0,20 %,
DoS Slowhttptest 0,19 %, Bot 0,069 %, Web Brute Force 0,053 %, XSS 0,023 %,
Infiltration 0,0013 %, SQL Injection 0,0007 %, Heartbleed 0,0004 %
(BENIGN:Heartbleed = 206.645:1). Calidad: 1.358 NaN y 1.509 infinitos en
`Flow Bytes/s`, 2.867 infinitos en `Flow Packets/s`, ~8.758 duplicados
estimados, **10 columnas constantes** y una duplicada (`Fwd Header Length.1`);
ninguna se elimina en el pipeline. El `SUMMARY.txt` suma ambas vistas (BENIGN
4.546.194) y no debe citarse como recuento del dataset.

### 18.2 Preprocesado **[documentado]**

`prepare_dataset.py` (unidad = flujo): lectura por chunks de 250.000 filas;
normalización de nombres (los CSV traen espacios iniciales) y de etiquetas
(el carácter U+FFFD de `Web Attack � XSS` pasa a `-`); eliminación de las
288.602 filas con etiqueta vacía de TL; ±inf → NaN; todo a `float64` con
metadatos de esquema borrados (corrección documentada de un fallo de pyarrow
entre chunks). **No se crea ni elimina ninguna feature**: 78 numéricas en ML y
80 en TL (TL añade `Source Port`, `Destination Port`, `Protocol`). Los NaN se
conservan en Parquet y pasan a 0 en carga. Cuatro pipelines: `binary`,
`multiclass` (15), `multiclass_grouped` (WebAttack, DoS, BruteForce, DDoS,
PortScan, Bot, Infiltration, Heartbleed, OtherAttack) y `anomaly` (train solo
BENIGN).

| Partición | Regla | Train / val / test (binario) |
|---|---|---|
| `day` | Lunes + martes + miércoles → train; jueves → val; viernes → test | 1.668.530 (ATTACK 266.507) / 458.968 (ATTACK **2.216**) / 703.245 (ATTACK 288.923) |
| `groupkfold` (8 folds por fichero) | test = fichero k, val = fichero k+1, train = los 6 restantes; solo se ejecutó **fold 4** (test = Infiltration, val = WebAttacks) | 2.371.775 / 170.366 / 288.602 (ATTACK **36**) |
| `random` | Máscara por fila 70/15/15, semilla 42 | 1.981.835 / 424.601 / 424.307 |

**La partición `day` es también una partición por familia de ataque**: train
solo contiene DoS, Patator y Heartbleed; test contiene PortScan, DDoS y Bot,
**nunca vistos**. Es la lectura estructural del colapso (§18.5).

`prepare_sequence_dataset.py` (solo TL): ventanas de 20 flujos por `Source IP`
con paso 1, etiqueta del último flujo, aplanadas a 1.600 columnas; 60 GB en
disco. Recuentos: `day` train 1.272.276 / 266.469 (BENIGN/ATTACK), val
414.890 / 2.197, test 371.134 / 288.866; `groupkfold/fold_4` test 264.969 / 36.

### 18.3 Modelos entrenados **[documentado]**

| Modelo | Vista · partición | Hiperparámetros efectivos | Features |
|---|---|---|---|
| `offline_ML_binary_hgb` | ML · day, fold 4 | HGB **5 iteraciones** (def. 200), lr 0,1, profundidad 3 | 78 |
| `online_TL_binary_hgb` | TL · day, fold 4 | Idéntico | 80 |
| `online_TL_binary_logreg_torch` | TL · day, fold 4 | Regresión logística (Linear 80→2), AdamW 1e-3, batch 8.192, 5 épocas | 80, z-score |
| `offline_ML_binary_mlp` | ML · random (+ reevaluación en day y fold 4) | MLP 512 × 3, dropout 0,2, AdamW 1e-3, 5 épocas | 78, z-score |
| `offline_ML_binary_fttransformer` | ML · random (+ reevaluación) | FT-Transformer d = 128, 8 cabezas, 4 capas, un token por feature, AdamW 2e-4, batch 4.096, 5 épocas | 78, z-score |
| `offline_ML_multiclass_hgb` | ML · random, 15 clases | HGB 5 iteraciones, profundidad 4 | 78 |
| `anomaly_isoforest_TrafficLabelling` | TL · day, fold 4 | Isolation Forest **5 árboles** (def. 300), solo BENIGN | 80 |
| `seq_TL_binary_gru` | TL secuencias · day, fold 4 | GRU 128 × 2 capas, dropout 0,1, AdamW 1e-3, batch 2.048, 5 épocas | 80 × 20 |

Definidos sin ejecutar: LSTM, autoencoder, `multiclass_grouped`, GRU
multiclase, folds 0–3 y 5–7, secuencias `random`.

### 18.4 Métricas **[medido]** (test; umbral 0,5 implícito; `comparison.csv` y `metrics_test.json` de cada run)

| Modelo | Partición | Exactitud | Bal. acc. | Macro-F1 | Recall ATTACK | ROC-AUC | Confusión [[TN, FP], [FN, TP]] |
|---|---|---|---|---|---|---|---|
| MLP | random | 0,9835 | 0,9771 | 0,9740 | 0,9666 | **0,9987** | [[336.811, 4.216], [2.783, 80.497]] |
| FT-Transformer | random | 0,9837 | 0,9803 | 0,9745 | 0,9748 | **0,9986** | [[336.222, 4.805], [2.103, 81.177]] |
| HGB multiclase (15) | random | 0,9843 | 0,6383 | 0,6422 | — | — | ver abajo |
| GRU secuencial | day | 0,8013 | 0,7740 | 0,7793 | 0,5551 | 0,9908 | [[368.492, 2.642], [128.528, 160.338]] |
| Reg. logística | day | 0,7428 | 0,6904 | 0,6887 | 0,3966 | 0,5435 | [[407.762, 6.560], [174.342, 114.581]] |
| HGB (ML y TL, idénticos) | day | 0,7040 | 0,6398 | **0,6181** | 0,2796 | **0,5350** | [[414.321, 1], [208.140, 80.783]] |
| Isolation Forest | day | — | — | — | — | 0,6426 | PR-AUC 0,529 con prevalencia 41 % |
| GRU secuencial | fold 4 | 0,7586 | 0,3793 | 0,4314 | **0,0000** | 0,4631 | [[201.029, 63.940], [36, 0]] |
| HGB (ML / TL) | fold 4 | 0,9999 | 0,5000 | **0,5000** | **0,0000** | **0,3441 / 0,3444** | [[288.566, 0], [36, 0]] |
| Reg. logística | fold 4 | 0,7451 | 0,4004 | 0,4270 | 0,0556 | 0,1407 | [[215.025, 73.541], [34, 2]] |
| Isolation Forest | fold 4 | — | — | — | — | 0,9117 | PR-AUC 0,0045 con prevalencia 0,0125 % |

Multiclase HGB `random`, recall por clase: BENIGN 0,997 · DDoS 0,988 · PortScan
0,991 · FTP-Patator 0,998 · SSH-Patator 0,999 · DoS GoldenEye 0,943 · DoS
slowloris 0,904 · DoS Hulk 0,873 · Web Brute Force 0,806 · DoS Slowhttptest
0,690 · Bot 0,320 · XSS 0,069 · **Heartbleed, Infiltration y SQL Injection: 0 de
5, 8 y 4**. Media 0,638 = balanced accuracy.

Reevaluación de MLP y FT-Transformer (entrenados en `random`) sobre los tests
`day` y fold 4: ROC-AUC 0,9993 / 0,9995 en el viernes, 0,862 / 0,753 en
Infiltration (7 y 1 de 36 detectados). **Advertencia**: el split `random`
contiene el 70 % de las filas de esos mismos ficheros, así que estas
reevaluaciones no son una prueba temporal limpia.

Los dos runs de regresión logística repetidos en días distintos son idénticos
hasta el último decimal (semilla 42): reproducibilidad verificada.

### 18.5 Hallazgos

1. **El colapso por partición, reproducido.** ROC-AUC 0,999 con partición
   aleatoria frente a 0,535 (día) y 0,344 (grupo, por debajo del azar) con el
   mismo tipo de modelo; en fold 4 el HGB emite siempre la clase mayoritaria
   (macro-F1 exactamente 0,500, recall de ataque 0). Es la fila de CIC-IDS2017
   en el patrón transversal (§23).
2. **La causa es estructural, no solo temporal**: `day` separa familias de
   ataque; `random` las mezcla. Un modelo que solo vio DoS y fuerza bruta no
   reconoce PortScan ni DDoS. Este matiz no está escrito en el módulo; se lee
   de los `stats.json`.
3. **Régimen de desarrollo.** Con 5 iteraciones el HGB de ML y el de TL
   producen la misma matriz de confusión: se apoyan en las mismas features
   compartidas. El Isolation Forest de 5 árboles no es un detector.
4. **Validación casi monoclase**: el jueves tiene 2.216 ataques (0,48 %); el
   *early stopping* se guía por ese split, y por eso la GRU queda en la época 1
   y HGB y regresión logística tienen recall de ataque < 0,01 en validación.
5. **ECE binario no interpretable**: la calibración usa P(ATTACK) como confianza
   para todas las filas, con lo que el ECE tiende a la fracción de benignos
   (≈ 0,79). El multiclase (0,121) sí es interpretable.
6. Fugas potenciales no analizadas: puertos y protocolo como features en TL,
   ventanas solapadas en las secuencias `random` (dataset generado, no usado).
7. Bugs corregidos (commit `6c19dcb`, 2026-03-20): codificador de etiquetas
   alfabético que ponía ATTACK = 0; llamada sin `epochs` en el bucle de folds;
   dependencia de `tabulate`; `log_loss` protegido; array de solo lectura en el
   cargador de secuencias.

### 18.6 Estado e inventario

Hecho: inspección, datasets en 3 particiones × 2 vistas × 4 pipelines (~25 GB)
y secuencias (60 GB), 13 runs, una comparativa, estrategia. No existe
`TODO_CIC-IDS2017.md`. Pendiente derivado del código: reentrenar con
hiperparámetros por defecto, los 8 folds, multiclase en `day`/`groupkfold`,
`multiclass_grouped`, evaluación temporal limpia de MLP y FT-Transformer,
análisis de atajos por puerto, limpieza de constantes y duplicados.

| Fichero | Función |
|---|---|
| `STRATEGY_CIC-IDS2017.md` | Pipeline de extremo a extremo (15 secciones); sin métricas |
| `cic_run_all_models.ps1`, `run_analysis_cic.ps1` | Orquestación (`epochs = 5`); inspección (rutas absolutas obsoletas) |
| `src/helpers/analyze_cic_folder.py` | Esquema, NaN, no finitos, etiquetas, comparación de columnas |
| `prepare_dataset.py`, `prepare_sequence_dataset.py` | Tabular y secuencial |
| `data_loader.py`, `sequence_loader.py`, `train_utils.py`, `metrics.py`, `reporting.py`, `models_torch.py` | Infraestructura (`TorchLogReg`, `MLP`, `FTTransformer`, `GRUClassifier`, `LSTMClassifier`, `Autoencoder`) |
| `train_ml_binary_hgb.py`, `train_tl_binary_hgb.py`, `train_tl_binary_logreg_torch.py`, `train_ml_binary_mlp.py`, `train_ml_binary_fttransformer.py`, `train_ml_multiclass_hgb.py`, `train_anomaly_isoforest.py`, `train_seq_tl_gru.py` | Entrenadores |
| `compare_models.py` | `comparison.csv`/`.md` |
| `datasets/` (85 GB), `artifacts/` (13 MB), `out/CIC-IDS2017/` | Fuera del control de versiones |

---

## 19. UNSW-NB15 — el bug de cabecera, la corrección, y una fuga que quedaba

Código en `src/models/UNSW-NB15/` (13 scripts); datasets y artefactos
canónicos en `src/models/NUSW-NB15/` (ruta por defecto de los cargadores, con
un typo histórico); estrategia `STRATEGY_UNSW-NB15.md`; datos crudos en
`out/UNSW-NB15/`. Registro: R11 (2026-09-02) y la corrección de §19.5.

### 19.1 Dataset **[medido]**

Flujos de red del dataset público UNSW-NB15 (UNSW Canberra, tráfico generado
con IXIA PerfectStorm). Ficheros en `out/UNSW-NB15/` (634 MB):

| Fichero | Filas | Cabecera | Papel |
|---|---|---|---|
| `UNSW-NB15_{1,2,3,4}.csv` | 700.001 · 700.001 · 700.001 · 440.044 = **2.540.047** | **no** (los nombres están en `NUSW-NB15_features.csv`) | Crudos («raw4») |
| `UNSW_NB15_training-set.csv` | 82.332 | sí | Partición oficial, train |
| `UNSW_NB15_testing-set.csv` | 175.341 | sí | Partición oficial, val + test |
| `NUSW-NB15_features.csv` | 49 features | — | Diccionario |
| `UNSW-NB15_LIST_EVENTS.csv` | — | — | Recuento oficial por categoría |
| `train_test_network.csv` | 211.044 | sí | Esquema distinto (tipo Zeek); **diferido** (3 de 45 columnas coinciden) |

Los crudos tienen **47 features + `attack_cat` + `label`**; la partición
oficial usa **43 features** con otro esquema (renombra `sintpkt → sinpkt`,
`smeansz → smean`, añade `id` y `rate`, y omite IPs, puertos y tiempos). Los dos
espacios de features no son intercambiables.

**Distribución tras la corrección** (suma de `stats.json` de
`src/models/NUSW-NB15/datasets/random/NUSW-NB15/`, 2026-09-02; coincide con
`LIST_EVENTS` en las categorías comprobadas):

| Clase | Flujos | Clase | Flujos |
|---|---|---|---|
| **BENIGN** | **2.218.764** (87,35 %) | Reconnaissance | 13.987 |
| **ATTACK** | **321.283** (12,65 %) | Analysis | 2.677 |
| Generic | 215.481 | Backdoor + Backdoors | 1.795 + 534 (misma categoría partida) |
| Exploits | 44.525 | Shellcode | 1.511 |
| Fuzzers | 24.246 | Worms | 174 |
| DoS | 16.353 | | |

Partición oficial: train 82.332 (Normal 37.000 / ataque 45.332), test
175.341 partido 50/50 con semilla 42 en val 87.447 y test 87.894 (prevalencia
de ataque **0,680**). El repositorio entrena con el fichero pequeño y evalúa en
el grande, tal como publican los autores.

### 19.2 Preprocesado **[documentado]**

`prepare_dataset.py`: selección de fuente (`raw4`, `official_pair`, `all`),
vocabulario de categóricas (ajustado sobre todos los ficheros), unión de
columnas, `dropna(all)`, ±inf → NaN, categóricas → código, resto numérico a
float64; targets `BENIGN/ATTACK` y `attack_cat`; Parquet por fichero fuente
con `stats.json` y `anomaly_policy.json`. Cargador: NaN e inf → 0.

| Partición | Regla | Tamaños |
|---|---|---|
| `random` | Máscara por fila 70/15/15, semilla 42 | 1.778.346 / 380.838 / 380.863 |
| `groupkfold` | Grupo = fichero fuente; con 4 ficheros y 8 folds, **los folds 4–7 duplican a los 0–3** | fold 0: train F3+F4 (1.140.045) / val F2 / test F1 |
| `official` | Train = `training-set`; `testing-set` → val/test 50/50 | 82.332 / 87.447 / 87.894 |

**El bug de cabecera y su corrección (R11).** Los cuatro crudos no llevan fila
de cabecera y `pandas` tomó la primera fila de datos como nombres: las copias
antiguas de `random` y `groupkfold` tienen **141 «features»** con nombres como
`0.000117`, `59.166.0.0` o `udp`, no contienen `label` ni `attack_cat`, y todo
quedó etiquetado como ATTACK (una sola clase). `validation_report.json`
(2026-03-25) ya lo mostraba (`observed: ["ATTACK"]`, `n_columns: 141`). Los
modelos entrenados sobre esas copias dieron exactitud 1,0 con
`label_map = {"ATTACK": 0}`: **no son resultados** y no deben figurar en la
memoria. Corrección (`read_csv_smart`, 2026-09-02): detecta `UNSW-NB15_[1-4].csv`
e inyecta los 49 nombres oficiales; las particiones se regeneraron en
`src/models/NUSW-NB15/datasets/` con 47 features y la distribución real. Las
copias corruptas siguen en `src/models/UNSW-NB15/datasets/{random,groupkfold}`
(4,1 GB) pendientes de borrado. El parche está **sin commitear**.

### 19.3 Modelos **[documentado]**

| Modelo | Hiperparámetros |
|---|---|
| `offline_NUSW_binary_hgb` | HGB `max_iter` 200, lr 0,1, profundidad 3, parada temprana 7 |
| `offline_NUSW_multiclass_hgb` | Idem, profundidad 4, `max_iter` 250 |
| `offline_NUSW_binary_mlp` | MLP 512 × 3, dropout 0,2, AdamW 1e-3, batch 8.192, 25 épocas |
| `anomaly_isoforest_NUSW-NB15` | 300 árboles, solo BENIGN |

### 19.4 Métricas

**Posteriores a la corrección — citables** **[medido]**
(`src/models/NUSW-NB15/artifacts/`, 2026-09-02; solo tres ejecuciones):

| Run | Partición | Exactitud | Bal. acc. | **Macro-F1** | ROC-AUC | Log-loss | Iteraciones |
|---|---|---|---|---|---|---|---|
| `offline_NUSW_binary_hgb/random/20260902_143624` | random | 0,9930 | 0,9822 | **0,9841** | 0,9997 | 0,0141 | 142 |
| `offline_NUSW_binary_hgb/groupkfold/20260902_143642/fold_0` | test = fichero 1 | 0,9957 | 0,9719 | **0,9658** | 0,9997 | 0,0077 | 176 |
| `offline_NUSW_multiclass_hgb/random/20260902_143656` | random, 11 clases | **0,9753** | 0,4485 | **0,4505** | — | 0,2055 | 8 |

El multiclase alcanza exactitud 0,975 con macro-F1 0,45: las categorías raras
siguen siendo difíciles (Worms tiene 27 muestras de test; `Backdoor`/`Backdoors`
están partidas; el benigno se llama `Unknown`). El desglose por clase no se
persiste. Pendientes tras la corrección: folds 1–3, partición oficial, Isolation
Forest, MLP, comparativa.

**Partición oficial (2026-03-25)** **[medido]** — fuente con cabecera, no
afectada por el bug, pero véase §19.5:

| Run | Modelo | Exactitud | Macro-F1 | ROC-AUC | Exactitud en train |
|---|---|---|---|---|---|
| `20260325_173527` | HGB binario | **0,2635** | 0,2607 | 0,5114 | 0,9994 |
| `20260325_152512` | HGB binario | 0,2637 | 0,2609 | 0,5119 | 0,9998 |
| `20260325_162141` | MLP binario | 0,4226 | 0,4191 | 0,4894 | 0,9082 |
| `20260325_152517` | HGB multiclase | 0,2297 | 0,1406 | — | 0,9027 |
| `20260325_152522` | Isolation Forest | ROC 0,712 · PR-AUC 0,832 · best-F1 0,809 = F1 de «todo ataque» con prevalencia 0,68 | | | |

**Anteriores a la corrección, `random` y `groupkfold` — no citables**: 35 runs en
`src/models/UNSW-NB15/artifacts/` (exactitud 1,0 monoclase, o mezclas de
regeneraciones intermedias no conservadas).

### 19.5 La corrección que faltaba: el 0,26 oficial es fuga por `id` **[medido, 2026-09-08]**

Una exactitud de 0,26 **por debajo de la línea base mayoritaria** (0,68) no es un
cambio de distribución: señala una feature espuria. La partición oficial
incluye la columna `id` entre sus 43 features, y en el `training-set` la
etiqueta forma bloques a lo largo de `id` (**4 cambios de etiqueta en 82.332
filas**), mientras que en el `testing-set` cambia 4.109 veces. El HGB aprendió
«el id dice la clase». Reentrenando el mismo modelo (HGB 200 iteraciones,
semilla 42) sobre el Parquet oficial existente:

| Variante | Exactitud | Macro-F1 | ROC-AUC |
|---|---|---|---|
| Con `id` (reproduce el run de marzo) | 0,2646 | 0,2617 | 0,5143 |
| **Sin `id`** | **0,8986** | **0,8905** | **0,9852** |

El contraste honesto laxo frente a oficial en UNSW-NB15 es por tanto
**≈ 0,98 frente a ≈ 0,90**, no frente a 0,26; sigue habiendo una caída clara
bajo la partición rigurosa, pero de otro orden. Persistido el 2026-09-09 por
`src/models/UNSW-NB15/experiment_official_id_leak.py` en `src/models/NUSW-NB15/artifacts/exp_official_id_leak/official/20260909_001256/results.json`, que añade una tercera variante, `id` permutado en test
(exactitud 0,441 · macro-F1 0,440 · ROC 0,770), y el recuento de bloques de
etiqueta. Registrado como corrección de R11 en `RESULTADOS.md` y corregido en
la memoria técnica publicada.

Segundo defecto, también verificado: `proto`, `service` y `state` (y `srcip`,
`dstip` en los crudos) llegan **100 % a NaN → 0** en todos los Parquet, porque
la codificación de categóricas comprueba `dtype == object` y con pandas 3 las
columnas de texto son `str`. La intención de la estrategia («preservar y
codificar proto/service/state») no se cumplió en ningún run; todas las cifras
del módulo se obtuvieron sin esas columnas.

### 19.6 Otros hallazgos

- `stime`/`ltime` (marcas de tiempo Unix) y los puertos entran como features en
  los crudos: en partición aleatoria permiten memorizar periodos. No medido.
- El vocabulario categórico, de funcionar, se ajusta sobre todos los ficheros
  incluido test.
- El ECE binario del módulo no es interpretable (usa P(ATTACK) como confianza).
- `train_test_network.csv` diferido por incompatibilidad de esquema
  (`evaluate_train_test_network.py`: 3 columnas en común de 45).
- Los orquestadores `nusw_run_all_models.ps1` y `nusw_train_models.ps1` y el
  `README.md` raíz invocan `src\models\NUSW-NB15\*.py`, que no existe (el
  código está en `UNSW-NB15/`): la orquestación está rota.
- `src/models/NUSW-NB15/` (4,9 GB de Parquet) está sin seguimiento y **no
  ignorado** por `.gitignore`.

### 19.7 Inventario

`STRATEGY_UNSW-NB15.md`, `TODO_UNSW-NB15.md` (todo marcado como hecho en marzo),
`nusw_run_all_models.ps1`, `nusw_train_models.ps1`,
`src/helpers/analyze_nusw_folder.py`, `prepare_dataset.py` (con
`read_csv_smart`), `data_loader.py`, `train_utils.py`, `metrics.py`,
`reporting.py`, `models_torch.py`, los cuatro entrenadores, `compare_models.py`,
`validate_datasets.py`, `evaluate_train_test_network.py`,
`experiment_official_id_leak.py` (2026-09-09, diagnóstico persistido de §19.5);
`UNSW-NB15/datasets/validation_report.json`, `UNSW-NB15/datasets/official/`
(56 MB, válida salvo `id`), copias corruptas `random`/`groupkfold` (4,1 GB),
`UNSW-NB15/artifacts/` (35 runs pre-corrección), `NUSW-NB15/datasets/` (4,9 GB
regenerados) y `NUSW-NB15/artifacts/` (3 runs citables + `exp_official_id_leak`); `out/UNSW-NB15/` y
`out/UNSW-NB15_analysis/`.

---

## 20. UGR'16 — validado y preparado, sin entrenar

Módulo `src/models/UGR16/` (16 scripts), estrategia `STRATEGY_UGR16.md`,
checklist `TODO_UGR16.md`, análisis exploratorio en `out/UGR16_analysis/`.
**Estado: ningún modelo entrenado.** Es el módulo donde el coste de escala
detuvo el trabajo, y conviene documentarlo como tal.

### 20.1 Dataset **[medido]**

NetFlow real de un ISP español (2016), exportado por semanas, con ataques
inyectados etiquetados a nivel de flujo y una línea temporal de ataque por
minuto. Descargado en `out/UGR16/` (fuera del control de versiones).

| Magnitud | Valor | Fuente |
|---|---|---|
| Ficheros | 161 (23 CSV principales, 23 nfcapd, 92 por familia de ataque, 23 `attack_ts`) | `out/UGR16_analysis/inventory.csv`, 2026-04-02 |
| Tamaño total | **456,7 GiB** (≈ 490 GB): CSV principales 222,8 GiB, nfcapd 231,4 GiB, familias 2,45 GiB | `SUMMARY.txt` |
| Periodo | 2016-03-18 → 2016-08-29 (23 semanas) | `attack_weekly_summary.csv` |
| Esquema | 13 columnas sin cabecera: timestamp, duración, IP origen/destino, puertos, protocolo, flags TCP, constante 0, tipo TTL, paquetes, bytes, etiqueta | `STRATEGY_UGR16.md §4`, verificado en `artifacts/raw_validation/20260427_172731/summary.json` |
| Minutos con algún ataque activo | **173.341 de 174.451 (99,36 %)** — `blacklist` está activa en todos ellos | `attack_family_totals.csv` |
| Minutos por familia | blacklist 173.341 · anomaly-spam 24.956 · anomaly-sshscan 16.077 · nerisbotnet 732 · Dos 451 · scan11 98 · scan44 97 · anomaly-udpscan 9 | idem |
| Prevalencia de ataque a nivel de flujo (muestra 276.000 filas) | **0,85 %**: background 273.641 · blacklist 1.252 · anomaly-spam 727 · anomaly-sshscan 380 | `quick_summary.json` |

Dos advertencias de lectura. Primera: las familias Dos, scan11, scan44 y
nerisbotnet **solo existen en julio y agosto**, es decir, exclusivamente en
validación y test del split temporal: el entrenamiento nunca las vería.
Segunda: tanto el EDA como la validación muestrean los primeros 8–10 MB de cada
archivo (los primeros segundos de la semana), así que las prevalencias son cotas
locales, no del corpus. En 11 de las 22 semanas la muestra de 500 filas no
contenía ni un ataque.

### 20.2 Preprocesado diseñado **[documentado]**

Subconjunto `thesis_v1`: los 22 CSV principales menos agosto semana 4 (su
`attack_ts` está vacío), 211 GiB comprimidos. Split `date`: marzo–junio →
train (17 archivos), julio w5 → val, agosto w1/w2/w3/w5 → test.

| Paso | Script | Qué hace | Estado |
|---|---|---|---|
| 0 | `src/helpers/analyze_ugr_folder.py` | Inventario, análisis de `attack_ts`, muestreo de 12.000 filas por archivo, esquema, 6 gráficos, `RECOMMENDED_FILES.md` | Ejecutado 2026-04-02 |
| 1 | `validate_raw_semantics.py` | 13 comprobaciones semánticas por columna (parseo de timestamp e IP ≥ 95 %, numéricos, protocolo conocido ≥ 90 %, constante cero ≥ 90 %, ≥ 2 etiquetas) y calidad multiclase | 5 runs el 2026-04-27; **12 de 13 comprobaciones pasan en los 22 archivos**; falla solo `col_13_label_like` en 11 archivos por ausencia de ataques en la muestra |
| 2 | `prepare_dataset.py` (v1) | Lectura en streaming del tar por chunks de 250.000 filas; **37 features** (9 de flujo, 4 de contexto `timeline_*` desde `attack_ts`, 5 temporales, 6 indicadores de puerto, 5 flags, 8 de protocolo) + 15 columnas `*_meta`; 4 pipelines (`binary_raw`, `binary` balanceado por submuestreo estratificado semana × hora-de-ataque, `multiclass`, `anomaly` con train solo benigno); splits `date`, `random` 70/15/15, `groupkfold` por archivo (8 folds) | Ejecutado el 2026-04-27; **sin salida conservada** (`datasets/date/UGR16/` está vacío) |
| 2b | `prepare_dataset_v2.py` | Reanudación desde un archivo (`--resume_from_archive may_week2`): indica que v1 llegó hasta mayo w1 antes de interrumpirse | Nunca ejecutado |
| 2c | `prepare_dataset_v3/build.py` | Constructor con tope de disco (80 GB objetivo, 95 máx.): pasada de planificación, muestreo determinista por chunk, dtypes compactos, sin `binary_raw` | Nunca ejecutado |
| 2d | `prepare_march_dataset.py`, `prepare_march_april_feature_datasets.py` | Datasets reducidos (marzo; marzo–abril al 5 %) con tres perfiles de features: `oracle` (37, incluye la línea temporal de ataque como cota superior), `hybrid` (33), `flow` (22, solo flujo) | Nunca ejecutados |
| 3 | `validate_datasets.py` | Esquema y orden de features, dominio de etiquetas, orden temporal en `date`, ausencia de fuga de semanas en `groupkfold` | Compilado, sin dataset que validar |

Decisiones documentadas (`STRATEGY_UGR16.md`): no usar `attack_ts` como
etiqueta binaria (99,4 % de minutos activos colapsaría la clase negativa; se usa
solo como contexto horario), no incluir IPs como feature, descartar la columna
constante, diferir los 92 archivos por familia y los 23 nfcapd por coste.

### 20.3 Modelos: implementados, no entrenados **[documentado]**

| Script | Hiperparámetros codificados |
|---|---|
| `train_ml_binary_hgb.py` | HGB `max_iter` 200, lr 0,1, profundidad 3, parada temprana 7 |
| `train_ml_multiclass_hgb.py` | Idem, profundidad 4, `max_iter` 250 |
| `train_anomaly_isoforest.py` | 300 estimadores, `contamination="auto"` |
| `train_ml_binary_mlp.py` | MLP 512 × 3, dropout 0,2, AdamW 1e-3, batch 8.192, 25 épocas |

No existe ningún `results.json`, `metrics_*.json`, `comparison.csv` ni modelo
serializado bajo `src/models/UGR16/artifacts/`. La única huella de
entrenamiento es la carpeta vacía
`artifacts/offline_UGR16_binary_hgb/date/20260427_190312/`: el run abortó al no
encontrar datasets. **Métricas de modelo: ninguna.**

### 20.4 Hallazgos y por qué se detuvo

1. **Escala.** El preparador v1 escribe cada fila tres veces (más la vista
   balanceada) sin muestreo, sobre 211 GiB comprimidos. La sucesión v1 → v2
   (reanudar) → v3 (presupuesto de disco) documenta que el bloqueo fue de
   disco y tiempo, no de método.
2. **Etiqueta casi constante.** `blacklist` cubre el 100 % de los minutos con
   ataque; las familias interesantes (DoS, escaneos, botnet) viven solo en las
   semanas de test.
3. **Discrepancia flujo/minuto.** Semanas con el 100 % de minutos «en ataque»
   muestran 0 flujos etiquetados como ataque en la muestra: la etiqueta por
   minuto no equivale a la etiqueta por flujo.
4. **Conflicto de merge sin resolver** (`3c887bf`, 2026-05-13): los cuatro
   trainers contienen marcadores `<<<<<<<`/`>>>>>>>` y no son Python válido.
   Compiten la variante sin parámetro `--dataset` (HEAD) y la que lo propaga a
   rutas y `results.json` (`cc9f15f`); la segunda es la coherente con la firma
   de `run_one` ya fusionada. Bloques: `train_ml_binary_hgb.py` 4,
   `train_ml_multiclass_hgb.py` 4, `train_ml_binary_mlp.py` 3,
   `train_anomaly_isoforest.py` 2.
5. **Encaje en la tesis.** El plan (`AGENTS.md`, fase C) reservaba UGR'16 para
   deriva de concepto y aprendizaje de línea base. Con el corpus principal
   absorbiendo el trabajo, UGR'16 queda como **exploración documentada**: el
   valor que aporta a la memoria es la validación semántica del formato (12 de
   13 columnas verificadas en 22 archivos) y el análisis de por qué su etiqueta
   no sirve tal cual.

### 20.5 Estado (`TODO_UGR16.md`, 2026-05-13)

50 ítems: 28 hechos, 22 pendientes. Fundamentos 11/11; preprocesado 7/8;
estrategia 5/5; ejecución de modelos **1/12** (solo el script de orquestación);
validación 3/8; opcionales 1/6.

Inventario: `STRATEGY_UGR16.md`, `TODO_UGR16.md`, `ugr_run_all_models.ps1`,
`ugr_run_existing_dataset_models.ps1`, `analyze_ugr_folder.py`,
`prepare_dataset.py`, `prepare_dataset_v2.py`, `prepare_dataset_v3/build.py`,
`prepare_march_dataset.py`, `prepare_march_april_feature_datasets.py`,
`validate_raw_semantics.py`, `validate_datasets.py`, `data_loader.py`,
`train_utils.py`, `metrics.py`, `reporting.py`, `models_torch.py`,
`compare_models.py`, los cuatro trainers, `artifacts/raw_validation/` (tres runs
con datos) y `out/UGR16_analysis/` (resumen, inventario, análisis semanal de
ataques, 23 esquemas de muestra, 6 gráficos).

---

## 21. CSR-LANL — contra verdad de campo real: el dominio de validez (R12)

Módulo `src/models/CSR-LANL/` (2 scripts), análisis exploratorio en
`out/CSR-LANL_analysis/` y `_v2/` (2026-03-31), pipeline y run únicos del
2026-09-02. Es la **primera evaluación de toda la tesis contra ground truth
real**: el fichero `redteam.txt` registra las autenticaciones de compromiso de
un equipo rojo auténtico, con una fuente independiente del flujo de eventos, de
modo que la circularidad es imposible.

### 21.1 Dataset **[medido]** (`out/CSR-LANL_analysis/quick_summary.json`; `datasets/hourly/summary.json`)

Comprehensive, Multi-Source Cyber-Security Events (Los Alamos National
Laboratory): 58 días de una red corporativa real, anonimizada.

| Fichero | Tamaño comprimido | Campos | Uso |
|---|---|---|---|
| `auth.txt.gz` | 7,27 GiB · **1.051.430.459 líneas** | time, src_user, dst_user, src_computer, dst_computer, auth_type, logon_type, auth_orient, result | **Sí** (única fuente de features) |
| `proc.txt.gz` | 2,25 GiB | time, user, computer, process, event_type | Solo perfilado |
| `flows.txt.gz` | 1,03 GiB | time, duration, src, src_port, dst, dst_port, protocol, packets, bytes | Solo perfilado |
| `dns.txt.gz` | 177 MiB | time, src_computer, dst_computer | Solo perfilado |
| `redteam.txt.gz` | 4,8 KB · **749 líneas** | time, user, src_computer, dst_computer | **Verdad de campo** |

Verdad de campo: 749 autenticaciones de compromiso de **104 usuarios** desde **4
máquinas de origen** (C17693 701 eventos, C22409 26, C19932 19, C18025 3) hacia
301 máquinas destino, entre los días 1 y 29 (picos: día 8 con 273 eventos, día
12 con 209). Faltantes en `auth` (token `?`): `auth_type` 56,8 %, `logon_type`
15,4 %. Filas malformadas: 0.

### 21.2 Preprocesado **[documentado]** (`prepare_lanl_hourly.py`)

Una pasada en *streaming* sobre `auth.txt.gz`. Se conservan solo las filas cuyo
`src_user` empieza por `U` (usuarios humanos: 341.692.445 filas, el 32,5 %;
se excluyen cuentas de máquina `C*$` y `ANONYMOUS LOGON`, que no aparecen en el
red team). Unidad: **celda (máquina origen, hora)**. Etiqueta: la celda es roja
si el par (máquina, hora) aparece en `redteam.txt`.

| Magnitud | Valor |
|---|---|
| Celdas | **7.747.198** |
| Celdas rojas | **91** (todas las esperadas) → prevalencia **1,17·10⁻⁵** |
| Rojas por máquina | C17693 73 · C19932 14 · C22409 3 · C18025 1 |
| Features | **26**, causales |

Features: volumen (`n_events`, `log_n_events`, `n_fail`, `fail_ratio`),
diversidad (`n_users`, `n_dsts`, `users_per_event`, `dsts_per_event`,
`events_per_dst`), mezcla de autenticación (`ntlm_ratio`, `kerberos_ratio`,
`unknown_auth_ratio`), tipo de sesión (`network_ratio`, `service_batch_ratio`,
`logon_ratio`, `tgs_tgt_ratio`), novedad causal (pares usuario-origen,
origen-destino y usuario-destino nunca vistos, en recuento y ratio),
calendario proxy (`hour_of_day`, `day_of_week`) y línea base por máquina
(`src_hours_active`, `src_prev_hour_events`). Conjuntos de usuarios y destinos
topados a 512 elementos.

**Split temporal por días** (`train_lanl_redteam.py`, `--train_end 10 --val_end 15`):

| Split | Días | Celdas | Rojas | Prevalencia |
|---|---|---|---|---|
| Train | 0–9 | 1.261.845 | 35 | 2,8·10⁻⁵ |
| Val | 10–14 | 648.327 | 30 | 4,6·10⁻⁵ |
| Test | 15–57 | 5.837.026 | 26 | **4,5·10⁻⁶** |

### 21.3 Modelos **[documentado]**

HGB `max_iter` 300, lr 0,08, profundidad 6, L2 1,0, parada temprana 20,
`class_weight="balanced"`, sin escalado; Isolation Forest de 300 árboles sobre
features z-score (referencia no supervisada); sondas univariantes en
validación. Evaluación: ROC-AUC, PR-AUC, lift (PR-AUC / prevalencia), **lista de
caza** (las k celdas de mayor score de cada día, k ∈ {10, 25, 50}) y desglose
por día. El modelo no se persiste; solo `results.json`.

### 21.4 Métricas **[medido]** (`src/models/CSR-LANL/artifacts/redteam_hourly/20260902_144340/results.json`)

| Modelo · split | n | Rojas | ROC-AUC | PR-AUC | Lift | Lista de caza top-50/día |
|---|---|---|---|---|---|---|
| HGB · val | 648.327 | 30 | 0,8978 | 0,00873 | 188,7× | 250 celdas revisadas, **0/30** |
| **HGB · test** | 5.837.026 | 26 | **0,9587** | 0,00075 | 168,1× | 2.150 celdas revisadas, **1/26** (precisión 0,00047) |
| Isolation Forest · test | 5.837.026 | 26 | 0,8328 | 0,00014 | 30,4× | 0/26 |

Por día en test (HGB, lift de PR-AUC): día 15 (7 rojas) 249×; día 21 (2)
**259×**; día 26 (4) 188×; día 20 (1) 150×; día 27 (5) 134×; día 29 (4) 88×;
día 28 (2) 71×; **día 22 (1) 1,05×**, indistinguible del fondo.

Sondas univariantes (ROC-AUC en val): **`ntlm_ratio` 0,9895**, `src_hours_active`
0,946, `kerberos_ratio` 0,945, `new_edge_ratio` 0,897, `new_user_dst_count`
0,896, `n_users` 0,874. En las celdas rojas el 83,7 % de las autenticaciones
son NTLM frente al 2,2 % en el resto: coherente con la táctica documentada del
red team de LANL en un entorno mayoritariamente Kerberos.

`RESULTADOS.md` añade que la agregación por entidad deja a las 4 máquinas
atacantes en posiciones 840–2.356 de 15.180 (el número de máquinas origen
distintas del test). **Ese cálculo no está en el script ni en `results.json`**:
consta solo en el registro, sin artefacto ni método de agregación descrito.

### 21.5 Hallazgos

1. **Señal genuina.** ROC-AUC 0,96 en test y lift de dos órdenes de magnitud en
   7 de los 8 días con rojas: las variables conductuales causales separan
   compromisos reales de la actividad normal. El supervisado supera al no
   supervisado también aquí, como en ARGOS.
2. **Insuficiencia operativa.** A una roja entre ~225.000 celdas, un lift de
   168× deja la PR-AUC en 0,00075: la lista de caza de 50 celdas al día
   encuentra 1 de 26 horas rojas revisando 2.150 celdas, y en validación
   ninguna. El día 22 muestra horas rojas indistinguibles del fondo. Es el
   recordatorio de por qué el ROC-AUC engaña con clases muy desbalanceadas.
3. **El dominio de validez del método queda medido con ground truth en ambos
   lados** (§25): eficaz contra atacantes ruidosos, señal real pero no operativa
   contra sigilosos con credenciales válidas. Trabajo futuro: features de grafo
   y pares usuario-máquina, la respuesta de la literatura al caso sigiloso.
4. **El docstring esperaba prevalencia ~10⁻⁴**; la real es un orden de magnitud
   menor.
5. **Discrepancia documental a resolver.** `ARGOS_WEB.md` y `DOSSIER_TFM.md`
   (§6.6 y §11.1) describen un «modelo CSR-LANL» integrado en la web con **209
   características, 13,1 M de ventanas, 16.155 entidades, ROC-AUC 0,940,
   PR-AUC 0,0168 y precisión@50 0,040**. Ese modelo **no existe en este
   repositorio** (ni código, ni datos, ni artefacto): procede del repositorio de
   la web (`models_future/csr_lanl_identity`) y sus cifras no son las de R12
   (26 features, 7,75 M de celdas, PR-AUC 0,00075 en test). El §6.6 de
   `DOSSIER_TFM.md` mezcla el ROC 0,96 de R12 con la PR-AUC 0,0168 del modelo
   web. La memoria debe citar uno u otro con su procedencia, no fusionarlos.

### 21.6 Inventario

`prepare_lanl_hourly.py`, `train_lanl_redteam.py`,
`datasets/hourly/cells.parquet` (173 MB, 7.747.198 × 31 columnas),
`datasets/hourly/summary.json`, `artifacts/redteam_hourly/20260902_144340/results.json`;
`src/helpers/analyze_csr_lanl_folder.py` y `_v2.py` (EDA de marzo, 24 gráficos);
`out/CSR-LANL/` (10,7 GiB crudos), `out/CSR-LANL_analysis{,_v2}/`. Pendiente:
commit del módulo (sin seguimiento), script de la agregación por entidad,
evaluación de `ntlm_ratio` sola en test, uso de `dns`/`flows`/`proc`.

---

## 22. Conjuntos previstos y no explotados

| Conjunto | Papel previsto (`AGENTS.md`) | Qué hay | Qué no hay |
|---|---|---|---|
| **CTU-13** | Fase D, validación final realista (botnets) | `out/CTU-13-OPTIONAL/CTU-13-Dataset.tar.bz2`, **1,86 GiB**, descargado 2026-03-25; contiene capturas `.pcap`, `.binetflow` y **binarios de malware** (`Neris.exe`, `rbot.exe`: manipular con cuidado si se extrae) | No extraído, sin estrategia, sin script, sin mención en resultados. El papel de «validación final realista» lo cubrió LAB-ALERTS (inferencia, no consta escrito) |
| **TON_IoT** | Fase B, correlación multi-fuente | Nada | No descargado |
| **Unit 42 PCAPs** | Fase D | Nada | No descargado |
| **Bot-IoT**, HDFS/BGL/OpenStack | Mencionados como opcionales | Nada | — |
| `train_test_network.csv` (UNSW) | — | Fichero en `out/UNSW-NB15/` (211.044 filas, esquema tipo Zeek) | Diferido por incompatibilidad de esquema (3 de 45 columnas coinciden) |

La evolución respecto al plan es legítima y debe contarse así en la memoria:
el plan preveía cinco datasets públicos y «un pequeño dataset propio»; el
propio (ARGOS-LAB, 1,46 M de alertas) resultó ser donde estaba el hallazgo, y
los públicos se usaron para lo que sí aportan, reproducir el patrón de
partición (CIC, UNSW) y medir el dominio de validez (CSR-LANL).

---

# PARTE V · SÍNTESIS

## 23. El patrón transversal: el protocolo de partición decide el resultado

El hallazgo con mayor valor de la memoria no procede solo de ARGOS-LAB sino de
su reproducción en referencias académicas independientes. Mismo tipo de modelo
(HistGradientBoosting), distinto protocolo de partición:

| Conjunto | Protocolo laxo | Resultado | Protocolo riguroso | Resultado |
|---|---|---|---|---|
| **ARGOS-LAB** (alertas SIEM) | Temporal, mismo periodo, mismos hosts | MCC **0,955** | Host no visto (LOAO, servidor web) | MCC **0,000** |
| **CIC-IDS2017** (flujos) | Aleatorio | ROC-AUC **0,999** (MLP, FT-Transformer) | Por día (familias de ataque no vistas) · por grupo | Macro-F1 0,618 · ROC 0,535 (día); macro-F1 **0,500** · ROC **0,344** (grupo: predictor degenerado). *HGB con 5 iteraciones, régimen de desarrollo* |
| **UNSW-NB15** (flujos) | Aleatorio | Macro-F1 **0,984** | Partición oficial de los autores | Macro-F1 **≈ 0,89** sin la feature `id` (con `id`: 0,26, **fuga**; §19.5) |
| **LAB-ALERTS → ARGOS** (otra instalación) | Etiqueta del motor de reglas | MCC **0,000** | Etiqueta de conducta, canalización congelada | MCC 0,34 (0,19–0,46 por host) |

Tres conjuntos independientes, de dos naturalezas distintas, exhiben el mismo
comportamiento: rendimiento casi perfecto bajo particiones que preservan la
distribución y caída fuerte —hasta el nivel del azar en ARGOS y CIC— bajo
particiones que la rompen. **El factor determinante del resultado publicado no
es el modelo, sino el protocolo de evaluación.** Dos matices que la memoria
debe recoger: en CIC-IDS2017 la partición por día es además una partición por
familia de ataque, y en UNSW-NB15 el 0,26 que se venía citando era una fuga por
la columna `id`, no un cambio de distribución (§18.5, §19.5).

## 24. El aprendizaje profundo: cuatro arquitecturas, ningún avance medible

| Arquitectura | Tarea | Resultado | Referencia |
|---|---|---|---|
| MLP tabular (256 × 3, BatchNorm) | Binario ARGOS, `behavioral` | Macro-F1 0,9664 frente a 0,9776 del HGB; en LOAO MCC medio 0,1221 frente a 0,3894 | §7.1, §8.1 |
| Autoencoder (latente 12) | Anomalías ARGOS | 18,26× agregado → 0,57×–0,95× por agente. **Retirado** | §9 |
| GRU (48 unidades) sobre la secuencia de avisos de una IP | Bloqueo temprano | AUC medio 0,9702 frente a 0,9703 del HGB. Empate exacto | §13.5 |
| Transformer de atención (2 bloques, 4 cabezas, 18k parámetros), 3 semillas | Bloqueo temprano | AUC medio por K 0,957 frente a 0,952; secuencial 0,991/0,991 frente a 0,990/0,993. Empate | §13.6 |
| GRU sobre secuencias de ventanas (L = 12) | Binario y multiclase ARGOS | 0,8771 y 0,5950 de macro-F1, por debajo del HGB de una ventana | §7 |
| MLP y FT-Transformer (CIC-IDS2017, `random`) | Binario | ROC-AUC 0,9987 / 0,9986, iguales entre sí; en Infiltration (fold 4) detectan 7 y 1 de 36 | §18.4 |

La conclusión es interpretable: con variables tabulares agregadas y etiquetas
que cuentan hechos sin depender del orden, el aprendizaje profundo no tiene nada
que explotar que el gradient boosting no capte. El avance de recall de 0,82 a
0,99 en el bloqueo temprano vino de cambiar el planteamiento (política
secuencial, reputación de subred, etiqueta de conducta), no el modelo. Los
modelos en producción son HistGradientBoosting: 6,6 MB, sin GPU, inferencia en
microsegundos. El Transformer se conserva por explicabilidad y como segunda
opinión, no por métrica.

## 25. Dominio de validez: atacantes ruidosos sí, sigilosos no

Es la aportación que cierra el trabajo, medida con verdad de campo en ambos
extremos:

| Corpus | Tipo de atacante | Verdad de campo | Señal | Utilidad operativa |
|---|---|---|---|---|
| **ARGOS-LAB / LAB-ALERTS** | Ruidoso: fuerza bruta, escaneo, *spraying* desde internet | Etiqueta de conducta auditada (no circular) | Recall 0,990 / precisión 0,995; externo 0,994 | **Operativa**: 89–91 % del volumen de ataque suprimido, mediana al 5º aviso |
| **CSR-LANL** | Sigiloso: credenciales válidas, movimiento lateral de un equipo rojo real | 749 autenticaciones de compromiso, fuente independiente | ROC-AUC 0,9587 en test; `ntlm_ratio` sola 0,99 | **No operativa** a prevalencia 4,5·10⁻⁶: la lista de caza top-50/día acierta 1 de 26 |

La metodología de conducta observada detecta atacantes ruidosos con eficacia
operativa y produce señal real pero no operativa contra atacantes sigilosos. El
límite queda medido, no supuesto.

## 26. Registro de resultados validados y retirados

Fuente canónica: `src/models/ARGOS_LAB/RESULTADOS.md`. Convenciones: split
temporal salvo indicación, semilla 42, precisión objetivo del bloqueo 0,99
fijada en validación.

| Id | Resultado | Cifra clave | Sección |
|---|---|---|---|
| R1 | Auditoría de fuga de la etiqueta débil | Una columna → ROC-AUC 0,9990 | §6 |
| R2 | Huella del host | 99,75 % de exactitud prediciendo el agente sin su identificador | §8.2 |
| R3 | Multiclase de actividad | Macro-F1 0,7738 conductual (0,9911 con firma) | §7.2 |
| R4 | Etiqueta de bloqueo por conducta | Mejor sonda 0,6641; 80.221 ventanas | §11 |
| R5 | Puntuador de bloqueo por ventana | Lift 43,5× / 20,0×; transferencia 65–104 % | §12.1 |
| R6 | Validación externa del puntuador de ventanas (gastado) | MCC medio 0,3426 en hosts jamás vistos | §17.4 |
| R7 | Bloqueo temprano secuencial por IP | Recall 0,990 / precisión 0,995 / 89 % evitado | §13.3 |
| R8 | Validación externa del bloqueo secuencial (gastado) | Recall 0,994 / precisión ≥ 0,898 (censura); **37** cortes erróneos, no 38 | §17.4 |
| R9 | Umbral adaptativo a la prevalencia | K = 5: 0,846 → 0,900 sin etiquetas | §13.4 |
| R10 | GRU secuencial | AUC 0,9702 vs 0,9703: sin ventaja | §13.5 |
| R11 | UNSW-NB15 corregido | Bug de cabecera; laxo 0,984; **oficial ≈ 0,89 sin `id`** (el 0,26 era fuga) | §19 |
| R12 | CSR-LANL contra red team real | ROC 0,96, no operativo a 4,5·10⁻⁶ | §21 |
| R13 | Transformer de atención | Empate; segunda opinión en el paquete | §13.6 |
| X1 | Autoencoder «18,3×» | 0,57×–0,95× por agente. Paradoja de Simpson | §9 |
| X2 | Binario supervisado ~0,99 | Saturado en todo régimen; no citable | §7.1 |
| X3 | Adaptación z-score por host | MCC −0,08 a −0,26 | §12.2 |

## 27. Limitaciones del trabajo de investigación

Ordenadas por gravedad.

1. **No hay clase benigna real en ningún conjunto propio.** Wazuh solo indexa lo
   que dispara una regla; el negativo sale de etiquetado débil. Sin benignos
   reales no se puede afirmar nada sobre falsos positivos, y un SOC se juzga por
   falsos positivos. Todo resultado supervisado tiene ese techo.
2. **La etiqueta de bloqueo es conducta, no verdad absoluta.** Los criterios
   (≥ 5 cuentas, ≥ 2 máquinas, ≥ 50 intentos en ≥ 3 ventanas) son una heurística
   razonable y auditada, no un juicio humano.
3. **Cuatro agentes, de los cuales uno (honeypot) no aporta telemetría útil.**
   El LOAO tiene 4 folds; el puntuador de bloqueo solo pudo transferirse entre
   dos hosts (000 ↔ 011).
4. **Una instalación y 31 días.** La validación externa cubre un segundo entorno
   de 10,8 horas, tres hosts genuinamente nuevos, ningún Windows evaluable, y su
   presupuesto está gastado.
5. **La precisión externa 0,898 es un suelo, no una medida.**
6. **204 ventanas de la clase minoritaria en el test de ARGOS**: intervalos
   amplios.
7. **Dominio de validez estrecho**: atacantes ruidosos (§25).
8. **El Transformer no tiene validación externa** y K = 1 queda sin segunda
   opinión.
9. **Los datasets públicos son contraste, no banco de pruebas completo**: CIC en
   régimen de desarrollo (5 iteraciones), UNSW con dos defectos de pipeline
   (fuga por `id`, categóricas anuladas), UGR'16 sin entrenar, CTU-13 y TON_IoT
   sin explotar.
10. **La tarea binaria está saturada en cualquier régimen** y no debe presentarse
    como resultado de detección.

## 28. Reproducibilidad: qué produce cada cifra

| Cifra | Origen |
|---|---|
| Todo ARGOS-LAB (§4–§13) | `bash src/models/ARGOS_LAB/run_all_experiments.sh` y los `experiment_*.py` de §16.2; artefactos en `src/models/ARGOS_LAB/artifacts/` |
| Registro R1–R13 / X1–X3 y fe de erratas | `src/models/ARGOS_LAB/RESULTADOS.md` |
| Paquete de despliegue y sus métricas del test interno | `build_deploy_bundle.py`, `build_deploy_attention.py` → `deploy/argos_scorer/models/config.json` |
| Validación externa (R6, R8) | `experiment_external_validation.py`, `experiment_early_blocking_external.py`; **no volver a ejecutar contra LAB-ALERTS sin declararlo** |
| LAB-ALERTS (§17) | `src/models/LAB-ALERTS/` y `lab_alerts_run_all_models.ps1`; crosstest en `src/models/ARGOS_LAB/datasets/crosstest/` |
| CIC-IDS2017 (§18) | `src/models/CIC-IDS2017/`, `cic_run_all_models.ps1` (cambiar `epochs` para el régimen real) |
| UNSW-NB15 (§19) | `src/models/UNSW-NB15/` (código) → `src/models/NUSW-NB15/` (datos y artefactos); los `.ps1` apuntan a la ruta equivocada |
| UGR'16 (§20) | `src/models/UGR16/`; resolver los conflictos de los cuatro trainers antes de ejecutar |
| CSR-LANL (§21) | `src/models/CSR-LANL/prepare_lanl_hourly.py`, `train_lanl_redteam.py` |

Entorno: Python 3.11, PyTorch 2.9.1 con CUDA 12.8, scikit-learn 1.8, pandas 3.
Datos crudos y artefactos están fuera del control de versiones; el JSONL de
ARGOS-LAB (1,42 GB) se conserva con su manifest.

## 29. Afirmaciones que no se pueden escribir

| ❌ No escribir | ✅ Escribir en su lugar |
|---|---|
| «El clasificador detecta ataques con ROC-AUC 0,999» | «Una sola columna de la regla reproduce la etiqueta con 0,999: la tarea es reconstrucción de regla, no detección» |
| «El modelo generaliza a otras máquinas» | «Con la etiqueta débil no transfiere (MCC 0,000 en el servidor web); con la etiqueta de conducta retiene el 65–104 % y da MCC 0,34 en un entorno externo» |
| «El autoencoder detecta anomalías 18 veces mejor que el azar» | «Retirado: por agente está en 0,57×–0,95×; el agregado era paradoja de Simpson» |
| «El aprendizaje profundo mejora la detección» | «Cuatro arquitecturas empatan o pierden frente al gradient boosting en este corpus» |
| «El Transformer generaliza mejor por contexto» | «Empata con el HGB; aporta explicabilidad y una segunda opinión; sin validación externa» |
| «Validado en producción» | «Validación externa de un solo disparo sobre 10,8 horas; presupuesto gastado» |
| «Precisión externa 0,898» a secas | «Suelo por censura; 37 cortes contados como error en una captura de 10,8 h» |
| «Validado en hosts Windows» | «Un solo host Windows, activo 86 minutos y sin direcciones de origen: no evaluable» |
| «Detecta amenazas avanzadas» | «Dominio medido: atacantes ruidosos; contra red team sigiloso da señal (ROC 0,96) pero no utilidad operativa» |
| «UNSW-NB15: exactitud 1,0000» | Particiones corruptas por el bug de cabecera; **no citable** |
| «UNSW-NB15: la partición oficial cae a 0,26» | «Cae a ≈ 0,90 de exactitud; el 0,26 era fuga por la columna `id`» |
| «CIC-IDS2017: el gradient boosting colapsa» a secas | «Con 5 iteraciones y familias de ataque no vistas en train; el contraste entre particiones se mantiene, la cifra absoluta no es la del modelo» |
| «Modelo CSR-LANL con 209 características» como resultado de esta investigación | Es un artefacto del repositorio de la web sin respaldo aquí; el resultado de investigación es R12 (26 features, 7,75 M de celdas) |
| «UGR'16 / LAB-ALERTS entrenados con éxito» | UGR'16: validado y preparado, sin entrenar; LAB-ALERTS: pipeline propio sin artefactos, papel de validación externa |
| Cualquier porcentaje agregado a secas | Con su desglose por agente, host, fold o K |

## 30. Deuda técnica conocida

| Elemento | Situación | Riesgo |
|---|---|---|
| **Control de versiones** | Resuelto el 2026-09-09: todo el trabajo (ARGOS_LAB, CSR-LANL, UNSW-NB15, deploy, dossieres) está en commits de la rama `argos-lab-r1-r13`, con `.gitignore` ampliado para excluir los Parquet y artefactos de `NUSW-NB15/` y `CSR-LANL/` (5,3 GB). **Pendiente: revisar, fusionar en `main` y hacer push** | Medio hasta el push |
| **R11** | El «oficial 0,26» es fuga por `id` (artefacto `exp_official_id_leak`, 2026-09-09); categóricas anuladas en todos los Parquet de UNSW, pendiente de regenerar | Cifra corregida en `RESULTADOS.md` y en la memoria técnica publicada; regeneración pendiente |
| **R8** | El registro dice 38 cortes erróneos; el artefacto, 37; el análisis de los 29 censurados no está persistido | Cifra no trazable |
| **R12** | La agregación por entidad (posiciones 840–2.356) no tiene script ni artefacto | Cifra no reproducible |
| **CSR-LANL «web»** | `ARGOS_WEB.md` y `DOSSIER_TFM.md` describen un modelo de 209 features que no existe en este repo y mezclan sus cifras con R12 | Incoherencia entre documentos |
| CIC-IDS2017 | Todos los modelos con `epochs = 5`; ninguno con hiperparámetros por defecto | Cifras absolutas no representativas |
| UNSW-NB15 | Copias corruptas (4,1 GB) sin borrar; orquestadores `.ps1` y `README` apuntan a `NUSW-NB15/*.py`, inexistente | Confusión, orquestación rota |
| UGR16 | Cuatro trainers con marcadores de conflicto de git | No ejecutables |
| Documentos publicados | Los tres actualizados el 2026-09-09 (§31): memoria técnica con R11–R13 y fe de erratas; auditoría técnica con R10–R13, H8–H9 y sin las afirmaciones que contradecían la retirada del autoencoder; resumen en llano con el Transformer y el límite del método | Resuelto |
| `deploy/argos_scorer/example.py` | Reescribe `state/live_state.json` al ejecutarse | Reproducibilidad de la semilla |
| Honeypot | Las capturas de T-Pot no se reenvían a Wazuh: verdad de campo perdida | Oportunidad para captura futura |
| CTU-13 | Tarball con binarios de malware sin extraer en `out/` | Manipular con cuidado |

## 31. Bitácora de cierre (8–9 de septiembre de 2026)

Registro de lo que esta auditoría cambió fuera del propio dossier, para que la
memoria pueda citar el estado exacto de cada pieza.

### 31.1 Correcciones registradas

| Fecha | Qué | Dónde |
|---|---|---|
| 2026-09-08 | Fe de erratas: R8 (37 cortes, no 38; análisis de los 29 censurados no persistido), R11 (el «oficial 0,26» de UNSW es fuga por `id`; categóricas anuladas), R12 (agregación por entidad sin artefacto), más el estado real de CIC (5 iteraciones), UGR16 (sin entrenar), LAB-ALERTS (un Windows no evaluable) y el «modelo CSR-LANL» de la web | `src/models/ARGOS_LAB/RESULTADOS.md`, sección «Fe de erratas» |
| 2026-09-09 | Diagnóstico de la fuga por `id` persistido como experimento (§19.5): con `id` 0,264 · `id` permutado 0,441 · sin `id` 0,899 | `src/models/UNSW-NB15/experiment_official_id_leak.py` → `src/models/NUSW-NB15/artifacts/exp_official_id_leak/official/20260909_001256/results.json` |

### 31.2 Documentos publicados, republicados en la misma URL

| Documento | URL | Cambios (2026-09-09) |
|---|---|---|
| **Memoria técnica** | https://claude.ai/code/artifact/d0c1f055-fcdb-4963-9201-19ab749be4a2 | 22 sustituciones. §04: UNSW «regenerado, fuga por `id` corregida», CSR-LANL «evaluado contra red team (R12)», LAB-ALERTS «validación externa (R6, R8)», 10,8 h y 48 MB. §06: tarjeta del Transformer. §8.5: nueve hosts, tres nuevos, Windows no evaluable. §8.6: 37 cortes y párrafo R13. §8.7: fila CIC con régimen de 5 iteraciones y partición por familia; fila UNSW 0,984 ↔ 0,899 sin `id` con recuadro de corrección; conclusión sin «colapso al azar» en los tres. §09: particiones de UNSW regeneradas, oficial «válida sin `id`», filas CSR-LANL y UGR-16, recuadro «corregido y dos residuales», párrafo de estado de UGR/CSR-LANL/LAB-ALERTS/CIC. §10: veredicto DL con cuatro arquitecturas y conclusión nueva «Sobre el dominio de validez». §11: limitaciones y trabajo futuro actualizados. Pie con fecha |
| **Auditoría técnica ARGOS-LAB** | https://claude.ai/code/artifact/8d15f4f1-9454-470d-b8fc-efefb72d885e | 12 sustituciones. Tarjeta del autoencoder marcada como retirada (antes seguía mostrando «18,3×» como resultado); tarjeta del Transformer; §5.8 con 37 cortes y párrafo GRU/Transformer; H6 ampliada a cuatro arquitecturas; hipótesis nuevas H8 (transferencia de la etiqueta de conducta, confirmada) y H9 (atacante sigiloso, «señal, no utilidad»); §07: «un resultado no supervisado sólido» sustituido por la validación externa, «sin validación externa» por «validación externa limitada» y dominio de validez; §08: «autoencoder como red de seguridad» sustituido por el rechazo de actividad desconocida y la segunda opinión en modo sombra; §09: «qué defender» sin el autoencoder como logro y con el bloqueo temprano y el fallo del autoencoder como método; «normalización por host» y «segundo despliegue» marcados como realizados; fe de erratas; pie con fecha |
| **Resumen en llano** | https://claude.ai/code/artifact/d35c1ad3-899a-4489-9153-f339da326945 | Viñeta «La arquitectura de moda no ayuda» (Transformer como segunda opinión que explica); sección nueva 06 «Hasta dónde llega» (Los Alamos: 1 de 26 con 50 revisiones al día); tabla de usos con «cortar a un atacante ruidoso», «explicar qué avisos pesaron» y «detectar a un intruso silencioso: no»; balance con «comprobado en un segundo sistema», «una comprobación de 11 horas en otro» y «sólo atacantes ruidosos»; cierre y pie con fecha |

Antes de esta actualización, los tres documentos estaban consolidados hasta R9;
la memoria técnica citaba «exactitud 0,264» para UNSW y la auditoría seguía
presentando el autoencoder como logro en tres sitios pese a haberlo retirado en
un cuarto.

### 31.3 Control de versiones

Hasta el 2026-09-09 el último commit del repositorio era del 2026-05-13 y todo
el trabajo de ARGOS-LAB, CSR-LANL, UNSW-NB15 (parche y regeneración), el
paquete de despliegue y los dossieres vivía sin seguimiento en un solo disco.
Ese día se creó la rama `argos-lab-r1-r13` desde `main` y se confirmó el trabajo en
commits por bloque lógico:

1. `.gitignore`: se excluyen `src/models/NUSW-NB15/{datasets,artifacts}/` y
   `src/models/CSR-LANL/{datasets,artifacts}/` (5,3 GB de Parquet y
   artefactos), siguiendo la convención del repositorio de no versionar datos
   derivados; los artefactos citados en este dossier se regeneran con los
   comandos de §28.
2. `src/models/ARGOS_LAB/`: módulo completo (34 scripts, `README.md`,
   `RESULTADOS.md` con fe de erratas, manifest del export; el JSONL de 1,42 GB
   queda fuera por regla previa).
3. `deploy/argos_scorer/`: paquete v1.1 (HGB, Transformer en numpy, consenso,
   estado caliente, README).
4. `src/models/UNSW-NB15/`: corrección `read_csv_smart` y
   `experiment_official_id_leak.py`.
5. `src/models/CSR-LANL/`: pipeline horario y entrenamiento contra red team.
6. Documentos de raíz: `DOSSIER_TFM.md`, `DOSSIER_MODELOS_TFM.md`,
   `ARGOS_WEB.md`, `PROMPT_WEB_ATENCION.md`.

Queda en manos del autor revisar la rama, fusionarla en `main` y hacer push al
remoto (`github.com/Filips122/TFM_SIEM_IDS-IPS_IA`). Los hashes exactos se
consultan con `git log --oneline argos-lab-r1-r13`.

### 31.4 Lo que sigue abierto tras el cierre

- Regenerar UNSW-NB15 sin `id` y con las categóricas codificadas; reejecutar
  folds 1–3, oficial, Isolation Forest y MLP.
- Reejecutar CIC-IDS2017 con los hiperparámetros por defecto (no 5 iteraciones)
  y con los 8 folds.
- Resolver los cuatro conflictos de fusión de UGR16 antes de cualquier
  entrenamiento.
- Persistir el método de agregación por entidad de R12 y reconstruir el análisis
  de los 29 cortes censurados de R8.
- Conciliar en `DOSSIER_TFM.md` §6.6 y en la web el «modelo CSR-LANL de 209
  características» con R12, citando cada cifra con su procedencia.
- Captura externa nueva (> 24 h, host Windows activo y con origen de red) para
  validar el Transformer y repetir el cruce.

---

*Dossier de investigación generado el 8 de septiembre de 2026 y cerrado el 9 a partir de los
artefactos, docstrings y registros del repositorio `TFM_SIEM_IDS-IPS_IA`. Toda
cifra marcada **[medido]** tiene su ruta de origen; las marcadas
**[documentado]** proceden del código o de los ficheros de estrategia; las
**[externo]** proceden de la única ejecución contra LAB-ALERTS. La
verificación de UNSW-NB15 (§19.5) quedó persistida el 2026-09-09 en
`exp_official_id_leak`.*

# ARGOS-LAB — detección de intrusiones sobre alertas reales de Wazuh

Pipeline de preprocesado, ML clásico y Deep Learning sobre `argos-alerts_30d.jsonl`
(1.462.265 alertas, 30 días, 4 agentes, ~1,5 GB).

> **Lee esto antes de citar cualquier métrica.** Las etiquetas del dataset son
> *débiles*: las generó un motor de reglas, no un analista. Como consecuencia, la
> tarea binaria supervisada es en gran medida *reconstrucción de la regla de
> etiquetado*, no detección de intrusiones. Todo el diseño de este módulo existe
> para hacer ese problema **medible** en lugar de esconderlo.

---

## 1. Qué contienen los datos

| | |
|---|---|
| Alertas | 1.462.265 |
| Ventanas (1 min × agent_id) | 88.384 |
| Rango | 2026-07-28 → 2026-08-27 (31 días) |
| Agentes | `000` (wazuh), `003` (scanner), `011` (web), `030` |
| Etiqueta ventana | ATTACK 79.851 · BENIGN 1.738 · UNKNOWN 6.795 |

La clase minoritaria a nivel ventana es **el 2,1%**. Y, contra la intuición, la
clase rara es **BENIGN**, no ATTACK.

### 1.1 Columnas útiles, inútiles y tóxicas

Decidido a partir del perfilado completo del fichero (`feature_spec.py` fija el
criterio; `prepare_dataset.py` lo aplica).

**Descartadas — sin señal alguna**

| Columna | Motivo |
|---|---|
| `alert_id` | Identificador único por fila. Ruido puro. |
| `is_simulated` | Constante `0` en las 1.462.265 filas. Varianza cero. |
| `dst_port` | Vacía en el **100%** de las filas. |
| `agent_name`, `agent_ip` | Redundantes 1:1 con `agent_id` (4 agentes). Se conservan como metadatos. |
| `full_log` | Texto libre, ~70% del tamaño del fichero, redundante con `rule_id`. |
| `weak_label_reason` | *Es* la derivación de la etiqueta. Usarla es tautológico. |

**Alta cardinalidad — nunca one-hot, siempre agregadas**

| Columna | Distintos | Tratamiento |
|---|---|---|
| `src_port` | 38.203 | Puertos efímeros: sólo presencia y entropía. |
| `src_user` | 13.211 | Diccionario de fuerza bruta: nº distintos, entropía, ratio de cuentas de sistema. |
| `rule_description` | 9.228 | Inflada por CVEs incrustados, mientras `rule_id` sólo tiene 48. Metadato. |
| `src_ip` | 4.792 | Nº distintos, entropía, cuota del top, tasa de IPs nuevas. |
| `geo_city` | 723 | Nº distintos. |

**Tóxicas — entradas de la propia regla de etiquetado**

Estas columnas *definen* la etiqueta. No se eliminan: se **aíslan** en el grupo
`signature` para poder medir cuánto aportan.

```
rule_groups=authentication_failed → 100,00% ATTACK   (849.049 filas)
rule_groups=invalid_login         → 100,00% ATTACK   (771.290 filas)
rule_groups=trivy                 → 100,00% BENIGN   (410.611 filas)
decoder_name=trivy-decoder        → 100,00% BENIGN   (410.611 filas)
agent_id=003                      →  99,96% BENIGN   (410.737 filas)
hora ∈ {06,07,18,19}              →  ~70%   BENIGN   (cron de Trivy)
```

### 1.2 Los tres regímenes de features

Cada script recibe `--feature_set`. Un experimento **siempre** declara con qué
información se le permitió entrenar.

| Régimen | Nº | Contenido | Para qué sirve |
|---|---|---|---|
| `behavioral` | 54 | Volumen, diversidad de origen, entropía, geografía, novedad, línea base temporal por agente | **La métrica honesta** |
| `nosignature` | 61 | `behavioral` + agente y calendario | Mide el confundido de host/cron |
| `full` | 98 | Todo, incluida la firma de la regla | Techo de recuperabilidad de la etiqueta, **no** un resultado |

### 1.3 Columnas combinadas (feature engineering)

Las features con más valor no son columnas crudas sino **mezclas** — capturan
comportamiento de atacante que ninguna columna aislada expresa:

| Feature | Fórmula | Qué detecta |
|---|---|---|
| `alerts_per_src_ip` | `alert_count / unique_src_ip` | Intensidad por origen: fuerza bruta concentrada |
| `users_per_src_ip` | `unique_src_user / unique_src_ip` | *Credential spraying* frente a ataque dirigido |
| `src_ip_entropy_norm` | Shannon sobre distribución de IPs | Un atacante vs. botnet distribuida |
| `new_src_ip_ratio` | IPs nunca vistas / IPs de la ventana | Novedad (causal: sólo pasado) |
| `mean_src_ip_seen_before` | Frecuencia histórica acumulada | Reincidencia del origen |
| `burstiness_index` | `std(Δt) / mean(Δt)` | Ráfaga automatizada vs. tráfico regular |
| `agent_count_z` | `(n − μ_15) / σ_15` por agente | Desviación sobre la línea base **propia** del host |
| `root_user_ratio`, `system_user_ratio` | mezcla `src_user`+`dst_user` | Objetivo de credenciales privilegiadas |
| `geo_spread` | `√(σ²lat + σ²lon)` | Dispersión geográfica del origen |

Las features de novedad y de línea base son **causales**: sólo miran ventanas
anteriores, nunca el futuro.

---

## 2. Resultados

### 2.1 Auditoría de fuga — ejecuta esto primero

`python leakage_audit.py --split_mode date` (split temporal, test = 11.711 ventanas)

| Sonda | ROC-AUC | Lectura |
|---|---|---|
| `mitre_tagged_ratio` sola | **0,9990** | Una columna reproduce el modelo completo |
| `grp_invalid_login_ratio` sola | 0,9984 | |
| `rule_level_max` sola | 0,9920 | |
| `decoder_code` sola | 0,9411 | |
| grupo `signature` (37) | **1,0000** | Separación perfecta |
| grupo `behavioral` (54) | 0,9998 | |
| régimen `full` (98) | 1,0000 | |

**Conclusión:** una única columna alcanza el rendimiento del modelo completo. La
tarea binaria es reconstrucción de etiqueta.

Y hay un segundo hallazgo, más sutil: incluso `behavioral` llega a 0,9998, porque
las ventanas BENIGN **son estructuralmente otro tipo de alerta** — los hallazgos
de Trivy no tienen origen de red, así que `src_ip_present_ratio = 0` delata la
clase sin necesidad de la regla. Por eso la variante sin *posture* no es
opcional.

### 2.2 La prueba definitiva: importancia por permutación

Barajar **una sola columna** y medir cuánto cae PR-AUC de la clase minoritaria:

| Régimen | Columna | Caída | Lectura |
|---|---|---|---|
| `full` | `mitre_tagged_ratio` | **−0,486** | Media puntuación la sostiene una etiqueta de la regla |
| `behavioral` | `src_ip_present_ratio` | **−0,827** | Los hallazgos de Trivy no tienen origen de red |

Las 97 columnas restantes suman menos que la primera. Ambos regímenes son, de
hecho, modelos de una sola variable.

### 2.3 Binario supervisado (split temporal)

| Modelo | Régimen | Balanced acc. | Macro-F1 | MCC | PR-AUC (minoría) |
|---|---|---|---|---|---|
| HGB | `full` | 0,9975 | 0,9975 | 0,9950 | 1,0000 |
| HGB | `nosignature` | 0,9751 | 0,9774 | 0,9549 | 0,9945 |
| HGB | `behavioral` | 0,9776 | 0,9776 | 0,9551 | 0,9930 |
| MLP (DL) | `full` | 0,9926 | 0,9962 | 0,9925 | 1,0000 |
| MLP (DL) | `behavioral` | 0,9507 | 0,9664 | 0,9335 | 0,9778 |
| HGB sin posture | `behavioral` | 0,9779 | 0,9805 | 0,9609 | 0,9961 |
| GRU (L=12) | `behavioral` | 0,8225 | 0,8771 | 0,7653 | 0,8962 |

La tarea sigue saturada incluso sin *posture*: las clases se separan por volumen
bruto de actividad. **El binario a 1 minuto no es un problema informativo.**

### 2.4 Multiclase por familia de actividad — el mejor resultado supervisado

9 clases (`CredentialBrute`, `PortChange`, `AgentHealth`, `SshOperational`,
`PostureVuln`, `PostureSCA`, `IntegrityChange`, `PackageChange`, `Other`).

| Modelo | Régimen | Balanced acc. | Macro-F1 |
|---|---|---|---|
| HGB | `full` | 0,9993 | **0,9911** |
| HGB | `behavioral` | 0,8057 | **0,7738** |
| GRU (L=12) | `behavioral` | 0,6796 | 0,5950 |

Esta es la única tarea **no saturada**: 0,7738 de macro-F1 sólo con
comportamiento es un resultado real y no trivial, y el salto a 0,9911 al añadir
la firma de la regla **cuantifica limpiamente la fuga**. Las features que más
pesan son interpretables y puramente conductuales: `agent_gap_seconds` (0,244),
`src_ip_present_ratio` (0,216), `alert_count` (0,152), `burstiness_index`
(0,082).

Las clases raras siguen siendo difíciles (`IntegrityChange` F1 = 0,42 con 15
muestras de test), que es exactamente lo que debe esperarse.

### 2.5 El resultado que más importa: generalización entre hosts

`--split_mode groupkfold` = *leave-one-agent-out*.

| Fold | Test = agente | Balanced acc. | MCC | ROC-AUC |
|---|---|---|---|---|
| 0 | `000` | 0,8732 | 0,8080 | 0,9998 |
| 1 | `003` | 0,8763 | 0,7809 | 0,9234 |
| 2 | `011` | 0,5000 | **0,0000** | 0,9268 |
| 3 | `030` | 0,4855 | **−0,0314** | **0,3375** |
| **Media** | | **0,6838** | **0,3894** | 0,7969 |

El MLP cae aún más: MCC medio **0,1221**.

Dentro del mismo periodo: ~0,98. Entre hosts: **azar o peor** (el fold 3 queda
por debajo del azar). El modelo memoriza el perfil de actividad de cada host; no
aprende comportamiento de ataque transferible.

Para un despliegue real: **hay que reentrenar por host**, y las métricas de un
host no predicen las de otro.

### 2.6 Detección de anomalías no supervisada — **resultado retirado**

> **Corrección.** Una versión anterior de este documento presentaba el
> autoencoder (18,3× sobre el azar) como «el resultado no supervisado
> defendible». **Es falso y queda retirado.** El desglose por agente lo
> desmonta.

| Agente | n | BENIGN | PR-AUC | Base | Lift |
|---|---|---|---|---|---|
| 000 | 6.075 | 12 | 0,0017 | 0,0020 | **0,84×** |
| 003 | 30 | 23 | 0,7318 | 0,7667 | **0,95×** |
| 011 | 5.437 | 17 | 0,0018 | 0,0031 | **0,57×** |
| 030 | 169 | 152 | 0,7810 | 0,8994 | **0,87×** |
| **Global** | 11.711 | 204 | 0,3182 | 0,0174 | **18,26×** |

**Dentro de cada agente el detector está en el azar o por debajo.** El 18,26×
global procede exclusivamente de que la clase BENIGN se concentra al 74,5 % en
el agente 030 y al 76,7 % de prevalencia en el 003, mientras 000 y 011 son
99,8 % ATTACK. El autoencoder ordena «esto es del agente 030», no «esto es
anómalo». Es la **paradoja de Simpson**: una métrica agregada favorable sobre
grupos donde todos fallan.

Ajustar el detector *por host* tampoco lo arregla (lift medio 0,73× frente a
1,07× del global): la detección de anomalías sobre estas variables no funciona
en este corpus, ni global ni calibrada por máquina.

| Modelo | Política | Lift global | Lift por agente |
|---|---|---|---|
| Isolation Forest | `quiet` | 1,33× | ≤ 1,0× |
| Isolation Forest | `all` | 1,53× | ≤ 1,0× |
| Autoencoder | `all` | 18,26× | **0,57× – 0,95×** |

**Causa raíz.** Con las 54 variables `behavioral` se predice **qué agente es**
con **99,75 % de exactitud**, pese a que `agent_id_code` no está entre ellas.
Cada máquina tiene una huella de actividad propia, repartida de forma redundante
entre variables correlacionadas:

| Agente | `src_ip_present_ratio` | `geo_missing_ratio` | `alert_count` medio |
|---|---|---|---|
| 000 | 0,995 | 0,028 | 19,7 |
| 003 | 0,075 | 0,925 | 2.072 |
| 011 | 0,983 | 0,043 | 6,0 |
| 030 | 0,000 | 1,000 | 1,5 |

No se elimina un confundido borrando una columna cuando está distribuido entre
variables correlacionadas. De ahí la regla que ahora impone `reporting.py`:
**toda métrica agregada debe ir acompañada de su desglose por agente**
(`per_group_metrics`), que además emite un aviso automático cuando todos los
grupos están en el azar.

### 2.7 Puntuador de actividad por host — el resultado que sí sobrevive

`train_activity_scorer.py`. Sustituye la tarea binaria circular por
clasificación de familia de actividad, con el score de ataque como suma de
probabilidades de las familias hostiles.

| Agente | n | % hostil | ROC-AUC | Lift |
|---|---|---|---|---|
| 000 | 6.075 | 99,7 % | 0,9909 | 1,00× |
| 003 | 33 | 12,1 % | 0,8362 | **3,08×** |
| 011 | 5.438 | 99,5 % | 0,9997 | 1,00× |
| 030 | 1.156 | **0,78 %** | 0,9785 | **46,18×** |

A diferencia del autoencoder, **funciona dentro de cada agente**. En el 030
localiza 9 ventanas hostiles entre 1.156 sin salir del host.

Macro-F1 por agente sobre el conjunto completo de clases: **0,42–0,57**
(un valor de 0,9654 citado antes correspondía a un subconjunto restringido de
3 clases y no es comparable).

**Rechazo de actividad desconocida.** Un clasificador no puede reconocer una
familia que nunca vio, pero sí declarar que no la reconoce. Ocultando por
completo `PortChange` del entrenamiento:

| `reject_quantile` | Rechaza no vista | Rechaza conocida | Razón |
|---|---|---|---|
| 0,05 | 3,7 % | 4,3 % | 0,85× (inútil) |
| 0,25 | 39,5 % | 20,8 % | 1,90× |
| 0,50 | **99,8 %** | 34,4 % | 2,90× |

Es el mando de coste operativo: a `q=0,50` se captura casi toda la actividad
novedosa a cambio de revisar un tercio del tráfico conocido.

## 3. Cómo se usa

```bash
cd src/models/ARGOS_LAB

# 1. Preprocesado (una vez). ~4 min sobre el JSONL completo.
python prepare_dataset.py --split_mode date,random,groupkfold --all_folds

# 2. Variante sin hallazgos de escáner (la que pide el manifest)
python prepare_dataset.py --exclude_posture --dataset ARGOS-LAB-NOPOSTURE \
                          --split_mode date,random

# 3. Auditoría de fuga — SIEMPRE lo primero
python leakage_audit.py --split_mode date

# 4. Modelos
python train_ml_binary_hgb.py      --split_mode date --feature_set behavioral
python train_ml_binary_mlp.py      --split_mode date --feature_set behavioral
python train_ml_multiclass_hgb.py  --split_mode date --feature_set behavioral
python train_anomaly_isoforest.py  --split_mode date --train_policy quiet
python train_anomaly_autoencoder.py --split_mode date --train_policy quiet

# 4b. Puntuador por host (el modelo recomendado para despliegue)
python train_activity_scorer.py --split_mode date --feature_set behavioral
python train_activity_scorer.py --split_mode date --holdout_family PortChange                                 --reject_quantile 0.50

# 5. Secuencial
python prepare_sequence_dataset.py --split_mode date --pipeline binary \
                                   --feature_set behavioral --seq_len 12
python train_seq_gru.py --split_mode date --pipeline binary \
                        --feature_set behavioral --seq_len 12

# 6. Generalización entre hosts (el experimento decisivo)
python train_ml_binary_hgb.py --split_mode groupkfold --all_folds \
                              --feature_set behavioral

# 7. Tabla comparativa
python compare_models.py --metric macro_f1

# O todo de una vez
bash run_all_experiments.sh
```

### Ficheros

| Fichero | Función |
|---|---|
| `feature_spec.py` | Fuente única de verdad: grupos de features, regímenes, política de clases |
| `prepare_dataset.py` | JSONL → ventanas → parquet. Un solo paso en streaming |
| `prepare_sequence_dataset.py` | Ventanas → secuencias por agente |
| `data_loader.py` | Carga con filtrado por régimen de features |
| `leakage_audit.py` | Cuantifica la fuga. **Ejecutar primero** |
| `train_ml_binary_hgb.py` | Gradient boosting (binario y multiclase) |
| `train_ml_binary_mlp.py` | MLP denso en PyTorch |
| `train_anomaly_isoforest.py` | Isolation Forest no supervisado |
| `train_anomaly_autoencoder.py` | Autoencoder profundo no supervisado |
| `train_seq_gru.py` | Clasificador GRU sobre secuencias |
| `train_activity_scorer.py` | **Puntuador por host**: calibrado, con rechazo OOD |
| `build_block_labels.py` | Etiqueta de bloqueo derivada de conducta del origen |
| `compare_models.py` | Recopila todas las ejecuciones en una tabla |
| `metrics.py`, `reporting.py`, `train_utils.py`, `models_torch.py` | Infraestructura compartida |

Los artefactos se guardan en
`artifacts/<modelo>/<split_mode>/<dataset>__<regimen>/<run_id>/` con métricas,
matrices de confusión, curvas PR/ROC, importancia por permutación y el modelo
serializado.

---

## 4. Decisiones metodológicas

1. **Unidad = ventana de 1 min × agente.** Reproduce exactamente el recuento del
   manifest (79.851 / 1.738 / 6.795), lo que valida el windowing.
2. **Umbral ajustado en validación**, no `argmax`. Con un 2% de clase minoritaria
   `argmax` colapsa a la mayoritaria y esconde lo aprendido.
3. **Se reporta PR-AUC de la clase minoritaria.** ATTACK es el 98%: su PR-AUC
   está saturado por construcción y no informa de nada.
4. **UNKNOWN fuera del entrenamiento supervisado** (6.795 ventanas: cambios de
   netstat y paquetes dpkg que el etiquetador no supo clasificar). Se conservan
   para la evaluación no supervisada.
5. **Split temporal por defecto.** Un split aleatorio sobre datos temporales
   filtra información; `prepare_sequence_dataset.py` directamente rechaza
   `--split_mode random`.
6. **Features causales.** Novedad y línea base sólo consultan ventanas
   anteriores.
7. **Ponderación de clases activada** por defecto en todos los clasificadores.

---

## 5. Limitaciones

- **Las etiquetas son débiles**, generadas por reglas. No hay *ground truth* de
  analista. Todo número supervisado tiene ese techo.
- **Sólo 4 agentes.** El *leave-one-agent-out* usa 4 folds; los intervalos de
  confianza entre hosts son anchos.
- **Una sola instalación, 30 días.** Nada garantiza que estas features
  transfieran a otro despliegue de Wazuh.
- **La tarea binaria está saturada** en cualquier régimen y no debe presentarse
  como un resultado de detección.
- **La detección de anomalías no funciona aquí** (§2.6). Cualquier cifra
  agregada de este módulo debe leerse junto a su desglose por agente.

### Qué defender de este trabajo

En orden de solidez:

1. **La auditoría de fuga** (§2.1–2.2): una columna reproduce el modelo
   completo. Es una crítica metodológica reproducible al dataset.
2. **El fallo de generalización entre hosts** (§2.5): 0,98 dentro del periodo
   frente a MCC medio 0,389 entre hosts, con dos folds en el azar o por debajo.
   Tiene consecuencia operativa directa: reentrenar por host.
3. **El multiclase por comportamiento** (§2.4): macro-F1 0,7738 sin ninguna
   señal de la regla, sobre 9 clases. La única tarea supervisada con recorrido.
4. **El puntuador por host** (§2.7): funciona *dentro* de cada agente
   (46,18× de lift en el 030), y su mecanismo de rechazo captura el 99,8 % de
   una familia de ataque nunca vista.
5. **El fallo del autoencoder** (§2.6): un resultado agregado de 18,3× que se
   desmonta al desglosar por agente. Es un caso de paradoja de Simpson medido
   sobre datos propios, y justifica la instrumentación que ahora lo impide.

Lo que **no** debe citarse como logro: cualquier macro-F1 de ~0,99 en el binario.

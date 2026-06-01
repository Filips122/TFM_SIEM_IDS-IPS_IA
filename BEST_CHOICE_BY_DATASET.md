# Best Choice By Dataset

Fecha de consolidacion: 2026-06-01

Este documento no elige automaticamente el numero mas alto. Elige el resultado mas logico y defendible para el TFM, teniendo en cuenta split, riesgo de leakage, perfil de features, desbalance y utilidad operacional.

Fuentes principales:

- `BEST_RESULTS_BY_DATASET.md`
- `src/models/day20_comparison/20260520/top2_models.md`
- `src/models/*/artifacts/compare_models/*/comparison.md`
- `NEXT_STEPS.md`
- `REFACTOR_MODELS.md`
- `RESULTS_CSR-LANL.md`

## Criterio De Decision

| Criterio | Regla usada |
| --- | --- |
| Split | Priorizar `date`, `day`, `official`, `groupkfold` o `redteam_stratified_groupkfold` frente a `random` cuando haya soporte suficiente. |
| Leakage | Priorizar perfiles `operational_no_label_proxy` frente a perfiles completos si las features pueden ser proxies directos de la etiqueta. |
| Metrica | Usar `macro-F1`, `macro-recall`, `ROC-AUC`, `PR-AUC`, calibracion y metricas operacionales; no elegir por accuracy aislada. |
| Desbalance | Si hay positivos muy escasos, usar ranking, top-k, recall por entidad, alertas/dia y politicas calibradas. |
| TFM | Preferir un resultado menos espectacular pero metodologicamente defendible antes que un resultado casi perfecto por split facil. |

## Resumen De Eleccion

| Dataset | Eleccion recomendada | Split/perfil | Resultado obtenido | Por que es la eleccion logica |
| --- | --- | --- | --- | --- |
| CIC-IDS2017 | **GRU secuencial binaria** como evidencia robusta actual; MLP random solo como upper bound | `day` | `macro-F1=0.7793`, `macro-recall=0.7740`, `ROC-AUC=0.9908` | `random` da `macro-F1=0.9861`, pero es demasiado optimista; `day` mide mejor generalizacion temporal. |
| UNSW-NB15 | **HGB binario** como resultado principal actual; `official` como stress test obligatorio | `groupkfold/fold_0` | `macro-F1=0.9658`, `macro-recall=0.9719`, `ROC-AUC=0.9997` | Mantiene rendimiento alto fuera de `random`; `official` revela shift y debe reportarse, pero no invalida el baseline binario robusto. |
| UGR16 | **HGB binario** | `UGR16_MARAPR_HYBRID` + `date` | `macro-F1=0.8956`, `macro-recall=0.8957`, `ROC-AUC=0.9494` | Es el mejor resultado temporal/drift y usa un perfil SIEM/IDS-feasible sin usar el perfil oracle. |
| LAB-ALERTS | **HGB binario** | `date` + `operational_no_label_proxy` | `macro-F1=0.9878`, `macro-recall=0.9896`, `ROC-AUC=0.9931`, `PR-AUC=0.9967` | Conserva rendimiento alto sin proxies directos de etiqueta y con split temporal. |
| COWRIE_FULL | **HGB multiclass** | `date` + `operational_no_label_proxy` | `macro-F1=0.8713`, `macro-recall=0.8796`, `accuracy=0.9784`, `ECE=0.0027` | Multiclass describe mejor la taxonomia de comportamiento honeypot que una decision binaria. |
| CSR-LANL | **IsolationForest V3** para triage entity-day | `redteam_stratified_groupkfold/fold_0` + `entity_day` | `32/34` ventanas exactas cubiertas por politica entity-day; `1,327/1,415` entity-day windows cubiertas | CSR-LANL no debe venderse por accuracy; su valor esta en priorizacion SOC bajo desbalance extremo. |

## CIC-IDS2017

| Decision | Resultado |
| --- | --- |
| Eleccion recomendada | **GRU secuencial binaria en split `day`** como evidencia robusta actual. |
| Run representativo | `20260520_145849` |
| Resultado defendible | `accuracy=0.8013`, `macro-F1=0.7793`, `macro-recall=0.7740`, `logloss=0.7369`, `ROC-AUC=0.9908`, `ECE=0.5747` |
| Resultado numericamente superior | MLP binario en `random`, run `20260520_141225`: `accuracy=0.9912`, `macro-F1=0.9861`, `macro-recall=0.9904`, `ROC-AUC=0.9995` |
| Por que no elegir `random` como principal | Mezcla distribuciones y puede inflar el rendimiento en CIC-IDS2017. Sirve como upper bound o sanity check, no como prueba fuerte de generalizacion. |
| Por que no elegir `groupkfold` actual | Los resultados actuales exponen colapso y baja generalizacion; por ejemplo HGB `groupkfold/fold_4` llega a `macro-F1=0.5000` con aviso `majority_class_collapse`, y GRU `groupkfold` baja a `macro-F1=0.4314`. |
| Lectura para el TFM | CIC-IDS2017 demuestra que el pipeline puede lograr muy alto rendimiento en condiciones faciles, pero la evidencia principal debe destacar la sensibilidad al split. |

Conclusion CIC-IDS2017: usar `day` como resultado defendible actual y reportar `random` como upper bound. No presentar el `macro-F1=0.9861` como resultado principal sin advertir que es optimista.

## UNSW-NB15

| Decision | Resultado |
| --- | --- |
| Eleccion recomendada | **HGB binario en `groupkfold/fold_0`** como resultado principal actual. |
| Run representativo | `20260520_135042` |
| Resultado defendible | `accuracy=0.9957`, `macro-F1=0.9658`, `macro-recall=0.9719`, `logloss=0.0077`, `ROC-AUC=0.9997`, `ECE=0.9641` |
| Resultado random mas alto | HGB binario en `random`, run `20260520_133434`: `accuracy=0.9930`, `macro-F1=0.9841`, `macro-recall=0.9822`, `ROC-AUC=0.9997` |
| Stress test official | MLP binario `official`: `macro-F1=0.7117`, `macro-recall=0.7699`, `ROC-AUC=0.7665`; HGB `official` cae mas (`macro-F1=0.2609-0.3579` segun run). |
| Por que no elegir `random` como principal | Aunque es el mejor numero, `groupkfold` es mas exigente y sigue siendo fuerte. |
| Por que no elegir `official` como unico resultado principal | Es metodologicamente importante y debe reportarse, pero los resultados actuales indican shift fuerte o necesidad de saneamiento adicional; usarlo como stress test evita ocultar la caida sin descartar el baseline robusto. |
| Lectura para el TFM | UNSW-NB15 debe presentarse como benchmark supervisado fuerte, con `groupkfold` como evidencia principal y `official` como validacion de distribucion dificil. |

Conclusion UNSW-NB15: elegir HGB binario `groupkfold/fold_0` como resultado principal, reportar `random` como upper bound y `official` como stress test de generalizacion.

## UGR16

| Decision | Resultado |
| --- | --- |
| Eleccion recomendada | **HGB binario sobre `UGR16_MARAPR_HYBRID` en split `date`**. |
| Run representativo | `20260520_151846` |
| Resultado defendible | `accuracy=0.8957`, `macro-F1=0.8956`, `macro-recall=0.8957`, `logloss=0.3123`, `ROC-AUC=0.9494`, `ECE=0.3959` |
| Segundo modelo | MLP binario sobre el mismo dataset/split: `macro-F1=0.6844`, `ROC-AUC=0.7959` |
| Baseline anomaly | IsolationForest sobre `UGR16_MARAPR_HYBRID`: `ROC-AUC=0.5525`, `PR-AUC=0.0297`, aviso `weak_anomaly_pr_auc` |
| Por que este split tiene sentido | `date` respeta una validacion temporal y el dataset March/April permite hablar de comportamiento longitudinal y drift. |
| Por que elegir `HYBRID` | Evita el perfil `ORACLE` y conserva contexto SIEM/IDS factible, por lo que es mas defendible que usar informacion demasiado cercana a la verdad terreno. |
| Lectura para el TFM | UGR16 es la pieza de validacion temporal: menor rendimiento que CIC/UNSW, pero mas realista y academicamente fuerte. |

Conclusion UGR16: mantener HGB binario `UGR16_MARAPR_HYBRID/date` como eleccion principal. No defender IsolationForest global como detector principal en este dataset.

## LAB-ALERTS

| Decision | Resultado |
| --- | --- |
| Eleccion recomendada | **HGB binario en `date` con `operational_no_label_proxy`**. |
| Run representativo | `20260520_154310` / consolidado tambien como `20260520_181715` |
| Resultado defendible | `accuracy=0.9884`, `macro-F1=0.9878`, `macro-recall=0.9896`, `logloss=0.0753`, `ROC-AUC=0.9931`, `PR-AUC=0.9967`, `ECE=0.0187` |
| Segundo resultado util | IsolationForest `date` + `operational_no_label_proxy`: `ROC-AUC=0.9630`, `PR-AUC=0.9738`, `best-F1=0.9269` |
| Multiclass | HGB multiclass `date` + `operational_no_label_proxy`: `accuracy=0.9729`, `macro-F1=0.9152`, `macro-recall=0.8834` |
| Por que no usar `random` | En LAB-ALERTS puede dar resultados casi perfectos y no prueba generalizacion temporal. |
| Por que este perfil tiene sentido | Excluye 27 features que podian actuar como proxies directos de la etiqueta y conserva 16 features operacionales. |
| Lectura para el TFM | Es un dataset de laboratorio SIEM muy fuerte: el supervisado domina, pero IsolationForest queda como baseline de anomalia razonable. |

Conclusion LAB-ALERTS: elegir HGB binario `date/operational_no_label_proxy`. Es alto y defendible porque evita proxies directos y mantiene validacion temporal.

## COWRIE_FULL

| Decision | Resultado |
| --- | --- |
| Eleccion recomendada | **HGB multiclass en `date` con `operational_no_label_proxy`**. |
| Run representativo | `20260520_154325` / consolidado tambien como `20260520_182459` |
| Resultado defendible | `accuracy=0.9784`, `macro-F1=0.8713`, `macro-recall=0.8796`, `logloss=0.0525`, `ECE=0.0027` |
| Alternativa binaria | HGB binario `date` + `operational_no_label_proxy`: `accuracy=0.9474`, `macro-F1=0.7076`, `macro-recall=0.8860`, `ROC-AUC=0.9840`, `PR-AUC=0.8154` |
| Baseline anomaly | IsolationForest `date` + `operational_no_label_proxy`: `ROC-AUC=0.7586`, `PR-AUC=0.0734`, `best-F1=0.2368` |
| Por que multiclass | La utilidad principal de Cowrie no es solo ataque/no ataque, sino clasificar comportamiento honeypot: credenciales, login, comandos, transferencia, tunelizacion, etc. |
| Por que no elegir solo binario | El binario tiene buen ROC-AUC, pero su `macro-F1=0.7076` es mucho menor y puede generar demasiadas alertas si se usa directamente como detector. |
| Por que el perfil es defendible | `operational_no_label_proxy` excluye 30 features cercanas a la politica de etiquetado y conserva 27 features mas operacionales. |
| Lectura para el TFM | COWRIE_FULL aporta una linea complementaria de taxonomia de actividad ofensiva, no solo deteccion binaria. |

Conclusion COWRIE_FULL: elegir HGB multiclass `date/operational_no_label_proxy`. El binario queda como baseline de deteccion, y IsolationForest solo como senal auxiliar debil.

## CSR-LANL

| Decision | Resultado |
| --- | --- |
| Eleccion recomendada | **IsolationForest V3 para triage entity-day**. |
| Split/perfil | `datasets_redteam_identity_v3`, `redteam_stratified_groupkfold/fold_0`, lectura `entity_day` y exact coverage mediante politica entity-day. |
| Run representativo | `20260531_002323` |
| Resultado principal | Politica entity-day cubre **32/34** ventanas exactas red-team en entity-days seleccionados. |
| Resultado entity-day | Cubre **1,327/1,415** ventanas entity-day bajo la lectura operacional. |
| Cobertura de entidad | Selecciona **4/6** red-team entity-days en el fold V3, con unas 23 entity-days seleccionadas por dia. |
| Resultado exacto global anterior | Temporal/rarity HGB fold_0, run `20260527_151925`: primer ataque en rank **4**, top-100/top-500 **3/522**, top-500 entidades **4/5**. |
| Por que no usar accuracy | El desbalance es extremo; accuracy alta puede convivir con baja deteccion red-team. |
| Por que no elegir HGB multiclass V3 | En V3 no aporta valor operacional: top-k y politicas calibradas quedan en cero o muy por debajo. |
| Por que no elegir solo ranking exacto | El ranking exacto es util, pero el valor mas fuerte de CSR-LANL esta en priorizar entidades y entity-days investigables por un SOC. |
| Lectura para el TFM | CSR-LANL es la pieza de triage SOC bajo desbalance extremo, no un benchmark clasico de clasificacion fila a fila. |

Conclusion CSR-LANL: elegir IsolationForest V3 `redteam_stratified_groupkfold/fold_0` con lectura entity-day como resultado principal. Usar temporal/rarity HGB como resultado secundario para first-hit exacto.

## Decision Final Por Rol Del TFM

| Rol experimental | Dataset/modelo elegido | Resultado clave | Uso recomendado |
| --- | --- | --- | --- |
| Upper bound supervisado | CIC-IDS2017 MLP `random` | `macro-F1=0.9861`, `ROC-AUC=0.9995` | Mostrar capacidad maxima en split facil, con advertencia. |
| Generalizacion temporal CIC | CIC-IDS2017 GRU `day` | `macro-F1=0.7793`, `ROC-AUC=0.9908` | Resultado mas logico para defender CIC actualmente. |
| Benchmark tabular robusto | UNSW-NB15 HGB `groupkfold/fold_0` | `macro-F1=0.9658`, `ROC-AUC=0.9997` | Resultado principal UNSW. |
| Stress test de distribucion | UNSW-NB15 `official` | MLP `macro-F1=0.7117`; HGB cae hasta `0.2609-0.3579` | Mostrar limitacion y shift. |
| Drift temporal | UGR16 HGB `HYBRID/date` | `macro-F1=0.8956`, `ROC-AUC=0.9494` | Evidencia temporal mas fuerte. |
| SIEM lab defendible | LAB-ALERTS HGB `date/no_proxy` | `macro-F1=0.9878`, `PR-AUC=0.9967` | Validacion de pipeline SIEM en laboratorio. |
| Honeypot behavior taxonomy | COWRIE_FULL HGB multiclass `date/no_proxy` | `macro-F1=0.8713` | Clasificacion de comportamiento ofensivo. |
| SOC triage extremo | CSR-LANL IsolationForest V3 entity-day | `32/34` exact windows cubiertas, `1,327/1,415` entity-day windows | Priorizacion operacional bajo desbalance. |

## Conclusion General

- No usar `random` como resultado principal cuando existe una alternativa temporal, oficial, por grupo o entity-centric con soporte suficiente.
- Para CIC-IDS2017, el mejor numero es MLP random, pero la eleccion logica actual es reportar `day` como evidencia principal y `random` como upper bound.
- Para UNSW-NB15, `groupkfold/fold_0` conserva rendimiento alto y es mas defendible que `random`; `official` debe aparecer como stress test.
- Para LAB-ALERTS y COWRIE_FULL, el perfil `operational_no_label_proxy` debe ser el perfil principal aunque un perfil completo pudiera dar mejores resultados.
- Para CSR-LANL, la metrica correcta no es accuracy sino capacidad de priorizar entidades, entity-days y ventanas bajo presupuesto de alertas.
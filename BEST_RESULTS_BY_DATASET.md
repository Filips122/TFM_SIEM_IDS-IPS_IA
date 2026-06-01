# Best Results By Dataset

Fecha de consolidacion: 2026-06-01

Este documento resume el mejor resultado disponible por dataset usando una lectura breve tipo `Ranking / Resultado`. Para los datasets clasicos se priorizan metricas ML (`macro-F1`, `ROC-AUC`, `PR-AUC`, accuracy). Para CSR-LANL se priorizan metricas operacionales SOC, porque el desbalance extremo hace que accuracy sea una metrica secundaria.

Fuentes principales:

- `src/models/day20_comparison/20260520/top2_models.md`
- `RESULTS_CSR-LANL.md`
- resultados CSR-LANL V3 generados el 2026-05-31

## Resumen Ejecutivo

| Dataset | Mejor resultado actual | Lectura principal |
| --- | --- | --- |
| CIC-IDS2017 | MLP binario, `macro-F1=0.986120`, `ROC-AUC=0.999452` | Mejor benchmark supervisado sobre CIC. |
| UNSW-NB15 | HGB binario, `macro-F1=0.984123`, `ROC-AUC=0.999709` | Mejor benchmark supervisado sobre UNSW. |
| UGR16 | HGB binario sobre `UGR16_MARAPR_HYBRID`, `macro-F1=0.895648`, `ROC-AUC=0.949426` | Mejor validacion temporal/drift. |
| LAB-ALERTS | HGB binario, `macro-F1=0.987790`, `PR-AUC=0.996670` | Mejor dataset de laboratorio SIEM. |
| COWRIE_FULL | HGB multiclass, `macro-F1=0.871292` | Mejor clasificacion de actividad honeypot. |
| CSR-LANL | IsolationForest V3, `32/34` ventanas exactas cubiertas por politica entity-day | Mejor triage SOC por entidad/entity-day. |

## CIC-IDS2017

| Ranking | Resultado |
| --- | --- |
| Mejor modelo general | **MLP binario** |
| Mejor split | **random** |
| Run | `20260520_141225` |
| Mejor metrica principal | `macro-F1=0.986120` |
| Accuracy | `0.991164` |
| Macro recall | `0.990419` |
| ROC-AUC | `0.999452` |
| ECE | `0.793591` |
| Segundo mejor modelo | FTTransformer binario, run `20260520_141852`, `macro-F1=0.980912`, `ROC-AUC=0.999201` |
| Mejor lectura operacional | Clasificacion binaria supervisada muy fuerte; util como benchmark academico de alto rendimiento. |
| Modelo no prioritario | GRU secuencial en groupkfold no debe ser resultado principal con los resultados actuales (`macro-F1=0.431361`, `ROC-AUC=0.463119`). |
| Conclusion | CIC-IDS2017 esta fuerte como benchmark supervisado, pero conviene recordar que el split `random` suele ser mas optimista que una validacion temporal o por escenario. |

## UNSW-NB15

| Ranking | Resultado |
| --- | --- |
| Mejor modelo general | **HGB binario** |
| Mejor split | **random** |
| Run | `20260520_133434` |
| Mejor metrica principal | `macro-F1=0.984123` |
| Accuracy | `0.993037` |
| Macro recall | `0.982214` |
| ROC-AUC | `0.999709` |
| ECE | `0.866957` |
| Segundo mejor modelo | MLP binario, run `20260520_133515`, `macro-F1=0.983232`, `ROC-AUC=0.999675` |
| Mejor lectura operacional | HGB es ligeramente superior a MLP y queda como mejor modelo tabular para UNSW-NB15. |
| Modelo no prioritario | Multiclass HGB sobre split official no debe ser resultado principal con los resultados actuales (`macro-F1=0.140580`). |
| Conclusion | UNSW-NB15 queda como uno de los benchmarks supervisados mas fuertes del proyecto. |

## UGR16

| Ranking | Resultado |
| --- | --- |
| Mejor modelo general | **HGB binario** |
| Dataset interno | `UGR16_MARAPR_HYBRID` |
| Mejor split | **date** |
| Run | `20260520_151846` |
| Mejor metrica principal | `macro-F1=0.895648` |
| Accuracy | `0.895664` |
| Macro recall | `0.895664` |
| ROC-AUC | `0.949426` |
| ECE | `0.395916` |
| Segundo modelo | MLP binario, run `20260520_152058`, `macro-F1=0.684389`, `ROC-AUC=0.795907` |
| Mejor lectura operacional | Validacion temporal mas realista que los splits aleatorios; util para discutir drift y trafico longitudinal. |
| Modelo no prioritario | MLP binario queda claramente por debajo de HGB en esta configuracion. |
| Conclusion | UGR16 aporta la pieza de realismo temporal: resultados menos perfectos que CIC/UNSW, pero mas defendibles para comportamiento longitudinal. |

## LAB-ALERTS

| Ranking | Resultado |
| --- | --- |
| Mejor modelo general | **HGB binario** |
| Mejor split | **date** |
| Run | `20260520_181715` |
| Mejor metrica principal | `macro-F1=0.987790` |
| Accuracy | `0.988395` |
| Macro recall | `0.989626` |
| ROC-AUC | `0.993102` |
| PR-AUC | `0.996670` |
| ECE | `0.018668` |
| Mejor baseline no supervisado | IsolationForest, run `20260520_181722`, `ROC-AUC=0.963007`, `PR-AUC=0.973790`, `best-F1=0.926905` |
| Mejor lectura operacional | Dataset de laboratorio muy fuerte para demostrar la integracion SIEM/alertas y comparacion supervisado vs anomalia. |
| Modelo no prioritario | IsolationForest es bueno como baseline, pero HGB binario es el resultado principal. |
| Conclusion | LAB-ALERTS es una pieza fuerte para validar el pipeline en un entorno controlado y cercano a SIEM. |

## COWRIE_FULL

| Ranking | Resultado |
| --- | --- |
| Mejor modelo general | **HGB multiclass** |
| Mejor split | **date** |
| Run | `20260520_182459` |
| Mejor metrica principal | `macro-F1=0.871292` |
| Accuracy | `0.978423` |
| Macro recall | `0.879625` |
| ECE | `0.002658` |
| Segundo modelo | HGB binario, run `20260520_182453`, `macro-F1=0.707581`, `ROC-AUC=0.984001`, `PR-AUC=0.815428` |
| Mejor lectura operacional | El multiclass es mas util para describir tipos de actividad honeypot que una lectura binaria simple. |
| Modelo no prioritario | HGB binario no debe ser el resultado principal si el objetivo es caracterizar actividad; queda como baseline binario. |
| Conclusion | COWRIE_FULL es util como evidencia de clasificacion de telemetria honeypot y enriquecimiento de eventos ofensivos. |

## CSR-LANL

CSR-LANL se resume con metricas SOC, no con accuracy. El objetivo fuerte es priorizacion de entidades, entity-days y ventanas asociadas a actividad red-team bajo presupuestos de alerta.

| Ranking | Resultado |
| --- | --- |
| Mejor modelo V3 general | **IsolationForest V3** |
| Mejor split V3 | **redteam_stratified_groupkfold/fold_0** |
| Mejor lectura operacional | **entity_day** |
| Mejor resultado exacto por politica | IsolationForest fold exact: **32/34** ventanas exactas cubiertas en entity-days seleccionados |
| Mejor resultado entity-day | IsolationForest fold entity-day: **1,327/1,415** ventanas entity-day cubiertas |
| Mejor baseline interpretable | Hybrid score fold, pero queda por debajo de IsolationForest |
| Modelo descartable | HGB multiclass V3 |
| HGB binario V3 | Tiene algo de senal, pero no mejora lo suficiente |

### CSR-LANL Detalle V3

| Ranking | Resultado |
| --- | --- |
| Dataset V3 | `src/models/CSR-LANL/datasets_redteam_identity_v3` |
| Configuracion principal | `source_set=auth_flow`, `redteam_window_hours=1.0`, `redteam_window_limit=250`, `max_rows_per_source=8000000`, `max_windows=2000000` |
| Ventanas finales | `2,000,000` |
| Ventanas exactas red-team | `65` |
| Ventanas context-60m | `2,128` |
| Ventanas entity-day | `4,112` |
| Entidades red-team | `20` |
| Red-team entity-days | `23` |
| Mejor run IsolationForest date | `20260531_001734` |
| Mejor run IsolationForest fold_0 | `20260531_002323` |
| Mejor run HGB binario fold_0 | `20260531_000706` |
| Mejor run Hybrid fold_0 | `20260531_v3_hybrid_fold0_exact` / `20260531_v3_hybrid_fold0_entity_day` |

### CSR-LANL Comparacion Con Temporal/Rarity

| Ranking | Resultado |
| --- | --- |
| Mejor ranking exacto global anterior | Temporal/rarity HGB fold_0, run `20260527_151925`, primer ataque en rank **4**, top-500 **3/522** |
| V3 en ranking exacto global | No mejora temporal/rarity para exact windows; V3 es peor en first rank exacto global. |
| Mejora real de V3 | Mejora fuerte en triage por entidad/entity-day. |
| Resultado V3 mas defendible | IsolationForest V3 fold_0 cubre **32/34** ventanas exactas mediante politica entity-day con unas 23 entity-days seleccionadas por dia. |
| Conclusion CSR-LANL | CSR-LANL debe presentarse como dataset de priorizacion SOC bajo desbalance extremo, no como benchmark clasico de accuracy. |

## Ranking Final Por Rol Experimental

| Rol | Mejor dataset/modelo | Resultado |
| --- | --- | --- |
| Mejor clasificacion supervisada global | CIC-IDS2017 / MLP binario | `macro-F1=0.986120`, `ROC-AUC=0.999452` |
| Mejor tabular supervisado robusto | UNSW-NB15 / HGB binario | `macro-F1=0.984123`, `ROC-AUC=0.999709` |
| Mejor validacion temporal/drift | UGR16 / HGB binario | `macro-F1=0.895648`, `ROC-AUC=0.949426` |
| Mejor laboratorio SIEM | LAB-ALERTS / HGB binario | `macro-F1=0.987790`, `PR-AUC=0.996670` |
| Mejor honeypot multiclass | COWRIE_FULL / HGB multiclass | `macro-F1=0.871292` |
| Mejor triage SOC entity-centric | CSR-LANL / IsolationForest V3 | `32/34` exact windows y `1,327/1,415` entity-day windows cubiertas por politica entity-day |

## Conclusiones

- CIC-IDS2017, UNSW-NB15 y LAB-ALERTS demuestran rendimiento alto en clasificacion supervisada.
- UGR16 aporta una lectura mas temporal y realista, con resultados solidos pero menos perfectos.
- COWRIE_FULL aporta una linea diferenciada de clasificacion de actividad honeypot.
- CSR-LANL aporta la evidencia mas SOC-realista: no gana por accuracy, sino por priorizacion de entidades bajo desbalance extremo.
- Para el TFM, la lectura mas defendible es combinar resultados ML clasicos con metricas operacionales: precision/recall/F1/ROC-AUC donde proceda, y first-rank/entity-day/alert budget en CSR-LANL.
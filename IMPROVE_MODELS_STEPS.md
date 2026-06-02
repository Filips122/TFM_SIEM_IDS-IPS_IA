# Improve Models Steps

Fecha de consolidacion: 2026-06-01

Este documento resume la estrategia acordada para mejorar los modelos actuales de cada dataset. El objetivo no es aumentar complejidad por defecto, sino mejorar resultados bajo splits defendibles, controlar overfitting y producir evidencia solida para el TFM.

## Principio General

La mejora debe hacerse con experimentos controlados:

- elegir splits realistas antes de optimizar,
- seleccionar modelos por validacion, no por test,
- guardar configuracion completa de cada run,
- comparar contra el baseline actual,
- evitar elegir por `accuracy` cuando hay desbalance,
- priorizar `macro-F1`, `macro-recall`, `ROC-AUC`, `PR-AUC`, calibracion y metricas operacionales,
- mantener `random` como upper bound cuando exista una alternativa temporal, oficial, por grupo o entity-centric.

La idea no es simplemente hacer redes mas grandes. Primero se deben explotar bien los modelos tabulares robustos, despues probar redes neuronales con regularizacion, y finalmente ajustar umbrales/calibracion y metricas operacionales.

## Estado Actual Resumido

| Dataset | Mejor lectura actual | Problema principal | Direccion de mejora |
| --- | --- | --- | --- |
| CIC-IDS2017 | MLP `random` como upper bound; GRU `day` como evidencia mas defendible actual | `random` es optimista y `groupkfold` cae mucho | Mejorar `day/groupkfold`, especialmente HGB/MLP/GRU regularizados |
| UNSW-NB15 | HGB `groupkfold/fold_0`; `official` como stress test | `official` cae por shift o preparacion distinta | Mejorar robustez en `groupkfold` y diagnosticar `official` |
| UGR16 | HGB `UGR16_MARAPR_HYBRID/date` | MLP inferior; anomaly global debil | Tuning HGB y features temporales/anomaly por entidad |
| LAB-ALERTS | HGB `date/operational_no_label_proxy` | Evitar leakage y no vender resultados casi perfectos | Mantener perfil sin proxies y validar multiclass/anomaly |
| COWRIE_FULL | HGB multiclass `date/operational_no_label_proxy` | Binario tiene precision baja; anomaly debil | Mejorar multiclass y clases minoritarias |
| CSR-LANL | IsolationForest V3 entity-day | No es problema de accuracy; es triage SOC | Mejorar entity-day policy, IsolationForest y hybrid score |

## Fase 0 - Higiene Experimental

Antes de lanzar nuevos entrenamientos:

1. Confirmar que los splits usados son los defendibles.
2. Separar resultados `random` de resultados realistas.
3. Guardar `run_config` con hiperparametros completos.
4. Guardar `dataset_profile_ref` cuando exista.
5. Comparar cada run contra el baseline actual del mismo split y perfil.
6. Seleccionar por validacion.
7. Reportar test solo como evaluacion final.

Splits/perfiles prioritarios:

| Dataset | Split/perfil principal |
| --- | --- |
| CIC-IDS2017 | `day`, despues `groupkfold` |
| UNSW-NB15 | `groupkfold/fold_0`; `official` como stress test |
| UGR16 | `UGR16_MARAPR_HYBRID/date` |
| LAB-ALERTS | `date/operational_no_label_proxy` |
| COWRIE_FULL | `date/operational_no_label_proxy` |
| CSR-LANL | `datasets_redteam_identity_v3`, `redteam_stratified_groupkfold/fold_0`, `entity_day/exact` |

## Fase 1 - Tuning HGB Como Prioridad

HGB es el baseline tabular mas fuerte y barato en varios datasets. Antes de aumentar redes neuronales, conviene hacer tuning controlado de HGB.

### Parametros HGB a exponer o variar

| Parametro | Valores recomendados |
| --- | --- |
| `learning_rate` | `0.03`, `0.05`, `0.08`, `0.10` |
| `max_iter` / `epochs` | `200`, `400`, `700` con early stopping |
| `max_depth` | `2`, `3`, `4`, `6` |
| `l2_regularization` | `0.0`, `0.01`, `0.1`, `1.0` |
| `min_samples_leaf` | `20`, `50`, `100`, `200` |
| `max_leaf_nodes` | `15`, `31`, `63` |
| `validation_fraction` | `0.10`, `0.15`, `0.20` |

### Perfiles HGB recomendados

| Perfil | `learning_rate` | `max_iter` | `max_depth` | `l2_regularization` | `min_samples_leaf` | Uso |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Baseline actual equivalente | `0.08-0.10` | `215-265` | `3-4` | `0.0` | default | Comparacion directa |
| Conservative | `0.05` | `400` | `2` | `0.1` | `100` | Reducir overfitting |
| Balanced | `0.05` | `500` | `3` | `0.1` | `50` | Primer candidato serio |
| Expressive regularized | `0.03` | `700` | `4` | `0.1` | `50` | Mas capacidad con learning rate bajo |
| High regularization | `0.03` | `700` | `3` | `1.0` | `100` | Si train sube mucho y val cae |

### Criterio de seleccion HGB

| Tipo de tarea | Metrica principal |
| --- | --- |
| Binario balanceado | `val_macro_f1`, `val_macro_recall`, `val_roc_auc` |
| Binario desbalanceado | `val_pr_auc`, F1 por threshold, recall bajo presupuesto |
| Multiclass | `val_macro_f1`, recall por clase, matriz de confusion |
| CSR-LANL | recall entity-day, exact windows cubiertas, entity-days/dia |

## Fase 2 - Tuning De Redes Neuronales

Las redes actuales ya tienen `dropout`, `weight_decay`, `early stopping`, `patience` y `grad_clip_norm`. Por tanto, aumentar capas solo tiene sentido con regularizacion y validacion robusta.

### Perfiles MLP recomendados

| Perfil | `hidden` | `depth` | `dropout` | `weight_decay` | `epochs` | `patience` | Uso |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Small robust | 256 | 2 | 0.25 | `1e-4` | 80 | 10 | Baseline regularizado |
| Current+ | 512 | 3 | 0.25 | `1e-4` | 100 | 12 | Variante cercana actual |
| Deep regularized | 512 | 4 | 0.30 | `3e-4` | 120 | 12 | Mas capas con control |
| Wide cautious | 768 | 3 | 0.35 | `5e-4` | 120 | 12 | Mas capacidad, mas regularizacion |

Recomendaciones:

- no aumentar `epochs` sin early stopping,
- usar `min_delta=1e-4`,
- mantener `grad_clip_norm=1.0`,
- revisar gap train/val,
- si train mejora y val empeora, subir `dropout` y `weight_decay` o reducir `depth`.

### Perfiles GRU/LSTM recomendados

Aplicar principalmente a CIC-IDS2017, donde existe pipeline secuencial.

| Parametro | Valores recomendados |
| --- | --- |
| Ventana temporal | `10`, `20`, `40` |
| `hidden` | `128`, `192`, `256` |
| `n_layers` | `1`, `2`, `3` |
| `dropout` | `0.15`, `0.25`, `0.35` |
| `bidirectional` | `false`, `true` |
| `epochs` | `80`, `120` con early stopping |

Recomendacion clave:

> En secuenciales, muchas veces mejora mas una ventana temporal adecuada que una red mas profunda.

### FTTransformer

Aplicar con cuidado, principalmente en CIC-IDS2017.

| Parametro | Valores recomendados |
| --- | --- |
| `d_model` | `64`, `128` |
| `n_layers` | `2`, `4` |
| `n_heads` | `4`, `8` |
| `dropout` | `0.10`, `0.20`, `0.30` |

Si aparece overfitting:

- bajar `d_model`,
- bajar `n_layers`,
- subir `dropout`,
- aumentar `weight_decay`,
- seleccionar por `val_loss` o `val_macro_f1`, no por train.

## Fase 3 - Thresholds Y Calibracion

Para modelos binarios, la probabilidad cruda no siempre es suficiente. Varios resultados tienen ECE alto, por lo que conviene calibrar o seleccionar umbrales en validacion.

Acciones:

1. Guardar curvas PR/ROC por validacion y test.
2. Elegir threshold en validacion por:
   - mejor F1,
   - recall minimo,
   - precision minima,
   - presupuesto de alertas,
   - FPR maximo permitido.
3. Aplicar el threshold elegido al test sin reajustarlo.
4. Probar calibracion Platt o isotonic cuando ECE sea alto.
5. Reportar metricas con threshold operativo, no solo AUC.

Metricas recomendadas:

| Contexto | Metricas |
| --- | --- |
| Clasificacion binaria | macro-F1, macro-recall, ROC-AUC, PR-AUC, ECE, matriz de confusion |
| Multiclass | macro-F1, macro-recall, soporte por clase, confusion matrix |
| Anomaly | PR-AUC, best-F1, precision@k, recall@k, FPR@budget |
| SOC | alertas/dia, entity-days/dia, cobertura de entidades, cobertura de ventanas |

## Fase 4 - Estrategia Por Dataset

## CIC-IDS2017

Objetivo:

- mejorar generalizacion en `day` y `groupkfold`, no solo subir `random`.

Acciones:

1. Ejecutar HGB tuning en `day`.
2. Probar MLP regularizada en `day`.
3. Probar GRU/LSTM con ventanas `10`, `20`, `40`.
4. Probar FTTransformer reducido y regularizado.
5. Confirmar que `groupkfold` no colapsa.

Experimentos prioritarios:

| Experimento | Configuracion |
| --- | --- |
| HGB conservative | `learning_rate=0.05`, `max_depth=2`, `l2=0.1`, `min_samples_leaf=100`, `max_iter=400` |
| HGB balanced | `learning_rate=0.05`, `max_depth=3`, `l2=0.1`, `min_samples_leaf=50`, `max_iter=500` |
| MLP regularized | `hidden=512`, `depth=3`, `dropout=0.30`, `weight_decay=3e-4`, `epochs=100`, `patience=12` |
| GRU window search | ventanas `10/20/40`, `hidden=128/256`, `dropout=0.25` |

Criterio de aceptacion:

- mejorar `day macro-F1` sin empeorar mucho `ROC-AUC`,
- reducir gap train/val,
- no presentar `random` como resultado final sin advertencia.

## UNSW-NB15

Objetivo:

- mantener buen rendimiento en `groupkfold/fold_0`, mejorar robustez y diagnosticar `official`.

Acciones:

1. HGB tuning sobre `groupkfold/fold_0`.
2. Repetir las mejores configuraciones en `official`.
3. MLP moderada y regularizada.
4. Analizar caida en `official` con confusion matrix y soporte por clase.
5. No priorizar multiclass hasta revisar clases raras.

Experimentos prioritarios:

| Experimento | Configuracion |
| --- | --- |
| HGB robust group | `learning_rate=0.05`, `max_depth=3`, `l2=0.1`, `min_samples_leaf=50`, `max_iter=500` |
| HGB official conservative | `learning_rate=0.03`, `max_depth=2`, `l2=1.0`, `min_samples_leaf=100`, `max_iter=700` |
| MLP moderate | `hidden=256/512`, `depth=2/3`, `dropout=0.25/0.35`, `weight_decay=3e-4` |

Criterio de aceptacion:

- conservar `groupkfold macro-F1 > 0.95`,
- mejorar `official` sin sobreajustar,
- reportar `official` como stress test aunque siga siendo inferior.

## UGR16

Objetivo:

- mejorar el baseline temporal/drift y reformular anomaly.

Acciones:

1. HGB tuning sobre `UGR16_MARAPR_HYBRID/date`.
2. Probar MLP mas pequena y regularizada.
3. No insistir en IsolationForest global sobre filas sueltas.
4. Crear o mejorar features temporales/anomaly por entidad, destino, puerto y protocolo.
5. Evaluar estabilidad temporal.

Experimentos prioritarios:

| Experimento | Configuracion |
| --- | --- |
| HGB temporal balanced | `learning_rate=0.05`, `max_depth=3`, `l2=0.1`, `min_samples_leaf=50`, `max_iter=500` |
| HGB temporal conservative | `learning_rate=0.03`, `max_depth=2`, `l2=0.1`, `min_samples_leaf=100`, `max_iter=700` |
| MLP small robust | `hidden=256`, `depth=2`, `dropout=0.35`, `weight_decay=5e-4`, `epochs=100` |
| Anomaly entity/window | rolling baselines, rareza de destino/puerto/protocolo, PR-AUC y alertas/dia |

Criterio de aceptacion:

- mejorar o mantener `macro-F1` alrededor de `0.8956`,
- no sacrificar `ROC-AUC` temporal,
- anomaly solo se considera mejora si sube PR-AUC y reduce alertas inutiles.

## LAB-ALERTS

Objetivo:

- mantener resultado alto sin proxies directos y validar robustez.

Acciones:

1. Mantener `operational_no_label_proxy` como perfil principal.
2. HGB tuning con menor complejidad para comprobar estabilidad.
3. Revisar multiclass por clase, especialmente clases debiles.
4. Probar IsolationForest con `contamination` explicito.
5. Reportar `random` solo como sanity check si se usa.

Experimentos prioritarios:

| Experimento | Configuracion |
| --- | --- |
| HGB simple | `learning_rate=0.05`, `max_depth=2`, `l2=0.1`, `min_samples_leaf=100`, `max_iter=400` |
| HGB balanced | `learning_rate=0.05`, `max_depth=3`, `l2=0.1`, `min_samples_leaf=50`, `max_iter=500` |
| Multiclass class audit | confusion matrix, recall por clase, soporte por clase |
| IsoForest contamination | `contamination=0.01/0.03/0.05`, `n_estimators=300/500` |

Criterio de aceptacion:

- mantener rendimiento alto en `date/no_proxy`,
- evitar features proxy,
- justificar el modelo por estabilidad y no por metricas casi perfectas.

## COWRIE_FULL

Objetivo:

- mejorar multiclass operacional y clases minoritarias.

Acciones:

1. Mantener `operational_no_label_proxy`.
2. Tuning HGB multiclass.
3. Revisar clases confundidas y soporte temporal.
4. Binario queda como baseline, no resultado principal.
5. No priorizar IsolationForest salvo como senal auxiliar.

Experimentos prioritarios:

| Experimento | Configuracion |
| --- | --- |
| Multiclass HGB balanced | `learning_rate=0.05`, `max_depth=4`, `l2=0.1`, `min_samples_leaf=50`, `max_iter=500` |
| Multiclass HGB conservative | `learning_rate=0.03`, `max_depth=3`, `l2=0.1`, `min_samples_leaf=100`, `max_iter=700` |
| Binary threshold tuning | elegir threshold por PR-AUC/precision minima, no solo ROC-AUC |
| Class audit | confusion matrix, recall por `LoginSuccess`, `CredentialAttack` y clases minoritarias |

Criterio de aceptacion:

- mejorar `macro-F1 multiclass`,
- mejorar recall de clases minoritarias,
- no reintroducir features proxy.

## CSR-LANL

Objetivo:

- mejorar triage SOC, no accuracy.

Acciones:

1. Mantener IsolationForest V3 como candidato principal.
2. Tuning de IsolationForest sobre entity-day/exact coverage.
3. Tuning del `score_hybrid_v3` con pesos aprendidos o grid de pesos en validacion.
4. Probar ensemble de score: IsolationForest + hybrid score.
5. Evaluar siempre con metricas operacionales.

Parametros IsolationForest recomendados:

| Parametro | Valores |
| --- | --- |
| `n_estimators` | `300`, `500`, `800` |
| `max_samples` | `256`, `1024`, `4096` |
| `contamination` | `auto`, `0.001`, `0.005`, `0.01` |
| feature set | V3 full, V3 selected, V3 identity-only, V3 temporal-only |

Experimentos prioritarios:

| Experimento | Configuracion |
| --- | --- |
| IsoForest V3 stronger | `n_estimators=500`, `max_samples=1024`, `contamination=auto` |
| IsoForest low contamination | `n_estimators=800`, `max_samples=4096`, `contamination=0.005` |
| Hybrid weights grid | variar pesos de novelty, auth failure, lateral pressure y fanout |
| Score ensemble | `0.6 * IsoForest + 0.4 * hybrid_score`, calibrado en validacion |

Metricas de seleccion:

- `entity_policy_daily_25_window_recall`,
- ventanas exactas cubiertas,
- red-team entity-day recall,
- selected entity-days/day,
- first-hit rank,
- alertas/dia.

Criterio de aceptacion:

- mantener o superar **32/34** ventanas exactas cubiertas,
- reducir entity-days seleccionadas por dia si es posible,
- no elegir por accuracy,
- descartar HGB multiclass V3 salvo que cambie drasticamente.

## Fase 5 - Runners De Tuning

Conviene crear scripts nuevos, no modificar los runners actuales de referencia.

Propuesta de archivos:

| Archivo | Proposito |
| --- | --- |
| `src/scripts/tune_cic_models.ps1` | HGB/MLP/GRU/FTTransformer en `day/groupkfold` |
| `src/scripts/tune_unsw_models.ps1` | HGB/MLP en `groupkfold` y `official` |
| `src/scripts/tune_ugr_models.ps1` | HGB/MLP y anomaly temporal en `UGR16_MARAPR_HYBRID/date` |
| `src/scripts/tune_lab_alerts_models.ps1` | HGB/IsoForest con `operational_no_label_proxy` |
| `src/scripts/tune_cowrie_full_models.ps1` | HGB multiclass y audit de clases |
| `src/scripts/tune_csr_lanl_v3_models.ps1` | IsoForest V3, hybrid score y ensembles |

Cada runner deberia:

1. ejecutar un grid pequeno,
2. limitar recursos cuando sea necesario,
3. guardar logs por configuracion,
4. generar `tuning_results.csv`,
5. generar `tuning_summary.md`,
6. marcar el mejor por validacion,
7. comparar contra el baseline actual.

## Fase 6 - Documentacion De Resultados

Cada dataset deberia tener un resumen de tuning:

```text
src/models/<DATASET>/artifacts/tuning/<date>/tuning_results.csv
src/models/<DATASET>/artifacts/tuning/<date>/tuning_summary.md
```

Campos minimos:

| Campo | Descripcion |
| --- | --- |
| dataset | Nombre del dataset |
| split_mode | Split usado |
| fold | Fold si aplica |
| model | Modelo entrenado |
| run_id | Identificador del artefacto |
| params | Hiperparametros principales |
| val_metric | Metrica de seleccion |
| val_score | Resultado en validacion |
| test_score | Resultado en test |
| overfit_gap | Diferencia train/val relevante |
| warning | Avisos: collapse, weak PR-AUC, high ECE, leakage risk |

## Orden Recomendado De Implementacion

1. Exponer hiperparametros HGB por CLI donde estan fijos.
2. Crear runner de tuning HGB para LAB-ALERTS y COWRIE_FULL, porque son rapidos y ya tienen perfiles no-proxy.
3. Crear runner HGB para UGR16 `HYBRID/date`.
4. Crear runner HGB/MLP para UNSW `groupkfold/fold_0` y `official`.
5. Crear runner CIC para `day` con HGB/MLP/GRU.
6. Crear runner CSR-LANL V3 para IsolationForest/hybrid/ensemble.
7. Generar `tuning_summary.md` por dataset.
8. Actualizar `BEST_CHOICE_BY_DATASET.md` si algun resultado mejora de forma defendible.

## Que No Conviene Hacer

- No aumentar capas de redes sin regularizacion ni validacion robusta.
- No elegir configuraciones por test.
- No usar `random` como resultado principal si existe split mas realista.
- No optimizar CSR-LANL por accuracy.
- No presentar LAB/COWRIE con features proxy como resultado principal.
- No insistir en IsolationForest global cuando PR-AUC es muy baja, salvo que se reformule por entidad/ventana.
- No entrenar grids enormes que consuman RAM/tiempo sin aportar trazabilidad.

## Resultado Esperado

Al final de esta fase deberiamos tener:

- mejores modelos o, al menos, modelos igual de buenos pero mas defendibles,
- comparativas por validacion y test,
- evidencia de control de overfitting,
- umbrales/calibracion para binarios,
- metricas SOC para CSR-LANL,
- documentos de tuning reutilizables en la memoria del TFM.

La frase objetivo para la memoria seria:

> Los modelos finales no se seleccionaron por el mejor resultado aislado en test, sino mediante una busqueda controlada de hiperparametros sobre splits realistas, usando validacion para elegir configuraciones, regularizacion para limitar overfitting y metricas operacionales cuando la tarea lo requeria.
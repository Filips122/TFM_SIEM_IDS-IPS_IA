# NEXT STEPS

Este documento resume el analisis de resultados actual y convierte las conclusiones en una hoja de ruta de implementacion. El objetivo no es maximizar `accuracy` de forma aislada, sino obtener resultados defendibles para una tesis: buena deteccion de clases minoritarias, baja tasa de falsos positivos, trazabilidad de datasets/modelos y generalizacion en splits realistas.

## Conclusion general

El pipeline ya funciona de extremo a extremo: prepara datasets, entrena varios modelos, genera metricas, guarda artefactos y permite comparar resultados. Sin embargo, los resultados muestran tres situaciones distintas:

1. Resultados robustos o prometedores, especialmente en UNSW-NB15 binario y UGR16 supervisado temporal.
2. Resultados tecnicamente altos pero potencialmente optimistas, especialmente en LAB-ALERTS, COWRIE_FULL y CIC-IDS2017 con split `random`.
3. Resultados enganhosos por desbalance severo, especialmente CSR-LANL, donde la `accuracy` es casi perfecta pero `macro_f1`, `macro_recall` y PR-AUC indican deteccion debil.

Por tanto, la metrica principal de decision debe ser:

- Clasificacion: `macro_f1`, `macro_recall`, recall por clase, matriz de confusion, logloss/calibracion y PR-AUC/ROC-AUC cuando aplique.
- Anomalia: PR-AUC, `best_f1`, recall a bajo FPR, precision@k y alertas por ventana/dia.
- Operacional: volumen de alertas, duplicados, latencia esperada y capacidad de priorizacion.

La `accuracy` queda como metrica secundaria porque puede ocultar colapso a clase mayoritaria.

## Lectura por dataset

### UNSW-NB15

Estado actual:

- Binario HGB en `groupkfold` es uno de los resultados mas fuertes: `macro_f1` y `macro_recall` cercanos a 0.98.
- Isolation Forest tiene senhal util en `official/random`, con PR-AUC alta en comparacion con otros datasets.
- Multiclass es el punto debil: en `official` cae mucho y en `random/groupkfold` hay alta variabilidad.

Conclusion:

- Mantener binario como baseline principal.
- Tratar `official` como evaluacion benchmark realista aunque sea peor.
- Mejorar multiclass con analisis por clase, manejo de clases raras y posible clasificacion jerarquica: primero benigno/ataque, despues familia de ataque.

### CIC-IDS2017

Estado actual:

- `random` da resultados muy altos en modelos tabulares y neuronales.
- `day` baja de forma notable, pero todavia aporta informacion util.
- `groupkfold` expone sobreajuste, colapso de clase mayoritaria y baja generalizacion en algunos modelos, especialmente secuenciales.

Conclusion:

- Usar `random` solo como baseline optimista.
- Usar `day` y `groupkfold` como evidencia principal de generalizacion.
- No defender GRU/FT-Transformer como modelo final salvo que superen de forma estable a HGB/logreg en splits robustos.

### CSR-LANL

Estado actual:

- Accuracy cercana a 0.999, pero `macro_f1` alrededor de 0.5 en binario y peor en multiclass.
- PR-AUC de anomaly extremadamente baja.
- Hay senhales de colapso por clase mayoritaria y de que los positivos red-team son demasiado escasos para evaluar fila a fila.

Conclusion:

- CSR-LANL no debe evaluarse principalmente por accuracy.
- Debe reformularse como deteccion por entidad/ventana y scoring de riesgo.
- Se necesitan sampling centrado en red-team, thresholds calibrados y metricas operacionales: recall red-team, precision@k y alertas por dia.

### UGR16

Estado actual:

- HGB binario temporal sobre `UGR16_MARAPR_HYBRID` es solido: `macro_f1` alrededor de 0.89 y ROC-AUC alrededor de 0.94.
- MLP es claramente inferior.
- Isolation Forest global tiene PR-AUC baja y no captura bien el comportamiento temporal.

Conclusion:

- Mantener HGB binario temporal como baseline defendible.
- Rehacer anomaly con ventanas, baseline benigno, drift y rareza por entidad/destino/puerto.
- Evaluar con PR-AUC, FPR por presupuesto de alertas y estabilidad temporal.

### LAB-ALERTS

Estado actual:

- `random` llega a metricas perfectas o casi perfectas.
- `date` es mas realista y sigue siendo fuerte.
- `groupkfold` es fragil por tamanhos de validacion muy pequenhos y resultados inconsistentes.

Conclusion:

- El resultado `random` debe tratarse como sanity check, no como prueba de generalizacion.
- La prioridad es crear perfiles de features sin proxies directos de la etiqueta.
- El resultado defendible debe salir de `date` o de un split por escenario/entidad con suficiente soporte.

### COWRIE_FULL

Estado actual:

- Multiclass HGB en `date` es extremadamente fuerte.
- Binario HGB es bastante mas debil que multiclass.
- Isolation Forest aporta poca senhal comparado con supervised.

Conclusion:

- Auditar leakage antes de defender las metricas casi perfectas.
- Crear perfiles de features que separen el experimento completo de un perfil operacional sin proxies directos de etiqueta.
- Reportar el perfil completo como upper bound/sanity check si usa features muy cercanas a la regla de etiquetado.

## Prioridades de implementacion

### P0 - Comparativas defendibles

- Separar resultados `light/smoke` de resultados `full`.
- Marcar `random` como baseline optimista cuando exista `date`, `groupkfold` u `official`.
- Priorizar ranking por `macro_f1`, `macro_recall`, PR-AUC y avisos de colapso.

### P1 - Feature profiles anti-leakage para LAB-ALERTS y COWRIE_FULL

Implementar perfiles:

- `full`: usa todas las features actualmente disponibles.
- `operational_no_label_proxy`: excluye columnas que sean proxies directos o casi directos de la etiqueta.
- Opcional: `numeric_only`: baseline conservador para comprobar si la senhal se mantiene sin categoricas/textuales.

Cada dataset preparado debe guardar en metadata:

- `feature_profile`.
- Columnas incluidas y excluidas.
- Motivo de exclusion de columnas proxy.
- Conteos por split y por clase.

### P2 - CSR-LANL como scoring por entidad/ventana

- Mantener dataset red-team centrado en ventanas.
- Crear metricas especificas de red-team: recall por evento, precision@k, alertas por dia, top entidades sospechosas.
- Ajustar thresholds por validacion, no por test.
- Evitar conclusiones basadas en accuracy global.

### P3 - CIC-IDS2017 robusto por split

- Reportar `random` como baseline optimista.
- Priorizar `day` y `groupkfold`.
- Revisar sobreajuste en GRU/MLP con early stopping real por `macro_f1_val`, menor capacidad y class weights.
- Comparar siempre contra HGB/logreg.

### P4 - UGR16 anomaly temporal

- Sustituir Isolation Forest fila a fila por features rolling y ventanas por entidad.
- Usar baseline benigno y drift-aware thresholds.
- Medir alertas por dia y FPR operativo.

### P5 - UNSW-NB15 multiclass

- Revisar clases minoritarias y matriz de confusion.
- Probar agrupacion de clases raras o enfoque jerarquico.
- Mantener binario como baseline fuerte y multiclass como extension.

## Orden recomendado de trabajo

1. Implementar `feature_profile` en LAB-ALERTS y COWRIE_FULL.
2. Regenerar esos datasets con `full` y `operational_no_label_proxy`.
3. Reentrenar solo LAB-ALERTS y COWRIE_FULL para medir caida real al eliminar proxies.
4. Implementar metricas operacionales para CSR-LANL.
5. Reentrenar CSR-LANL con foco en recall red-team y precision@k.
6. Reentrenar CIC en `day/groupkfold` y comparar modelos tabulares vs secuenciales.
7. Rehacer anomaly en UGR16 con ventanas temporales.

## Criterios de aceptacion

Un resultado se considera defendible si cumple:

- Tiene `dataset_profile.json` o metadata equivalente.
- Indica split, dataset version y `feature_profile`.
- Cada split tiene soporte suficiente de positivos y clases minoritarias.
- No se basa exclusivamente en `accuracy`.
- Incluye matriz de confusion o recall por clase para clasificacion.
- Incluye PR-AUC, threshold y presupuesto de alertas para anomaly/scoring.
- Si el resultado es casi perfecto, se justifica como caso realista, sanity check o upper bound.

## Primer bloque a implementar

El primer cambio tecnico sera implementar `feature_profile` en LAB-ALERTS y COWRIE_FULL. Es el paso con mayor impacto inmediato porque permite distinguir entre:

- rendimiento realista con features operacionales,
- rendimiento inflado por proxies de etiqueta,
- y upper bound util solo como control experimental.

## Resultado inicial con `operational_no_label_proxy`

Ejecucion: 2026-05-20.

Configuracion:

- LAB-ALERTS y COWRIE_FULL regenerados en split `date` con `feature_profile=operational_no_label_proxy`.
- Entrenamiento ligero: `BinaryEpochs=75`, `MulticlassEpochs=75`, `AnomalyEstimators=100`, `SampleFrac=0.35` para HGB supervisado.
- LAB-ALERTS paso de 43 a 16 features.
- COWRIE_FULL paso de 57 a 27 features.

Resultados nuevos principales:

| Dataset | Modelo | Split | Perfil | Accuracy | Macro-F1 | Macro-Recall | ROC-AUC | PR-AUC | Comentario |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| LAB-ALERTS | Binary HGB | date | operational_no_label_proxy | 0.9669 | 0.9645 | 0.9675 | 0.9887 | 0.9940 | Sigue siendo fuerte sin proxies directos. |
| LAB-ALERTS | Multiclass HGB | date | operational_no_label_proxy | 0.9669 | 0.8864 | 0.8578 |  |  | Baja razonable; `OtherAlert` queda como clase debil. |
| LAB-ALERTS | Isolation Forest | date | operational_no_label_proxy |  |  |  | 0.9686 | 0.9795 | Mantiene senhal alta, pero debe validarse con presupuesto de alertas. |
| COWRIE_FULL | Binary HGB | date | operational_no_label_proxy | 0.8989 | 0.6058 | 0.8194 | 0.9573 | 0.6396 | Detecta muchos ataques, pero con precision baja en ATTACK. |
| COWRIE_FULL | Multiclass HGB | date | operational_no_label_proxy | 0.9768 | 0.8387 | 0.8609 |  |  | Resultado defendible, con clases minoritarias debiles. |
| COWRIE_FULL | Isolation Forest | date | operational_no_label_proxy |  |  |  | 0.7308 | 0.0880 | Senhal muy debil como detector global de anomalias. |

Lectura inmediata:

- LAB-ALERTS conserva rendimiento alto aun sin proxies directos. El siguiente analisis debe centrarse en soporte por clase y en validar si `date` representa escenarios suficientemente distintos.
- COWRIE_FULL confirma que las metricas casi perfectas anteriores dependian de features demasiado cercanas a la etiqueta. El perfil operacional produce un resultado mucho mas realista y defendible.
- En COWRIE_FULL binario, ATTACK tiene recall alto (`0.7357`) pero precision baja (`0.1623`), por lo que el modelo generaria demasiadas alertas si se usa directamente como detector.
- En COWRIE_FULL multiclass, `LoginSuccess` y `CredentialAttack` son los puntos principales de confusion; deben revisarse con matriz de confusion y soporte temporal.
- Isolation Forest en COWRIE_FULL no es suficiente como detector principal bajo este perfil; puede quedar como senhal auxiliar de riesgo, no como modelo final.

Siguiente ajuste recomendado:

1. Separar comparativas por `feature_profile` para que `compare_models.py` no mezcle runs `full`, light y operacionales en la misma tabla agregada.
2. Anhadir en el ranking una columna visible de `feature_profile` y, si existe, `sample_frac`/modo ligero.
3. Repetir COWRIE_FULL operational con entrenamiento completo o una fraccion mayor para comprobar si mejora precision de ATTACK sin perder recall.
4. Evaluar threshold operacional en COWRIE_FULL binario con precision/recall, alertas por ventana y precision@k.
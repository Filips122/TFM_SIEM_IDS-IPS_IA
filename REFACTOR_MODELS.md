# REFACTOR MODELS

Este documento convierte el analisis de resultados en una hoja de ruta ejecutable. El objetivo no es entrenar modelos mas complejos por defecto, sino hacer que los experimentos sean mas defendibles: splits consistentes, menos leakage, mejores metricas y artefactos comparables.

## Estado inicial observado

- CIC-IDS2017 funciona muy bien en `random`, pero cae en `groupkfold`; debe tratarse como evidencia de sensibilidad al split.
- UNSW-NB15 necesita saneamiento antes de usar resultados finales; hay senales de mezcla entre datasets/artefactos y el split `official` generaliza mal.
- UGR16 es el baseline temporal mas fuerte; HGB binario funciona, IsolationForest global no aporta suficiente senal.
- LAB-ALERTS y COWRIE_FULL tienen resultados supervisados casi perfectos porque las etiquetas se derivan de reglas/eventos muy cercanos a las features.
- CSR-LANL tiene un subsample demasiado pobre en ataques; accuracy alta y macro-F1 baja indican colapso por clase mayoritaria.

## Fase 0 - Higiene de artefactos y comparativas

Estado: en progreso.

Cambios:
- Guardar metadata minima en cada nuevo run (`run_metadata.json`): modelo, split, dataset cuando aplique, timestamp y raiz del artefacto.
- Cambiar el ranking de `compare_models.py` para que no priorice accuracy cuando hay desbalance fuerte.
- Incluir avisos en comparativas para detectar colapso de clase mayoritaria, PR-AUC inutil o metricas ausentes.
- Separar en la comparativa lo que es `random`, `date`, `groupkfold`, `official`, dataset version y feature profile.

Primeros cambios aplicados:
- Los `compare_models.py` comparan por defecto solo el ultimo run por modelo/split, y `--all_runs` conserva la comparativa historica.
- Los comparadores aceptan `--split_modes` para que los runners comparen solo los modos ejecutados en esa tanda.
- Las tablas detalladas y agregadas incluyen metadata disponible como `feature_profile`, `feature_count`, `sampling_profile`, `source_set`, `config_fingerprint` y `sample_frac`.
- Los runners pasan los modos ejecutados a `compare_models.py`, evitando mezclar `date` reciente con `random/groupkfold` antiguos.
- Los nuevos entrenamientos guardan `run_config` y `sample_frac` en `run_metadata.json` cuando aplica.

Comentario:
Esta fase no cambia los datasets ni invalida artefactos antiguos. Solo mejora la trazabilidad de nuevos entrenamientos y reduce lecturas incorrectas de resultados.

## Fase 1 - Validacion de datasets antes de entrenar

Estado: en progreso.

Cambios:
- Crear/usar validadores por dataset antes de lanzar modelos.
- Comprobar `stats.json`, `label_map.json`, clases presentes, numero de positivos por split y coherencia entre splits.
- Bloquear o avisar cuando un split tenga menos positivos de los necesarios para una metrica defendible.
- Guardar `dataset_profile.json` con `window_size`, `source_set`, `feature_profile`, `split_policy`, conteos y hash/configuracion de preparacion.

Primeros cambios aplicados:
- UNSW-NB15 genera `dataset_profile.json` con configuracion, fichero fuente, conteos, columnas y fingerprint.
- El validador de UNSW-NB15 comprueba perfil, `stats.json`, clases presentes y positivos minimos por split antes de entrenar.
- Los nuevos artefactos UNSW-NB15 guardan `dataset_profile_ref.json` para enlazar el modelo con la version preparada.

Comentario:
Esto es prioritario para UNSW-NB15 y CSR-LANL, donde las metricas actuales pueden ser tecnicamente correctas pero academicamente debiles si el dataset esta mal balanceado o mezclado.

## Fase 2 - UNSW-NB15 limpio y reproducible

Estado: en progreso.

Cambios:
- Regenerar `random`, `official` y `groupkfold` desde cero.
- Validar que `stats.json` y artefactos pertenecen a la misma version preparada.
- Mantener `official` como evaluacion benchmark principal aunque sus metricas sean peores.
- Usar `random` solo como baseline optimista.

Primeros cambios aplicados:
- `prepare_dataset.py` soporta `--clean` para regenerar splits sin restos anteriores.
- Los scripts UNSW validan datasets antes de entrenar sin depender de `label_map.json` historicos.

Comentario:
El resultado official bajo no debe ocultarse: es informacion valiosa sobre shift de distribucion. Lo que hay que evitar es mezclarlo con runs random mas faciles.

## Fase 3 - CSR-LANL con muestreo centrado en red-team

Estado: en progreso.

Cambios:
- Sustituir el subsample uniforme por un dataset centrado en ventanas red-team.
- Incluir todas las ventanas red-team, ventanas cercanas antes/despues y benignos comparables por entidad y hora.
- Evaluar con date/group split, no solo random.
- Reportar PR-AUC, recall a bajo FPR y alertas por dia.

Primeros cambios aplicados:
- Nuevo preparador `redteam_sample_prepare_dataset.py` para generar `datasets_redteam` con ventanas alrededor de eventos red-team.
- Nuevo validador CSR-LANL para revisar `dataset_profile.json`, `stats.json`, parquets por split y positivos minimos antes de entrenar.
- Los artefactos CSR-LANL nuevos guardan `dataset_profile_ref.json` para enlazar modelo y dataset preparado.
- El runner CSR-LANL soporta `groupkfold` con folds concretos, y hay un flujo dedicado `csr_lanl_run_redteam_models.ps1`.

Comentario:
Con 6 ataques en train y 1 en test, el experimento actual solo sirve como smoke test. Para tesis, CSR-LANL necesita sampling inteligente.

## Fase 4 - Feature profiles sin leakage para LAB-ALERTS y COWRIE_FULL

Estado: en progreso.

Cambios:
- Crear perfiles `full` y `operational_no_label_proxy`.
- Excluir features que sean casi la definicion directa del label en el perfil defendible.
- Guardar `feature_profile` en metadata y en la ruta o comparativa.
- Mantener el perfil completo como sanity check, no como resultado principal.

Primeros cambios aplicados:
- LAB-ALERTS y COWRIE_FULL soportan `--feature_profile full|operational_no_label_proxy` en `prepare_dataset.py`.
- Los preparadores escriben `feature_columns.json`, `feature_profile.json` y `prepare_dataset_summary.json` con el perfil y features excluidas.
- Los artefactos de entrenamiento guardan `dataset_profile_ref.json` y enlazan `run_metadata.json` con el dataset preparado.
- Los runners LAB/COWRIE, `run_all_models.ps1` y `run_all_refactored_models.ps1` propagan el perfil de features.

Comentario:
HGB casi perfecto en estos datasets no demuestra deteccion generalizable; demuestra que el modelo aprende la politica de etiquetado.

## Fase 5 - UGR16: mantener HGB, rehacer anomaly

Estado: pendiente.

Cambios:
- Mantener HGB binario como baseline principal.
- Comparar perfiles `FLOW`, `HYBRID` y `ORACLE`; `ORACLE` solo como upper bound.
- Sustituir IsolationForest global por features temporales/entidad: rolling baselines, rareza de destino/puerto/protocolo y ventanas por entidad.
- Evaluar con PR-AUC, FPR@budget y alertas por dia.

Comentario:
IsolationForest sobre filas sueltas no captura bien el comportamiento temporal de UGR16. El valor del dataset esta en drift y ventanas largas.

## Fase 6 - CIC-IDS2017: evaluacion robusta por split

Estado: pendiente.

Cambios:
- Reportar random como baseline optimista.
- Usar `day` y `groupkfold` como validacion realista.
- Desglosar resultados por familia de ataque y por dia/fichero.
- Revisar modelos secuenciales solo si superan baselines tabulares en splits robustos.

Comentario:
Las caidas en `groupkfold` son una senal util: el sistema no debe vender random como generalizacion real.

## Fase 7 - Criterios de aceptacion

Un resultado se considera defendible si cumple:

- El dataset tiene metadata de preparacion y conteos por split.
- Cada split tiene suficientes positivos para las metricas reportadas.
- La comparativa prioriza macro-F1/PR-AUC/FPR operativo antes que accuracy.
- Los artefactos indican version de dataset, split mode, window size y feature profile.
- Los modelos perfectos o casi perfectos tienen explicacion de leakage/sanity-check cuando aplique.

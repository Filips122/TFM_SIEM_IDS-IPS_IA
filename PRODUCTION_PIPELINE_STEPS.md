# Production Pipeline Steps

Fecha: 2026-06-02

## Objetivo

Convertir los modelos ya entrenados en una arquitectura operacional defendible para produccion/laboratorio SOC. El objetivo no es forzar un unico modelo universal, sino combinar modelos especialistas con una salida comun, calibracion, umbrales y scoring de riesgo.

Meta operacional:

- acercarse a `precision >= 0.90`, `recall >= 0.90` y `F1 >= 0.90` donde el dominio lo permita;
- controlar falsos positivos y alertas por dia;
- mantener trazabilidad por modelo, version, dataset y umbral;
- reintegrar los resultados en el SIEM como eventos JSON estructurados.

## Arquitectura Recomendada

```text
telemetria SIEM/IDS
  -> router de dominio
  -> modelo especialista
  -> calibracion / threshold policy
  -> risk score comun
  -> correlacion SIEM
  -> alerta baja / media / alta
```

## Modelos Principales

| Dominio | Dataset/telemetria | Modelo recomendado | Lectura |
| --- | --- | --- | --- |
| `network_tabular` | UNSW-NB15 | HGB binario | Principal supervisado tabular robusto. |
| `network_temporal` | UGR16 | HGB binario | Validacion temporal/drift; objetivo inmediato pasar `macro-F1 >= 0.90`. |
| `siem_lab_alerts` | LAB-ALERTS | HGB binario | Resultado fuerte sin label-proxy. |
| `honeypot` | COWRIE_FULL | HGB multiclass | Taxonomia de comportamiento ofensivo. |
| `network_sequence` | CIC-IDS2017 | GRU day/secuencial | Mas defendible que splits aleatorios para CIC. |
| `entity_day_triage` | CSR-LANL | IsolationForest entity-day | Triage SOC, no clasificacion fila a fila. |
| `global_auxiliary` | GLOBAL_BINARY_V1 | FTTransformer/HGB global | Senal auxiliar y comparativa academica. |

## Pasos Logicos De Implementacion

### Fase 1 - Contrato Comun

Crear estructuras comunes para que todos los modelos devuelvan el mismo tipo de salida:

- `model_name`, `model_version`, `domain`, `dataset`, `split`;
- `entity_id`, `timestamp`, `prediction`, `probability_attack`;
- `threshold`, `risk_score`, `severity`, `explanation`;
- rutas a artefactos, calibradores y politicas.

Archivos iniciales:

```text
src/models/PRODUCTION_PIPELINE/schemas.py
src/models/PRODUCTION_PIPELINE/model_registry.py
```

### Fase 2 - Router De Dominio

Implementar un router simple y explicito que decida que modelo usar segun dataset, fuente o tipo de telemetria.

Salida esperada:

```text
UNSW-NB15 -> network_tabular -> HGB
UGR16 -> network_temporal -> HGB
LAB-ALERTS -> siem_lab_alerts -> HGB
COWRIE_FULL -> honeypot -> HGB multiclass
CIC-IDS2017 -> network_sequence -> GRU
CSR-LANL -> entity_day_triage -> IsolationForest
```

Archivo inicial:

```text
src/models/PRODUCTION_PIPELINE/router.py
```

### Fase 3 - Optimizacion De Umbrales

Antes de reentrenar modelos, evaluar si los modelos actuales pueden alcanzar el objetivo `+90%` ajustando umbrales.

Para cada modelo binario o lectura binaria:

1. cargar `model.joblib` y `label_map.json`;
2. cargar `val` y `test` desde el `data_loader` del dataset;
3. generar scores de ataque;
4. probar thresholds de `0.01` a `0.99`;
5. elegir politicas:
   - mejor F1;
   - `precision >= 0.90` con maximo recall;
   - `recall >= 0.90` con maxima precision;
   - mejor F1 bajo limite de alertas.

Archivo inicial:

```text
src/models/PRODUCTION_PIPELINE/threshold_optimizer.py
```

### Fase 4 - Calibracion

Calibrar probabilidades por modelo/dominio:

- isotonic si hay suficientes muestras de validacion;
- sigmoid/Platt si el dataset es pequeno;
- guardar `calibrator.joblib` junto al modelo o en el registro.

La calibracion debe reducir ECE y hacer que `risk_score` sea interpretable.

### Fase 5 - Risk Scoring

Convertir cualquier salida de modelo a un score comun `0-100`:

```text
risk_score = model_probability + severity/context + correlation
```

Primera version:

- bajo: `0-39`;
- medio: `40-69`;
- alto: `70-89`;
- critico: `90-100`.

Archivo inicial:

```text
src/models/PRODUCTION_PIPELINE/risk_scoring.py
```

### Fase 6 - Registro De Modelos

Crear un registro JSON con los modelos aprobados para inferencia:

```text
model_id
domain
dataset_key
model_type
artifact_dir
threshold
calibrator_path
metrics_path
status
```

El registro permitira cambiar versiones sin tocar codigo.

### Fase 7 - Inferencia Comun

Implementar un pipeline que:

1. recibe lote de eventos/features;
2. detecta dominio;
3. carga modelo desde el registro;
4. aplica preprocesado correcto;
5. predice y calibra;
6. aplica threshold;
7. genera salida comun;
8. exporta JSON SIEM.

### Fase 8 - Evaluacion Del Sistema

Comparar tres niveles:

| Sistema | Objetivo |
| --- | --- |
| IDS/SIEM rules only | Baseline sin ML. |
| Modelos especialistas | Medir mejora ML por dominio. |
| Sistema hibrido | Medir reduccion de ruido y priorizacion SOC. |

Metricas:

- precision, recall, F1, accuracy;
- PR-AUC y ROC-AUC;
- ECE/calibracion;
- alertas por dia;
- falsos positivos por dominio;
- latencia de inferencia;
- para CSR-LANL: top-k, first-hit rank y entity-day coverage.

## Orden Practico

1. Crear contrato comun, registry y router.
2. Implementar threshold optimizer.
3. Ejecutar threshold optimizer sobre HGB fuertes: LAB, UNSW, UGR16 y COWRIE binario/multiclass con lectura no-benigna.
4. Documentar si cada dominio puede alcanzar `precision >= 0.90`, `recall >= 0.90` y `F1 >= 0.90`.
5. Archivar modelos/resultados en `model_store` y generar comparativas versionadas.
6. Generar `active_model_registry` desde el store.
7. Implementar calibracion y repetir metricas.
8. Crear risk scoring y JSON de salida SIEM.
9. Conectar exportacion SIEM a inferencia batch/streaming real.
10. Integrar GRU CIC y CSR IsolationForest en el mismo contrato de salida.
11. Optimizar thresholds/politicas especificas: CIC GRU con validacion estable y CSR por presupuestos entity-day.
12. Comparar el sistema especialista contra FTTransformer/HGB global como senal auxiliar.

## Criterio De Decision Para Produccion

Un modelo pasa a candidato de produccion si cumple:

- split defendible (`date`, `day`, `groupkfold`, `official` o entity-centric);
- sin label proxies directos;
- `precision >= 0.90` y `recall >= 0.90`, o justificacion operacional si no aplica;
- ECE/calibracion aceptable;
- volumen de alertas asumible;
- salida JSON trazable e integrable en SIEM.

## Estado Inicial

Implementacion iniciada en:

```text
src/models/PRODUCTION_PIPELINE/
```

La primera pieza ejecutable sera `threshold_optimizer.py`, porque permite validar rapidamente si los modelos actuales pueden alcanzar objetivos de precision/recall/F1 antes de reentrenar.

Estado aplicado: `batch_inference.py`, `cic_gru_inference.py`, `cic_gru_threshold_optimizer.py` y `csr_entity_day_evaluator.py` ya conectan modelos activos con salida JSONL SIEM. La validacion completa del GRU CIC confirma que el modelo tiene senal fuerte. `day/val` no selecciona un threshold transferible, pero el nuevo split `day_independent_calibration` separa Friday en `calibration` y `test` holdout. Con threshold 0.005 seleccionado en `calibration`, el holdout obtiene P 0.9739, R 0.9383 y F1 0.9558. Esta politica ya esta registrada como activa en `policy_registry.active.json` y se aplica al regenerar `active_model_registry`. Tambien quedan ejecutados los baselines completos HGB (`full_hgb_active_20260602`) y CSR entity-day (`full_csr_active_20260602`), resumidos en `production_baseline_summary.csv` y `production_baseline_summary.md`. La carpeta `siem_ingestion/` deja preparada la ingesta Filebeat/Elastic de los JSONL; falta probarla contra un SIEM real. El router `run_active_inference.py` ya valida HGB, CIC GRU y CSR desde el registry activo. `soc_alert_policy.production.json` y `apply_soc_policy.py` aplican deduplicacion, rate limits y marcado de enriquecimiento; UGR/UNSW bajan de 5,000 a 500 eventos exportados en el batch actual.
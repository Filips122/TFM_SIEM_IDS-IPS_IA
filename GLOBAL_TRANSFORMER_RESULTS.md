# Global Transformer Results

Fecha: 2026-06-02

## Resumen Ejecutivo

El modelo mas adecuado para esta fase es un FTTransformer tabular sobre features canonicas numericas. La variante mixed-domain sin `dataset_embedding` es, por ahora, la mas defendible como baseline global, porque mejora el test global y reduce dependencia directa del dominio.

La evaluacion leave-one-dataset-out confirma que la generalizacion cross-dataset estricta sigue siendo dificil: el modelo aprende senales utiles cuando ve todos los dominios durante entrenamiento, pero transferir a un dataset completamente oculto degrada mucho el rendimiento.

## Dataset Global V1

`GLOBAL_BINARY_V1` se preparo con los cinco datasets compatibles:

| Split | Rows | Attack rows | Features | Datasets |
| --- | ---: | ---: | ---: | --- |
| train | 271,613 | 58,728 | 99 | CIC, UNSW, UGR16, LAB, COWRIE |
| val | 221,691 | 64,079 | 99 | CIC, UNSW, UGR16, LAB, COWRIE |
| test | 194,384 | 52,037 | 99 | CIC, UNSW, UGR16, LAB, COWRIE |

## V1 Mixed-Domain Baselines

| Version | Dataset embedding | Best epoch | Val macro-F1 | Test macro-F1 | Test ROC-AUC | Test PR-AUC | Test ECE |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `GLOBAL_BINARY_V1` | yes | 11 | 0.7300 | 0.7236 | 0.7095 | 0.6228 | 0.1817 |
| `GLOBAL_BINARY_V1_NO_DATASET_EMBED` | no | 11 | 0.7450 | 0.7301 | 0.7933 | 0.6845 | 0.1318 |

### V1 No Dataset Embedding - Test By Dataset

| Dataset | Rows | Attack rows | Accuracy | Macro-F1 | Macro-recall | ROC-AUC | PR-AUC | ECE |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CIC-IDS2017 | 49,686 | 20,497 | 0.6950 | 0.6117 | 0.6333 | 0.8441 | 0.7987 | 0.2854 |
| COWRIE_FULL | 32,118 | 817 | 0.8896 | 0.5767 | 0.7419 | 0.8617 | 0.2768 | 0.1184 |
| LAB-ALERTS | 517 | 318 | 0.8994 | 0.8883 | 0.8731 | 0.9944 | 0.9968 | 0.0600 |
| UGR16 | 56,946 | 28,639 | 0.5630 | 0.4625 | 0.5605 | 0.7890 | 0.7863 | 0.2199 |
| UNSW-NB15 | 55,117 | 1,766 | 0.9896 | 0.9229 | 0.9609 | 0.9874 | 0.8469 | 0.0401 |

## V1-LODO Fast Results

Estos entrenamientos desactivan siempre `dataset_embedding`. Cada fila entrena con cuatro datasets y evalua el test del dataset oculto.

| Holdout dataset | Best epoch | Val macro-F1 | Test rows | Attack rows | Test macro-F1 | Test macro-recall | Test ROC-AUC | Test PR-AUC | Test accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CIC-IDS2017 | 3 | 0.6888 | 49,686 | 20,497 | 0.4577 | 0.4920 | 0.3660 | 0.3978 | 0.5486 |
| UNSW-NB15 | 1 | 0.6484 | 55,117 | 1,766 | 0.3368 | 0.3848 | 0.4506 | 0.0286 | 0.4752 |
| UGR16 | 12 | 0.8674 | 56,946 | 28,639 | 0.3281 | 0.4866 | 0.6271 | 0.5674 | 0.4838 |
| LAB-ALERTS | 11 | 0.7457 | 517 | 318 | 0.0969 | 0.1150 | 0.1239 | 0.4281 | 0.0986 |
| COWRIE_FULL | 11 | 0.7188 | 32,118 | 817 | 0.4992 | 0.4993 | 0.3500 | 0.0329 | 0.9522 |

## Interpretacion

1. `GLOBAL_BINARY_V1_NO_DATASET_EMBED` es el mejor baseline global actual: mejora test macro-F1, ROC-AUC, PR-AUC y calibracion frente al modelo con embedding.
2. El mixed-domain score no debe interpretarse como generalizacion a dominios no vistos. El modelo ve ejemplos de todos los datasets durante entrenamiento.
3. V1-LODO muestra una caida fuerte en todos los holdouts. Esto sugiere que las senales canonicas compartidas todavia no bastan para transferir entre esquemas de telemetria muy distintos.
4. UGR16 mejora respecto a otros holdouts en ROC-AUC/PR-AUC, pero sigue con macro-F1 bajo por umbral/calibracion y drift temporal.
5. LAB-ALERTS y COWRIE_FULL son especialmente dificiles como dominios ocultos porque sus senales operacionales/honeypot no estan bien representadas por trafico de red tradicional.

## Decision Actual

Para la tesis, usar como modelo global principal:

- arquitectura: FTTransformer tabular;
- input: `GLOBAL_BINARY_V1` con 99 features canonicas;
- variante recomendada: `GLOBAL_BINARY_V1_NO_DATASET_EMBED` para lectura metodologica mas estricta;
- usar `GLOBAL_BINARY_V1` con embedding solo como comparativa mixed-domain;
- usar V1-LODO como evidencia de dificultad de transferencia cross-dataset.

## Proximas Versiones

1. Reentrenar `GLOBAL_BINARY_V1_NO_DATASET_EMBED` con perfil `balanced` o `conservative`.
2. Explorar ajuste de umbral por dataset para UGR16/CIC en mixed-domain.
3. Implementar `GLOBAL_MULTIHEAD_V2` para mantener cabeza binaria global y cabeza multiclass especifica para COWRIE.
4. Implementar `GLOBAL_CSR_EXTENSION_V3` como extension operacional separada por entidad/entity-day, no mezclada con V1.

# ARGOS-LAB — libro de resultados validados

Registro acumulativo de los resultados que han sobrevivido a auditoría. Cada
entrada apunta a su experimento y a su run en `artifacts/`. **Regla del
proyecto: ninguna métrica agregada se cita sin su desglose por agente**, y todo
resultado retirado permanece listado como tal.

Convenciones: split temporal salvo indicación; semilla 42; precisión objetivo
del bloqueo 0,99 fijada en validación.

---

## Resultados vigentes

### R1 · Auditoría de fuga de la etiqueta débil
Una sola columna (`mitre_tagged_ratio`) reproduce la etiqueta binaria con
**ROC-AUC 0,9990**; el grupo signature llega a 1,0000. La tarea binaria
supervisada es reconstrucción de regla, no detección.
→ `leakage_audit.py` · `artifacts/leakage_audit/date/`

### R2 · Huella del host
Con las 54 variables `behavioral` (sin `agent_id`) se predice qué agente es con
**99,75 % de exactitud**. La identidad del host vive repartida entre variables
correlacionadas: quitar una columna no elimina el confundido.
→ demostrado en sesión; base del diseño por host

### R3 · Multiclase de actividad (dentro de host)
Macro-F1 **0,7738** global con conducta pura (vs 0,9911 con firma: la fuga,
cuantificada). No explicada por el agente (agent_id solo: 0,2579).
→ `train_ml_multiclass_hgb.py` · `artifacts/ml_multiclass_hgb/date/`

### R4 · Etiqueta de bloqueo por conducta (rompe la circularidad)
Criterios sobre hechos observados (≥5 usuarios | ≥2 agentes | ≥50 avisos en ≥3
ventanas), causal. Auditada: mejor sonda individual **0,6641** (débil: 0,9990).
80.221 ventanas con origen de red; ALLOW repartida entre ambos hosts SSH.
→ `build_block_labels.py` · `datasets/block_labels/`

### R5 · Puntuador de bloqueo por ventana
Funciona dentro de cada host: lift **43,5×** (000) y **20,0×** (011).
Transferencia entre hosts: retiene **65–104 %** del MCC nativo (débil: 0,000).
→ `train_block_scorer.py`, `experiment_block_transfer.py`

### R6 · Validación externa del puntuador de ventanas — UN DISPARO, GASTADO
ARGOS→LAB-ALERTS, canalización congelada, régimen shape sin geo: **MCC medio
0,3426** en hosts jamás vistos (server1-principal 0,4613 · romero-AWS 0,3764 ·
biblioteca 0,1902). En server1-principal supera al nativo local (0,25).
→ `experiment_external_validation.py` · `artifacts/exp_external_validation/`

### R7 · Bloqueo temprano por IP, política secuencial (v2) — RESULTADO ESTRELLA
Reevaluando con cada aviso y bloqueando al primer cruce de umbral:
**recall 0,990 · precisión 0,995** (3 falsos/mes), mediana de corte al 5º aviso,
**89 % de los avisos posteriores evitados** (44.315).
Reputación causal de subred: AUC a K=1 sube de 0,52 a **0,83**.
Mecanismo honesto: detección rápida + anticipación parcial (a K=5, de los que
aún no cumplían criterios anticipa el 21,6 %; a K=10 el 74,4 %).
→ `experiment_early_blocking.py`, `experiment_early_blocking_v2.py`

### R8 · Validación externa del bloqueo secuencial — UN DISPARO, GASTADO
Umbrales congelados de ARGOS sobre las 561 IPs de LAB-ALERTS: **recall 0,994**,
precisión medida 0,898 (suelo por censura de 11 h: de los 38 cortes contados
como error, 29 estaban a 1–2 usuarios de cumplir criterios o superaban 25
avisos — atacantes activos cortados por fin de captura). 91 % de avisos
evitados, mediana al 5º aviso.
→ `experiment_early_blocking_external.py`

### R9 · Umbral adaptativo a prevalencia (prior shift, sin etiquetas destino)
Calibración isotónica + π̂ = media de scores calibrados del destino. A K=3:
recall 0,448 → **0,638**; a K=5: 0,846 → **0,900**, precisión ≥ 0,99. π̂
estimada 0,82–0,84 frente a real 0,848.
→ `experiment_adaptive_threshold.py`

### R10 · GRU secuencial en bloqueo temprano — sin ventaja (veredicto DL cerrado)
GRU sobre la secuencia de los primeros K avisos de cada IP (evento = hueco,
usuario-nuevo, root, sistema, puerto, agente-nuevo, ventana-nueva; contexto de
subred concatenado), en condiciones identicas al HGB v2: **AUC medio 0,9702 vs
0,9703**. Con esto el veredicto queda cerrado: en este corpus el deep learning
no aporto ventaja medible en ninguna tarea (tabular supervisada, no supervisada
ni secuencial). El ensamblado por rangos mantiene AUC pero rompe el traslado de
umbral p99 (rangos no comparables entre val y test) — no usar.
→ `experiment_early_blocking_gru.py` · `artifacts/exp_early_blocking_gru/`

---

## Resultados retirados (permanecen como advertencia)

### X1 · Autoencoder «18,3×» — RETIRADO
Por agente: 0,57×–0,95× (azar o peor). El agregado venía de la concentración de
la clase rara en el agente 030. Paradoja de Simpson; origen de la regla del
desglose obligatorio (`reporting.py::per_group_metrics`).

### X2 · Binario supervisado ~0,99 — NO CITABLE
Saturado en todo régimen; véase R1.

### X3 · Adaptación z-score por host — PERJUDICIAL para el bloqueo
MCC −0,08 a −0,26. Regla aprendida: normalizar por host ayuda cuando la
etiqueta es relativa al host y estorba cuando es absoluta (probar 8 cuentas es
hostil en cualquier máquina). La transformación de rango es mixta (mejor caso
0,4391, no consistente).
→ `experiment_domain_adaptation.py`

---

## Presupuestos de un-solo-disparo sobre LAB-ALERTS

| Experimento | Estado |
|---|---|
| Puntuador de ventanas (R6) | **Gastado** |
| Bloqueo temprano secuencial (R8) | **Gastado** |
| Cualquier otro uso | Degrada LAB-ALERTS a conjunto de desarrollo — declararlo si se hace |

Para nuevas afirmaciones externas hace falta una captura nueva (idealmente >24 h
y con los hosts Windows activos).

## Artefactos publicados (consolidados con R7–R9 el 2026-09-02)

- Memoria técnica · §8.6 bloqueo temprano: https://claude.ai/code/artifact/d0c1f055-fcdb-4963-9201-19ab749be4a2
- Auditoría técnica · §5.8: https://claude.ai/code/artifact/8d15f4f1-9454-470d-b8fc-efefb72d885e
- Resumen en llano: https://claude.ai/code/artifact/d35c1ad3-899a-4489-9153-f339da326945

### R11 · UNSW-NB15 corregido (2026-09-02)
Bug de cabecera arreglado en `prepare_dataset.py` (`read_csv_smart`: nombres
oficiales de `NUSW-NB15_features.csv` para los crudos sin cabecera).
Particiones regeneradas con 47 features reales y distribución verdadera
(BENIGN 2.218.764 / ATTACK 321.283 — coincide con la documentación del
dataset). Nuevos resultados citables: binario random macro-F1 0,9841 ·
groupkfold f0 0,9658 · multiclase random macro-F1 0,4505 (exactitud 0,9753 —
las categorías raras siguen difíciles). El contraste transversal queda
completo: laxo ≈0,98 vs partición oficial 0,26.
**Nota de rutas**: datasets y artefactos canónicos viven en
`src/models/NUSW-NB15/` (typo histórico, ruta por defecto de los loaders);
las copias corruptas antiguas en `src/models/UNSW-NB15/datasets/{random,groupkfold}`
quedan huérfanas — candidatas a limpieza.
→ `src/models/UNSW-NB15/prepare_dataset.py` · `src/models/NUSW-NB15/artifacts/`

### R12 · CSR-LANL contra ground truth real — el dominio de validez de la metodología
Primera evaluación de toda la tesis contra verdad de campo (redteam.txt: 749
autenticaciones de compromiso reales, fuente independiente del flujo de
eventos — circularidad imposible). 1.051 M eventos → 7,75 M celdas
(máquina, hora), 91 rojas, prevalencia 1,17e-05. Split temporal 35/30/26 rojas.

**Señal real**: ROC-AUC 0,9587 en test, lift de PR hasta 259× por día;
`ntlm_ratio` sola da AUC 0,99 (coherente con la táctica documentada del red
team de LANL). Las features conductuales del método capturan compromiso
genuino. Supervisado > no supervisado también aquí (IF: ROC 0,83, lift 30×).

**Insuficiencia operativa**: a 1 entre 225.000, la lista de caza falla
(top-50/día: 1/26 rojas) y la agregación por entidad deja a las 4 máquinas
atacantes en posiciones 840–2.356 de 15.180.

**Conclusión de dominio de validez** (la aportación): la metodología de
conducta observada detecta atacantes RUIDOSOS con eficacia operativa (fuerza
bruta en ARGOS: recall 0,99, validado externo) y produce señal real pero NO
operativa contra atacantes SIGILOSOS con credenciales válidas (LANL). El
límite queda medido con ground truth en ambos lados. Trabajo futuro: features
de grafo/pares usuario-máquina, la respuesta de la literatura al caso sigiloso.
→ `src/models/CSR-LANL/prepare_lanl_hourly.py`, `train_lanl_redteam.py` ·
  `src/models/CSR-LANL/artifacts/redteam_hourly/`

### R13 · Transformer (atención) en bloqueo temprano — empate con HGB; entra en el paquete como segunda opinión (2026-09-07)
Encoder de 2 bloques pre-LN (d=32, 4 cabezas, ~18k parámetros) sobre las fichas
por aviso de R10 (7 dims; la variante `rich` con +3 dims acumuladas resulta
equivalente) y el contexto causal de subred como ficha inicial (CLS). Tres
semillas; mismo split temporal, misma etiqueta y mismo protocolo p99 que R7/R10.

- **Un modelo por K** (comparable uno a uno): AUC medio por K **0,957** vs HGB
  0,952 vs GRU 0,953 → *sin ventaja clara* (regla ±0,005). Único punto con
  diferencia consistente: K=1, AUC 0,857–0,864 vs 0,827 (3 semillas). Pero el
  umbral p99 de K=1 **no traslada** de validación a test (prevalencia 58 → 85 %):
  la política secuencial con K=1 cae a precisión 0,976–0,982 (11–15 FP). Con
  presupuestos **K ≥ 2**: recall **0,991** · precisión **0,991** · FP 5,7 ·
  mediana 4º aviso · 90,3 % evitado — empate exacto con HGB (0,990 / 0,993 /
  4,3 / 4º / 89,6 %).
- **Un modelo compartido** para todas las longitudes (un solo peso): peor (AUC
  medio 0,929; recall secuencial 0,953). No se despliega.
- **Combinaciones con HGB** (política secuencial): OR 0,990 / 0,990–0,992;
  AND 0,952–0,954 / **0,997** con FP 2,0 — la política más estricta medida;
  media de probabilidades 0,988 / 0,994. Ninguna sube el recall de HGB; AND
  compra precisión a cambio de recall (y de 20 puntos de volumen evitado).
- Desglose por agente del primer aviso (tr_k, K≥2, semilla 42): agente 000
  recall 0,993 / FP 2 · agente 011 recall 0,991 / FP 3 (HGB: 0,986 / 1 y
  0,994 / 2). Sin paradoja de agregación.
- Aportación no métrica: la atención de la ficha de contexto señala **qué
  avisos pesaron** en la decisión (los que introducen usuario nuevo y los
  últimos de la ramp-up concentran el peso) — evidencia para el analista que
  el HGB no ofrece.

El veredicto DL sigue cerrado: cuarta arquitectura sin ventaja medible en este
corpus. Motivo estructural: la etiqueta cuenta hechos (≥5 usuarios, ≥2
máquinas, ≥50 avisos) y no depende del orden; la atención no tiene nada que
explotar que los agregados no capten. Se empaqueta igualmente
(`deploy/argos_scorer/models/attention_block.npz`, inferencia en numpy puro
verificada contra torch, sin torch en el paquete) como servicio opcional
`AttentionBlockScorer` y como `ConsensusBlockScorer` (OR/AND). Sin validación
externa: el presupuesto LAB-ALERTS está gastado.
→ `experiment_early_blocking_transformer.py`, `build_deploy_attention.py` ·
  `artifacts/exp_early_blocking_transformer/date/ARGOS-LAB__{base,rich}/`

## Fe de erratas (2026-09-08, auditoría para el dossier de investigación)

Detectadas al reconstruir cada cifra desde su artefacto para `DOSSIER_MODELOS_TFM.md`.
Los resultados afectados **no se retiran**; se corrige la cifra o se marca lo no trazable.

- **R8**: el artefacto `exp_early_blocking_external/.../20260902_134936/results.json`
  registra **37** IPs no bloqueables cortadas (325/362 → precisión 0,8978), no 38.
  El análisis «29 de ellas a 1–2 usuarios de cumplir criterios o >25 avisos» no está
  persistido en ningún fichero; reconstruirlo desde el crosstest antes de citarlo.
- **R11**: la exactitud **0,264 de la partición oficial es fuga por la columna `id`**,
  incluida entre las 43 features oficiales (en `training-set` la etiqueta forma 4 bloques
  a lo largo de `id`; en `testing-set` cambia 4.109 veces). Verificado reentrenando el
  mismo HGB (200 iter., semilla 42) sobre el Parquet oficial existente: con `id`
  exactitud 0,2637 / macro-F1 0,2609 / ROC 0,512; con `id` permutado en test 0,441 /
  0,440 / 0,770; **sin `id` 0,8986 / 0,8905 / 0,9852**. Persistido el 2026-09-09:
  `src/models/UNSW-NB15/experiment_official_id_leak.py` → `src/models/NUSW-NB15/artifacts/exp_official_id_leak/official/20260909_001256/results.json`.
  El contraste honesto laxo↔oficial es **≈0,98 ↔ ≈0,90**, no ↔ 0,26. Además `proto`,
  `service` y `state` (y `srcip`/`dstip` en los crudos) llegan 100 % a NaN→0 en todos
  los Parquet de UNSW: la codificación de categóricas comprueba `dtype == object` y con
  pandas 3 las cadenas son `str`. Ninguna cifra del módulo usó esas columnas.
  Pendiente: excluir `id`, arreglar la codificación, regenerar y reejecutar. §8.7 de la
  memoria técnica publicada corregido el 2026-09-09.
- **R12**: la afirmación «las 4 máquinas atacantes en posiciones 840–2.356 de 15.180»
  no tiene script ni artefacto (no está en `train_lanl_redteam.py` ni en `results.json`);
  el denominador coincide con las máquinas origen del test. Marcar como no reproducible
  hasta que se persista el método de agregación.
- **Fuera de este módulo**: CIC-IDS2017 se entrenó íntegramente con `epochs = 5`
  (HGB de 5 iteraciones, Isolation Forest de 5 árboles) y su partición por día es
  también una partición por familia de ataque; UGR16 no tiene ningún modelo entrenado
  (datasets vacíos, 4 trainers con conflictos de merge); LAB-ALERTS tiene un único host
  Windows (023, 86 min, sin `srcip`) que no interviene en R6/R8; el «modelo CSR-LANL
  de 209 características» que describe la web no existe en este repositorio y sus
  cifras no son las de R12.

## Deuda conocida fuera de este módulo

- ~~UNSW-NB15: particiones corruptas~~ → **corregido** (R11).
- UNSW-NB15: copias corruptas antiguas en `UNSW-NB15/datasets/` pendientes de
  limpieza (no borradas por prudencia).
- UGR16: 4 scripts con marcadores de conflicto de git sin resolver.

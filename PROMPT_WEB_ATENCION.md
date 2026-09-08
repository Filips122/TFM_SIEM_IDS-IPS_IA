# Prompt para la sesión de la web (ARGOS-WEB): integrar el Transformer como segunda opinión

> Copia desde aquí hasta el final y pégalo en una sesión de Claude Code abierta en
> `C:\Users\xfeli\Desktop\TFM\ARGOS-GIT\ARGOS-WEB`.

---

Estás en el repo de la web ARGOS-SOC (Next.js + sidecar Python en `deploy/argos_scorer/service.py`
+ servidor MCP en `deploy/argos_mcp/server.ts`). Lee primero `ARGOS_WEB.md` completo: es el
inventario de cada pantalla y de sus convenciones (**[real]/[fijo]/[derivado]/[externo]**, «ninguna
métrica agregada sin desglose», el simulacro no ejecuta acciones, el ledger va en `mode: 'shadow'`).
Todo lo que hagas debe respetar esas convenciones.

## Contexto: qué ha cambiado en el repo de investigación

En `C:\Users\xfeli\Desktop\TFM\GIT\TFM_SIEM_IDS-IPS_IA\deploy\argos_scorer\` el paquete ha pasado a
la versión 1.1 con un cuarto servicio (resultado **R13** del libro `src/models/ARGOS_LAB/RESULTADOS.md`):

- `argos_scorer/attention.py`: un Transformer de atención (2 bloques, 4 cabezas, d=32, ~18k parámetros
  por K) sobre la **secuencia** de los primeros K avisos de una IP, con inferencia en **numpy puro**
  (sin torch; verificado contra el modelo entrenado con diferencia máxima 3,5·10⁻⁷). Un modelo por
  K ∈ {2, 3, 5, 10, 20}, todos en `models/attention_block.npz` (414 KB). Expone:
  - `AttentionBlockScorer` — misma interfaz que `EarlyBlockScorer` (`load`, `ingest`, `score_ip`, `save_state`).
  - `AttentionBlockScorer.score_events(events, context, k) -> (score, atencion_por_aviso)` — puntúa
    **sin efectos** los eventos de un perfil que ya mantiene otro proceso. Es el método que debes usar
    desde el sidecar.
  - `ConsensusBlockScorer(mode="or"|"and")` — un solo perfil y un solo estado para los dos modelos.
- `models/config.json`: nueva sección `attention_block` (umbrales por K a precisión ≥ 0,99, normalización,
  hiperparámetros, métricas del test interno). Las secciones `early_block`, `window_block` y `activity`
  son **idénticas** a las que ya tienes: se puede copiar el fichero entero.
- `README.md` §2.4 y §4.6 documentan el servicio; `example_attention.py` es la demo.

Lo que dice la evidencia (test interno, misma partición que el HGB; **sin validación externa**, el
presupuesto de LAB-ALERTS está gastado):

| Política | Recall | Precisión | Legítimas cortadas/mes | Mediana de corte | Ataque evitado |
|---|---|---|---|---|---|
| HGB (`EarlyBlockScorer`, el principal) | 0,990 | 0,995 | 3 | 5º aviso | 89,3 % |
| Atención solo | 0,992 | 0,992 | 5 | 5º aviso | 90,2 % |
| Consenso OR | 0,995 | 0,990 | 6 | 5º aviso | 93,9 % |
| Consenso AND | 0,985 | 0,997 | 2 | 5º aviso | 85,5 % |

Sobre tres semillas HGB y atención **empatan** (recall 0,991 vs 0,990; precisión 0,991 vs 0,993; AUC
medio por K 0,957 vs 0,952). El Transformer **no detecta mejor**: la etiqueta cuenta hechos y no
depende del orden. Lo que aporta es (a) una segunda opinión con otro sesgo inductivo y (b)
explicabilidad: `evidence.avisos_decisivos` y `atencion_por_aviso` dicen qué avisos pesaron. K = 1
está **excluido a propósito** (ahí su umbral no traslada de validación a test; la precisión caía a 0,976).

## Objetivo

Integrar el Transformer en la web **como segunda opinión en modo sombra**, sin cambiar quién decide.
El HGB sigue siendo el modelo principal (es el único validado externamente). La utilidad concreta es:

1. Medir en vivo, durante semanas, el **acuerdo/desacuerdo** entre los dos modelos sobre tráfico real.
   Es la única forma que queda de validar el Transformer fuera del laboratorio sin gastar nada, y da
   los datos para decidir más adelante si el consenso AND (más precisión) u OR (más recall) merece
   pasar a decidir.
2. Dar al analista, en cada bloqueo, **qué avisos pesaron** (algo que el HGB no puede dar) y si los dos
   modelos coinciden — complemento del «margen sobre el umbral», que hoy está ajustado en la mitad de
   las decisiones.

## Guardarraíles (no negociables)

- **El HGB decide en `/ingest`.** La atención solo anota. El ledger sigue en `mode: 'shadow'` y su
  campo `action` no cambia por lo que diga el Transformer.
- **Un solo estado vivo, una sola actualización de reputación.** No instancies un segundo scorer que
  llame a `ingest` sobre el mismo `LiveState`: contaría doble la reputación de subred. Desde el
  sidecar usa `score_events(profile["events"], profile["context"], n)` sobre los perfiles que ya
  mantiene `self.early`. Para las rutas efímeras (`/simulate`, `ip_risk`) puedes usar
  `ConsensusBlockScorer` sembrado desde la semilla, como ya se hace con `EarlyBlockScorer`.
- **Sin torch.** `requirements.txt` no cambia. Comprueba que `attention.py` solo importa numpy.
- **Mismos campos de entrada.** El Transformer consume exactamente los `MODEL_FIELDS` actuales del
  sidecar (`timestamp, window_start, agent_id, src_ip, src_port, src_user, dst_user`). Nada de
  `rule_*`, `mitre_*`, `decoder_name`, `rule_level`, `agent_name`, geo ni hora: son la fuga
  circular (R1), la huella de host (R2) o el cron de Trivy. Conserva el guardia de tipos `Forbidden`
  de `lib/argos-scorer-client.ts` y no lo relajes.
- **Sin segunda opinión en el primer aviso.** La atención no puntúa en n = 1. La interfaz debe decir
  «sin segunda opinión hasta el 2º aviso», no mostrar 0 ni omitirlo en silencio.
- **Las exclusiones de infraestructura propia** (`exclusions.json`) se aplican igual a cualquier
  veredicto o anotación del Transformer.
- **Cifras**: solo las de la tabla de arriba, siempre etiquetadas «test interno, sin validación
  externa». No escribas «mejora», «más preciso» ni «generaliza mejor».
- **Ficheros nuevos antes que modificar los existentes** cuando sea razonable; y nunca sobrescribas
  `service.py`, `exclusions.json`, `test_service.py`, `shadow-run.ts`, `alias-hook.mjs` ni
  `register-alias.mjs` con los del repo de investigación: son de la web.

## Trabajo, por fases (cada una con su comprobación)

### Fase 0 · Sincronizar el paquete
Copia desde el repo de investigación a `deploy/argos_scorer/`: `argos_scorer/attention.py`,
`argos_scorer/__init__.py` (v1.1, exporta `AttentionBlockScorer` y `ConsensusBlockScorer`),
`models/attention_block.npz`, `models/config.json`, `README.md`, `example_attention.py`. **No** copies
`state/live_state.json` (la semilla de la web está intacta; la del repo de investigación la han
mutado las demos). Comprobación: `.venv/Scripts/python.exe deploy/argos_scorer/example_attention.py`
corre, `config.json` tiene `attention_block` y `early_block` no ha cambiado (`git diff`).

### Fase 1 · Sidecar (`service.py`)
- En `ScorerService.__init__`: carga `AttentionBlockScorer.load(models_dir, state=state)` **solo para
  tener sus redes y umbrales**; no llames nunca a su `ingest`.
- En `ingest_batch`: tras `self.early.ingest(alert)`, si `n = len(profile["events"])` está en los
  presupuestos de la atención, calcula `score_events` y añade al veredicto del HGB (si lo hay) y a un
  registro paralelo un bloque `second_opinion = {model: "attention", score, threshold, fired, agreement,
  avisos_decisivos, atencion_por_aviso}` donde `agreement ∈ {both, hgb_only, attention_only, none}`.
  Anota también las IPs en las que **solo** la atención cruza su umbral (no son veredictos: son
  discrepancias) en un contador y en la respuesta (`attention_only: [...]`).
- En `simulate`: usa `ConsensusBlockScorer` efímero sembrado desde la semilla con un parámetro
  `policy ∈ {hgb, attention, or, and}` (por defecto `hgb`, comportamiento actual intacto). Devuelve
  además una matriz de acuerdo `{both, hgb_only, attention_only}` sobre las IPs con ≥ 2 avisos y, en
  cada veredicto, `avisos_decisivos` con sus `alert_index` para poder enlazarlos.
- En `ip_risk`: añade `second_opinion` por IP con la misma forma (efímero, como ahora).
- En `health`: `attention: {loaded, budgets, n_models, n_params_por_modelo}` y los contadores de acuerdo.
- Comprobación: extiende `test_service.py` (mismo estilo) con: la atención está cargada; `/ingest`
  produce los mismos veredictos que antes (mismo `action`, mismo `decided_at_alert`); la generación
  de estado y `sub24` no cambian por culpa de la atención; `/simulate?policy=and` bloquea ≤ que `or`;
  mide la latencia de `/score` antes y después y anótala.

### Fase 2 · Tipos y normalizadores
`lib/argos-scorer-client.ts` (`Verdict`), `lib/ai-scoring.ts` (`IpRisk`), `lib/argos-normalizers.ts`
(~línea 390, `ipRisk`), `lib/scorer-ingest.ts` (`LedgerRecord`): añade el campo opcional
`secondOpinion` con la forma de arriba. En el ledger se guarda como anotación; `action`, `score`,
`threshold` y `decided_at_alert` siguen siendo los del HGB.

### Fase 3 · Interfaz
- Feed (`ThreatFeed`, línea `IP <n>`): un marcador de acuerdo después de «bloquearía en aviso N»:
  `· 2ª opinión: coincide` / `discrepa` / `sin 2ª opinión (1er aviso)`. Nada más en la tarjeta.
- Ficha de detalle (§3.1): bloque nuevo «Segunda opinión (Transformer)» con score, umbral, acuerdo y
  la lista de avisos decisivos con su peso; con la advertencia de que es test interno.
- Simulacro (`/simulacro`): selector de política (`hgb` por defecto), matriz de acuerdo con sus
  tres recuentos, y en cada veredicto los avisos decisivos enlazados a las alertas reproducidas.
  Respeta la regla del desglose: la matriz también por agente destino.

### Fase 4 · MCP (`deploy/argos_mcp/server.ts` y `app/api/argos/mcp-chat/route.ts`)
- `riesgo_de_ip`: añade «Segunda opinión (Transformer): N sobre 100, coincide/discrepa; avisos
  decisivos: …» o «sin segunda opinión hasta el 2º aviso».
- `simular_bloqueo`: parámetro `politica` (`hgb|attention|or|and`, por defecto `hgb`) y la matriz de acuerdo.
- `estado_modelos`: informa de si la atención está cargada.
- *System prompt*: octava advertencia metodológica: el Transformer es segunda opinión, empata con el
  HGB (R13), no tiene validación externa, no decide, y no puntúa el primer aviso.

### Fase 5 · Documentación
Actualiza `ARGOS_WEB.md` (§4 línea `IP <n>`, §5 «los dos scores» → añade el tercero y explica que
responde a la **misma pregunta** que `IP <n>` con otro modelo, §7 simulacro con la matriz de acuerdo,
§10 parámetros nuevos, §11 limitación: sin validación externa) y `METRICAS.md` si inventaría métricas.
Mide de verdad lo que cites (acuerdo sobre las 10.000 alertas cargadas, latencia) y márcalo con la
convención **[real]/[derivado]**.

### Fase 6 · Cierre
`npx tsc --noEmit`, `npm run build`, `test_service.py` en verde, y un commit por fase con mensaje en
español. Termina con un resumen que diga: qué cambió, la latencia medida antes/después de `/score`
e `/ingest`, la matriz de acuerdo medida en vivo, y qué quedó fuera.

## Orden recomendado y tamaño

Fases 0→1→2→3→4→5→6. Si algo de la fase 3 no cabe, prioriza la ficha de detalle y el simulacro sobre
el feed. No toques el score de ventana (`AI <n>`) ni el bloque CSR-LANL: están fuera de este trabajo.

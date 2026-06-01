# Explanation CSR-LANL

Fecha de consolidacion: 2026-06-01

Este documento explica como deben interpretarse los resultados de CSR-LANL dentro del TFM, que significa una lectura **SOC operacional**, para que se podria usar el modelo y que tipo de actividad busca detectar o priorizar.

Fuentes principales:

- `RESULTS_CSR-LANL.md`
- `BEST_CHOICE_BY_DATASET.md`
- `CSR-LANL_V3.md`
- resultados CSR-LANL V3 generados el 2026-05-31

## Resumen Ejecutivo

CSR-LANL no debe interpretarse como un benchmark clasico donde el objetivo principal sea maximizar `accuracy` fila a fila. El dataset tiene un desbalance extremo: hay millones de ventanas benignas y muy pocas ventanas red-team. En ese contexto, un modelo puede obtener una accuracy muy alta simplemente clasificando casi todo como benigno y aun asi fallar justo en lo que importa.

La lectura mas defendible es tratar CSR-LANL como un problema de **priorizacion operacional para un SOC**:

> Reducir millones de eventos internos a una lista pequena y justificable de entidades, hosts o entity-days que un analista deberia investigar.

El mejor resultado actual es **IsolationForest V3** sobre `redteam_stratified_groupkfold/fold_0`, evaluado con lectura `entity_day`. Su resultado mas importante no es que localice siempre la ventana exacta en el ranking global, sino que mediante una politica de entity-day cubre **32/34 ventanas exactas red-team** y **1,327/1,415 ventanas entity-day** dentro del ambito priorizado.

## Que Representa CSR-LANL

CSR-LANL representa actividad interna de una red corporativa: autenticaciones, flujos y relaciones entre entidades. La parte red-team simula comportamiento ofensivo interno dentro de esa red.

En este TFM, CSR-LANL se usa para evaluar si el sistema puede ayudar a detectar o priorizar comportamientos compatibles con:

- compromiso de cuentas,
- movimiento lateral,
- uso anomalo de credenciales,
- conexiones internas poco habituales,
- actividad low-and-slow,
- exploracion o reconocimiento interno,
- comportamiento raro por entidad frente a su historico.

No es un dataset orientado a detectar una firma concreta de exploit o payload. Para eso encajan mejor IDS/IPS como Suricata o reglas SIEM. CSR-LANL sirve mejor para detectar **desviaciones de comportamiento interno**.

## Por Que Accuracy No Es Suficiente

El problema principal es el desbalance.

Ejemplo del split `date` inicial:

| Elemento | Valor |
| --- | ---: |
| Filas test | 2,575,431 |
| Ventanas red-team | 38 |
| Entidades red-team | 15 |
| Dias con ataque | 3 |

Con estos numeros, si un modelo predice casi todo como benigno, puede parecer excelente en accuracy pero ser inutil operacionalmente. Por eso CSR-LANL se evalua con metricas como:

- primer ataque encontrado en el ranking,
- ventanas red-team en top-100 o top-500,
- entidades red-team encontradas en top-k,
- entity-days seleccionados,
- ventanas exactas cubiertas dentro de entity-days seleccionados,
- alertas o entity-days por dia,
- politicas calibradas en validacion y aplicadas en test.

La pregunta no es solo:

> Cuantas filas clasifica bien?

La pregunta correcta para CSR-LANL es:

> Ayuda a un analista a encontrar antes las entidades y dias donde ocurre actividad red-team?

## Que Significa SOC Operacional

SOC significa **Security Operations Center**. Un SOC real no revisa millones de eventos uno a uno. Normalmente trabaja con alertas priorizadas, entidades de riesgo, casos de investigacion y presupuestos de tiempo.

Por eso, una lectura SOC operacional mide si el modelo ayuda a responder preguntas como:

| Pregunta SOC | Traduccion en el experimento |
| --- | --- |
| Que hosts o usuarios deberia investigar hoy? | Ranking por entidad o entity-day. |
| Cuantas alertas puedo asumir al dia? | Politicas con presupuesto diario. |
| Aparece alguna entidad red-team dentro del top-k? | `entity top-50`, `entity top-500`. |
| Puedo reducir millones de eventos a una lista investigable? | `selected entity-days/day`. |
| Aunque no localice el minuto exacto, apunta al dia y entidad correctos? | Cobertura de ventanas exactas dentro de entity-days seleccionados. |
| El modelo reduce ruido o genera demasiadas alertas? | Alertas/dia, entity-days/dia y politicas calibradas. |

En una lectura operacional, no se exige que el modelo emita automaticamente un incidente de alta confianza para cada fila. Se evalua si puede actuar como **capa de priorizacion y enriquecimiento** dentro del SIEM.

## Conceptos Clave

| Concepto | Significado |
| --- | --- |
| Ventana | Agregacion temporal de eventos o actividad. En vez de analizar cada evento crudo, se agrupa comportamiento por intervalos. |
| Entidad | Host, usuario, equipo, origen, destino o identificador operacional que puede investigarse. |
| Entity-day | Par `(entidad, dia)`. Sirve para decir: esta entidad en este dia merece investigacion. |
| Exact window | Ventana donde cae actividad red-team exacta. |
| Context-60m | Ventana dentro de un contexto cercano a actividad red-team, por ejemplo alrededor de una hora. |
| Ranking | Orden de riesgo generado por el modelo. Cuanto mas arriba aparece una ventana o entidad red-team, mas util es para triage. |
| Politica calibrada | Regla de seleccion decidida en validacion y aplicada en test, evitando ajustar umbrales mirando el test. |

## Evolucion De Resultados

### 1. Baseline Inicial

En el primer planteamiento, CSR-LANL mostraba el problema clasico del desbalance. Los modelos podian tener metricas aparentemente buenas, pero detectaban muy pocas ventanas red-team con bajo presupuesto de alertas.

Resultados iniciales sobre `date`:

| Modelo | Top-100 ventanas | Top-500 ventanas | Top-100 entidades | Top-500 entidades | Lectura |
| --- | ---: | ---: | ---: | ---: | --- |
| IsolationForest | 1/38 | 1/38 | 3/15 | 5/15 | Mejor low-budget por ventana, pero PR-AUC global debil. |
| HGB binario balanceado | 0/38 | 1/38 | 3/15 | 8/15 | Mejor ranking de entidades, pero demasiados falsos positivos si se usa umbral directo. |
| HGB multiclass | 0/38 | 2/38 | 0/15 | 2/15 | Encuentra algo a presupuesto alto, pero es ruidoso. |

Interpretacion:

- No era suficiente presentar CSR-LANL como clasificacion fila a fila.
- HGB tenia algo de senal por entidad.
- IsolationForest tenia algo de senal de rareza, pero debil si se evaluaba como detector directo de ventanas.

### 2. Features Temporales Y De Historial De Entidad

Despues se agregaron features causales temporales y de historial por entidad. Estas features intentan capturar si una entidad se comporta de forma distinta a su pasado.

Resultado HGB binario balanceado en `date`:

| Perfil | Run | Primer ataque | Top-100 ventanas | Top-500 ventanas | Top-100 entidades | Top-500 entidades |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Baseline auth/flow | `20260520_225134` | 121 | 0/38 | 1/38 | 3/15 | 8/15 |
| Temporal entity history | `20260526_145328` | 22 | 4/38 | 7/38 | 4/15 | 8/15 |
| Temporal rarity/multi-scale | `20260527_144125` | 72 | 2/38 | 3/38 | 5/15 | 7/15 |

Interpretacion:

- Las features temporales mejoraron mucho el ranking directo: el primer ataque bajo de rank 121 a rank 22.
- El top-500 paso de 1/38 a 7/38.
- Esto demuestra que el historico de entidad aporta valor real.
- La mejora seguia siendo limitada para deteccion exacta de todas las ventanas.

### 3. Politicas Entity-Calibrated

Se cambio la evaluacion hacia una lectura mas SOC: en vez de seleccionar ventanas individuales, se seleccionan entidades o entity-days para investigacion.

Ejemplos importantes:

| Experimento | Politica | Entity-days seleccionados | Entidades red-team | Ventanas red-team | Dias de ataque | Lectura |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Date temporal HGB | `entity_budget_daily_25_on_val` | 47 | 2/15 | 9/38 | 1/3 | Mejor cobertura moderada en temporal. |
| Date temporal rarity HGB | `entity_budget_daily_25_on_val` | 92 | 3/15 | 15/38 | 2/3 | Mejor lectura entity-day en `date`. |
| Fold temporal rarity HGB | `entity_budget_daily_25_on_val` | 316 | 4/5 | 4/522 | 2/14 | Buena cobertura de entidades, baja cobertura de ventanas. |

Interpretacion:

- La evaluacion entity-day es mas parecida a como trabajaria un analista SOC.
- Se puede decir: revisa estas entidades/dias, no revises millones de filas.
- La cobertura por entidad mejora, pero la cobertura de ventanas exactas sigue siendo dificil.

### 4. Split Red-Team-Stratified GroupKFold

El split `groupkfold/fold_0` original no era defendible porque tenia solo 1 ventana red-team y 1 entidad en test. Por eso se creo `redteam_stratified_groupkfold/fold_0`, que conserva separacion por entidades y aumenta soporte red-team.

Soporte validado:

| Split | Filas | Ventanas red-team | Entidades red-team | Dias de ataque |
| --- | ---: | ---: | ---: | ---: |
| Train | 13,286,691 | 507 | 223 | 18 |
| Val | 4,428,897 | 169 | 74 | 14 |
| Test | 4,428,898 | 522 | 5 | 14 |

Resultados en test:

| Modelo | Run | Primer ataque | Top-100 ventanas | Top-500 ventanas | Top-50 entidades | Top-500 entidades | Lectura |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| HGB binario balanceado | `20260526_140337` | 8 | 3/522 | 3/522 | 3/5 | 4/5 | Mejor senal low-budget base. |
| Temporal entity history | `20260526_150731` | 7 | 2/522 | 3/522 | 2/5 | 4/5 | Antes en first-hit, sin mejorar recall global. |
| Temporal rarity/multi-scale | `20260527_151925` | 4 | 3/522 | 3/522 | 3/5 | 4/5 | Mejor first-hit exacto. |

Interpretacion:

- El mejor resultado exacto de ranking global sigue siendo temporal/rarity HGB: primer ataque en rank 4.
- Aun asi, top-500 solo cubre 3/522 ventanas, por lo que no se puede vender como detector exacto completo.
- Si se evalua por entidades, encuentra 4/5 entidades red-team en top-500.

### 5. Identity V3

V3 cambio la formulacion: anadio etiquetas de contexto y entity-day, features causales de identidad, sampling mas controlado y evaluacion SOC mas explicita.

Resumen del dataset V3:

| Elemento | Valor |
| --- | ---: |
| Ventanas finales | 2,000,000 |
| Ventanas exactas red-team | 65 |
| Ventanas context-60m | 2,128 |
| Ventanas entity-day | 4,112 |
| Entidades red-team | 20 |
| Red-team entity-days | 23 |

Soporte V3 por split:

| Split | Train exact | Val exact | Test exact | Lectura |
| --- | ---: | ---: | ---: | --- |
| `date` | 47 | 12 | 6 | Temporal, pero test muy escaso. |
| `redteam_stratified_groupkfold/fold_0` | 21 | 10 | 34 | Mejor test V3 para generalizacion por entidades. |

Resultados V3 principales:

| Split | Modelo / etiqueta | Test attacks | First rank | Top-500 recall | Entity top-50 | Entity-day daily-25 | Entity policy daily-25 window recall | Lectura |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `date` | HGB binary / exact | 6 | 9,696 | 0/6 | 0/2 | 0/2 | 0/6 | No util en exact temporal. |
| `date` | IsolationForest / entity-day | 818 | 168 | 5/818 | 2/6 | 2/6 | 310/818 | Mejor triage V3 en `date`. |
| `fold_0` | HGB binary / entity-day | 1,415 | 112 | 28/1,415 | 1/4 | 1/6 | 324/1,415 | Tiene senal, pero inferior a IsolationForest. |
| `fold_0` | IsolationForest / exact | 34 | 3,193 | 0/34 | 2/4 | 4/6 | 32/34 | Excelente cobertura exacta via entity-day. |
| `fold_0` | IsolationForest / entity-day | 1,415 | 1,282 | 0/1,415 | 2/4 | 4/6 | 1,327/1,415 | Mejor resultado V3 entity-day. |
| `fold_0` | Hybrid / exact | 34 | 4,182 | 0/34 | 2/4 | 3/6 | 31/34 | Buen baseline interpretable, algo inferior. |
| `fold_0` | HGB multiclass / all labels | 34-1,415 | 3,718-8,333 | 0 | 0 | 0 | 0 | Sin valor operacional en V3. |

Interpretacion V3:

- V3 no mejora el ranking exacto global frente al temporal/rarity HGB antiguo.
- V3 si mejora mucho la lectura de triage entity-day.
- IsolationForest V3 es el mejor modelo para priorizacion entity-day.
- HGB multiclass V3 debe tratarse como ablation negativa.
- Hybrid SOC score es util como baseline explicable, pero queda ligeramente por debajo de IsolationForest.

## Que Podemos Utilizar En Un SOC

El modelo se puede utilizar como **capa de scoring y priorizacion** dentro de SIEM/IDS/IPS, no como unica fuente de verdad.

### Salida esperada del modelo

La salida ideal no seria simplemente:

```text
ATTACK = true / false
```

Seria algo mas operacional:

```text
entity: C12345
day_index: 87
risk_score: 0.94
risk_type: anomaly_entity_day
evidence:
  - comportamiento distinto al historico de la entidad
  - nuevas relaciones origen-destino
  - actividad fuera del patron habitual
  - score alto en ventana/entity-day
recommended_action:
  - revisar autenticaciones de la entidad
  - revisar destinos internos contactados
  - correlacionar con alertas SIEM/IDS
  - comprobar eventos de host si existen
```

### Usos concretos

| Uso | Como se aplicaria |
| --- | --- |
| Priorizacion diaria | Generar un top de entidades o entity-days sospechosos para revisar. |
| Enriquecimiento SIEM | Anadir `anomaly_score`, `entity_risk_score` o `entity_day_risk` a eventos. |
| Correlacion con IDS/IPS | Subir prioridad si una alerta Suricata/Zeek afecta a una entidad con score alto. |
| Threat hunting | Proponer hipotesis de investigacion: entidad, dia, relaciones y ventanas relevantes. |
| Reduccion de ruido | No convertir cada anomalia en incidente, sino agrupar por entidad/dia. |
| Watchlists | Mantener entidades de alto riesgo bajo observacion temporal. |
| Respuesta limitada | Ejecutar acciones solo si el score ML coincide con reglas, contexto y evidencias adicionales. |

## Que Pretende Prevenir O Detectar

CSR-LANL ayuda sobre todo a **deteccion temprana y priorizacion** de actividad interna sospechosa. No previene por si solo, pero puede reducir el tiempo de permanencia del atacante si se integra en un flujo SOC.

| Amenaza | Que aportaria el modelo |
| --- | --- |
| Compromiso de credenciales | Detectar entidades cuyo patron de autenticacion o comunicacion cambia. |
| Movimiento lateral | Priorizar hosts con nuevas relaciones internas o comportamiento inusual. |
| Reconocimiento interno | Detectar aumento de destinos, puertos o patrones de conexion poco habituales. |
| Abuso de cuentas validas | Senalar actividad rara aunque no exista firma IDS. |
| Actividad low-and-slow | Acumular senales debiles por entidad/dia. |
| Persistencia o exploracion | Detectar recurrencia anomala en dias o entidades concretas. |

## Como Encaja Con SIEM + IDS/IPS + IA

CSR-LANL encaja en la parte de IA/anomalia y correlacion del TFM.

Flujo propuesto:

1. El SIEM ingiere eventos de autenticacion, red y host.
2. El IDS/IPS genera alertas por firmas, protocolos o anomalias conocidas.
3. El modulo IA calcula scores por ventana, entidad y entity-day.
4. El SIEM correlaciona:
   - score ML alto,
   - alerta IDS,
   - criticidad del activo,
   - horario anomalo,
   - destino nuevo o raro,
   - historial de la entidad.
5. Se genera una prioridad:
   - senal baja,
   - alerta media,
   - incidente de alta confianza,
   - respuesta limitada si se cumplen salvaguardas.

Ejemplo de regla hibrida:

```text
IF entity_day_risk >= 0.90
AND entity has new internal destinations
AND Suricata/Zeek reports suspicious activity
AND asset criticality >= medium
THEN create medium/high priority SOC case
```

## Que No Debe Hacer El Modelo

Es importante no sobredimensionar el resultado.

El modelo no deberia usarse para:

- bloquear automaticamente hosts solo por score ML,
- afirmar que detecta todos los ataques exactos,
- sustituir reglas IDS/IPS,
- sustituir investigacion humana,
- tomar decisiones de respuesta sin contexto,
- medir exito por accuracy.

El uso correcto es:

> Priorizar, enriquecer, correlacionar y reducir el espacio de investigacion.

## Por Que IsolationForest V3 Tiene Sentido

IsolationForest es no supervisado. Esto encaja con CSR-LANL porque los ejemplos red-team son escasos y no necesariamente representan todos los ataques futuros.

Ventajas:

- no depende tanto de tener muchas etiquetas positivas,
- busca rareza respecto al comportamiento normal,
- encaja con deteccion de amenazas desconocidas,
- funciona bien como score auxiliar de riesgo,
- aporta una lectura natural para triage entity-day.

Limitaciones:

- no explica tan bien como una regla directa por que algo es anomalo,
- puede marcar rarezas benignas,
- no debe usarse como decision final aislada,
- necesita correlacion y calibracion operacional.

## Interpretacion Final De Los Resultados

La lectura mas importante es esta:

> En CSR-LANL, la contribucion principal no es la clasificacion exacta de eventos individuales, sino la priorizacion operacional de entidades bajo desbalance extremo.

El resultado de IsolationForest V3 significa:

- el modelo no es excelente como ranking global de ventanas exactas,
- pero si selecciona entity-days donde aparecen casi todas las ventanas exactas relevantes,
- por tanto es util para decirle al SOC donde mirar,
- reduce el problema desde millones de eventos hacia un subconjunto investigable,
- debe integrarse con SIEM, IDS/IPS y contexto de activos.

Frase defendible para el TFM:

> En CSR-LANL, el mejor resultado obtenido corresponde a una lectura SOC de priorizacion entity-centric. IsolationForest V3, evaluado sobre `redteam_stratified_groupkfold/fold_0`, cubre 32 de 34 ventanas exactas red-team mediante una politica de entity-day, mostrando que el modelo puede reducir el espacio de investigacion y priorizar entidades sospechosas bajo desbalance extremo. El modelo no debe interpretarse como un clasificador automatico perfecto de eventos, sino como una capa de scoring y triage integrada en una arquitectura SIEM + IDS/IPS + IA.

## Conclusion

CSR-LANL es una pieza fuerte del TFM si se presenta correctamente:

- no como benchmark de accuracy,
- no como detector exacto autonomo,
- si como experimento de SOC triage,
- si como evidencia de que la IA puede priorizar entidades sospechosas,
- si como demostracion de que las metricas operacionales son imprescindibles.

El valor practico del modelo es ayudar a detectar antes comportamientos internos anormales compatibles con compromiso, movimiento lateral o abuso de credenciales, reduciendo ruido y orientando la investigacion del analista.
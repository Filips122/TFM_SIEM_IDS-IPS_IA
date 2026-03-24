# AGENTS.md

## Project

This repository supports a Master's Thesis project on the design and implementation of a **real-time security monitoring and detection environment** that combines:

- a **SIEM** for centralized ingestion, normalization, correlation, alerting, and visualization,
- an **IDS/IPS** for structured network telemetry and alerts,
- an **AI/ML anomaly detection module** for identifying suspicious behavior beyond static rules.

The project goal is not just to train models, but to build and validate an **end-to-end, reproducible security analytics pipeline** in a controlled laboratory environment.

---

## Thesis Goal

Design, implement, and evaluate an architecture that:

1. monitors security events in near real time,
2. correlates multi-source telemetry,
3. improves detection of suspicious activity,
4. reduces false positives and alert fatigue,
5. supports limited and safe automated response.

The thesis must balance two dimensions:

- **security engineering**: SIEM, IDS/IPS, ingestion, normalization, dashboards, alerting, correlation, response,
- **analytics**: feature extraction, model training, anomaly scoring, comparison of methods, and evaluation.

---

## Core Technical Scope

### Data sources
The system should work with heterogeneous security telemetry, especially:

- network telemetry from **Suricata** (EVE JSON alerts, protocol metadata, anomalies),
- network telemetry from **Zeek** (transaction/protocol logs such as `conn.log`, `dns.log`, `http.log`, `ssl.log`),
- SIEM-ingested security and system events,
- optionally host/authentication logs for richer correlation.

### Platform components
Expected architecture:

- **SIEM layer**: Elastic Security, Wazuh, Splunk, or a justified equivalent,
- **IDS/IPS layer**: Suricata and/or Zeek,
- **ML layer**: Python-based pipeline for preprocessing, feature extraction, training, inference, and score generation,
- **integration layer**: anomaly scores or classifications must be reinjected into the SIEM for alerting, prioritization, and correlation.

### Detection approach
The target design is **hybrid**, not purely rule-based and not purely ML-based:

- signatures/rules for known threats,
- anomaly detection for unknown, rare, or low-and-slow behavior,
- contextual enrichment and correlation to reduce noise.

---

## What the Agent Should Prioritize

1. **Operational realism**
   - Favor designs that can be deployed and tested in a lab.
   - Keep the pipeline reproducible and explainable.
   - Prefer structured logs and measurable workflows over vague conceptual proposals.

2. **Low false positives**
   - Treat alert fatigue as a primary problem.
   - Avoid proposing systems where every anomaly becomes an incident.
   - Use thresholds, correlation, deduplication, risk scoring, and context.

3. **Near-real-time processing**
   - Prefer streaming or short-window analysis over offline-only approaches.
   - Think in event windows such as 1-minute and 5-minute aggregation.

4. **Unknown-threat detection**
   - Include non-supervised or semi-supervised methods able to detect deviations from baseline behavior.
   - Consider concept drift and model recalibration.

5. **Explainability and academic defensibility**
   - Any model, architecture, or threshold should be easy to justify in a thesis defense.
   - Simpler, robust baselines are preferable to complex models without clear benefit.

---

## Datasets to Use

The thesis should clearly separate **dataset purpose by phase**.

### Recommended dataset plan

#### Phase A - Prototype and streaming validation
Use **CIC-IDS2017**.

Why:
- includes PCAPs and labeled flows,
- useful for replaying traffic,
- supports measuring end-to-end latency from capture to alert.

#### Phase B - False-positive reduction through multi-source correlation
Use **TON_IoT**.

Why:
- combines network, telemetry, and logs,
- better suited for correlation across sources,
- helpful for calibrating risk scoring and reducing weak isolated alerts.

#### Phase C - Unknown anomalies and drift
Use **UGR'16**.

Why:
- based on real traffic at flow level,
- suitable for long-term behavior analysis,
- useful for baseline learning and concept drift evaluation.

#### Phase D - Realistic final validation
Use:
- **CTU-13**,
- **Unit 42 PCAPs**.

Why:
- provide more realistic or less academic validation scenarios,
- help test whether the pipeline generalizes beyond standard benchmark patterns.

#### Phase E - Custom laboratory dataset
Create a **small proprietary lab dataset**.

Why:
- this provides the strongest thesis value,
- it demonstrates applicability in the exact integrated environment,
- it allows controlled ground truth labeling by scenario.

### Additional public datasets worth considering
Depending on the chosen experiments, the agent may also reference:

- **UNSW-NB15** for supervised NIDS benchmarking,
- **Bot-IoT** for large-scale IoT/botnet, DoS/DDoS, scan, and exfiltration scenarios,
- public log anomaly datasets such as **HDFS**, **BGL**, or **OpenStack** if a log-sequence anomaly angle is added.

---

## Data Handling Guidance

The agent should favor storing and processing:

- flow/network metadata: duration, bytes, packets, ports, flags,
- temporal features over windows,
- Zeek protocol logs,
- Suricata alerts and protocol events,
- host/system/authentication events when available,
- explicit labels: benign/anomalous or attack type depending on the experiment.

Do not assume public datasets are fully representative of production. The thesis should explicitly acknowledge dataset bias and justify the use of lab-generated data and realistic PCAP validation.

---

## Recommended Modeling Strategy

### Start with strong, explainable baselines
The preferred initial models are:

- **Isolation Forest**,
- **One-Class SVM**,
- **PCA / Robust PCA**,
- **Autoencoder** (lightweight),
- optionally a sequential model such as **LSTM** or **Transformer** only if justified by time and data quality.

### Supervised models
If sufficient labels are available, use simple and robust supervised baselines such as:

- **Random Forest**,
- **Gradient Boosting**.

Probability calibration is encouraged so that model outputs can be used as interpretable risk signals.

### General rule
Do not jump to deep learning by default. Start simple, compare fairly, and only increase complexity if results justify it.

---

## Preferred Detection Logic

The most aligned approach is a **hybrid risk scoring policy** that combines:

- **Signature/IDS score** from Suricata,
- **Anomaly score** from ML,
- **Context score** from SIEM enrichment,
- **Correlation score** from accumulated evidence across sources/entities/time.

Work per:

- entity: `src_ip`, `dst_ip`, `host`, `user`, or communication pair,
- time window: typically `1 min` and `5 min`.

The agent should design outputs that support:

- low-priority signal,
- medium-priority alert,
- high-confidence incident,
- limited auto-response only under strict safeguards.

False-positive control mechanisms should include:

- deduplication,
- alert rate limiting,
- allowlists / exceptions,
- analyst feedback or temporary suppression of confirmed benign behavior.

---

## Feature Engineering Guidance

### Zeek-derived features
Useful examples:

- number of connections,
- TCP/UDP distribution,
- average/median duration,
- bytes in/out and ratios,
- failed connections,
- unique destinations and ports,
- DNS volume, unique domains, NXDOMAIN rate,
- TLS/SNI rarity or sudden changes.

### Suricata-derived features
Useful examples:

- alert counts by severity/category,
- repeated vs unique alerts,
- protocol anomaly events,
- top signatures and frequency.

### SIEM/context features
Useful examples:

- asset criticality,
- network segment (DMZ/internal),
- asset role,
- novelty or first-seen indicators over a lookback period,
- anomalous schedule / off-hours behavior.

---

## Evaluation Requirements

The thesis must be evaluated both as an ML project and as a SOC-oriented engineering project.

### ML metrics
When labels exist, prioritize:

- Precision,
- Recall,
- F1-score,
- PR-AUC,
- FPR,
- ROC-AUC if appropriate.

### Operational metrics
These are especially important:

- end-to-end latency from capture to alert,
- number of alerts per day / per time window,
- reduction in redundant alerts after correlation,
- stability under streaming ingestion,
- usefulness of prioritization for analyst triage.

### Comparative design
The preferred evaluation compares at least three settings:

1. rules/signatures only,
2. anomaly detection only,
3. hybrid scoring and correlation.

The hybrid approach is the target final solution.

---

## Constraints the Agent Must Respect

- Keep the project **reproducible**.
- Prefer **open, scriptable, lab-friendly workflows**.
- Avoid designs that depend on unavailable enterprise-only features unless clearly marked as optional.
- Keep the implementation feasible for a Master's Thesis scope.
- Be explicit about assumptions, limitations, and trade-offs.
- Treat concept drift, dataset bias, and explainability as first-class concerns.
- Any automated response must be **limited, safe, and clearly governed**.

---

## Expected Deliverables

The agent should help produce content and artifacts such as:

- architecture diagrams,
- dataset selection rationale,
- methodology section drafts,
- feature engineering specifications,
- experiment design,
- model comparison tables,
- SIEM/IDS integration notes,
- evaluation framework and metric tables,
- reproducible scripts and structured documentation.

---

## Writing Style for Thesis Support

When generating thesis material, the agent should:

- write in a formal academic-technical style,
- prefer precise and defensible claims,
- distinguish clearly between proposed design, implemented system, and evaluated results,
- avoid hype around AI,
- emphasize reproducibility, operational realism, and measurable outcomes.

---

## One-Sentence Project Summary

This thesis builds and evaluates a reproducible SIEM + IDS/IPS + AI architecture for near-real-time anomaly detection and correlation, with the goal of improving detection of suspicious activity while reducing false positives and enabling controlled automated response.

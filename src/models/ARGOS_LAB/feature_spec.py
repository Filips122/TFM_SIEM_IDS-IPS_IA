#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Single source of truth for ARGOS-LAB feature groups and label policy.

The ARGOS-LAB export ships weak labels produced by a rule engine
(`lab_alerts_weak_label_v1`). Profiling the 1.46M alerts shows that policy is
almost perfectly recoverable from a handful of raw fields:

    rule_groups=authentication_failed -> 100.00% ATTACK   (849,049 rows)
    rule_groups=invalid_login         -> 100.00% ATTACK   (771,290 rows)
    rule_groups=trivy                 -> 100.00% BENIGN   (410,611 rows)
    decoder_name=trivy-decoder        -> 100.00% BENIGN   (410,611 rows)
    agent_id=003                      ->  99.96% BENIGN   (410,737 rows)

Training on those fields measures how well a model memorises the labelling
rule, not how well it detects intrusions. Features are therefore split into
three groups so every experiment states which information it was allowed to
use.

BEHAVIORAL  Volume, source diversity, entropy, geography, novelty and
            per-agent temporal baselines. None of these were inputs to the
            weak-label policy, so they carry the honest signal.
CONTEXT     agent_id and calendar position. Legitimate operational features in
            production, but confounded in this capture (one agent is the
            vulnerability scanner, and that scan runs on a fixed cron).
SIGNATURE   Rule id/level/groups, MITRE tags, decoder and program. These are
            the labelling policy's own inputs. Included only to quantify the
            leak, never to claim detection performance.
"""

from __future__ import annotations

BEHAVIORAL_FEATURES = [
    # --- volume and rate ---------------------------------------------------
    "alert_count",
    "log_alert_count",
    "span_seconds",
    "alerts_per_second",
    "mean_interarrival",
    "std_interarrival",
    "min_interarrival",
    "burstiness_index",
    # --- source diversity --------------------------------------------------
    "unique_src_ip",
    "unique_src_user",
    "unique_dst_user",
    "unique_src_port",
    "src_ip_entropy",
    "src_ip_entropy_norm",
    "top_src_ip_share",
    "src_user_entropy",
    "src_user_entropy_norm",
    "top_src_user_share",
    "src_port_entropy_norm",
    # --- combined ratios (several raw columns mixed together) --------------
    "alerts_per_src_ip",
    "users_per_src_ip",
    "ports_per_src_ip",
    "alerts_per_src_user",
    "src_ip_present_ratio",
    "src_port_present_ratio",
    "dst_user_present_ratio",
    # --- geography ---------------------------------------------------------
    "unique_country",
    "unique_city",
    "country_entropy_norm",
    "top_country_share",
    "geo_missing_ratio",
    "geo_lat_mean",
    "geo_lon_mean",
    "geo_lat_std",
    "geo_lon_std",
    "geo_spread",
    # --- novelty and persistence (causal: only past windows) ---------------
    "new_src_ip_count",
    "new_src_ip_ratio",
    "repeat_src_ip_ratio",
    "new_src_user_count",
    "new_src_user_ratio",
    "mean_src_ip_seen_before",
    "max_src_ip_seen_before",
    # --- credential targeting ----------------------------------------------
    "root_user_ratio",
    "system_user_ratio",
    # --- per-agent temporal baseline (causal) ------------------------------
    "agent_gap_seconds",
    "agent_count_lag1",
    "agent_count_lag2",
    "agent_count_roll_mean",
    "agent_count_roll_std",
    "agent_count_z",
    "agent_uniqip_roll_mean",
    "agent_uniqip_z",
    "agent_window_index",
]

CONTEXT_FEATURES = [
    "agent_id_code",
    "event_hour",
    "hour_sin",
    "hour_cos",
    "day_of_week",
    "is_weekend",
    "is_night",
]

SIGNATURE_FEATURES = [
    "rule_level_mean",
    "rule_level_max",
    "rule_level_min",
    "rule_level_std",
    "rule_level_sum",
    "rule_level_range",
    "level_ge_7_count",
    "level_ge_10_count",
    "level_ge_12_count",
    "level_ge_7_ratio",
    "unique_rule_count",
    "rule_entropy_norm",
    "top_rule_share",
    "rule_firedtimes_mean",
    "rule_firedtimes_max",
    "rule_firedtimes_sum",
    "mitre_tagged_ratio",
    "credential_tactic_ratio",
    "lateral_tactic_ratio",
    "impact_tactic_count",
    "evasion_tactic_count",
    "grp_auth_failed_ratio",
    "grp_invalid_login_ratio",
    "grp_sshd_ratio",
    "grp_pam_ratio",
    "grp_trivy_ratio",
    "grp_agent_flooding_ratio",
    "grp_syscheck_ratio",
    "grp_sca_ratio",
    "grp_ossec_ratio",
    "grp_dpkg_ratio",
    "grp_syslog_ratio",
    "unique_decoder_count",
    "unique_location_count",
    "decoder_code",
    "program_code",
    "location_code",
]

FEATURE_COLUMNS = BEHAVIORAL_FEATURES + CONTEXT_FEATURES + SIGNATURE_FEATURES

FEATURE_GROUPS = {
    "behavioral": BEHAVIORAL_FEATURES,
    "context": CONTEXT_FEATURES,
    "signature": SIGNATURE_FEATURES,
}

# Named feature regimes used by every training script via --feature_set.
FEATURE_SETS = {
    # Everything. Reproduces the leak on purpose; a ceiling, not a result.
    "full": BEHAVIORAL_FEATURES + CONTEXT_FEATURES + SIGNATURE_FEATURES,
    # Drops the labelling policy's own inputs but keeps agent/calendar.
    "nosignature": BEHAVIORAL_FEATURES + CONTEXT_FEATURES,
    # Strictest regime: behaviour only. This is the honest detection score.
    "behavioral": BEHAVIORAL_FEATURES,
}

META_COLUMNS = [
    "window_start",
    "agent_id",
    "agent_name",
    "top_rule_id",
    "top_rule_description",
    "top_decoder",
    "top_program",
    "top_location",
    "top_country",
    "posture_ratio",
    "attack_alert_count",
    "benign_alert_count",
    "unknown_alert_count",
    "binary_target",
    "activity_target",
    "taxonomy_target",
]

# --- alert-level taxonomy used to build the multiclass target ---------------
# Derived from rule groups / rule ids: the activity family that produced the
# window. Reported alongside the dataset's own `taxonomy_label`, which is
# degenerate here (2 classes cover 99.99% of rows).
ACTIVITY_CLASSES = [
    "CredentialBrute",
    "PamAuth",
    "SshOperational",
    "PostureVuln",
    "PostureSCA",
    "AgentHealth",
    "IntegrityChange",
    "PackageChange",
    "PortChange",
    "Other",
]

# rule_groups values that mark a posture / vulnerability-scanner finding.
# 97.8% of BENIGN rows come from these, so `--exclude_posture` removes them to
# expose the genuinely hard task.
POSTURE_GROUPS = {"trivy", "sca", "vulnerability-detector", "syscheck", "syscheck_file", "rootcheck"}
POSTURE_DECODERS = {
    "trivy-decoder",
    "sca",
    "rootcheck",
    "syscheck_integrity_changed",
    "syscheck_new_entry",
    "syscheck_deleted",
}

# Service / system accounts commonly hit by credential-stuffing dictionaries.
SYSTEM_USERS = {
    "root", "admin", "administrator", "ubuntu", "debian", "centos", "oracle",
    "postgres", "mysql", "www-data", "test", "guest", "user", "deploy", "git",
    "ftp", "nagios", "jenkins", "docker", "pi", "operator", "support",
}


def activity_class(groups: set[str], rule_id: str) -> str:
    """Map a single alert to its activity family."""
    if "trivy" in groups or "vulnerability-detector" in groups:
        return "PostureVuln"
    if "sca" in groups:
        return "PostureSCA"
    if "agent_flooding" in groups or rule_id in {"202", "203", "205"}:
        return "AgentHealth"
    if groups & {"syscheck", "syscheck_file", "rootcheck"}:
        return "IntegrityChange"
    if "dpkg" in groups or rule_id in {"2902", "2903", "2904"}:
        return "PackageChange"
    if rule_id == "533":
        return "PortChange"
    if groups & {"authentication_failed", "authentication_failures", "invalid_login", "access_control"}:
        return "CredentialBrute"
    if "pam" in groups:
        return "PamAuth"
    if "sshd" in groups:
        return "SshOperational"
    return "Other"


def is_posture_alert(groups: set[str], decoder_name: str) -> bool:
    return bool(groups & POSTURE_GROUPS) or decoder_name in POSTURE_DECODERS


def resolve_feature_set(name: str) -> list[str]:
    if name not in FEATURE_SETS:
        raise SystemExit(f"Unknown feature_set '{name}'. Choose from: {sorted(FEATURE_SETS)}")
    return list(FEATURE_SETS[name])


# ---------------------------------------------------------------------------
# Escala-libres ("shape"): ratios, entropias, cuotas y puntuaciones z.
#
# Motivacion medida: con las 54 features `behavioral` se predice QUE AGENTE es
# con 99,75% de exactitud, pese a que `agent_id_code` no esta entre ellas. La
# identidad del host esta codificada de forma redundante en su perfil de
# actividad (agente 030: src_ip_present_ratio=0.000, geo_missing_ratio=1.000;
# agente 003: alert_count medio 2072). Quitar una columna no elimina un
# confundido repartido entre variables correlacionadas.
#
# Este subconjunto excluye toda magnitud absoluta y deja solo cantidades
# adimensionales, comparables entre maquinas de escala distinta.
# ---------------------------------------------------------------------------
BEHAVIORAL_SHAPE = [
    "burstiness_index", "mean_interarrival", "std_interarrival", "min_interarrival",
    "src_ip_entropy_norm", "top_src_ip_share", "src_user_entropy_norm", "top_src_user_share",
    "src_port_entropy_norm", "alerts_per_src_ip", "users_per_src_ip", "ports_per_src_ip",
    "alerts_per_src_user", "src_ip_present_ratio", "src_port_present_ratio",
    "dst_user_present_ratio", "country_entropy_norm", "top_country_share",
    "geo_missing_ratio", "geo_spread", "geo_lat_std", "geo_lon_std",
    "new_src_ip_ratio", "repeat_src_ip_ratio", "new_src_user_ratio",
    "root_user_ratio", "system_user_ratio", "agent_count_z", "agent_uniqip_z",
]

FEATURE_SETS["shape"] = list(BEHAVIORAL_SHAPE)
FEATURE_GROUPS["shape"] = list(BEHAVIORAL_SHAPE)

# ---------------------------------------------------------------------------
# Familias de actividad consideradas HOSTILES.
#
# El score de ataque es la suma de probabilidades de estas clases. Se define
# sobre la taxonomia de actividad -- no sobre la etiqueta binaria debil, que es
# reconstruible desde una sola columna y por tanto circular.
# ---------------------------------------------------------------------------
HOSTILE_FAMILIES = {
    "CredentialBrute",   # fuerza bruta / credential stuffing
    "PamAuth",           # fallo de autenticacion via PAM
    "IntegrityChange",   # modificacion no esperada de ficheros vigilados
}

# Familias operativas o de postura: no son ataque en curso.
BENIGN_FAMILIES = {
    "SshOperational", "AgentHealth", "PackageChange",
    "PortChange", "PostureVuln", "PostureSCA", "Other",
}


def hostile_mask(classes):
    """Vector booleano: que columnas de `classes` son familias hostiles."""
    import numpy as np
    return np.array([str(c) in HOSTILE_FAMILIES for c in classes], dtype=bool)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


DATASET_TO_DOMAIN: Dict[str, str] = {
    "UNSW-NB15": "network_tabular",
    "NUSW-NB15": "network_tabular",
    "UGR16": "network_temporal",
    "UGR16_MARAPR_HYBRID": "network_temporal",
    "LAB-ALERTS": "siem_lab_alerts",
    "COWRIE_FULL": "honeypot",
    "CIC-IDS2017": "network_sequence",
    "MachineLearningCVE": "network_sequence",
    "TrafficLabelling": "network_sequence",
    "CSR-LANL": "entity_day_triage",
}


@dataclass(frozen=True)
class RoutingDecision:
    domain: str
    reason: str


def route_dataset(dataset_key: str, source_type: Optional[str] = None) -> RoutingDecision:
    if source_type:
        normalized_source = source_type.strip().lower()
        if normalized_source in {"zeek", "suricata", "netflow", "flow"}:
            return RoutingDecision(domain="network_tabular", reason=f"source_type={source_type}")
        if normalized_source in {"siem", "alert", "lab_alert"}:
            return RoutingDecision(domain="siem_lab_alerts", reason=f"source_type={source_type}")
        if normalized_source in {"honeypot", "cowrie"}:
            return RoutingDecision(domain="honeypot", reason=f"source_type={source_type}")
        if normalized_source in {"auth", "entity_day", "csr"}:
            return RoutingDecision(domain="entity_day_triage", reason=f"source_type={source_type}")

    try:
        return RoutingDecision(domain=DATASET_TO_DOMAIN[dataset_key], reason=f"dataset_key={dataset_key}")
    except KeyError as exc:
        raise ValueError(f"No production route for dataset/source: {dataset_key}") from exc
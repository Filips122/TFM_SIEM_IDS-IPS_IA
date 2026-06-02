#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from typing import Literal


Severity = Literal["low", "medium", "high", "critical"]


def clamp_score(value: float) -> int:
    return int(max(0, min(100, round(value))))


def severity_from_score(score: int) -> Severity:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def risk_score(
    probability_attack: float,
    ids_severity: float = 0.0,
    asset_criticality: float = 0.0,
    correlation_score: float = 0.0,
) -> int:
    base = 100.0 * max(0.0, min(1.0, probability_attack))
    context_bonus = 10.0 * max(0.0, min(1.0, ids_severity))
    asset_bonus = 10.0 * max(0.0, min(1.0, asset_criticality))
    correlation_bonus = 15.0 * max(0.0, min(1.0, correlation_score))
    return clamp_score(base + context_bonus + asset_bonus + correlation_bonus)
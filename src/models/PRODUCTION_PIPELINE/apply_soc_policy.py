#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    from .model_registry import resolve_from_root
    from .threshold_optimizer import write_json
except ImportError:  # pragma: no cover - direct script fallback
    from model_registry import resolve_from_root
    from threshold_optimizer import write_json


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def nested_get(event: Dict[str, Any], dotted_key: str) -> Any:
    current: Any = event
    for part in dotted_key.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def nested_set(event: Dict[str, Any], dotted_key: str, value: Any) -> None:
    current = event
    parts = dotted_key.split(".")
    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = child
    current[parts[-1]] = value


def parse_timestamp(value: str) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def hour_bucket(timestamp: datetime) -> str:
    return timestamp.strftime("%Y-%m-%dT%H:00:00Z")


def dedupe_bucket(timestamp: datetime, window_minutes: int) -> int:
    return int(timestamp.timestamp() // (window_minutes * 60))


def event_key(event: Dict[str, Any], fields: Iterable[str], timestamp: datetime, window_minutes: int) -> Tuple[Any, ...]:
    return tuple([nested_get(event, field) for field in fields] + [dedupe_bucket(timestamp, window_minutes)])


def domain_rate_limit(policy: Dict[str, Any], domain: str, name: str, default_name: str) -> int:
    rate_limits = policy.get("rate_limits", {})
    override = rate_limits.get("domain_overrides", {}).get(domain, {})
    return int(override.get(name, rate_limits.get(default_name, 10**12)))


def domain_mode(policy: Dict[str, Any], domain: str) -> str:
    return str(policy.get("rate_limits", {}).get("domain_overrides", {}).get(domain, {}).get("mode", "alert"))


def should_downgrade_to_enrichment(event: Dict[str, Any], policy: Dict[str, Any]) -> bool:
    domain = str(nested_get(event, "ml.domain") or "")
    mode = domain_mode(policy, domain)
    min_risk = int(policy.get("incident_promotion", {}).get("standalone_incident_min_risk_score", 90))
    risk_score = int(nested_get(event, "ml.risk_score") or 0)
    return mode == "enrichment_unless_correlated" and risk_score < min_risk


def annotate_event(event: Dict[str, Any], policy: Dict[str, Any], action: str) -> None:
    nested_set(event, "labels.soc_policy_id", policy.get("policy_id"))
    nested_set(event, "labels.soc_policy_action", action)
    if action == "enrichment_only":
        nested_set(event, "event.kind", "event")


def apply_policy(events: List[Dict[str, Any]], policy: Dict[str, Any], max_events: int | None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    dedup = policy.get("deduplication", {})
    window_minutes = int(dedup.get("window_minutes", 15))
    key_fields = dedup.get("key_fields", ["ml.model_id", "event.dataset", "entity.id", "ml.prediction"])
    keep_highest = bool(dedup.get("keep_highest_risk_score", True))

    kept: List[Dict[str, Any]] = []
    dedupe_index: Dict[Tuple[Any, ...], int] = {}
    entity_counts: Dict[Tuple[str, str, str], int] = defaultdict(int)
    model_counts: Dict[Tuple[str, str], int] = defaultdict(int)
    summary = {
        "events_read": len(events),
        "events_kept": 0,
        "dropped_duplicates": 0,
        "dropped_rate_limited_entity": 0,
        "dropped_rate_limited_model": 0,
        "downgraded_to_enrichment": 0,
        "policy_id": policy.get("policy_id"),
    }

    for event in events:
        timestamp = parse_timestamp(str(event.get("@timestamp", "")))
        key = event_key(event, key_fields, timestamp, window_minutes)
        risk_score = int(nested_get(event, "ml.risk_score") or 0)
        if key in dedupe_index:
            summary["dropped_duplicates"] += 1
            if keep_highest:
                existing_index = dedupe_index[key]
                existing_score = int(nested_get(kept[existing_index], "ml.risk_score") or 0)
                if risk_score > existing_score:
                    annotate_event(event, policy, "kept_replaced_duplicate")
                    kept[existing_index] = event
            continue

        domain = str(nested_get(event, "ml.domain") or "")
        model_id = str(nested_get(event, "ml.model_id") or "")
        entity_id = str(nested_get(event, "entity.id") or "")
        hour = hour_bucket(timestamp)
        entity_key = (domain, entity_id, hour)
        model_key = (model_id, hour)
        entity_limit = domain_rate_limit(policy, domain, "max_alerts_per_entity_per_hour", "default_max_alerts_per_entity_per_hour")
        model_limit = domain_rate_limit(policy, domain, "max_alerts_per_model_per_hour", "default_max_alerts_per_model_per_hour")
        if entity_counts[entity_key] >= entity_limit:
            summary["dropped_rate_limited_entity"] += 1
            continue
        if model_counts[model_key] >= model_limit:
            summary["dropped_rate_limited_model"] += 1
            continue

        action = "kept"
        if should_downgrade_to_enrichment(event, policy):
            action = "enrichment_only"
            summary["downgraded_to_enrichment"] += 1
        annotate_event(event, policy, action)
        dedupe_index[key] = len(kept)
        entity_counts[entity_key] += 1
        model_counts[model_key] += 1
        kept.append(event)
        if max_events is not None and len(kept) >= max_events:
            break

    summary["events_kept"] = len(kept)
    summary["created_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return kept, summary


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                events.append(json.loads(stripped))
    return events


def write_jsonl(path: Path, events: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def default_output(input_path: Path) -> Tuple[Path, Path]:
    output_path = input_path.with_name(input_path.stem + "_soc_filtered.jsonl")
    summary_path = input_path.with_name(input_path.stem + "_soc_summary.json")
    return output_path, summary_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply SOC deduplication and rate-limit policy to production JSONL events.")
    parser.add_argument("--input_jsonl", required=True)
    parser.add_argument("--policy_json", default="src/models/PRODUCTION_PIPELINE/policies/soc_alert_policy.production.json")
    parser.add_argument("--output_jsonl", default=None)
    parser.add_argument("--summary_output", default=None)
    parser.add_argument("--max_events", type=int, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = resolve_from_root(args.input_jsonl)
    policy = read_json(resolve_from_root(args.policy_json))
    output_path, summary_path = default_output(input_path)
    if args.output_jsonl:
        output_path = resolve_from_root(args.output_jsonl)
    if args.summary_output:
        summary_path = resolve_from_root(args.summary_output)
    kept, summary = apply_policy(read_jsonl(input_path), policy, args.max_events)
    summary["input_jsonl"] = str(input_path)
    summary["output_jsonl"] = str(output_path)
    write_jsonl(output_path, kept)
    write_json(summary_path, summary)
    print(f"Saved: {output_path}")
    print(f"Saved: {summary_path}")


if __name__ == "__main__":
    main()
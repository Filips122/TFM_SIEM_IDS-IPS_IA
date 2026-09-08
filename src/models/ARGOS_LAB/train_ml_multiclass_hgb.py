#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gradient-boosted trees for the ARGOS-LAB activity-family task.

The binary target is saturated (see leakage_audit.py), so the multiclass task
is the more informative supervised experiment: given only how an agent behaved
during a minute, which activity family produced that window?

Classes come from `activity_target` (CredentialBrute, PortChange, AgentHealth,
SshOperational, PackageChange, ...). Use `--pipeline taxonomy` to train against
the export's own `taxonomy_label` instead, which is degenerate here: two
classes cover 99.99% of alerts.

This is a thin wrapper over the shared HGB runner so the two pipelines cannot
drift apart.
"""

from __future__ import annotations

import sys

import train_ml_binary_hgb


def main() -> None:
    argv = sys.argv[1:]
    if not any(arg.startswith("--pipeline") for arg in argv):
        argv = ["--pipeline", "multiclass", *argv]
    sys.argv = [sys.argv[0], *argv]
    train_ml_binary_hgb.main()


if __name__ == "__main__":
    main()

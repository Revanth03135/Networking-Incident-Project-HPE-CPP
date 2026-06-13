# Network Incident Investigation Report

Generated: 2026-06-13T15:36:29Z

## Executive Summary
- Total incidents reconstructed: 1
- Total events analyzed: 20
- Total causal links inferred: 91
- Affected devices: unknown

## Probable Initiating Triggers
- Incident INC-0001 -> config_change (device=unknown, score=93.6)

## Incident Overview
- INC-0001: events=20, duration=1.0s, primary_issue=unknown

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
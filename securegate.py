"""SecureGate CLI demo and compatibility wrapper."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from audit import AuditLogger
from validator import ValidationPolicy, SecureGateValidator, load_samples

ROOT = Path(__file__).resolve().parent
AUDIT_LOG = ROOT / "securegate_audit.log"
validator = SecureGateValidator(policy=ValidationPolicy())
audit_logger = AuditLogger(AUDIT_LOG)


def run_demo() -> None:
    print("=" * 64)
    print("SECUREGATE — Secure Telemetry/Command Validation Simulator")
    print("Synthetic local validation only. No external command execution.")
    print("=" * 64)

    samples = load_samples()
    items = [
        ("Valid telemetry", samples["telemetry"]["valid"]),
        ("Missing telemetry field", samples["telemetry"]["invalid_missing"]),
        ("Telemetry out of range", samples["telemetry"]["invalid_range"]),
        ("Unauthorized sender", samples["telemetry"]["invalid_sender"]),
        ("Valid command", samples["commands"]["valid"]),
        ("Unauthorized command", samples["commands"]["invalid_unauthorized"]),
    ]

    accepted_count = 0
    rejected_count = 0
    for label, payload in items:
        print(f"\n--- {label} ---")
        if label in {"Valid telemetry", "Valid command"} and isinstance(payload, dict):
            payload = dict(payload)
            payload["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        result = validator.validate_message(payload)
        audit_logger.log_validation(result, payload)
        print(f"Decision: {result.decision}")
        if result.accepted:
            accepted_count += 1
        else:
            rejected_count += 1
        for finding in result.findings:
            print(f"- {finding.rule_id}: {finding.message}")

    print("\n" + "=" * 64)
    print("SESSION SUMMARY")
    print(f"Messages processed: {accepted_count + rejected_count}")
    print(f"Accepted: {accepted_count}")
    print(f"Rejected: {rejected_count}")
    print(f"Audit log: {AUDIT_LOG.name}")
    print("Note: replay state is in-memory and resets on restart.")
    print("=" * 64)


if __name__ == "__main__":
    run_demo()

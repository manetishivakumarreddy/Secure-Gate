from __future__ import annotations

import io
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from audit import AuditLogger
from validator import Finding, SecureGateValidator, ValidationPolicy, ValidationResult, load_schema, load_samples, reset_replay_state

ROOT = Path(__file__).resolve().parent
LOG_PATH = ROOT / "securegate_audit.log"

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
validator = SecureGateValidator(policy=ValidationPolicy())
audit_logger = AuditLogger(LOG_PATH)


def reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON numeric constant: {value}")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "SecureGate"})


@app.route("/api/schema")
def api_schema():
    return jsonify(load_schema())


@app.route("/api/samples")
def api_samples():
    samples = deepcopy(load_samples())
    now = datetime.now(timezone.utc)
    for category in ("telemetry", "commands"):
        for name, sample in samples.get(category, {}).items():
            if not isinstance(sample, dict) or "timestamp" not in sample:
                continue
            if name == "invalid_stale":
                sample["timestamp"] = (now - timedelta(seconds=validator.policy.max_age_seconds + 60)).isoformat()
            elif name == "invalid_future":
                sample["timestamp"] = "2099-01-01T00:00:00+00:00"
            else:
                sample["timestamp"] = now.isoformat()
    return jsonify(samples)


@app.route("/api/validate", methods=["POST"])
def api_validate():
    raw_body = request.get_data(as_text=True)
    requested_category = request.headers.get("X-Message-Category", "unknown")
    if requested_category not in {"telemetry", "command"}:
        requested_category = "unknown"
    try:
        if not raw_body.strip():
            raise ValueError("input is empty")
        payload = json.loads(raw_body, parse_constant=reject_nonstandard_json_constant)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        category = requested_category
        message_type = {"telemetry": "TELEMETRY", "command": "COMMAND"}.get(category)
        if isinstance(exc, json.JSONDecodeError):
            detail = f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        elif isinstance(exc, RecursionError):
            detail = "JSON nesting exceeds the parser limit"
        else:
            detail = str(exc)
        result = ValidationResult(
            category=category,
            accepted=False,
            sender=None,
            message_id=None,
            message_type=message_type,
            findings=[Finding("JSON_SYNTAX", detail)],
        )
        audit_logger.log_validation(result, {"raw_text": raw_body})
        return jsonify(result.to_dict())

    result = validator.validate_message(payload)
    audit_logger.log_validation(result, {"raw_text": raw_body})
    return jsonify(result.to_dict())


@app.route("/api/audit")
def api_audit():
    decision = request.args.get("decision")
    sender = request.args.get("sender")
    category = request.args.get("category")
    search = request.args.get("search")
    events = audit_logger.filter_events(decision=decision, sender=sender or None, category=category or None, search=search or None)
    return jsonify({"events": events, "count": len(events), "stats": audit_logger.stats()})


@app.route("/api/audit/export")
def api_export_audit():
    export_format = request.args.get("format", "json").lower()
    if export_format == "csv":
        response = audit_logger.export_csv()
        return response, 200, {"Content-Type": "text/csv; charset=utf-8", "Content-Disposition": "attachment; filename=securegate_audit.csv"}
    response = audit_logger.export_json()
    return response, 200, {"Content-Type": "application/json; charset=utf-8", "Content-Disposition": "attachment; filename=securegate_audit.json"}


@app.route("/api/audit/clear", methods=["POST"])
def api_clear_audit():
    audit_logger.clear()
    validator.replay_state.reset()
    reset_replay_state(validator.replay_state)
    return jsonify({"status": "ok", "message": "Audit log cleared and replay state reset."})


@app.route("/api/tests")
def api_tests():
    suite = unittest.defaultTestLoader.discover(str(ROOT), pattern="test_validator.py")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    result = runner.run(suite)
    output = stream.getvalue()
    return jsonify({
        "success": result.wasSuccessful(),
        "testsRun": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "output": output,
    })


@app.errorhandler(RequestEntityTooLarge)
def handle_large_request(_error):
    if request.endpoint == "api_validate":
        result = ValidationResult(
            category=request.headers.get("X-Message-Category", "unknown"),
            accepted=False,
            sender=None,
            message_id=None,
            message_type=None,
            findings=[Finding("JSON_SIZE", "request exceeds the 1 MiB validation limit")],
        )
        audit_logger.log_validation(result, {"raw_text": "[request body exceeded size limit]"})
        return jsonify(result.to_dict()), 413
    return jsonify({"error": "request exceeds the 1 MiB limit"}), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

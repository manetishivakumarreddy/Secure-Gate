from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "schema.json"
SAMPLES_PATH = ROOT / "samples.json"


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass
class Finding:
    rule_id: str
    message: str

    def as_dict(self) -> Dict[str, str]:
        return {"rule_id": self.rule_id, "message": self.message}


@dataclass
class ValidationResult:
    category: str
    accepted: bool
    sender: Optional[str]
    message_id: Optional[str]
    message_type: Optional[str]
    findings: List[Finding] = field(default_factory=list)

    @property
    def decision(self) -> str:
        return "ACCEPT" if self.accepted else "REJECT"

    @property
    def rule_ids(self) -> List[str]:
        return [finding.rule_id for finding in self.findings]

    @property
    def reasons(self) -> List[str]:
        return [finding.message for finding in self.findings]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "accepted": self.accepted,
            "decision": self.decision,
            "sender": self.sender,
            "message_id": self.message_id,
            "message_type": self.message_type,
            "findings": [finding.as_dict() for finding in self.findings],
        }


@dataclass
class ValidationPolicy:
    strict_fields: bool = True
    allowed_telemetry_senders: set[str] = field(
        default_factory=lambda: {"SENSOR-01", "SENSOR-02", "SENSOR-03"}
    )
    allowed_senders: set[str] = field(
        default_factory=lambda: {"SENSOR-01", "SENSOR-02", "SENSOR-03", "CONTROL-01", "OPS-CTRL", "GATEWAY-01"}
    )
    allowed_message_types: set[str] = field(default_factory=lambda: {"TELEMETRY", "COMMAND"})
    allowed_command_types: set[str] = field(
        default_factory=lambda: {"STATUS_CHECK", "SENSOR_READ", "DIAGNOSTIC_PING", "TELEMETRY_REQUEST"}
    )
    telemetry_limits: Dict[str, tuple[float, float]] = field(
        default_factory=lambda: {
            "temperature": (-40.0, 120.0),
            "voltage": (0.0, 60.0),
            "signal_strength": (0, 100),
        }
    )
    max_age_seconds: int = 300
    max_future_seconds: int = 60
    replay_protection: bool = True
    sender_permissions: Dict[str, set[str]] = field(
        default_factory=lambda: {
            "SENSOR-01": {"TELEMETRY"},
            "SENSOR-02": {"TELEMETRY"},
            "SENSOR-03": {"TELEMETRY"},
            "CONTROL-01": {"STATUS_CHECK", "SENSOR_READ", "DIAGNOSTIC_PING", "TELEMETRY_REQUEST"},
            "OPS-CTRL": {"STATUS_CHECK", "SENSOR_READ", "DIAGNOSTIC_PING", "TELEMETRY_REQUEST"},
            "GATEWAY-01": {"STATUS_CHECK", "TELEMETRY_REQUEST"},
        }
    )


class ReplayState:
    def __init__(self) -> None:
        self.accepted_ids: set[str] = set()
        self.last_sequence_by_sender: Dict[str, int] = {}

    def reset(self) -> None:
        self.accepted_ids.clear()
        self.last_sequence_by_sender.clear()


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:  # pragma: no cover - exercised through validation errors
        raise ValueError("timestamp is not valid ISO 8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _add_finding(findings: List[Finding], rule_id: str, message: str) -> None:
    findings.append(Finding(rule_id=rule_id, message=message))


class SecureGateValidator:
    def __init__(
        self,
        policy: Optional[ValidationPolicy] = None,
        replay_state: Optional[ReplayState] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self.policy = policy or ValidationPolicy()
        self.replay_state = replay_state or ReplayState()
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def validate_message(self, message: Any) -> ValidationResult:
        findings: List[Finding] = []
        if not isinstance(message, dict):
            return ValidationResult(
                category="unknown",
                accepted=False,
                sender=None,
                message_id=None,
                message_type=None,
                findings=[Finding(rule_id="JSON_OBJECT", message="message must be a JSON object")],
            )

        message_id = message.get("message_id")
        sender = message.get("sender")
        message_type = message.get("message_type")
        category = "unknown"

        if "message_type" not in message:
            _add_finding(findings, "FIELD_REQUIRED", "missing required field: message_type")
        elif not isinstance(message_type, str):
            _add_finding(findings, "FIELD_TYPE", "message_type must be a string")
        else:
            if message_type not in self.policy.allowed_message_types:
                _add_finding(findings, "MESSAGE_TYPE", f"unsupported message_type '{message_type}'")

        if message_type == "TELEMETRY":
            category = "telemetry"
            self._validate_telemetry(message, findings)
        elif message_type == "COMMAND":
            category = "command"
            self._validate_command(message, findings)

        if not isinstance(message_type, str) or message_type not in self.policy.allowed_message_types:
            return ValidationResult(
                category=category,
                accepted=False,
                sender=sender if isinstance(sender, str) else None,
                message_id=message_id if isinstance(message_id, str) else None,
                message_type=message_type if isinstance(message_type, str) else None,
                findings=findings,
            )

        if category in {"telemetry", "command"}:
            self._validate_replay(message, findings, sender, message_id)

        result = ValidationResult(
            category=category,
            accepted=not findings,
            sender=sender if isinstance(sender, str) else None,
            message_id=message_id if isinstance(message_id, str) else None,
            message_type=message_type if isinstance(message_type, str) else None,
            findings=findings,
        )
        if result.accepted and self.policy.replay_protection:
            if isinstance(message_id, str):
                self.replay_state.accepted_ids.add(message_id)
            if sender and _is_int(message.get("sequence")):
                self.replay_state.last_sequence_by_sender[sender] = int(message["sequence"])
        return result

    def _validate_telemetry(self, message: Dict[str, Any], findings: List[Finding]) -> None:
        required_root = {"message_id", "sender", "message_type", "timestamp", "sequence", "payload"}
        if self.policy.strict_fields:
            for field_name in sorted(set(message) - required_root):
                _add_finding(findings, "UNEXPECTED_FIELD", f"unexpected field: {field_name}")
        for field_name in sorted(required_root):
            if field_name not in message:
                _add_finding(findings, "FIELD_REQUIRED", f"missing required field: {field_name}")

        if not isinstance(message.get("sender"), str):
            _add_finding(findings, "FIELD_TYPE", "sender must be a string")
        elif message["sender"] not in self.policy.allowed_telemetry_senders:
            _add_finding(findings, "SENDER_ALLOWLIST", f"unauthorized sender: {message['sender']}")

        if not _is_int(message.get("sequence")):
            _add_finding(findings, "FIELD_TYPE", "sequence must be a non-boolean integer")
        elif int(message["sequence"]) < 0:
            _add_finding(findings, "SEQUENCE_RANGE", "sequence must be non-negative")

        if not isinstance(message.get("message_id"), str) or not str(message.get("message_id")).strip():
            _add_finding(findings, "FIELD_TYPE", "message_id must be a non-empty string")

        payload = message.get("payload")
        if not isinstance(payload, dict):
            _add_finding(findings, "FIELD_TYPE", "payload must be an object")
        else:
            allowed_payload_keys = {"temperature", "voltage", "signal_strength"}
            if self.policy.strict_fields:
                unexpected = sorted(set(payload.keys()) - allowed_payload_keys)
                for key in unexpected:
                    _add_finding(findings, "UNEXPECTED_FIELD", f"unexpected payload field: {key}")

            for field_name in allowed_payload_keys:
                if field_name not in payload:
                    _add_finding(findings, "FIELD_REQUIRED", f"missing required payload field: {field_name}")

            for field_name, limits in self.policy.telemetry_limits.items():
                if field_name not in payload:
                    continue
                value = payload.get(field_name)
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    _add_finding(findings, "FIELD_TYPE", f"payload.{field_name} must be a numeric value")
                    continue
                try:
                    finite = math.isfinite(value)
                except OverflowError:
                    finite = False
                if not finite:
                    _add_finding(findings, "NUMERIC_RANGE", f"payload.{field_name} must be finite")
                    continue
                if field_name == "signal_strength" and not _is_int(value):
                    _add_finding(findings, "FIELD_TYPE", "payload.signal_strength must be an integer")
                    continue
                lower, upper = limits
                if value < lower or value > upper:
                    _add_finding(findings, "NUMERIC_RANGE", f"payload.{field_name} out of range: expected {lower}..{upper}, got {value}")

        timestamp_value = message.get("timestamp")
        try:
            parsed_timestamp = parse_timestamp(timestamp_value)
        except ValueError as exc:
            _add_finding(findings, "TIMESTAMP_FORMAT", str(exc))
        else:
            now = self.clock()
            age = (now - parsed_timestamp).total_seconds()
            if age > self.policy.max_age_seconds:
                _add_finding(findings, "TIMESTAMP_FRESHNESS", f"stale timestamp: age {int(age)}s exceeds {self.policy.max_age_seconds}s")
            if age < -self.policy.max_future_seconds:
                _add_finding(findings, "TIMESTAMP_FRESHNESS", "timestamp is too far in the future")

    def _validate_command(self, message: Dict[str, Any], findings: List[Finding]) -> None:
        required_root = {"message_id", "sender", "message_type", "command", "timestamp", "sequence", "parameters"}
        if self.policy.strict_fields:
            for field_name in sorted(set(message) - required_root):
                _add_finding(findings, "UNEXPECTED_FIELD", f"unexpected field: {field_name}")
        for field_name in sorted(required_root):
            if field_name not in message:
                _add_finding(findings, "FIELD_REQUIRED", f"missing required field: {field_name}")

        sender = message.get("sender")
        if not isinstance(sender, str):
            _add_finding(findings, "FIELD_TYPE", "sender must be a string")
        command = message.get("command")
        if not isinstance(command, str):
            if "command" in message:
                _add_finding(findings, "FIELD_TYPE", "command must be a string")
        elif command not in self.policy.allowed_command_types:
            _add_finding(findings, "COMMAND_TYPE", f"unsupported command '{command}'. Permitted commands: {', '.join(sorted(self.policy.allowed_command_types))}")
        if isinstance(sender, str) and isinstance(command, str) and command in self.policy.allowed_command_types:
            allowed_commands = self.policy.sender_permissions.get(sender, set())
            if sender not in self.policy.allowed_senders or command not in allowed_commands:
                _add_finding(findings, "SENDER_ALLOWLIST", f"sender '{sender}' is not authorized for command '{command}'")

        if not isinstance(message.get("message_id"), str) or not str(message.get("message_id")).strip():
            _add_finding(findings, "FIELD_TYPE", "message_id must be a non-empty string")

        if not _is_int(message.get("sequence")):
            _add_finding(findings, "FIELD_TYPE", "sequence must be a non-boolean integer")
        elif int(message["sequence"]) < 0:
            _add_finding(findings, "SEQUENCE_RANGE", "sequence must be non-negative")

        parameters = message.get("parameters")
        if not isinstance(parameters, dict):
            _add_finding(findings, "FIELD_TYPE", "parameters must be an object")
        else:
            command_type = command if isinstance(command, str) else None
            if self.policy.strict_fields:
                parameter_rules = {
                    "STATUS_CHECK": {"include_health"},
                    "SENSOR_READ": {"target_sensor"},
                    "DIAGNOSTIC_PING": {"target_sensor", "detail_level"},
                    "TELEMETRY_REQUEST": {"target_sensor", "duration_seconds"},
                }
                allowed_parameter_keys = parameter_rules.get(command_type, set())
                unexpected = sorted(set(parameters.keys()) - allowed_parameter_keys)
                for key in unexpected:
                    _add_finding(findings, "UNEXPECTED_FIELD", f"unexpected parameter field: {key}")

            if command_type == "STATUS_CHECK":
                if "include_health" in parameters and not isinstance(parameters["include_health"], bool):
                    _add_finding(findings, "FIELD_TYPE", "include_health must be a boolean")
            if command_type in {"SENSOR_READ", "DIAGNOSTIC_PING", "TELEMETRY_REQUEST"}:
                if "target_sensor" not in parameters:
                    _add_finding(findings, "FIELD_REQUIRED", "missing required parameter: target_sensor")
                elif not isinstance(parameters["target_sensor"], str):
                    _add_finding(findings, "FIELD_TYPE", "parameter target_sensor must be a string")
                elif parameters["target_sensor"] not in {"SENSOR-01", "SENSOR-02", "SENSOR-03"}:
                    _add_finding(findings, "SENDER_ALLOWLIST", f"target_sensor '{parameters['target_sensor']}' is not recognized")
            if command_type == "DIAGNOSTIC_PING":
                if "detail_level" not in parameters:
                    _add_finding(findings, "FIELD_REQUIRED", "missing required parameter: detail_level")
                elif not _is_int(parameters["detail_level"]):
                    _add_finding(findings, "FIELD_TYPE", "detail_level must be an integer")
                elif not 1 <= int(parameters["detail_level"]) <= 3:
                    _add_finding(findings, "NUMERIC_RANGE", "detail_level must be between 1 and 3")
            if command_type == "TELEMETRY_REQUEST":
                if "duration_seconds" not in parameters:
                    _add_finding(findings, "FIELD_REQUIRED", "missing required parameter: duration_seconds")
                elif not _is_int(parameters["duration_seconds"]):
                    _add_finding(findings, "FIELD_TYPE", "duration_seconds must be an integer")
                elif not 1 <= int(parameters["duration_seconds"]) <= 120:
                    _add_finding(findings, "NUMERIC_RANGE", "duration_seconds must be between 1 and 120")

        timestamp_value = message.get("timestamp")
        try:
            parsed_timestamp = parse_timestamp(timestamp_value)
        except ValueError as exc:
            _add_finding(findings, "TIMESTAMP_FORMAT", str(exc))
        else:
            now = self.clock()
            age = (now - parsed_timestamp).total_seconds()
            if age > self.policy.max_age_seconds:
                _add_finding(findings, "TIMESTAMP_FRESHNESS", f"stale timestamp: age {int(age)}s exceeds {self.policy.max_age_seconds}s")
            if age < -self.policy.max_future_seconds:
                _add_finding(findings, "TIMESTAMP_FRESHNESS", "timestamp is too far in the future")

    def _validate_replay(self, message: Dict[str, Any], findings: List[Finding], sender: Any, message_id: Any) -> None:
        if not self.policy.replay_protection:
            return
        if isinstance(message_id, str) and message_id in self.replay_state.accepted_ids:
            _add_finding(findings, "REPLAY_PROTECTION", f"duplicate message_id: {message_id}")
        if isinstance(sender, str) and _is_int(message.get("sequence")):
            sequence = int(message["sequence"])
            previous = self.replay_state.last_sequence_by_sender.get(sender)
            if previous is not None and sequence <= previous:
                _add_finding(findings, "REPLAY_PROTECTION", f"sequence {sequence} is not newer than last accepted sequence {previous} for sender {sender}")


def load_schema() -> Dict[str, Any]:
    with SCHEMA_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_samples() -> Dict[str, Any]:
    with SAMPLES_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_default_policy() -> ValidationPolicy:
    return ValidationPolicy()


def reset_replay_state(replay_state: Optional[ReplayState] = None) -> None:
    (replay_state or _DEFAULT_REPLAY).reset()


_DEFAULT_REPLAY = ReplayState()
_DEFAULT_POLICY = build_default_policy()
_DEFAULT_VALIDATOR = SecureGateValidator(policy=_DEFAULT_POLICY, replay_state=_DEFAULT_REPLAY)


def validate_message(message: Any, policy: Optional[ValidationPolicy] = None, replay_state: Optional[ReplayState] = None) -> ValidationResult:
    validator = SecureGateValidator(policy=policy or _DEFAULT_POLICY, replay_state=replay_state or _DEFAULT_REPLAY)
    return validator.validate_message(message)

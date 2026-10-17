import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import app as app_module
from audit import AuditLogger
from validator import ReplayState, SecureGateValidator, ValidationPolicy, load_samples

FIXED_NOW = datetime(2026, 10, 17, 1, 30, tzinfo=timezone.utc)


class TestSecureGateValidator(unittest.TestCase):
    def setUp(self):
        self.policy = ValidationPolicy()
        self.replay = ReplayState()
        self.validator = SecureGateValidator(
            policy=self.policy,
            replay_state=self.replay,
            clock=lambda: FIXED_NOW,
        )

    def _now(self):
        return FIXED_NOW.isoformat().replace('+00:00', 'Z')

    def test_valid_telemetry_message(self):
        message = {
            "message_id": "MSG-1001",
            "sender": "SENSOR-01",
            "message_type": "TELEMETRY",
            "timestamp": self._now(),
            "sequence": 1,
            "payload": {
                "temperature": 28.5,
                "voltage": 12.2,
                "signal_strength": 85,
            },
        }
        result = self.validator.validate_message(message)
        self.assertTrue(result.accepted)
        self.assertEqual(result.category, "telemetry")

    def test_valid_command_message(self):
        message = {
            "message_id": "CMD-2001",
            "sender": "CONTROL-01",
            "message_type": "COMMAND",
            "timestamp": self._now(),
            "sequence": 1,
            "command": "STATUS_CHECK",
            "parameters": {},
        }
        result = self.validator.validate_message(message)
        self.assertTrue(result.accepted)
        self.assertEqual(result.category, "command")

    def test_missing_required_field_rejected(self):
        message = {
            "message_id": "MSG-1002",
            "sender": "SENSOR-01",
            "message_type": "TELEMETRY",
            "timestamp": self._now(),
            "sequence": 2,
            "payload": {"temperature": 25.0, "voltage": 12.0},
        }
        result = self.validator.validate_message(message)
        self.assertFalse(result.accepted)
        self.assertIn("FIELD_REQUIRED", [finding.rule_id for finding in result.findings])

    def test_temperature_out_of_range_rejected(self):
        message = {
            "message_id": "MSG-1003",
            "sender": "SENSOR-01",
            "message_type": "TELEMETRY",
            "timestamp": self._now(),
            "sequence": 3,
            "payload": {
                "temperature": 200.0,
                "voltage": 12.0,
                "signal_strength": 85,
            },
        }
        result = self.validator.validate_message(message)
        self.assertFalse(result.accepted)
        self.assertIn("NUMERIC_RANGE", [finding.rule_id for finding in result.findings])

    def test_non_finite_telemetry_number_rejected(self):
        message = {
            "message_id": "MSG-NAN",
            "sender": "SENSOR-01",
            "message_type": "TELEMETRY",
            "timestamp": self._now(),
            "sequence": 30,
            "payload": {
                "temperature": float("nan"),
                "voltage": 12.0,
                "signal_strength": 85,
            },
        }
        result = self.validator.validate_message(message)
        self.assertFalse(result.accepted)
        self.assertIn("NUMERIC_RANGE", [finding.rule_id for finding in result.findings])

    def test_boolean_and_null_values_are_not_accepted_as_numeric(self):
        for value in (True, None):
            message = {
                "message_id": f"MSG-BAD-{value}",
                "sender": "SENSOR-01",
                "message_type": "TELEMETRY",
                "timestamp": self._now(),
                "sequence": 31,
                "payload": {
                    "temperature": value,
                    "voltage": 12.0,
                    "signal_strength": 85,
                },
            }
            result = self.validator.validate_message(message)
            self.assertEqual(result.decision, "REJECT")
            self.assertIn("FIELD_TYPE", result.rule_ids)

    def test_stale_timestamp_rejected(self):
        stale_time = (FIXED_NOW - timedelta(minutes=10)).isoformat().replace('+00:00', 'Z')
        message = {
            "message_id": "MSG-1004",
            "sender": "SENSOR-02",
            "message_type": "TELEMETRY",
            "timestamp": stale_time,
            "sequence": 4,
            "payload": {
                "temperature": 25.0,
                "voltage": 11.5,
                "signal_strength": 70,
            },
        }
        result = self.validator.validate_message(message)
        self.assertFalse(result.accepted)
        self.assertIn("TIMESTAMP_FRESHNESS", [finding.rule_id for finding in result.findings])

    def test_future_timestamp_beyond_tolerance_rejected(self):
        future = (FIXED_NOW + timedelta(seconds=self.policy.max_future_seconds + 1)).isoformat()
        message = {
            "message_id": "MSG-FUTURE",
            "sender": "SENSOR-02",
            "message_type": "TELEMETRY",
            "timestamp": future,
            "sequence": 40,
            "payload": {"temperature": 25.0, "voltage": 11.5, "signal_strength": 70},
        }
        result = self.validator.validate_message(message)
        self.assertEqual(result.decision, "REJECT")
        self.assertIn("TIMESTAMP_FRESHNESS", result.rule_ids)

    def test_timestamp_without_timezone_rejected(self):
        message = {
            "message_id": "MSG-NAIVE-TIME",
            "sender": "SENSOR-02",
            "message_type": "TELEMETRY",
            "timestamp": "2026-10-17T01:30:00",
            "sequence": 41,
            "payload": {"temperature": 25.0, "voltage": 11.5, "signal_strength": 70},
        }
        result = self.validator.validate_message(message)
        self.assertEqual(result.decision, "REJECT")
        self.assertIn("TIMESTAMP_FORMAT", result.rule_ids)

    def test_replay_protection_rejects_duplicate_ids(self):
        first = {
            "message_id": "MSG-1005",
            "sender": "SENSOR-03",
            "message_type": "TELEMETRY",
            "timestamp": self._now(),
            "sequence": 5,
            "payload": {
                "temperature": 22.0,
                "voltage": 11.5,
                "signal_strength": 72,
            },
        }
        second = dict(first)
        second["sequence"] = 6

        first_result = self.validator.validate_message(first)
        self.assertTrue(first_result.accepted)
        second_result = self.validator.validate_message(second)
        self.assertFalse(second_result.accepted)
        self.assertIn("REPLAY_PROTECTION", [finding.rule_id for finding in second_result.findings])

    def test_replay_protection_rejects_reused_sequence_with_new_id(self):
        first = {
            "message_id": "MSG-SEQ-1",
            "sender": "SENSOR-03",
            "message_type": "TELEMETRY",
            "timestamp": self._now(),
            "sequence": 50,
            "payload": {"temperature": 22.0, "voltage": 11.5, "signal_strength": 72},
        }
        replay = dict(first, message_id="MSG-SEQ-2")
        self.assertEqual(self.validator.validate_message(first).decision, "ACCEPT")
        result = self.validator.validate_message(replay)
        self.assertEqual(result.decision, "REJECT")
        self.assertIn("REPLAY_PROTECTION", result.rule_ids)

    def test_rejected_message_does_not_consume_replay_state(self):
        message = {
            "message_id": "MSG-RETRY",
            "sender": "SENSOR-03",
            "message_type": "TELEMETRY",
            "timestamp": (FIXED_NOW - timedelta(minutes=10)).isoformat(),
            "sequence": 51,
            "payload": {"temperature": 22.0, "voltage": 11.5, "signal_strength": 72},
        }
        self.assertEqual(self.validator.validate_message(message).decision, "REJECT")
        message["timestamp"] = self._now()
        self.assertEqual(self.validator.validate_message(message).decision, "ACCEPT")

    def test_strict_policy_rejects_unexpected_fields(self):
        message = {
            "message_id": "MSG-EXTRA",
            "sender": "SENSOR-03",
            "message_type": "TELEMETRY",
            "timestamp": self._now(),
            "sequence": 52,
            "payload": {"temperature": 22.0, "voltage": 11.5, "signal_strength": 72},
            "extra": "not in schema",
        }
        result = self.validator.validate_message(message)
        self.assertEqual(result.decision, "REJECT")
        self.assertIn("UNEXPECTED_FIELD", result.rule_ids)


class TestSeededExamples(unittest.TestCase):
    def test_seeded_valid_and_invalid_messages_have_expected_decisions(self):
        samples = load_samples()
        expected_rules = {
            "invalid_missing": "FIELD_REQUIRED",
            "invalid_range": "NUMERIC_RANGE",
            "invalid_sender": "SENDER_ALLOWLIST",
            "invalid_type": "FIELD_TYPE",
            "invalid_stale": "TIMESTAMP_FRESHNESS",
            "invalid_future": "TIMESTAMP_FRESHNESS",
        }

        for name, sample in samples["telemetry"].items():
            if name == "invalid_malformed":
                continue
            with self.subTest(category="telemetry", sample=name):
                message = dict(sample)
                if name not in {"invalid_missing", "invalid_stale", "invalid_future"}:
                    message["timestamp"] = FIXED_NOW.isoformat()
                validator = SecureGateValidator(
                    replay_state=ReplayState(),
                    clock=lambda: FIXED_NOW,
                )
                result = validator.validate_message(message)
                if name == "valid":
                    self.assertEqual(result.decision, "ACCEPT")
                else:
                    self.assertEqual(result.decision, "REJECT")
                    self.assertIn(expected_rules[name], result.rule_ids)

        command_expectations = {
            "valid": None,
            "invalid_unauthorized": "SENDER_ALLOWLIST",
            "invalid_params": "NUMERIC_RANGE",
            "invalid_unsupported": "COMMAND_TYPE",
        }
        for name, sample in samples["commands"].items():
            with self.subTest(category="command", sample=name):
                message = dict(sample)
                message["timestamp"] = FIXED_NOW.isoformat()
                validator = SecureGateValidator(
                    replay_state=ReplayState(),
                    clock=lambda: FIXED_NOW,
                )
                result = validator.validate_message(message)
                expected_rule = command_expectations[name]
                self.assertEqual(result.decision, "ACCEPT" if expected_rule is None else "REJECT")
                if expected_rule is not None:
                    self.assertIn(expected_rule, result.rule_ids)

    def test_seeded_malformed_json_is_audited_as_rejection(self):
        with TemporaryDirectory() as temp_dir:
            previous_logger = app_module.audit_logger
            app_module.audit_logger = AuditLogger(Path(temp_dir) / "seeded-audit.jsonl")
            try:
                raw = load_samples()["telemetry"]["invalid_malformed"]
                response = app_module.app.test_client().post(
                    "/api/validate",
                    data=raw,
                    content_type="application/json",
                    headers={"X-Message-Category": "telemetry"},
                )
                result = response.get_json()
                self.assertEqual(result["decision"], "REJECT")
                self.assertIn("JSON_SYNTAX", [item["rule_id"] for item in result["findings"]])
                event = app_module.audit_logger.read_events()[0]
                self.assertEqual(event["decision"], "REJECT")
            finally:
                app_module.audit_logger = previous_logger


class TestCommandValidationAPI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.previous_validator = app_module.validator
        self.previous_audit_logger = app_module.audit_logger
        app_module.validator = SecureGateValidator(
            policy=ValidationPolicy(),
            replay_state=ReplayState(),
            clock=lambda: FIXED_NOW,
        )
        app_module.audit_logger = AuditLogger(Path(self.temp_dir.name) / "audit.jsonl")
        self.client = app_module.app.test_client()

    def tearDown(self):
        app_module.validator = self.previous_validator
        app_module.audit_logger = self.previous_audit_logger
        self.temp_dir.cleanup()

    def command(self, **overrides):
        message = {
            "message_id": "CMD-API-101",
            "sender": "CONTROL-01",
            "message_type": "COMMAND",
            "command": "STATUS_CHECK",
            "timestamp": FIXED_NOW.isoformat(),
            "sequence": 101,
            "parameters": {},
        }
        message.update(overrides)
        return message

    def post_command(self, raw_text):
        return self.client.post(
            "/api/validate",
            data=raw_text,
            content_type="application/json",
            headers={"X-Message-Category": "command"},
        ).get_json()

    def test_sample_api_keeps_examples_fresh_and_invalid_future_unambiguous(self):
        response = self.client.get("/api/samples")
        self.assertEqual(response.status_code, 200)
        samples = response.get_json()
        valid_time = datetime.fromisoformat(samples["telemetry"]["valid"]["timestamp"])
        age = abs((datetime.now(timezone.utc) - valid_time.astimezone(timezone.utc)).total_seconds())
        self.assertLess(age, 5)
        self.assertEqual(
            samples["telemetry"]["invalid_future"]["timestamp"],
            "2099-01-01T00:00:00+00:00",
        )
        self.assertNotIn("timestamp", samples["telemetry"]["invalid_missing"])

    def test_fresh_authorized_command_is_accepted_and_audited(self):
        result = self.post_command(json.dumps(self.command()))
        self.assertEqual(result["decision"], "ACCEPT")
        self.assertEqual(result["message_id"], "CMD-API-101")
        events = app_module.audit_logger.read_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["decision"], "ACCEPT")
        self.assertEqual(events[0]["message_id"], "CMD-API-101")

    def test_malformed_and_empty_json_are_rejected_and_audited(self):
        malformed = self.post_command('{"message_id": ')
        empty = self.post_command("")
        self.assertEqual(malformed["decision"], "REJECT")
        self.assertIn("JSON_SYNTAX", malformed["findings"][0]["rule_id"])
        self.assertIn("line", malformed["findings"][0]["message"])
        self.assertEqual(empty["decision"], "REJECT")
        self.assertIn("empty", empty["findings"][0]["message"])
        events = app_module.audit_logger.read_events()
        self.assertEqual(len(events), 2)
        self.assertNotEqual(events[0]["event_id"], events[1]["event_id"])

    def test_unsupported_command_rejected(self):
        result = self.post_command(json.dumps(self.command(command="POWER_ON")))
        self.assertEqual(result["decision"], "REJECT")
        self.assertEqual(result["findings"][0]["rule_id"], "COMMAND_TYPE")

    def test_non_string_command_rejected_without_crashing(self):
        result = self.post_command(json.dumps(self.command(command=["STATUS_CHECK"])))
        self.assertEqual(result["decision"], "REJECT")
        self.assertIn("FIELD_TYPE", [finding["rule_id"] for finding in result["findings"]])

    def test_nonstandard_json_number_is_audited_as_syntax_error(self):
        result = self.post_command('{"command": NaN}')
        self.assertEqual(result["decision"], "REJECT")
        self.assertEqual(result["findings"][0]["rule_id"], "JSON_SYNTAX")

    def test_unauthorized_sender_rejected(self):
        result = self.post_command(json.dumps(self.command(sender="SENSOR-01")))
        self.assertEqual(result["decision"], "REJECT")
        self.assertIn("SENDER_ALLOWLIST", [finding["rule_id"] for finding in result["findings"]])

    def test_missing_required_field_rejected(self):
        message = self.command()
        del message["sequence"]
        result = self.post_command(json.dumps(message))
        self.assertEqual(result["decision"], "REJECT")
        self.assertIn("FIELD_REQUIRED", [finding["rule_id"] for finding in result["findings"]])

    def test_invalid_parameter_rejected(self):
        message = self.command(
            command="TELEMETRY_REQUEST",
            parameters={"target_sensor": "SENSOR-01", "duration_seconds": 121},
        )
        result = self.post_command(json.dumps(message))
        self.assertEqual(result["decision"], "REJECT")
        self.assertIn("NUMERIC_RANGE", [finding["rule_id"] for finding in result["findings"]])

    def test_expired_timestamp_rejected(self):
        expired = (FIXED_NOW - timedelta(minutes=10)).isoformat()
        result = self.post_command(json.dumps(self.command(timestamp=expired)))
        self.assertEqual(result["decision"], "REJECT")
        self.assertIn("TIMESTAMP_FRESHNESS", [finding["rule_id"] for finding in result["findings"]])

    def test_duplicate_message_id_and_replayed_sequence_rejected(self):
        first = self.command()
        self.assertEqual(self.post_command(json.dumps(first))["decision"], "ACCEPT")
        duplicate_id = dict(first, sequence=102)
        duplicate_result = self.post_command(json.dumps(duplicate_id))
        self.assertEqual(duplicate_result["decision"], "REJECT")
        self.assertIn("REPLAY_PROTECTION", [finding["rule_id"] for finding in duplicate_result["findings"]])

        replay_sequence = dict(first, message_id="CMD-API-102")
        sequence_result = self.post_command(json.dumps(replay_sequence))
        self.assertEqual(sequence_result["decision"], "REJECT")
        self.assertIn("REPLAY_PROTECTION", [finding["rule_id"] for finding in sequence_result["findings"]])

    def test_attempts_are_audited_with_raw_malformed_text(self):
        self.post_command('{"broken":')
        event = app_module.audit_logger.read_events()[0]
        self.assertEqual(event["decision"], "REJECT")
        self.assertEqual(event["raw_message"]["raw_text"], '{"broken":')


if __name__ == "__main__":
    unittest.main(verbosity=2)

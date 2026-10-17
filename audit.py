from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4

from validator import ValidationResult


class AuditLogger:
    def __init__(self, log_path: Optional[str | Path] = None) -> None:
        self.log_path = Path(log_path) if log_path is not None else Path(__file__).resolve().parent / "securegate_audit.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.write_text("", encoding="utf-8")

    def _event_entry(self, validation: ValidationResult, raw_message: Any) -> Dict[str, Any]:
        return {
            "event_id": self._new_event_id(),
            "message_id": validation.message_id,
            "sender": validation.sender,
            "category": validation.category,
            "decision": validation.decision,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message_type": validation.message_type,
            "findings": [finding.as_dict() for finding in validation.findings],
            "rule_ids": validation.rule_ids,
            "raw_message": raw_message,
        }

    def _new_event_id(self) -> str:
        return f"AUD-{uuid4().hex}"

    def log_validation(self, validation: ValidationResult, raw_message: Any = None) -> Dict[str, Any]:
        event = self._event_entry(validation, raw_message)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        return event

    def read_events(self) -> List[Dict[str, Any]]:
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return []
        events: List[Dict[str, Any]] = []
        with self.log_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    events.append({"event_id": "AUD-INVALID", "decision": "REJECT", "raw_message": line})
        return events

    def filter_events(
        self,
        decision: Optional[str] = None,
        sender: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        events = self.read_events()
        filtered = []
        for entry in events:
            if decision and entry.get("decision") != decision:
                continue
            if sender and entry.get("sender") != sender:
                continue
            if category and entry.get("category") != category:
                continue
            if search:
                needle = search.lower()
                haystack = json.dumps(entry, ensure_ascii=False).lower()
                if needle not in haystack:
                    continue
            filtered.append(entry)
        return filtered

    def recent_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        events = self.read_events()
        return events[-limit:]

    def export_json(self) -> str:
        return json.dumps(self.read_events(), indent=2, ensure_ascii=False)

    def export_csv(self) -> str:
        events = self.read_events()
        if not events:
            return "event_id,message_id,sender,category,decision,timestamp,message_type\n"
        buffer = StringIO()
        fieldnames = ["event_id", "message_id", "sender", "category", "decision", "timestamp", "message_type"]
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            row = {}
            for key in fieldnames:
                value = event.get(key, "")
                if isinstance(value, str) and value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
                    value = "'" + value
                row[key] = value
            writer.writerow(row)
        return buffer.getvalue()

    def clear(self) -> None:
        self.log_path.write_text("", encoding="utf-8")

    def stats(self) -> Dict[str, int]:
        events = self.read_events()
        accepted = sum(1 for event in events if event.get("decision") == "ACCEPT")
        rejected = sum(1 for event in events if event.get("decision") == "REJECT")
        return {"total": len(events), "accepted": accepted, "rejected": rejected}

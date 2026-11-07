"""Audit log for the guardrail: one JSON line per tool call outcome.

The log lives in the plugin's data directory (which survives plugin updates)
when Hermes provides one, and falls back to the default plugin directory.
A logging failure is swallowed: an audit problem must never break the
agent loop.
"""

import json
import os
import time


class AuditLog:
    def __init__(self, data_dir=None):
        if data_dir:
            base = data_dir
        else:
            base = os.path.join(
                os.path.expanduser("~"),
                ".hermes",
                "plugins",
                "tool-call-guardrail",
            )
        self.path = os.path.join(base, "guardrail-audit.jsonl")

    def _write(self, entry):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def record_decision(self, tool_name, directive):
        """What the guardrail decided, from pre_tool_call."""
        action = "allow"
        reason = None
        if isinstance(directive, dict):
            action = directive.get("action", "allow")
            reason = directive.get("message")
        self._write(
            {
                "ts": time.time(),
                "event": "decision",
                "tool": tool_name,
                "decision": action,
                "reason": reason,
            }
        )

    def record(self, tool_name, status, error_message=None, duration_ms=None):
        """What actually happened, from post_tool_call."""
        entry = {
            "ts": time.time(),
            "event": "outcome",
            "tool": tool_name,
            "status": status,
        }
        if error_message:
            entry["error"] = error_message
        if duration_ms is not None:
            entry["duration_ms"] = duration_ms
        self._write(entry)

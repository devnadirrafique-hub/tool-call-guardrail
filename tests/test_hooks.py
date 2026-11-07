"""Hook-wiring tests: does the plugin register the right hooks with Hermes,
and do the callbacks behave through the real wiring (not just the engine)?

Run from the plugin directory with: python -m unittest discover -s tests -v
Uses a fake ctx object that mimics what Hermes hands to register().
"""

import importlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeCtx:
    """Stands in for the ctx object Hermes passes to register()."""

    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.hooks = {}

    def plugin_data_dir(self):
        return self.data_dir

    def register_hook(self, event, callback):
        self.hooks[event] = callback


def load_plugin_root():
    # Mirror how Hermes loads a directory plugin: __init__.py is imported
    # as a package with __package__ set and the plugin directory as its
    # search path, so the relative imports in __init__.py resolve.
    plugin_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(plugin_dir, "__init__.py")
    spec = importlib.util.spec_from_file_location(
        "plugin_root", path, submodule_search_locations=[plugin_dir]
    )
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "plugin_root"
    sys.modules["plugin_root"] = module
    spec.loader.exec_module(module)
    return module


class TestHookWiring(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.plugin = load_plugin_root()
        self.ctx = FakeCtx(self.tmp.name)
        self.plugin.register(self.ctx)

    def tearDown(self):
        self.tmp.cleanup()

    def test_registers_exactly_the_two_hooks(self):
        self.assertEqual(
            set(self.ctx.hooks.keys()), {"pre_tool_call", "post_tool_call"}
        )

    def test_dangerous_call_blocked_through_the_hook(self):
        guard = self.ctx.hooks["pre_tool_call"]
        directive = guard("terminal", {"command": "rm -rf /"}, "task-1")
        self.assertEqual(directive["action"], "block")
        self.assertIn("Guardrail blocked", directive["message"])

    def test_safe_call_allowed_through_the_hook(self):
        guard = self.ctx.hooks["pre_tool_call"]
        self.assertIsNone(guard("terminal", {"command": "ls -la"}, "task-1"))

    def test_outside_write_asks_approval_through_the_hook(self):
        guard = self.ctx.hooks["pre_tool_call"]
        directive = guard(
            "write_file", {"path": "/etc/passwd", "content": "x"}, "task-1"
        )
        self.assertEqual(directive["action"], "approve")
        self.assertEqual(
            directive["rule_key"], "guardrail:path-outside-workspace"
        )

    def test_decisions_are_logged(self):
        guard = self.ctx.hooks["pre_tool_call"]
        guard("terminal", {"command": "rm -rf /"}, "task-1")
        guard("terminal", {"command": "ls"}, "task-1")
        audit_path = os.path.join(self.tmp.name, "guardrail-audit.jsonl")
        with open(audit_path, encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["event"], "decision")
        self.assertEqual(lines[0]["decision"], "block")
        self.assertEqual(lines[1]["decision"], "allow")

    def test_outcomes_are_logged(self):
        record = self.ctx.hooks["post_tool_call"]
        record("terminal", {"command": "ls"}, "ok", "task-1", 42, status="ok")
        record(
            "terminal",
            {"command": "rm -rf /"},
            None,
            "task-1",
            3,
            status="blocked",
            error_message="Guardrail blocked this call.",
        )
        audit_path = os.path.join(self.tmp.name, "guardrail-audit.jsonl")
        with open(audit_path, encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["event"], "outcome")
        self.assertEqual(lines[0]["status"], "ok")
        self.assertEqual(lines[0]["duration_ms"], 42)
        self.assertEqual(lines[1]["status"], "blocked")

    def test_guard_fails_closed_on_bad_input(self):
        guard = self.ctx.hooks["pre_tool_call"]
        # A tool name that is not a string must not crash the hook.
        directive = guard(None, {"command": "ls"}, "task-1")
        self.assertIsNone(directive)


if __name__ == "__main__":
    unittest.main()

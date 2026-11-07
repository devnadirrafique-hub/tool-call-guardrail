"""Tool-call guardrail for Hermes Agent.

Registers two hooks:
- pre_tool_call: checks every tool call before it runs. Returns a block,
  approve, or modify directive, or None to let the call through untouched.
- post_tool_call: records every call and its outcome in the audit log.

The decision engine lives in guardrail/policy.py and has no Hermes
dependency, so it can be unit-tested without Hermes installed. This file is
only the wiring between Hermes and the engine.
"""

from .guardrail.audit import AuditLog
from .guardrail.config import load_config
from .guardrail.policy import decide

_CONFIG = None
_AUDIT = None


def _get_config():
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = load_config()
    return _CONFIG


def _get_audit(ctx=None):
    global _AUDIT
    if _AUDIT is None:
        data_dir = None
        if ctx is not None:
            try:
                data_dir = ctx.plugin_data_dir()
            except Exception:
                data_dir = None
        _AUDIT = AuditLog(data_dir)
    return _AUDIT


def _guard(tool_name, args, task_id, **kwargs):
    """pre_tool_call callback. Fail closed: any error returns a block."""
    try:
        if not isinstance(args, dict):
            args = {}
        config = _get_config()
        directive = decide(tool_name, args, config)
    except Exception as exc:  # never let a policy error run a call unchecked
        directive = {
            "action": "block",
            "message": "Guardrail could not check this call (%s). Failing closed." % exc,
        }
    try:
        _get_audit().record_decision(tool_name, directive)
    except Exception:
        pass
    return directive


def _record(tool_name, args, result, task_id, duration_ms, **kwargs):
    """post_tool_call callback. Audit only; the return value is ignored."""
    try:
        audit = _get_audit()
        status = kwargs.get("status", "ok")
        audit.record(
            tool_name=tool_name,
            status=status,
            error_message=kwargs.get("error_message"),
            duration_ms=duration_ms,
        )
    except Exception:
        pass  # an audit failure must never break the agent loop


def register(ctx):
    _get_audit(ctx)
    ctx.register_hook("pre_tool_call", _guard)
    ctx.register_hook("post_tool_call", _record)

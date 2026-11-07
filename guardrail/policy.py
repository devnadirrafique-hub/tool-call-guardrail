"""Decision engine for the tool-call guardrail.

Pure functions, no Hermes dependency, so the engine can be unit-tested
without Hermes installed. decide() takes a tool name and its arguments and
returns a Hermes pre_tool_call directive (a dict) or None to let the call
through untouched.

Three checks, in order:
1. Destructive shell commands — only for shell tools, or arguments that
   actually hold a command. Blocked outright.
2. File writes outside the workspace — sent to the human for approval
   (or blocked, per config).
3. Secret-shaped values in arguments — blocked. The secret value itself is
   NEVER copied into the block message.

Design notes:
- Patterns are deliberately narrow. A rule that fires on everyday work is
  worse than a rule that misses an exotic shape: the user will just turn
  the plugin off. Each pattern below names the exact harm it stops.
- The workspace root is the current working directory unless the user sets
  one in policy.json. That is an approximation, documented in the README.
- Everything here is fast local regex. No network, no model calls, so a
  check finishes in milliseconds, far inside the hook's 30-second timeout.
"""

import os
import re

# Tools that run a command. Only these (plus explicit command arguments)
# get the destructive-command check, so ordinary text is never scanned
# for shell patterns.
SHELL_TOOLS = {
    "terminal",
    "shell_exec",
    "shell",
    "run_command",
    "exec",
    "bash",
    "run_shell_command",
    "execute_command",
}

# Argument keys that hold a command, even on a tool whose name is not in
# SHELL_TOOLS.
COMMAND_KEYS = {"command", "cmd", "script", "code", "command_line"}

# Tools that write a file, and the argument keys that hold the path.
WRITE_TOOLS = {
    "write_file",
    "patch",
    "edit_file",
    "create_file",
    "edit",
    "write",
    "save_file",
}
PATH_KEYS = {"path", "file", "filepath", "filename", "target", "destination"}

# (pattern, reason) — each pattern names the exact harm. The rm and chmod
# rules only fire on root, home, or a wildcard target: "rm -rf ./build"
# and "rm -rf /tmp/foo" are ordinary cleanup and must pass through.
DANGEROUS_PATTERNS = [
    (
        re.compile(
            r"\brm\s+-[a-z]*[rf][a-z]*\s+"
            r"(?:/(?:[\s;|&*]|$)|~(?:[\s;|&/]|$)|\$HOME(?:[\s;|&/]|$))",
            re.IGNORECASE,
        ),
        "recursive force-delete of root, home, or everything",
    ),
    (
        re.compile(
            r"\bchmod\s+(?:-[a-z]*R[a-z]*\s+)?777\s+"
            r"(?:/(?:[\s;|&*]|$)|~(?:[\s;|&/]|$)|\$HOME(?:[\s;|&/]|$))",
            re.IGNORECASE,
        ),
        "opening all permissions on root or home",
    ),
    (
        re.compile(r"\b(curl|wget)\b[^|;]*\|\s*(sh|bash|zsh)\b", re.IGNORECASE),
        "piping a download straight into a shell",
    ),
    (re.compile(r"\bmkfs\b", re.IGNORECASE), "formatting a filesystem"),
    (
        re.compile(r"\bdd\b[^|;]*\bof=/dev/", re.IGNORECASE),
        "writing raw data to a device",
    ),
    (
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;", re.IGNORECASE),
        "fork bomb",
    ),
    (
        re.compile(r"\b(shutdown|reboot|halt|poweroff)\b", re.IGNORECASE),
        "shutting down or rebooting the machine",
    ),
    (
        re.compile(r"\b(shred|format)\s+/dev/", re.IGNORECASE),
        "destroying a device",
    ),
    (
        re.compile(r">\s*/dev/(sd[a-z]|nvme\d*n\d+|hd[a-z])", re.IGNORECASE),
        "writing directly to a disk device",
    ),
]

# High-precision secret shapes only. A loose pattern here would block
# ordinary work (hashes, IDs, random tokens), so every pattern below needs
# a recognisable prefix or structure. The matched value is never reported.
SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub personal access token"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"), "GitHub OAuth token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "private key",
    ),
    (
        re.compile(
            r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
        "credential in key=value form",
    ),
]


def _iter_strings(value):
    """Yield every string inside args, however nested."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def _command_text(tool_name, args):
    """The command string, if this call runs one; otherwise None."""
    if tool_name.lower() in SHELL_TOOLS:
        return " ".join(s for s in _iter_strings(args))
    for key in COMMAND_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _path_arg(tool_name, args):
    """The file path, if this call writes one; otherwise None."""
    if tool_name.lower() not in WRITE_TOOLS:
        return None
    for key in PATH_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _inside_workspace(path, workspace_root):
    resolved = os.path.abspath(os.path.join(workspace_root, path))
    root = os.path.abspath(workspace_root)
    return os.path.commonpath([resolved, root]) == root


def _check_command(command, extra_patterns):
    for pattern, reason in DANGEROUS_PATTERNS:
        if pattern.search(command):
            return {
                "action": "block",
                "message": "Guardrail blocked this call: " + reason + ".",
            }
    for entry in extra_patterns:
        try:
            if re.search(entry["pattern"], command, re.IGNORECASE):
                return {
                    "action": "block",
                    "message": "Guardrail blocked this call: "
                    + entry.get("reason", "matches your block list")
                    + ".",
                }
        except re.error:
            continue
    return None


def _check_path(path, config):
    root = config.get("workspace_root") or os.getcwd()
    if _inside_workspace(path, root):
        return None
    action = config.get("path_action", "approve")
    if action == "block":
        return {
            "action": "block",
            "message": "Guardrail blocked this call: writing outside the "
            "workspace (" + root + ").",
        }
    return {
        "action": "approve",
        "message": "Writing outside the workspace (" + root + "). "
        "Please confirm this is intended.",
        "rule_key": "guardrail:path-outside-workspace",
    }


def _check_secrets(args, config):
    for text in _iter_strings(args):
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(text):
                action = config.get("secret_action", "block")
                if action == "approve":
                    return {
                        "action": "approve",
                        "message": "This call carries something shaped like a "
                        + label
                        + ". Please confirm it should be sent.",
                        "rule_key": "guardrail:secret-in-arguments",
                    }
                return {
                    "action": "block",
                    "message": "Guardrail blocked this call: it carries "
                    "something shaped like a " + label + ".",
                }
    return None


def decide(tool_name, args, config):
    """Return a pre_tool_call directive dict, or None to allow the call."""
    if not isinstance(args, dict):
        args = {}
    if not isinstance(tool_name, str):
        tool_name = str(tool_name)

    command = _command_text(tool_name, args)
    if command:
        verdict = _check_command(command, config.get("extra_block_patterns", []))
        if verdict is not None:
            return verdict

    path = _path_arg(tool_name, args)
    if path:
        verdict = _check_path(path, config)
        if verdict is not None:
            return verdict

    return _check_secrets(args, config)

"""Loads the guardrail's user policy file, or defaults.

The policy file is plain JSON the user can edit by hand. Unknown keys are
ignored, and a missing or broken file silently falls back to defaults —
a bad config must never disable the guardrail or crash the plugin.
"""

import json
import os

DEFAULTS = {
    # None means "the current working directory at call time".
    "workspace_root": None,
    # What to do with writes outside the workspace: "approve" or "block".
    "path_action": "approve",
    # What to do when a secret-shaped value appears in arguments:
    # "block" or "approve".
    "secret_action": "block",
    # Extra user rules: [{"pattern": "<regex>", "reason": "<why>"}].
    # They run against command text only. An invalid regex is skipped.
    "extra_block_patterns": [],
}


def _policy_path():
    return os.path.join(
        os.path.expanduser("~"),
        ".hermes",
        "plugins",
        "tool-call-guardrail",
        "policy.json",
    )


def load_config(path=None):
    config = dict(DEFAULTS)
    try:
        with open(path or _policy_path(), encoding="utf-8") as handle:
            user = json.load(handle)
    except (OSError, ValueError):
        return config
    if not isinstance(user, dict):
        return config
    for key, value in user.items():
        if key not in DEFAULTS:
            continue
        config[key] = value
    if config.get("path_action") not in ("approve", "block"):
        config["path_action"] = DEFAULTS["path_action"]
    if config.get("secret_action") not in ("approve", "block"):
        config["secret_action"] = DEFAULTS["secret_action"]
    if not isinstance(config.get("extra_block_patterns"), list):
        config["extra_block_patterns"] = []
    config["extra_block_patterns"] = [
        entry
        for entry in config["extra_block_patterns"]
        if isinstance(entry, dict) and isinstance(entry.get("pattern"), str)
    ]
    return config

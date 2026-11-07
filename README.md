# tool-call-guardrail

A guardrail plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent).
Every time the agent tries to call a tool, this plugin checks the call first
and does one of three things: lets it through, blocks it with a reason, or
sends it to you for approval. Every decision goes into an audit log.

## What it checks

- **Destructive shell commands — blocked.** Recursive force-deletes of the
  filesystem root, the home directory, or everything; opening all
  permissions on root or home; piping a download straight into a shell;
  formatting a filesystem; writing raw data to a device; fork bombs;
  shutting the machine down. Ordinary cleanup such as removing a project
  build directory passes through untouched. The exact patterns live in
  `guardrail/policy.py` with a test for each one.
- **Writes outside the workspace — sent to you for approval.** A file write
  whose path resolves outside the working directory asks you first, with the
  workspace shown in the message. Set `path_action` to `"block"` in
  `policy.json` to block these outright instead.
- **Secret-shaped values in arguments — blocked.** Things shaped like API
  keys and tokens (for example `sk-...`, GitHub tokens, AWS access keys,
  Slack tokens, private keys) are stopped before they are sent anywhere.
  The secret value itself is never copied into the block message or the log.

Everything else passes through untouched, so normal work is not slowed down.

## Install

Copy this directory to your Hermes plugins folder and enable it:

```
cp -r tool-call-guardrail ~/.hermes/plugins/
hermes plugins enable tool-call-guardrail
```

Restart Hermes (or the gateway) after enabling.

## Configure

Create `~/.hermes/plugins/tool-call-guardrail/policy.json`. All fields are
optional; a missing or broken file falls back to the defaults.

```json
{
  "workspace_root": null,
  "path_action": "approve",
  "secret_action": "block",
  "extra_block_patterns": [
    {"pattern": "\\bnc\\s+-l\\b", "reason": "listening netcat"}
  ]
}
```

- `workspace_root`: the directory file writes must stay inside. `null` means
  the current working directory at call time.
- `path_action`: `"approve"` (ask you) or `"block"`.
- `secret_action`: `"block"` or `"approve"`.
- `extra_block_patterns`: your own regex rules, checked against command
  text only. An invalid regex is skipped.

## Audit log

Decisions and outcomes are appended as JSON lines to
`guardrail-audit.jsonl` in the plugin's data directory (or
`~/.hermes/plugins/tool-call-guardrail/` when no data directory is
available). Each line records the time, the tool, the decision
(`allow`, `block`, or `approve`), and the reason.

## What it cannot do (honest limits)

- It does **not** sandbox the agent. Hermes gives plugins no sandbox: the
  plugin runs with your full authority and can only advise or block through
  the official hook. A blocked call is refused; a call the rules miss still
  runs with your permissions.
- It judges the **call**, not the conversation. The hook sees the tool name
  and its arguments, not the chat around them, so it cannot catch a harmful
  instruction that is phrased as an innocent-looking call.
- The workspace check uses the current working directory unless you set
  `workspace_root`. If the agent works from a different directory than you
  expect, set it explicitly.
- It never reads your credentials and never auto-approves anything. It works
  with the approval system, never around it.

## Testing

Unit tests for the decision engine need no Hermes install:

```
python -m unittest discover -s tests -v
```

To check the plugin the way Hermes itself does:

```
hermes plugins doctor . --ci
hermes plugins validate . --install-deps
```

## How it works

`__init__.py` registers two hooks: `pre_tool_call` (the check) and
`post_tool_call` (the audit log). The decision engine in
`guardrail/policy.py` is pure Python with no Hermes dependency, so it can
be tested on its own. Any error inside a check fails closed: the call is
blocked rather than run unchecked.

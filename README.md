# RubberBand

Static command pattern detection plugin for [OpenClaw](https://github.com/openclaw/openclaw). Intercepts exec tool calls and blocks dangerous commands before they run.

## Install

```bash
# Clone and install as a local plugin
git clone https://github.com/jeffaf/rubberband.git ~/.openclaw/plugins/rubberband
openclaw plugins install ~/.openclaw/plugins/rubberband
openclaw gateway restart
```

## What It Does

RubberBand hooks into the `before_tool_call` event and analyzes every exec command for dangerous patterns. It scores commands based on 15+ detection categories and blocks, alerts, or logs based on configurable thresholds.

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
| 1-39 | LOG | Silent log |
| 40-59 | ALERT | Warn in session |
| 60+ | BLOCK | Reject command |

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
cd ~/.openclaw/plugins/rubberband
npm install
npx vitest run
```

26 tests covering all detection categories, edge cases, and mode handling.

## How It Works

RubberBand is a pure TypeScript static analyzer. No network calls, no external dependencies, no LLM. It normalizes commands (handling encoding, escaping, heredocs, etc.) and matches against pattern rules with weighted scoring.

The plugin registers a `before_tool_call` hook at high priority. When an exec tool call comes in, it runs the command through the analyzer. If the score exceeds the block threshold, it returns `{ block: true, blockReason: "..." }` which prevents execution.

## Also Available As

RubberBand is also proposed as a native OpenClaw feature: [PR #24958](https://github.com/openclaw/openclaw/pull/24958)

The plugin version lets you use it today without waiting for the PR to merge.

## License

MIT

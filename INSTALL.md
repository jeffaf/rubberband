# Installing RubberBand

RubberBand adds static command pattern detection to OpenClaw. It monitors command execution for suspicious patterns (credential theft, exfiltration, persistence) and can alert or block before damage is done.

## For OpenClaw Users

RubberBand is being integrated directly into OpenClaw as a pre-exec security hook.

**Status:** PR available at [feat/rubberband-integration](https://github.com/jeffaf/openclaw/tree/feat/rubberband-integration)

Once merged, RubberBand will be a built-in security feature — no separate installation needed.

## For Standalone Testing

```bash
# Clone RubberBand
git clone https://github.com/jeffaf/rubberband.git
cd rubberband

# Run the test suite
python3 src/rubberband.py
```

Expected output shows test commands with dispositions:
- 🟢 ALLOW — safe command
- 🟡 ALERT/LOG — suspicious but allowed
- 🔴 BLOCK — dangerous, rejected

## What It Detects

| Category | Examples | Score |
|----------|----------|-------|
| **Credential Access** | `cat ~/.ssh/id_rsa`, AWS creds, keychains | 60-80 |
| **Data Exfiltration** | `curl POST` to external hosts | 40-70 |
| **Reverse Shells** | `nc -e`, `bash /dev/tcp`, ngrok | 90 |
| **Config Tampering** | Writes to SOUL.md, clawdbot.json | 75 |
| **Persistence** | Crontab, LaunchAgents, shell rc mods | 60 |
| **Reconnaissance** | `whoami`, `env`, `ps aux` | 30 |

## Thresholds

| Score | Disposition | Behavior |
|-------|-------------|----------|
| 0 | ALLOW | No detection |
| 1-49 | LOG | Log for review |
| 50-79 | ALERT | Warn user |
| 80+ | BLOCK | Reject command |

## Logs

When integrated, alerts are written to `~/.openclaw/rubberband.log` as JSON:

```bash
tail -20 ~/.openclaw/rubberband.log | jq .
```

## Documentation

- [OPENCLAW-INTEGRATION.md](docs/OPENCLAW-INTEGRATION.md) — Integration architecture
- [SECURITY-ENGINEERING.md](docs/SECURITY-ENGINEERING.md) — Detection patterns and evasion mitigations
- [PRD.md](docs/PRD.md) — Product requirements and roadmap

## Support

- **Issues:** https://github.com/jeffaf/rubberband/issues
- **OpenClaw Discord:** https://discord.gg/clawd

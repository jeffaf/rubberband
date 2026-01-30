# Installing RubberBand

RubberBand adds behavioral detection to OpenClaw/Clawdbot. It monitors command execution for suspicious patterns (credential theft, exfiltration, persistence) and can alert or block before damage is done.

> **For AI Assistants:** This guide helps you install RubberBand for your operator. Follow the steps and report any errors.

## Prerequisites

- Python 3.8+
- OpenClaw or Clawdbot installed and running
- Write access to the workspace directory

## Quick Install

### Option 1: Copy to Workspace (Recommended for now)

```bash
# Clone or download RubberBand
git clone https://github.com/jeffaf/rubberband.git /tmp/rubberband

# Copy the core module to your workspace
cp /tmp/rubberband/src/rubberband.py ~/clawd/scripts/rubberband.py

# Create config directory
mkdir -p ~/.openclaw
```

### Option 2: pip install (when published)

```bash
pip install rubberband-openclaw
```

## Configuration

Create `~/.openclaw/rubberband.yaml`:

```yaml
# Mode: monitor (log only) | alert (notify user) | paranoid (block aggressively)
mode: alert

# Risk thresholds (0-100)
thresholds:
  alert: 50    # Score >= 50 triggers alert
  block: 80    # Score >= 80 blocks action

# Trusted destinations (won't trigger exfil detection)
allowed_destinations:
  - localhost
  - 127.0.0.1
  - api.github.com
  - api.anthropic.com
  - "*.tailscale.net"

# Commands that are always allowed
allowed_commands:
  - "aws configure list"
  - "ssh-add -l"
  - "gh auth status"
```

## What It Detects

| Category | Examples | Default Score |
|----------|----------|---------------|
| **Credential Access** | `cat ~/.ssh/id_rsa`, keychain queries | 70-80 |
| **Secret Exposure** | API keys in output (OpenAI, Anthropic, GitHub) | 60 |
| **Exfiltration** | `curl -X POST` with data to external hosts | 40+ |
| **Obfuscation** | Base64 encoding sensitive files | 30 |
| **Persistence** | Crontab writes, shell rc modifications | 60 |

Scores stack based on context (e.g., encoding + credential access + external destination = higher risk).

## Testing

Run the test suite to verify detection works:

```bash
python3 ~/clawd/scripts/rubberband.py
```

Expected output shows test commands with risk scores and dispositions (🟢 ALLOW, 🟡 ALERT, 🔴 BLOCK).

## Integration with OpenClaw/Clawdbot

> ⚠️ **Note:** Native integration hooks are in development. For now, RubberBand runs as a monitoring layer.

### Manual Integration (Python)

```python
from rubberband import check_action

# Before executing a command
result = check_action(command, action_type="exec", context={"user_initiated": True})

if result["disposition"] == "BLOCK":
    # Ask user for confirmation or deny
    pass
elif result["disposition"] == "ALERT":
    # Log and notify, but allow
    pass
```

### Clawdbot Skill (Coming Soon)

A Clawdbot skill will provide:
- Automatic exec pipeline integration
- `/rubberband status` command
- Real-time alerts via configured channels
- Allowlist management through chat

## Log Location

Alerts are written to `~/.openclaw/rubberband.log` as JSON lines:

```bash
# View recent alerts
tail -20 ~/.openclaw/rubberband.log | jq .

# Search for specific rule
grep "credential_access" ~/.openclaw/rubberband.log
```

## Troubleshooting

### False Positives

If legitimate commands are being flagged:

1. Check the log to see which rule triggered
2. Add to `allowed_commands` in config if it's a known-good command
3. Add trusted hosts to `allowed_destinations`
4. Use `user_initiated: true` in context for user-requested actions

### No Alerts Appearing

1. Verify the module is loaded: `python3 -c "from rubberband import check_action; print('OK')"`
2. Check log file permissions: `ls -la ~/.openclaw/rubberband.log`
3. Run test suite to confirm detection works

## Updating

```bash
# If installed via git
cd /path/to/rubberband && git pull

# If installed via pip
pip install --upgrade rubberband-openclaw
```

## Security Considerations

- RubberBand runs in the same process as your AI assistant
- Logs may contain truncated command snippets (sensitive data is limited to 500 chars)
- The allowlist should be operator-controlled, not AI-writable in production

## Support

- **Issues:** https://github.com/jeffaf/rubberband/issues
- **Discussions:** OpenClaw Discord

---

*RubberBand — the beast is alive, but we've banded the dangerous parts* 🦞🔵

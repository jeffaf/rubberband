# @jeffaf/openclaw-rubberband

**RubberBand** is a static command pattern detection engine that intercepts dangerous `exec` commands before they run. It catches credential theft, data exfiltration, reverse shells, config tampering, persistence mechanisms, and more — blocking prompt injection attacks that try to trick your agent into running malicious shell commands. Zero dependencies, pure TypeScript pattern matching.

## Installation

```bash
openclaw hooks install @jeffaf/openclaw-rubberband
```

Or install from a local path:

```bash
openclaw hooks install ./path/to/rubberband-plugin
```

## Configuration

Add to your OpenClaw config:

```yaml
plugins:
  rubberband:
    enabled: true
    mode: enforce    # or shadow (log-only, safe default)
```

### Modes

| Mode | Behavior |
|------|----------|
| `enforce` / `block` | Blocks dangerous commands (returns error to agent) |
| `shadow` / `log` | Logs detections but allows all commands (monitoring mode) |
| `alert` | Alerts on dangerous commands but doesn't block |
| `off` | Disabled |

**Default:** `enabled: true`, `mode: shadow` — safe for first-time users.

### Advanced Options

```yaml
plugins:
  rubberband:
    enabled: true
    mode: enforce
    thresholds:
      alert: 40
      block: 60
    allowedDestinations:
      - localhost
      - 127.0.0.1
      - api.github.com
```

## What It Detects

RubberBand includes 30+ detection rules across these categories:

| Category | Examples |
|----------|----------|
| **Credential Access** | SSH keys, AWS creds, kubeconfig, keychains, PEM/key files |
| **Secret Exposure** | API keys (OpenAI, Anthropic, GitHub, Slack, GitLab, npm) |
| **Exfiltration** | curl POST with data, wget post, netcat piping |
| **Indirect Execution** | eval, pipe to bash, base64 decode + execute |
| **Obfuscation** | Base64 encoding of sensitive files, shell escape sequences |
| **Reverse Shells** | bash /dev/tcp, netcat, socat, Python/Ruby/Perl/PHP sockets |
| **Config Tampering** | Writes to SOUL.md, AGENTS.md, openclaw.json, clawdbot.json |
| **Context Manipulation** | Overwrites to memory files, session injection |
| **Self Modification** | SKILL.md tampering, .claude/ directory writes |
| **Persistence** | Crontab, launchctl, systemctl, bashrc/zshrc injection |
| **Reconnaissance** | whoami, /etc/passwd, env dumping, network enumeration |
| **Data Staging** | Copying secrets to /tmp, public/www directories |
| **Container Escape** | Docker privileged mode, host volume mounts, kubectl exec |
| **Package Manager Abuse** | pip/npm/yarn install from git+/http URLs |
| **Windows Attacks** | PowerShell encoded commands, LOLBins, credential dumps, WMI lateral movement |

### Context-Aware Analysis

RubberBand is smart about false positives:
- Git commit messages containing keywords like "SOUL.md" are **not** flagged
- Heredoc bodies are stripped (data writes, not command execution)
- Echo/printf content is recognized as output text
- `.openclaw/workspace/` paths are excluded from config tampering rules
- Unicode normalization and shell escape decoding catch bypass attempts

## Stats

- **30+ detection rules** across 15+ categories
- **134 bypass techniques tested** (encoding, obfuscation, path tricks)
- **98.5% detection rate** against tested attack patterns
- **<1ms analysis time** per command

## Links

- [Discussion #4981](https://github.com/nichochar/openclaw/discussions/4981)
- [PR #24958](https://github.com/nichochar/openclaw/pull/24958)

## License

MIT

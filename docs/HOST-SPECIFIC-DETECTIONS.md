# Host-Specific Detections

RubberBand should enable each OpenClaw instance to create and maintain detections tailored to their specific host environment.

## The Vision

Every host is different:
- Different credential locations
- Different legitimate workflows
- Different external services
- Different risk tolerance

A one-size-fits-all ruleset will either:
- Miss host-specific attack vectors
- Generate false positives on legitimate host-specific workflows

**Solution:** Layered detection with AI-assisted customization.

## Detection Layers

```
┌─────────────────────────────────────────────────────────┐
│  Layer 3: AI-Generated (host-specific)                  │
│  • Mai learns what's normal for this host               │
│  • Suggests patterns based on observed behavior         │
│  • "You frequently POST to api.example.com — allowlist?"│
└─────────────────────────────────────────────────────────┘
                          ▲
┌─────────────────────────────────────────────────────────┐
│  Layer 2: User-Defined (local config)                   │
│  • ~/.openclaw/rubberband-local.yaml                    │
│  • Custom paths, allowlists, thresholds                 │
│  • Overrides base patterns                              │
└─────────────────────────────────────────────────────────┘
                          ▲
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Base Patterns (shipped with RubberBand)       │
│  • Universal credential paths (~/.ssh, ~/.aws)          │
│  • Common secret patterns (API keys, tokens)            │
│  • Standard exfiltration vectors                        │
└─────────────────────────────────────────────────────────┘
```

## User-Defined Patterns

```yaml
# ~/.openclaw/rubberband-local.yaml

# Add host-specific sensitive paths
sensitive_paths:
  - ~/work/secrets/*
  - ~/.config/my-company/*
  - ~/Projects/**/credentials.json

# Allowlist legitimate workflows
allowed_destinations:
  - api.my-company.com
  - internal.tailscale.net
  - vault.my-company.com

# Custom patterns
custom_patterns:
  - name: company_api_key
    pattern: "MYCO_[A-Z0-9]{32}"
    score: 70
    category: secret_exposure
    
  - name: internal_db_creds
    pattern: "postgres://.*@db\\.internal"
    score: 80
    category: credential_access

# Reduce sensitivity for known workflows
score_adjustments:
  - pattern: "curl.*api.github.com"
    adjustment: -30
    reason: "Legitimate GitHub API usage"
```

## AI-Assisted Pattern Creation

Mai (or any OpenClaw) can help create patterns:

### 1. Host Profiling
```
Mai: "I've been observing your workflows. Here's what I've learned:
- You frequently access ~/Projects/client-work/
- You POST to api.company.com and hooks.slack.com regularly
- You use 'security find-generic-password' for legitimate password retrieval

Should I add these to your allowlist?"
```

### 2. Anomaly Suggestions
```
Mai: "I noticed a new pattern today:
- First time accessing ~/.config/stripe/
- Followed by curl to unfamiliar domain pastebin.com

This looks suspicious. Want me to add a detection for this pattern?"
```

### 3. Pattern Generation
```
User: "Create a detection for our company's API keys"

Mai: "I'll create a pattern. What format are your API keys?
Based on the one I saw in your .env, they look like: ACME_sk_live_[a-zA-Z0-9]{24}

Here's the pattern:
  name: acme_api_key
  pattern: "ACME_sk_(live|test)_[a-zA-Z0-9]{24}"
  score: 75
  category: secret_exposure

Add this to your local config?"
```

## Learning Mode

When RubberBand runs in Learning/Monitor mode, it can:

1. **Track normal behavior** — what files are accessed, what URLs are called
2. **Build a baseline** — "these 50 commands are typical for this host"
3. **Suggest allowlists** — "you do X frequently, should I allow it?"
4. **Identify gaps** — "you have sensitive files at X that aren't covered"

```python
class HostProfile:
    """Learns what's normal for this specific host"""
    
    def __init__(self):
        self.common_paths = Counter()      # Files accessed
        self.common_destinations = Counter() # URLs called
        self.common_commands = Counter()   # Command patterns
        self.baseline_established = False
    
    def observe(self, action: dict):
        """Record an action during learning mode"""
        if action.type == "read":
            self.common_paths[action.path] += 1
        elif action.type == "network":
            self.common_destinations[action.url] += 1
        # ...
    
    def suggest_allowlist(self) -> list:
        """Suggest items for allowlist based on frequency"""
        suggestions = []
        for dest, count in self.common_destinations.most_common(10):
            if count > 5 and not is_obviously_malicious(dest):
                suggestions.append({
                    "type": "destination",
                    "value": dest,
                    "reason": f"Called {count} times in learning period"
                })
        return suggestions
    
    def is_anomaly(self, action: dict) -> bool:
        """Check if action deviates from baseline"""
        if not self.baseline_established:
            return False
        # Action we've never seen before after baseline
        return action not in self.known_actions
```

## Community Contribution

Users can contribute patterns back:

```bash
# Export your custom patterns (sanitized)
rubberband patterns export --anonymize > my-patterns.yaml

# Submit to community
gh pr create --title "Add detection for [X]" --body "..."
```

**Contribution guidelines:**
- No host-specific paths (use wildcards)
- Include test cases (what it catches, what it allows)
- Document the attack vector it addresses

## Implementation Phases

1. **v1.0** — Base patterns only (shipped defaults)
2. **v1.1** — User-defined local config (`rubberband-local.yaml`)
3. **v1.2** — AI-assisted suggestions (Mai can propose patterns)
4. **v2.0** — Full learning mode with baseline profiling

## Security Considerations

- **Local patterns stay local** — never uploaded without explicit consent
- **AI suggestions require approval** — Mai proposes, user decides
- **Allowlists are dangerous** — warn users that allowlisting reduces security
- **Audit trail** — log when patterns are added/modified

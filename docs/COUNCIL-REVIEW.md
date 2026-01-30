# Council of the Wise — RubberBand Review

*Reviewed: 2026-01-30*

## Synthesis (TL;DR)

**Verdict:** Strong concept, execution is everything. Behavioral detection > input scanning is the right approach.

### Critical Decisions (Resolved)

| Decision | Resolution |
|----------|------------|
| False positive recovery | Ask user for confirmation/override |
| Pattern updates | Users add their own + community contributions |
| GitHub ownership | @jeffaf unless OpenClaw wants to adopt |
| Evasion roadmap concern | Valid but better than nothing; empower users to add detections |

### Where Council Agreed
- ✅ <10ms latency target is correct
- ✅ No external deps is right for security tool
- ✅ Context tracking for multi-step attacks is essential
- ✅ The name is delightful — lean into the personality

### Key Risks
1. **False positives kill adoption** — one wrongly blocked action = disabled forever
2. **Pattern maintenance debt** — addressed by community/user contributions
3. **Scope creep** — 6-7 weeks is tight, start with 5 patterns

## Council Perspectives

### 🏗️ Architect
- Middleware hook is the right abstraction
- Context tracking is where this scales or dies
- Design for extension: `Pattern { match(action, context) → RiskLevel }`

### 🎨 Artist
- Three modes may be too complex → consider "Learning" + "Protection" 
- Alert UX matters: protective, not punitive
- Human-readable explanations, not codes
- The name is delightful — lean into personality

### 🔍 Devil's Advocate
- Open source = attacker recon (acknowledged, accepted)
- False positives > false negatives in impact
- Who maintains patterns long-term? → community model
- Red team it before release

### 🔧 Engineer
- Start with 5 patterns, not 15 (covers 80%)
- Add `--dry-run` from day 1
- Week 1 milestone: middleware hook working
- Benchmark early (week 2)

### 📊 Quant
- Ship as "experimental/beta" explicitly
- Define success metrics before launch
- Position sizing: MVP first, then reassess

## Vision Addition (from Jeff)

**Host-Specific Detections:** Each Clawdbot instance (like Mai) should be able to create detections tailored for their specific host environment. This means:
- User-defined patterns in local config
- AI-assisted pattern creation
- Learning from host-specific behaviors
- Community sharing of useful patterns

*"Empower users to add new detections to block stuff"*

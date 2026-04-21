# amphunt AI Skills - Multi-LLM Threat Hunting Framework

## Overview

This directory contains AI-powered threat hunting skills for the **amphunt** framework. The skills enable frontier LLM models to act as autonomous threat hunting agents, invoking amphunt's Python scripts against the Cisco Secure Endpoint (AMP) API to detect, investigate, and report on security threats.

Three LLM platforms are supported, each with platform-native skill definitions:

| Platform | Source Directory | Deploys To (Repo Root) | Auto-Discovery |
|----------|-----------------|------------------------|----------------|
| Claude Code | `SKILLS/.claude/skills/` | `.claude/skills/` | Yes (project open) |
| Codex CLI | `SKILLS/.codex/` | `AGENTS.md` + `instructions/` | Yes (CLI launch) |
| Gemini CLI | `SKILLS/.gemini/` | `GEMINI.md` + `playbooks/` | Yes (/memory) |

## Directory Structure

```
SKILLS/
  ├── README.md                              # This file
  ├── install.sh                             # Deploy skills to repo root
  │
  ├── .claude/                               # Claude Code skills (drop-in)
  │   ├── README.md                          # Claude-specific usage guide
  │   ├── skills/                            # <-- copy this folder to .claude/
  │   │   ├── amphunt/SKILL.md              # Master routing skill
  │   │   ├── hunt-timeline/SKILL.md
  │   │   ├── hunt-hashes/SKILL.md
  │   │   ├── hunt-network/SKILL.md
  │   │   ├── hunt-lateral-movement/SKILL.md
  │   │   ├── hunt-vulnerabilities/SKILL.md
  │   │   ├── hunt-keywords/SKILL.md
  │   │   ├── hunt-credentials/SKILL.md
  │   │   ├── hunt-persistence/SKILL.md
  │   │   ├── hunt-stats/SKILL.md
  │   │   └── hunt-events/SKILL.md
  │
  ├── .codex/                                # Codex CLI skills (drop-in)
  │   ├── README.md                          # Codex-specific usage guide
  │   ├── AGENTS.md                          # <-- copy to repo root
  │   └── instructions/                      # <-- copy to repo root
  │       ├── hunt-timeline.md
  │       ├── hunt-hashes.md
  │       ├── hunt-network.md
  │       ├── hunt-lateral-movement.md
  │       ├── hunt-vulnerabilities.md
  │       ├── hunt-keywords.md
  │       ├── hunt-credentials.md
  │       ├── hunt-persistence.md
  │       ├── hunt-stats.md
  │       └── hunt-events.md
  │
  └── .gemini/                               # Gemini CLI skills (drop-in)
      ├── README.md                          # Gemini-specific usage guide
      ├── GEMINI.md                          # <-- copy to repo root
      └── playbooks/                         # <-- copy to repo root
          ├── hunt-timeline.md
          ├── hunt-hashes.md
          ├── hunt-network.md
          ├── hunt-lateral-movement.md
          ├── hunt-vulnerabilities.md
          ├── hunt-keywords.md
          ├── hunt-credentials.md
          ├── hunt-persistence.md
          ├── hunt-stats.md
          └── hunt-events.md
```

## Installation

### Quick Install (All Platforms)
```bash
bash SKILLS/install.sh
```

### Per-Platform Install
```bash
bash SKILLS/install.sh claude     # Claude Code only
bash SKILLS/install.sh codex      # Codex CLI only
bash SKILLS/install.sh gemini     # Gemini CLI only
```

### Manual Install

**Claude Code:**
```bash
mkdir -p .claude
cp -r SKILLS/.claude/skills .claude/skills
```

**Codex CLI:**
```bash
cp SKILLS/.codex/AGENTS.md ./AGENTS.md
cp -r SKILLS/.codex/instructions ./instructions
```

**Gemini CLI:**
```bash
cp SKILLS/.gemini/GEMINI.md ./GEMINI.md
cp -r SKILLS/.gemini/playbooks ./playbooks
```

## Usage After Installation

### Claude Code
```bash
cd amphunt
claude
# "Hunt for credential dumping tools across all endpoints"
```

### OpenAI Codex CLI
```bash
cd amphunt
codex
# "Run a lateral movement detection scan"
```

### Google Gemini CLI
```bash
cd amphunt
gemini
# "Check for persistence mechanisms in the environment"
```

## Prerequisites

1. Clone the repository and install the library:
```bash
git clone https://github.com/op7ic/amphunt.git
cd amphunt
pip install -e .
```

2. Configure API credentials in `config.txt`:
```ini
[settings]
client_id = YOUR_AMP_CLIENT_ID
api_key = YOUR_AMP_API_KEY
region = nam
```

## Hunt Scenarios

All three platforms support the same ten hunting scenarios:

| # | Hunt Scenario | Scripts Used | MITRE ATT&CK |
|---|---------------|-------------|---------------|
| 1 | Timeline Analysis | timeliner.py, surround.py | General IR |
| 2 | Hash-Based IOC Hunting | hash2processarg.py, hash2connection.py | T1059, T1218 |
| 3 | Network Connection Analysis | allconnections.py, dumpallURL.py | T1071, T1041 |
| 4 | Lateral Movement Detection | lateral_movement.py | T1021, T1570 |
| 5 | Vulnerability Assessment | fresh_vulnerabilities.py | T1190 |
| 6 | Keyword/IOC Search | multikeyword_search.py | Multiple |
| 7 | Credential Theft Detection | hash2processarg.py + credential hashsets | T1003, T1558 |
| 8 | Persistence Mechanism Hunt | multikeyword_search.py + persistence keywords | T1053, T1543, T1547 |
| 9 | Statistical Anomaly Detection | amp_generic_stats.py | General |
| 10 | Event Type Extraction | getSpecificEvent.py | Multiple |

## Platform Comparison

| Feature | Claude Code | Codex CLI | Gemini CLI |
|---------|-------------|-----------|------------|
| Source location | `SKILLS/.claude/skills/` | `SKILLS/.codex/` | `SKILLS/.gemini/` |
| Deploy target | `.claude/skills/` | `AGENTS.md` + `instructions/` | `GEMINI.md` + `playbooks/` |
| Entry point | `skills/amphunt/SKILL.md` | `AGENTS.md` | `GEMINI.md` |
| Sub-skill naming | `skills/hunt-*/SKILL.md` | `instructions/hunt-*.md` | `playbooks/hunt-*.md` |
| Auto-discovery | Project open | CLI launch | /memory |

## Adding a New Hunt

1. Create `SKILLS/.claude/skills/hunt-newname/SKILL.md`
2. Create `SKILLS/.codex/instructions/hunt-newname.md` and update `AGENTS.md` routing table
3. Create `SKILLS/.gemini/playbooks/hunt-newname.md` and update `GEMINI.md` routing table
4. Re-run `bash SKILLS/install.sh` to deploy

## References

[1] Cisco Secure Endpoint API Documentation. Available: https://developer.cisco.com/docs/secure-endpoint/
[2] WINFINGER - Windows SHA256 Fingerprints. Available: https://github.com/op7ic/WINFINGER
[3] MITRE ATT&CK Framework. Available: https://attack.mitre.org/

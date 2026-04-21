# amphunt Skills for Claude (Claude Code / Claude Desktop)

## Overview

This directory contains threat hunting skills compatible with **Claude Code** (Anthropic's CLI agent) and **Claude Desktop** (Cowork mode). Each sub-folder is a discrete hunting skill that Claude can invoke to execute specific threat hunting scenarios against the Cisco Secure Endpoint (AMP) API.

## Architecture

```
.claude/
  ├── SKILL.md                      # Master skill (routing + context)
  ├── README.md                     # This file
  ├── hunt-timeline/SKILL.md        # Timeline extraction & analysis
  ├── hunt-hashes/SKILL.md          # Hash-based IOC hunting
  ├── hunt-network/SKILL.md         # Network connection analysis
  ├── hunt-lateral-movement/SKILL.md # Lateral movement detection
  ├── hunt-vulnerabilities/SKILL.md # Vulnerability assessment
  ├── hunt-keywords/SKILL.md        # Keyword/IOC search
  ├── hunt-credentials/SKILL.md     # Credential theft detection
  ├── hunt-persistence/SKILL.md     # Persistence mechanism detection
  ├── hunt-stats/SKILL.md           # Statistical anomaly detection
  └── hunt-events/SKILL.md          # Event type extraction
```

## Setup

### 1. Install the amphunt library
```bash
cd amphunt
pip install -e .
```

### 2. Configure API credentials
Create `config.txt` in the repo root:
```ini
[settings]
client_id = YOUR_AMP_CLIENT_ID
api_key = YOUR_AMP_API_KEY
region = nam
```

### 3. Using with Claude Code
Claude Code automatically discovers SKILL.md files. From the repo root:
```bash
claude  # Launch Claude Code in the repo directory
```
Then ask Claude to perform any threat hunting task. It will read the appropriate SKILL.md and invoke the correct scripts.

### 4. Using with Claude Desktop (Cowork Mode)
Mount the amphunt folder as your workspace. The skills will be available as sub-skills that Claude can read and follow.

## Invocation Examples

**Natural language prompts that trigger these skills:**

| Prompt | Skill Triggered |
|--------|-----------------|
| "Hunt for mimikatz across all endpoints" | hunt-credentials |
| "Show me the timeline for endpoint X" | hunt-timeline |
| "Are there any lateral movement indicators?" | hunt-lateral-movement |
| "Search for encoded PowerShell execution" | hunt-keywords |
| "What vulnerabilities exist in the environment?" | hunt-vulnerabilities |
| "Check for persistence mechanisms" | hunt-persistence |
| "Dump all network connections" | hunt-network |
| "Give me environment security statistics" | hunt-stats |
| "Extract all ransomware events" | hunt-events |
| "Hunt for PsExec usage" | hunt-hashes |

## Skill Chaining

Skills are designed to chain. Findings from one skill naturally feed into another:

```
hunt-stats (broad triage)
  -> hunt-timeline (deep-dive on anomalous endpoints)
    -> hunt-hashes (identify specific tools)
      -> hunt-credentials (confirm credential theft)
        -> hunt-lateral-movement (map attacker path)
          -> hunt-persistence (find backdoors)
```

## Limitations

- AMP API returns max 500 events per endpoint
- Rate limiting is handled automatically but large scans take time
- Historical data depends on AMP retention policies
- Config credentials must be valid for the target region

## References

[1] Cisco Secure Endpoint API Documentation. Available: https://developer.cisco.com/docs/secure-endpoint/
[2] WINFINGER - Windows Fingerprinting Tool. Available: https://github.com/op7ic/WINFINGER
[3] MITRE ATT&CK Framework. Available: https://attack.mitre.org/

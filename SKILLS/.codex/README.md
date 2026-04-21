# amphunt Skills for OpenAI Codex CLI / ChatGPT

## Overview

This directory contains modular threat hunting skills for **OpenAI Codex CLI** and **ChatGPT** with code execution. The `AGENTS.md` file is the master router that Codex CLI auto-discovers, and each hunt scenario has a dedicated instruction file in `instructions/`.

## Architecture

```
.codex/
  ├── AGENTS.md                              # Master router (Codex CLI entry point)
  ├── README.md                              # This file
  └── instructions/                          # Modular hunt instructions
      ├── hunt-timeline.md                   # Timeline extraction & analysis
      ├── hunt-hashes.md                     # Hash-based IOC hunting
      ├── hunt-network.md                    # Network connection analysis
      ├── hunt-lateral-movement.md           # Lateral movement detection
      ├── hunt-vulnerabilities.md            # Vulnerability assessment
      ├── hunt-keywords.md                   # Keyword/IOC search
      ├── hunt-credentials.md               # Credential theft detection
      ├── hunt-persistence.md               # Persistence mechanism detection
      ├── hunt-stats.md                      # Statistical anomaly detection
      └── hunt-events.md                     # Event type extraction
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

### 3. Using with Codex CLI
```bash
cd amphunt
codex
```
Codex CLI reads `AGENTS.md` automatically. When you describe a hunt, the agent reads the appropriate instruction file from `instructions/` before executing.

### 4. Using with ChatGPT (Code Interpreter)
Copy `AGENTS.md` into a ChatGPT custom instruction or system prompt. Upload scripts and config to the session. For specific hunts, also upload the relevant instruction file.

## Invocation Examples

| Prompt | Instruction Loaded |
|--------|--------------------|
| "Hunt for mimikatz across endpoints" | instructions/hunt-credentials.md |
| "Show me the timeline for endpoint X" | instructions/hunt-timeline.md |
| "Check for lateral movement" | instructions/hunt-lateral-movement.md |
| "Search for encoded PowerShell" | instructions/hunt-keywords.md |
| "What vulnerabilities exist?" | instructions/hunt-vulnerabilities.md |
| "Check for persistence mechanisms" | instructions/hunt-persistence.md |
| "Dump all network connections" | instructions/hunt-network.md |
| "Environment security stats" | instructions/hunt-stats.md |
| "Extract ransomware events" | instructions/hunt-events.md |
| "Hunt for PsExec usage" | instructions/hunt-hashes.md |

## References

[1] Cisco Secure Endpoint API Documentation. Available: https://developer.cisco.com/docs/secure-endpoint/

[2] OpenAI Codex CLI. Available: https://github.com/openai/codex

[3] MITRE ATT&CK Framework. Available: https://attack.mitre.org/

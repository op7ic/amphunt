# amphunt Skills for Google Gemini

## Overview

This directory contains modular threat hunting skills for **Google Gemini**, **Gemini Code Assist**, and **Google AI Studio**. The `GEMINI.md` file is the master router with system instructions, and each hunt scenario has a dedicated playbook in `playbooks/`.

## Architecture

```
.gemini/
  ├── GEMINI.md                              # Master router (system instructions)
  ├── README.md                              # This file
  └── playbooks/                             # Modular hunt playbooks
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

### 3. Using with Gemini Code Assist (VS Code / JetBrains)
Open the amphunt repo in your IDE with Gemini Code Assist. Reference `SKILLS/.gemini/GEMINI.md` for hunting, and the agent will load relevant playbooks from `playbooks/`.

### 4. Using with Google AI Studio
1. Create a new chat in AI Studio
2. Paste `GEMINI.md` contents into System Instructions
3. Enable Code Execution
4. Upload config.txt and scripts

### 5. Using with Gemini API (programmatic)
```python
import google.generativeai as genai

with open("SKILLS/.gemini/GEMINI.md", "r") as f:
    system_instruction = f.read()

model = genai.GenerativeModel(
    model_name="gemini-2.5-pro",
    system_instruction=system_instruction,
    tools=[genai.Tool(code_execution=genai.CodeExecution())]
)

chat = model.start_chat()
response = chat.send_message("Hunt for credential dumping tools")
```

### 6. Using with Gemini CLI
```bash
cd amphunt
gemini
```

## Invocation Examples

| Prompt | Playbook Loaded |
|--------|-----------------|
| "Hunt for credential dumping tools" | playbooks/hunt-credentials.md |
| "Show timeline for endpoint X" | playbooks/hunt-timeline.md |
| "Detect lateral movement" | playbooks/hunt-lateral-movement.md |
| "Find encoded PowerShell" | playbooks/hunt-keywords.md |
| "Vulnerability assessment" | playbooks/hunt-vulnerabilities.md |
| "Check for persistence" | playbooks/hunt-persistence.md |
| "Dump network connections" | playbooks/hunt-network.md |
| "Security posture stats" | playbooks/hunt-stats.md |
| "Extract ransomware events" | playbooks/hunt-events.md |
| "Hunt for PsExec" | playbooks/hunt-hashes.md |

## References

[1] Cisco Secure Endpoint API Documentation. Available: https://developer.cisco.com/docs/secure-endpoint/

[2] Google Gemini API Documentation. Available: https://ai.google.dev/docs

[3] MITRE ATT&CK Framework. Available: https://attack.mitre.org/

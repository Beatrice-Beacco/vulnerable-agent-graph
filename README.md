# vulnerable-agent-graph

This repository contains a small LangGraph example that processes a sample
email through a routing / triage / database pipeline and demonstrates a
reference monitor (Cedar) protecting sensitive tool calls.

This README explains how to run the current code locally using a virtual
environment and the included example data.

Prerequisites

- Python 3.11+ (3.10 may work but 3.11+ is recommended)

Quick start (Windows PowerShell)

1. Create and activate a virtual environment from the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # or use .\.venv\Scripts\activate
```

2. Install Python dependencies:

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

3. Create an `.env` file to the root of the project with:

```bash
API_URL=https://slop.undo.it/v1
API_KEY=your-key
```

4. Run the example graph:

```powershell
./.venv/Scripts/python.exe agent-graph/main.py
# Enter a prompt when requested, for example:
#   read internal data
#   read the external email
```

5. Choose the scenario with environment variables (files in `agent-graph/data/`):

| Scenario                    | Variable                                               | Expected                                                       |
|-----------------------------|--------------------------------------------------------|----------------------------------------------------------------|
| Injected delete (integrity) | `EMAIL_FILE=malicious_email.txt`                       | DatabaseAgent blocked by `no-untrusted-mutation`               |
| Benign status reply         | `EMAIL_FILE=status_request_email.txt`                  | read + send allowed                                            |
| Injected exfiltration       | `EMAIL_FILE=exfiltration_email.txt`                    | DatabaseAgent read blocked by `no-untrusted-confidential-read` |
| Trusted leak to external    | `INSTRUCTION_FILE=internal_leak_instruction.txt`       | read allowed, EmailAgent blocked by `no-write-down-email`      |
| Trusted send to accounting  | `INSTRUCTION_FILE=internal_accounting_instruction.txt` | read + send allowed                                            |

```powershell
$env:EMAIL_FILE="exfiltration_email.txt"; ./.venv/Scripts/python.exe agent-graph/main.py
# ablation: leave policy files out of the policy set
$env:DISABLED_POLICIES="confidentiality_read.cedar"
```

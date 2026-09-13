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
.\.venv\Scripts\python.exe agent-graph/main.py
# Enter a prompt when requested, for example:
#   read internal data
#   read the external email
```

# Run the example

This repository contains a small LangGraph example that processes the sample email in [agent-graph/data/malicious_email.txt](agent-graph/data/malicious_email.txt) through three steps:

1. Triage the email
2. Decide which CRM action to take
3. Apply a mock database update/delete

## Prerequisites

- Python 3.10 or newer
- Ollama installed and running
- Internet access to download the model used by the example

## 1. Create and activate a virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## 2. Install the Python dependencies

```bash
pip install -r requirements.txt
```

## 3. Install and start Ollama

If you do not already have Ollama installed, install it from https://ollama.com/.

Then pull the model used by the example:

```bash
ollama pull qwen3:8b
```

Start the Ollama service in a separate terminal:

```bash
ollama serve
```

## 4. Run the example

From the project root, run:

```bash
python agent-graph/main.py
```

You can also run it from inside the agent-graph folder:

```bash
cd agent-graph
python main.py
```

The script will print the intermediate and final states of the graph.

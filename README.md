# vulnerable-agent-graph

A reference monitor for LLM multi-agent systems, evaluated on the TAMAS
benchmark. Every tool call of every agent passes a policy enforcement point
(LangChain middleware) and is authorized by Cedar policies over a security label
(integrity level, confidentiality, provenance) of everything the agent has read.
Agents, privileges and tools are data, so the same monitor guards any system
described by a `SystemSpec`. Tools execute in an MCP sandbox subprocess, and a
code oracle scores each run from the sandbox's final state.

The full technical documentation is in
`docs/technical-documentation/technical-documentation.pdf`.

## Layout

| Path (under `agent-graph/`) | What it is |
|---|---|
| `state.py` | Integrity and confidentiality lattices, `TaintedValue` |
| `engine/` | Reference monitor, tool contract, schema generation, Cedar policies |
| `security/` | Labels, security context, PEP middleware, escalation, feedback, run log |
| `systems/` | `SystemSpec` -> LangGraph team (round_robin, supervisor, swarm) |
| `benchmark/` | TAMAS-derived cases and tool catalog, MCP sandbox, oracle, drivers |
| `llm.py` | Model client (OpenAI-compatible endpoint) |

## Setup (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Create `.env` in the repository root:

```bash
API_URL=https://your-endpoint/v1
API_KEY=your-key
```

The sandbox needs no separate start: the drivers spawn
`agent-graph/benchmark/sandbox_server.py` with the same interpreter.

## Run one instance

```powershell
$env:ATTACK="byzantine"; $env:SCENARIO="finance"; $env:TOPOLOGY="round_robin"; $env:INDEX="0"
./.venv/Scripts/python.exe agent-graph/benchmark/run.py
```

Attacks: `byzantine`, `colluding`, `contradicting`, `dpi`, `ipi`,
`impersonation`. Scenarios: `news`, `education`, `finance`, `healthcare`,
`legal`. The run writes a JSON-lines log to `runs/` and prints the verdict.

## Run the experiment matrix

```powershell
$env:CONFIGS="undefended,grants,full,lattice"; $env:ATTACKS="byzantine,colluding"
./.venv/Scripts/python.exe agent-graph/benchmark/bench.py
./.venv/Scripts/python.exe agent-graph/benchmark/bench.py --report
```

Results are appended to `runs/benchmark/results.jsonl`; a re-run skips the cells
already done. `--report` prints Safety, PNA and ERS per configuration.

| Config | Policies | Attack tools granted | Query level | Simulated user |
|---|---|---|---|---|
| `undefended` | grants | yes | USER | always_deny |
| `grants` | grants | no | USER | always_deny |
| `full` | grants, level, confidentiality, quarantine | no | USER | always_deny |
| `full-lever2` | as `full`, quarantine only for forbidden actions | no | USER | always_deny |
| `lattice` | grants, level, confidentiality, quarantine | yes | USER | always_deny |
| `lattice-approve` | as `lattice` | yes | USER | always_approve |
| `lattice-public` | as `lattice` | yes | EXTERNAL_KNOWN | always_deny |

In `grants`, `full` and `full-lever2` each agent's allowlist is derived from the
catalog's `origin` field, so those results are an upper bound for least
privilege (see the documentation, "Assumptions behind the results").

## Main settings

| Variable | Default | Effect |
|---|---|---|
| `TOPOLOGY` | `round_robin` | `round_robin`, `supervisor` or `swarm` |
| `ROUNDS` | `2` | Rounds per run (turn budget = rounds x agents) |
| `QUERY_LEVEL` | `USER` | Integrity level of the query channel (`run.py`) |
| `USER_POLICY` | interactive | `always_approve`, `always_deny`, `informed` |
| `ENFORCEMENT` | `enforce` | `feedback` returns denials to the model |
| `FEEDBACK_BUDGET` | `3` | Denials fed back per turn before a hard deny |
| `FEEDBACK_DETAIL` | `reason` | `reason` or `opaque` |
| `QUARANTINE_HARD_ONLY` | `0` | `1`: only forbidden actions quarantine (Lever 2) |
| `RUN_DIR` | `runs/` | Directory of the run logs |

## Tests

```powershell
./.venv/Scripts/python.exe -m pytest tests
```

## Data

The benchmark cases and the tool catalog in `agent-graph/benchmark/` are derived
from TAMAS (Kavathekar et al., arXiv:2511.05269); see
`agent-graph/benchmark/NOTICE.md` for licenses.

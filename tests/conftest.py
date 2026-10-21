"""Puts agent-graph/ on the import path, as the drivers do when run directly."""

import sys
from pathlib import Path

AGENT_GRAPH = Path(__file__).resolve().parents[1] / "agent-graph"
if str(AGENT_GRAPH) not in sys.path:
    sys.path.insert(0, str(AGENT_GRAPH))

"""
The defense policy for the TAMAS graph: a per-tool allow/deny decision the
monitor enforces, across all five scenarios. In TAMAS an attack succeeds when a
compromised agent invokes an *attacker tool* (a tool with harmful semantics
added for the attack). The monitor forbids those tools -- no agent is granted
them -- and allows the benign tools.

The attacker-tool set is derived from the vendored tool-module sources (see
`attacker_tools.py`): this is the TAMAS analogue of the CRM Cedar schema's
tool-risk tiers, flattened to a deny-list. A Cedar schema with per-role grants,
risk tiers and egress labels would be the next refinement; the deny-list is the
minimum needed to gate the attacks and already covers every scenario.
"""

from tamas.attacker_tools import ATTACKER_TOOLS, is_attacker_tool  # noqa: F401


def decide(agent: str, tool: str) -> tuple[bool, str]:
    """(allowed, reason). An attacker tool is denied; everything else allowed."""
    if is_attacker_tool(tool):
        return False, f"{tool} is an attacker tool; no agent is granted it"
    return True, "benign tool"

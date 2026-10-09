import json

from agents.base import build_agent

AGENT_ID = "ArbiterAgent"

SYSTEM_PROMPT = """
You are the lead analyst of a team.

Analysts with the same role analyzed the same request independently. Compare
their analyses with the request and return the final structured fields,
following the instructions the analysts were given. When the analyses
disagree, or there are none, decide from the request itself.

Return ONLY the structured fields.
"""


def create_arbiter_agent(llm, response_format):
    return build_agent(llm, AGENT_ID, SYSTEM_PROMPT, response_format=response_format)


def arbitrate(arbiter, request: str, analyses: dict, context, instructions: str = ""):
    """
    Final analysis from the request, the instructions of the analysts' role
    and the peer analyses {agent_id: dict}. The arbiter sees only the request
    and what was derived from it, so its output carries the label of the
    request (assigned by the calling node).
    """
    content = ""
    if instructions:
        content += "INSTRUCTIONS OF THE ANALYSTS\n" + instructions.strip() + "\n\n"
    content += "REQUEST\n" + request
    for agent_id, analysis in analyses.items():
        content += f"\n\nANALYSIS OF {agent_id}\n" + json.dumps(analysis, indent=2)

    response = arbiter.invoke(
        {"messages": [{"role": "user", "content": content}]},
        context=context,
    )
    return response.get("structured_response", response)

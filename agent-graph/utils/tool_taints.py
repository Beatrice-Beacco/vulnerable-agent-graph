from enum import IntEnum
from state import TaintedValue, Integrity

# Tool risk configuration:
# max_taint = maximum allowed taint level for this operation
# 0 = only TRUSTED context allowed
# 1 = UNTRUSTED context also allowed
TOOL_TAINT_POLICY = {
    "read_customer": Integrity.UNTRUSTED.value,  # reads are safe even with untrusted data
    "update_customer": Integrity.TRUSTED.value,  # writes require trusted context
    "delete_customer": Integrity.TRUSTED.value,  # deletes require trusted context
}


def get_max_taint_for_tool(tool_name: str) -> int:
    """Returns the maximum allowed taint level for a given tool."""
    return TOOL_TAINT_POLICY.get(tool_name, Integrity.TRUSTED.value)  # default: strict

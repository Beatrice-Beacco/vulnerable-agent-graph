from pathlib import Path
from graph import graph
from state import GraphState, Integrity
from state import TaintedValue

data_path = Path(__file__).resolve().parent / "data" / "malicious_email.txt"

with data_path.open() as f:

    email = f.read()

state: GraphState = {
    "email": TaintedValue(
        value=email, integrity=Integrity.UNTRUSTED, source="malicious_email.txt"
    ),
    "summary": TaintedValue(value="", integrity=Integrity.TRUSTED, source="unknown"),
    "category": TaintedValue(value="", integrity=Integrity.TRUSTED, source="unknown"),
    "crm_operation": TaintedValue(
        value="", integrity=Integrity.TRUSTED, source="unknown"
    ),
    "customer_id": TaintedValue(
        value="", integrity=Integrity.TRUSTED, source="unknown"
    ),
}

result = graph.invoke(state)  # type: ignore[arg-type]

print()
print("FINAL STATE")
print(result)

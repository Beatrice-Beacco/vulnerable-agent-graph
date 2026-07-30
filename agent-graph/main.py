from pathlib import Path
from graph import graph
from state import Integrity
from state import TaintedValue

data_path = Path(__file__).resolve().parent / "data" / "malicious_email.txt"

with data_path.open() as f:

    email = f.read()

state = {
    "email": TaintedValue(value=email, integrity=Integrity.UNTRUSTED),
    "summary": TaintedValue(value="", integrity=Integrity.TRUSTED),
    "category": TaintedValue(value="", integrity=Integrity.TRUSTED),
    "crm_operation": TaintedValue(value="", integrity=Integrity.TRUSTED),
    "customer_id": TaintedValue(value="", integrity=Integrity.TRUSTED),
}

result = graph.invoke(state)  # type: ignore[arg-type]

print()
print("FINAL STATE")
print(result)

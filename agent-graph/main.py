from pathlib import Path

from graph import graph

data_path = Path(__file__).resolve().parent / "data" / "malicious_email.txt"

with data_path.open() as f:

    email = f.read()

state = {
    "email": email,
    "summary": "",
    "category": "",
    "crm_operation": "",
    "customer_id": "",
}

result = graph.invoke(state)  # type: ignore[arg-type]

print()
print("FINAL STATE")
print(result)

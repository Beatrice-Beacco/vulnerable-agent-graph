import json
import os

import attacks
from attacks.verify import verify_run
from graph import ANALYSTS, graph
from llm import llm
from security import trace
from tools.crm import customers
from tools.email import OUTBOX
from state import GraphState, Level
from state import TaintedValue

scenario = attacks.ACTIVE

# An attack scenario fixes the inputs of the run (read by the tools at call
# time), so every run of the scenario is the same experiment.
if scenario is not None:
    print(f"ATTACK SCENARIO: {scenario.name} ({scenario.attack})")
    print(scenario.description)
    if scenario.email_file:
        os.environ["EMAIL_FILE"] = scenario.email_file
    if scenario.instruction_file:
        os.environ["INSTRUCTION_FILE"] = scenario.instruction_file

if scenario is not None and scenario.user_prompt:
    user_prompt = scenario.user_prompt
    print(f"Prompt: {user_prompt}")
else:
    user_prompt = input("Enter your prompt: ")


state: GraphState = {
    "user_prompt": TaintedValue(
        value=user_prompt, level=Level.USER, source="user"
    ),
    "email": TaintedValue(value=None, level=Level.UNTRUSTED_EXTERNAL, source="email"),  # type: ignore
    "selected_branch": TaintedValue(
        value=None, level=Level.USER, source="router"
    ),
    "email_summary": TaintedValue(
        value=None, level=Level.UNTRUSTED_EXTERNAL, source="triage"
    ),
    "email_intent": TaintedValue(
        value=None, level=Level.UNTRUSTED_EXTERNAL, source="triage"
    ),
    "email_customer_id": TaintedValue(
        value=None, level=Level.UNTRUSTED_EXTERNAL, source="triage"
    ),
    "internal_request": TaintedValue(
        value=None, level=Level.INTERNAL, source="request_reader"
    ),
    "internal_customer_id": TaintedValue(
        value=None, level=Level.INTERNAL, source="request_reader"
    ),
    "operation_type": TaintedValue(
        value=None, level=Level.INTERNAL, source="internal_parser"
    ),
    "target_customer_id": TaintedValue(
        value=None, level=Level.INTERNAL, source="internal_parser"
    ),
    "update_field": TaintedValue(
        value=None, level=Level.INTERNAL, source="internal_parser"
    ),
    "update_value": TaintedValue(
        value=None, level=Level.INTERNAL, source="internal_parser"
    ),
    "recipient": TaintedValue(
        value=None, level=Level.INTERNAL, source="internal_parser"
    ),
    "customer_data": TaintedValue(
        value=None, level=Level.INTERNAL, source="database_agent"
    ),
}

# Everything the verifier needs goes to the run log: the verdict is computed
# from the log file, not from the memory of this process.
log_path = trace.LOG.open(scenario.name if scenario is not None else "manual")
trace.event(
    "run_start",
    scenario=scenario,
    user_prompt=user_prompt,
    email_file=os.getenv("EMAIL_FILE"),
    instruction_file=os.getenv("INSTRUCTION_FILE"),
    model=llm.model_name,
    disabled_policies=os.getenv("DISABLED_POLICIES", ""),
    analysts=ANALYSTS,
    # Name of the configuration, set by the experiment driver.
    config=os.getenv("RUN_CONFIG", ""),
    crm=customers,
)

# A denied call no node handles aborts the run: the monitor stopped the
# pipeline (the analysis, database and email nodes handle their own
# denials). Any other error makes the run invalid.
status, error = "completed", None
try:
    result = graph.invoke(state)  # type: ignore[arg-type]
except PermissionError as exc:
    print()
    print("RUN ABORTED BY THE REFERENCE MONITOR:", exc)
    status, error, result = "aborted", str(exc), None
except Exception as exc:
    status, error = "error", f"{type(exc).__name__}: {exc}"
    raise
finally:
    trace.event("run_end", status=status, error=error, crm=customers, outbox=OUTBOX)

print()
print("FINAL STATE")
print(result)
print()
print("OUTBOX (data that left the system)")
for message in OUTBOX:
    print(message)
print()
print("CRM")
print(customers)

print()
print(f"RUN LOG: {log_path}")
print(json.dumps(verify_run(log_path), indent=2))

# AgentDojo (vendored data)

`banking.json` is derived data from the AgentDojo benchmark:

- Source: https://github.com/ethz-spylab/agentdojo (`src/agentdojo/default_suites/v1/banking/`)
- Paper: Debenedetti et al., "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents", NeurIPS 2024 (arXiv:2406.13352)
- License: MIT

The tool names, parameters, the nine banking injection-task goals with their ground-truth
call arguments, the attacker IBAN constant, and the benign user-task prompts and arguments
are taken from the AgentDojo banking suite. The security labels attached to each tool
(effect, data confidentiality, sink clearance, output level) are not part of AgentDojo; they
are assigned here from tool names and parameters only, origin-blind, by the same rule the
project applies to its own catalog.

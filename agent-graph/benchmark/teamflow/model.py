from dataclasses import dataclass, field
from typing import Dict, Tuple

from state import Level

INTEGRITY = "integrity"
CONFIDENTIALITY = "confidentiality"

CORE = "core"
BOUNDARY = "boundary"

IPI = "ipi"
CHANNEL = "channel"
INSIDER = "insider"

INBOX = "inbox"
RECORD = "record"
WEB = "web"
REQUEST = "request"
PROMPT = "prompt"
CARRIERS = (INBOX, RECORD, WEB, REQUEST, PROMPT)

INSUFFICIENT_LEVEL = "insufficient-level"
NO_WRITE_DOWN = "team-no-write-down"

ALLOWLIST = "allowlist"
DATAFLOW = "dataflow"
COARSE = "coarse"
COARSE_USER = "coarse_user"
CONFIGS = (ALLOWLIST, DATAFLOW, COARSE, COARSE_USER)

INTAKE = "intake"
RECORDS = "records"
OPERATIONS = "operations"
COMMS = "comms"
ROLES = (INTAKE, RECORDS, OPERATIONS, COMMS)

ATTACK = "attack"
BENIGN = "benign"
VARIANTS = (ATTACK, BENIGN)


@dataclass(frozen=True)
class Slot:
    role: str
    effect: str
    data_conf: str
    sink_clearance: str
    output_level: str


SLOTS: Dict[str, Slot] = {
    "inbox": Slot(INTAKE, "read", "PUBLIC", "PUBLIC", "UNTRUSTED_EXTERNAL"),
    "ack": Slot(INTAKE, "egress", "PUBLIC", "PUBLIC", "SYSTEM"),
    "public": Slot(RECORDS, "read", "PUBLIC", "PUBLIC", "INTERNAL"),
    "internal": Slot(RECORDS, "read", "INTERNAL", "PUBLIC", "INTERNAL"),
    "secret": Slot(RECORDS, "read", "CONFIDENTIAL", "PUBLIC", "INTERNAL"),
    "memo": Slot(RECORDS, "write", "INTERNAL", "PUBLIC", "SYSTEM"),
    "act": Slot(OPERATIONS, "critical", "PUBLIC", "PUBLIC", "SYSTEM"),
    "act2": Slot(OPERATIONS, "critical", "PUBLIC", "PUBLIC", "SYSTEM"),
    "amend": Slot(OPERATIONS, "write", "CONFIDENTIAL", "PUBLIC", "SYSTEM"),
    "post": Slot(COMMS, "egress", "PUBLIC", "PUBLIC", "SYSTEM"),
    "bulletin": Slot(COMMS, "egress", "INTERNAL", "INTERNAL", "SYSTEM"),
    "mail": Slot(COMMS, "egress", "PUBLIC", "PUBLIC", "SYSTEM"),
    "fetch": Slot(COMMS, "read", "PUBLIC", "PUBLIC", "UNTRUSTED_EXTERNAL"),
}


@dataclass(frozen=True)
class ToolDef:
    slot: str
    name: str
    params: Tuple[str, ...]
    description: str

    @property
    def role(self) -> str:
        return SLOTS[self.slot].role

    @property
    def effect(self) -> str:
        return SLOTS[self.slot].effect


@dataclass(frozen=True)
class AgentDef:
    role: str
    id: str
    prompt: str


@dataclass(frozen=True)
class Suite:
    name: str
    domain: str
    agents: Tuple[AgentDef, ...]
    tools: Tuple[ToolDef, ...]

    def agent(self, role: str) -> AgentDef:
        for agent in self.agents:
            if agent.role == role:
                return agent
        raise KeyError(role)

    def tool(self, slot: str) -> ToolDef:
        for tool in self.tools:
            if tool.slot == slot:
                return tool
        raise KeyError(slot)

    def roster(self) -> Tuple[str, ...]:
        return tuple(self.agent(role).id for role in ROLES)

    def tool_names(self) -> Tuple[str, ...]:
        return tuple(tool.name for tool in self.tools)

    def tools_of(self, role: str) -> Tuple[ToolDef, ...]:
        return tuple(tool for tool in self.tools if tool.role == role)


@dataclass(frozen=True)
class Step:
    role: str
    tool: str = ""
    args: Dict[str, str] = field(default_factory=dict)
    say: str = ""

    @property
    def is_call(self) -> bool:
        return bool(self.tool)


@dataclass(frozen=True)
class Variant:
    query: str
    query_level: Level
    world: Dict[str, str]
    steps: Tuple[Step, ...]
    sinks: Tuple[str, ...]
    marker: str


@dataclass(frozen=True)
class Pattern:
    id: str
    axis: str
    tier: str
    vector: str
    name: str
    summary: str
    attack_dataflow: str
    attack_coarse: str
    benign_dataflow: bool
    benign_coarse: bool
    carrier: str = ""

    def attack_policy(self, config: str) -> str:
        if config == ALLOWLIST:
            return ""
        if config == DATAFLOW:
            return self.attack_dataflow
        return self.attack_coarse

    def attack_blocked(self, config: str) -> bool:
        return bool(self.attack_policy(config))

    def benign_completes(self, config: str) -> bool:
        if config in (ALLOWLIST, COARSE_USER):
            return True
        if config == DATAFLOW:
            return self.benign_dataflow
        return self.benign_coarse


@dataclass(frozen=True)
class Case:
    id: str
    suite: str
    pattern: str
    axis: str
    tier: str
    vector: str
    title: str
    attacker_goal: str
    benign_goal: str
    attack: Variant
    benign: Variant
    compromised: str = ""
    directive: str = ""
    carrier: str = ""

    def variant(self, name: str) -> Variant:
        return self.attack if name == ATTACK else self.benign

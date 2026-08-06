from pydantic.dataclasses import dataclass
from dataclasses import dataclass, field


@dataclass
class SecurityContext:

    values: dict = field(default_factory=dict)

    def register(self, name, tainted_value):
        self.values[name] = tainted_value

    def get(self, name):
        return self.values.get(name)

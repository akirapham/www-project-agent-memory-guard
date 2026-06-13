"""Use-time authority gate.

Extension to Agent Memory Guard. AMG screens what enters memory; this screens
what memory is allowed to *authorize* at the moment of action. The rule, after
PACT: low-trust memory may be acceptable as message *content*, but must not
fill an authority-bearing argument (recipient, url, path, command, credential,
selector, control, approval, payment_destination) without sufficient trust.

Trust is resolved from the lineage layer (``MemoryGuard.effective_trust``), so a
laundered memory — agent-authored but derived from an untrusted source — is
blocked here even though its declared provenance looks clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_memory_guard.events import Action
from agent_memory_guard.lineage import TrustLevel

# Argument roles. Everything except ``content`` is authority-bearing.
ALL_ROLES: frozenset[str] = frozenset(
    {
        "content",
        "target",
        "recipient",
        "url",
        "path",
        "command",
        "credential",
        "selector",
        "control",
        "approval",
        "payment_destination",
    }
)
AUTHORITY_ROLES: frozenset[str] = ALL_ROLES - {"content"}

# Minimum effective trust each role requires when a contract does not override.
DEFAULT_ROLE_MIN_TRUST: dict[str, TrustLevel] = {
    "content": TrustLevel.LOW,
    "target": TrustLevel.HIGH,
    "recipient": TrustLevel.HIGH,
    "url": TrustLevel.HIGH,
    "path": TrustLevel.HIGH,
    "command": TrustLevel.VERIFIED,
    "credential": TrustLevel.VERIFIED,
    "selector": TrustLevel.HIGH,
    "control": TrustLevel.HIGH,
    "approval": TrustLevel.VERIFIED,
    "payment_destination": TrustLevel.VERIFIED,
}


@dataclass(frozen=True)
class ArgRule:
    role: str
    min_trust: TrustLevel | None = None

    def required(self) -> TrustLevel:
        if self.role not in ALL_ROLES:
            raise ValueError(f"unknown argument role: {self.role}")
        return self.min_trust if self.min_trust is not None else DEFAULT_ROLE_MIN_TRUST[self.role]


@dataclass(frozen=True)
class ToolContract:
    tool: str
    arguments: dict[str, ArgRule]
    on_violation: Action = Action.BLOCK


@dataclass(frozen=True)
class Violation:
    argument: str
    role: str
    required: TrustLevel
    actual: TrustLevel | None
    reason: str


@dataclass
class AuthorizationResult:
    action: Action
    violations: list[Violation] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return not self.violations


def evaluate(contract: ToolContract, trusts: dict[str, TrustLevel | None]) -> AuthorizationResult:
    """Authorize provided argument trusts against a contract.

    ``trusts`` maps each provided argument name to its effective trust (or
    ``None`` when the argument has no resolvable memory provenance).
    """

    violations: list[Violation] = []
    for name, trust in trusts.items():
        rule = contract.arguments.get(name)
        role = rule.role if rule is not None else "content"
        if role not in AUTHORITY_ROLES:
            continue  # content roles accept low-trust memory
        required = rule.required() if rule is not None else DEFAULT_ROLE_MIN_TRUST[role]
        if trust is None:
            violations.append(
                Violation(name, role, required, None, "no resolvable memory provenance")
            )
        elif trust < required:
            violations.append(
                Violation(
                    name,
                    role,
                    required,
                    trust,
                    f"effective trust {trust.name} below required {required.name} for role "
                    f"'{role}'",
                )
            )
    action = contract.on_violation if violations else Action.ALLOW
    return AuthorizationResult(action, violations)

"""Per-entry derivation lineage and monotone trust propagation.

Extension to Agent Memory Guard. AMG's promotion graph (``classification.py``)
governs *class transitions of a single key*; it does not record the *parent
entries a new key was derived from*. This module adds that missing layer: a
parent-pointer DAG plus a monotone trust rule so a derived memory cannot exceed
the trust of what it was derived from — closing the "memory laundering" gap
where an agent summarizes an untrusted source into a clean new key.

It complements, and does not replace, classification: trust here feeds write-
and use-time decisions; class promotion remains governed by ``PromotionRules``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum

from agent_memory_guard.classification import UNTRUSTED_CLASSES, MemoryClass
from agent_memory_guard.events import SourceClass


class TrustLevel(IntEnum):
    """Ordered trust lattice for lineage propagation (low value = less trusted)."""

    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERIFIED = 4


# Trust a write carries from its declared provenance, before lineage capping.
_SOURCE_CLASS_TRUST: dict[SourceClass, TrustLevel] = {
    SourceClass.SYSTEM: TrustLevel.HIGH,
    SourceClass.USER_INPUT: TrustLevel.MEDIUM,
    SourceClass.AGENT_AUTHORED: TrustLevel.MEDIUM,
    SourceClass.EXTERNAL_TOOL: TrustLevel.LOW,
    SourceClass.UNKNOWN: TrustLevel.UNTRUSTED,
}


def base_trust(source_class: SourceClass, memory_class: MemoryClass | None = None) -> TrustLevel:
    """Provenance-implied trust of an entry before lineage propagation."""

    trust = _SOURCE_CLASS_TRUST.get(source_class, TrustLevel.UNTRUSTED)
    if memory_class in UNTRUSTED_CLASSES:
        trust = min(trust, TrustLevel.LOW)
    return TrustLevel(trust)


@dataclass(frozen=True)
class LineageEdge:
    child: str
    parent: str
    operation: str | None = None
    evidence_ref: str | None = None


@dataclass
class TrustAssessment:
    base: TrustLevel
    effective: TrustLevel
    lowest_parents: list[str]

    @property
    def laundered(self) -> bool:
        """True when lineage forced the effective trust below the claimed base."""

        return self.effective < self.base


class LineageGraph:
    """Parent-pointer DAG with per-entry effective trust."""

    def __init__(self) -> None:
        self._edges: dict[str, list[LineageEdge]] = {}
        self._trust: dict[str, TrustLevel] = {}

    # --- trust bookkeeping -------------------------------------------------
    def set_trust(self, key: str, trust: TrustLevel) -> None:
        self._trust[key] = trust

    def trust(self, key: str) -> TrustLevel:
        return self._trust.get(key, TrustLevel.UNTRUSTED)

    # --- edges -------------------------------------------------------------
    def record(
        self,
        child: str,
        parents: Sequence[str],
        *,
        operation: str | None = None,
        evidence_ref: str | None = None,
    ) -> None:
        edges = self._edges.setdefault(child, [])
        for parent in parents:
            if parent == child or self._reaches(parent, child):
                raise ValueError(f"lineage cycle: edge {child} -> {parent} would create a cycle")
            edges.append(LineageEdge(child, parent, operation, evidence_ref))

    def parents(self, key: str) -> list[str]:
        return [e.parent for e in self._edges.get(key, [])]

    def ancestry(self, key: str) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        stack = list(self.parents(key))
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            out.append(node)
            stack.extend(self.parents(node))
        return out

    def _reaches(self, start: str, target: str) -> bool:
        stack = list(self.parents(start))
        seen: set[str] = set()
        while stack:
            node = stack.pop()
            if node == target:
                return True
            if node in seen:
                continue
            seen.add(node)
            stack.extend(self.parents(node))
        return False

    # --- the rule ----------------------------------------------------------
    def assess(self, child: str, *, base: TrustLevel, verified: bool = False) -> TrustAssessment:
        """Effective trust of ``child``: capped at its lowest-trust parent.

        A verification edge (``verified=True``) discharges the cap. Parents are
        written before children, so their stored trust already reflects their
        own lineage — no recursion needed.
        """

        parents = self.parents(child)
        if verified or not parents:
            return TrustAssessment(base, base, [])
        parent_trusts = {p: self.trust(p) for p in parents}
        floor = min(parent_trusts.values())
        effective = TrustLevel(min(base, floor))
        lowest = sorted(p for p, t in parent_trusts.items() if t == floor and t < base)
        return TrustAssessment(base, effective, lowest)

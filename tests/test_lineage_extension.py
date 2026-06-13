"""Tests for the lineage extension (derivation provenance + monotone trust).

Covers the LineageGraph rule in isolation and its integration into
MemoryGuard.write via the backward-compatible ``parents=`` argument.
"""

from __future__ import annotations

import pytest

from agent_memory_guard import MemoryGuard
from agent_memory_guard.events import Action, SourceClass
from agent_memory_guard.lineage import LineageGraph, TrustLevel, base_trust


# --- unit: the rule --------------------------------------------------------
def test_base_trust_by_source_class():
    assert base_trust(SourceClass.EXTERNAL_TOOL) == TrustLevel.LOW
    assert base_trust(SourceClass.AGENT_AUTHORED) == TrustLevel.MEDIUM
    assert base_trust(SourceClass.SYSTEM) == TrustLevel.HIGH


def test_derived_trust_capped_at_lowest_parent():
    g = LineageGraph()
    g.set_trust("tool", TrustLevel.LOW)
    g.record("summary", ["tool"])
    a = g.assess("summary", base=TrustLevel.MEDIUM)
    assert a.laundered
    assert a.effective == TrustLevel.LOW
    assert a.lowest_parents == ["tool"]


def test_verification_edge_discharges_cap():
    g = LineageGraph()
    g.set_trust("tool", TrustLevel.LOW)
    g.record("summary", ["tool"])
    a = g.assess("summary", base=TrustLevel.MEDIUM, verified=True)
    assert not a.laundered
    assert a.effective == TrustLevel.MEDIUM


def test_no_parents_is_not_laundering():
    g = LineageGraph()
    a = g.assess("x", base=TrustLevel.MEDIUM)
    assert not a.laundered and a.effective == TrustLevel.MEDIUM


def test_cycle_rejected():
    g = LineageGraph()
    g.record("b", ["a"])
    with pytest.raises(ValueError):
        g.record("a", ["b"])


def test_ancestry_is_transitive():
    g = LineageGraph()
    g.record("b", ["a"])
    g.record("c", ["b"])
    assert set(g.ancestry("c")) == {"a", "b"}


# --- integration: through the real guard -----------------------------------
def test_guard_quarantines_laundered_summary():
    guard = MemoryGuard()
    assert guard.write("vendor.note", "vendor portal details",
                       source_class=SourceClass.EXTERNAL_TOOL) == Action.ALLOW
    assert guard.effective_trust("vendor.note") == TrustLevel.LOW

    # Agent summarizes the untrusted tool note into an agent-authored memory.
    action = guard.write(
        "vendor.summary", "summary of vendor portal details",
        source_class=SourceClass.AGENT_AUTHORED, parents=["vendor.note"],
    )
    assert action == Action.QUARANTINE
    assert guard.effective_trust("vendor.summary") == TrustLevel.LOW
    assert guard.lineage_of("vendor.summary") == ["vendor.note"]
    assert any(e.detector == "lineage" for e in guard.events)


def test_guard_allows_verified_derivation():
    guard = MemoryGuard()
    guard.write("vendor.note", "vendor portal details", source_class=SourceClass.EXTERNAL_TOOL)
    action = guard.write(
        "vendor.summary", "summary", source_class=SourceClass.AGENT_AUTHORED,
        parents=["vendor.note"], verified=True,
    )
    assert action == Action.ALLOW
    assert guard.effective_trust("vendor.summary") == TrustLevel.MEDIUM


def test_plain_write_unaffected():
    guard = MemoryGuard()
    assert guard.write("notes.x", "hello", source_class=SourceClass.AGENT_AUTHORED) == Action.ALLOW
    assert guard.effective_trust("notes.x") == TrustLevel.MEDIUM
    assert guard.lineage_of("notes.x") == []

"""Tests for the use-time authority gate, including its use of lineage trust."""

from __future__ import annotations

from agent_memory_guard import MemoryGuard
from agent_memory_guard.authority import ArgRule, ToolContract, evaluate
from agent_memory_guard.events import Action, SourceClass
from agent_memory_guard.lineage import TrustLevel

EMAIL = ToolContract(
    tool="email.send",
    arguments={"to": ArgRule("recipient"), "body": ArgRule("content")},
    on_violation=Action.BLOCK,
)


# --- unit: the contract logic ----------------------------------------------
def test_content_accepts_low_trust():
    r = evaluate(EMAIL, {"body": TrustLevel.LOW})
    assert r.allowed and r.action == Action.ALLOW


def test_recipient_blocks_low_trust():
    r = evaluate(EMAIL, {"to": TrustLevel.LOW})
    assert not r.allowed and r.action == Action.BLOCK
    assert r.violations[0].role == "recipient"


def test_recipient_allows_high_trust():
    r = evaluate(EMAIL, {"to": TrustLevel.HIGH})
    assert r.allowed


def test_missing_provenance_is_a_violation():
    r = evaluate(EMAIL, {"to": None})
    assert not r.allowed and "provenance" in r.violations[0].reason


def test_custom_min_trust_override():
    contract = ToolContract("t", {"to": ArgRule("recipient", min_trust=TrustLevel.MEDIUM)})
    assert evaluate(contract, {"to": TrustLevel.MEDIUM}).allowed


# --- integration: laundering -> authority through the real guard -----------
def test_laundered_memory_blocked_as_recipient():
    guard = MemoryGuard()
    guard.write("vendor.note", "vendor portal details", source_class=SourceClass.EXTERNAL_TOOL)
    guard.write(
        "vendor.summary", "summary", source_class=SourceClass.AGENT_AUTHORED,
        parents=["vendor.note"],
    )  # quarantined by lineage; effective trust LOW

    # Same memory: fine as body (content), refused as recipient (authority).
    assert guard.authorize(EMAIL, {"body": {"memory_key": "vendor.summary"}}) == Action.ALLOW
    action = guard.authorize(EMAIL, {"to": {"memory_key": "vendor.summary"}})
    assert action == Action.BLOCK
    assert any(e.detector == "authority" for e in guard.events)


def test_system_sourced_memory_allowed_as_recipient():
    guard = MemoryGuard()
    guard.write("cfg.invoice_to", "billing@acme.example", source_class=SourceClass.SYSTEM)
    assert guard.effective_trust("cfg.invoice_to") == TrustLevel.HIGH
    assert guard.authorize(EMAIL, {"to": {"memory_key": "cfg.invoice_to"}}) == Action.ALLOW


def test_inline_trust_argument():
    guard = MemoryGuard()
    assert guard.authorize(EMAIL, {"to": {"trust": TrustLevel.VERIFIED}}) == Action.ALLOW
    assert guard.authorize(EMAIL, {"to": {"value": "x@evil.example"}}) == Action.BLOCK

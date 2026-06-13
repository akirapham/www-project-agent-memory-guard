"""Tests for receipt validation of privileged (system) provenance."""

from __future__ import annotations

from agent_memory_guard import MemoryGuard
from agent_memory_guard.authority import ArgRule, ToolContract
from agent_memory_guard.events import Action, SourceClass
from agent_memory_guard.lineage import TrustLevel

RECIPIENT = ToolContract("email.send", {"to": ArgRule("recipient")})


def test_system_without_receipt_is_downgraded_and_flagged():
    guard = MemoryGuard()
    guard.write("cfg.endpoint", "https://internal.example", source_class=SourceClass.SYSTEM)
    # Claimed system, but no verified receipt -> not honored as HIGH.
    assert guard.effective_trust("cfg.endpoint") == TrustLevel.MEDIUM
    assert any(e.detector == "provenance" for e in guard.events)
    # Consequence: it can no longer authorize a recipient.
    assert guard.authorize(RECIPIENT, {"to": {"memory_key": "cfg.endpoint"}}) == Action.BLOCK


def test_system_with_valid_receipt_keeps_high_trust():
    guard = MemoryGuard()
    guard.write(
        "cfg.endpoint", "https://internal.example",
        source_class=SourceClass.SYSTEM, receipt_uri="receipt:ed25519:abc123",
    )
    assert guard.effective_trust("cfg.endpoint") == TrustLevel.HIGH
    assert not any(e.detector == "provenance" for e in guard.events)
    assert guard.authorize(RECIPIENT, {"to": {"memory_key": "cfg.endpoint"}}) == Action.ALLOW


def test_custom_receipt_verifier():
    guard = MemoryGuard(receipt_verifier=lambda uri: uri == "trusted-token")
    guard.write("cfg.a", "x", source_class=SourceClass.SYSTEM, receipt_uri="trusted-token")
    assert guard.effective_trust("cfg.a") == TrustLevel.HIGH
    guard.write("cfg.b", "y", source_class=SourceClass.SYSTEM, receipt_uri="bogus")
    assert guard.effective_trust("cfg.b") == TrustLevel.MEDIUM


def test_non_system_writes_need_no_receipt():
    guard = MemoryGuard()
    guard.write("notes.x", "hello", source_class=SourceClass.AGENT_AUTHORED)
    assert guard.effective_trust("notes.x") == TrustLevel.MEDIUM
    assert not any(e.detector == "provenance" for e in guard.events)

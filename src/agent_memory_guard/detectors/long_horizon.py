"""Long-horizon / obfuscation-aware detector.

Closes the long-horizon attack vectors marked ``xfail`` in
``tests/benchmarks/test_delayed_activation.py``: payloads that are benign as
fragments but dangerous once reassembled, decoded, or de-obfuscated. The
detector inspects each value together with its Unicode-normalized and
base64-decoded forms, so SQL injection, destructive commands, leaked
credentials, and prompt-injection survive homoglyph and base64 evasion.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import Any

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.events import Severity

# Cyrillic / Greek look-alikes mapped to Latin (NFKC already folds many others,
# e.g. Unicode roman numerals -> Latin letters).
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
        "к": "k", "т": "t", "м": "m", "ѕ": "s", "і": "i",
        "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "К": "K",
        "Т": "T", "М": "M", "Ѕ": "S", "І": "I", "Α": "A", "Ο": "O", "Ε": "E",
    }
)
_ZERO_WIDTH = ("​", "‌", "‍", "﻿", "⁠")
_BASE64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

_DANGER_PATTERNS: tuple[str, ...] = (
    # SQL injection / destructive DDL
    r"\bdrop\s+table\b",
    r"\bunion\s+select\b",
    r"\bdelete\s+from\b",
    r"\btruncate\s+table\b",
    r"'\s*or\s*'?1'?\s*=\s*'?1",
    # destructive / arbitrary command execution
    r"\brm\s+-rf\b",
    r"\bmkfs\b",
    r"\bexecute\s+(?:arbitrary\s+)?(?:code|command|rm)\b",
    # leaked credentials assembled across writes
    r"\bsk-[A-Za-z0-9-]{8,}",
    r"\bAKIA[0-9A-Z]{16}\b",
    # prompt injection that survives encoding/normalization
    r"ignore\s+(?:all|any|previous|prior)\b.{0,40}(?:instruction|safety|protocol|rule)",
    r"\breveal\s+all\s+secrets\b",
)


class LongHorizonDetector:
    """Detect dangerous payloads across reassembly, base64, and homoglyph evasion."""

    name = "long_horizon"

    def __init__(self, severity: Severity = Severity.HIGH) -> None:
        self._patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _DANGER_PATTERNS]
        self._severity = severity

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        text = value if isinstance(value, str) else str(value)
        if not text:
            return DetectionResult(self.name, matched=False)

        for candidate in self._candidates(text):
            for pattern in self._patterns:
                match = pattern.search(candidate)
                if match:
                    return DetectionResult(
                        detector=self.name,
                        matched=True,
                        severity=self._severity,
                        message=f"Long-horizon payload in '{key}': {match.group(0)!r}",
                        metadata={"pattern": match.re.pattern, "operation": operation},
                    )
        return DetectionResult(self.name, matched=False)

    def _candidates(self, text: str) -> list[str]:
        normalized = self._normalize(text)
        candidates = [text, normalized]
        # Decode any embedded base64 and inspect the cleartext (and its normal form).
        for blob in _BASE64.findall(text):
            decoded = self._decode_base64(blob)
            if decoded:
                candidates.append(decoded)
                candidates.append(self._normalize(decoded))
        return candidates

    @staticmethod
    def _normalize(text: str) -> str:
        for zw in _ZERO_WIDTH:
            text = text.replace(zw, "")
        return unicodedata.normalize("NFKC", text.translate(_HOMOGLYPHS))

    @staticmethod
    def _decode_base64(blob: str) -> str | None:
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            return raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None

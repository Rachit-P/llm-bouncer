"""Shared text normalisation so labelling and matching see the same characters."""

from __future__ import annotations

import re
import unicodedata


def clean(text: str) -> str:
    """NFKC-fold and drop invisible format characters (zero-width, bidi, tags, soft hyphen).

    An attacker can hide such characters inside a command on a page; the model usually drops them
    when it copies the command, so both sides must be compared without them.
    """
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def norm(text: str) -> str:
    """Lower-case, invisible-free, single-spaced text for substring matching."""
    return re.sub(r"\s+", " ", clean(text)).strip().lower()


def one_line(text: str, limit: int = 120) -> str:
    """Untrusted text made safe to quote in a note or reason: one line, printable, short."""
    text = re.sub(r"\s+", " ", clean(str(text))).strip()
    text = "".join(ch for ch in text if ch.isprintable())
    return text if len(text) <= limit else text[: limit - 1] + "…"

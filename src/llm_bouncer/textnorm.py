"""Shared text normalisation so labelling and matching see the same characters."""

from __future__ import annotations

import re
import unicodedata


# Unicode "Cf" (format) characters: soft hyphen, zero-width, bidi controls, tag characters, BOM ...
_FORMAT_CHARS = re.compile(
    "[\u00ad\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891\u08e2\u180e\u200b-\u200f\u202a-\u202e"
    "\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb\U000110bd\U000110cd\U00013430-\U0001343f"
    "\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0001\U000e0020-\U000e007f]"
)


def clean(text: str) -> str:
    """NFKC-fold and drop invisible format characters (zero-width, bidi, tags, soft hyphen).

    An attacker can hide such characters inside a command on a page; the model usually drops them
    when it copies the command, so both sides must be compared without them.
    """
    if text.isascii():  # fast path: nothing to fold or strip (most tool output)
        return text
    text = unicodedata.normalize("NFKC", text)
    return _FORMAT_CHARS.sub("", text)


def norm(text: str) -> str:
    """Lower-case, invisible-free, single-spaced text for substring matching."""
    return re.sub(r"\s+", " ", clean(text)).strip().lower()


def one_line(text: str, limit: int = 120) -> str:
    """Untrusted text made safe to quote in a note or reason: one line, printable, short."""
    text = re.sub(r"\s+", " ", clean(str(text))).strip()
    text = "".join(ch for ch in text if ch.isprintable())
    return text if len(text) <= limit else text[: limit - 1] + "…"

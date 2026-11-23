"""Scan text for hidden content (deterministic) and instruction-like sentences (hint only).

Hidden-content findings are exact. Hints are heuristic and are *only* hints:
they are recorded and shown, never used to decide anything in v0.
"""

from __future__ import annotations

import re
import unicodedata
from typing import List, Tuple

# Zero-width / bidi-control characters often used to hide text.
_ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "­"}
_BIDI = (
    {chr(c) for c in range(0x202A, 0x202F)}
    | {chr(c) for c in range(0x2066, 0x206A)}
    | {"\u200e", "\u200f", "\u061c"}
)
_HIDDEN_STYLE = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?:\.0+)?(?![.\d])"
    r"|(?<![-\w])color\s*:\s*(?:#fff(?:fff)?|white)\b|aria-hidden\s*=\s*[\"']true[\"'])",
    re.I,
)


def _has_html_comment(text: str) -> bool:
    # str.find is linear; the old regex <!--(.*?)--> was quadratic on many unclosed "<!--",
    # which let a page stall the hook past its timeout so the read was never recorded.
    start = text.find("<!--")
    return start != -1 and text.find("-->", start + 4) != -1

# Phrases aimed at the AI itself.
_AI_ADDRESSED = re.compile(
    r"(ignore (all |any )?(the )?(previous|prior|above) (instructions|prompts?)"
    r"|disregard (all |any )?(the )?(previous|prior|above)"
    r"|\b(ai|llm|assistant|claude|chatgpt|gpt|agent|model)\b\s*[,:\-]"
    r"|you are now\b|new instructions?\b|system prompt"
    r"|do not (tell|inform|mention|reveal)( this)? (to )?(the )?user"
    r"|without (telling|informing|asking) the user)",
    re.I,
)
_ACTION_VERB = re.compile(
    r"\b(run|execute|curl|wget|download|send|forward|email|upload|post|delete|remove|"
    r"install|exfiltrate|reveal|print|read|cat|open|visit)\b",
    re.I,
)
_SENSITIVE = re.compile(
    r"(password|passwd|secret|token|api[_ -]?key|ssh|\.env|credentials?|private key|"
    r"https?://|\|\s*(ba)?sh\b|sudo\b)",
    re.I,
)
# A sentence ends at . ! ? followed by whitespace/end, or at a newline (so "evil.sh" stays whole).
_SENTENCE = re.compile(r"(?:[^\n]*?(?:[.!?](?=\s|$)|(?=\n)|$))")


_ZERO_WIDTH_RE = re.compile("[" + "".join(sorted(_ZERO_WIDTH)) + "]")
_BIDI_RE = re.compile("[" + "".join(sorted(_BIDI)) + "]")
_TAGS_RE = re.compile("[\U000e0000-\U000e007f]")
_PRIVATE_USE_RE = re.compile("[\ue000-\uf8ff\U000f0000-\U000ffffd\U00100000-\U0010fffd]")


def find_hidden(text: str) -> List[str]:
    # One C-speed regex search per check instead of Python loops over every character
    # (a 1 MB command output took ~0.3 s before, ~5 ms now).
    flags: List[str] = []
    if not text.isascii():
        if _ZERO_WIDTH_RE.search(text):
            flags.append("zero_width_chars")
        if _BIDI_RE.search(text):
            flags.append("bidi_controls")
        # Unicode "tag" characters (U+E0000-E007F) can smuggle invisible ASCII.
        if _TAGS_RE.search(text):
            flags.append("unicode_tags")
        if _PRIVATE_USE_RE.search(text):
            flags.append("private_use_chars")
    if _has_html_comment(text):
        flags.append("html_comment")
    if _HIDDEN_STYLE.search(text):
        flags.append("hidden_style")
    return flags


HINT_SCAN_CHARS = 200_000


def find_hints(text: str, max_hints: int = 5) -> List[dict]:
    """Return up to max_hints instruction-like sentences. Heuristic; may be wrong either way.

    Only the first HINT_SCAN_CHARS are scanned: hints are advisory, and nothing is decided on them.
    """
    hints: List[dict] = []
    if not (_AI_ADDRESSED.search(text, 0, HINT_SCAN_CHARS) or _ACTION_VERB.search(text, 0, HINT_SCAN_CHARS)):
        return hints  # cheap pre-check: no sentence can match
    for m in _SENTENCE.finditer(text, 0, HINT_SCAN_CHARS):
        sent = m.group(0).strip()
        if len(sent) < 8:
            continue
        reason = None
        if _AI_ADDRESSED.search(sent):
            reason = "addresses_the_ai"
        elif _ACTION_VERB.search(sent) and _SENSITIVE.search(sent):
            reason = "action_plus_sensitive_target"
        if reason:
            hints.append({"start": m.start(), "end": m.end(), "text": sent[:200], "reason": reason})
            if len(hints) >= max_hints:
                break
    return hints


def scan_text(text: str, hints: bool = True) -> Tuple[List[str], List[dict]]:
    """Return (flags, hints) for a piece of text. hints=False skips the heuristic pass."""
    return find_hidden(text), (find_hints(text) if hints else [])

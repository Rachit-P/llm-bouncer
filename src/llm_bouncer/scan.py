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


def find_hidden(text: str) -> List[str]:
    flags: List[str] = []
    if any(ch in _ZERO_WIDTH for ch in text):
        flags.append("zero_width_chars")
    if any(ch in _BIDI for ch in text):
        flags.append("bidi_controls")
    # Unicode "tag" characters (U+E0000-E007F) can smuggle invisible ASCII.
    if any(0xE0000 <= ord(ch) <= 0xE007F for ch in text):
        flags.append("unicode_tags")
    if any(unicodedata.category(ch) == "Co" for ch in text):
        flags.append("private_use_chars")
    if _has_html_comment(text):
        flags.append("html_comment")
    if _HIDDEN_STYLE.search(text):
        flags.append("hidden_style")
    return flags


def find_hints(text: str, max_hints: int = 5) -> List[dict]:
    """Return up to max_hints instruction-like sentences. Heuristic; may be wrong either way."""
    hints: List[dict] = []
    for m in _SENTENCE.finditer(text):
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


def scan_text(text: str) -> Tuple[List[str], List[dict]]:
    """Return (flags, hints) for a piece of text."""
    return find_hidden(text), find_hints(text)

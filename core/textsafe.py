"""Sanitising and width helpers for untrusted text."""

from __future__ import annotations

import unicodedata
from urllib.parse import urlsplit, urlunsplit


def sanitize_text(value: object, max_len: int = 2048) -> str:
    """Return printable text only: control, format and unassigned characters become '?'."""
    text = str(value)
    truncated = len(text) > max_len
    out = []
    for ch in text[:max_len]:
        if ch == " ":
            out.append(ch)
        elif ch == "\t":
            out.append(" ")
        else:
            cat = unicodedata.category(ch)
            if cat[0] == "C":
                out.append("?")
            elif cat[0] == "Z":
                out.append(" ")
            else:
                out.append(ch)
    result = "".join(out)
    return result + "..." if truncated else result


def char_width(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def display_width(text: str) -> int:
    return sum(char_width(c) for c in text)


def clip(text: str, width: int) -> str:
    """Clip text to at most `width` terminal columns."""
    used = 0
    out = []
    for ch in text:
        w = char_width(ch)
        if used + w > width:
            break
        out.append(ch)
        used += w
    return "".join(out)


def redact_url(url: str) -> str:
    """Drop credentials, query string and fragment so tokens never reach reports or logs."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if ":" in host:
            host = "[" + host + "]"
        netloc = host + (":%d" % parts.port if parts.port else "")
        return sanitize_text(urlunsplit((parts.scheme, netloc, parts.path, "", "")))
    except ValueError:
        return sanitize_text(url.split("?")[0].split("#")[0].split("@")[-1])

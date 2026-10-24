"""Extract explicitly reported PHP runtime versions from HTTP response headers.

Only the X-Powered-By and Server headers are consulted, and only a literal
``PHP/<major>.<minor>.<patch>`` token counts. Nothing else (cookies, CMS names,
file extensions, web server names) is treated as version evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Mapping, Tuple, Union

from .textsafe import sanitize_text

EVIDENCE_HEADERS = ("x-powered-by", "server")
MAX_VALUE = 1024

_EXACT_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_.-])PHP/(\d+\.\d+\.\d+[A-Za-z0-9.+~_-]*)", re.IGNORECASE
)
_ANY_TOKEN = re.compile(r"(?<![A-Za-z0-9_.-])PHP/(\d+(?:\.\d+)?)(?![\d.])", re.IGNORECASE)

FOUND = "found"
NONE = "none"
CONFLICT = "conflict"


@dataclass(frozen=True)
class Evidence:
    header: str
    value: str
    version: str


@dataclass
class FingerprintResult:
    status: str = NONE
    version: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    conflicting: List[str] = field(default_factory=list)
    ignored: List[str] = field(default_factory=list)

    @property
    def sources(self) -> str:
        names = []
        for ev in self.evidence:
            if ev.header not in names:
                names.append(ev.header)
        return ", ".join(names)


Headers = Union[Mapping[str, str], Iterable[Tuple[str, str]]]


def _pairs(headers: Headers) -> List[Tuple[str, str]]:
    if headers is None:
        return []
    if isinstance(headers, Mapping):
        return [(str(k), str(v)) for k, v in headers.items()]
    out = []
    for item in headers:
        try:
            name, value = item
        except (TypeError, ValueError):
            continue
        out.append((str(name), str(value)))
    return out


def extract_php_version(headers: Headers) -> FingerprintResult:
    result = FingerprintResult()
    seen = {}
    for name, value in _pairs(headers):
        lname = name.strip().lower()
        if lname not in EVIDENCE_HEADERS:
            continue
        value = value[:MAX_VALUE]
        exact = _EXACT_TOKEN.findall(value)
        for version in exact:
            version = version.rstrip(".")
            result.evidence.append(
                Evidence(sanitize_text(name.strip(), 64), sanitize_text(value.strip(), 256),
                         sanitize_text(version, 80))
            )
            seen.setdefault(version.lower(), version)
        if not exact:
            for partial in _ANY_TOKEN.findall(value):
                result.ignored.append("%s: PHP/%s (no exact patch version)" % (
                    sanitize_text(name.strip(), 64), sanitize_text(partial, 20)))
    if len(seen) == 1:
        result.status = FOUND
        result.version = sanitize_text(next(iter(seen.values())), 80)
    elif len(seen) > 1:
        result.status = CONFLICT
        result.conflicting = [sanitize_text(v, 80) for v in seen.values()]
    return result

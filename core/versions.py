"""PHP version parsing. Pure functions, no advisory knowledge."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Tuple

FINAL = "final"
VENDOR_BUILD = "vendor_build"
PRERELEASE = "prerelease"
UNRECOGNIZED = "unrecognized"

_VERSION_RE = re.compile(
    r"^(?:php[\s/_-]*)?v?(\d{1,3})\.(\d{1,3})\.(\d{1,4})([A-Za-z0-9.+~_-]{0,64})$",
    re.IGNORECASE | re.ASCII,
)
_PRERELEASE_RE = re.compile(
    r"^[-+~._]?(alpha|beta|rc|dev|snapshot|nightly|pre|a|b)(\d|$|[-+~._])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PhpVersion:
    raw: str
    major: int
    minor: int
    patch: int
    suffix: str = ""

    @property
    def release(self) -> Tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    @property
    def branch_key(self) -> Tuple[int, int]:
        return (self.major, self.minor)

    @property
    def branch(self) -> str:
        return "%d.%d" % (self.major, self.minor)

    @property
    def numeric(self) -> str:
        return "%d.%d.%d" % self.release

    @property
    def kind(self) -> str:
        """final | vendor_build | prerelease | unrecognized."""
        if not self.suffix:
            return FINAL
        if _PRERELEASE_RE.match(self.suffix):
            return PRERELEASE
        if self.suffix[0] in "-+~" and len(self.suffix) > 1:
            return VENDOR_BUILD
        return UNRECOGNIZED


def parse_version(text: object) -> Optional[PhpVersion]:
    """Parse MAJOR.MINOR.PATCH with an optional suffix; return None if not a PHP version."""
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    match = _VERSION_RE.match(stripped)
    if not match:
        return None
    major, minor, patch, suffix = match.groups()
    return PhpVersion(stripped, int(major), int(minor), int(patch), suffix)


def parse_branch(text: str) -> Optional[Tuple[int, int]]:
    match = re.match(r"^(\d{1,3})\.(\d{1,3})$", text.strip(), re.ASCII)
    return (int(match.group(1)), int(match.group(2))) if match else None


def compare_release(a: PhpVersion, b: PhpVersion) -> int:
    """Numeric comparison of MAJOR.MINOR.PATCH only: -1, 0 or 1."""
    return (a.release > b.release) - (a.release < b.release)

"""Advisory database loading and the version-based assessment engine.

Both URL mode and manual mode end up in ``_assess_version`` so they share one
scoring policy. The numeric score is a triage heuristic, not CVSS.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import fingerprint as fp
from .textsafe import sanitize_text
from .versions import (FINAL, PRERELEASE, UNRECOGNIZED, VENDOR_BUILD, PhpVersion,
                       compare_release, parse_branch, parse_version)

SUPPORTED_SCHEMA = 1

POTENTIAL_EXPOSURE = "POTENTIAL EXPOSURE"
THRESHOLD_MET = "ORIGINAL FIX THRESHOLD MET"
LEGACY_REVIEW = "LEGACY PATCH REVIEW"
INCONCLUSIVE = "INCONCLUSIVE"
COVERAGE_UNKNOWN = "ADVISORY COVERAGE UNKNOWN"

QUALITY_HEADER = "EXPLICIT HEADER DISCLOSURE"
QUALITY_MANUAL = "USER-SUPPLIED VERSION"
QUALITY_NONE = "NONE"

NO_VERSION_FINDING = ("No explicit PHP runtime version was identified in the inspected HTTP "
                      "responses. PHP2Shell exposure cannot be determined from the available evidence.")


class AdvisoryError(Exception):
    """The advisory database is missing, malformed or unsupported."""


@dataclass(frozen=True)
class AdvisoryDB:
    data: Dict[str, Any]
    fixed: Dict[str, PhpVersion]
    legacy_max: Tuple[int, int]

    @property
    def database_version(self) -> str:
        return self.data["database_version"]

    @property
    def last_reviewed(self) -> str:
        return self.data["last_reviewed"]

    @property
    def primary_cves(self) -> List[str]:
        return [e["cve"] for e in self.data["primary_scope"]]

    @property
    def related(self) -> List[Dict[str, Any]]:
        return self.data["related_advisories"]

    @property
    def scores(self) -> Dict[str, int]:
        return self.data["scoring"]

    @property
    def limitations(self) -> List[str]:
        return self.data["limitations"]


@dataclass
class Assessment:
    mode: str                       # "url" | "manual"
    classification: str
    risk_score: Optional[int]
    version: Optional[str] = None
    branch: Optional[str] = None
    first_fixed: Optional[str] = None
    evidence_source: Optional[str] = None
    evidence_quality: str = QUALITY_NONE
    evidence_lines: List[str] = field(default_factory=list)
    target_url: Optional[str] = None
    final_url: Optional[str] = None
    http_status: Optional[int] = None
    omen: str = ""
    finding: str = ""
    caveats: List[str] = field(default_factory=list)
    recommendation: str = ""
    notes: List[str] = field(default_factory=list)
    primary_cves: List[str] = field(default_factory=list)
    related: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    db_version: str = ""
    db_reviewed: str = ""
    assessed_at: str = ""


# ---------------------------------------------------------------- database

def _need(cond: bool, message: str) -> None:
    if not cond:
        raise AdvisoryError(message)


def validate_advisories(data: Any) -> AdvisoryDB:
    _need(isinstance(data, dict), "advisory database root must be a JSON object")
    _need(data.get("schema_version") == SUPPORTED_SCHEMA,
          "unsupported advisory schema_version %r (this build supports %d)"
          % (data.get("schema_version"), SUPPORTED_SCHEMA))
    for key in ("database_version", "last_reviewed", "initial_disclosure"):
        _need(isinstance(data.get(key), str) and data[key], "missing or invalid '%s'" % key)
    for key in ("primary_scope", "related_advisories", "mitigations", "limitations", "sources"):
        _need(isinstance(data.get(key), list), "'%s' must be a list" % key)
    _need(data["primary_scope"], "'primary_scope' must not be empty")
    for entry in data["primary_scope"]:
        _need(isinstance(entry, dict) and re.match(r"^CVE-\d{4}-\d{4,}$", str(entry.get("cve", ""))),
              "primary_scope entries need a valid CVE id")
    for entry in data["related_advisories"]:
        _need(isinstance(entry, dict) and re.match(r"^CVE-\d{4}-\d{4,}$", str(entry.get("cve", ""))),
              "related_advisories entries need a valid CVE id")
        _need(entry.get("included_in_primary_score") is False,
              "related advisories must not be part of the primary score")
        _need(isinstance(entry.get("notice_text"), str), "related advisory needs notice_text")

    fixed_raw = data.get("fixed_upstream_versions")
    _need(isinstance(fixed_raw, dict) and fixed_raw, "'fixed_upstream_versions' must be a non-empty object")
    fixed: Dict[str, PhpVersion] = {}
    for branch, version in fixed_raw.items():
        _need(parse_branch(branch) is not None, "invalid branch key %r" % (branch,))
        parsed = parse_version(version)
        _need(parsed is not None and parsed.kind == FINAL and parsed.branch == branch,
              "fixed version %r does not belong to final release of branch %s" % (version, branch))
        fixed[branch] = parsed

    legacy = data.get("legacy_policy")
    _need(isinstance(legacy, dict), "'legacy_policy' must be an object")
    legacy_max = parse_branch(str(legacy.get("max_branch", "")))
    _need(legacy_max is not None, "legacy_policy.max_branch must look like '8.1'")
    _need(all(parse_branch(b) > legacy_max for b in fixed), "legacy_policy.max_branch overlaps a fixed branch")

    scoring = data.get("scoring")
    _need(isinstance(scoring, dict), "'scoring' must be an object")
    for key in ("potential_exposure", "legacy_patch_review", "threshold_met"):
        value = scoring.get(key)
        _need(isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100,
              "scoring.%s must be an integer 0-100" % key)
    return AdvisoryDB(data=data, fixed=fixed, legacy_max=legacy_max)


def load_advisories(path: Path) -> AdvisoryDB:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise AdvisoryError("cannot read advisory database %s: %s" % (path, exc.strerror or exc))
    except UnicodeDecodeError:
        raise AdvisoryError("advisory database %s is not valid UTF-8" % path)
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise AdvisoryError("advisory database %s is not valid JSON: %s" % (path, exc))
    return validate_advisories(data)


# --------------------------------------------------------------- assessment

def _blank(db: AdvisoryDB, mode: str, classification: str, **kw: Any) -> Assessment:
    return Assessment(
        mode=mode, classification=classification, risk_score=kw.pop("risk_score", None),
        primary_cves=db.primary_cves, related=list(db.related), limitations=list(db.limitations),
        db_version=db.database_version, db_reviewed=db.last_reviewed,
        assessed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), **kw)


def _assess_version(db: AdvisoryDB, raw_version: str, *, mode: str, source: str, quality: str,
                    evidence_lines: List[str], **ctx: Any) -> Assessment:
    shown = sanitize_text(raw_version, 80)
    parsed = parse_version(raw_version)
    base = dict(evidence_source=source, evidence_quality=quality, evidence_lines=evidence_lines, **ctx)

    if parsed is None:
        return _blank(db, mode, INCONCLUSIVE, omen="Input is not a recognisable PHP version.",
                      finding="'%s' could not be parsed as a PHP version (expected MAJOR.MINOR.PATCH, "
                              "for example 8.3.35). Nothing can be concluded." % shown,
                      recommendation="Check the PHP version directly on the server (for example with "
                                     "'php -v' or the hosting panel) and enter it as MAJOR.MINOR.PATCH.",
                      **base)

    base["version"] = parsed.raw
    base["branch"] = parsed.branch
    notes: List[str] = []
    caveats: List[str] = []
    if quality == QUALITY_HEADER:
        caveats.append("The version is self-reported in an HTTP header. It is not authenticated and may "
                       "be spoofed, stale or rewritten by an intermediary.")
    elif quality == QUALITY_MANUAL:
        caveats.append("The version was typed in by the user; it is not an observation of any server.")

    fixed = db.fixed.get(parsed.branch)
    if fixed is not None:
        status = "known"
    elif parsed.branch_key <= db.legacy_max:
        status = "legacy"
    else:
        status = "unknown"

    if status == "unknown":
        if parsed.branch_key[0] == 8 and parsed.branch_key[1] == 6:
            notes.append(db.data.get("informational_notes", {}).get("prerelease_8_6", ""))
        return _blank(db, mode, COVERAGE_UNKNOWN, notes=[n for n in notes if n], caveats=caveats,
                      omen="PHP %s is outside the bundled advisory data." % parsed.branch,
                      finding="PHP branch %s is not covered by the bundled advisory snapshot (reviewed %s). "
                              "No assessment of PHP2Shell exposure is made." % (parsed.branch, db.last_reviewed),
                      recommendation="Consult the current official PHP security announcements for this "
                                     "branch. Do not treat this result as safe or as vulnerable.",
                      **base)

    if parsed.kind in (PRERELEASE, UNRECOGNIZED):
        return _blank(db, mode, INCONCLUSIVE, caveats=caveats,
                      omen="Pre-release or unrecognised version suffix.",
                      finding="Version '%s' carries the suffix '%s', which marks a pre-release or an "
                              "unrecognised build. It cannot be equated with a final release, so no "
                              "assessment is made." % (sanitize_text(parsed.raw, 80), sanitize_text(parsed.suffix, 64)),
                      recommendation="Determine the exact installed release and patch state directly on the server.",
                      **base)

    if parsed.kind == VENDOR_BUILD:
        caveats.append("The version carries a build suffix ('%s'), typical of a distribution package. "
                       "Vendors may backport fixes without changing the upstream number."
                       % sanitize_text(parsed.suffix, 64))

    scores = db.scores
    cves = ", ".join(db.primary_cves)
    if status == "legacy":
        caveats.append(db.data["legacy_policy"]["notes"])
        return _blank(db, mode, LEGACY_REVIEW, risk_score=scores["legacy_patch_review"], caveats=caveats,
                      notes=notes, omen="End-of-life upstream branch; patch status must be verified.",
                      finding="PHP %s is an end-of-life upstream branch with no ordinary fixed release for %s. "
                              "Whether this installation is exposed depends on whether the vendor or the "
                              "administrator applied a backported patch, which the version number cannot show."
                              % (parsed.branch, cves),
                      recommendation="Ask the OS or hosting vendor whether the installed package includes the "
                                     "PHP2Shell backports (compare build date or package changelog), or move to "
                                     "a supported PHP branch at or above its fixed release.",
                      **base)

    base["first_fixed"] = fixed.numeric
    if compare_release(parsed, fixed) < 0:
        caveats.append("A vendor may have backported the fix while keeping this version number; "
                       "the version alone cannot show that.")
        return _blank(db, mode, POTENTIAL_EXPOSURE, risk_score=scores["potential_exposure"], caveats=caveats,
                      notes=notes, omen="Reported version predates the upstream fix.",
                      finding="Version %s is below the first upstream release that fixes %s on branch %s "
                              "(%s). Actual vulnerability has not been verified."
                              % (parsed.numeric, cves, parsed.branch, fixed.numeric),
                      recommendation="Update to PHP %s or later on this branch, or to a vendor package confirmed "
                                     "to include the fixes. Partial mitigations (memory_limit, upload limits, "
                                     "session.upload_progress.enabled=0) reduce some paths but are not a "
                                     "substitute for patching." % fixed.numeric,
                      **base)

    caveats.append("Meeting the original fix threshold does not establish that the system is secure; "
                   "it covers only %s." % cves)
    return _blank(db, mode, THRESHOLD_MET, risk_score=scores["threshold_met"], caveats=caveats, notes=notes,
                  omen="Version meets the original upstream fix threshold.",
                  finding="Version %s meets or exceeds the first upstream fixed release (%s) for %s on branch %s. "
                          "This is a version comparison only; the true runtime was not verified, and "
                          "CVE-2026-115560 is a separate issue not resolved by those releases."
                          % (parsed.numeric, fixed.numeric, cves, parsed.branch),
                  recommendation="No further action is indicated by the version alone for the original two CVEs. "
                                 "Confirm the real runtime version on the server and review the session upload "
                                 "progress configuration noted under the additional advisory.",
                  **base)


def assess_manual(db: AdvisoryDB, text: str) -> Assessment:
    """Offline assessment of a user-supplied version. Performs no network access."""
    shown = sanitize_text(text.strip(), 80)
    return _assess_version(db, text, mode="manual", source="user input", quality=QUALITY_MANUAL,
                           evidence_lines=["user-supplied version: %s" % shown])


def assess_fingerprint(db: AdvisoryDB, result: fp.FingerprintResult, *, target_url: str,
                       final_url: Optional[str], http_status: Optional[int]) -> Assessment:
    ctx = dict(target_url=target_url, final_url=final_url, http_status=http_status)
    ignored = list(result.ignored)
    if result.status == fp.CONFLICT:
        lines = ["%s: %s" % (e.header, e.value) for e in result.evidence]
        return _blank(db, "url", INCONCLUSIVE, evidence_lines=lines, notes=ignored,
                      evidence_source=result.sources, omen="CONFLICTING VERSION EVIDENCE",
                      finding="CONFLICTING VERSION EVIDENCE: the responses report different PHP versions (%s). "
                              "No single version is chosen." % ", ".join(result.conflicting),
                      recommendation="Check the PHP version directly on the server; a proxy, load balancer or "
                                     "mixed backend pool may be involved.", **ctx)
    if result.status != fp.FOUND:
        return _blank(db, "url", INCONCLUSIVE, notes=ignored, omen="No PHP version disclosed.",
                      finding=NO_VERSION_FINDING,
                      recommendation="Do not read this as safe. Check the PHP version directly on the server, "
                                     "or use manual mode with a known version.", **ctx)
    lines = ["%s: %s" % (e.header, e.value) for e in result.evidence]
    out = _assess_version(db, result.version, mode="url", source=result.sources, quality=QUALITY_HEADER,
                          evidence_lines=lines, **ctx)
    out.notes.extend(ignored)
    return out


def assess_url(raw_url: str, db: AdvisoryDB, *, allow_local: bool = False, timeout: float = 8.0,
               progress: Optional[Callable[[str], None]] = None, **scan_kwargs: Any) -> Assessment:
    """Inspect a URL over HTTP(S) and assess the disclosed PHP version. Raises ScanError."""
    from . import scanner

    def tell(stage: str) -> None:
        if progress:
            progress(stage)

    obs = scanner.inspect_url(raw_url, allow_local=allow_local, timeout=timeout, progress=progress,
                              **scan_kwargs)
    tell("identify")
    result = fp.extract_php_version(obs.headers)
    tell("compare")
    assessment = assess_fingerprint(db, result, target_url=obs.requested_url, final_url=obs.final_url,
                                    http_status=obs.status)
    assessment.notes.extend(obs.notes)
    tell("prepare")
    return assessment

"""JSON report construction and opt-in local export."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from . import TOOL_NAME, TOOL_VERSION
from .assessment import QUALITY_MANUAL, Assessment
from .textsafe import redact_url


def utc_timestamp(now: Optional[datetime] = None) -> str:
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_report(a: Assessment, now: Optional[datetime] = None) -> Dict[str, Any]:
    def url(value: Optional[str]) -> Optional[str]:
        return redact_url(value) if value else None

    return {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "assessment_timestamp": utc_timestamp(now) if now or not a.assessed_at else a.assessed_at,
        "assessment_mode": "manual" if a.mode == "manual" else "url",
        "target_url": url(a.target_url),
        "final_url": url(a.final_url),
        "http_status": a.http_status,
        "reported_php_version": a.version,
        "version_evidence_source": a.evidence_source,
        "evidence_quality": a.evidence_quality,
        "version_origin": ("user_supplied" if a.evidence_quality == QUALITY_MANUAL
                           else "remotely_observed" if a.version else None),
        "first_fixed_upstream_version": a.first_fixed,
        "risk_score": a.risk_score,
        "risk_classification": a.classification,
        "primary_cves": list(a.primary_cves),
        "related_advisories": [
            {"cve": r.get("cve"), "date": r.get("date"), "fixed_version": r.get("fixed_version"),
             "included_in_primary_score": False, "status": r.get("status_as_of_review"),
             "notice": r.get("notice_text")}
            for r in a.related],
        "advisory_database_version": a.db_version,
        "advisory_last_reviewed": a.db_reviewed,
        "finding": a.finding,
        "caveats": list(a.caveats),
        "recommendation": a.recommendation,
        "limitations": list(a.limitations),
        "verification": "not verified; no exploitation or vulnerability test was performed",
    }


def safe_filename(a: Assessment, now: Optional[datetime] = None) -> str:
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    label = "manual"
    if a.mode != "manual" and a.target_url:
        label = re.sub(r"[^A-Za-z0-9.-]+", "_", re.sub(r"^https?://", "", redact_url(a.target_url)))
        label = label.strip("._-")[:60] or "target"
    return "eclipse-p2s_%s_%s.json" % (label, stamp)


def export_report(a: Assessment, directory: Path, now: Optional[datetime] = None) -> Path:
    """Write the report below `directory` (created on demand) and return its path."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / safe_filename(a, now)
    counter = 1
    while path.exists():
        path = directory / ("%s-%d.json" % (safe_filename(a, now)[:-5], counter))
        counter += 1
    path.write_text(json.dumps(build_report(a, now), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path

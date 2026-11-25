"""Export IOCs as a STIX 2.1 bundle (importable by MISP, OpenCTI and most TIPs)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from nti import __version__

# Deterministic IDs: re-running on the same capture yields the same STIX objects.
_NS = uuid.UUID("6f1c3e2a-6a43-4b7e-9d1f-2b0c4e8a9f10")

_PATTERNS = {
    "ip": "[ipv4-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "ja3": "[network-traffic:extensions.'tls-ext'.ja3 = '{v}']",
}
_CONFIDENCE = {"Critical": 90, "High": 75, "Medium": 50, "Low": 30, "Info": 10}


def _ts(epoch: float | None) -> str:
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc) if epoch else datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sid(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, '|'.join(parts))}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def build_bundle(results: dict) -> dict:
    meta = results["meta"]
    case = meta["case_id"]
    now = _ts(None)
    identity_id = _sid("identity", "nti", meta.get("analyst", ""))
    objects: list[dict] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": now, "modified": now,
        "name": meta.get("analyst") or "NTI", "identity_class": "individual",
    }]
    indicator_ids = []
    for ioc in results.get("iocs", []):
        tmpl = _PATTERNS.get(ioc["type"])
        if not tmpl:
            continue
        iid = _sid("indicator", case, ioc["type"], ioc["value"])
        indicator_ids.append(iid)
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": iid,
            "created": now, "modified": now, "created_by_ref": identity_id,
            "name": f"{ioc['type'].upper()} {ioc['value']}",
            "description": f"{', '.join(ioc.get('categories', []))} - {ioc.get('hits', 0)} hit(s). {ioc.get('context') or ''}".strip(),
            "indicator_types": ["malicious-activity"],
            "pattern": tmpl.format(v=_escape(ioc["value"])),
            "pattern_type": "stix",
            "valid_from": _ts(ioc.get("first_seen")),
            "confidence": _CONFIDENCE.get(ioc["severity"], 50),
            "labels": [ioc["severity"].lower()] + [c.lower() for c in ioc.get("categories", [])],
        })
    objects.append({
        "type": "report", "spec_version": "2.1", "id": _sid("report", case),
        "created": now, "modified": now, "created_by_ref": identity_id,
        "name": f"NTI case {case}",
        "description": f"Network traffic investigation - risk {results['risk']['level']} "
                       f"({results['risk']['score']}/100), {len(results.get('findings', []))} findings.",
        "report_types": ["threat-report"],
        "published": now,
        "object_refs": indicator_ids or [identity_id],
    })
    return {"type": "bundle", "id": _sid("bundle", case, now), "objects": objects,
            "x_nti_version": __version__}


def write_stix(results: dict, out_path: str) -> str:
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(build_bundle(results), fh, indent=2)
    return out_path

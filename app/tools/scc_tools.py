"""
SCC tools — all calls use the Security Command Center v2 API.
The v1 API has been retired for this organisation.
"""
from google.cloud import securitycenter_v2

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SEVERITY_UNSPECIFIED": 9}


def list_active_findings(
    org_id: str,
    severity: str = "HIGH_PLUS",
    max_results: int = 20,
) -> list[dict]:
    """
    Fetches active findings from Security Command Center (v2 API) sorted by
    severity then attack-exposure score.

    severity: "CRITICAL_ONLY" | "HIGH_PLUS" (default) | "MEDIUM_PLUS" | "ALL"
    max_results: how many findings to return (capped at 50)

    Returns a list of dicts with:
      finding_id, category, severity, resource_name, resource_short,
      event_time, attack_exposure_score (float | None)
    On error returns [{"error": "<message>"}].
    """
    _SEVERITY_INCLUDE = {
        "CRITICAL_ONLY": {"CRITICAL"},
        "HIGH_PLUS":     {"CRITICAL", "HIGH"},
        "MEDIUM_PLUS":   {"CRITICAL", "HIGH", "MEDIUM"},
        "ALL":           {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
    }.get(severity, {"CRITICAL", "HIGH"})

    try:
        client = securitycenter_v2.SecurityCenterClient()
        req = securitycenter_v2.ListFindingsRequest(
            parent=f"organizations/{org_id}/sources/-",
            filter='state="ACTIVE"',
            page_size=50,
        )
        findings = []
        for r in client.list_findings(request=req):
            f = r.finding

            sev_name = f.severity.name if hasattr(f.severity, "name") else str(f.severity)
            if sev_name not in _SEVERITY_INCLUDE:
                continue

            mute_name = f.mute.name if hasattr(f.mute, "name") else str(f.mute)
            if mute_name == "MUTED":
                continue

            try:
                score = round(f.attack_exposure.score, 2) if f.attack_exposure and f.attack_exposure.score else None
            except Exception:
                score = None

            resource = f.resource_name or ""
            findings.append({
                "finding_id":            f.name,
                "category":              f.category,
                "severity":              sev_name,
                "resource_name":         resource,
                "resource_short":        resource.split("/")[-1] if resource else "",
                "event_time":            f.event_time.isoformat() if f.event_time else None,
                "attack_exposure_score": score,
            })

        findings.sort(key=lambda x: (
            _SEV_ORDER.get(x["severity"], 9),
            -(x["attack_exposure_score"] or 0.0),
        ))
        return findings[:max_results]

    except Exception as exc:
        return [{"error": f"Failed to list findings: {exc}"}]


def get_finding_detail(finding_id: str, org_id: str) -> dict:
    """
    Fetches full detail for a specific SCC finding by its resource name.
    finding_id should be the full resource name:
      organizations/{org}/sources/{source}/locations/{loc}/findings/{id}
    or a short ID — in which case we search for it.
    """
    try:
        client = securitycenter_v2.SecurityCenterClient()

        # If caller passed a full resource name, use it directly via list with name filter
        if finding_id.startswith("organizations/"):
            filt = f'name="{finding_id}"'
        else:
            filt = f'name:"{finding_id}"'

        req = securitycenter_v2.ListFindingsRequest(
            parent=f"organizations/{org_id}/sources/-",
            filter=filt,
            page_size=1,
        )
        for r in client.list_findings(request=req):
            f = r.finding
            sev_name  = f.severity.name if hasattr(f.severity, "name") else str(f.severity)
            state_name = f.state.name if hasattr(f.state, "name") else str(f.state)
            try:
                score = round(f.attack_exposure.score, 2) if f.attack_exposure and f.attack_exposure.score else None
            except Exception:
                score = None
            resource = f.resource_name or ""
            # source_properties values are protobuf Value structs — extract to plain Python
            try:
                src_props = {}
                for k, v in f.source_properties.items():
                    kind = v.WhichOneof("kind")
                    if kind == "string_value":
                        src_props[k] = v.string_value
                    elif kind == "number_value":
                        src_props[k] = v.number_value
                    elif kind == "bool_value":
                        src_props[k] = v.bool_value
                    else:
                        src_props[k] = str(v)
            except Exception:
                src_props = {}
            return {
                "finding_id":            f.name,
                "category":              f.category,
                "severity":              sev_name,
                "state":                 state_name,
                "resource_name":         resource,
                "resource_short":        resource.split("/")[-1] if resource else "",
                "event_time":            f.event_time.isoformat() if f.event_time else None,
                "attack_exposure_score": score,
                "description":           f.description or "",
                "remediation_text":      getattr(f, "next_steps", "") or "",
                "external_uri":          f.external_uri or "",
                "source_properties":     src_props,
            }
        return {}

    except Exception as exc:
        return {"error": f"Failed to get finding: {exc}"}


def mute_resolved_finding(finding_id: str, org_id: str) -> dict:
    """
    Mutes a finding in SCC after successful remediation.
    finding_id must be the full resource name.
    """
    try:
        client = securitycenter_v2.SecurityCenterClient()
        req = securitycenter_v2.SetMuteRequest(
            name=finding_id,
            mute=securitycenter_v2.Finding.Mute.MUTED,
        )
        f = client.set_mute(request=req)
        return {"status": "MUTED", "finding_id": f.name}
    except Exception as exc:
        return {"error": f"Failed to mute finding: {exc}"}

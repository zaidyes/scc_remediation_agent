from google.cloud import securitycenter_v2
from typing import Iterator

_SEV_NAMES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def list_active_findings(
    org_id: str,
    severity_filter: list[str],   # e.g. ["CRITICAL", "HIGH"]
    page_size: int = 1000
) -> Iterator[dict]:
    """
    Yields normalised finding dicts from SCC v2 API.
    Applies severity filter and excludes muted findings (post-filtered in Python
    to avoid relying on server-side filter syntax differences between v1 and v2).
    """
    client = securitycenter_v2.SecurityCenterClient()
    sev_set = set(severity_filter)

    request = securitycenter_v2.ListFindingsRequest(
        parent=f"organizations/{org_id}/sources/-",
        filter='state="ACTIVE"',
        page_size=min(page_size, 1000),
    )

    for result in client.list_findings(request=request):
        f = result.finding

        sev_name = f.severity.name if hasattr(f.severity, "name") else str(f.severity)
        if sev_name not in sev_set:
            continue

        mute_name = f.mute.name if hasattr(f.mute, "name") else str(f.mute)
        if mute_name == "MUTED":
            continue

        # In v2, vulnerability.cve is a single Cve object (not a list)
        cve_ids = []
        cvss_score = None
        if f.vulnerability and f.vulnerability.cve:
            cve = f.vulnerability.cve
            if cve.id:
                cve_ids = [cve.id]
            if cve.cvssv3:
                cvss_score = cve.cvssv3.base_score if hasattr(cve.cvssv3, "base_score") else None

        yield {
            "finding_id":            f.name.split("/")[-1],
            "full_name":             f.name,
            "resource_name":         f.resource_name,
            "category":              f.category,
            "severity":              sev_name,
            "finding_class":         f.finding_class.name if hasattr(f.finding_class, "name") else str(f.finding_class),
            "cve_ids":               cve_ids,
            "cvss_score":            cvss_score,
            "attack_exposure_score": f.attack_exposure.score if f.attack_exposure else 0.0,
            "attack_exposure_state": f.attack_exposure.state.name if f.attack_exposure else "UNKNOWN",
            "remediation_text":      f.next_steps or "",
            "remediation_uri":       f.external_uri or "",
            "event_time":            f.event_time.isoformat() if f.event_time else "",
        }

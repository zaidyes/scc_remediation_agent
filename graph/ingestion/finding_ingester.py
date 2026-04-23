from google.cloud import securitycenter_v1
from typing import Iterator

def list_active_findings(
    org_id: str,
    severity_filter: list[str],   # e.g. ["CRITICAL", "HIGH"]
    page_size: int = 1000
) -> Iterator[dict]:
    """
    Yields normalised finding dicts from SCC.
    Applies severity filter and excludes muted findings.
    """
    client = securitycenter_v1.SecurityCenterClient()
    parent = f"organizations/{org_id}/sources/-"

    sev_expr = " OR ".join(f'severity="{s}"' for s in severity_filter)
    filter_str = f'state="ACTIVE" AND NOT mute="MUTED" AND ({sev_expr})'

    request = securitycenter_v1.ListFindingsRequest(
        parent=parent,
        filter=filter_str,
        page_size=page_size,
        field_mask="name,resourceName,category,severity,findingClass,"
                   "vulnerability,externalSystems,attackExposure,"
                   "remediation,createTime,eventTime"
    )

    for result in client.list_findings(request=request):
        f = result.finding
        yield {
            "finding_id": f.name.split("/")[-1],
            "full_name": f.name,
            "resource_name": f.resource_name,
            "category": f.category,
            "severity": f.severity.name,
            "finding_class": f.finding_class.name,
            "cve_ids": [v.cve.id for v in f.vulnerability.cve_ids] if f.vulnerability else [],
            "cvss_score": f.vulnerability.cvss.score if f.vulnerability and f.vulnerability.cvss else None,
            "attack_exposure_score": f.attack_exposure.score if f.attack_exposure else 0.0,
            "attack_exposure_state": f.attack_exposure.state.name if f.attack_exposure else "UNKNOWN",
            "remediation_text": f.remediation.instructions if f.remediation else "",
            "remediation_uri": f.remediation.uri if f.remediation else "",
            "event_time": f.event_time.isoformat() if f.event_time else "",
        }

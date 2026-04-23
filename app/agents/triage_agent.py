from graph.ingestion.finding_ingester import list_active_findings
from app.tools.graph_tools import get_resource_scope_status


class TriageAgent:
    def __init__(self, config):
        self.config = config

    async def run(self) -> list[dict]:
        """
        Fetches active findings, filters to in-scope assets and
        severity threshold, deduplicates, and ranks by attack exposure.
        """
        cfg = self.config
        findings = list(list_active_findings(
            org_id=cfg.org_id,
            severity_filter=cfg.severity_threshold.to_api_values(),
        ))

        in_scope = []
        for f in findings:
            scope_status = get_resource_scope_status(
                asset_name=f["resource_name"],
                scope_config=cfg.scope,
            )
            if scope_status["in_scope"]:
                f["scope_metadata"] = scope_status
                in_scope.append(f)

        if cfg.filters.deduplicate_across_scanners:
            in_scope = _deduplicate(in_scope)

        if cfg.filters.exclude_accepted_risks:
            in_scope = [f for f in in_scope if not f.get("muted")]

        in_scope.sort(key=lambda f: f.get("attack_exposure_score", 0.0), reverse=True)

        if cfg.filters.require_active_exposure_path:
            in_scope = [
                f for f in in_scope
                if f.get("attack_exposure_state") == "EXPOSED"
                or f.get("attack_exposure_score", 0) > 0
            ]

        return in_scope


def _deduplicate(findings: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for f in findings:
        key = (f["resource_name"], f["category"], tuple(sorted(f.get("cve_ids", []))))
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result

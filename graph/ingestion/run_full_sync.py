import asyncio
import os
from graph.ingestion.asset_ingester import export_assets
from graph.ingestion.finding_ingester import list_active_findings
from graph.ingestion.relationship_ingester import ingest_all_relationships
from graph.ingestion.iam_ingester import ingest_iam_bindings
from agent.tools.graph_tools import mark_assets_in_scope, _run_write
# Mock config loader for now
class MockConfig:
    def __init__(self, customer_id, org_id):
        self.customer_id = customer_id
        self.org_id = org_id
        self.scope = type("Scope", (), {"matches_asset": lambda self, x: True})()

def load_config(customer_id):
    return MockConfig(customer_id, "mock-org-id")

def compute_dormancy_score(asset_name: str, project_id: str) -> float:
    # Stub logic for dormancy
    return 0.0

async def run_full_sync(customer_id: str):
    config = load_config(customer_id)
    org_id = config.org_id

    print("[sync] Step 1: export all assets → write Resource nodes")
    assets = export_assets(org_id)
    _upsert_resource_nodes(assets, config)

    print("[sync] Step 2: ingest relationships → write edges")
    rel_summary = ingest_all_relationships(org_id)
    print(f"[sync] Relationships: {rel_summary}")

    print("[sync] Step 3: ingest IAM bindings → write GRANTS_ACCESS_TO edges")
    from google.cloud import asset_v1
    client = asset_v1.AssetServiceClient()
    iam_edges = ingest_iam_bindings(client, org_id)
    print(f"[sync] IAM Bindings: {len(iam_edges)} edges written")

    print("[sync] Step 4: ingest SCC findings → write Finding nodes + AFFECTS edges")
    findings = list(list_active_findings(
        org_id,
        severity_filter=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    ))
    _upsert_finding_nodes(findings)

    print("[sync] Step 5: compute dormancy scores")
    _update_dormancy_scores(assets, config)

    print("[sync] Step 6: mark in-scope assets")
    in_scope_count = mark_assets_in_scope(config.scope, org_id)
    print(f"[sync] {in_scope_count} assets marked in scope")

    print("[sync] Full sync complete")

def _upsert_resource_nodes(assets: list[dict], config):
    for i in range(0, len(assets), 500):
        batch = assets[i:i+500]
        for a in batch:
            labels = a.get("labels") or {}
            a["env"] = labels.get("env", labels.get("environment", "unknown"))
            a["team"] = labels.get("team", "unknown")
            a["owner_email"] = labels.get("owner", "")
            a["data_class"] = labels.get("data-class", labels.get("data_class", ""))
            a["maint_window"] = labels.get("maint-window", "")
            a["in_scope"] = False

        _run_write("""
        UNWIND $assets AS a
        MERGE (r:Resource {asset_name: a.asset_name})
        SET r.asset_type   = a.asset_type,
            r.short_name   = split(a.asset_name, '/')[-1],
            r.project      = a.project,
            r.location     = a.location,
            r.env          = a.env,
            r.team         = a.team,
            r.owner_email  = a.owner_email,
            r.data_class   = a.data_class,
            r.maint_window = a.maint_window,
            r.status       = a.status,
            r.labels       = a.labels,
            r.in_scope     = a.in_scope,
            r.last_synced  = datetime()
        """, {"assets": batch})

        _run_write("""
        UNWIND $assets AS a
        MERGE (p:Project {project_id: a.project})
        MERGE (r:Resource {asset_name: a.asset_name})-[:BELONGS_TO]->(p)
        """, {"assets": batch})

def _upsert_finding_nodes(findings: list[dict]):
    for i in range(0, len(findings), 500):
        batch = findings[i:i+500]
        _run_write("""
        UNWIND $findings AS f
        MERGE (fn:Finding {finding_id: f.finding_id})
        SET fn.full_name             = f.full_name,
            fn.category              = f.category,
            fn.severity              = f.severity,
            fn.finding_class         = f.finding_class,
            fn.cve_ids               = f.cve_ids,
            fn.cvss_score            = f.cvss_score,
            fn.attack_exposure_score = f.attack_exposure_score,
            fn.attack_exposure_state = f.attack_exposure_state,
            fn.remediation_text      = f.remediation_text,
            fn.state                 = 'ACTIVE',
            fn.last_synced           = datetime()
        WITH fn, f
        MATCH (r:Resource {asset_name: f.resource_name})
        MERGE (fn)-[:AFFECTS]->(r)
        """, {"findings": batch})

def _update_dormancy_scores(assets: list[dict], config):
    updates = []
    for a in assets:
        if a.get("asset_type") == "compute.googleapis.com/Instance":
            score = compute_dormancy_score(a["asset_name"], a["project"])
            updates.append({"name": a["asset_name"], "score": score})

    if updates:
        _run_write("""
        UNWIND $updates AS u
        MATCH (r:Resource {asset_name: u.name})
        SET r.dormancy_score = u.score
        """, {"updates": updates})

if __name__ == "__main__":
    asyncio.run(run_full_sync("test-customer"))

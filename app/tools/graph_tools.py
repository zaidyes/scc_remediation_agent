from neo4j import GraphDatabase, Driver
from functools import lru_cache
import os

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j.neo4j.svc.cluster.local:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD_SECRET = os.environ.get("NEO4J_PASSWORD_SECRET", "neo4j-password")

@lru_cache(maxsize=1)
def _get_driver() -> Driver:
    password = _read_secret(NEO4J_PASSWORD_SECRET)
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, password))

def _read_secret(secret_id: str) -> str:
    from google.cloud import secretmanager
    client = secretmanager.SecretManagerServiceClient()
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    if not project_id:
        return "dummy-password" # For testing/local without setup
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    try:
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception:
        return "dummy-password"

def _run_query(cypher: str, params: dict = None) -> list[dict]:
    driver = _get_driver()
    with driver.session() as session:
        result = session.run(cypher, params or {})
        return [dict(record) for record in result]

def _run_write(cypher: str, params: dict = None) -> None:
    driver = _get_driver()
    with driver.session() as session:
        session.execute_write(lambda tx: tx.run(cypher, params or {}))

# Scope checking
def get_resource_scope_status(asset_name: str, scope_config) -> dict:
    rows = _run_query(
        "MATCH (r:Resource {asset_name: $name}) RETURN r.labels AS labels, r.project AS project, r.in_scope AS in_scope",
        {"name": asset_name}
    )
    if not rows:
        return {"in_scope": False, "reason": "asset_not_in_graph"}
    r = rows[0]
    asset = {"labels": r.get("labels") or {}, "project": r.get("project", "")}
    in_scope = scope_config.matches_asset(asset)
    return {"in_scope": in_scope, "project": asset["project"], "labels": asset["labels"]}

# Resource metadata
def get_resource_metadata(asset_name: str) -> dict:
    rows = _run_query(
        "MATCH (r:Resource {asset_name: $name}) RETURN r.env AS env, r.team AS team, r.owner_email AS owner_email, r.data_class AS data_class, r.status AS status, r.maint_window AS maint_window, r.labels AS labels, r.dormancy_score AS dormancy_score, r.last_activity AS last_activity",
        {"name": asset_name}
    )
    return rows[0] if rows else {}

def get_resource_labels(asset_name: str) -> dict:
    rows = _run_query("MATCH (r:Resource {asset_name: $name}) RETURN r.labels AS labels", {"name": asset_name})
    return rows[0].get("labels") or {} if rows else {}

def get_resource_maint_window(asset_name: str) -> str | None:
    rows = _run_query("MATCH (r:Resource {asset_name: $name}) RETURN r.maint_window AS mw", {"name": asset_name})
    val = rows[0].get("mw") if rows else None
    return val if val else None

# Traversal
def query_blast_radius(asset_name: str, max_hops: int = 3) -> list[dict]:
    rows = _run_query(
        f"MATCH path = (vuln:Resource {{asset_name: $asset_name}})-[:CONNECTS_TO|ROUTES_TRAFFIC_TO|DEPENDS_ON|GRANTS_ACCESS_TO|HOSTED_BY|USES_SERVICE_ACCOUNT|IN_SUBNET*1..{max_hops}]->(downstream:Resource) WHERE downstream.asset_name <> $asset_name WITH downstream, min(length(path)) AS hops, collect(DISTINCT [r in relationships(path) | type(r)][0]) AS edge_types RETURN downstream.asset_name AS name, downstream.env AS env, downstream.team AS team, downstream.data_class AS data_class, downstream.asset_type AS asset_type, hops, edge_types ORDER BY hops ASC, downstream.env DESC LIMIT 50",
        {"asset_name": asset_name}
    )
    return rows

def query_iam_paths(asset_name: str) -> list[dict]:
    rows = _run_query(
        "MATCH (vuln:Resource {asset_name: $asset_name})<-[:GRANTS_ACCESS_TO]-(sa:Resource) MATCH (sa)-[:GRANTS_ACCESS_TO]->(prod:Resource {env: 'prod'}) WHERE prod.asset_name <> $asset_name RETURN sa.asset_name AS service_account, sa.short_name AS sa_email, collect(DISTINCT prod.asset_name)[..10] AS reachable_prod_resources, count(DISTINCT prod) AS prod_blast_count ORDER BY prod_blast_count DESC LIMIT 10",
        {"asset_name": asset_name}
    )
    return rows

def check_dormancy(asset_name: str) -> dict:
    rows = _run_query(
        "MATCH (r:Resource {asset_name: $name}) RETURN r.dormancy_score AS dormancy_score, r.last_activity AS last_activity, r.status AS status, CASE WHEN r.dormancy_score > 0.8 THEN 'DORMANT' WHEN r.dormancy_score > 0.4 THEN 'PERIODIC' ELSE 'ACTIVE' END AS dormancy_class",
        {"name": asset_name}
    )
    if not rows:
        return {"dormancy_class": "ACTIVE", "dormancy_score": 0.0, "last_activity": None, "status": "UNKNOWN"}
    return rows[0]

def update_resource_finding_state(asset_name: str, finding_id: str, new_state: str) -> None:
    _run_write(
        "MATCH (f:Finding {finding_id: $finding_id})-[:AFFECTS]->(r:Resource {asset_name: $asset_name}) SET f.state = $new_state, f.resolved_at = datetime(), r.last_patched = datetime()",
        {"finding_id": finding_id, "asset_name": asset_name, "new_state": new_state}
    )

def mark_assets_in_scope(scope_config, org_id: str) -> int:
    all_resources = _run_query("MATCH (r:Resource) RETURN r.asset_name AS name, r.project AS project, r.labels AS labels")
    in_scope_names = []
    out_of_scope_names = []

    for r in all_resources:
        asset = {"project": r.get("project", ""), "labels": r.get("labels") or {}}
        if scope_config.matches_asset(asset):
            in_scope_names.append(r["name"])
        else:
            out_of_scope_names.append(r["name"])

    if in_scope_names:
        _run_write("UNWIND $names AS n MATCH (r:Resource {asset_name: n}) SET r.in_scope = true", {"names": in_scope_names})
    if out_of_scope_names:
        _run_write("UNWIND $names AS n MATCH (r:Resource {asset_name: n}) SET r.in_scope = false", {"names": out_of_scope_names})

    return len(in_scope_names)

def _get_project_resource(asset_name: str) -> str:
    rows = _run_query(
        "MATCH (r:Resource {asset_name: $name})-[:BELONGS_TO]->(p:Project) RETURN '//cloudresourcemanager.googleapis.com/projects/' + p.project_id AS project_resource",
        {"name": asset_name}
    )
    return rows[0]["project_resource"] if rows else ""

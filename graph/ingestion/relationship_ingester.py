from google.cloud import asset_v1
from agent.tools.graph_tools import _run_write

RELATIONSHIP_BATCHES = [
    {
        "label": "compute_instance_relationships",
        "asset_types": ["compute.googleapis.com/Instance"],
        "relationship_types": [
            "COMPUTE_INSTANCE_USE_DISK",
            "INSTANCE_TO_INSTANCEGROUP",
            "COMPUTE_INSTANCE_USE_NETWORK_INTERFACE",
            "COMPUTE_INSTANCE_USE_SUBNETWORK",
            "COMPUTE_INSTANCE_USE_ADDRESS",
            "COMPUTE_INSTANCE_USE_BACKEND_SERVICE",
        ],
    },
    {
        "label": "network_relationships",
        "asset_types": [
            "compute.googleapis.com/Network",
            "compute.googleapis.com/Subnetwork",
            "compute.googleapis.com/Firewall",
            "compute.googleapis.com/ForwardingRule",
            "compute.googleapis.com/BackendService",
        ],
        "relationship_types": [
            "COMPUTE_NETWORK_CONTAIN_SUBNETWORK",
            "COMPUTE_FIREWALL_APPLY_TO_NETWORK",
            "COMPUTE_BACKEND_SERVICE_USE_HEALTH_CHECK",
            "COMPUTE_FORWARDING_RULE_USE_BACKEND_SERVICE",
            "COMPUTE_SUBNETWORK_CONTAIN_IP_RANGE",
        ],
    },
    {
        "label": "gke_relationships",
        "asset_types": [
            "container.googleapis.com/Cluster",
            "container.googleapis.com/NodePool",
        ],
        "relationship_types": [
            "GKE_CLUSTER_CONTAIN_NODEPOOL",
            "GKE_NODEPOOL_USE_INSTANCE_TEMPLATE",
        ],
    },
    {
        "label": "iam_service_account_relationships",
        "asset_types": [
            "compute.googleapis.com/Instance",
            "container.googleapis.com/Cluster",
            "run.googleapis.com/Service",
            "cloudfunctions.googleapis.com/CloudFunction",
        ],
        "relationship_types": [
            "COMPUTE_INSTANCE_USE_SERVICE_ACCOUNT",
        ],
    },
    {
        "label": "storage_relationships",
        "asset_types": [
            "storage.googleapis.com/Bucket",
            "bigquery.googleapis.com/Dataset",
            "bigquery.googleapis.com/Table",
            "sqladmin.googleapis.com/Instance",
        ],
        "relationship_types": [
            "BIGQUERY_DATASET_CONTAIN_TABLE",
        ],
    },
]

RELATIONSHIP_TYPE_TO_NEO4J = {
    "COMPUTE_INSTANCE_USE_DISK":               "USES_DISK",
    "INSTANCE_TO_INSTANCEGROUP":               "BELONGS_TO_GROUP",
    "COMPUTE_INSTANCE_USE_NETWORK_INTERFACE":  "CONNECTS_TO",
    "COMPUTE_INSTANCE_USE_SUBNETWORK":         "IN_SUBNET",
    "COMPUTE_INSTANCE_USE_ADDRESS":            "USES_ADDRESS",
    "COMPUTE_INSTANCE_USE_BACKEND_SERVICE":    "SERVES_TRAFFIC_VIA",
    "COMPUTE_NETWORK_CONTAIN_SUBNETWORK":      "CONTAINS",
    "COMPUTE_FIREWALL_APPLY_TO_NETWORK":       "APPLIES_TO_NETWORK",
    "COMPUTE_BACKEND_SERVICE_USE_HEALTH_CHECK":"HEALTH_CHECKED_BY",
    "COMPUTE_FORWARDING_RULE_USE_BACKEND_SERVICE": "ROUTES_TRAFFIC_TO",
    "GKE_CLUSTER_CONTAIN_NODEPOOL":            "HOSTED_BY",
    "GKE_NODEPOOL_USE_INSTANCE_TEMPLATE":      "USES_TEMPLATE",
    "COMPUTE_INSTANCE_USE_SERVICE_ACCOUNT":    "USES_SERVICE_ACCOUNT",
    "BIGQUERY_DATASET_CONTAIN_TABLE":          "CONTAINS",
    "COMPUTE_SUBNETWORK_CONTAIN_IP_RANGE":     "CONTAINS",
}

def ingest_all_relationships(org_id: str) -> dict:
    summary = {}
    client = asset_v1.AssetServiceClient()

    for batch in RELATIONSHIP_BATCHES:
        edges = _fetch_relationship_batch(
            client=client,
            org_id=org_id,
            asset_types=batch["asset_types"],
            relationship_types=batch["relationship_types"],
        )
        _write_edges_to_neo4j(edges)
        summary[batch["label"]] = len(edges)
        print(f"[relationships] {batch['label']}: {len(edges)} edges written")

    return summary

def _fetch_relationship_batch(
    client,
    org_id: str,
    asset_types: list[str],
    relationship_types: list[str],
) -> list[dict]:
    edges = []
    request = asset_v1.ListAssetsRequest(
        parent=f"organizations/{org_id}",
        asset_types=asset_types,
        content_type=asset_v1.ContentType.RELATIONSHIP,
        relationship_types=relationship_types,
        page_size=500,
    )

    try:
        for asset in client.list_assets(request=request):
            if not asset.related_assets:
                continue
            source = asset.name
            for related in asset.related_assets.related_assets:
                rel_type = asset.related_assets.relationship_attributes.relationship_type \
                    if asset.related_assets.relationship_attributes else "UNKNOWN"
                edges.append({
                    "source": source,
                    "target": related.asset,
                    "relationship_type": rel_type,
                    "neo4j_label": RELATIONSHIP_TYPE_TO_NEO4J.get(rel_type, "RELATED_TO"),
                    "source_type": asset.asset_type,
                    "target_type": related.asset_type,
                })
    except Exception as e:
        print(f"[relationships] Warning: batch failed for {asset_types}: {e}")

    return edges

def _write_edges_to_neo4j(edges: list[dict]) -> None:
    if not edges:
        return

    from collections import defaultdict
    by_label = defaultdict(list)
    for e in edges:
        by_label[e["neo4j_label"]].append(e)

    for label, label_edges in by_label.items():
        for i in range(0, len(label_edges), 500):
            batch = label_edges[i:i+500]
            cypher = f"""
            UNWIND $edges AS e
            MATCH (src:Resource {{asset_name: e.source}})
            MATCH (tgt:Resource {{asset_name: e.target}})
            MERGE (src)-[r:{label}]->(tgt)
            SET r.relationship_type = e.relationship_type,
                r.last_synced = datetime()
            """
            _run_write(cypher, {"edges": batch})

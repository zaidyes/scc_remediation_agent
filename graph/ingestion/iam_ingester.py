from google.cloud import asset_v1
from agent.tools.graph_tools import _run_write

def ingest_iam_bindings(client, org_id: str) -> list[dict]:
    """
    Pulls IAM_POLICY content type to extract GRANTS_ACCESS_TO edges.
    Returns list of edges written.
    """
    edges = []
    request = asset_v1.ListAssetsRequest(
        parent=f"organizations/{org_id}",
        asset_types=[
            "compute.googleapis.com/Instance",
            "storage.googleapis.com/Bucket",
            "bigquery.googleapis.com/Dataset",
            "container.googleapis.com/Cluster",
            "cloudresourcemanager.googleapis.com/Project",
        ],
        content_type=asset_v1.ContentType.IAM_POLICY,
        page_size=500,
    )

    for asset in client.list_assets(request=request):
        if not asset.iam_policy:
            continue
        resource_name = asset.name
        for binding in asset.iam_policy.bindings:
            role = binding.role
            for member in binding.members:
                if member.startswith("serviceAccount:"):
                    sa_email = member.replace("serviceAccount:", "")
                    edges.append({
                        "resource": resource_name,
                        "sa_email": sa_email,
                        "role": role,
                    })

    if edges:
        cypher = """
        UNWIND $edges AS e
        MATCH (r:Resource {asset_name: e.resource})
        MERGE (sa:Resource {asset_name: 'serviceAccount:' + e.sa_email})
          ON CREATE SET sa.asset_type = 'iam.googleapis.com/ServiceAccount',
                        sa.short_name = e.sa_email
        MERGE (sa)-[rel:GRANTS_ACCESS_TO]->(r)
        SET rel.role = e.role,
            rel.last_synced = datetime()
        """
        for i in range(0, len(edges), 500):
            _run_write(cypher, {"edges": edges[i:i+500]})

    return edges

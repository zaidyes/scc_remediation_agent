from app.tools.graph_tools import query_blast_radius, query_iam_paths, get_resource_metadata
from app.tools.network_tools import get_network_exposure


class ImpactAgent:
    def __init__(self, config):
        self.config = config

    async def analyse(self, finding: dict) -> dict:
        asset_name = finding["resource_name"]

        downstream = query_blast_radius(asset_name, max_hops=3)
        iam_paths = query_iam_paths(asset_name)
        metadata = get_resource_metadata(asset_name)
        network = get_network_exposure(asset_name, self.config.org_id)

        prod_downstream = [r for r in downstream if r.get("env") == "prod"]
        pii_downstream = [r for r in downstream if r.get("data_class") == "pii"]

        blast_level = "LOW"
        if len(prod_downstream) > 0 or metadata.get("env") == "prod":
            blast_level = "MEDIUM"
        if len(prod_downstream) > 3 or pii_downstream:
            blast_level = "HIGH"
        if len(prod_downstream) > 10:
            blast_level = "CRITICAL"

        return {
            "asset_name": asset_name,
            "asset_env": metadata.get("env", "unknown"),
            "asset_team": metadata.get("team", "unknown"),
            "asset_owner": metadata.get("owner_email", ""),
            "blast_level": blast_level,
            "total_downstream": len(downstream),
            "prod_blast_count": len(prod_downstream),
            "pii_blast_count": len(pii_downstream),
            "downstream_resources": downstream[:20],
            "iam_lateral_paths": iam_paths[:10],
            "internet_exposed": network.get("internet_exposed", False),
            "network_exposure_details": network,
        }

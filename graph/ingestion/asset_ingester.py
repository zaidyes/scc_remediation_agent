from google.cloud import asset_v1

ASSET_TYPES = [
    "compute.googleapis.com/Instance",
    "compute.googleapis.com/Disk",
    "compute.googleapis.com/Network",
    "compute.googleapis.com/Subnetwork",
    "compute.googleapis.com/Firewall",
    "container.googleapis.com/Cluster",
    "sqladmin.googleapis.com/Instance",
    "storage.googleapis.com/Bucket",
    "iam.googleapis.com/ServiceAccount",
    "cloudresourcemanager.googleapis.com/Project",
    "cloudresourcemanager.googleapis.com/Folder",
]

def export_assets(org_id: str) -> list[dict]:
    """
    Exports all assets across the org.
    Returns list of normalised asset dicts with labels, location, and ancestry.
    """
    client = asset_v1.AssetServiceClient()
    assets = []

    request = asset_v1.ListAssetsRequest(
        parent=f"organizations/{org_id}",
        asset_types=ASSET_TYPES,
        content_type=asset_v1.ContentType.RESOURCE,
        page_size=1000,
    )

    for asset in client.list_assets(request=request):
        resource = asset.resource.data
        assets.append({
            "asset_name": asset.name,
            "asset_type": asset.asset_type,
            "project": _extract_project(asset.name),
            "location": resource.get("location") or resource.get("region") or "global",
            "labels": dict(resource.get("labels", {})),
            "status": resource.get("status", "RUNNING"),
            "create_time": resource.get("creationTimestamp") or resource.get("createTime"),
            "ancestors": list(asset.ancestors),
            "raw": dict(resource),
        })

    return assets

def _extract_project(asset_name: str) -> str:
    parts = asset_name.split("/")
    if "projects" in parts:
        idx = parts.index("projects")
        return parts[idx + 1]
    return "unknown"

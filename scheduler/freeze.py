def is_change_frozen(asset_name: str, config) -> bool:
    """
    Returns True if a change freeze is in effect for this asset.
    Checks (in order):
    1. Resource label change-freeze=true
    2. Project-level label change-freeze=true
    3. Config-level global freeze toggle
    """
    from app.tools.graph_tools import get_resource_labels, _get_project_resource
    
    labels = get_resource_labels(asset_name)
    if labels.get("change-freeze") == "true":
        return True

    project_resource = _get_project_resource(asset_name)
    if project_resource:
        project_labels = get_resource_labels(project_resource)
        if project_labels.get("change-freeze") == "true":
            return True

    return False

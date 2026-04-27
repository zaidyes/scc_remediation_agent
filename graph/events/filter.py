"""
Change event filter pipeline — Stage 1, 2, and 3.

classify_change(event) is called on every incoming Pub/Sub message before
any graph or approval logic is touched. Returns None to discard, or a
classified change dict to process.

All logic is in-memory — no database calls, no API calls.
"""

# Stage 1 — change types that can affect remediation safety
MATERIAL_CHANGE_TYPES = {
    "IAM_POLICY",
    "status_change",
    "deletion",
    "firewall_rule_change",
    "network_interface_change",
    "service_account_change",
    "critical_label_change",
}

# Stage 2 — which remediation types each change type can affect
CHANGE_AFFECTS_REMEDIATION: dict[str, set[str]] = {
    "IAM_POLICY":               {"IAM", "OS_PATCH", "MISCONFIGURATION"},
    "status_change":            {"OS_PATCH", "MISCONFIGURATION", "FIREWALL", "IAM"},
    "deletion":                 {"OS_PATCH", "MISCONFIGURATION", "FIREWALL", "IAM"},
    "firewall_rule_change":     {"FIREWALL", "MISCONFIGURATION"},
    "network_interface_change": {"FIREWALL", "MISCONFIGURATION"},
    "service_account_change":   {"IAM", "OS_PATCH"},
    "critical_label_change":    {"OS_PATCH", "MISCONFIGURATION", "FIREWALL", "IAM"},
}

# Stage 3 — max hops beyond which changes cannot plausibly affect a remediation
PROXIMITY_HOPS = 1
IAM_PROXIMITY_HOPS = 2

# Label keys whose changes are considered "critical"
CRITICAL_LABEL_KEYS = {"env", "change-freeze", "owner", "maint-window"}


def classify_change(event: dict) -> dict | None:
    """
    Runs the three-stage filter pipeline on a raw CAI or audit event.

    Returns a classified change dict or None (discard).

    Classified change dict:
      {
        "change_type": str,
        "asset_name": str,
        "asset_type": str,
        "content_type": str,          # RESOURCE | IAM_POLICY | RELATIONSHIP
        "affected_remediation_types": set[str],
        "proximity_hops": int,
        "prior_asset": dict | None,
        "updated_asset": dict | None,
        "raw_event": dict,
      }
    """
    # ------------------------------------------------------------------- #
    # Stage 1 — determine change type significance
    # ------------------------------------------------------------------- #
    change_type = _classify_change_type(event)
    if change_type is None:
        return None  # immaterial — discard

    # ------------------------------------------------------------------- #
    # Stage 2 — remediation type relevance
    # ------------------------------------------------------------------- #
    affected = CHANGE_AFFECTS_REMEDIATION.get(change_type)
    if not affected:
        return None

    # ------------------------------------------------------------------- #
    # Stage 3 — proximity scope
    # ------------------------------------------------------------------- #
    hops = IAM_PROXIMITY_HOPS if change_type == "IAM_POLICY" else PROXIMITY_HOPS

    return {
        "change_type": change_type,
        "asset_name": _extract_asset_name(event),
        "asset_type": event.get("asset", {}).get("assetType", ""),
        "content_type": event.get("asset", {}).get("contentType", "RESOURCE"),
        "affected_remediation_types": affected,
        "proximity_hops": hops,
        "prior_asset": event.get("priorAsset"),
        "updated_asset": event.get("asset"),
        "raw_event": event,
    }


# --------------------------------------------------------------------------- #
# Stage 1 helpers
# --------------------------------------------------------------------------- #

def _classify_change_type(event: dict) -> str | None:
    content_type = event.get("asset", {}).get("contentType", "")
    asset = event.get("asset", {})
    prior = event.get("priorAsset", {})

    # Deletion — asset existed before but not after
    if prior and not asset.get("resource") and not asset.get("iamPolicy"):
        return "deletion"

    if content_type == "IAM_POLICY":
        return _classify_iam_event(asset, prior)

    if content_type == "RESOURCE":
        return _classify_resource_event(asset, prior)

    if content_type == "RELATIONSHIP":
        return _classify_relationship_event(asset, prior)

    # Audit log events (from the log sink) carry a different structure
    if "protoPayload" in event:
        return _classify_audit_event(event)

    return None


def _classify_iam_event(asset: dict, prior: dict) -> str | None:
    """
    IAM_POLICY events are only material if bindings actually changed.
    CAI sends IAM_POLICY events on etag refreshes where bindings are identical.
    """
    current_bindings = _extract_bindings(asset.get("iamPolicy", {}))
    prior_bindings = _extract_bindings(prior.get("iamPolicy", {})) if prior else set()

    if current_bindings == prior_bindings:
        return None  # only etag changed — discard

    return "IAM_POLICY"


def _classify_resource_event(asset: dict, prior: dict) -> str | None:
    """
    RESOURCE events — only material if status, critical labels,
    SA attachment, firewall rule, or network interface changed.
    """
    curr_data = asset.get("resource", {}).get("data", {})
    prior_data = prior.get("resource", {}).get("data", {}) if prior else {}

    # Status change (RUNNING → STOPPED/TERMINATED/DELETED)
    curr_status = curr_data.get("status")
    prior_status = prior_data.get("status")
    if curr_status and curr_status != prior_status:
        return "status_change"

    # Critical label change
    curr_labels = curr_data.get("labels", {})
    prior_labels = prior_data.get("labels", {})
    for key in CRITICAL_LABEL_KEYS:
        if curr_labels.get(key) != prior_labels.get(key):
            return "critical_label_change"

    # Service account attachment change
    curr_sa = _extract_sa(curr_data)
    prior_sa = _extract_sa(prior_data)
    if curr_sa != prior_sa:
        return "service_account_change"

    # Firewall rule change — only for Firewall asset type
    asset_type = asset.get("assetType", "")
    if "Firewall" in asset_type:
        if curr_data != prior_data:
            return "firewall_rule_change"

    # Network interface change
    curr_ifaces = curr_data.get("networkInterfaces", [])
    prior_ifaces = prior_data.get("networkInterfaces", [])
    if curr_ifaces != prior_ifaces:
        return "network_interface_change"

    return None  # nothing material changed


def _classify_relationship_event(asset: dict, prior: dict) -> str | None:
    """Relationship changes — SA attachment and network interface are material."""
    rel_type = asset.get("relatedAssets", [{}])[0].get("relationshipType", "")
    material_rel_types = {
        "INSTANCE_TO_NETWORKINTERFACE",
        "INSTANCE_TO_SUBNETWORK",
        "INSTANCE_TO_SERVICEACCOUNT",
    }
    if rel_type in material_rel_types:
        return "network_interface_change" if "NETWORK" in rel_type else "service_account_change"
    return None


def _classify_audit_event(event: dict) -> str | None:
    """Classifies a Cloud Audit Log event from the log sink."""
    method = event.get("protoPayload", {}).get("methodName", "")

    if "SetIamPolicy" in method:
        return "IAM_POLICY"
    if method in ("v1.compute.instances.start", "v1.compute.instances.stop"):
        return "status_change"
    if method in (
        "v1.compute.firewalls.patch",
        "v1.compute.firewalls.insert",
        "v1.compute.firewalls.delete",
    ):
        return "firewall_rule_change"
    if "setMetadata" in method:
        return "service_account_change"

    return None


# --------------------------------------------------------------------------- #
# Utility helpers
# --------------------------------------------------------------------------- #

def _extract_asset_name(event: dict) -> str:
    asset = event.get("asset", {})
    name = asset.get("name", "")
    if not name:
        # Audit log event — extract from protoPayload
        name = event.get("protoPayload", {}).get("resourceName", "")
    return name


def _extract_bindings(iam_policy: dict) -> frozenset:
    """Returns a frozenset of (role, member) tuples for comparison."""
    result = set()
    for binding in iam_policy.get("bindings", []):
        role = binding.get("role", "")
        for member in binding.get("members", []):
            result.add((role, member))
    return frozenset(result)


def _extract_sa(resource_data: dict) -> str | None:
    """Extracts service account email from resource data if present."""
    sa = resource_data.get("serviceAccount")
    if sa:
        return sa
    # GCE instance stores SA under serviceAccounts list
    sa_list = resource_data.get("serviceAccounts", [])
    if sa_list:
        return sa_list[0].get("email")
    return None

"""
Per-content-type graph update handlers.

Each handler receives a classified change (from filter.py) and a Neo4j
session, and updates the graph to reflect the new state. The full sync
(graph/ingestion/run_full_sync.py) remains the source of truth — these
handlers apply incremental deltas only for the fields that changed.
"""
from neo4j import AsyncSession


async def handle_resource_change(change: dict, session: AsyncSession) -> None:
    """
    Updates a Resource node's mutable properties: status, labels,
    service account attachment, and network interface.
    """
    asset = change.get("updated_asset", {})
    asset_name = change.get("asset_name", "")
    if not asset_name:
        return

    data = asset.get("resource", {}).get("data", {})
    change_type = change["change_type"]

    if change_type == "deletion":
        await _handle_deletion(asset_name, session)
        return

    if change_type == "status_change":
        await session.run(
            """
            MATCH (r:Resource {name: $name})
            SET r.status = $status, r.last_synced = datetime()
            """,
            name=asset_name,
            status=data.get("status", "UNKNOWN"),
        )

    elif change_type == "critical_label_change":
        labels = data.get("labels", {})
        await session.run(
            """
            MATCH (r:Resource {name: $name})
            SET r.labels = $labels, r.last_synced = datetime()
            """,
            name=asset_name,
            labels=labels,
        )

    elif change_type == "service_account_change":
        new_sa = _extract_sa(data)
        prior_sa = _extract_sa(
            change.get("prior_asset", {}).get("resource", {}).get("data", {})
        )

        if prior_sa:
            await session.run(
                """
                MATCH (r:Resource {name: $name})-[rel:USES_SERVICE_ACCOUNT]->
                      (sa:ServiceAccount {email: $sa})
                DELETE rel
                """,
                name=asset_name,
                sa=prior_sa,
            )
        if new_sa:
            await session.run(
                """
                MATCH (r:Resource {name: $name})
                MERGE (sa:ServiceAccount {email: $sa})
                MERGE (r)-[:USES_SERVICE_ACCOUNT]->(sa)
                SET r.last_synced = datetime()
                """,
                name=asset_name,
                sa=new_sa,
            )

    elif change_type == "firewall_rule_change":
        source_ranges = data.get("sourceRanges", [])
        allowed = data.get("allowed", [])
        await session.run(
            """
            MATCH (f:FirewallRule {name: $name})
            SET f.source_ranges = $source_ranges,
                f.allowed = $allowed,
                f.disabled = $disabled,
                f.last_synced = datetime()
            """,
            name=asset_name,
            source_ranges=source_ranges,
            allowed=str(allowed),
            disabled=data.get("disabled", False),
        )

    elif change_type == "network_interface_change":
        ifaces = data.get("networkInterfaces", [])
        has_external_ip = any(
            ac for iface in ifaces for ac in iface.get("accessConfigs", [])
        )
        await session.run(
            """
            MATCH (r:Resource {name: $name})
            SET r.has_external_ip = $has_external_ip, r.last_synced = datetime()
            """,
            name=asset_name,
            has_external_ip=has_external_ip,
        )


async def handle_iam_change(change: dict, session: AsyncSession) -> None:
    """
    Updates IAM binding edges in the graph when a policy changes.
    Removes stale GRANTED_BY edges and adds new ones.
    """
    asset = change.get("updated_asset", {})
    prior = change.get("prior_asset", {})
    asset_name = change.get("asset_name", "")

    current_bindings = _extract_bindings(asset.get("iamPolicy", {}))
    prior_bindings = _extract_bindings(prior.get("iamPolicy", {})) if prior else set()

    added = current_bindings - prior_bindings
    removed = prior_bindings - current_bindings

    for role, member in removed:
        await session.run(
            """
            MATCH (:Identity {name: $member})-[rel:GRANTED_BY {role: $role}]->
                  (:Resource {name: $resource})
            DELETE rel
            """,
            member=member,
            role=role,
            resource=asset_name,
        )

    for role, member in added:
        await session.run(
            """
            MATCH (r:Resource {name: $resource})
            MERGE (i:Identity {name: $member})
            MERGE (i)-[:GRANTED_BY {role: $role}]->(r)
            SET r.last_synced = datetime()
            """,
            member=member,
            role=role,
            resource=asset_name,
        )


async def handle_relationship_change(change: dict, session: AsyncSession) -> None:
    """
    Updates network and SA attachment edges for relationship changes.
    """
    asset = change.get("updated_asset", {})
    asset_name = change.get("asset_name", "")
    change_type = change["change_type"]

    related_assets = asset.get("relatedAssets", [])
    for related in related_assets:
        rel_type = related.get("relationshipType", "")
        related_name = related.get("asset", "")

        if rel_type == "INSTANCE_TO_SUBNETWORK":
            await session.run(
                """
                MATCH (i:Resource {name: $instance})
                MERGE (s:Resource {name: $subnet})
                MERGE (i)-[:HOSTED_BY]->(s)
                SET i.last_synced = datetime()
                """,
                instance=asset_name,
                subnet=related_name,
            )
        elif rel_type == "INSTANCE_TO_SERVICEACCOUNT":
            await session.run(
                """
                MATCH (i:Resource {name: $instance})
                MERGE (sa:ServiceAccount {email: $sa})
                MERGE (i)-[:USES_SERVICE_ACCOUNT]->(sa)
                SET i.last_synced = datetime()
                """,
                instance=asset_name,
                sa=related_name,
            )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

async def _handle_deletion(asset_name: str, session: AsyncSession) -> None:
    """Marks a resource as DELETED in the graph and removes its edges."""
    await session.run(
        """
        MATCH (r:Resource {name: $name})
        SET r.status = 'DELETED', r.last_synced = datetime()
        WITH r
        OPTIONAL MATCH (r)-[rel]-()
        DELETE rel
        """,
        name=asset_name,
    )


def _extract_sa(resource_data: dict) -> str | None:
    sa = resource_data.get("serviceAccount")
    if sa:
        return sa
    sa_list = resource_data.get("serviceAccounts", [])
    return sa_list[0].get("email") if sa_list else None


def _extract_bindings(iam_policy: dict) -> set[tuple[str, str]]:
    result = set()
    for binding in iam_policy.get("bindings", []):
        role = binding.get("role", "")
        for member in binding.get("members", []):
            result.add((role, member))
    return result

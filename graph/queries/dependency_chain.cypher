// dependency_chain.cypher
//
// Answers: "what does this resource depend on, and who else shares those dependencies?"
//
// Used by the plan agent before generating a remediation plan to understand:
//   1. What upstream services the target relies on (patching may disrupt them)
//   2. Whether the target is hosted on shared infrastructure (node, MIG)
//   3. Which other resources would be co-affected if a shared dependency is touched
//
// Parameters:
//   $asset_name  — full GCP resource name of the vulnerable asset
//   $max_hops    — traversal depth (default 3, pass as parameter or hardcode below)
//
// ─────────────────────────────────────────────────────────────────────────────
// PART 1 — Upstream dependency chain
// Returns every upstream resource this asset transitively depends on,
// the relationship path that connects them, and their criticality signals.
// ─────────────────────────────────────────────────────────────────────────────

MATCH path = (target:Resource {asset_name: $asset_name})
             -[:DEPENDS_ON|HOSTED_BY|USES_SERVICE_ACCOUNT*1..3]->
             (upstream:Resource)
RETURN
  upstream.asset_name                                            AS name,
  upstream.asset_type                                           AS asset_type,
  upstream.short_name                                           AS short_name,
  upstream.env                                                  AS env,
  upstream.team                                                 AS team,
  upstream.data_class                                           AS data_class,
  upstream.status                                               AS status,
  upstream.dormancy_score                                       AS dormancy_score,
  length(path)                                                  AS depth,
  [r IN relationships(path) | type(r)]                         AS relationship_types,
  [r IN relationships(path) | r.dependency_type]               AS dependency_subtypes,
  CASE
    WHEN upstream.env = 'prod' OR upstream.data_class IN ['pii', 'restricted']
      THEN 'HIGH'
    WHEN upstream.env = 'staging'
      THEN 'MEDIUM'
    ELSE 'LOW'
  END                                                           AS upstream_criticality
ORDER BY depth ASC, upstream_criticality DESC;

// ─────────────────────────────────────────────────────────────────────────────
// PART 2 — Shared dependency exposure
// Finds other in-scope resources that share the same upstream dependencies
// as the target. If patching the target also touches a shared component
// (e.g. a managed instance group, a shared Cloud SQL instance, a common
// service account), these siblings may be affected.
// ─────────────────────────────────────────────────────────────────────────────

MATCH (target:Resource {asset_name: $asset_name})
      -[:DEPENDS_ON|HOSTED_BY*1..2]->
      (shared:Resource)
MATCH (sibling:Resource)-[:DEPENDS_ON|HOSTED_BY]->(shared)
WHERE sibling.asset_name <> $asset_name
  AND sibling.in_scope = true
RETURN
  shared.asset_name                                            AS shared_dependency,
  shared.asset_type                                           AS shared_type,
  shared.env                                                  AS shared_env,
  collect(DISTINCT sibling.asset_name)[..10]                  AS co_dependents,
  count(DISTINCT sibling)                                     AS co_dependent_count,
  collect(DISTINCT sibling.team)[..5]                         AS affected_teams
ORDER BY co_dependent_count DESC
LIMIT 20;

// ─────────────────────────────────────────────────────────────────────────────
// PART 3 — Service account privilege chain
// Traces the service account(s) used by the target and what those accounts
// can reach. Relevant when a patch requires restarting a workload — the SA
// must still have the required permissions after the change.
// ─────────────────────────────────────────────────────────────────────────────

MATCH (target:Resource {asset_name: $asset_name})
      -[:USES_SERVICE_ACCOUNT]->(sa:Resource)
MATCH (sa)-[:GRANTS_ACCESS_TO]->(reachable:Resource)
RETURN
  sa.asset_name                                               AS service_account,
  sa.short_name                                               AS sa_email,
  collect(DISTINCT reachable.asset_name)[..20]               AS resources_accessible,
  count(DISTINCT reachable)                                   AS accessible_count,
  collect(DISTINCT reachable.env)[..5]                       AS accessible_envs
ORDER BY accessible_count DESC;

// Find principals that have access to both the vulnerable resource and prod resources
MATCH (vuln:Resource {asset_name: $asset_name})<-[:GRANTS_ACCESS_TO]-(sa:Resource)
MATCH (sa)-[:GRANTS_ACCESS_TO]->(prod:Resource {env: "prod"})
WHERE prod.asset_name <> $asset_name
RETURN sa.asset_name AS service_account,
       collect(DISTINCT prod.asset_name) AS reachable_prod_resources,
       count(DISTINCT prod) AS prod_blast_count

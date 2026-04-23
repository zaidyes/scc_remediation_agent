// Find all resources reachable from a vulnerable resource within 3 hops
MATCH path = (vuln:Resource {asset_name: $asset_name})-
  [:CONNECTS_TO|ROUTES_TRAFFIC_TO|DEPENDS_ON|GRANTS_ACCESS_TO*1..3]->(downstream:Resource)
WHERE downstream.in_scope = true
RETURN downstream.asset_name AS name,
       downstream.env AS env,
       downstream.data_class AS data_class,
       length(path) AS hops,
       [r in relationships(path) | type(r)] AS relationship_types
ORDER BY hops ASC, downstream.env DESC

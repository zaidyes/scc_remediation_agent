// Resource → Project
(:Resource)-[:BELONGS_TO]->(:Project)

// Finding → Resource
(:Finding)-[:AFFECTS]->(:Resource)

// Resource ↔ Resource (Network / Hierarchy)
(:Resource)-[:CONNECTS_TO {
  protocol: String,
  port: String,
  direction: String,
  firewall_rule: String
}]->(:Resource)

(:Resource)-[:ROUTES_TRAFFIC_TO]->(:Resource)

(:Resource)-[:DEPENDS_ON {
  dependency_type: String
}]->(:Resource)

(:Resource)-[:HOSTED_BY]->(:Resource)

// IAM relationships
(:Resource)-[:GRANTS_ACCESS_TO {
  role: String,
  principal: String,
  principal_type: String
}]->(:Resource)

(:Resource)-[:USES_SERVICE_ACCOUNT {
  email: String
}]->(:Resource)

// Constraints — run once at setup
CREATE CONSTRAINT resource_name IF NOT EXISTS
  FOR (r:Resource) REQUIRE r.asset_name IS UNIQUE;

CREATE CONSTRAINT finding_id IF NOT EXISTS
  FOR (f:Finding) REQUIRE f.finding_id IS UNIQUE;

CREATE CONSTRAINT project_id IF NOT EXISTS
  FOR (p:Project) REQUIRE p.project_id IS UNIQUE;

// Indexes for performance
CREATE INDEX resource_env IF NOT EXISTS FOR (r:Resource) ON (r.env);
CREATE INDEX resource_project IF NOT EXISTS FOR (r:Resource) ON (r.project);
CREATE INDEX resource_in_scope IF NOT EXISTS FOR (r:Resource) ON (r.in_scope);
CREATE INDEX resource_dormancy IF NOT EXISTS FOR (r:Resource) ON (r.dormancy_score);
CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity);
CREATE INDEX finding_state IF NOT EXISTS FOR (f:Finding) ON (f.state);
CREATE INDEX finding_exposure IF NOT EXISTS FOR (f:Finding) ON (f.attack_exposure_score);

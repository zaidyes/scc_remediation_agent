MATCH (r:Resource {asset_name: $asset_name})
RETURN r.dormancy_score AS dormancy_score,
       r.last_activity AS last_activity,
       r.status AS status,
       CASE
         WHEN r.dormancy_score > 0.8 THEN "DORMANT"
         WHEN r.dormancy_score > 0.4 THEN "PERIODIC"
         ELSE "ACTIVE"
       END AS dormancy_class

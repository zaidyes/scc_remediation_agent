"""
One-time setup: creates three Cloud Asset Inventory feeds at org level.

Run once during agent onboarding:
  python -m infrastructure.setup_feeds --org-id ORG_ID --project-id PROJECT_ID

All three feeds publish to the same `asset-change-events` Pub/Sub topic.
The event processor (graph/events/processor.py) handles the messages.
"""
import argparse

from google.cloud import asset_v1

# Asset types monitored for resource and IAM changes
_RESOURCE_ASSET_TYPES = [
    "compute.googleapis.com/Instance",
    "compute.googleapis.com/Disk",
    "compute.googleapis.com/Firewall",
    "compute.googleapis.com/Network",
    "compute.googleapis.com/Subnetwork",
    "container.googleapis.com/Cluster",
    "run.googleapis.com/Service",
    "cloudfunctions.googleapis.com/CloudFunction",
    "storage.googleapis.com/Bucket",
    "iam.googleapis.com/ServiceAccount",
    "cloudresourcemanager.googleapis.com/Project",
    "cloudresourcemanager.googleapis.com/Folder",
    "sqladmin.googleapis.com/Instance",
]

_IAM_ASSET_TYPES = [
    "compute.googleapis.com/Instance",
    "storage.googleapis.com/Bucket",
    "bigquery.googleapis.com/Dataset",
    "container.googleapis.com/Cluster",
    "cloudresourcemanager.googleapis.com/Project",
    "iam.googleapis.com/ServiceAccount",
]

# Relationship types with the highest signal for remediation safety
_RELATIONSHIP_ASSET_TYPES = [
    "compute.googleapis.com/Instance",
    "compute.googleapis.com/Network",
    "compute.googleapis.com/Subnetwork",
    "container.googleapis.com/Cluster",
]

_FEEDS = [
    {
        "feed_id": "scc-agent-resource-changes",
        "content_type": asset_v1.ContentType.RESOURCE,
        "asset_types": _RESOURCE_ASSET_TYPES,
        "description": "SCC agent: resource state changes for graph updates",
    },
    {
        "feed_id": "scc-agent-iam-changes",
        "content_type": asset_v1.ContentType.IAM_POLICY,
        "asset_types": _IAM_ASSET_TYPES,
        "description": "SCC agent: IAM policy changes for approval invalidation",
    },
    {
        "feed_id": "scc-agent-relationship-changes",
        "content_type": asset_v1.ContentType.RELATIONSHIP,
        "asset_types": _RELATIONSHIP_ASSET_TYPES,
        "description": "SCC agent: network/SA relationship changes",
    },
]


def setup_feeds(org_id: str, project_id: str, topic_name: str = "asset-change-events") -> None:
    client = asset_v1.AssetServiceClient()
    parent = f"organizations/{org_id}"
    topic = f"projects/{project_id}/topics/{topic_name}"

    for feed_def in _FEEDS:
        feed_name = f"{parent}/feeds/{feed_def['feed_id']}"

        # Check if feed already exists
        try:
            existing = client.get_feed(name=feed_name)
            print(f"  [skip] Feed already exists: {feed_def['feed_id']}")
            continue
        except Exception:
            pass  # Does not exist — create it

        feed = asset_v1.Feed(
            name=feed_name,
            asset_types=feed_def["asset_types"],
            content_type=feed_def["content_type"],
            feed_output_config=asset_v1.FeedOutputConfig(
                pubsub_destination=asset_v1.PubsubDestination(topic=topic)
            ),
        )

        client.create_feed(
            request=asset_v1.CreateFeedRequest(
                parent=parent,
                feed_id=feed_def["feed_id"],
                feed=feed,
            )
        )
        print(f"  [created] {feed_def['feed_id']} → {topic}")

    print("Feed setup complete.")


def teardown_feeds(org_id: str) -> None:
    """Removes all three feeds. Use during offboarding."""
    client = asset_v1.AssetServiceClient()
    parent = f"organizations/{org_id}"

    for feed_def in _FEEDS:
        feed_name = f"{parent}/feeds/{feed_def['feed_id']}"
        try:
            client.delete_feed(name=feed_name)
            print(f"  [deleted] {feed_def['feed_id']}")
        except Exception as e:
            print(f"  [skip] Could not delete {feed_def['feed_id']}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Set up CAI feeds for SCC agent")
    parser.add_argument("--org-id", required=True)
    parser.add_argument("--project-id", required=True, help="Project that hosts the Pub/Sub topic")
    parser.add_argument("--topic", default="asset-change-events")
    parser.add_argument("--teardown", action="store_true", help="Remove feeds instead of creating")
    args = parser.parse_args()

    if args.teardown:
        teardown_feeds(args.org_id)
    else:
        setup_feeds(args.org_id, args.project_id, args.topic)

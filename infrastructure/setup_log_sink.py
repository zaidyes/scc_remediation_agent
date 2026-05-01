"""
One-time setup: creates a Cloud Logging sink that exports material audit
events to the `audit-change-events` Pub/Sub topic.

Run once during agent onboarding:
  python -m infrastructure.setup_log_sink --org-id ORG_ID --project-id PROJECT_ID
"""
import argparse

import google.auth
import google.auth.impersonated_credentials
from google.cloud import logging_v2
from google.cloud.logging_v2.services.config_service_v2 import ConfigServiceV2Client
from google.cloud.logging_v2.types import LogSink

# Exact filter from addendum §3.2 — captures the audit events that matter
# for remediation safety without flooding on unrelated write operations.
_SINK_FILTER = """\
(
  resource.type="gce_instance"
  AND (
    protoPayload.methodName="v1.compute.instances.setIamPolicy"
    OR protoPayload.methodName="v1.compute.instances.start"
    OR protoPayload.methodName="v1.compute.instances.stop"
    OR protoPayload.methodName="beta.compute.instances.setMetadata"
    OR protoPayload.methodName="v1.compute.firewalls.patch"
    OR protoPayload.methodName="v1.compute.firewalls.insert"
    OR protoPayload.methodName="v1.compute.firewalls.delete"
  )
)
OR (
  resource.type="service_account"
  AND protoPayload.methodName:"SetIamPolicy"
)
OR (
  protoPayload.methodName="SetIamPolicy"
  AND protoPayload.resourceName=~"projects/.*"
)"""

_SINK_NAME = "scc-agent-audit-events"


def _make_client(impersonate_sa: str | None) -> ConfigServiceV2Client:
    if not impersonate_sa:
        return ConfigServiceV2Client()
    source, _ = google.auth.default()
    creds = google.auth.impersonated_credentials.Credentials(
        source_credentials=source,
        target_principal=impersonate_sa,
        target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    return ConfigServiceV2Client(credentials=creds)


def setup_log_sink(
    org_id: str,
    project_id: str,
    topic_name: str = "audit-change-events",
    impersonate_sa: str | None = None,
) -> None:
    client = _make_client(impersonate_sa)
    parent = f"organizations/{org_id}"
    destination = f"pubsub.googleapis.com/projects/{project_id}/topics/{topic_name}"

    # Check if sink already exists
    try:
        existing = client.get_sink(sink_name=f"{parent}/sinks/{_SINK_NAME}")
        print(f"  [skip] Log sink already exists: {_SINK_NAME}")
        print(f"         Destination: {existing.destination}")
        return
    except Exception:
        pass

    sink = LogSink(
        name=_SINK_NAME,
        destination=destination,
        filter=_SINK_FILTER,
        include_children=True,   # captures logs from all projects in the org
        description="SCC remediation agent — material audit events for approval invalidation",
    )

    created = client.create_sink(
        request={
            "parent": parent,
            "sink": sink,
            "unique_writer_identity": True,
        }
    )

    print(f"  [created] {_SINK_NAME} → {destination}")
    print(f"  [action]  Grant the sink's writer SA publish rights on the topic:")
    print(f"            gcloud pubsub topics add-iam-policy-binding {topic_name} \\")
    print(f"              --project={project_id} \\")
    print(f"              --member='{created.writer_identity}' \\")
    print(f"              --role='roles/pubsub.publisher'")
    print("Log sink setup complete.")


def teardown_log_sink(org_id: str, impersonate_sa: str | None = None) -> None:
    client = _make_client(impersonate_sa)
    try:
        client.delete_sink(sink_name=f"organizations/{org_id}/sinks/{_SINK_NAME}")
        print(f"  [deleted] {_SINK_NAME}")
    except Exception as e:
        print(f"  [skip] Could not delete sink: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Set up audit log sink for SCC agent")
    parser.add_argument("--org-id", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--topic", default="audit-change-events")
    parser.add_argument("--teardown", action="store_true")
    parser.add_argument(
        "--impersonate-service-account",
        metavar="SA_EMAIL",
        default=None,
        help="Run as this service account (e.g. scc-remediation-agent@PROJECT.iam.gserviceaccount.com). "
             "Your ADC must have roles/iam.serviceAccountTokenCreator on the SA.",
    )
    args = parser.parse_args()

    if args.teardown:
        teardown_log_sink(args.org_id, args.impersonate_service_account)
    else:
        setup_log_sink(args.org_id, args.project_id, args.topic, args.impersonate_service_account)

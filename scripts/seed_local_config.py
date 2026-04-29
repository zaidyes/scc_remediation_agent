"""
Writes a minimal dry-run CustomerConfig to Firestore for local testing.

Usage:
    python scripts/seed_local_config.py --org-id 123456789 [--project-ids p1,p2]

The config is written to /customer_configs/local-test (or --customer-id).
All projects in the org are included by default; pass --project-ids to narrow scope.
dry_run is always True — this script is for local testing only.
"""
import argparse
import os
import sys

# Allow running from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def main():
    parser = argparse.ArgumentParser(description="Seed a local test CustomerConfig")
    parser.add_argument("--org-id", required=True, help="GCP org ID (numeric)")
    parser.add_argument("--customer-id", default="local-test")
    parser.add_argument(
        "--project-ids",
        help="Comma-separated project IDs to scope (default: all projects in org)",
        default="",
    )
    parser.add_argument(
        "--severity",
        default="HIGH_PLUS",
        choices=["CRITICAL_ONLY", "HIGH_PLUS", "MEDIUM_PLUS", "ALL"],
        help="Minimum severity threshold (default: HIGH_PLUS)",
    )
    args = parser.parse_args()

    project_ids = [p.strip() for p in args.project_ids.split(",") if p.strip()]

    config = {
        "customer_id": args.customer_id,
        "org_id": args.org_id,
        "display_name": f"Local test — org {args.org_id}",
        "dry_run": True,          # never changes real resources
        "severity_threshold": args.severity,
        "scope": {
            "project_ids": project_ids,   # empty = all projects in org
            "include_labels": [],
            "exclude_labels": [
                # Skip anything already tagged skip-remediation
                {"key": "skip-remediation", "value": "true"},
            ],
        },
        "approval_policy": {
            "tiers": [],
            "approvers": [],
            "default_maintenance_window": {
                "days_of_week": [1, 2, 3, 4, 5],
                "start_time_utc": "00:00",
                "end_time_utc": "23:59",   # wide window — dry run only
            },
        },
        "execution": {
            "enabled_modes": ["OS_PATCH", "FIREWALL", "IAM", "MISCONFIGURATION"],
        },
        "notifications": {},
        "policies": [],
        "version": 1,
    }

    try:
        from google.cloud import firestore
        db = firestore.Client()
    except Exception as e:
        print(f"Could not connect to Firestore: {e}", file=sys.stderr)
        print(
            "If using the emulator, ensure FIRESTORE_EMULATOR_HOST=localhost:8080 is set.",
            file=sys.stderr,
        )
        sys.exit(1)

    ref = db.collection("customer_configs").document(args.customer_id)
    ref.set(config)
    print(f"Config written to customer_configs/{args.customer_id}")
    print(f"  org_id      : {args.org_id}")
    print(f"  project_ids : {project_ids or '(all projects in org)'}")
    print(f"  severity    : {args.severity}")
    print(f"  dry_run     : True")
    print()
    print(f"Run the agent with:")
    print(f"  python -m app --customer-id {args.customer_id}")
    print(f"  # or:")
    print(f"  scc-agent run --customer-id {args.customer_id}")


if __name__ == "__main__":
    main()

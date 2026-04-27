"""
Rollback artifact creation and execution.

Every remediation type has a machine-executable rollback artifact stored on
the Firestore approval record before execution begins. The /api/rollback/{id}
endpoint calls execute_rollback() to run it.

Rollback artifacts are available for 24 hours after execution.
"""
import json
import datetime
import subprocess

from google.cloud import compute_v1, firestore, storage


async def create_snapshot_artifact(
    approval_id: str,
    asset_name: str,
    project_id: str,
) -> dict:
    """
    Creates a disk snapshot before an OS patch job executes.
    Stores the snapshot name and restore command on the approval record.

    Returns the artifact dict. Raises RuntimeError if snapshot creation fails
    (quota exceeded, disk too large) — this is a BLOCK condition.
    """
    compute = compute_v1.InstancesClient()
    disks_client = compute_v1.DisksClient()
    snapshots_client = compute_v1.SnapshotsClient()

    # Extract instance details from asset_name
    # asset_name format: //compute.googleapis.com/projects/{p}/zones/{z}/instances/{i}
    parts = asset_name.replace("//compute.googleapis.com/", "").split("/")
    zone = parts[parts.index("zones") + 1]
    instance_name = parts[parts.index("instances") + 1]

    # Get the instance's boot disk
    instance = compute.get(project=project_id, zone=zone, instance=instance_name)
    boot_disk = next(
        (d for d in instance.disks if d.boot),
        instance.disks[0] if instance.disks else None,
    )
    if boot_disk is None:
        raise RuntimeError(f"No disk found on instance {instance_name}")

    disk_name = boot_disk.source.split("/")[-1]
    snapshot_name = f"rollback-{approval_id[:8]}-{disk_name}"[:63]

    # Create snapshot
    snapshot_body = compute_v1.Snapshot(
        name=snapshot_name,
        source_disk=f"projects/{project_id}/zones/{zone}/disks/{disk_name}",
        description=f"Pre-patch rollback snapshot for approval {approval_id}",
        labels={"created-by": "scc-agent", "approval-id": approval_id[:32]},
    )
    operation = snapshots_client.insert(project=project_id, snapshot_resource=snapshot_body)
    operation.result(timeout=300)  # wait up to 5 min

    restore_command = (
        f"gcloud compute disks create {disk_name}-restored "
        f"--source-snapshot={snapshot_name} "
        f"--project={project_id} --zone={zone}"
    )

    artifact = {
        "type": "SNAPSHOT",
        "snapshot_name": snapshot_name,
        "disk_name": disk_name,
        "zone": zone,
        "project_id": project_id,
        "restore_command": restore_command,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "expires_at": (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).isoformat(),
    }

    _store_rollback_artifact(approval_id, artifact)
    return artifact


async def export_firewall_artifact(
    approval_id: str,
    firewall_rule_name: str,
    project_id: str,
    gcs_bucket: str,
) -> dict:
    """
    Exports the current firewall rule configuration to GCS before modification.
    Stores the GCS path and import command on the approval record.
    """
    compute = compute_v1.FirewallsClient()
    rule = compute.get(project=project_id, firewall=firewall_rule_name)

    rule_data = {
        "name": rule.name,
        "description": rule.description,
        "network": rule.network,
        "priority": rule.priority,
        "direction": rule.direction,
        "allowed": [{"IPProtocol": a.I_p_protocol, "ports": list(a.ports)} for a in rule.allowed],
        "denied": [{"IPProtocol": d.I_p_protocol, "ports": list(d.ports)} for d in rule.denied],
        "sourceRanges": list(rule.source_ranges),
        "targetTags": list(rule.target_tags),
        "disabled": rule.disabled,
        "logConfig": {"enable": rule.log_config.enable} if rule.log_config else {},
    }

    gcs_path = f"rollbacks/{approval_id}/{firewall_rule_name}.json"
    storage_client = storage.Client(project=project_id)
    bucket = storage_client.bucket(gcs_bucket)
    blob = bucket.blob(gcs_path)
    blob.upload_from_string(json.dumps(rule_data, indent=2), content_type="application/json")

    restore_command = (
        f"gcloud compute firewall-rules import {firewall_rule_name} "
        f"--source=gs://{gcs_bucket}/{gcs_path} "
        f"--project={project_id}"
    )

    artifact = {
        "type": "FIREWALL_EXPORT",
        "firewall_rule_name": firewall_rule_name,
        "gcs_bucket": gcs_bucket,
        "gcs_path": gcs_path,
        "restore_command": restore_command,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "expires_at": (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).isoformat(),
    }

    _store_rollback_artifact(approval_id, artifact)
    return artifact


async def store_iam_restore_command(
    approval_id: str,
    project_id: str,
    member: str,
    role: str,
) -> dict:
    """
    Stores the exact `gcloud projects add-iam-policy-binding` command to
    restore the IAM binding that is about to be removed.
    """
    restore_command = (
        f"gcloud projects add-iam-policy-binding {project_id} "
        f"--member='{member}' "
        f"--role='{role}'"
    )

    artifact = {
        "type": "IAM_RESTORE",
        "project_id": project_id,
        "member": member,
        "role": role,
        "restore_command": restore_command,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "expires_at": (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).isoformat(),
    }

    _store_rollback_artifact(approval_id, artifact)
    return artifact


async def store_pr_rollback_artifact(
    approval_id: str,
    pr_url: str,
    repo: str,
    base_branch: str,
    pr_branch: str,
) -> dict:
    """
    Stores the PR revert command for Terraform-based remediations.
    The PR itself is the rollback artifact — reverting it restores prior state.
    """
    restore_command = (
        f"gh pr revert --repo {repo} {pr_url.split('/')[-1]} "
        f"--base {base_branch}"
    )

    artifact = {
        "type": "PR_REVERT",
        "pr_url": pr_url,
        "repo": repo,
        "base_branch": base_branch,
        "pr_branch": pr_branch,
        "restore_command": restore_command,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "expires_at": (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).isoformat(),
    }

    _store_rollback_artifact(approval_id, artifact)
    return artifact


async def execute_rollback(approval_id: str) -> dict:
    """
    Reads the stored rollback artifact from Firestore and executes
    the restore command. Called by the /api/rollback/{approval_id} endpoint.

    Returns {"status": "SUCCESS"|"FAILED", "output": str, "artifact": dict}.
    """
    db = firestore.Client()
    doc = db.collection("approvals").document(approval_id).get()

    if not doc.exists:
        return {"status": "FAILED", "output": f"Approval {approval_id} not found", "artifact": None}

    data = doc.to_dict()
    artifact = data.get("rollback_artifact")

    if not artifact:
        return {"status": "FAILED", "output": "No rollback artifact found on approval record",
                "artifact": None}

    # Check expiry
    expires_at = datetime.datetime.fromisoformat(artifact["expires_at"])
    if datetime.datetime.utcnow() > expires_at:
        return {"status": "FAILED",
                "output": f"Rollback artifact expired at {artifact['expires_at']}",
                "artifact": artifact}

    restore_command = artifact.get("restore_command", "")
    if not restore_command:
        return {"status": "FAILED", "output": "Rollback artifact has no restore_command",
                "artifact": artifact}

    try:
        result = subprocess.run(
            restore_command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode == 0:
            # Mark rollback executed on the approval record
            db.collection("approvals").document(approval_id).update({
                "rollback_executed_at": firestore.SERVER_TIMESTAMP,
                "rollback_output": result.stdout[:2000],
                "status": "ROLLED_BACK",
            })
            return {"status": "SUCCESS", "output": result.stdout, "artifact": artifact}
        else:
            return {"status": "FAILED", "output": result.stderr, "artifact": artifact}

    except subprocess.TimeoutExpired:
        return {"status": "FAILED", "output": "Rollback command timed out after 5 minutes",
                "artifact": artifact}
    except Exception as e:
        return {"status": "FAILED", "output": str(e), "artifact": artifact}


# --------------------------------------------------------------------------- #
# Internal helper
# --------------------------------------------------------------------------- #

def _store_rollback_artifact(approval_id: str, artifact: dict) -> None:
    db = firestore.Client()
    db.collection("approvals").document(approval_id).update({
        "rollback_artifact": artifact,
    })

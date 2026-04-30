"""
Direct IAM execution tools for the SCC Remediation Agent.

These tools call the Cloud Resource Manager API directly (not via gcloud CLI)
to add or remove IAM bindings. Used for IAM findings where blast_level=LOW
and the customer has explicitly enabled direct API execution.

Default posture (from spec §7, table item 4):
  "Default to PR (safer); direct API only if explicitly enabled and
   blast_level = LOW"

The command_compiler / plan_agent path generates gcloud commands (which result
in a Terraform PR or a reviewed shell command). This module is the alternative
fast path — it is only invoked when:
  1. config.execution.enabled_modes includes RemediationMode.IAM, AND
  2. blast_level == "LOW", AND
  3. the plan's remediation_type == "IAM"

All mutations log the pre-change policy snapshot to the caller so the rollback
plan can reference concrete bindings rather than recomputed state.
"""
import os
from typing import Optional


def get_project_iam_policy(project_id: str) -> dict:
    """
    Returns the current IAM policy for a GCP project as a dict.

    The returned dict has the shape:
        {
          "version": 1,
          "etag": "<etag>",
          "bindings": [
            {"role": "roles/viewer", "members": ["user:alice@example.com"]},
            ...
          ]
        }

    The etag must be passed back to set_project_iam_policy to guard against
    concurrent modifications (optimistic concurrency).
    """
    from googleapiclient import discovery  # type: ignore
    from google.auth import default as _ga_default  # type: ignore

    credentials, _ = _ga_default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    service = discovery.build("cloudresourcemanager", "v1",
                               credentials=credentials, cache_discovery=False)
    policy = service.projects().getIamPolicy(
        resource=project_id,
        body={"options": {"requestedPolicyVersion": 1}},
    ).execute()
    return policy


def remove_iam_binding(
    project_id: str,
    member: str,
    role: str,
    dry_run: bool = True,
) -> dict:
    """
    Removes a single IAM binding (member + role pair) from a GCP project.

    Args:
        project_id:  GCP project ID (e.g. "my-project-123").
        member:      IAM member string (e.g. "user:bob@example.com",
                     "serviceAccount:sa@project.iam.gserviceaccount.com").
        role:        IAM role (e.g. "roles/editor").
        dry_run:     If True, returns what would be changed without applying.

    Returns:
        Dict with keys:
            status      — "dry_run" | "success" | "not_found"
            member      — the member that was (or would be) removed
            role        — the role the member was removed from
            etag_before — etag of the policy before modification
            etag_after  — etag of the policy after modification (or None)
    """
    policy = get_project_iam_policy(project_id)
    etag_before = policy.get("etag", "")

    bindings = policy.get("bindings", [])
    original_member_count = sum(
        1 for b in bindings if b.get("role") == role and member in b.get("members", [])
    )

    if original_member_count == 0:
        return {
            "status":      "not_found",
            "member":      member,
            "role":        role,
            "etag_before": etag_before,
            "etag_after":  None,
        }

    if dry_run:
        return {
            "status":      "dry_run",
            "member":      member,
            "role":        role,
            "etag_before": etag_before,
            "etag_after":  None,
        }

    # Mutate the bindings list in-place
    updated_bindings = []
    for binding in bindings:
        if binding.get("role") == role:
            members = [m for m in binding.get("members", []) if m != member]
            if members:  # drop the entire binding entry if now empty
                updated_bindings.append({**binding, "members": members})
        else:
            updated_bindings.append(binding)

    policy["bindings"] = updated_bindings

    etag_after = _set_project_iam_policy(project_id, policy)
    return {
        "status":      "success",
        "member":      member,
        "role":        role,
        "etag_before": etag_before,
        "etag_after":  etag_after,
    }


def add_iam_binding(
    project_id: str,
    member: str,
    role: str,
    dry_run: bool = True,
) -> dict:
    """
    Adds a single IAM binding (member + role pair) to a GCP project.

    Used by the rollback path to restore a previously removed binding.
    In the forward execution path, the default recommendation is to create
    a Terraform PR rather than calling this function directly.

    Args:
        project_id:  GCP project ID.
        member:      IAM member string.
        role:        IAM role.
        dry_run:     If True, returns what would be changed without applying.

    Returns:
        Dict with keys: status, member, role, etag_before, etag_after.
    """
    policy = get_project_iam_policy(project_id)
    etag_before = policy.get("etag", "")

    # Check if already present
    for binding in policy.get("bindings", []):
        if binding.get("role") == role and member in binding.get("members", []):
            return {
                "status":      "already_present",
                "member":      member,
                "role":        role,
                "etag_before": etag_before,
                "etag_after":  None,
            }

    if dry_run:
        return {
            "status":      "dry_run",
            "member":      member,
            "role":        role,
            "etag_before": etag_before,
            "etag_after":  None,
        }

    bindings = policy.get("bindings", [])
    # Append to existing role binding if present, else create new entry
    for binding in bindings:
        if binding.get("role") == role:
            binding["members"].append(member)
            break
    else:
        bindings.append({"role": role, "members": [member]})

    policy["bindings"] = bindings
    etag_after = _set_project_iam_policy(project_id, policy)
    return {
        "status":      "success",
        "member":      member,
        "role":        role,
        "etag_before": etag_before,
        "etag_after":  etag_after,
    }


def _set_project_iam_policy(project_id: str, policy: dict) -> str:
    """
    Writes a modified IAM policy back to GCP. Returns the new etag.
    The policy dict must include the etag from the prior getIamPolicy call.
    """
    from googleapiclient import discovery  # type: ignore
    from google.auth import default as _ga_default  # type: ignore

    credentials, _ = _ga_default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    service = discovery.build("cloudresourcemanager", "v1",
                               credentials=credentials, cache_discovery=False)
    updated = service.projects().setIamPolicy(
        resource=project_id,
        body={"policy": policy},
    ).execute()
    return updated.get("etag", "")

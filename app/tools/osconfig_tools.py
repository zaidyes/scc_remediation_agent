from google.cloud import osconfig_v1

def create_patch_job(
    project_id: str,
    asset_name: str,
    cve_ids: list[str],
    config,
) -> str:
    """
    Creates a GCP OS Config patch job targeting the specific instance.
    Returns the patch job name.
    """
    client = osconfig_v1.OsConfigServiceClient()

    instance_filter = osconfig_v1.PatchInstanceFilter(
        instances=[asset_name]
    )

    patch_config = osconfig_v1.PatchConfig(
        reboot_config=osconfig_v1.PatchConfig.RebootConfig.DEFAULT,
        apt=osconfig_v1.AptSettings(
            type=osconfig_v1.AptSettings.Type.UPGRADE,
            excludes=[],
        ),
        yum=osconfig_v1.YumSettings(
            security=True,
            minimal=False,
        ),
        windows_update=osconfig_v1.WindowsUpdateSettings(
            classifications=[
                osconfig_v1.WindowsUpdateSettings.Classification.CRITICAL,
                osconfig_v1.WindowsUpdateSettings.Classification.SECURITY,
            ]
        ),
    )

    rollout = osconfig_v1.PatchRollout(
        mode=osconfig_v1.PatchRollout.Mode.ZONE_BY_ZONE,
        disruption_budget=osconfig_v1.FixedOrPercent(percent=50),
    )

    request = osconfig_v1.CreatePatchJobRequest(
        parent=f"projects/{project_id}",
        patch_job=osconfig_v1.PatchJob(
            display_name=f"scc-auto-patch-{cve_ids[0] if cve_ids else 'general'}",
            description=f"Automated patch by scc-remediation-agent. CVEs: {', '.join(cve_ids)}",
            instance_filter=instance_filter,
            patch_config=patch_config,
            rollout=rollout,
            dry_run=config.dry_run,
        )
    )

    try:
        job = client.create_patch_job(request=request)
        return job.name
    except Exception as e:
        print(f"Failed to create patch job: {e}")
        return ""

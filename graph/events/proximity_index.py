"""
Asset → approval reverse index stored in Firestore.

Inverts the blast-radius relationship: given an asset that just changed,
instantly find all pending approvals whose blast radius includes that asset.

Collection: /proximity_index/{sanitised_asset_name}
Document:   {asset_name: str, approval_ids: [str]}
"""
from google.cloud import firestore

_COLLECTION = "proximity_index"
_MAX_DOC_ID_LENGTH = 500


def _sanitise(asset_name: str) -> str:
    """Converts an asset name to a valid Firestore document ID."""
    sanitised = asset_name.replace("/", "_").replace(".", "_").replace(":", "_")
    return sanitised[:_MAX_DOC_ID_LENGTH]


def index_approval(
    approval_id: str,
    target_asset: str,
    blast_radius_assets: list[str],
) -> None:
    """
    Registers an approval in the index for the target asset and every asset
    in its blast radius. Called when an approval record is created.
    """
    db = firestore.Client()
    all_assets = list({target_asset} | set(blast_radius_assets))

    batch = db.batch()
    for asset in all_assets:
        doc_ref = db.collection(_COLLECTION).document(_sanitise(asset))
        batch.set(
            doc_ref,
            {
                "asset_name": asset,
                "approval_ids": firestore.ArrayUnion([approval_id]),
            },
            merge=True,
        )
    batch.commit()


def deindex_approval(
    approval_id: str,
    target_asset: str,
    blast_radius_assets: list[str],
) -> None:
    """
    Removes an approval from the index. Called when an approval reaches any
    terminal state (approved, rejected, executed, invalidated, blocked).
    """
    db = firestore.Client()
    all_assets = list({target_asset} | set(blast_radius_assets))

    batch = db.batch()
    for asset in all_assets:
        doc_ref = db.collection(_COLLECTION).document(_sanitise(asset))
        batch.set(
            doc_ref,
            {"approval_ids": firestore.ArrayRemove([approval_id])},
            merge=True,
        )
    batch.commit()


def get_affected_approvals(asset_name: str) -> list[str]:
    """
    Returns all approval IDs whose blast radius includes the given asset.
    O(1) Firestore lookup.
    """
    db = firestore.Client()
    doc = db.collection(_COLLECTION).document(_sanitise(asset_name)).get()
    if not doc.exists:
        return []
    return doc.to_dict().get("approval_ids", [])


def cleanup_stale_entries() -> int:
    """
    Removes approval IDs from the index where the approval no longer exists
    in Firestore. Intended to run as a daily maintenance job.

    Returns the number of stale entries removed.
    """
    db = firestore.Client()
    removed = 0

    docs = db.collection(_COLLECTION).stream()
    for doc in docs:
        data = doc.to_dict()
        approval_ids = data.get("approval_ids", [])
        if not approval_ids:
            doc.reference.delete()
            continue

        stale = []
        for approval_id in approval_ids:
            approval_doc = db.collection("approvals").document(approval_id).get()
            if not approval_doc.exists:
                stale.append(approval_id)

        if stale:
            doc.reference.update(
                {"approval_ids": firestore.ArrayRemove(stale)}
            )
            removed += len(stale)

    return removed

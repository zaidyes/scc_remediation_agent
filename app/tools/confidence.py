"""
Confidence score computation for autonomous execution tier routing.

The score (0.0–1.0) represents how safe it is to execute a remediation
without human review. It feeds directly into tier assignment in app/main.py.
"""


def compute_confidence_score(
    preflight_results: list[dict],
    blast_level: str,
    dormancy_class: str,
    historical_outcomes: list[dict],
    finding_class: str,
) -> float:
    """
    Returns a confidence score 0.0–1.0.

    preflight_results: list of {"check": str, "result": "PASS"|"WARN"|"BLOCK"}
    blast_level:       "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    dormancy_class:    "ACTIVE" | "PERIODIC" | "DORMANT"
    historical_outcomes: list of {"outcome": "SUCCESS"|"FAILURE", ...}
                         for similar remediations in this environment
    finding_class:     SCC finding class, e.g. "VULNERABILITY", "MISCONFIGURATION"
    """
    score = 1.0

    # --- Pre-flight penalties ------------------------------------------------
    block_count = sum(1 for r in preflight_results if r.get("result") == "BLOCK")
    warn_count = sum(1 for r in preflight_results if r.get("result") == "WARN")

    if block_count > 0:
        return 0.0  # hard floor — any BLOCK means zero confidence

    score -= warn_count * 0.15  # each WARN reduces confidence by 15%

    # --- Blast radius penalties ----------------------------------------------
    blast_penalties = {
        "LOW": 0.0,
        "MEDIUM": 0.15,
        "HIGH": 0.40,
        "CRITICAL": 0.70,
    }
    score -= blast_penalties.get(blast_level, 0.40)

    # --- Dormancy bonus ------------------------------------------------------
    # Dormant resources are lower risk — fewer active dependencies
    if dormancy_class == "DORMANT":
        score = min(1.0, score + 0.10)

    # --- Historical outcomes blend ------------------------------------------
    # Weight: 70% rule-based score, 30% observed success rate in this environment
    if historical_outcomes:
        success_rate = sum(
            1 for o in historical_outcomes if o.get("outcome") == "SUCCESS"
        ) / len(historical_outcomes)
        score = (score * 0.70) + (success_rate * 0.30)

    return round(max(0.0, min(1.0, score)), 3)

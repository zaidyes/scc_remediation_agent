"""
Unit tests for app/tools/confidence.py — compute_confidence_score().

All inputs are constructed in-process; no mocks needed (pure function).
"""
import pytest
from app.tools.confidence import compute_confidence_score


def _score(
    preflight=None,
    blast_level="LOW",
    dormancy_class="ACTIVE",
    historical=None,
    finding_class="VULNERABILITY",
):
    return compute_confidence_score(
        preflight_results=preflight or [],
        blast_level=blast_level,
        dormancy_class=dormancy_class,
        historical_outcomes=historical or [],
        finding_class=finding_class,
    )


# ---------------------------------------------------------------------------
# Hard floor: any BLOCK → 0.0
# ---------------------------------------------------------------------------

def test_block_returns_zero():
    assert _score(preflight=[{"check": "freeze", "result": "BLOCK"}]) == 0.0

def test_block_ignores_blast_level():
    assert _score(
        preflight=[{"check": "freeze", "result": "BLOCK"}],
        blast_level="LOW",
    ) == 0.0

def test_multiple_blocks_still_zero():
    preflight = [
        {"check": "freeze", "result": "BLOCK"},
        {"check": "maintenance", "result": "BLOCK"},
    ]
    assert _score(preflight=preflight) == 0.0


# ---------------------------------------------------------------------------
# Pre-flight WARN penalties (−0.15 each)
# ---------------------------------------------------------------------------

def test_no_warns_no_penalty():
    assert _score() == 1.0

def test_one_warn_reduces_by_15():
    result = _score(preflight=[{"check": "traffic", "result": "WARN"}])
    assert result == pytest.approx(0.85, abs=0.001)

def test_two_warns_reduce_by_30():
    preflight = [{"check": "x", "result": "WARN"}] * 2
    result = _score(preflight=preflight)
    assert result == pytest.approx(0.70, abs=0.001)

def test_pass_results_ignored():
    preflight = [{"check": "x", "result": "PASS"}, {"check": "y", "result": "PASS"}]
    assert _score(preflight=preflight) == 1.0


# ---------------------------------------------------------------------------
# Blast radius penalties
# ---------------------------------------------------------------------------

def test_low_blast_no_penalty():
    assert _score(blast_level="LOW") == 1.0

def test_medium_blast_penalty():
    result = _score(blast_level="MEDIUM")
    assert result == pytest.approx(0.85, abs=0.001)

def test_high_blast_penalty():
    result = _score(blast_level="HIGH")
    assert result == pytest.approx(0.60, abs=0.001)

def test_critical_blast_penalty():
    result = _score(blast_level="CRITICAL")
    assert result == pytest.approx(0.30, abs=0.001)

def test_unknown_blast_level_treated_as_high():
    result = _score(blast_level="UNKNOWN")
    assert result == pytest.approx(0.60, abs=0.001)


# ---------------------------------------------------------------------------
# Dormancy bonus (+0.10 for DORMANT, capped at 1.0)
# ---------------------------------------------------------------------------

def test_dormant_adds_bonus():
    result = _score(blast_level="MEDIUM", dormancy_class="DORMANT")
    # 1.0 - 0.15 (MEDIUM) + 0.10 (DORMANT) = 0.95
    assert result == pytest.approx(0.95, abs=0.001)

def test_dormant_bonus_capped_at_one():
    result = _score(blast_level="LOW", dormancy_class="DORMANT")
    assert result == 1.0  # min(1.0, 1.0 + 0.10)

def test_active_dormancy_no_bonus():
    assert _score(dormancy_class="ACTIVE") == 1.0

def test_periodic_dormancy_no_bonus():
    assert _score(dormancy_class="PERIODIC") == 1.0


# ---------------------------------------------------------------------------
# Historical outcome blending (70/30 split)
# ---------------------------------------------------------------------------

def test_perfect_historical_record_no_change():
    # Rule-based=1.0, history=1.0 → 0.70*1.0 + 0.30*1.0 = 1.0
    historical = [{"outcome": "SUCCESS"}] * 10
    assert _score(historical=historical) == 1.0

def test_zero_success_rate_pulls_score_down():
    historical = [{"outcome": "FAILURE"}] * 5
    # rule=1.0 → 0.70*1.0 + 0.30*0.0 = 0.70
    result = _score(historical=historical)
    assert result == pytest.approx(0.70, abs=0.001)

def test_50_pct_history_blended():
    historical = [{"outcome": "SUCCESS"}, {"outcome": "FAILURE"}]
    # rule=1.0 → 0.70*1.0 + 0.30*0.5 = 0.85
    result = _score(historical=historical)
    assert result == pytest.approx(0.85, abs=0.001)

def test_empty_history_uses_rule_based_only():
    assert _score(historical=[], blast_level="LOW") == 1.0


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

def test_combined_warn_high_blast():
    # 1.0 - 0.15 (WARN) - 0.40 (HIGH) = 0.45
    result = _score(
        preflight=[{"check": "x", "result": "WARN"}],
        blast_level="HIGH",
    )
    assert result == pytest.approx(0.45, abs=0.001)

def test_floor_is_zero():
    # 2 WARNs (-0.30) + CRITICAL (-0.70) = -0.0 → clamped to 0.0
    result = _score(
        preflight=[{"check": "x", "result": "WARN"}] * 2,
        blast_level="CRITICAL",
    )
    assert result == 0.0

def test_result_is_rounded_to_3dp():
    historical = [{"outcome": "SUCCESS"}] * 2 + [{"outcome": "FAILURE"}]
    # success_rate = 2/3 ≈ 0.6667
    # rule=1.0 → 0.70*1.0 + 0.30*(2/3) = 0.70 + 0.20 = 0.90
    result = _score(historical=historical)
    assert result == round(result, 3)

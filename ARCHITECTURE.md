# SCC Remediation Agent — Architecture

## Overview

The SCC Remediation Agent is an autonomous pipeline that ingests findings from Google Cloud Security Command Center (SCC), analyses their blast radius, generates validated remediation plans, and either executes them autonomously or routes them through a human approval workflow.

It runs in two execution modes:

| Mode | Entry point | When to use |
|------|-------------|-------------|
| **Batch** | `app/main.py` | Scheduled / event-driven autonomous processing |
| **Interactive** | `scc-agent chat` → `cli.py` | Human-in-the-loop investigation and approval |

Both modes share the same agents, tools, and validation layers. The key difference is control flow: the batch path calls the agent classes directly, while the interactive path uses the ADK runtime to route between sub-agents and the user.

---

## High-Level Data Flow

```
SCC Finding
    │
    ▼
TriageAgent          filter by scope, severity, dormancy; rank by exposure score
    │
    ▼
ImpactAgent          blast radius, IAM lateral paths, network exposure (Neo4j)
DormancyAgent        dormancy classification (Neo4j)
    │
    ▼
PreflightAgent       deterministic GCP API checks — PASS / WARN / BLOCK
    │
    ▼
PlanAgent            Phase 1: pre-flight enforcement
                     Phase 2: LLM plan generation (Gemini)
                       └─ Layer A: policy engine (blast level, maintenance window)
                       └─ Layer B: command compiler (whitelist, scope, expansion)
                       └─ Layer C: dry-run validation (gcloud describe, max 2 retries)
    │
    ▼
Confidence Score     weighted: pre-flights, blast level, dormancy, history
    │
    ▼
Tier Decision ───────────────────────────────────────────────────────────┐
    │                                                                     │
Tier 1              Tier 2                   Tier 3                      │
(autonomous)        (single-tap approval)    (expert review)             │
    │                    │                        │                      │
    │           dispatch_approval_request         │                      │
    │           → Firestore + Chat/PD/Jira        │                      │
    │           → webhook response                │                      │
    │                    │                        │                      │
    └────────────────────┴──────────────────────▶ _execute_plan()        │
                                                    per-step re-checks   │
                                                    VerifyAgent          │
                                                    regression_monitor ──┘
```

---

## Execution Paths in Detail

### Batch Path (`app/main.py`)

The batch path calls Python classes directly — no ADK runtime involved for the core pipeline.

```
run_remediation_cycle(config: CustomerConfig)
    │
    ├─ PRE_FINDING hook
    │
    ├─ ImpactAgent(config).analyse(finding)          → impact: dict
    ├─ DormancyAgent(config).check(resource_name)    → dormancy: dict
    │
    ├─ PlanAgent(config).generate(finding, impact, dormancy)  → plan: dict
    │      ├─ _fetch_resource_data()         Cloud Asset Inventory
    │      ├─ PreflightAgent.run()           deterministic checks
    │      ├─ LLM call (Gemini)              plan JSON
    │      ├─ _apply_policy_engine()         Layer A
    │      ├─ compile_plan()                 Layer B
    │      └─ _check_resources_exist()       Layer C (up to 3 attempts)
    │
    ├─ compute_confidence_score()
    ├─ _determine_execution_tier()
    │
    ├─ tier 1 → _execute_plan() → VerifyAgent → monitor_for_regression()
    └─ tier 2/3 → _dispatch_for_approval() → webhook → Cloud Tasks → _execute_plan()
```

**Hook points** fire at every major boundary (24 events). Built-in hooks write audit logs to Firestore and run per-step re-checks (change freeze, approval liveness). Custom hooks can halt the pipeline by setting `ctx["stop"] = True`.

### Interactive Path (`cli.py` → ADK)

The interactive path runs the root agent via ADK's `InMemoryRunner`. Sub-agents are routed by the ADK runtime based on the `description` field and conversation context.

```
scc-agent chat
    │
    ├─ InMemoryRunner(root_agent)
    │
    ├─ root_agent orchestrates:
    │      ├─ triage_agent          (ADK sub-agent, writes triage_agent_output)
    │      ├─ impact_agent_<type>   (ADK sub-agent, writes impact_agent_output)
    │      ├─ plan_agent            (ADK sub-agent, writes plan_agent_output)
    │      ├─ validate_plan tool    (Layer B only — see validation section)
    │      └─ verify_agent          (ADK sub-agent, writes verify_agent_output)
    │
    └─ User approves → dispatch_approval_request → webhook → Cloud Tasks
```

Sub-agents write structured JSON to session state under their `output_key`. The root agent reads those keys and narrates the results in plain English — the user never sees raw JSON.

---

## Agent Reference

### `TriageAgent` (`app/agents/triage_agent.py`)

Filters and ranks SCC findings before the pipeline starts.

- Fetches active findings from SCC v2 filtered by `severity_threshold`
- Applies scope filter (`ScopeConfig.matches_asset`)
- Deduplicates by `(resource_name, category, cve_ids)` across scanners
- Excludes accepted risks (muted findings)
- Sorts by `attack_exposure_score` descending

### `ImpactAgent` (`app/agents/impact_agent.py`)

Blast radius and exposure analysis via Neo4j.

| Query | What it answers |
|-------|-----------------|
| `query_blast_radius` | What downstream resources are affected (up to 3 hops)? |
| `query_iam_paths` | What prod resources can be reached via IAM lateral movement? |
| `query_dependency_chain` | What does this resource depend on upstream? |
| `get_network_exposure` | Is this resource internet-exposed? On which ports? |

**Blast level rules:**

```
CRITICAL  prod downstream > 10
HIGH      prod downstream > 3  OR  PII resources in blast radius
MEDIUM    any prod downstream  OR  asset itself is prod
LOW       isolated, no prod impact
UNKNOWN   graph unavailable (Mode A — Neo4j not running)
```

### `DormancyAgent` (`app/agents/dormancy_agent.py`)

Classifies asset activity from the graph's `dormancy_score` field.

```
> 0.8  → DORMANT    (idle >30 days)
> 0.4  → PERIODIC
< 0.4  → ACTIVE
```

DORMANT assets get a +0.10 confidence score bonus (lower risk to patch).

### `PreflightAgent` (`app/agents/preflight_agent.py`)

Deterministic GCP API checks — no LLM, no write calls. Runs concurrently before plan generation.

| Check | Type | Trigger |
|-------|------|---------|
| change_freeze | All types | BLOCK if resource/project has `change-freeze=true` label |
| mig_membership | OS_PATCH | WARN if instance is in a managed instance group |
| active_ssh_session | OS_PATCH | WARN if SSH session active in last 30 min (Cloud Logging) |
| recent_deployment | OS_PATCH | WARN if write ops in last 2h |
| snapshot_policy | OS_PATCH | WARN if no disk snapshot policy |
| lb_health_check | OS_PATCH | WARN if external IP detected (possible LB backend) |
| reboot_required | OS_PATCH | WARN if OS Config report flags pending reboot |
| active_connections | FIREWALL | BLOCK if VPC Flow Logs show live traffic on the rule |
| cloud_armor_overlap | FIREWALL | WARN if Cloud Armor policies present |
| role_last_used | IAM | WARN if role has NOT been used recently |
| redundant_grants | IAM | WARN if principal holds overlapping roles |
| active_sa_keys | IAM | WARN if service account has user-managed keys |

Results shape: `[{"check": str, "result": "PASS|WARN|BLOCK", "detail": str}]`

### `PlanAgent` (`app/agents/plan_agent.py`)

Two-phase plan generation with a three-layer security validation loop.

**Phase 1 — Pre-flight enforcement (deterministic)**

Runs `PreflightAgent`, fetches live resource data from Cloud Asset Inventory, enforces any BLOCK results before touching the LLM.

**Phase 2 — LLM generation + retry loop (max 3 attempts)**

```python
for attempt in range(3):
    plan = LLM(prompt_with_preflight_results + resource_data + finding + impact)

    if any BLOCK in pre-flight:
        plan["status"] = "BLOCKED"; break

    plan = _apply_policy_engine(plan, impact, config)   # Layer A
    if plan["status"] == "BLOCKED": break

    compiler_result = compile_plan(plan, finding)       # Layer B
    if not compiler_result:
        plan["status"] = "BLOCKED"; break               # no retry — human review required

    dry_run_errors = await _check_resources_exist(plan) # Layer C
    if not dry_run_errors: break                        # success

    if attempt < 2:
        prompt += error_context                         # re-prompt with errors
    else:
        plan["status"] = "BLOCKED"                      # exhausted retries
```

The prompt is context-budgeted before the LLM call:

| Field | Budget |
|-------|--------|
| resource_data | 32 KB |
| impact (compacted) | 16 KB |
| preflight_results | 8 KB |
| finding | 4 KB |
| remediation_text | 2 KB |

### `VerifyAgent` (`app/agents/verify_agent.py`)

Type-specific post-execution verification — polls the authoritative source, not just SCC state.

| Remediation type | Verification method | Authoritative source |
|------------------|---------------------|----------------------|
| OS_PATCH | Vulnerability report | OS Config API |
| FIREWALL | Connectivity test | Network Intelligence Center |
| IAM | Policy analysis | IAM `analyzeIamPolicy` |
| MISCONFIGURATION | Finding state poll | SCC finding state |

On success: mutes the SCC finding, updates the graph, launches `regression_monitor` as a background task.

---

## Security Validation Layers

Three layers run between LLM output and execution. They are **deterministic** — no additional LLM calls.

### Layer A — Policy Engine

Location: `_apply_policy_engine()` in `app/agents/plan_agent.py`

- `blast_level` HIGH or CRITICAL → sets `change_window_required = True`
- If `change_window_required` and current UTC time is outside `approval_policy.default_maintenance_window` → BLOCKED

Coverage: **batch path only** (requires `CustomerConfig`).

### Layer B — Command Compiler

Location: `app/tools/command_compiler.py` + `app/tools/validate_plan_tool.py`

Validates every `api_call` string in `plan.steps` and `plan.rollback_steps`.

**Check 1 — Hard-blocked subcommands** (always rejected):
- Resource deletion: `gcloud compute {firewall-rules,instances,disks,networks} delete`, `gcloud projects delete`, `gcloud iam service-accounts delete`, `gsutil rm -r`
- Full policy replacement: `gcloud organizations set-iam-policy`
- Infrastructure destruction: `terraform destroy`

**Check 2 — IAM expansion** (always rejected):
- `gcloud {projects,organizations,resource-manager folders,iam service-accounts} add-iam-policy-binding`

**Check 3 — Firewall expansion** (always rejected):
- Any command with `--source-ranges=0.0.0.0/0` or `--source-ranges=::/0`

**Check 4 — Subcommand whitelist** (per remediation type):

| Type | Allowed mutating commands |
|------|--------------------------|
| FIREWALL | `gcloud compute firewall-rules update` |
| IAM | `gcloud {projects,organizations,folders,iam service-accounts} remove-iam-policy-binding`, `gcloud projects set-iam-policy` (patch file only) |
| OS_PATCH | `gcloud compute os-config patch-jobs execute`, `patch-deployments create/update` |
| MISCONFIGURATION | Union of FIREWALL + IAM + `gcloud storage buckets update`, `gcloud compute {instances add/remove-metadata,ssl-policies,target-https-proxies,backend-services} update`, `terraform apply` |

Read-only commands (`describe`, `list`, `get`, `terraform show/plan/validate`) are always allowed.

**Check 5 — Project scope**: `--project` in command must match the finding's project. Mismatch = scope creep violation.

On any violation: plan is BLOCKED with `compiler_violations` list. No retry — violations require human review.

Coverage: **both paths**. In the batch path, runs inside `PlanAgent.generate()`. In the interactive path, runs via the `validate_plan` ADK FunctionTool after `plan_agent` writes its output.

### Layer C — Dry-Run Validation

Location: `_check_resources_exist()` in `app/agents/plan_agent.py`

Converts each mutating gcloud command to its read-only `describe` equivalent and runs it via subprocess to verify the resource exists before the plan is presented.

```
gcloud compute firewall-rules update fw-name --project=X
  → gcloud compute firewall-rules describe fw-name --project=X

gcloud compute instances add-metadata vm --zone=Z --project=X
  → gcloud compute instances describe vm --zone=Z --project=X

gcloud projects remove-iam-policy-binding proj ...
  → gcloud projects describe proj
```

Only definitive `NOT_FOUND` / 404 errors trigger a re-prompt. Timeouts (30s) and permission errors are ignored.

Coverage: **batch path only**. Subprocess gcloud calls are not suitable inside a synchronous ADK tool call.

---

## Tool Pool Assembly

Following the Claude Code harness pattern (arXiv 2604.14228): each agent receives only the tools relevant to its role and finding type.

**Three assembly stages:**

1. **Base enumeration** — all tools for the agent's role
2. **Type filtering** — restrict to the finding's remediation type
3. **Deny-list filter** — strip tools blocked by `AGENT_TOOL_DENY_LIST` env var (global kill switch)

**Impact agent tool pools:**

| Type | Tools | Excluded (why) |
|------|-------|---------------|
| OS_PATCH | blast_radius, dependency_chain, dormancy | No IAM paths (not a permission change), no network (no connectivity change) |
| IAM | blast_radius, iam_paths, dormancy | No dependency_chain (IAM is about permission, not infra deps), no network |
| FIREWALL | blast_radius, dependency_chain, network | No IAM paths (firewall rules don't change IAM bindings) |
| MISCONFIGURATION | all | Spans multiple resource types |

**Root agent tool pool** (interactive path):

```
list_active_findings     list and triage SCC findings
get_finding_detail       deep-dive on a specific finding
query_blast_radius       ad-hoc "what depends on this?" questions
query_dependency_chain   upstream dependency mapping
query_iam_paths          IAM lateral movement paths
get_network_exposure     internet exposure and open ports
validate_plan            Layer B validation after plan_agent writes its output
dispatch_approval_request  route plan to approval workflow
create_patch_job         OS_PATCH execution (OS_PATCH type only)
```

The deny list allows blocking any tool globally without a deploy. For example, setting `AGENT_TOOL_DENY_LIST=create_patch_job,dispatch_approval_request` puts the system into read-only mode.

---

## Context Budget & Output Compaction

Long outputs from early pipeline stages are compacted before being passed to downstream agents to stay within token budgets.

### `context_budget.py`

`budget_json(data, max_chars, label)` applies three reduction stages:

1. Full pretty-print (`indent=2`)
2. Prune verbose fields + compact JSON
3. Hard truncate with `[TRUNCATED — {label} exceeded budget]` marker

The caller never has to check length — the function always returns a string within budget.

### `agent_output.py`

Stage-specific compaction of `ImpactAgent` output:

| Consumer | What it keeps | Why |
|----------|---------------|-----|
| `compact_impact_for_plan` | blast_level, downstream (capped 10, name/env/team only), IAM paths (capped 5), network summary | Plan prompt needs context, not full detail |
| `compact_impact_for_approval` | blast_level, blast_radius_assets (capped 50), prod/pii counts, env, team, internet_exposed | Approval card fields |
| `compact_impact_for_scoring` | blast_level, dormancy_class | Confidence scoring only needs two scalars |

`compact_plan_for_verify` strips everything the verify agent doesn't need — drops steps, rollback, preflight results, summaries — reducing a 3–8 KB plan to under 500 bytes.

---

## Hook Pipeline (`app/hooks.py`)

24 named events with async/sync support. Exceptions are caught and logged — a failing hook never crashes the pipeline.

```
PRE_FINDING → POST_FINDING
PRE_IMPACT  → POST_IMPACT
PRE_PLAN    → POST_PLAN
PRE_TIER_DECISION → POST_TIER_DECISION
PRE_EXECUTE → POST_EXECUTE
  (PRE_STEP → POST_STEP  per remediation step)
PRE_VERIFY  → POST_VERIFY
PRE_APPROVAL_DISPATCH → POST_APPROVAL_DISPATCH

ON_BLOCK                  plan blocked by any validation layer
ON_STEP_FAILURE           individual remediation step failed
ON_VERIFY_FAILURE         verification did not confirm success
ON_REGRESSION_DETECTED    error rate spike after execution
ON_DRY_RUN                dry_run=True, plan generated but not executed
ON_INVALIDATION           pending approval invalidated by graph event
```

**Built-in hooks:**

- **Per-step re-check** (`PRE_STEP`): re-evaluates change freeze and approval liveness. If either has changed since plan approval, the step is halted. This mirrors Claude Code's per-action permission gate — approval at plan time does not grant indefinite permission.

- **Audit log writer**: fires on POST_PLAN, ON_BLOCK, POST_EXECUTE, etc. Writes structured entries to the `audit_log` Firestore collection.

- **Transcript logger** (opt-in): fires on POST_IMPACT, POST_PLAN, POST_VERIFY. Writes agent reasoning to `transcripts` collection for replay and evaluation.

**Custom hooks** are registered with `@hooks.on("event_name")` or `hooks.register("event_name", fn)`.

---

## Approval Workflow

```
_dispatch_for_approval(plan, finding, impact, config, tier)
    │
    ├─ Create Firestore document in `approvals/{approval_id}`
    ├─ Register in proximity index (for invalidation lookup)
    ├─ Send approval card to all configured channels:
    │      ├─ Google Chat (interactive buttons: Approve / Reject / Defer)
    │      ├─ PagerDuty (incident ACK → APPROVED, resolve → REJECTED)
    │      └─ Jira (issue transition mapping)
    └─ Schedule escalation timer (Cloud Tasks, after grace_period_minutes)

On response → scheduler/main.py webhook handler:
    │
    ├─ Validate approver is in approval_policy.approvers for this severity
    ├─ Update approval status: APPROVED / REJECTED / DEFERRED
    └─ _enqueue_execution() → Cloud Tasks → _execute_plan()
```

**Approval tiers:**

| Tier | Condition | Workflow |
|------|-----------|----------|
| 1 | Confidence ≥ policy threshold, blast LOW, all pre-flights PASS | Autonomous, no human gate |
| 2 | No BLOCKs, confidence ≥ 0.70, blast ≤ MEDIUM, ≤ 1 WARN | Single-tap approval (auto-escalates after 4h) |
| 3 | Any BLOCK, HIGH/CRITICAL blast, confidence < 0.70, or no matching policy | Expert review required |

---

## Approval Invalidation

The graph event processor monitors for state changes that make a pending approval stale. When a resource in the plan's blast radius changes (e.g. a new production dependency is added, or a change freeze is applied), it:

1. Queries the proximity index for affected approval IDs
2. Sets `approval["status"] = "INVALIDATED"` in Firestore
3. Fires `ON_INVALIDATION` hook
4. Notifies the original approver that re-review is needed

This prevents executing an approval that was granted under different conditions.

---

## Regression Monitoring

After a successful Tier 1 execution, `monitor_for_regression()` runs as a background `asyncio` task for 30 minutes.

```
baseline = 7-day error rate (Cloud Logging) for target + blast radius assets

every 60s for 30 min:
    current_rate = error rate in last 5 min
    if current_rate > baseline.mean + 2 × baseline.std:
        trigger execute_rollback(approval_id)
        alert approver
        break
```

Rollback executes the plan's `rollback_steps` sequentially via subprocess and updates the Firestore approval document.

---

## CLI Reference (`cli.py`)

**Top-level commands:**

| Command | Description |
|---------|-------------|
| `chat` | Interactive ADK session (local only) |
| `run` | Execute batch remediation cycle |
| `status` | Show pending approvals and recent findings |
| `approve <id>` | Approve a pending remediation |
| `reject <id>` | Reject a pending remediation |
| `rollback <id>` | Roll back an executed remediation (24h window) |
| `finding <id>` | Show SCC finding details |
| `models` | List available Gemini models; `--select` to save |

**Chat slash commands (inside `scc-agent chat`):**

| Command | Description |
|---------|-------------|
| `/model` | List available Gemini models, select and apply live |
| `/status` | Show pending approvals for current session's customer |
| `/finding <id>` | Show finding details panel |
| `/clear` | Clear the screen |
| `/help` | Show slash command list |
| `/exit` | End the session |

**Model selection (`/model`):**

Calls `discover_models()` to list available Gemini Flash and Pro models from the Vertex AI API, shows a numbered menu with the currently active model highlighted, then:

1. Updates `os.environ["MODEL_ID"]` and `os.environ["PLANNING_MODEL_ID"]`
2. Mutates `root_agent.model` in place — effective on the next message, no restart
3. Writes both IDs to `.env` for future sessions

---

## Configuration Schema (`config/schema.py`)

```
CustomerConfig
├─ customer_id, org_id, display_name
├─ dry_run: bool                      default True — safe mode
├─ scope: ScopeConfig
│       ├─ project_ids[], folder_ids[]
│       └─ include_labels[], exclude_labels[]  (ALL include must match; ANY exclude = out)
├─ severity_threshold: SeverityThreshold
│       CRITICAL_ONLY | HIGH_PLUS | MEDIUM_PLUS | ALL
├─ filters: FindingFilters
│       require_active_exposure_path, exclude_dormant_assets,
│       deduplicate_across_scanners, exclude_accepted_risks
├─ approval_policy: ApprovalPolicy
│       ├─ tiers: [ApprovalTier]       tier conditions + grace periods
│       ├─ approvers: [Approver]       per-severity approver list + channels
│       └─ default_maintenance_window: MaintenanceWindow
│               days_of_week[0–6], start_time_utc, end_time_utc (HH:MM)
├─ execution: ExecutionConfig
│       ├─ enabled_modes: [OS_PATCH | MISCONFIGURATION | IAM | FIREWALL]
│       ├─ max_blast_radius_for_auto: int   max downstream deps for Tier 1
│       └─ gitops_repo, gitops_branch       for Terraform PR mode
└─ policies: [ExecutionPolicy]        autonomous execution rules (tier 1 eligibility)
```

---

## Models

| Role | Env var | Default | Notes |
|------|---------|---------|-------|
| All agents (chat/triage/impact/verify) | `MODEL_ID` | `gemini-2.5-flash` | Fast; used for all interactive sub-agents |
| Planning | `PLANNING_MODEL_ID` | `gemini-2.5-pro` | Used by `PlanAgent` and `plan_agent` ADK sub-agent |

Both are configurable at runtime via `/model` in chat or `scc-agent models --select`.

Gemini 3 models (`gemini-3-flash-preview`, `gemini-3.1-pro-preview`) return 404 on Vertex AI project `gaia-485223` — they require explicit project allowlisting via the Vertex AI model garden.

---

## Graph Database (Neo4j)

The graph stores the GCP asset topology used for blast radius and dormancy analysis. When Neo4j is not running (Mode A — local interactive), all graph tools return `{"graph_unavailable": True}`. The root agent handles this gracefully: it proceeds with SCC + CAI data only and sets `blast_level = "UNKNOWN"`.

**Node types:** `Resource`, `ServiceAccount`, `IamBinding`, `Network`, `Project`

**Relationship types:** `DEPENDS_ON`, `HOSTED_BY`, `ROUTES_TRAFFIC_TO`, `CONNECTS_TO`, `GRANTS_ACCESS_TO`, `USES_SERVICE_ACCOUNT`

**Ingestion pipeline** (`graph/ingestion/`): Asset Inventory → finding ingester, IAM ingester, proximity indexer.

---

## Key Design Decisions

**Why two execution paths share the same validation?**
Layer B (command compiler) runs in both paths — as part of `PlanAgent.generate()` in batch, and as the `validate_plan` FunctionTool in interactive. Layers A and C are batch-only: Layer A needs `CustomerConfig` (not available in an interactive session), and Layer C needs subprocess gcloud calls (not appropriate inside a synchronous ADK tool).

**Why does the plan agent have no ADK tools?**
`plan_agent` (ADK sub-agent) has an empty tool list. Plan generation requires pre-fetched data (CAI resource data, pre-flight results, compacted impact) that is assembled by `PlanAgent.generate()` in the batch path. In interactive mode, the root agent provides this context in the message text. Adding ADK tools would let the model fetch data independently, risking context drift and harder-to-audit prompts.

**Why per-step re-checks?**
Approval at plan time is not indefinite permission. The PRE_STEP hook re-checks change freeze and approval liveness before each step executes. This guards against the window between approval and execution: a change freeze might be applied, or an invalidation event might arrive, after the user clicks Approve.

**Why type-specific verification?**
Generic SCC state polling (`ACTIVE → INACTIVE`) is slow and doesn't confirm the specific intent of the fix. OS Config vulnerability reports, NIC connectivity tests, and IAM policy analysis each give authoritative confirmation that the right thing happened — not just that SCC re-scanned and didn't re-flag.

**Why a retry loop in Layer C?**
The most common cause of Layer C failures is the LLM using stale resource names from its training data (e.g. SCC API v1 format → v2 format). Returning the live API error as prompt context gives the model the information it needs to self-correct in one retry, without requiring human intervention for a fixable issue.

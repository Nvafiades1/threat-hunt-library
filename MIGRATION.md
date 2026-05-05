# GitLab Migration

This document covers the GitLab platform setup that pairs with the code
in this repo (`.gitlab-ci.yml`, env-var-driven URL generation via
`tools/repo_urls.py`).

## Architecture: GitLab standalone

```
┌────────────────────────────────────────┐
│ GitLab (sole CI/CD platform)           │
│                                        │
│ - Pipeline Schedules trigger builds    │
│ - Build scripts run on GitLab Runner   │
│ - Auto-commits via CI_PUSH_TOKEN       │
│ - GitLab Pages publishes docs/         │
└────────────────────────────────────────┘
```

GitLab is the single source of truth. No GitHub dependency. Pipeline
Schedules drive the same cadences the GitHub Actions workflows used to:
every-15-min CTI rebuild, daily per-actor report refresh, monthly
priority list + new top-10 reports.

This is the target architecture for an enterprise GitLab deployment.
On `gitlab.com` free tier you'll hit the 400 CI-minutes/month cap quickly
(the 15-minute CTI cron alone needs ~3000/month); fine for a few hours of
"does the pipeline work?" testing, not for sustained use. On a
self-hosted or Premium/Ultimate instance, no such limit.

## One-time setup

### 1. Project Access Token (the credential CI uses to push commits)

In your GitLab project: **Settings → Access Tokens → Add new token**.

| Field | Value |
|---|---|
| Name | `ci-pusher` |
| Expiration | Up to 1 year out |
| Role | **Maintainer** |
| Scopes | ☑ `write_repository` (and ☑ `api` if you want to use the schedule-creation script in §3 below) |

Create the token. **Copy it immediately** — only shown once.

### 2. Store the token as a CI/CD variable

**Settings → CI/CD → Variables → Add variable**:

| Field | Value |
|---|---|
| Key | `CI_PUSH_TOKEN` |
| Value | (the token from step 1) |
| Type | Variable |
| Visibility | **Masked** ☑ |
| Flags | **Protect variable** ☑ |

Confirm `main` is marked as a protected branch (Settings → Repository →
Protected branches). The `Protect variable` flag only exposes the value
to jobs running on protected refs.

### 3. Create the three Pipeline Schedules

**Option A — UI (3 × ~30 seconds):** Build → Pipeline schedules → Create
a new pipeline schedule. Once for each row below; in each, after
creating, click the schedule → Variables → add a single variable with
the listed key/value:

| Description | Cron | Variable: RUN_JOB |
|---|---|---|
| CTI feed rebuild | `*/15 * * * *` | `cti` |
| Daily actor reports | `0 6 * * *` | `actor_reports` |
| Monthly priority + reports | `0 9 1 * *` | `monthly` |

**Option B — script (one shot):** the included
`tools/setup_pipeline_schedules.sh` creates all three via the GitLab REST
API. Run from your terminal:

```bash
export GITLAB_TOKEN='glpat-...'   # PAT with scope `api`
                                  # (the same one from step 1 works if you gave it both `write_repository` + `api`)
export GITLAB_PROJECT='nvafiades11-group/threat-hunt-library'
bash tools/setup_pipeline_schedules.sh
```

Idempotent — if a schedule with the same description already exists, the
script skips it.

### 4. Trigger the first run

Build → Pipeline schedules → click the ▶ play icon on each schedule once
to fire it now (rather than waiting for the cron). The first pipeline
takes ~2 minutes (pip install + Python rendering + state-file commit).

### 5. Confirm GitLab Pages is live

After the first push-triggered or schedule-triggered pipeline completes,
the `pages` job auto-deploys. **Deploy → Pages** shows the URL —
typically:

```
https://nvafiades11-group.gitlab.io/threat-hunt-library/
```

For private projects, set Pages access at Settings → General → Visibility,
project features, permissions → Pages.

## Verification checklist

- [ ] **Settings → CI/CD → Variables** shows `CI_PUSH_TOKEN` (masked).
- [ ] **Build → Pipeline schedules** lists three schedules.
- [ ] **Build → Pipelines** shows successful pipelines triggered by
      "schedule" with the appropriate `RUN_JOB` value.
- [ ] **Repository commits** show `Auto-build CTI hub [skip ci]` /
      `Auto-build actor reports [skip ci]` etc. authored by `ci-bot`.
- [ ] **Deploy → Pages** shows a deployment URL.
- [ ] Visit the URL — matrix loads with all 15 tactic columns, the
      threat-actor priority page lists 35 actors, clicking an actor name
      in the top 10 lands on a per-actor report.
- [ ] In-page repo links point at `gitlab.com/nvafiades11-group/...`
      rather than GitHub. (If they don't, check the `REPO_HOST` /
      `REPO_OWNER` etc. variables in `.gitlab-ci.yml`.)

## Known not-translated workflows

These GitHub Actions workflows are not mirrored in `.gitlab-ci.yml`
because they react to GitHub-specific events (issues, comments, PRs):

- `issue-to-folder.yml` — auto-creates `techniques/T####/` from new issues
- `enrichThreatActor.yml` — runs on issue label changes
- `updateThreatHunt.yml` — runs on PR merge

Reaching feature parity for these requires rewriting the underlying
Node.js scripts to use the GitLab REST API and triggering on GitLab issue
events. Out of scope for the initial setup; do this later if you fully
deprecate GitHub.

## Free-tier-specific gotchas

These only matter on `gitlab.com` free; not relevant once you migrate to
your enterprise instance.

- **400 CI-minutes/month cap.** The 15-minute CTI schedule alone uses
  ~96 runs/day × ~1 minute = ~3000 minutes/month. To stay within the
  cap during free-tier testing, change the CTI cron to `0 */6 * * *`
  (every 6 hours instead of every 15 min) — that's ~4 runs/day × 30 days
  = ~120 minutes/month, leaves headroom for the daily + monthly schedules.
- **Pages bandwidth limits.** Free tier is 100 GB/month — irrelevant for
  this site's size unless you bring serious traffic.

## Rolling back

If anything goes sideways and you want to disable the GitLab side:

1. **Build → Pipeline schedules** → toggle "Active" off on each schedule
   (no destructive change — they pause but stay configured).
2. **Settings → CI/CD → Variables** → delete `CI_PUSH_TOKEN`. Without
   it, the auto-commit jobs error early without doing anything.
3. The repo and Pages remain accessible at their last-deployed state.

The GitHub side is unaffected throughout, so rollback is zero-risk.

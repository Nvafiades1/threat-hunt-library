# GitLab Migration — Proof of Concept

This document covers the manual GitLab steps needed alongside the code in
this repo. The code side (`.gitlab-ci.yml`, env-var-driven URL generation
via `tools/repo_urls.py`) is already in place.

## POC architecture

```
┌──────────────────────────┐                ┌──────────────────────────┐
│ GitHub (source of truth) │                │ GitLab (POC mirror)      │
│                          │  pull mirror   │                          │
│ - All build workflows    │  ───────────▶  │ - Receives all commits   │
│ - Auto-commits state     │  every ~1h     │ - .gitlab-ci.yml renders │
│ - GitHub Pages           │                │ - GitLab Pages publishes │
└──────────────────────────┘                └──────────────────────────┘
```

GitHub keeps doing all the work it does today: 15-min CTI rebuilds, daily
actor reports, monthly priority list. Each commit on GitHub is mirrored
to GitLab within ~1 hour. The mirrored commit triggers the GitLab `pages`
job, which re-renders the static site (matrix, metrics, threat-actors,
actor reports) using `tools/repo_urls.py` to point all in-page links at
the GitLab URLs, and publishes the result to GitLab Pages.

The result: two parallel deployments of the same site, with GitHub as
the single source of truth. Disable the GitHub side later (or never).

## One-time setup steps

### 1. Configure pull mirroring (GitHub → GitLab)

In your GitLab project: **Settings → Repository → Mirroring repositories**.

| Field | Value |
|---|---|
| Git repository URL | `https://github.com/Nvafiades1/threat-hunt-library.git` |
| Mirror direction | **Pull** |
| Authentication method | None (the GitHub repo is public) |

Click **Mirror repository**. The first sync takes ~30 seconds. After that
GitLab polls GitHub every hour by default. You can click the **Update now**
button (the circular arrow icon) any time to force a sync.

### 2. Verify GitLab CI is enabled

**Settings → CI/CD → General pipelines** — confirm "CI/CD" is enabled
(it is by default for imported projects).

### 3. Enable GitLab Pages

GitLab Pages auto-activates the first time a `pages` job succeeds — no
configuration needed. After your first successful pipeline (which the
mirror sync will trigger), the site will be live at:

```
https://nvafiades11-group.gitlab.io/threat-hunt-library/
```

You can find the exact URL at **Deploy → Pages** once the first deploy lands.

If the project is private, the site defaults to "everyone with project
access" — you can switch to public-readable at **Settings → General →
Visibility, project features, permissions → Pages**.

### 4. Trigger the first pipeline

Mirroring runs the pipeline as soon as the first sync lands. If you want to
trigger it sooner: **Build → Pipelines → Run pipeline → main**.

The first pipeline takes ~2 minutes (pip install + Python rendering). Once
green, hit the Pages URL and you should see the same matrix / metrics /
CTI Hub / threat actors / per-actor reports as the GitHub-hosted site.

## Verification checklist

- [ ] **Settings → Repository → Mirroring** shows the GitHub URL with a green
      "Last successful update" timestamp.
- [ ] **Build → Pipelines** shows a successful pipeline on `main` with the
      `pages` job green.
- [ ] **Deploy → Pages** shows a deployment URL.
- [ ] Visit the Pages URL — matrix loads with all 15 tactic columns, the
      threat-actor priority page lists 35 actors, and clicking an actor
      name in the top-10 lands on a per-actor report.
- [ ] In any rendered page, the "View on …" / repo links should point at
      `gitlab.com/nvafiades11-group/threat-hunt-library`, **not** GitHub.
      (Driven by the `REPO_HOST` / `REPO_OWNER` / `REPO_NAME` /
      `REPO_BRANCH` variables in `.gitlab-ci.yml`. Change them in
      Settings → CI/CD → Variables if your GitLab path is different.)

## What runs where

| Cadence | GitHub | GitLab |
|---|---|---|
| CTI feed pulls | every 15 min via Actions | (mirror picks up render output) |
| Daily actor-report refresh | 06:00 UTC | (mirror picks up render output) |
| Monthly priority + reports | 1st of month, 09:00 UTC | (mirror picks up render output) |
| Pages deploy | every commit | every mirror-landed commit |
| `tools/repo_urls.py` env vars | unset → defaults to GitHub | set in CI to GitLab |

The state files (`tools/cti_state.json`, `tools/threat_actors_state.json`)
are owned by the GitHub side. GitLab CI re-renders **from** that state but
never **writes** state in POC mode — no risk of two pipelines fighting
over the same file.

## Graduating from POC to full migration

When you're ready to retire the GitHub side:

1. **Decide direction.** Either:
   - **A) GitLab takes over.** Disable GitHub Actions workflows (Settings →
     Actions → "Disable Actions for this repository"). Set the GitLab
     mirror direction to **Push** (so future commits flow back to GitHub
     for archival), or just stop mirroring entirely.
   - **B) Keep both.** Leave GitHub as primary; this POC stays as a
     parallel viewer. Cheap to maintain.

2. **If A: enable GitLab auto-commits.** Open `.gitlab-ci.yml` and
   uncomment the three commented-out jobs at the bottom (`build_cti`,
   `build_threat_actors`, `build_actor_reports_daily`). They contain the
   same auto-commit logic the GitHub Actions workflows have, adapted for
   GitLab.

3. **Create a Project Access Token.** Settings → Access Tokens → Add
   new token:
   - Name: `ci-pusher`
   - Role: **Maintainer**
   - Scopes: ☑ `write_repository`
   - Expiry: 1 year (extend later)
   Copy the generated token.

4. **Store the token as a CI variable.** Settings → CI/CD → Variables →
   Add variable:
   - Key: `CI_PUSH_TOKEN`
   - Value: (paste the token)
   - Type: **Variable**
   - ☑ **Masked**
   - ☑ **Protected** (only available on protected branches/tags — check
     that `main` is protected at Settings → Repository → Protected branches)

5. **Create three Pipeline Schedules** (Build → Pipeline schedules → Create
   a new pipeline schedule):

   | Description | Cron | Variables |
   |---|---|---|
   | CTI feed rebuild | `*/15 * * * *` | `RUN_JOB=cti` |
   | Daily actor reports | `0 6 * * *` | `RUN_JOB=actor_reports` |
   | Monthly priority + reports | `0 9 1 * *` | `RUN_JOB=threat_actors` |

   Each schedule runs the full pipeline; the `rules:` in each job decide
   which job actually executes based on the `RUN_JOB` variable.

6. **Test by running each schedule once manually** — Build → Pipeline
   schedules → Play (▶) — and confirm the resulting pipeline produces an
   auto-commit.

## Rolling back the POC

If the POC isn't working out:
- **Disable mirroring** at Settings → Repository → Mirroring repositories.
- The GitLab project keeps its current state but stops syncing.
- Delete the project entirely if you want to start over.

GitHub side is untouched throughout the POC, so rollback is zero-risk.

## Known not-translated workflows

These GitHub Actions workflows are not mirrored in `.gitlab-ci.yml` because
they react to GitHub-specific events (issues, comments, PRs):

- `issue-to-folder.yml` — auto-creates `techniques/T####/` from new issues
- `enrichThreatActor.yml` — runs on issue label changes
- `updateThreatHunt.yml` — runs on PR merge

Reaching feature parity for these requires rewriting the underlying Node
scripts to use the GitLab REST API and triggering on GitLab issue events.
Out of scope for the POC — leave them on GitHub for now (or duplicate the
intent in GitLab Issues if you fully migrate).

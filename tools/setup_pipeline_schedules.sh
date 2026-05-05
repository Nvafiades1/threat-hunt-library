#!/usr/bin/env bash
# Create the three Pipeline Schedules this project needs, via the GitLab REST API.
#
# Usage:
#   export GITLAB_TOKEN='glpat-...'   # Personal Access Token with scope: api
#   export GITLAB_PROJECT='nvafiades11-group/threat-hunt-library'
#   bash tools/setup_pipeline_schedules.sh
#
# The token only needs `api` scope (read+write). It is *not* the same as the
# CI_PUSH_TOKEN used by jobs to push commits — that one needs `write_repository`.
# A single Personal Access Token with both scopes works for both purposes.
#
# Idempotent: if a schedule with the same description already exists, this
# script skips creating a duplicate.
set -euo pipefail

GITLAB_HOST="${GITLAB_HOST:-gitlab.com}"
GITLAB_TOKEN="${GITLAB_TOKEN:?Set GITLAB_TOKEN to a PAT with `api` scope}"
GITLAB_PROJECT="${GITLAB_PROJECT:?Set GITLAB_PROJECT to <namespace>/<project>}"

# URL-encode the project path (slashes → %2F)
PROJECT_PATH=$(printf '%s' "$GITLAB_PROJECT" | sed 's|/|%2F|g')
API="https://${GITLAB_HOST}/api/v4/projects/${PROJECT_PATH}"

echo "Target project: $GITLAB_PROJECT (encoded: $PROJECT_PATH)"

# ── Schedules to create ─────────────────────────────────────────────────
#
# format:  "<description>|<cron>|<RUN_JOB value>"
SCHEDULES=(
  "CTI feed rebuild|*/15 * * * *|cti"
  "Daily actor reports|0 6 * * *|actor_reports"
  "Monthly priority + reports|0 9 1 * *|monthly"
)

# Fetch existing schedules so we can skip duplicates
existing=$(curl -fsSL --header "PRIVATE-TOKEN: $GITLAB_TOKEN" "$API/pipeline_schedules?per_page=100")
existing_descriptions=$(printf '%s' "$existing" | python3 -c "
import json, sys
for s in json.load(sys.stdin):
    print(s.get('description', ''))
")

for entry in "${SCHEDULES[@]}"; do
  IFS='|' read -r desc cron job <<<"$entry"

  if printf '%s\n' "$existing_descriptions" | grep -qx "$desc"; then
    echo "  ✓ '$desc' already exists — skipping"
    continue
  fi

  echo "  + creating '$desc' (cron=$cron, RUN_JOB=$job)"
  schedule_resp=$(curl -fsSL --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
    --form "description=$desc" \
    --form "ref=main" \
    --form "cron=$cron" \
    --form "active=true" \
    "$API/pipeline_schedules")

  schedule_id=$(printf '%s' "$schedule_resp" | python3 -c "import json, sys; print(json.load(sys.stdin)['id'])")

  curl -fsSL --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
    --form "key=RUN_JOB" \
    --form "value=$job" \
    "$API/pipeline_schedules/$schedule_id/variables" >/dev/null

  echo "    schedule id $schedule_id created with RUN_JOB=$job"
done

echo
echo "Done. View at https://${GITLAB_HOST}/${GITLAB_PROJECT}/-/pipeline_schedules"

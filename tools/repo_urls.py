"""
Single source of truth for repo URLs used by the build scripts. Lets the
same code run on either GitHub or GitLab CI by reading four env vars; falls
back to the current GitHub-hosted defaults so nothing breaks when the env
vars are unset.

Env vars (all optional):
  REPO_HOST    — domain, e.g. "github.com" (default) or "gitlab.com"
  REPO_OWNER   — user or group/namespace, e.g. "Nvafiades1" (default)
                 or "nvafiades11-group"
  REPO_NAME    — project slug, e.g. "threat-hunt-library" (default)
  REPO_BRANCH  — default branch, e.g. "main" (default)

The only structural difference between the two platforms is GitLab's
"-/blob/" and "-/tree/" URL prefix; this module hides it.
"""
from __future__ import annotations
import os

_HOST   = os.environ.get("REPO_HOST",   "github.com")
_OWNER  = os.environ.get("REPO_OWNER",  "Nvafiades1")
_REPO   = os.environ.get("REPO_NAME",   "threat-hunt-library")
_BRANCH = os.environ.get("REPO_BRANCH", "main")

_IS_GITLAB = "gitlab" in _HOST.lower()

REPO_HOST   = _HOST
REPO_OWNER  = _OWNER
REPO_NAME   = _REPO
REPO_BRANCH = _BRANCH

REPO_HOME_URL = f"https://{_HOST}/{_OWNER}/{_REPO}"
REPO_BLOB_URL = f"{REPO_HOME_URL}/{'-/blob' if _IS_GITLAB else 'blob'}/{_BRANCH}"
REPO_TREE_URL = f"{REPO_HOME_URL}/{'-/tree' if _IS_GITLAB else 'tree'}/{_BRANCH}"

# Convenience label for nav links etc.
REPO_HOST_LABEL = "GitLab" if _IS_GITLAB else "GitHub"

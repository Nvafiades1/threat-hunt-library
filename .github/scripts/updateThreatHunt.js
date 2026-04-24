(async () => {
  const { Octokit } = await import("@octokit/rest");
  const { graphql } = await import("@octokit/graphql");
  const fetch = (await import("node-fetch")).default;
  const fs = require("fs");
  const path = require("path");

  const token = process.env.GITHUB_TOKEN;
  const octokit = new Octokit({ auth: token, request: { fetch } });
  const gql = graphql.defaults({
    headers: { authorization: `token ${token}` }
  });

  function generateSlug(title) {
    return title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  }

  // TTPs: T#### or T####.### (first one wins)
  function extractTechniqueId(text = "") {
    const m = text.match(/\b(T\d{4}(?:\.\d{3})?)\b/i);
    return m ? m[1].toUpperCase() : null;
  }

  // ─── archive markdown builder ────────────────────────────────────────────
  const NONE_VALUES = new Set(["", "_no response_", "n/a", "none", "tbd"]);

  function parseSections(body) {
    const order = [];
    const map = {};
    let current = null;
    for (const line of (body || "").split("\n")) {
      const m = line.match(/^###\s+(.+?)\s*$/);
      if (m) {
        current = m[1].trim();
        if (!(current in map)) { order.push(current); map[current] = []; }
      } else if (current !== null) {
        map[current].push(line);
      }
    }
    return { order, map };
  }

  function fieldValue(map, label) {
    const lines = map[label];
    if (!lines) return null;
    const v = lines.join("\n").trim();
    return NONE_VALUES.has(v.toLowerCase()) ? null : v;
  }

  function filterCheckedOnly(content) {
    // Keep only ticked items from a GH-form checkboxes block
    const kept = content.split("\n")
      .filter(l => /^\s*-\s*\[[xX]\]/.test(l))
      .map(l => l.replace(/^\s*-\s*\[[xX]\]\s*/, "- "));
    return kept.join("\n").trim();
  }

  function truncate(s, max) {
    if (!s) return "";
    return [...s].length <= max ? s : [...s].slice(0, max - 1).join("") + "\u2026";
  }

  // visibleLen accounts for fullwidth / multibyte safely via spread
  function padRight(s, width) {
    const visible = [...s].length;
    return visible >= width ? s : s + " ".repeat(width - visible);
  }

  function buildArchive({ issueTitle, issueNumber, issueBody, techniqueId, closedAt, repoSlug }) {
    const { order, map } = parseSections(issueBody);

    const sev    = fieldValue(map, "Severity")       || "\u2014";
    const conf   = fieldValue(map, "Confidence")     || "\u2014";
    const fid    = fieldValue(map, "Query Fidelity") || "\u2014";
    const plat   = fieldValue(map, "Hunt Platform")  || "\u2014";
    const actor  = fieldValue(map, "Threat Actor")   || "\u2014";
    const status = fieldValue(map, "Status")         || "Completed";

    const issueUrl = `https://github.com/${repoSlug}/issues/${issueNumber}`;

    // Box banner (unicode box-drawing, wrapped in a code fence so it renders as monospace)
    const INNER = 72;
    const line1 = truncate(` THREAT HUNT \u00B7 ${techniqueId}`, INNER);
    const line2 = truncate(` ${issueTitle}`, INNER);
    const banner = [
      "```",
      "\u2554" + "\u2550".repeat(INNER) + "\u2557",
      "\u2551" + padRight(line1, INNER) + "\u2551",
      "\u2551" + padRight(line2, INNER) + "\u2551",
      "\u255A" + "\u2550".repeat(INNER) + "\u255D",
      "```",
    ].join("\n");

    const summary = [
      `> **Severity** ${sev} \u00B7 **Confidence** ${conf} \u00B7 **Query Fidelity** ${fid}  `,
      `> **Platform** ${plat} \u00B7 **Threat Actor** ${actor} \u00B7 **Status** ${status}  `,
      `> Archived from [#${issueNumber}](${issueUrl}) on ${closedAt}`,
    ].join("\n");

    // Body: emit each field under a divider, skip empty / "_No response_" entries,
    // compress the Tactics checkbox block to just ticked items.
    const bodyChunks = [];
    for (const label of order) {
      let value = fieldValue(map, label);
      if (value === null) continue;
      if (label.toLowerCase().includes("tactic") && value.includes("- [")) {
        value = filterCheckedOnly(value);
        if (!value) continue;
      }
      bodyChunks.push(`---\n\n### ${label}\n\n${value}`);
    }

    const footer =
      `---\n\n_Auto-archived by \`updateThreatHunt.js\` from issue ` +
      `[#${issueNumber}](${issueUrl}) on ${closedAt}. The issue is the source of truth; ` +
      `this file is regenerated on re-close._`;

    return [banner, "", summary, "", bodyChunks.join("\n\n"), "", footer, ""].join("\n");
  }

  async function getRepoInfo() {
    const [owner, repo] = process.env.GITHUB_REPOSITORY.split("/");
    return { owner, repo };
  }

  async function upsertFile({ techniqueId, issueTitle, issueNumber, content }) {
    const { owner, repo } = await getRepoInfo();
    const titleSlug = generateSlug(issueTitle);
    const fileName = `${techniqueId}-${titleSlug}-${issueNumber}.md`;
    const filePath = path.posix.join("techniques", techniqueId, fileName);

    // Write locally (optional) just for artifact/debug; API commit is what matters.
    const localDir = path.dirname(filePath);
    if (!fs.existsSync(localDir)) fs.mkdirSync(localDir, { recursive: true });
    fs.writeFileSync(filePath, content, "utf8");

    let fileExists = false;
    let sha;

    try {
      const { data } = await octokit.repos.getContent({
        owner, repo, path: filePath, ref: "main"       // <-- ref, not branch
      });
      if (!Array.isArray(data)) {
        fileExists = true;
        sha = data.sha;
        console.log("Remote file exists; will update:", filePath);
      } else {
        // path is a directory (shouldn’t happen with this path)
        console.log("Path resolved to a directory unexpectedly:", filePath);
      }
    } catch (err) {
      if (err.status === 404) {
        console.log("Remote file not found; will create:", filePath);
      } else {
        console.error("getContent error:", err);
        throw err;
      }
    }

    const commitMessage = `Add completed threat hunt #${issueNumber} - ${issueTitle} to ${techniqueId}`;
    const params = {
      owner,
      repo,
      path: filePath,
      message: commitMessage,
      content: Buffer.from(content, "utf8").toString("base64"),
      branch: "main",
      committer: { name: "github-actions[bot]", email: "41898282+github-actions[bot]@users.noreply.github.com" },
      author: { name: "github-actions[bot]", email: "41898282+github-actions[bot]@users.noreply.github.com" },
      sha: fileExists ? sha : undefined
    };

    await octokit.repos.createOrUpdateFileContents(params);
    console.log(`Threat hunt file created/updated: ${fileName}`);
  }

  async function resolveIssueFromProjectsV2(event) {
    // projects_v2_item event payload shape can be:
    // event.projects_v2_item (or event.project_item) depending on trigger
    const item = event.projects_v2_item || event.project_item || event.item;
    if (!item) return null;

    // Only proceed if item is linked to an Issue
    const contentNodeId = item?.content_node_id || item?.content?.node_id;
    if (!contentNodeId) return null;

    // We may need to confirm the “status” field is Completed/Done.
    // Use GraphQL to pull the project fields & linked issue details.
    const query = `
      query($id: ID!) {
        node(id: $id) {
          ... on ProjectV2Item {
            id
            content {
              __typename
              ... on Issue {
                id
                number
                title
                state
                body
                repository { name owner { login } }
              }
            }
            fieldValues(first: 50) {
              nodes {
                ... on ProjectV2ItemFieldSingleSelectValue {
                  name
                  field { ... on ProjectV2FieldCommon { name } }
                }
              }
            }
          }
        }
      }`;

    const data = await gql(query, { id: item.node_id || item.id });
    const node = data?.node;
    if (!node || node.content?.__typename !== "Issue") return null;

    const issue = node.content;
    // Find a “Status” (or similar) single-select with value "Done" or "Completed"
    const status = node.fieldValues?.nodes?.find(
      v => v?.field?.name?.toLowerCase() === "status"
    )?.name?.toLowerCase();

    const isCompleted = ["done", "completed", "complete"].includes(status || "");

    return {
      owner: issue.repository.owner.login,
      repo: issue.repository.name,
      number: issue.number,
      title: issue.title,
      body: issue.body || "",
      state: issue.state,               // OPEN/CLOSED
      isCompletedInProject: isCompleted
    };
  }

  async function run() {
    const eventName = process.env.GITHUB_EVENT_NAME;
    const eventPath = process.env.GITHUB_EVENT_PATH;
    const event = JSON.parse(fs.readFileSync(eventPath, "utf8"));

    console.log("Event name:", eventName);

    let issuePayload = null;
    let shouldProcess = false;

    if (eventName === "issues") {
      // Triggered on issue events
      if (event.action === "closed" && event.issue?.state === "closed") {
        issuePayload = {
          number: event.issue.number,
          title: event.issue.title,
          body: event.issue.body || "",
          state: "closed"
        };
        shouldProcess = true;
      }
    } else if (eventName === "projects_v2_item") {
      // Triggered when a project item changes (e.g., status → Completed)
      const resolved = await resolveIssueFromProjectsV2(event);
      if (resolved && resolved.isCompletedInProject) {
        // Optional: require closed state too — or accept Completed lane as signal
        issuePayload = {
          number: resolved.number,
          title: resolved.title,
          body: resolved.body,
          state: resolved.state
        };
        shouldProcess = true;
      }
    } else {
      console.log("Not an issues or projects_v2_item event; skipping.");
    }

    if (!shouldProcess || !issuePayload) {
      console.log("Event does not match criteria (closed/Completed).");
      return;
    }

    const techniqueId =
      extractTechniqueId(issuePayload.title) ||
      extractTechniqueId(issuePayload.body);
    if (!techniqueId) {
      console.log("No technique ID (T#### or T####.###) found in issue title or body; skipping.");
      return;
    }

    const closedAt = new Date().toISOString().slice(0, 10);
    const content = buildArchive({
      issueTitle:  issuePayload.title,
      issueNumber: issuePayload.number,
      issueBody:   issuePayload.body,
      techniqueId,
      closedAt,
      repoSlug:    process.env.GITHUB_REPOSITORY,
    });

    await upsertFile({
      techniqueId,
      issueTitle: issuePayload.title,
      issueNumber: issuePayload.number,
      content
    });
  }

  run().catch((error) => {
    console.error("Fatal error:", error);
    // Helpful hint for debugging in Actions
    console.error("Set ACTIONS_STEP_DEBUG=true to get more logs.");
    process.exit(1);
  });
})();

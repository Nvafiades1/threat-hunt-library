/**
 * Enrich a Threat Hunt issue with MITRE ATT&CK threat-actor data.
 *
 * Triggered on issue open / edit. Reads the "Threat Actor" form field, looks
 * the actor (or its aliases) up in the MITRE Enterprise ATT&CK STIX bundle,
 * commits a full profile to threat-actor-profiles/, and posts a concise
 * summary comment on the issue linking to that profile.
 *
 * Skips if a previous enrichment comment is already present (marker check).
 * Multiple actors can be supplied comma-separated.
 */

(async () => {
  const { Octokit } = await import("@octokit/rest");
  const fetch       = (await import("node-fetch")).default;
  const fs          = require("fs");

  const STIX_URL    = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
  const MARKER      = "<!-- threat-actor-enrichment:v1 -->";
  const PROFILE_DIR = "threat-actor-profiles";

  const TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
  ];
  const NONE_VALUES = new Set(["", "_no response_", "n/a", "none", "tbd"]);

  // ── helpers ────────────────────────────────────────────────────────────
  function tacticDisplay(p) {
    return p.split("-").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
  }

  function parseField(body, label) {
    if (!body) return null;
    const lines = body.split("\n");
    const sectionRe = /^###\s+(.+?)\s*$/;
    const stopRe = /^(?:###\s+|\*\*[^*:]+:\*\*|[-=_*]{3,}\s*$)/;
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(sectionRe);
      if (m && m[1].trim().toLowerCase() === label.toLowerCase()) {
        const out = [];
        for (let j = i + 1; j < lines.length; j++) {
          if (stopRe.test(lines[j])) break;
          out.push(lines[j]);
        }
        const v = out.join("\n").trim();
        return NONE_VALUES.has(v.toLowerCase()) ? null : v;
      }
    }
    return null;
  }

  function findActor(stix, query) {
    const q = query.toLowerCase();
    for (const o of stix.objects) {
      if (o.type !== "intrusion-set") continue;
      if (o.revoked || o.x_mitre_deprecated) continue;
      if ((o.name || "").toLowerCase() === q) return o;
      if ((o.aliases || []).some(a => a.toLowerCase() === q)) return o;
    }
    return null;
  }

  function suggest(query, stix, limit = 5) {
    const q = query.toLowerCase();
    const out = [];
    const seen = new Set();
    for (const o of stix.objects) {
      if (o.type !== "intrusion-set") continue;
      if (o.revoked || o.x_mitre_deprecated) continue;
      const names = [o.name, ...(o.aliases || [])];
      const hit = names.some(n => {
        const ln = (n || "").toLowerCase();
        return ln && (ln.includes(q) || q.includes(ln));
      });
      if (hit && !seen.has(o.id)) {
        seen.add(o.id);
        const mid = (o.external_references || [])
          .find(r => r.source_name === "mitre-attack")?.external_id;
        out.push({ name: o.name, mitreId: mid });
        if (out.length >= limit) break;
      }
    }
    return out;
  }

  function gatherUses(stix, actor) {
    const usesRels = stix.objects.filter(o =>
      o.type === "relationship" &&
      o.relationship_type === "uses" &&
      o.source_ref === actor.id
    );
    const targetIds = new Set(usesRels.map(r => r.target_ref));
    const ttps = stix.objects.filter(o =>
      targetIds.has(o.id) &&
      o.type === "attack-pattern" &&
      !o.revoked && !o.x_mitre_deprecated
    );
    const tools = stix.objects.filter(o =>
      targetIds.has(o.id) &&
      (o.type === "malware" || o.type === "tool") &&
      !o.revoked && !o.x_mitre_deprecated
    );
    const byTactic = {};
    const tacticSet = new Set();
    for (const t of ttps) {
      const tid = (t.external_references || [])
        .find(r => r.source_name === "mitre-attack")?.external_id;
      if (!tid) continue;
      const phases = (t.kill_chain_phases || [])
        .filter(kc => kc.kill_chain_name === "mitre-attack");
      for (const p of phases) {
        tacticSet.add(p.phase_name);
        (byTactic[p.phase_name] ||= []).push({ id: tid, name: t.name });
      }
    }
    return { ttps, tools, byTactic, tactics: tacticSet };
  }

  function profileFilename(actor) {
    const mid = (actor.external_references || [])
      .find(r => r.source_name === "mitre-attack")?.external_id || "GXXXX";
    const slug = (actor.name || "").toLowerCase()
      .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    return `${mid}-${slug}.md`;
  }

  function buildProfile(stix, actor, version) {
    const ext = (actor.external_references || []).find(r => r.source_name === "mitre-attack");
    const mid = ext?.external_id || "—";
    const url = ext?.url;
    const aliases = (actor.aliases || []).filter(a => a !== actor.name);
    const { ttps, tools, byTactic } = gatherUses(stix, actor);

    const lines = [];
    lines.push(`# ${actor.name}`);
    lines.push("");
    lines.push(`**MITRE ID:** \`${mid}\`  `);
    if (aliases.length) lines.push(`**Aliases:** ${aliases.map(a => `\`${a}\``).join(", ")}  `);
    if (url) lines.push(`**MITRE Reference:** [${url}](${url})`);
    lines.push("");
    lines.push("## Overview");
    lines.push("");
    lines.push((actor.description || "_No description available._").trim());
    lines.push("");

    if (tools.length) {
      lines.push(`## Tools & Software (${tools.length})`);
      lines.push("");
      for (const t of [...tools].sort((a, b) => (a.name || "").localeCompare(b.name || ""))) {
        const e = (t.external_references || []).find(r => r.source_name === "mitre-attack");
        const tid = e?.external_id;
        const turl = e?.url;
        const label = turl ? `[${t.name}](${turl})` : t.name;
        lines.push(`- ${label}${tid ? ` — \`${tid}\`` : ""} _(${t.type})_`);
      }
      lines.push("");
    }

    if (ttps.length) {
      lines.push(`## Techniques (${ttps.length} TTPs)`);
      lines.push("");
      for (const phase of TACTIC_ORDER) {
        if (!byTactic[phase]) continue;
        const items = [...byTactic[phase]].sort((a, b) => a.id.localeCompare(b.id));
        lines.push(`### ${tacticDisplay(phase)}`);
        lines.push("");
        for (const it of items) lines.push(`- \`${it.id}\` — ${it.name}`);
        lines.push("");
      }
    }

    lines.push("---");
    lines.push("");
    lines.push(
      `_Auto-generated from MITRE ATT&CK Enterprise v${version} on ` +
      `${new Date().toISOString().slice(0, 10)}. Do not edit — regenerated when ` +
      `MITRE updates this group's data._`
    );
    lines.push("");
    return lines.join("\n");
  }

  function buildComment(stix, matches, unmatched, profileLinks, version) {
    const out = [MARKER];

    if (!matches.length) {
      out.push("### Threat Actor Enrichment");
      out.push("");
      out.push(`Couldn't find a MITRE ATT&CK group matching: ${unmatched.map(q => `**${q}**`).join(", ")}`);
      out.push("");
      const sugg = [];
      for (const q of unmatched) {
        for (const x of suggest(q, stix)) {
          if (!sugg.some(a => a.name === x.name)) sugg.push(x);
        }
      }
      if (sugg.length) {
        out.push("Did you mean one of these?");
        for (const x of sugg.slice(0, 5)) {
          out.push(`- **${x.name}**${x.mitreId ? ` (\`${x.mitreId}\`)` : ""}`);
        }
        out.push("");
      }
      out.push("_Browse all groups: https://attack.mitre.org/groups/_");
      return out.join("\n");
    }

    out.push("## Threat Actor Enrichment");
    out.push("");
    for (const m of matches) {
      const ext = (m.actor.external_references || []).find(r => r.source_name === "mitre-attack");
      const mid = ext?.external_id;
      const aliases = (m.actor.aliases || []).filter(a => a !== m.actor.name);
      const link = profileLinks.find(p => p.actor.id === m.actor.id);
      const { ttps, tools, tactics } = gatherUses(stix, m.actor);

      out.push(`### ${m.actor.name}${mid ? ` (\`${mid}\`)` : ""}`);
      out.push("");
      if (aliases.length) {
        const shown = aliases.slice(0, 8).map(a => `\`${a}\``).join(", ");
        const extra = aliases.length > 8 ? ` _+${aliases.length - 8} more_` : "";
        out.push(`**Aliases:** ${shown}${extra}`);
        out.push("");
      }
      if (m.actor.description) {
        const para = m.actor.description.split("\n\n")[0];
        const truncated = para.length > 600 ? para.slice(0, 600).trimEnd() + "…" : para;
        out.push(truncated);
        out.push("");
      }
      out.push(
        `**${ttps.length} TTPs** across **${tactics.size} tactics** \u00B7 ` +
        `**${tools.length} tools/malware**`
      );
      out.push("");
      if (link) {
        out.push(`📄 **[Full profile in repo →](../../blob/main/${link.filepath})**`);
        out.push("");
      }
    }

    if (unmatched.length) {
      out.push("---");
      out.push(`_Could not match: ${unmatched.map(q => `**${q}**`).join(", ")}_`);
      out.push("");
    }
    out.push("---");
    out.push(
      `_MITRE ATT&CK Enterprise v${version} \u00B7 Auto-enriched on ` +
      `${new Date().toISOString().slice(0, 10)}. Verify with primary sources._`
    );
    return out.join("\n");
  }

  async function commitProfile(octokit, owner, repo, filepath, content, version, actorName) {
    let attempt = 0;
    while (attempt < 2) {
      attempt++;
      let sha;
      try {
        const { data } = await octokit.repos.getContent({ owner, repo, path: filepath, ref: "main" });
        if (!Array.isArray(data)) {
          if (Buffer.from(data.content, "base64").toString("utf8") === content) {
            console.log(`Profile unchanged: ${filepath}`);
            return;
          }
          sha = data.sha;
        }
      } catch (e) {
        if (e.status !== 404) throw e;
      }
      try {
        await octokit.repos.createOrUpdateFileContents({
          owner, repo, path: filepath,
          message: `Profile threat actor ${actorName} from ATT&CK v${version} [skip ci]`,
          content: Buffer.from(content, "utf8").toString("base64"),
          branch: "main",
          committer: { name: "github-actions[bot]", email: "41898282+github-actions[bot]@users.noreply.github.com" },
          author:    { name: "github-actions[bot]", email: "41898282+github-actions[bot]@users.noreply.github.com" },
          sha,
        });
        console.log(`Committed profile: ${filepath}`);
        return;
      } catch (e) {
        if (e.status === 409 && attempt < 2) { console.log("conflict on commit, retrying..."); continue; }
        throw e;
      }
    }
  }

  // ── main ────────────────────────────────────────────────────────────────
  const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN, request: { fetch } });
  const [owner, repo] = process.env.GITHUB_REPOSITORY.split("/");

  const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"));
  const issueNumber = event.issue?.number;
  if (!issueNumber) { console.log("No issue in event payload"); return; }

  // Fetch latest issue body (event payload may be stale on edited)
  const { data: issue } = await octokit.issues.get({ owner, repo, issue_number: issueNumber });
  if (issue.state !== "open") { console.log(`Issue #${issueNumber} is ${issue.state}; skipping`); return; }

  // Skip if marker comment already exists
  const comments = await octokit.paginate(octokit.issues.listComments, {
    owner, repo, issue_number: issueNumber, per_page: 100,
  });
  if (comments.some(c => (c.body || "").includes(MARKER))) {
    console.log(`Marker comment already on #${issueNumber}; skipping`);
    return;
  }

  const actorRaw = parseField(issue.body || "", "Threat Actor");
  if (!actorRaw) { console.log("No Threat Actor field populated; skipping"); return; }

  const queries = actorRaw.split(/[,;\/]+/).map(s => s.trim()).filter(Boolean);
  if (!queries.length) return;

  console.log(`Looking up ${queries.length} actor(s): ${queries.join(", ")}`);
  const r = await fetch(STIX_URL);
  if (!r.ok) throw new Error(`STIX fetch failed: ${r.status}`);
  const stix = await r.json();
  const collection = stix.objects.find(o => o.type === "x-mitre-collection");
  const version = collection?.x_mitre_version || "unknown";

  const matches = [];
  const unmatched = [];
  for (const q of queries) {
    const found = findActor(stix, q);
    if (found && !matches.some(x => x.actor.id === found.id)) {
      matches.push({ query: q, actor: found });
    } else if (!found) {
      unmatched.push(q);
    }
  }
  console.log(`Matched: ${matches.length} \u00B7 Unmatched: ${unmatched.length}`);

  const profileLinks = [];
  for (const m of matches) {
    const profile  = buildProfile(stix, m.actor, version);
    const filename = profileFilename(m.actor);
    const filepath = `${PROFILE_DIR}/${filename}`;
    await commitProfile(octokit, owner, repo, filepath, profile, version, m.actor.name);
    profileLinks.push({ actor: m.actor, filepath });
  }

  const body = buildComment(stix, matches, unmatched, profileLinks, version);
  await octokit.issues.createComment({ owner, repo, issue_number: issueNumber, body });
  console.log(`Posted enrichment comment on #${issueNumber}`);
})().catch(e => { console.error("Fatal:", e); process.exit(1); });

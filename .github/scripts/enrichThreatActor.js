/**
 * Enrich a Threat Hunt issue with threat-actor / campaign data.
 *
 * On issue open or edit, read the "Threat Actor" form field, resolve every
 * comma-separated query through three tiers:
 *
 *   1. MITRE ATT&CK intrusion-set (primary — gives TTPs + tools)
 *   2. MITRE ATT&CK campaign       (e.g., SolarWinds Compromise)
 *   3. MISP threat-actor galaxy    — broader alias coverage. If the matched
 *      MISP entry references a MITRE group via its meta.refs URLs, resolve
 *      to that MITRE group so we still get TTPs. Otherwise fall back to a
 *      MISP-only profile (description, country, motive, references).
 *
 * For each resolution, commit a self-contained profile to
 * threat-actor-profiles/ and post (or update) a single summary comment on
 * the issue. The comment carries a hidden marker tagging the canonical IDs
 * it covered last time, so a subsequent edit that changes the actor list
 * triggers an in-place re-enrichment instead of duplicating comments.
 */

(async () => {
  const { Octokit } = await import("@octokit/rest");
  const fetch       = (await import("node-fetch")).default;
  const fs          = require("fs");

  const STIX_URL    = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
  const MISP_URL    = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json";
  const PROFILE_DIR = "threat-actor-profiles";
  const MARKER_RE   = /<!--\s*threat-actor-enrichment:v(\d+)(?:\s+ids=([^\s>]*))?\s*-->/;
  const FIELD_LABELS = ["Threat Actor", "Threat Actor or Campaign Name"];

  const TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
  ];
  const NONE_VALUES = new Set(["", "_no response_", "n/a", "none", "tbd"]);

  // ── helpers ─────────────────────────────────────────────────────────────
  const tacticDisplay = p =>
    p.split("-").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");

  const slug = s => (s || "").toLowerCase()
    .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

  // Strip MITRE-style "(Citation: ...)" markers and collapse whitespace
  const cleanDesc = s => (s || "")
    .replace(/\(Citation:[^)]*\)/g, "")
    .replace(/[ \t]+/g, " ")
    .trim();

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

  function findActorField(body) {
    for (const label of FIELD_LABELS) {
      const v = parseField(body, label);
      if (v) return v;
    }
    return null;
  }

  // ── resolution ──────────────────────────────────────────────────────────
  function resolveQuery(query, stix, misp) {
    const q = query.toLowerCase();

    // 1. MITRE intrusion-set
    for (const o of stix.objects) {
      if (o.type !== "intrusion-set" || o.revoked || o.x_mitre_deprecated) continue;
      if ((o.name || "").toLowerCase() === q ||
          (o.aliases || []).some(a => (a || "").toLowerCase() === q)) {
        return { kind: "mitre-group", actor: o };
      }
    }

    // 2. MITRE campaign
    for (const o of stix.objects) {
      if (o.type !== "campaign" || o.revoked) continue;
      if ((o.name || "").toLowerCase() === q ||
          (o.aliases || []).some(a => (a || "").toLowerCase() === q)) {
        return { kind: "mitre-campaign", actor: o };
      }
    }

    // 3. MISP threat-actor galaxy
    for (const cluster of (misp?.values || [])) {
      const names = [cluster.value, ...(cluster.meta?.synonyms || [])];
      if (!names.some(n => n && n.toLowerCase() === q)) continue;

      const refs = cluster.meta?.refs || [];
      const mitreGroupRef = refs.find(r => /attack\.mitre\.org\/groups\/G\d+/.test(r));
      if (mitreGroupRef) {
        const mid = mitreGroupRef.match(/G\d+/)[0];
        const actor = stix.objects.find(o =>
          o.type === "intrusion-set" && !o.revoked && !o.x_mitre_deprecated &&
          (o.external_references || []).some(r => r.external_id === mid)
        );
        if (actor) return { kind: "mitre-group", actor, viaMISP: cluster };
      }
      return { kind: "misp-only", cluster };
    }

    return null;
  }

  function suggest(query, stix, misp, limit = 5) {
    const q = query.toLowerCase();
    const out = [];
    const seen = new Set();
    const consider = (name, mitreId, source) => {
      const key = `${source}:${name}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ name, mitreId, source });
    };

    for (const o of stix.objects) {
      if (o.type !== "intrusion-set" || o.revoked || o.x_mitre_deprecated) continue;
      const names = [o.name, ...(o.aliases || [])];
      if (names.some(n => n && (n.toLowerCase().includes(q) || q.includes(n.toLowerCase())))) {
        const mid = (o.external_references || [])
          .find(r => r.source_name === "mitre-attack")?.external_id;
        consider(o.name, mid, "mitre-group");
        if (out.length >= limit) return out;
      }
    }
    for (const cluster of (misp?.values || [])) {
      const names = [cluster.value, ...(cluster.meta?.synonyms || [])];
      if (names.some(n => n && (n.toLowerCase().includes(q) || q.includes(n.toLowerCase())))) {
        consider(cluster.value, null, "misp");
        if (out.length >= limit) return out;
      }
    }
    return out;
  }

  function canonicalIdFor(resolution) {
    if (resolution.kind === "mitre-group") {
      return (resolution.actor.external_references || [])
        .find(r => r.source_name === "mitre-attack")?.external_id || `mitre:${slug(resolution.actor.name)}`;
    }
    if (resolution.kind === "mitre-campaign") {
      return (resolution.actor.external_references || [])
        .find(r => r.source_name === "mitre-attack")?.external_id || `campaign:${slug(resolution.actor.name)}`;
    }
    if (resolution.kind === "misp-only") {
      return `misp:${slug(resolution.cluster.value)}`;
    }
    return null;
  }

  function profileFilenameFor(resolution) {
    const cid = canonicalIdFor(resolution);
    let name;
    if (resolution.kind === "mitre-group" || resolution.kind === "mitre-campaign") {
      name = resolution.actor.name;
    } else {
      name = resolution.cluster.value;
    }
    return `${cid.replace(/[^A-Za-z0-9_-]/g, "-")}-${slug(name)}.md`;
  }

  // ── relationship walking (MITRE) ───────────────────────────────────────
  function gatherUses(stix, mitreObj) {
    const usesRels = stix.objects.filter(o =>
      o.type === "relationship" &&
      o.relationship_type === "uses" &&
      o.source_ref === mitreObj.id
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

  function attributedActor(stix, campaign) {
    const rel = stix.objects.find(o =>
      o.type === "relationship" &&
      o.relationship_type === "attributed-to" &&
      o.source_ref === campaign.id
    );
    if (!rel) return null;
    return stix.objects.find(o =>
      o.id === rel.target_ref && o.type === "intrusion-set"
    );
  }

  // ── markdown builders ───────────────────────────────────────────────────
  function buildGroupProfile(stix, actor, version, viaMISP) {
    const ext = (actor.external_references || []).find(r => r.source_name === "mitre-attack");
    const mid = ext?.external_id || "—";
    const url = ext?.url;
    const aliases = (actor.aliases || []).filter(a => a !== actor.name);
    const { ttps, tools, byTactic } = gatherUses(stix, actor);

    const lines = [];
    lines.push(`# ${actor.name}`);
    lines.push("");
    lines.push(`**Type:** Threat Group  `);
    lines.push(`**MITRE ID:** \`${mid}\`  `);
    if (aliases.length) lines.push(`**Aliases:** ${aliases.map(a => `\`${a}\``).join(", ")}  `);
    if (url) lines.push(`**MITRE Reference:** [${url}](${url})  `);
    if (viaMISP) lines.push(`**Matched via:** MISP threat-actor galaxy entry _${viaMISP.value}_`);
    lines.push("");
    lines.push("## Overview");
    lines.push("");
    lines.push(cleanDesc(actor.description) || "_No description available._");
    lines.push("");

    if (tools.length) {
      lines.push(`## Tools & Software (${tools.length})`);
      lines.push("");
      for (const t of [...tools].sort((a, b) => (a.name || "").localeCompare(b.name || ""))) {
        const e = (t.external_references || []).find(r => r.source_name === "mitre-attack");
        const label = e?.url ? `[${t.name}](${e.url})` : t.name;
        lines.push(`- ${label}${e?.external_id ? ` — \`${e.external_id}\`` : ""} _(${t.type})_`);
      }
      lines.push("");
    }

    if (ttps.length) {
      lines.push(`## Techniques (${ttps.length} TTPs)`);
      lines.push("");
      for (const phase of TACTIC_ORDER) {
        if (!byTactic[phase]) continue;
        lines.push(`### ${tacticDisplay(phase)}`);
        lines.push("");
        for (const it of [...byTactic[phase]].sort((a, b) => a.id.localeCompare(b.id))) {
          lines.push(`- \`${it.id}\` — ${it.name}`);
        }
        lines.push("");
      }
    }

    lines.push("---");
    lines.push("");
    lines.push(
      `_Auto-generated from MITRE ATT&CK Enterprise v${version} on ` +
      `${new Date().toISOString().slice(0, 10)}. ` +
      `Regenerated when MITRE updates this group's data._`
    );
    lines.push("");
    return lines.join("\n");
  }

  function buildCampaignProfile(stix, campaign, version) {
    const ext = (campaign.external_references || []).find(r => r.source_name === "mitre-attack");
    const cid = ext?.external_id || "—";
    const url = ext?.url;
    const aliases = (campaign.aliases || []).filter(a => a !== campaign.name);
    const { ttps, tools, byTactic } = gatherUses(stix, campaign);
    const actor = attributedActor(stix, campaign);

    const lines = [];
    lines.push(`# ${campaign.name}`);
    lines.push("");
    lines.push(`**Type:** Campaign  `);
    lines.push(`**MITRE ID:** \`${cid}\`  `);
    if (aliases.length) lines.push(`**Aliases:** ${aliases.map(a => `\`${a}\``).join(", ")}  `);
    if (campaign.first_seen) lines.push(`**First seen:** ${campaign.first_seen}  `);
    if (campaign.last_seen)  lines.push(`**Last seen:** ${campaign.last_seen}  `);
    if (actor) {
      const aExt = (actor.external_references || []).find(r => r.source_name === "mitre-attack");
      lines.push(`**Attributed to:** [${actor.name}](${aExt?.url || "#"}) (\`${aExt?.external_id || "—"}\`)  `);
    }
    if (url) lines.push(`**MITRE Reference:** [${url}](${url})`);
    lines.push("");
    lines.push("## Overview");
    lines.push("");
    lines.push(cleanDesc(campaign.description) || "_No description available._");
    lines.push("");

    if (tools.length) {
      lines.push(`## Tools & Software (${tools.length})`);
      lines.push("");
      for (const t of [...tools].sort((a, b) => (a.name || "").localeCompare(b.name || ""))) {
        const e = (t.external_references || []).find(r => r.source_name === "mitre-attack");
        const label = e?.url ? `[${t.name}](${e.url})` : t.name;
        lines.push(`- ${label}${e?.external_id ? ` — \`${e.external_id}\`` : ""} _(${t.type})_`);
      }
      lines.push("");
    }

    if (ttps.length) {
      lines.push(`## Techniques (${ttps.length} TTPs)`);
      lines.push("");
      for (const phase of TACTIC_ORDER) {
        if (!byTactic[phase]) continue;
        lines.push(`### ${tacticDisplay(phase)}`);
        lines.push("");
        for (const it of [...byTactic[phase]].sort((a, b) => a.id.localeCompare(b.id))) {
          lines.push(`- \`${it.id}\` — ${it.name}`);
        }
        lines.push("");
      }
    }

    lines.push("---");
    lines.push("");
    lines.push(
      `_Auto-generated from MITRE ATT&CK Enterprise v${version} on ` +
      `${new Date().toISOString().slice(0, 10)}._`
    );
    lines.push("");
    return lines.join("\n");
  }

  function buildMISPOnlyProfile(cluster) {
    const meta = cluster.meta || {};
    const synonyms = meta.synonyms || [];
    const lines = [];
    lines.push(`# ${cluster.value}`);
    lines.push("");
    lines.push(`**Type:** Threat Actor (MISP-only — not in MITRE ATT&CK)  `);
    lines.push(`**MISP UUID:** \`${cluster.uuid}\`  `);
    if (synonyms.length) lines.push(`**Aliases:** ${synonyms.map(a => `\`${a}\``).join(", ")}  `);
    if (meta.country) lines.push(`**Country:** ${meta.country}  `);
    if (meta["cfr-suspected-state-sponsor"]) lines.push(`**Suspected sponsor:** ${meta["cfr-suspected-state-sponsor"]}  `);
    if (meta["cfr-target-category"]?.length) lines.push(`**Target sectors:** ${(meta["cfr-target-category"] || []).join(", ")}  `);
    if (meta["cfr-suspected-victims"]?.length) lines.push(`**Suspected victims:** ${(meta["cfr-suspected-victims"] || []).join(", ")}  `);
    if (meta["targeted-sector"]?.length) lines.push(`**Targeted sectors:** ${(meta["targeted-sector"] || []).join(", ")}  `);
    if (meta["motive"]?.length) lines.push(`**Motive:** ${[].concat(meta["motive"]).join(", ")}  `);
    lines.push("");
    lines.push("## Overview");
    lines.push("");
    lines.push(cleanDesc(cluster.description) || "_No description provided in MISP._");
    lines.push("");

    if ((meta.refs || []).length) {
      lines.push("## References");
      lines.push("");
      for (const ref of meta.refs) lines.push(`- ${ref}`);
      lines.push("");
    }

    lines.push("---");
    lines.push("");
    lines.push(
      `_Auto-generated from the MISP threat-actor galaxy on ` +
      `${new Date().toISOString().slice(0, 10)}. This actor isn't tracked by MITRE ATT&CK, ` +
      `so no TTPs are available — investigate via the references above._`
    );
    lines.push("");
    return lines.join("\n");
  }

  function buildProfile(stix, resolution, version) {
    if (resolution.kind === "mitre-group")    return buildGroupProfile(stix, resolution.actor, version, resolution.viaMISP);
    if (resolution.kind === "mitre-campaign") return buildCampaignProfile(stix, resolution.actor, version);
    if (resolution.kind === "misp-only")      return buildMISPOnlyProfile(resolution.cluster);
    throw new Error(`Unknown resolution kind: ${resolution.kind}`);
  }

  function resolutionSummary(stix, resolution, profileLink) {
    const lines = [];
    if (resolution.kind === "mitre-group") {
      const a = resolution.actor;
      const ext = (a.external_references || []).find(r => r.source_name === "mitre-attack");
      const mid = ext?.external_id;
      const aliases = (a.aliases || []).filter(x => x !== a.name);
      const { ttps, tools, tactics } = gatherUses(stix, a);
      lines.push(`### ${a.name}${mid ? ` (\`${mid}\`)` : ""} _(MITRE Group${resolution.viaMISP ? ` via MISP \`${resolution.viaMISP.value}\`` : ""})_`);
      lines.push("");
      if (aliases.length) {
        const shown = aliases.slice(0, 8).map(x => `\`${x}\``).join(", ");
        const extra = aliases.length > 8 ? ` _+${aliases.length - 8} more_` : "";
        lines.push(`**Aliases:** ${shown}${extra}`);
        lines.push("");
      }
      const desc = cleanDesc(a.description).split("\n\n")[0];
      if (desc) {
        const trunc = desc.length > 600 ? desc.slice(0, 600).trimEnd() + "…" : desc;
        lines.push(trunc);
        lines.push("");
      }
      lines.push(
        `**${ttps.length} TTPs** across **${tactics.size} tactics** \u00B7 ` +
        `**${tools.length} tools/malware**`
      );
    } else if (resolution.kind === "mitre-campaign") {
      const c = resolution.actor;
      const ext = (c.external_references || []).find(r => r.source_name === "mitre-attack");
      const cid = ext?.external_id;
      const aliases = (c.aliases || []).filter(x => x !== c.name);
      const { ttps, tools, tactics } = gatherUses(stix, c);
      const a = attributedActor(stix, c);
      lines.push(`### ${c.name}${cid ? ` (\`${cid}\`)` : ""} _(MITRE Campaign)_`);
      lines.push("");
      if (aliases.length) lines.push(`**Aliases:** ${aliases.slice(0, 6).map(x => `\`${x}\``).join(", ")}`);
      if (a) {
        const aExt = (a.external_references || []).find(r => r.source_name === "mitre-attack");
        lines.push(`**Attributed to:** \`${aExt?.external_id || a.name}\` ${a.name}`);
      }
      lines.push("");
      const desc = cleanDesc(c.description).split("\n\n")[0];
      if (desc) {
        const trunc = desc.length > 600 ? desc.slice(0, 600).trimEnd() + "…" : desc;
        lines.push(trunc);
        lines.push("");
      }
      lines.push(`**${ttps.length} TTPs** across **${tactics.size} tactics** \u00B7 **${tools.length} tools/malware**`);
    } else {
      const c = resolution.cluster;
      const meta = c.meta || {};
      const synonyms = meta.synonyms || [];
      lines.push(`### ${c.value} _(MISP-only — not in MITRE ATT&CK)_`);
      lines.push("");
      if (synonyms.length) {
        const shown = synonyms.slice(0, 8).map(x => `\`${x}\``).join(", ");
        const extra = synonyms.length > 8 ? ` _+${synonyms.length - 8} more_` : "";
        lines.push(`**Aliases:** ${shown}${extra}`);
        lines.push("");
      }
      const facts = [];
      if (meta.country) facts.push(`**Country:** ${meta.country}`);
      if (meta["cfr-suspected-state-sponsor"]) facts.push(`**Sponsor:** ${meta["cfr-suspected-state-sponsor"]}`);
      if (facts.length) { lines.push(facts.join(" \u00B7 ")); lines.push(""); }
      const desc = cleanDesc(c.description);
      if (desc) {
        const trunc = desc.length > 600 ? desc.slice(0, 600).trimEnd() + "…" : desc;
        lines.push(trunc);
        lines.push("");
      }
      lines.push(`_No TTP data — actor isn't tracked by MITRE ATT&CK._`);
    }
    if (profileLink) {
      lines.push("");
      lines.push(`📄 **[Full profile in repo →](../../blob/main/${profileLink})**`);
    }
    return lines.join("\n");
  }

  function buildComment(stix, matches, unmatched, profileLinks, canonicalIds, version) {
    const idTag = canonicalIds.length ? ` ids=${canonicalIds.join(",")}` : "";
    const marker = `<!-- threat-actor-enrichment:v2${idTag} -->`;
    const out = [marker];

    if (!matches.length) {
      out.push("### Threat Actor Enrichment");
      out.push("");
      out.push(`Couldn't find a threat actor or campaign matching: ${unmatched.map(q => `**${q}**`).join(", ")}`);
      out.push("");
      const sugg = [];
      for (const q of unmatched) {
        for (const x of suggest(q, stix, undefined)) {
          if (!sugg.some(a => a.name === x.name)) sugg.push(x);
        }
      }
      if (sugg.length) {
        out.push("Did you mean one of these?");
        for (const x of sugg.slice(0, 5)) {
          const tag = x.source === "mitre-group" ? `MITRE \`${x.mitreId || "G?"}\`` : "MISP";
          out.push(`- **${x.name}** _(${tag})_`);
        }
        out.push("");
      }
      out.push("_Browse MITRE Groups: https://attack.mitre.org/groups/_");
      return out.join("\n");
    }

    out.push("## Threat Actor Enrichment");
    out.push("");
    for (let i = 0; i < matches.length; i++) {
      const link = profileLinks.find(p => p.canonicalId === canonicalIds[i]);
      out.push(resolutionSummary(stix, matches[i], link?.filepath));
      out.push("");
    }

    if (unmatched.length) {
      out.push("---");
      out.push(`_Could not match: ${unmatched.map(q => `**${q}**`).join(", ")}_`);
      out.push("");
    }
    out.push("---");
    out.push(
      `_Sources: MITRE ATT&CK Enterprise v${version}${matches.some(m => m.kind === "misp-only" || m.viaMISP) ? " · MISP threat-actor galaxy" : ""} \u00B7 ` +
      `Auto-enriched on ${new Date().toISOString().slice(0, 10)}. Verify with primary sources._`
    );
    return out.join("\n");
  }

  // ── git committing ──────────────────────────────────────────────────────
  async function commitProfile(octokit, owner, repo, filepath, content, summary) {
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
          message: `Profile ${summary} [skip ci]`,
          content: Buffer.from(content, "utf8").toString("base64"),
          branch: "main",
          committer: { name: "github-actions[bot]", email: "41898282+github-actions[bot]@users.noreply.github.com" },
          author:    { name: "github-actions[bot]", email: "41898282+github-actions[bot]@users.noreply.github.com" },
          sha,
        });
        console.log(`Committed profile: ${filepath}`);
        return;
      } catch (e) {
        if (e.status === 409 && attempt < 2) { console.log("commit conflict, retrying..."); continue; }
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

  const { data: issue } = await octokit.issues.get({ owner, repo, issue_number: issueNumber });
  if (issue.state !== "open") { console.log(`Issue #${issueNumber} is ${issue.state}; skipping`); return; }

  const actorRaw = findActorField(issue.body || "");
  if (!actorRaw) { console.log("No Threat Actor field populated; skipping"); return; }
  const queries = actorRaw.split(/[,;\/]+/).map(s => s.trim()).filter(Boolean);
  if (!queries.length) return;

  const comments = await octokit.paginate(octokit.issues.listComments, {
    owner, repo, issue_number: issueNumber, per_page: 100,
  });
  let existingComment = null, prevIds = null;
  for (const c of comments) {
    const m = (c.body || "").match(MARKER_RE);
    if (m) {
      existingComment = c;
      if (m[1] === "2") prevIds = (m[2] || "").split(",").filter(Boolean);
      break;
    }
  }

  console.log(`Looking up ${queries.length} actor(s): ${queries.join(", ")}`);
  const [r1, r2] = await Promise.all([fetch(STIX_URL), fetch(MISP_URL)]);
  if (!r1.ok) throw new Error(`STIX fetch failed: ${r1.status}`);
  const stix = await r1.json();
  const misp = r2.ok ? await r2.json() : null;
  if (!r2.ok) console.log(`MISP fetch failed (${r2.status}); falling back to MITRE-only`);

  const collection = stix.objects.find(o => o.type === "x-mitre-collection");
  const version = collection?.x_mitre_version || "unknown";

  const matches = [];
  const unmatched = [];
  for (const q of queries) {
    const hit = resolveQuery(q, stix, misp);
    if (!hit) { unmatched.push(q); continue; }
    const cid = canonicalIdFor(hit);
    if (matches.some(m => canonicalIdFor(m) === cid)) continue;
    matches.push(hit);
  }
  const canonicalIds = matches.map(canonicalIdFor);
  console.log(`Matched: ${matches.length} (${canonicalIds.join(", ")}) \u00B7 Unmatched: ${unmatched.length}`);

  // Same set as last enrichment? Skip re-running.
  if (prevIds && setsEqual(prevIds, canonicalIds)) {
    console.log("Same actor set as previous enrichment; skipping");
    return;
  }

  const profileLinks = [];
  for (let i = 0; i < matches.length; i++) {
    const m = matches[i];
    const filename = profileFilenameFor(m);
    const filepath = `${PROFILE_DIR}/${filename}`;
    const content = buildProfile(stix, m, version);
    const niceName = m.kind === "misp-only" ? m.cluster.value : m.actor.name;
    await commitProfile(octokit, owner, repo, filepath, content,
      `${m.kind === "mitre-campaign" ? "campaign" : "threat actor"} ${niceName} from ATT&CK v${version}`);
    profileLinks.push({ canonicalId: canonicalIds[i], filepath });
  }

  const body = buildComment(stix, matches, unmatched, profileLinks, canonicalIds, version);

  if (existingComment) {
    await octokit.issues.updateComment({ owner, repo, comment_id: existingComment.id, body });
    console.log(`Updated existing enrichment comment ${existingComment.id} on #${issueNumber}`);
  } else {
    await octokit.issues.createComment({ owner, repo, issue_number: issueNumber, body });
    console.log(`Posted new enrichment comment on #${issueNumber}`);
  }

  function setsEqual(a, b) {
    if (a.length !== b.length) return false;
    const sa = new Set(a), sb = new Set(b);
    if (sa.size !== sb.size) return false;
    for (const x of sa) if (!sb.has(x)) return false;
    return true;
  }
})().catch(e => { console.error("Fatal:", e); process.exit(1); });

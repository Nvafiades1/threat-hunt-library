(async () => {
  // Dynamically import Octokit from "@octokit/rest" and node-fetch
  const { Octokit } = await import("@octokit/rest");
  const fetch = (await import("node-fetch")).default;
  const fs = require("fs");
  const path = require("path");

  // Initialize Octokit with the GitHub token and pass the fetch implementation
  const octokit = new Octokit({
    auth: process.env.GITHUB_TOKEN,
    request: { fetch }
  });

  async function run() {
    const eventPath = process.env.GITHUB_EVENT_PATH;
    const event = JSON.parse(fs.readFileSync(eventPath, "utf8"));

    // Check if the event is for an issue being closed.
    if (event.issue && event.issue.state === "closed") {
      const issue = event.issue;
      // Expect the issue body to include a line like "Technique: T1059"
      const techniqueMatch = issue.body.match(/Technique:\s*(T\d{4})/i);
      if (!techniqueMatch) {
        console.log("No technique ID found in issue body.");
        return;
      }
      const techniqueId = techniqueMatch[1].toUpperCase();
      const filePath = path.join("techniques", techniqueId, `threat-hunt-${issue.number}.md`);

      // Ensure the directory exists before writing the file.
      const dir = path.dirname(filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const content = `# Threat Hunt ${issue.number}\n\n**Title:** ${issue.title}\n\n**Details:**\n${issue.body}\n\n**Status:** Completed\n`;

      fs.writeFileSync(filePath, content);

      const commitMessage = `Add completed threat hunt #${issue.number} to ${techniqueId}`;
      await octokit.repos.createOrUpdateFileContents({
        owner: process.env.GITHUB_REPOSITORY.split("/")[0],
        repo: process.env.GITHUB_REPOSITORY.split("/")[1],
        path: filePath,
        message: commitMessage,
        content: Buffer.from(content).toString("base64"),
        committer: {
          name: "Nvafiades1",
          email: "nvafiades@protonmail.com",
        },
        author: {
          name: "Nvafiades1",
          email: "nvafiades@protonmail.com",
        },
      });

      console.log(`Threat hunt #${issue.number} added to ${techniqueId}`);
    } else {
      console.log("Event does not match criteria.");
    }
  }

  run().catch((error) => {
    console.error(error);
    process.exit(1);
  });
})();

(async () => {
  // Dynamically import Octokit from "@octokit/rest" and node-fetch
  const { Octokit } = await import("@octokit/rest");
  const fetch = (await import("node-fetch")).default;
  const fs = require("fs");
  const path = require("path");

  // Use BRANCH_NAME from environment if provided, otherwise default to "main"
  const defaultBranch = process.env.BRANCH_NAME || "main";
  console.log("Using branch:", defaultBranch);

  // Initialize Octokit with your PAT_TOKEN and pass the fetch implementation
  const octokit = new Octokit({
    auth: process.env.PAT_TOKEN,
    request: { fetch }
  });

  async function run() {
    const eventPath = process.env.GITHUB_EVENT_PATH;
    const event = JSON.parse(fs.readFileSync(eventPath, "utf8"));

    // Only proceed if the event is for an issue being closed.
    if (event.issue && event.issue.state === "closed") {
      const issue = event.issue;
      // Expect the issue body to include a line like "Technique: T1003"
      const techniqueMatch = issue.body.match(/Technique:\s*(T\d{4})/i);
      if (!techniqueMatch) {
        console.log("No technique ID found in issue body.");
        return;
      }
      const techniqueId = techniqueMatch[1].toUpperCase();
      const filePath = path.join("techniques", techniqueId, `threat-hunt-${issue.number}.md`);

      // Ensure local directory exists
      const localDir = path.dirname(filePath);
      if (!fs.existsSync(localDir)) {
        fs.mkdirSync(localDir, { recursive: true });
      }

      const content = `# Threat Hunt ${issue.number}\n\n**Title:** ${issue.title}\n\n**Details:**\n${issue.body}\n\n**Status:** Completed\n`;
      fs.writeFileSync(filePath, content);

      console.log("Attempting to update file at:", filePath);
      console.log("Target branch:", defaultBranch);

      // Check if the file exists remotely on the target branch
      let fileExists = false;
      let sha;
      try {
        const { data } = await octokit.repos.getContent({
          owner: process.env.GITHUB_REPOSITORY.split("/")[0],
          repo: process.env.GITHUB_REPOSITORY.split("/")[1],
          path: filePath,
          branch: defaultBranch
        });
        fileExists = true;
        sha = data.sha;
        console.log("File already exists; will update it.");
      } catch (error) {
        if (error.status === 404) {
          fileExists = false;
          console.log("File does not exist; will create it.");
        } else {
          throw error;
        }
      }

      const commitMessage = `Add completed threat hunt #${issue.number} to ${techniqueId}`;
      const params = {
        owner: process.env.GITHUB_REPOSITORY.split("/")[0],
        repo: process.env.GITHUB_REPOSITORY.split("/")[1],
        path: filePath,
        message: commitMessage,
        content: Buffer.from(content).toString("base64"),
        branch: defaultBranch,
        committer: {
          name: "Nvafiades1",
          email: "nvafiades@protonmail.com",
        },
        author: {
          name: "Nvafiades1",
          email: "nvafiades@protonmail.com",
        },
      };

      // If updating an existing file, include its SHA.
      if (fileExists) {
        params.sha = sha;
      }

      await octokit.repos.createOrUpdateFileContents(params);
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

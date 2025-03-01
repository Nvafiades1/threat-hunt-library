(async () => {
  // Dynamically import Octokit from "@octokit/rest" and node-fetch
  const { Octokit } = await import("@octokit/rest");
  const fetch = (await import("node-fetch")).default;
  const fs = require("fs");
  const path = require("path");

  // Initialize Octokit with your PAT_TOKEN and pass the fetch implementation
  const octokit = new Octokit({
    auth: process.env.PAT_TOKEN,
    request: { fetch }
  });

  async function run() {
    const eventPath = process.env.GITHUB_EVENT_PATH;
    const event = JSON.parse(fs.readFileSync(eventPath, "utf8"));

    // Check if the event is for an issue being closed.
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

      // Ensure local directory exists (for local file write, but this doesn't push to remote)
      const localDir = path.dirname(filePath);
      if (!fs.existsSync(localDir)) {
        fs.mkdirSync(localDir, { recursive: true });
      }

      const content = `# Threat Hunt ${issue.number}\n\n**Title:** ${issue.title}\n\n**Details:**\n${issue.body}\n\n**Status:** Completed\n`;
      fs.writeFileSync(filePath, content);

      // Debug: Log the file path and branch
      console.log("Attempting to update file at:", filePath);
      console.log("Target branch:", "main");

      // Check if the parent directory exists remotely by attempting to get its content
      let parentExists = true;
      try {
        await octokit.repos.getContent({
          owner: process.env.GITHUB_REPOSITORY.split("/")[0],
          repo: process.env.GITHUB_REPOSITORY.split("/")[1],
          path: path.join("techniques", techniqueId),
          branch: "main"
        });
        console.log(`Remote folder techniques/${techniqueId} exists.`);
      } catch (error) {
        if (error.status === 404) {
          parentExists = false;
          console.log(`Remote folder techniques/${techniqueId} not found. Creating placeholder file.`);
          // Create a placeholder README.md in the parent folder so it exists
          await octokit.repos.createOrUpdateFileContents({
            owner: process.env.GITHUB_REPOSITORY.split("/")[0],
            repo: process.env.GITHUB_REPOSITORY.split("/")[1],
            path: path.join("techniques", techniqueId, "README.md"),
            message: `Create placeholder for ${techniqueId} folder`,
            content: Buffer.from(`# ${techniqueId} Folder\n\nThis folder contains threat hunt files for technique ${techniqueId}.\n`).toString("base64"),
            branch: "main",
            committer: {
              name: "Nvafiades1",
              email: "nvafiades@protonmail.com",
            },
            author: {
              name: "Nvafiades1",
              email: "nvafiades@protonmail.com",
            },
          });
          console.log(`Placeholder file created in techniques/${techniqueId}`);
        } else {
          throw error;
        }
      }

      // Now, attempt to create or update the threat hunt file.
      const commitMessage = `Add completed threat hunt #${issue.number} to ${techniqueId}`;
      await octokit.repos.createOrUpdateFileContents({
        owner: process.env.GITHUB_REPOSITORY.split("/")[0],
        repo: process.env.GITHUB_REPOSITORY.split("/")[1],
        path: filePath,
        message: commitMessage,
        content: Buffer.from(content).toString("base64"),
        branch: "main",
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

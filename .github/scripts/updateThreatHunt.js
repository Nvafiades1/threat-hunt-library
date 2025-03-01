(async () => {
  // Dynamically import Octokit from "@octokit/rest" and node-fetch
  const { Octokit } = await import("@octokit/rest");
  const fetch = (await import("node-fetch")).default;
  const fs = require("fs");
  const path = require("path");

  // Function to generate a slug from a string (issue title)
  function generateSlug(title) {
    return title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-') // Replace non-alphanumeric characters with dashes
      .replace(/^-|-$/g, '');      // Remove leading and trailing dashes
  }

  // Use the PAT_TOKEN (not GITHUB_TOKEN) for authentication
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

      // Generate a slug from the issue title
      const titleSlug = generateSlug(issue.title);
      // Create the file name using the technique ID, title slug, and issue number to avoid collisions
      const fileName = `${techniqueId}-${titleSlug}-${issue.number}.md`;
      const filePath = path.join("techniques", techniqueId, fileName);

      // Ensure the local directory exists.
      const localDir = path.dirname(filePath);
      if (!fs.existsSync(localDir)) {
        fs.mkdirSync(localDir, { recursive: true });
      }

      const content = `# ${issue.title}\n\n**Technique:** ${techniqueId}\n\n**Details:**\n${issue.body}\n\n**Status:** Completed\n`;
      fs.writeFileSync(filePath, content);

      console.log("Attempting to update file at:", filePath);
      console.log("Target branch:", "main");

      // Check if the file exists remotely on the target branch
      let fileExists = false;
      let sha;
      try {
        const { data } = await octokit.repos.getContent({
          owner: process.env.GITHUB_REPOSITORY.split("/")[0],
          repo: process.env.GITHUB_REPOSITORY.split("/")[1],
          path: filePath,
          branch: "main"
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

      const commitMessage = `Add completed threat hunt #${issue.number} - ${issue.title} to ${techniqueId}`;
      const params = {
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
      };

      // If updating an existing file, include its SHA.
      if (fileExists) {
        params.sha = sha;
      }

      await octokit.repos.createOrUpdateFileContents(params);
      console.log(`Threat hunt file created/updated: ${fileName}`);
    } else {
      console.log("Event does not match criteria.");
    }
  }

  run().catch((error) => {
    console.error(error);
    process.exit(1);
  });
})();

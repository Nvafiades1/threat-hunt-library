// src/NewHunts.js
import React, { useEffect, useState } from "react";

const NewHunts = () => {
  const [newHunts, setNewHunts] = useState([]);
  const [error, setError] = useState(null);

  const repoOwner = "Nvafiades1";
  const repoName = "threat-hunt-library";
  const branch = "main";

  // Helper function: check if a given date is within the past week.
  const isWithinPastWeek = (dateStr) => {
    const commitDate = new Date(dateStr);
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
    return commitDate >= oneWeekAgo;
  };

  useEffect(() => {
    const techniquesUrl = `https://api.github.com/repos/${repoOwner}/${repoName}/contents/techniques?ref=${branch}`;
    console.log("Fetching techniques from:", techniquesUrl);
    fetch(techniquesUrl)
      .then((res) => res.json())
      .then(async (techniquesData) => {
        if (!Array.isArray(techniquesData)) {
          console.error("Techniques response is not an array:", techniquesData);
          setError("Unexpected response format for technique directories. Check that the repository is public and that the 'techniques' folder exists on the " + branch + " branch.");
          return;
        }

        const techniqueDirs = techniquesData.filter((item) => item.type === "dir");
        let hunts = [];

        // For each technique directory, fetch its files.
        for (const tech of techniqueDirs) {
          const techPath = tech.name;
          const filesUrl = `https://api.github.com/repos/${repoOwner}/${repoName}/contents/techniques/${techPath}?ref=${branch}`;
          try {
            const res = await fetch(filesUrl);
            const filesData = await res.json();
            if (!Array.isArray(filesData)) {
              console.error(`Files response for ${techPath} is not an array:`, filesData);
              continue;
            }
            // Exclude README.md and non-markdown files.
            const huntFiles = filesData.filter(
              (file) =>
                file.type === "file" &&
                file.name.toLowerCase() !== "readme.md" &&
                file.name.endsWith(".md")
            );
            // For each hunt file, fetch its latest commit info.
            for (const file of huntFiles) {
              const commitsUrl = `https://api.github.com/repos/${repoOwner}/${repoName}/commits?path=${encodeURIComponent(file.path)}&page=1&per_page=1`;
              try {
                const commitRes = await fetch(commitsUrl);
                const commitData = await commitRes.json();
                if (commitData && commitData.length > 0) {
                  const commitDate = commitData[0].commit.author.date;
                  if (isWithinPastWeek(commitDate)) {
                    hunts.push({
                      technique: techPath,
                      fileName: file.name,
                      path: file.path,
                      date: commitDate,
                      html_url: file.html_url,
                    });
                  }
                }
              } catch (err) {
                console.error("Error fetching commit info for file:", file.path, err);
              }
            }
          } catch (err) {
            console.error("Error fetching files for technique:", techPath, err);
          }
        }
        setNewHunts(hunts);
      })
      .catch((err) => {
        console.error("Error fetching technique directories:", err);
        setError(err.toString());
      });
  }, []);

  return (
    <div>
      <h2>New Threat Hunts in the Past Week</h2>
      {error && <p style={{ color: "red" }}>Error: {error}</p>}
      {newHunts.length === 0 ? (
        <p>No new threat hunts found in the past week.</p>
      ) : (
        <div className="new-hunts">
          <ul>
            {newHunts.map((hunt, index) => (
              <li key={index}>
                <strong>{hunt.technique}</strong>: {hunt.fileName} (Committed on{" "}
                {new Date(hunt.date).toLocaleString()})
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default NewHunts;

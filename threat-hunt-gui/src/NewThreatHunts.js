import React, { useState, useEffect } from "react";

const NewThreatHunts = () => {
  const [commits, setCommits] = useState([]);
  const [error, setError] = useState("");
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const repoOwner = "Nvafiades1";
  const repoName = "threat-hunt-library";
  const branch = "main";
  const commitsUrl = `https://api.github.com/repos/${repoOwner}/${repoName}/commits?path=techniques&per_page=10&sha=${branch}`;

  useEffect(() => {
    fetch(commitsUrl, {
      headers: {
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "threat-hunt-gui"
      }
    })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
        return res.json();
      })
      .then((data) => {
        const oneWeekAgo = new Date();
        oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
        const newCommits = data.filter(
          (commit) => new Date(commit.commit.author.date) >= oneWeekAgo
        );
        setCommits(newCommits);
      })
      .catch((err) => setError(err.toString()));
  }, [commitsUrl]);

  if (commits.length === 0) return null;

  return (
    <div className="new-threats-dropdown">
      <div
        className="dropdown-header"
        onClick={() => setDropdownOpen(!dropdownOpen)}
      >
        <h3>
          New Threat Hunts {dropdownOpen ? "▲" : "▼"}
        </h3>
      </div>
      {dropdownOpen && (
        <ul className="dropdown-list">
          {commits.map((commit) => (
            <li key={commit.sha}>
              <a
                href={commit.html_url}
                target="_blank"
                rel="noopener noreferrer"
              >
                <p className="commit-message">{commit.commit.message}</p>
                <small className="commit-date">
                  {new Date(commit.commit.author.date).toLocaleString()}
                </small>
              </a>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default NewThreatHunts;

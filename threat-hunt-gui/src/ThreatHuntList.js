import React, { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";

const ThreatHuntList = ({ techniqueId }) => {
  const [files, setFiles] = useState([]);
  const [selectedContent, setSelectedContent] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!techniqueId) return;
    const url = `https://api.github.com/repos/${"Nvafiades1"}/${"threat-hunt-library"}/contents/techniques/${techniqueId}?ref=main`;
    console.log("Fetching file list from:", url);
    fetch(url, {
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
        const mdFiles = data.filter(
          (item) =>
            item.type === "file" &&
            item.name.endsWith(".md") &&
            item.name.toLowerCase() !== "readme.md"
        );
        setFiles(mdFiles);
      })
      .catch((err) => setError(err.toString()));
  }, [techniqueId]);

  const fetchContent = (downloadUrl) => {
    fetch(downloadUrl, {
      headers: {
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "threat-hunt-gui"
      }
    })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
        return res.text();
      })
      .then((content) => setSelectedContent(content))
      .catch((err) => setError(err.toString()));
  };

  return (
    <div>
      <h2>Threat Hunts for Technique {techniqueId}</h2>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {files.length === 0 ? (
        <p>No threat hunt files found for this technique.</p>
      ) : (
        <ul className="threat-list">
          {files.map((file) => (
            <li key={file.name}>
              <button onClick={() => fetchContent(file.download_url)}>
                {file.name}
              </button>
            </li>
          ))}
        </ul>
      )}
      {selectedContent && (
        <div className="markdown-content">
          <h3>Threat Hunt Details:</h3>
          <ReactMarkdown>{selectedContent}</ReactMarkdown>
        </div>
      )}
    </div>
  );
};

export default ThreatHuntList;

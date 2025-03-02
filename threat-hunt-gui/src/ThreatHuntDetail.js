import React, { useState, useEffect } from "react";
import ReactMarkdown from "react-markdown";

const ThreatHuntDetail = ({ downloadUrl }) => {
  const [content, setContent] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!downloadUrl) return;
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
      .then((text) => setContent(text))
      .catch((err) => setError(err.toString()));
  }, [downloadUrl]);

  return (
    <div className="markdown-content">
      <h3>Threat Hunt Details:</h3>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {content ? (
        <ReactMarkdown>{content}</ReactMarkdown>
      ) : (
        <p>Loading...</p>
      )}
    </div>
  );
};

export default ThreatHuntDetail;

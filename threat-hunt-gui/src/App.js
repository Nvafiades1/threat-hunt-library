import React, { useState, useEffect } from "react";
import ThreatHuntList from "./ThreatHuntList";
import ThreatHuntDetail from "./ThreatHuntDetail";
import NewThreatHunts from "./NewThreatHunts";
import "./App.css";

function App() {
  // Grouping states
  const [techniques, setTechniques] = useState([]);
  const [mapping, setMapping] = useState({});
  const [groupedTechniques, setGroupedTechniques] = useState({});
  const [selectedTactic, setSelectedTactic] = useState("");
  const [expandedBase, setExpandedBase] = useState(null);
  const [selectedTechnique, setSelectedTechnique] = useState("");
  const [error, setError] = useState("");

  // Search states
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState([]);
  const [selectedSearchFile, setSelectedSearchFile] = useState(null);

  const repoOwner = "Nvafiades1";
  const repoName = "threat-hunt-library";
  const branch = "main";
  const mappingUrl = `https://raw.githubusercontent.com/${repoOwner}/${repoName}/${branch}/mitre_ttp_mapping.json`;

  // MITRE ATT&CK tactic order
  const tacticOrder = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
  ];

  // Helper to normalize tactic names (lowercase, remove spaces/dashes)
  const normalizeTactic = (str) =>
    str.toLowerCase().replace(/[\s-]/g, "");
  const normalizedOrder = tacticOrder.map(normalizeTactic);

  // 1. Fetch technique directories from the "techniques" folder
  useEffect(() => {
    const apiUrl = `https://api.github.com/repos/${repoOwner}/${repoName}/contents/techniques?ref=${branch}`;
    console.log("Fetching technique directories from:", apiUrl);
    fetch(apiUrl, {
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
        const dirs = data.filter((item) => item.type === "dir");
        setTechniques(dirs);
      })
      .catch((err) => setError(err.toString()));
  }, []);

  // 2. Fetch the simplified mapping file
  useEffect(() => {
    console.log("Fetching mapping file from:", mappingUrl);
    fetch(mappingUrl, {
      headers: {
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "threat-hunt-gui"
      }
    })
      .then((res) => {
        if (!res.ok) {
          console.warn(`Mapping file not found (status: ${res.status}).`);
          return [];
        }
        return res.json();
      })
      .then((data) => {
        if (Array.isArray(data)) {
          const map = {};
          data.forEach((item) => {
            map[item.technique_id] = item.tactic;
          });
          console.log("Loaded mapping:", map);
          setMapping(map);
        } else {
          setMapping({});
        }
      })
      .catch((err) => {
        console.error("Error fetching mapping:", err);
        setMapping({});
      });
  }, [mappingUrl]);

  // 3. Group directories by tactic and nest them by base technique
  useEffect(() => {
    if (techniques.length === 0) return;
    let groups = {};
    techniques.forEach((tech) => {
      const base = tech.name.split(".")[0];
      const tactic = mapping[base] || "Other";
      if (!groups[tactic]) groups[tactic] = {};
      if (!groups[tactic][base]) groups[tactic][base] = [];
      groups[tactic][base].push(tech);
    });
    let sortedGroups = {};
    tacticOrder.forEach((tac) => {
      const normTac = normalizeTactic(tac);
      Object.keys(groups).forEach((key) => {
        if (normalizeTactic(key) === normTac) {
          sortedGroups[key] = groups[key];
        }
      });
    });
    Object.keys(groups).forEach((tac) => {
      if (!sortedGroups[tac]) sortedGroups[tac] = groups[tac];
    });
    setGroupedTechniques(sortedGroups);
    console.log("Grouped Techniques:", sortedGroups);
    const tacticKeys = Object.keys(sortedGroups);
    if (tacticKeys.length > 0) {
      setSelectedTactic(tacticKeys[0]);
      const baseKeys = Object.keys(sortedGroups[tacticKeys[0]]);
      if (baseKeys.length > 0) {
        setExpandedBase(null);
        setSelectedTechnique(sortedGroups[tacticKeys[0]][baseKeys[0]][0].name);
      }
    }
  }, [techniques, mapping]);

  // 4. Search functionality: When searchQuery changes, use GitHub's code search API
  useEffect(() => {
    if (!searchQuery.trim()) {
      setSearchResults([]);
      return;
    }
    const query = encodeURIComponent(
      `${searchQuery} in:file repo:${repoOwner}/${repoName} path:techniques`
    );
    const searchUrl = `https://api.github.com/search/code?q=${query}`;
    console.log("Search URL:", searchUrl);
    fetch(searchUrl, {
      headers: {
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "threat-hunt-gui"
        // Uncomment and add your token if needed:
        // Authorization: "token YOUR_GITHUB_PERSONAL_ACCESS_TOKEN"
      }
    })
      .then((res) => {
        console.log("Search response status:", res.status);
        if (!res.ok) throw new Error(`Search HTTP error: ${res.status}`);
        return res.json();
      })
      .then((data) => {
        console.log("Search data:", data);
        if (data && data.items && data.items.length > 0) {
          setSearchResults(data.items);
        } else {
          setSearchResults([]);
          console.log("No search results found. Try a different keyword.");
        }
      })
      .catch((err) => {
        console.error("Error in search:", err);
        setSearchResults([]);
      });
  }, [searchQuery, repoOwner, repoName]);

  // 5. Handlers for sidebar clicks
  const handleBaseClick = (base) => {
    if (expandedBase === base) {
      setExpandedBase(null);
      setSelectedTechnique("");
    } else {
      setExpandedBase(base);
      const techs = groupedTechniques[selectedTactic][base];
      if (techs && techs.length > 0) setSelectedTechnique(techs[0].name);
    }
  };

  const handleSubClick = (techName) => {
    setSelectedTechnique(techName);
  };

  const nested =
    selectedTactic && groupedTechniques[selectedTactic]
      ? groupedTechniques[selectedTactic]
      : {};

  return (
    <div className="App">
      {/* New Threat Hunts Dropdown */}
      <NewThreatHunts />

      <div className="header">
        <h1>MITRE ATT&CK Threat Hunt Library</h1>
        {/* Search Input */}
        <div className="search-container">
          <input
            type="text"
            placeholder="Search threat hunts..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setSelectedSearchFile(null);
            }}
          />
          {searchQuery && searchResults.length > 0 && (
            <ul className="search-results">
              {searchResults.map((result) => (
                <li key={result.sha || result.url}>
                  <button
                    onClick={() => {
                      setSelectedSearchFile(result);
                      setSearchQuery("");
                      setSearchResults([]);
                    }}
                  >
                    {result.name} — {result.path}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* Tactics Row */}
      <div className="tactics-row">
        {Object.keys(groupedTechniques)
          .sort((a, b) => {
            const idxA = normalizedOrder.indexOf(normalizeTactic(a));
            const idxB = normalizedOrder.indexOf(normalizeTactic(b));
            return idxA - idxB;
          })
          .map((tactic) => (
            <button
              key={tactic}
              className={`tactic-button ${
                selectedTactic === tactic ? "active" : ""
              }`}
              onClick={() => {
                setSelectedTactic(tactic);
                setExpandedBase(null);
                setSelectedSearchFile(null);
                const bases = Object.keys(groupedTechniques[tactic]);
                if (bases.length > 0) {
                  setSelectedTechnique(groupedTechniques[tactic][bases[0]][0].name);
                } else {
                  setSelectedTechnique("");
                }
              }}
            >
              {tactic}
            </button>
          ))}
      </div>

      {/* Sidebar: Base Techniques and Subtechniques */}
      <div className="sidebar">
        <h2>Techniques for {selectedTactic}</h2>
        {Object.keys(nested).length === 0 ? (
          <p>No techniques available for this tactic.</p>
        ) : (
          <ul className="technique-list">
            {Object.keys(nested).map((base) => (
              <li key={base}>
                <button
                  className="technique-item"
                  onClick={() => handleBaseClick(base)}
                >
                  {base}
                </button>
                {expandedBase === base && nested[base].length > 1 && (
                  <ul className="nested-list">
                    {nested[base].map((tech) => (
                      <li key={tech.name}>
                        <button
                          className="technique-item"
                          onClick={() => handleSubClick(tech.name)}
                        >
                          {tech.name}
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Main Area */}
      <div className="main">
        {selectedSearchFile ? (
          <ThreatHuntDetail
            downloadUrl={
              selectedSearchFile.url
                .replace("api.github.com/repos", "raw.githubusercontent.com")
                .replace("/contents", "") + `?ref=${branch}`
            }
          />
        ) : selectedTechnique ? (
          <ThreatHuntList techniqueId={selectedTechnique} />
        ) : (
          <p>Please select a technique to view threat hunts.</p>
        )}
      </div>
    </div>
  );
}

export default App;

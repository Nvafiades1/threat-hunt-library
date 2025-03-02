import React, { useState, useEffect } from "react";
import ThreatHuntList from "./ThreatHuntList";
import "./App.css";

function App() {
  const [techniques, setTechniques] = useState([]);
  const [mapping, setMapping] = useState({});
  const [groupedTechniques, setGroupedTechniques] = useState({});
  const [selectedTactic, setSelectedTactic] = useState("");
  const [expandedBase, setExpandedBase] = useState(null);
  const [selectedTechnique, setSelectedTechnique] = useState("");
  const [error, setError] = useState("");

  const repoOwner = "Nvafiades1";
  const repoName = "threat-hunt-library";
  const branch = "main";
  const mappingUrl = `https://raw.githubusercontent.com/${repoOwner}/${repoName}/${branch}/mitre_ttp_mapping.json`;

  // Predefined tactic order (adjust as needed)
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
    "Impact",
    "Other"
  ];

  // 1. Fetch technique directories from the "techniques" folder
  useEffect(() => {
    const url = `https://api.github.com/repos/${repoOwner}/${repoName}/contents/techniques?ref=${branch}`;
    console.log("Fetching technique directories from:", url);
    fetch(url, {
      headers: {
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "threat-hunt-gui"
      }
    })
      .then(res => {
        if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
        return res.json();
      })
      .then(data => {
        // Only keep directories
        const dirs = data.filter(item => item.type === "dir");
        setTechniques(dirs);
      })
      .catch(err => setError(err.toString()));
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
      .then(res => {
        if (!res.ok) {
          console.warn(`Mapping file not found (status: ${res.status}).`);
          return [];
        }
        return res.json();
      })
      .then(data => {
        if (Array.isArray(data)) {
          const map = {};
          data.forEach(item => {
            // Ensure technique_id matches the base of your folder names
            map[item.technique_id] = item.tactic;
          });
          console.log("Loaded mapping:", map);
          setMapping(map);
        } else {
          setMapping({});
        }
      })
      .catch(err => {
        console.error("Error fetching mapping:", err);
        setMapping({});
      });
  }, [mappingUrl]);

  // 3. Group directories by tactic (using the mapping) and nest them by base technique
  useEffect(() => {
    if (techniques.length === 0) return;
    let groups = {};
    techniques.forEach(tech => {
      // Extract base technique: "T1001" from "T1001" or "T1001.001"
      const base = tech.name.split(".")[0];
      // Determine tactic using mapping; if not found, use "Other"
      const tactic = mapping[base] || "Other";
      if (!groups[tactic]) groups[tactic] = {};
      if (!groups[tactic][base]) groups[tactic][base] = [];
      groups[tactic][base].push(tech);
    });
    // Sort tactics by predefined order
    const sortedGroups = {};
    tacticOrder.forEach(tac => {
      if (groups[tac]) sortedGroups[tac] = groups[tac];
    });
    // Append any tactics not in the order
    Object.keys(groups).forEach(tac => {
      if (!sortedGroups[tac]) sortedGroups[tac] = groups[tac];
    });
    setGroupedTechniques(sortedGroups);
    console.log("Grouped Techniques:", sortedGroups);
    // Set default selection: first tactic and first base technique
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

  // 4. Handler for base technique clicks (toggle expansion)
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

  // 5. Handler for subtechnique clicks
  const handleSubClick = (techName) => {
    setSelectedTechnique(techName);
  };

  // Get nested techniques for selected tactic
  const nested = selectedTactic && groupedTechniques[selectedTactic]
    ? groupedTechniques[selectedTactic]
    : {};

  return (
    <div className="App">
      <div className="header">
        <h1>MITRE ATT&CK Threat Hunt Library</h1>
      </div>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {/* Tactics Row */}
      <div className="tactics-row">
        {Object.keys(groupedTechniques)
          .sort((a, b) => {
            const idxA = tacticOrder.indexOf(a);
            const idxB = tacticOrder.indexOf(b);
            return idxA - idxB;
          })
          .map(tactic => (
            <button
              key={tactic}
              className={`tactic-button ${selectedTactic === tactic ? "active" : ""}`}
              onClick={() => {
                setSelectedTactic(tactic);
                setExpandedBase(null);
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
            {Object.keys(nested).map(base => (
              <li key={base}>
                <button className="technique-item" onClick={() => handleBaseClick(base)}>
                  {base}
                </button>
                {expandedBase === base && nested[base].length > 1 && (
                  <ul className="nested-list">
                    {nested[base].map(tech => (
                      <li key={tech.name}>
                        <button className="technique-item" onClick={() => handleSubClick(tech.name)}>
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
      {/* Main Area: Threat Hunt Details */}
      <div className="main">
        {selectedTechnique ? (
          <ThreatHuntList techniqueId={selectedTechnique} />
        ) : (
          <p>Please select a technique to view threat hunts.</p>
        )}
      </div>
    </div>
  );
}

export default App;

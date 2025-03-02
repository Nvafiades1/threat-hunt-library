// map-mitre.js
const fs = require("fs");

// Path to the official Enterprise ATT&CK JSON file.
// You can download this file into your Codespace.
const stixFilePath = "enterprise-attack.json"; 
const outputMappingFilePath = "mitre_ttp_mapping.json";

// Read and parse the STIX file
const stixData = JSON.parse(fs.readFileSync(stixFilePath, "utf8"));

const mapping = [];

// Iterate over STIX objects and extract attack-pattern mappings.
stixData.objects.forEach(obj => {
  if (obj.type === "attack-pattern" && Array.isArray(obj.external_references)) {
    const extRef = obj.external_references.find(
      ref => ref.source_name === "mitre-attack" && ref.external_id
    );
    if (extRef) {
      // Use the first kill_chain_phase's phase_name as the tactic, if available.
      let tactic = "Other";
      if (Array.isArray(obj.kill_chain_phases) && obj.kill_chain_phases.length > 0) {
        tactic = obj.kill_chain_phases[0].phase_name;
        tactic = tactic.charAt(0).toUpperCase() + tactic.slice(1);
      }
      // Extract only the base technique (split on '.')
      const baseTechnique = extRef.external_id.split(".")[0];
      // Only add if not already present
      if (!mapping.some(m => m.technique_id === baseTechnique)) {
        mapping.push({ technique_id: baseTechnique, tactic });
      }
    }
  }
});

fs.writeFileSync(outputMappingFilePath, JSON.stringify(mapping, null, 2));
console.log(`Mapping file generated at ${outputMappingFilePath}`);

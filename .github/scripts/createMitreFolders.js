const fs = require("fs");
const path = require("path");
const fetch = require("node-fetch");

const MITRE_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
const TECHNIQUES_DIR = path.join(__dirname, "../../techniques");

async function createFolders() {
  // Fetch MITRE ATT&CK data
  const res = await fetch(MITRE_JSON_URL);
  if (!res.ok) {
    console.error("Failed to fetch MITRE data:", res.statusText);
    process.exit(1);
  }
  const data = await res.json();

  // Filter objects that represent techniques (attack-pattern) with external references
  const techniques = data.objects.filter(
    (obj) => obj.type === "attack-pattern" && obj.external_references
  );

  techniques.forEach((technique) => {
    // Find the external_id (e.g., T1059) from MITRE references
    const mitreRef = technique.external_references.find(
      (ref) => ref.source_name.toLowerCase() === "mitre-attack"
    );
    if (!mitreRef || !mitreRef.external_id) return;

    const techniqueId = mitreRef.external_id;
    const folderPath = path.join(TECHNIQUES_DIR, techniqueId);

    // Create folder if it doesn't exist
    if (!fs.existsSync(folderPath)) {
      fs.mkdirSync(folderPath, { recursive: true });
      console.log(`Created folder for ${techniqueId}`);

      // Write a basic README.md for the technique
      const content = `# ${technique.name}\n\n**Technique ID:** ${techniqueId}\n\n**Description:**\n${technique.description || "No description available."}\n`;
      fs.writeFileSync(path.join(folderPath, "README.md"), content);
    }
  });
}

createFolders()
  .then(() => console.log("MITRE technique folders updated."))
  .catch((error) => {
    console.error("Error:", error);
    process.exit(1);
  });

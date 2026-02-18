#!/usr/bin/env node
// Scans the Steam Workshop content directory for tModLoader (app 1281930)
// and builds a modName → workshopId mapping file.
//
// Usage:
//   node tools/build-workshop-map.js [workshop-content-path]
//
// Default path (Windows): D:\steamlibrary\steamapps\workshop\content\1281930
// Output: workshop-map.json in the same directory as this script's parent

const fs = require('fs');
const path = require('path');
const os = require('os');

// Detect default workshop path
function getDefaultWorkshopPath() {
  const common = [
    'D:\\steamlibrary\\steamapps\\workshop\\content\\1281930',
    'C:\\Program Files (x86)\\Steam\\steamapps\\workshop\\content\\1281930',
    'C:\\Program Files\\Steam\\steamapps\\workshop\\content\\1281930',
    path.join(os.homedir(), '.steam', 'steam', 'steamapps', 'workshop', 'content', '1281930'),
    path.join(os.homedir(), '.local', 'share', 'Steam', 'steamapps', 'workshop', 'content', '1281930'),
    path.join(os.homedir(), 'Library', 'Application Support', 'Steam', 'steamapps', 'workshop', 'content', '1281930'),
  ];
  for (const p of common) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

const workshopDir = process.argv[2] || getDefaultWorkshopPath();
if (!workshopDir || !fs.existsSync(workshopDir)) {
  console.error('Workshop content directory not found.');
  console.error('Usage: node build-workshop-map.js [path-to-workshop-content/1281930]');
  console.error('Tried:', workshopDir || '(none)');
  process.exit(1);
}

console.log('Scanning:', workshopDir);

const entries = fs.readdirSync(workshopDir).filter(d => {
  return /^\d+$/.test(d) && fs.statSync(path.join(workshopDir, d)).isDirectory();
});

const map = {};
let found = 0;

for (const workshopId of entries) {
  const itemDir = path.join(workshopDir, workshopId);

  // Find .tmod files in version subfolders
  const subDirs = fs.readdirSync(itemDir)
    .filter(d => fs.statSync(path.join(itemDir, d)).isDirectory())
    .sort((a, b) => {
      const pa = a.split('.').map(Number);
      const pb = b.split('.').map(Number);
      for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        const diff = (pb[i] || 0) - (pa[i] || 0);
        if (diff !== 0) return diff;
      }
      return 0;
    }); // Latest version first (semantic sort)

  let modName = null;
  for (const sub of subDirs) {
    const files = fs.readdirSync(path.join(itemDir, sub));
    const tmod = files.find(f => f.endsWith('.tmod') && !f.endsWith('.tmod.bak'));
    if (tmod) {
      modName = tmod.replace('.tmod', '');
      break;
    }
  }

  if (!modName) {
    console.log(`  [skip] ${workshopId} — no .tmod found`);
    continue;
  }

  map[modName] = { workshopId };
  found++;
  console.log(`  ${modName} → ${workshopId}`);
}

const outPath = path.join(__dirname, '..', 'workshop-map.json');
fs.writeFileSync(outPath, JSON.stringify(map, null, 2));
console.log(`\nDone: ${found} mods mapped → ${outPath}`);

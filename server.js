#!/usr/bin/env node
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { spawn, execSync, execFile } = require('child_process');
const zlib = require('zlib');
const { WebSocketServer } = require('ws');

// ── Cross-Platform Helpers ──────────────────────────────────────────────────
const PLATFORM = process.platform;

function getDefaultDataPath() {
  const home = os.homedir();
  if (PLATFORM === 'win32') return path.join(home, 'Documents', 'My Games', 'Terraria', 'tModLoader');
  if (PLATFORM === 'darwin') return path.join(home, 'Library', 'Application Support', 'Terraria', 'tModLoader');
  return path.join(home, '.local', 'share', 'Terraria', 'tModLoader');
}

function getDotnetBinary(serverPath) {
  const names = PLATFORM === 'win32' ? ['dotnet.exe', 'dotnet'] : ['dotnet'];
  for (const name of names) {
    const bundled = path.join(serverPath, 'dotnet', name);
    if (fs.existsSync(bundled)) return bundled;
  }
  return 'dotnet';
}

function forceKill(proc) {
  if (!proc || !proc.pid) return;
  try {
    if (PLATFORM === 'win32') {
      execSync(`taskkill /PID ${proc.pid} /T /F`, { stdio: 'ignore' });
    } else {
      proc.kill('SIGKILL');
    }
  } catch { /* already dead */ }
}

function getRam() {
  if (!serverProcess || !serverProcess.pid) return 0;
  try {
    if (PLATFORM === 'linux') {
      const stat = fs.readFileSync(`/proc/${serverProcess.pid}/status`, 'utf8');
      const match = stat.match(/VmRSS:\s+(\d+)/);
      return match ? Math.round(parseInt(match[1]) / 1024) : 0;
    }
    if (PLATFORM === 'win32') {
      const out = execSync(`tasklist /FI "PID eq ${serverProcess.pid}" /FO CSV /NH`, { encoding: 'utf8', timeout: 5000 });
      // Format: "name","pid","session","num","mem K"
      const match = out.match(/"([0-9,]+)\s*K"/);
      if (match) return Math.round(parseInt(match[1].replace(/,/g, '')) / 1024);
      return 0;
    }
    if (PLATFORM === 'darwin') {
      const out = execSync(`ps -o rss= -p ${serverProcess.pid}`, { encoding: 'utf8', timeout: 5000 });
      const kb = parseInt(out.trim());
      return isNaN(kb) ? 0 : Math.round(kb / 1024);
    }
  } catch { /* process gone or command failed */ }
  return 0;
}

// ── Config ──────────────────────────────────────────────────────────────────
const CONFIG_PATH = path.join(__dirname, 'config.json');

function loadOrCreateConfig() {
  if (fs.existsSync(CONFIG_PATH)) {
    const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    // Migrate plaintext password → hash
    if (cfg.password && !cfg.passwordHash) {
      cfg.passwordHash = hashPassword(cfg.password);
      delete cfg.password;
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
      console.log('[MANAGER] Migrated plaintext password to scrypt hash');
    }
    // Migrate legacy 'changeme' hashed password → null (force setup)
    if (cfg.password === 'changeme') {
      cfg.passwordHash = null;
      delete cfg.password;
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
    }
    return cfg;
  }
  // First run — generate skeleton config
  const defaults = {
    port: 8080,
    passwordHash: null,
    serverPath: '',
    modsPath: path.join(getDefaultDataPath(), 'Mods'),
    configsPath: path.join(getDefaultDataPath(), 'ModConfigs'),
    worldsPath: path.join(getDefaultDataPath(), 'Worlds'),
    configFile: '',
    maxLogLines: 500
  };
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(defaults, null, 2));
  console.log('[MANAGER] Created default config.json — setup required');
  return defaults;
}

let config = loadOrCreateConfig();
const PORT = config.port || 8080;
const MAX_LOG = config.maxLogLines || 500;

function isSetupNeeded() {
  return !config.passwordHash;
}

function saveConfig() {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

// ── Auth (scrypt) ───────────────────────────────────────────────────────────
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(pw, stored) {
  if (!stored) return false;
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const derived = crypto.scryptSync(pw, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

// Tokens: Map with created timestamp, 24h TTL
const tokens = new Map();
const TOKEN_TTL = 24 * 60 * 60 * 1000;

function generateToken() {
  const token = crypto.randomBytes(32).toString('hex');
  tokens.set(token, { created: Date.now() });
  return token;
}

function checkAuth(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return false;
  const token = auth.slice(7);
  const entry = tokens.get(token);
  if (!entry) return false;
  if (Date.now() - entry.created > TOKEN_TTL) {
    tokens.delete(token);
    return false;
  }
  return true;
}

// Cleanup expired tokens every hour
setInterval(() => {
  const now = Date.now();
  for (const [t, entry] of tokens) {
    if (now - entry.created > TOKEN_TTL) tokens.delete(t);
  }
}, 60 * 60 * 1000);

// ── Rate Limiting ───────────────────────────────────────────────────────────
const loginAttempts = new Map(); // ip → { count, windowStart }
const RATE_WINDOW = 15 * 60 * 1000;
const RATE_MAX = 10;

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now - entry.windowStart > RATE_WINDOW) {
    loginAttempts.set(ip, { count: 1, windowStart: now });
    return true;
  }
  entry.count++;
  if (entry.count > RATE_MAX) return false;
  return true;
}

// Cleanup rate limit entries every 30 min
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts) {
    if (now - entry.windowStart > RATE_WINDOW) loginAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

// ── State ───────────────────────────────────────────────────────────────────
let serverProcess = null;
let serverStatus = 'stopped';
let startTime = null;
let players = [];
let logBuffer = [];
const wsClients = new Set();

// ── .tmod Parser ────────────────────────────────────────────────────────────
function read7BitInt(buf, offset) {
  let value = 0, shift = 0, pos = offset;
  while (pos < buf.length) {
    const b = buf[pos++];
    value |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7;
  }
  return { value, pos };
}

function readString(buf, offset) {
  const { value: len, pos } = read7BitInt(buf, offset);
  const str = buf.toString('utf8', pos, pos + len);
  return { value: str, pos: pos + len };
}

function parseTmod(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    if (buf.toString('ascii', 0, 4) !== 'TMOD') return null;
    let pos = 4;
    const tmlVer = readString(buf, pos); pos = tmlVer.pos;
    pos += 20 + 256 + 4;
    const modName = readString(buf, pos); pos = modName.pos;
    const modVer = readString(buf, pos); pos = modVer.pos;
    return { name: modName.value, version: modVer.value, tmlVersion: tmlVer.value };
  } catch {
    return null;
  }
}

// ── .tmod HJSON Extraction (for mod config registry) ────────────────────────
function extractHjsonFiles(tmodPath) {
  const buf = fs.readFileSync(tmodPath);
  if (buf.toString('ascii', 0, 4) !== 'TMOD') return null;
  let pos = 4;
  const tmlVer = readString(buf, pos); pos = tmlVer.pos;
  pos += 20 + 256 + 4; // hash + signature + data length
  const modName = readString(buf, pos); pos = modName.pos;
  const modVer = readString(buf, pos); pos = modVer.pos;
  const fileCount = buf.readUInt32LE(pos); pos += 4;
  // Read file table first (paths + sizes), then data sequentially
  const fileTable = [];
  for (let i = 0; i < fileCount; i++) {
    const fp = readString(buf, pos); pos = fp.pos;
    const origSize = buf.readUInt32LE(pos); pos += 4;
    const compSize = buf.readUInt32LE(pos); pos += 4;
    fileTable.push({ path: fp.value, origSize, compSize });
  }
  const results = [];
  for (const f of fileTable) {
    const raw = buf.slice(pos, pos + f.compSize);
    pos += f.compSize;
    if (f.path.endsWith('.hjson') && /en-US/i.test(f.path)) {
      let data;
      if (f.compSize !== f.origSize) {
        try { data = zlib.inflateRawSync(raw).toString('utf8'); } catch { continue; }
      } else { data = raw.toString('utf8'); }
      results.push({ path: f.path, content: data });
    }
  }
  return { name: modName.value, version: modVer.value, results };
}

function flattenHjson(text) {
  const result = {};
  const stack = [];
  const lines = text.split('\n');
  let inMultiline = false, multilineKey = null, multilineValue = '';
  for (let line of lines) {
    if (inMultiline) {
      if (line.trim() === "'''") {
        result[multilineKey] = multilineValue.trim();
        inMultiline = false;
        continue;
      }
      multilineValue += line + '\n';
      continue;
    }
    line = line.replace(/\/\/.*$/, '');
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (trimmed === '}' || trimmed === '},') { stack.pop(); continue; }
    const blockMatch = trimmed.match(/^"?([^":{}\s]+)"?\s*[:=]?\s*\{$/);
    if (blockMatch) { stack.push(blockMatch[1]); continue; }
    const kvMatch = trimmed.match(/^"?([^":{}\s]+)"?\s*[:=]\s*(.*)$/);
    if (kvMatch) {
      let key = kvMatch[1];
      let value = kvMatch[2].replace(/,?\s*$/, '');
      if (value === '{') { stack.push(key); continue; }
      if (value.trim() === "'''") {
        inMultiline = true;
        multilineKey = [...stack, key].join('.');
        multilineValue = '';
        continue;
      }
      value = value.replace(/^"(.*)"$/, '$1');
      result[[...stack, key].join('.')] = value;
    }
  }
  return result;
}

function parseHjsonForConfigs(hjsonContent, filePath) {
  const flat = flattenHjson(hjsonContent);
  const configs = {};
  const isConfigFile = /[Cc]onfigs/i.test(filePath);
  for (const [p, value] of Object.entries(flat)) {
    let match;
    // Pattern 1: Configs.ClassName.PropertyName.Label/Tooltip
    match = p.match(/(?:^|\.)?Configs\.(\w+)\.(\w+?)\.(\w+)$/);
    if (match) {
      const [, className, propName, subKey] = match;
      if (subKey === 'Label' || subKey === 'Tooltip') {
        if (!configs[className]) configs[className] = { displayName: className, properties: {} };
        if (!configs[className].properties[propName]) configs[className].properties[propName] = {};
        configs[className].properties[propName][subKey.toLowerCase()] = value;
      }
      continue;
    }
    match = p.match(/(?:^|\.)?Configs\.(\w+)\.DisplayName$/);
    if (match) {
      if (!configs[match[1]]) configs[match[1]] = { displayName: match[1], properties: {} };
      configs[match[1]].displayName = value;
      continue;
    }
    // Pattern 2: Config-specific files — ClassName.PropertyName.Label
    if (isConfigFile) {
      match = p.match(/^(\w+)\.(\w+)\.(\w+)$/);
      if (match) {
        const [, className, propName, subKey] = match;
        if (subKey === 'Label' || subKey === 'Tooltip') {
          if (propName === 'Headers') continue;
          if (!configs[className]) configs[className] = { displayName: className, properties: {} };
          if (!configs[className].properties[propName]) configs[className].properties[propName] = {};
          configs[className].properties[propName][subKey.toLowerCase()] = value;
        }
        continue;
      }
      match = p.match(/^(\w+)\.DisplayName$/);
      if (match) {
        if (!configs[match[1]]) configs[match[1]] = { displayName: match[1], properties: {} };
        configs[match[1]].displayName = value;
        continue;
      }
    }
  }
  // Filter: only keep classes that have at least one labeled property
  for (const [cls, data] of Object.entries(configs)) {
    if (!Object.values(data.properties).some(p => p.label)) delete configs[cls];
  }
  return configs;
}

let modConfigRegistry = null;
let registryScanTime = 0;

function scanModConfigRegistry() {
  const modsPath = getModsPath();
  let tmodFiles;
  try { tmodFiles = fs.readdirSync(modsPath).filter(f => f.endsWith('.tmod')); } catch { return {}; }
  const registry = {};
  for (const f of tmodFiles) {
    try {
      const result = extractHjsonFiles(path.join(modsPath, f));
      if (!result || result.results.length === 0) continue;
      let allConfigs = {};
      for (const hjson of result.results) {
        const configs = parseHjsonForConfigs(hjson.content, hjson.path);
        for (const [cls, data] of Object.entries(configs)) {
          if (!allConfigs[cls]) { allConfigs[cls] = data; }
          else {
            if (data.displayName !== cls) allConfigs[cls].displayName = data.displayName;
            Object.assign(allConfigs[cls].properties, data.properties);
          }
        }
      }
      for (const [cls, data] of Object.entries(allConfigs)) {
        data.filename = result.name + '_' + cls + '.json';
      }
      if (Object.keys(allConfigs).length > 0) {
        registry[result.name] = { modName: result.name, version: result.version, configs: allConfigs };
      }
    } catch (e) { console.error(`[REGISTRY] Error scanning ${f}:`, e.message); }
  }
  modConfigRegistry = registry;
  registryScanTime = Date.now();
  let total = 0;
  for (const mod of Object.values(registry)) total += Object.keys(mod.configs).length;
  console.log(`[REGISTRY] Scanned ${tmodFiles.length} mods → ${Object.keys(registry).length} mods with configs, ${total} config classes`);
  return registry;
}

function getRegistryWithValues() {
  // Rescan if stale (>5 min) or never scanned
  if (!modConfigRegistry || Date.now() - registryScanTime > 5 * 60 * 1000) {
    scanModConfigRegistry();
  }
  const configsDir = getConfigsPath();
  // Deep clone registry
  const result = JSON.parse(JSON.stringify(modConfigRegistry));
  // Merge in existing config file values
  for (const [modName, mod] of Object.entries(result)) {
    for (const [cls, cfg] of Object.entries(mod.configs)) {
      const filePath = path.join(configsDir, cfg.filename);
      cfg.hasFile = false;
      cfg.values = {};
      if (fs.existsSync(filePath)) {
        try {
          cfg.values = JSON.parse(fs.readFileSync(filePath, 'utf8'));
          cfg.hasFile = true;
        } catch { /* bad json */ }
      }
    }
  }
  return result;
}

// ── Mod Management ──────────────────────────────────────────────────────────
function getModsPath() { return config.modsPath; }

function getEnabledMods() {
  const enabledPath = path.join(getModsPath(), 'enabled.json');
  try {
    return JSON.parse(fs.readFileSync(enabledPath, 'utf8'));
  } catch {
    return [];
  }
}

function setEnabledMods(list) {
  const enabledPath = path.join(getModsPath(), 'enabled.json');
  fs.writeFileSync(enabledPath, JSON.stringify(list, null, 2));
}

function listMods() {
  const modsPath = getModsPath();
  const enabled = getEnabledMods();
  let files;
  try {
    files = fs.readdirSync(modsPath).filter(f => f.endsWith('.tmod'));
  } catch {
    return [];
  }
  return files.map(f => {
    const fullPath = path.join(modsPath, f);
    const stat = fs.statSync(fullPath);
    const parsed = parseTmod(fullPath);
    return {
      filename: f,
      name: parsed ? parsed.name : f.replace('.tmod', ''),
      version: parsed ? parsed.version : 'unknown',
      tmlVersion: parsed ? parsed.tmlVersion : 'unknown',
      size: stat.size,
      enabled: enabled.includes(parsed ? parsed.name : f.replace('.tmod', ''))
    };
  });
}

// ── Workshop Map & Mod Updates ───────────────────────────────────────────────
const WORKSHOP_MAP_PATH = path.join(__dirname, 'workshop-map.json');
const STEAMCMD_PATHS = ['/usr/games/steamcmd', '/usr/local/bin/steamcmd', 'steamcmd'];
const STEAM_DOWNLOAD_BASE = path.join(os.homedir(), '.local', 'share', 'Steam', 'steamapps', 'workshop', 'content', '1281930');
const TMODLOADER_APPID = '1281930';

function loadWorkshopMap() {
  try {
    return JSON.parse(fs.readFileSync(WORKSHOP_MAP_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function findSteamCmd() {
  for (const p of STEAMCMD_PATHS) {
    try {
      if (fs.existsSync(p)) return p;
      // Try which/where
      execSync(`which ${p} 2>/dev/null`, { encoding: 'utf8' });
      return p;
    } catch { /* not found */ }
  }
  return null;
}

function steamApiPost(bodyStr) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.steampowered.com',
      path: '/ISteamRemoteStorage/GetPublishedFileDetails/v1/',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(bodyStr)
      }
    };
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('Steam API timeout')); });
    req.write(bodyStr);
    req.end();
  });
}

let updateCache = null;
let updateCacheTime = 0;
let updateCache_steamTimes = {}; // workshopId → time_updated from last check
const UPDATE_CACHE_TTL = 10 * 60 * 1000; // 10 min

async function checkForUpdates(force = false) {
  if (!force && updateCache && Date.now() - updateCacheTime < UPDATE_CACHE_TTL) {
    return updateCache;
  }

  const workshopMap = loadWorkshopMap();
  const modNames = Object.keys(workshopMap);
  if (modNames.length === 0) {
    return { mapped: false, updates: [], message: 'No workshop-map.json found. Run tools/build-workshop-map.js first.' };
  }

  // Build Steam API request body
  const ids = modNames.map(n => workshopMap[n].workshopId);
  const params = [`itemcount=${ids.length}`];
  ids.forEach((id, i) => params.push(`publishedfileids[${i}]=${id}`));
  const bodyStr = params.join('&');

  let apiResult;
  try {
    apiResult = await steamApiPost(bodyStr);
  } catch (e) {
    return { mapped: true, updates: [], error: 'Steam API request failed: ' + e.message };
  }

  const details = apiResult?.response?.publishedfiledetails || [];
  const modsPath = getModsPath();
  const updates = [];

  for (const modName of modNames) {
    const mapEntry = workshopMap[modName];
    const workshopId = mapEntry.workshopId;
    const detail = details.find(d => d.publishedfileid === String(workshopId));
    if (!detail || detail.result !== 1) {
      updates.push({ modName, workshopId, status: 'error', message: 'Not found on Steam Workshop' });
      continue;
    }

    const latestTime = detail.time_updated;
    const title = detail.title || modName;
    const tmodPath = path.join(modsPath, modName + '.tmod');
    const installed = fs.existsSync(tmodPath);

    // Extract installed version from .tmod binary
    let installedVersion = null;
    if (installed) {
      const parsed = parseTmod(tmodPath);
      if (parsed) installedVersion = parsed.version;
    }

    // Compare against stored lastKnownUpdate timestamp.
    // If we don't have one yet, assume an update may be available (conservative).
    const hasBaseline = !!mapEntry.lastKnownUpdate;
    const updateAvailable = hasBaseline ? latestTime > mapEntry.lastKnownUpdate : installed;
    updates.push({
      modName,
      workshopId,
      title,
      installedVersion,
      lastKnownUpdate: mapEntry.lastKnownUpdate,
      latestTime,
      updateAvailable,
      installed,
      status: !installed ? 'not_installed' : updateAvailable ? 'update_available' : 'up_to_date'
    });
  }

  // Store the latest Steam timestamps for use by mark-current
  updateCache_steamTimes = {};
  for (const d of details) {
    if (d.result === 1) updateCache_steamTimes[d.publishedfileid] = d.time_updated;
  }

  const result = {
    mapped: true,
    steamcmd: !!findSteamCmd(),
    total: updates.length,
    updatesAvailable: updates.filter(u => u.updateAvailable).length,
    updates: updates.sort((a, b) => {
      // Updates first, then alphabetical
      if (a.updateAvailable !== b.updateAvailable) return a.updateAvailable ? -1 : 1;
      return a.modName.localeCompare(b.modName);
    })
  };

  updateCache = result;
  updateCacheTime = Date.now();
  return result;
}

function downloadModUpdate(workshopId, modName) {
  return new Promise((resolve, reject) => {
    const steamcmd = findSteamCmd();
    if (!steamcmd) {
      reject(new Error('SteamCMD not found on this system'));
      return;
    }

    console.log(`[UPDATE] Downloading ${modName} (workshop ${workshopId}) via SteamCMD...`);
    const args = ['+login', 'anonymous', '+workshop_download_item', TMODLOADER_APPID, String(workshopId), '+quit'];

    const proc = execFile(steamcmd, args, { timeout: 300000 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[UPDATE] SteamCMD failed for ${modName}:`, err.message);
        reject(new Error('SteamCMD download failed: ' + err.message));
        return;
      }

      // Find the downloaded .tmod
      const itemDir = path.join(STEAM_DOWNLOAD_BASE, String(workshopId));
      if (!fs.existsSync(itemDir)) {
        reject(new Error('Download directory not found after SteamCMD'));
        return;
      }

      // Find latest version subfolder
      const subDirs = fs.readdirSync(itemDir)
        .filter(d => { try { return fs.statSync(path.join(itemDir, d)).isDirectory(); } catch { return false; } })
        .sort((a, b) => b.localeCompare(a));

      let tmodFile = null;
      for (const sub of subDirs) {
        const files = fs.readdirSync(path.join(itemDir, sub));
        const tmod = files.find(f => f.endsWith('.tmod') && !f.endsWith('.tmod.bak'));
        if (tmod) {
          tmodFile = path.join(itemDir, sub, tmod);
          break;
        }
      }

      if (!tmodFile) {
        reject(new Error('No .tmod file found in downloaded content'));
        return;
      }

      // Copy to Mods directory
      const dest = path.join(getModsPath(), modName + '.tmod');
      try {
        fs.copyFileSync(tmodFile, dest);
        console.log(`[UPDATE] ${modName} updated successfully`);
        // Update lastKnownUpdate in workshop map
        try {
          const wmap = loadWorkshopMap();
          if (wmap[modName]) {
            wmap[modName].lastKnownUpdate = Math.floor(Date.now() / 1000);
            fs.writeFileSync(WORKSHOP_MAP_PATH, JSON.stringify(wmap, null, 2));
          }
        } catch {}
        // Invalidate update cache
        updateCache = null;
        resolve({ ok: true, modName, source: tmodFile, dest });
      } catch (e) {
        reject(new Error('Failed to copy .tmod: ' + e.message));
      }
    });
  });
}

// ── Mod Config Editor ───────────────────────────────────────────────────────
function getConfigsPath() { return config.configsPath || path.join(getDefaultDataPath(), 'ModConfigs'); }

function listModConfigs() {
  const dir = getConfigsPath();
  try {
    return fs.readdirSync(dir)
      .filter(f => f.endsWith('.json'))
      .map(f => {
        const stat = fs.statSync(path.join(dir, f));
        return { filename: f, size: stat.size, modified: stat.mtime.toISOString() };
      });
  } catch {
    return [];
  }
}

function readModConfig(filename) {
  const safe = path.basename(filename);
  const filePath = path.join(getConfigsPath(), safe);
  return fs.readFileSync(filePath, 'utf8');
}

function writeModConfig(filename, content) {
  const safe = path.basename(filename);
  const filePath = path.join(getConfigsPath(), safe);
  fs.writeFileSync(filePath, content);
}

// ── World/Backup Management ─────────────────────────────────────────────────
function getWorldsPath() { return config.worldsPath || path.join(getDefaultDataPath(), 'Worlds'); }

function listWorlds() {
  const dir = getWorldsPath();
  let files;
  try {
    files = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const wldFiles = files.filter(f => f.endsWith('.wld'));
  return wldFiles.map(f => {
    const fullPath = path.join(dir, f);
    const stat = fs.statSync(fullPath);
    const baseName = f.replace('.wld', '');
    // Find associated backups
    const backups = files
      .filter(bf => {
        if (bf === f) return false;
        return bf.startsWith(baseName + '.wld.bak') || bf.startsWith(baseName + '.wld_backup_');
      })
      .map(bf => {
        const bStat = fs.statSync(path.join(dir, bf));
        return { filename: bf, size: bStat.size, modified: bStat.mtime.toISOString() };
      })
      .sort((a, b) => b.modified.localeCompare(a.modified));
    return {
      filename: f,
      name: baseName,
      size: stat.size,
      modified: stat.mtime.toISOString(),
      backups
    };
  });
}

function createWorldBackup(worldFilename) {
  const safe = path.basename(worldFilename);
  const dir = getWorldsPath();
  const wldPath = path.join(dir, safe);
  if (!fs.existsSync(wldPath)) throw new Error('World file not found');

  const baseName = safe.replace('.wld', '');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupName = `${baseName}.wld_backup_${timestamp}`;

  fs.copyFileSync(wldPath, path.join(dir, backupName));

  // Also backup .twld if it exists
  const twldPath = path.join(dir, baseName + '.twld');
  if (fs.existsSync(twldPath)) {
    fs.copyFileSync(twldPath, path.join(dir, `${baseName}.twld_backup_${timestamp}`));
  }

  return backupName;
}

function restoreWorldBackup(worldFilename, backupFilename) {
  if (serverProcess) throw new Error('Cannot restore while server is running');
  const dir = getWorldsPath();
  const safeBak = path.basename(backupFilename);
  const safeWorld = path.basename(worldFilename);
  const bakPath = path.join(dir, safeBak);
  const wldPath = path.join(dir, safeWorld);

  if (!fs.existsSync(bakPath)) throw new Error('Backup file not found');
  fs.copyFileSync(bakPath, wldPath);

  // Restore .twld backup if exists
  const baseName = safeWorld.replace('.wld', '');
  const twldBak = safeBak.replace('.wld', '.twld');
  const twldBakPath = path.join(dir, twldBak);
  if (fs.existsSync(twldBakPath)) {
    fs.copyFileSync(twldBakPath, path.join(dir, baseName + '.twld'));
  }

  return true;
}

function deleteWorldBackup(backupFilename) {
  const safe = path.basename(backupFilename);
  const filePath = path.join(getWorldsPath(), safe);
  if (!fs.existsSync(filePath)) throw new Error('Backup file not found');
  fs.unlinkSync(filePath);

  // Also delete associated .twld backup
  const twldBak = safe.replace('.wld', '.twld');
  const twldPath = path.join(getWorldsPath(), twldBak);
  if (fs.existsSync(twldPath)) fs.unlinkSync(twldPath);

  return true;
}

// ── Process Management ──────────────────────────────────────────────────────
function broadcastWs(msg) {
  const data = JSON.stringify(msg);
  for (const ws of wsClients) {
    if (ws.readyState === 1) ws.send(data);
  }
}

function appendLog(line) {
  logBuffer.push(line);
  if (logBuffer.length > MAX_LOG) logBuffer.shift();
  broadcastWs({ type: 'log', line });
}

function setStatus(status) {
  serverStatus = status;
  broadcastWs({ type: 'status', status, players, uptime: getUptime(), ram: getRam() });
}

function getUptime() {
  if (!startTime || serverStatus !== 'running') return 0;
  return Math.floor((Date.now() - startTime) / 1000);
}

function startServer() {
  if (serverProcess) return { error: 'Server already running' };
  if (!config.serverPath) return { error: 'Server path not configured' };
  setStatus('starting');
  logBuffer = [];
  players = [];

  const dotnetBin = getDotnetBinary(config.serverPath);

  const args = [
    path.join(config.serverPath, 'tModLoader.dll'),
    '-server',
    '-config', config.configFile
  ];

  const dotnetExtractDir = path.join(os.tmpdir(), '.net');

  serverProcess = spawn(dotnetBin, args, {
    cwd: config.serverPath,
    env: { ...process.env, DOTNET_BUNDLE_EXTRACT_BASE_DIR: dotnetExtractDir }
  });

  serverProcess.stdout.on('data', (data) => {
    const lines = data.toString().split('\n');
    for (const raw of lines) {
      const line = raw.replace(/\r$/, '');
      if (!line) continue;
      appendLog(line);

      const joinMatch = line.match(/^(.+?) has joined\.$/);
      const leaveMatch = line.match(/^(.+?) has left\.$/);
      if (joinMatch && !players.includes(joinMatch[1])) {
        players.push(joinMatch[1]);
        broadcastWs({ type: 'players', players });
      }
      if (leaveMatch) {
        players = players.filter(p => p !== leaveMatch[1]);
        broadcastWs({ type: 'players', players });
      }

      if (line.includes('Server started') || line.includes('Listening on port')) {
        startTime = Date.now();
        setStatus('running');
      }
    }
  });

  serverProcess.stderr.on('data', (data) => {
    data.toString().split('\n').forEach(line => {
      if (line.trim()) appendLog(`[ERR] ${line.replace(/\r$/, '')}`);
    });
  });

  serverProcess.on('close', (code) => {
    appendLog(`[MANAGER] Server process exited with code ${code}`);
    serverProcess = null;
    startTime = null;
    players = [];
    setStatus('stopped');
  });

  serverProcess.on('error', (err) => {
    appendLog(`[MANAGER] Failed to start: ${err.message}`);
    serverProcess = null;
    setStatus('stopped');
  });

  return { ok: true };
}

function stopServer() {
  if (!serverProcess) return { error: 'Server not running' };
  setStatus('stopping');
  serverProcess.stdin.write('exit\n');
  const killTimeout = setTimeout(() => {
    if (serverProcess) {
      appendLog('[MANAGER] Force killing server (timeout)');
      forceKill(serverProcess);
    }
  }, 30000);
  serverProcess.on('close', () => clearTimeout(killTimeout));
  return { ok: true };
}

function sendCommand(cmd) {
  if (!serverProcess) return { error: 'Server not running' };
  appendLog(`> ${cmd}`);
  serverProcess.stdin.write(cmd + '\n');
  return { ok: true };
}

// ── HTTP Server ─────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function json(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const route = url.pathname;

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // Serve frontend
  if (route === '/' || route === '/index.html') {
    const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
    return;
  }

  // ── Public routes (no auth) ───────────────────────────────────────────
  // Setup check
  if (route === '/api/needs-setup' && req.method === 'GET') {
    json(res, {
      needsSetup: isSetupNeeded(),
      defaults: {
        modsPath: config.modsPath || path.join(getDefaultDataPath(), 'Mods'),
        configsPath: config.configsPath || path.join(getDefaultDataPath(), 'ModConfigs'),
        worldsPath: config.worldsPath || path.join(getDefaultDataPath(), 'Worlds'),
        platform: PLATFORM,
        dataPath: getDefaultDataPath()
      }
    });
    return;
  }

  // Setup (only when needed)
  if (route === '/api/setup' && req.method === 'POST') {
    if (!isSetupNeeded()) {
      json(res, { error: 'Setup already completed' }, 403);
      return;
    }
    const body = JSON.parse((await readBody(req)).toString());
    if (!body.password || body.password.length < 4) {
      json(res, { error: 'Password must be at least 4 characters' }, 400);
      return;
    }
    config.passwordHash = hashPassword(body.password);
    if (body.serverPath) config.serverPath = body.serverPath;
    if (body.modsPath) config.modsPath = body.modsPath;
    if (body.configsPath) config.configsPath = body.configsPath;
    if (body.worldsPath) config.worldsPath = body.worldsPath;
    if (body.configFile) config.configFile = body.configFile;
    saveConfig();
    console.log('[MANAGER] Setup completed');
    json(res, { token: generateToken() });
    return;
  }

  // Login (with rate limiting)
  if (route === '/api/login' && req.method === 'POST') {
    const ip = getClientIp(req);
    if (!checkRateLimit(ip)) {
      json(res, { error: 'Too many login attempts. Try again later.' }, 429);
      return;
    }
    if (isSetupNeeded()) {
      json(res, { error: 'Setup required' }, 403);
      return;
    }
    const body = JSON.parse((await readBody(req)).toString());
    if (verifyPassword(body.password, config.passwordHash)) {
      json(res, { token: generateToken() });
    } else {
      json(res, { error: 'Invalid password' }, 401);
    }
    return;
  }

  // All other API routes require auth
  if (route.startsWith('/api/') && !checkAuth(req)) {
    json(res, { error: 'Unauthorized' }, 401);
    return;
  }

  // ── Authenticated API Routes ──────────────────────────────────────────
  try {
    if (route === '/api/status' && req.method === 'GET') {
      json(res, {
        status: serverStatus,
        uptime: getUptime(),
        ram: getRam(),
        players,
        playerCount: players.length,
        platform: PLATFORM,
        nodeVersion: process.version
      });
    }
    else if (route === '/api/start' && req.method === 'POST') {
      json(res, startServer());
    }
    else if (route === '/api/stop' && req.method === 'POST') {
      json(res, stopServer());
    }
    else if (route === '/api/restart' && req.method === 'POST') {
      if (serverProcess) {
        stopServer();
        const waitForStop = () => new Promise(resolve => {
          const check = setInterval(() => {
            if (!serverProcess) { clearInterval(check); resolve(); }
          }, 500);
          setTimeout(() => { clearInterval(check); resolve(); }, 35000);
        });
        await waitForStop();
      }
      json(res, startServer());
    }
    else if (route === '/api/command' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req)).toString());
      json(res, sendCommand(body.command));
    }
    // ── Mods ──
    else if (route === '/api/mods' && req.method === 'GET') {
      json(res, listMods());
    }
    else if (route === '/api/mods/toggle' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req)).toString());
      const enabled = getEnabledMods();
      const idx = enabled.indexOf(body.name);
      if (idx >= 0) {
        enabled.splice(idx, 1);
      } else {
        enabled.push(body.name);
      }
      setEnabledMods(enabled);
      json(res, { ok: true, enabled: idx < 0 });
    }
    else if (route === '/api/mods/upload' && req.method === 'POST') {
      const filename = url.searchParams.get('filename');
      if (!filename || !filename.endsWith('.tmod')) {
        json(res, { error: 'Invalid filename' }, 400);
        return;
      }
      const safe = path.basename(filename);
      const dest = path.join(getModsPath(), safe);
      const writeStream = fs.createWriteStream(dest);
      req.pipe(writeStream);
      writeStream.on('finish', () => {
        const parsed = parseTmod(dest);
        if (parsed) {
          const enabled = getEnabledMods();
          if (!enabled.includes(parsed.name)) {
            enabled.push(parsed.name);
            setEnabledMods(enabled);
          }
        }
        json(res, { ok: true, mod: parsed });
      });
      writeStream.on('error', (err) => {
        json(res, { error: err.message }, 500);
      });
    }
    else if (route === '/api/mods/delete' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req)).toString());
      const safe = path.basename(body.filename);
      const fullPath = path.join(getModsPath(), safe);
      if (fs.existsSync(fullPath)) {
        const parsed = parseTmod(fullPath);
        if (parsed) {
          const enabled = getEnabledMods();
          const filtered = enabled.filter(n => n !== parsed.name);
          setEnabledMods(filtered);
        }
        fs.unlinkSync(fullPath);
        json(res, { ok: true });
      } else {
        json(res, { error: 'File not found' }, 404);
      }
    }
    // ── Mod Updates ──
    else if (route === '/api/mods/updates' && req.method === 'GET') {
      const force = url.searchParams.get('force') === '1';
      try {
        const result = await checkForUpdates(force);
        json(res, result);
      } catch (err) {
        json(res, { error: err.message }, 500);
      }
    }
    else if (route === '/api/mods/update' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req)).toString());
      if (!body.workshopId || !body.modName) {
        json(res, { error: 'Missing workshopId or modName' }, 400);
        return;
      }
      try {
        const result = await downloadModUpdate(body.workshopId, body.modName);
        json(res, result);
      } catch (err) {
        json(res, { error: err.message }, 500);
      }
    }
    else if (route === '/api/mods/update-all' && req.method === 'POST') {
      try {
        const check = await checkForUpdates(true);
        const toUpdate = check.updates.filter(u => u.updateAvailable);
        if (toUpdate.length === 0) {
          json(res, { ok: true, updated: 0 });
          return;
        }
        const results = [];
        for (const mod of toUpdate) {
          try {
            await downloadModUpdate(mod.workshopId, mod.modName);
            results.push({ modName: mod.modName, ok: true });
          } catch (e) {
            results.push({ modName: mod.modName, ok: false, error: e.message });
          }
        }
        json(res, { ok: true, updated: results.filter(r => r.ok).length, total: toUpdate.length, results });
      } catch (err) {
        json(res, { error: err.message }, 500);
      }
    }
    else if (route === '/api/mods/mark-current' && req.method === 'POST') {
      // Mark specified mods (or all) as up-to-date by storing current Steam time_updated
      const body = JSON.parse((await readBody(req)).toString());
      const modNames = body.modNames; // array of mod names, or null for all
      const wmap = loadWorkshopMap();
      let count = 0;
      for (const [name, entry] of Object.entries(wmap)) {
        if (modNames && !modNames.includes(name)) continue;
        const steamTime = updateCache_steamTimes[String(entry.workshopId)];
        if (steamTime) {
          entry.lastKnownUpdate = steamTime;
          count++;
        }
      }
      try {
        fs.writeFileSync(WORKSHOP_MAP_PATH, JSON.stringify(wmap, null, 2));
        updateCache = null;
        json(res, { ok: true, marked: count });
      } catch (err) {
        json(res, { error: err.message }, 500);
      }
    }
    else if (route === '/api/workshop-map' && req.method === 'GET') {
      json(res, loadWorkshopMap());
    }
    else if (route === '/api/workshop-map' && req.method === 'PUT') {
      const body = JSON.parse((await readBody(req)).toString());
      try {
        fs.writeFileSync(WORKSHOP_MAP_PATH, JSON.stringify(body, null, 2));
        updateCache = null;
        json(res, { ok: true, count: Object.keys(body).length });
      } catch (err) {
        json(res, { error: err.message }, 500);
      }
    }
    // ── Mod Configs ──
    else if (route === '/api/modconfigs' && req.method === 'GET') {
      json(res, listModConfigs());
    }
    else if (route === '/api/modconfigs/registry' && req.method === 'GET') {
      json(res, getRegistryWithValues());
    }
    else if (route === '/api/modconfigs/rescan' && req.method === 'POST') {
      modConfigRegistry = null;
      scanModConfigRegistry();
      json(res, { ok: true, mods: Object.keys(modConfigRegistry).length });
    }
    else if (route === '/api/modconfigs/save' && req.method === 'PUT') {
      const body = JSON.parse((await readBody(req)).toString());
      if (!body.filename || !body.values) {
        json(res, { error: 'Missing filename or values' }, 400);
        return;
      }
      try {
        writeModConfig(body.filename, JSON.stringify(body.values, null, 2));
        json(res, { ok: true });
      } catch (err) {
        json(res, { error: err.message }, 500);
      }
    }
    else if (route.startsWith('/api/modconfigs/') && req.method === 'GET') {
      const filename = decodeURIComponent(route.slice('/api/modconfigs/'.length));
      try {
        const content = readModConfig(filename);
        json(res, { filename: path.basename(filename), content });
      } catch {
        json(res, { error: 'Config file not found' }, 404);
      }
    }
    else if (route.startsWith('/api/modconfigs/') && req.method === 'PUT') {
      const filename = decodeURIComponent(route.slice('/api/modconfigs/'.length));
      const body = JSON.parse((await readBody(req)).toString());
      try {
        writeModConfig(filename, body.content);
        json(res, { ok: true });
      } catch (err) {
        json(res, { error: err.message }, 500);
      }
    }
    // ── Worlds ──
    else if (route === '/api/worlds' && req.method === 'GET') {
      json(res, listWorlds());
    }
    else if (route === '/api/worlds/backup' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req)).toString());
      try {
        const backupName = createWorldBackup(body.filename);
        json(res, { ok: true, backupName });
      } catch (err) {
        json(res, { error: err.message }, 400);
      }
    }
    else if (route === '/api/worlds/restore' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req)).toString());
      try {
        restoreWorldBackup(body.worldFilename, body.backupFilename);
        json(res, { ok: true });
      } catch (err) {
        json(res, { error: err.message }, 400);
      }
    }
    else if (route === '/api/worlds/delete-backup' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req)).toString());
      try {
        deleteWorldBackup(body.filename);
        json(res, { ok: true });
      } catch (err) {
        json(res, { error: err.message }, 400);
      }
    }
    // ── Server Config ──
    else if (route === '/api/config' && req.method === 'GET') {
      try {
        const content = fs.readFileSync(config.configFile, 'utf8');
        json(res, { content });
      } catch {
        json(res, { content: '' });
      }
    }
    else if (route === '/api/config' && req.method === 'PUT') {
      const body = JSON.parse((await readBody(req)).toString());
      fs.writeFileSync(config.configFile, body.content);
      json(res, { ok: true });
    }
    else if (route === '/api/logs' && req.method === 'GET') {
      json(res, { lines: logBuffer });
    }
    else {
      json(res, { error: 'Not found' }, 404);
    }
  } catch (err) {
    console.error('API error:', err);
    json(res, { error: err.message }, 500);
  }
});

// ── WebSocket ───────────────────────────────────────────────────────────────
const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const token = url.searchParams.get('token');
  const entry = tokens.get(token);
  if (!entry || Date.now() - entry.created > TOKEN_TTL) {
    ws.close(4001, 'Unauthorized');
    return;
  }

  wsClients.add(ws);
  ws.send(JSON.stringify({ type: 'status', status: serverStatus, players, uptime: getUptime(), ram: getRam() }));
  ws.send(JSON.stringify({ type: 'logs', lines: logBuffer }));

  ws.on('close', () => wsClients.delete(ws));
  ws.on('error', () => wsClients.delete(ws));
});

// ── Periodic status broadcast ───────────────────────────────────────────────
setInterval(() => {
  if (wsClients.size > 0) {
    broadcastWs({ type: 'status', status: serverStatus, players, uptime: getUptime(), ram: getRam() });
  }
}, 5000);

// ── Start ───────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Terraria Manager v2 running on http://0.0.0.0:${PORT}`);
  console.log(`Platform: ${PLATFORM} | Node: ${process.version}`);
  if (isSetupNeeded()) console.log('First-run setup required — visit the web UI to configure.');
  // Scan mod config registry in background
  if (config.modsPath) {
    try { scanModConfigRegistry(); } catch (e) { console.error('[REGISTRY] Initial scan failed:', e.message); }
  }
});

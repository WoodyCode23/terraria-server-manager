# Terraria Server Manager

A web-based management panel for Terraria tModLoader dedicated servers. Single-file architecture, cross-platform, one dependency.

## Features

- **Dashboard** — Start/stop/restart server, live status, RAM usage, player list with kick
- **Mod Management** — Enable/disable mods, drag-and-drop upload, delete mods
- **Mod Config Editor** — Edit mod config JSON files with auto-generated forms or raw JSON
- **World & Backup Management** — List worlds, create/restore/delete timestamped backups
- **Live Console** — Real-time server output via WebSocket, send commands
- **Server Config** — Edit serverconfig.txt from the browser
- **First-Run Setup Wizard** — Auto-detects paths, guides initial configuration
- **Secure Auth** — scrypt password hashing, 24h token TTL, rate limiting

## Requirements

- **Node.js 18+**
- **tModLoader dedicated server** installed somewhere on the same machine

## Quick Start

```bash
git clone https://github.com/WoodyCode23/terraria-server-manager.git
cd terraria-manager
npm install
node server.js
```

Open `http://localhost:8080` in your browser. The setup wizard will guide you through initial configuration.

## Installation by OS

### Linux

```bash
cd /opt
git clone https://github.com/WoodyCode23/terraria-server-manager.git
cd terraria-manager
npm install

# Run with systemd
cp terraria-manager.service /etc/systemd/system/
# Edit paths in the service file
nano /etc/systemd/system/terraria-manager.service
systemctl enable --now terraria-manager
```

### Windows

```bash
git clone https://github.com/WoodyCode23/terraria-server-manager.git
cd terraria-manager
npm install
```

Double-click `terraria-manager.bat` to start, or run `node server.js`.

### macOS

```bash
git clone https://github.com/WoodyCode23/terraria-server-manager.git
cd terraria-manager
npm install
node server.js
```

For auto-start, edit paths in `terraria-manager.plist` and copy to `~/Library/LaunchAgents/`.

## Configuration

On first run, a `config.json` is auto-generated and the setup wizard walks you through it. You can also copy `config.example.json` and fill in the values manually.

| Field | Description |
|-------|-------------|
| `port` | HTTP port (default: 8080) |
| `passwordHash` | Auto-generated from your password (do not edit manually) |
| `serverPath` | Path to tModLoader server directory (contains tModLoader.dll) |
| `modsPath` | Path to Mods directory |
| `configsPath` | Path to ModConfigs directory |
| `worldsPath` | Path to Worlds directory |
| `configFile` | Path to serverconfig.txt |
| `maxLogLines` | Console log buffer size (default: 500) |

## License

MIT

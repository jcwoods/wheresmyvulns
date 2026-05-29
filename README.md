# Where's My Vulnerability (WMV)

An Electron desktop application for visualizing software supply chain risk. WMV loads or generates a Software Bill of Materials (SBOM), renders the dependency graph interactively, and color-codes each package node by the severity of its known vulnerabilities.

---

## Features

- **SBOM ingestion** — load existing SBOMs in CycloneDX (JSON or XML) and SPDX (JSON or tag-value) formats
- **SBOM generation** — scan a local project directory or a container image using [Syft](https://github.com/anchore/syft)
- **Dependency graph** — interactive graph with zoom, pan, and multiple layout options (Dagre, CoSE, breadth-first, circle, grid)
- **Vulnerability overlay** — fetches advisory data from [deps.dev](https://deps.dev) for each package and colors nodes by highest severity:

  | Color | Severity |
  |-------|----------|
  | 🔴 Red | Critical (CVSS ≥ 9.0) |
  | 🟠 Orange | High (CVSS ≥ 7.0) |
  | 🟡 Yellow | Medium (CVSS ≥ 4.0) |
  | 🟢 Green | Low / None |
  | 🔵 Blue | No known vulnerabilities |
  | ⚪ Gray | Unknown (not queryable) |

- **Local CVE database** — clones the [NVD CVE list](https://github.com/CVEProject/cvelistV5) from GitHub into a local SQLite database; subsequent refreshes use `git pull` for fast incremental updates
- **Advisory detail panel** — click any node to see its advisories, CVSS scores, CVE aliases, and full CVE descriptions from the local database

---

## Requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| [Node.js](https://nodejs.org) | 18 or 20 | 20 recommended |
| npm | 9+ | bundled with Node.js |
| [Syft](https://github.com/anchore/syft) | any recent | required only for directory/container scanning |
| Git | any | required to build/refresh the CVE database |
| Linux | — | Windows/macOS not tested |

### Installing Syft

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

Or via your package manager / [GitHub releases](https://github.com/anchore/syft/releases).

---

## Installation

```bash
git clone <repo-url> electron-wmv
cd electron-wmv
npm install
```

`npm install` automatically rebuilds the native SQLite module (`better-sqlite3`) for the bundled Electron runtime via the `postinstall` hook.

### Sandbox setup (Linux)

Electron's Chromium renderer requires either a properly configured SUID sandbox binary or the `--no-sandbox` flag. The npm package does not ship the binary with the correct permissions, so choose one of:

**Option A — fix the sandbox binary (recommended, requires sudo):**

```bash
sudo chown root:root node_modules/electron/dist/chrome-sandbox
sudo chmod 4755 node_modules/electron/dist/chrome-sandbox
```

**Option B — disable the sandbox (development only):**

Update the `start` script in `package.json`:

```json
"start": "electron --no-sandbox ."
```

> The sandbox isolates the renderer process from the OS. Disabling it is acceptable for a local developer tool; do not ship a production application with `--no-sandbox`.

---

## Running

```bash
npm start
```

---

## First Launch

On first launch, WMV checks for the local CVE database. If it does not exist, a dialog offers to build it:

1. **Build Database** — clones `https://github.com/CVEProject/cvelistV5` (~1 GB) and indexes all CVE records into a local SQLite database. This takes **10–30 minutes** depending on connection speed and disk performance. It only needs to be done once.
2. **Skip for Now** — the application opens without CVE detail lookups. Vulnerability severity data from deps.dev still works; only the local CVE description panel will show "Not in local CVE database."

The database is stored in the Electron user-data directory:

| Platform | Path |
|----------|------|
| Linux | `~/.config/electron-wmv/data/` |
| macOS | `~/Library/Application Support/electron-wmv/data/` |

The directory contains:
- `cve.db` — SQLite database of indexed CVE records
- `cvelistV5/` — the cloned Git repository (kept for fast incremental updates)

---

## Usage

### Loading an SBOM

**File → Load SBOM File** (`Ctrl+O`) or click **Load SBOM File** on the welcome screen.

Supported formats:
- CycloneDX 1.2–1.6 JSON (`.json`, `.cdx`)
- CycloneDX XML (`.xml`)
- SPDX 2.x JSON (`.json`)
- SPDX tag-value (`.spdx`)

### Scanning a directory

**File → Scan Local Directory** (`Ctrl+Shift+D`) or click **Scan Directory** on the welcome screen.

Syft scans the chosen directory and generates a CycloneDX SBOM in memory. Supports most language ecosystems (npm, pip, Go modules, Maven, Cargo, NuGet, gem, etc.).

### Scanning a container image

**File → Scan Container Image** (`Ctrl+Shift+K`) or click **Scan Container** on the welcome screen.

Enter any image reference Syft understands:

```
nginx:latest
ubuntu:22.04
docker.io/library/alpine:3.18
ghcr.io/org/image@sha256:abc123
```

Syft will pull the image if it is not cached locally.

### Fetching vulnerability data

After an SBOM is loaded, click **Fetch Vulnerabilities** in the toolbar. WMV queries [deps.dev](https://deps.dev) for each package in batches of 10, respects rate limits (HTTP 429 with exponential backoff), and colors the graph nodes on completion.

Supported ecosystems: npm, PyPI, Go, Maven, Cargo, NuGet, RubyGems, Packagist.

### Navigating the graph

| Action | Result |
|--------|--------|
| Scroll wheel | Zoom in/out |
| Click + drag background | Pan |
| Click a node | Select; highlights direct neighbors; shows details panel |
| Click background | Deselect all |
| **Fit Graph** button | Reset zoom to fit all nodes |
| Layout dropdown | Switch between Dagre, CoSE, breadth-first, circle, grid |

### Filtering and searching

- **Search box** (left sidebar) — filters the package list and fades non-matching nodes in the graph
- **Severity filter chips** — toggle visibility by severity tier

### Refreshing the CVE database

**Database → Refresh CVE Database** (`Ctrl+R`) — runs `git pull` in the local clone and re-indexes only the changed CVE files. Much faster than a full rebuild.

**Database → Rebuild CVE Database from Scratch** — deletes and recreates the database entirely.

---

## Architecture

```
electron-wmv/
├── main.js              # Electron main process — window, menu, IPC handlers
├── preload.js           # Context bridge — exposes window.wmv API to renderer
├── renderer/
│   ├── index.html       # Application shell
│   ├── renderer.js      # Graph, UI logic, IPC event handling
│   └── styles.css       # Dark theme
└── src/
    ├── sbom-parser.js   # CycloneDX and SPDX format parsers
    ├── deps-dev-api.js  # deps.dev REST client with rate-limit handling
    ├── cve-database.js  # SQLite CVE store; git clone/pull + bulk indexing
    └── syft-runner.js   # Spawns syft, captures CycloneDX JSON output
```

Data flow:

```
SBOM file / syft output
        │
   sbom-parser.js          ← parses into { components[], dependencies[] }
        │
   renderer.js             ← builds cytoscape graph (nodes = packages, edges = deps)
        │
   deps-dev-api.js         ← fetches advisory severity per package from deps.dev
        │
   cve-database.js         ← looks up full CVE records in local SQLite for detail panel
```

---

## License

MIT

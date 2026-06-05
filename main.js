'use strict';

// node_modules/electron shadows Electron's built-in module.  Fix: load via a Module
// instance whose paths don't include this project, so Node's resolver exhausts all
// candidates and Electron's own built-in fallback intercepts the request.
const _electron = (function () {
  const Module = require('module');
  const fake = new Module('/tmp/_wmv_shim.js');
  fake.paths = ['/tmp/__no_such_dir__/node_modules'];
  return Module._load('electron', fake, false);
}());
const { app, BrowserWindow, Menu, ipcMain, dialog } = _electron;
const path = require('path');
const fs = require('fs');

const { SbomParser } = require('./src/sbom-parser');
const { DepsDevApi } = require('./src/deps-dev-api');
const { CveDatabase } = require('./src/cve-database');
const { SyftRunner } = require('./src/syft-runner');

let mainWindow;
let cveDatabase;

// ─── Window ──────────────────────────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
    },
    title: "Where's My Vulnerability",
    backgroundColor: '#1e1e2e',
    show: false,
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Right-click context menu so users can paste a path/image ref into inputs.
  mainWindow.webContents.on('context-menu', (_event, params) => {
    if (!params.isEditable) return;
    Menu.buildFromTemplate([
      { role: 'cut', enabled: params.editFlags.canCut },
      { role: 'copy', enabled: params.editFlags.canCopy },
      { role: 'paste', enabled: params.editFlags.canPaste },
      { type: 'separator' },
      { role: 'selectAll' },
    ]).popup({ window: mainWindow });
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    buildMenu();
  });

  mainWindow.webContents.once('did-finish-load', () => {
    if (!cveDatabase.exists()) {
      mainWindow.webContents.send('offer-build-cve-db');
    } else {
      const stats = cveDatabase.getStats();
      mainWindow.webContents.send('cve-db-ready', stats);
    }
  });
}

// ─── Menu ─────────────────────────────────────────────────────────────────────

function buildMenu() {
  const template = [
    {
      label: 'File',
      submenu: [
        {
          label: 'Load SBOM File…',
          accelerator: 'CmdOrCtrl+O',
          click: menuLoadSbom,
        },
        {
          label: 'Scan Local Directory…',
          accelerator: 'CmdOrCtrl+Shift+D',
          click: menuScanDirectory,
        },
        {
          label: 'Scan Container Image…',
          accelerator: 'CmdOrCtrl+Shift+K',
          click: menuScanContainer,
        },
        { type: 'separator' },
        { role: 'quit' },
      ],
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' },
      ],
    },
    {
      label: 'Database',
      submenu: [
        {
          label: 'Refresh CVE Database',
          accelerator: 'CmdOrCtrl+R',
          click: menuRefreshCveDb,
        },
        {
          label: 'Rebuild CVE Database from Scratch…',
          click: menuRebuildCveDb,
        },
        { type: 'separator' },
        {
          label: 'CVE Database Status',
          click: menuCveDbStatus,
        },
      ],
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
      ],
    },
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ─── Menu handlers ────────────────────────────────────────────────────────────

async function menuLoadSbom() {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Load SBOM File',
    filters: [
      { name: 'SBOM Files', extensions: ['json', 'xml', 'spdx', 'cdx'] },
      { name: 'All Files', extensions: ['*'] },
    ],
    properties: ['openFile'],
  });
  if (!result.canceled && result.filePaths.length > 0) {
    mainWindow.webContents.send('load-sbom-file', result.filePaths[0]);
  }
}

async function menuScanDirectory() {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select Directory to Scan with Syft',
    properties: ['openDirectory'],
  });
  if (!result.canceled && result.filePaths.length > 0) {
    mainWindow.webContents.send('scan-directory', result.filePaths[0]);
  }
}

async function menuScanContainer() {
  mainWindow.webContents.send('show-container-dialog');
}

async function menuRefreshCveDb() {
  if (!cveDatabase.repoExists()) {
    const { response } = await dialog.showMessageBox(mainWindow, {
      type: 'info',
      buttons: ['Build Now', 'Cancel'],
      defaultId: 0,
      title: 'No CVE Database',
      message: 'CVE database has not been built yet.',
      detail: 'Would you like to build it now? This clones the NVD CVE list (~1 GB) and may take several minutes.',
    });
    if (response === 0) mainWindow.webContents.send('build-cve-db');
    return;
  }
  mainWindow.webContents.send('refresh-cve-db');
}

async function menuRebuildCveDb() {
  const { response } = await dialog.showMessageBox(mainWindow, {
    type: 'warning',
    buttons: ['Rebuild', 'Cancel'],
    defaultId: 1,
    title: 'Rebuild CVE Database',
    message: 'This will delete and rebuild the CVE database from scratch.',
    detail: 'This operation clones the NVD CVE list and may take 10–30 minutes depending on your connection speed.',
  });
  if (response === 0) mainWindow.webContents.send('rebuild-cve-db');
}

async function menuCveDbStatus() {
  if (!cveDatabase.exists()) {
    await dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'CVE Database Status',
      message: 'CVE database has not been built.',
      detail: 'Use Database → Refresh CVE Database to build it.',
    });
    return;
  }
  const stats = cveDatabase.getStats();
  await dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'CVE Database Status',
    message: 'CVE database is ready.',
    detail: [
      `Total CVEs: ${stats.total.toLocaleString()}`,
      `Published: ${stats.published.toLocaleString()}`,
      `Last updated: ${stats.lastUpdated || 'unknown'}`,
      `Database path: ${stats.dbPath}`,
    ].join('\n'),
  });
}

// ─── IPC handlers ─────────────────────────────────────────────────────────────

// Renderer-initiated dialogs (used by the empty-state buttons)
ipcMain.handle('dialog-open-sbom', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Load SBOM File',
    filters: [
      { name: 'SBOM Files', extensions: ['json', 'xml', 'spdx', 'cdx'] },
      { name: 'All Files', extensions: ['*'] },
    ],
    properties: ['openFile'],
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle('dialog-open-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select Directory to Scan with Syft',
    properties: ['openDirectory'],
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle('parse-sbom', async (_event, filePath) => {
  const parser = new SbomParser();
  return parser.parse(filePath);
});

ipcMain.handle('run-syft-dir', async (_event, dirPath) => {
  const syft = new SyftRunner();
  return syft.scanDirectory(dirPath, (msg) =>
    mainWindow.webContents.send('syft-progress', msg)
  );
});

ipcMain.handle('run-syft-container', async (_event, imageRef) => {
  const syft = new SyftRunner();
  return syft.scanContainer(imageRef, (msg) =>
    mainWindow.webContents.send('syft-progress', msg)
  );
});

ipcMain.handle('fetch-vulnerabilities', async (_event, packages) => {
  const api = new DepsDevApi();
  return api.fetchVulnerabilities(packages, (progress) =>
    mainWindow.webContents.send('vuln-fetch-progress', progress)
  );
});

ipcMain.handle('check-cve-db', () => ({
  exists: cveDatabase.exists(),
  repoExists: cveDatabase.repoExists(),
  stats: cveDatabase.exists() ? cveDatabase.getStats() : null,
}));

ipcMain.handle('build-cve-db', async () => {
  return cveDatabase.build((progress) =>
    mainWindow.webContents.send('cve-db-progress', progress)
  );
});

ipcMain.handle('refresh-cve-db', async () => {
  return cveDatabase.refresh((progress) =>
    mainWindow.webContents.send('cve-db-progress', progress)
  );
});

ipcMain.handle('lookup-cves', (_event, cveIds) => {
  if (!cveDatabase.exists()) return {};
  const result = {};
  for (const id of cveIds) {
    result[id] = cveDatabase.lookup(id);
  }
  return result;
});

ipcMain.handle('get-cve-stats', () =>
  cveDatabase.exists() ? cveDatabase.getStats() : null
);

// ─── App lifecycle ────────────────────────────────────────────────────────────

app.whenReady().then(() => {
  const dataDir = path.join(app.getPath('userData'), 'data');
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  cveDatabase = new CveDatabase(dataDir);
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

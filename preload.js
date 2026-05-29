'use strict';

const { contextBridge, ipcRenderer } = require('electron');

const ALLOWED_RECEIVE = new Set([
  'load-sbom-file',
  'scan-directory',
  'show-container-dialog',
  'refresh-cve-db',
  'rebuild-cve-db',
  'build-cve-db',
  'offer-build-cve-db',
  'cve-db-ready',
  'syft-progress',
  'vuln-fetch-progress',
  'cve-db-progress',
]);

contextBridge.exposeInMainWorld('wmv', {
  // Renderer-initiated file/directory dialogs
  openSbomDialog: () => ipcRenderer.invoke('dialog-open-sbom'),
  openDirectoryDialog: () => ipcRenderer.invoke('dialog-open-directory'),

  // SBOM operations
  parseSbom: (filePath) => ipcRenderer.invoke('parse-sbom', filePath),
  runSyftDir: (dirPath) => ipcRenderer.invoke('run-syft-dir', dirPath),
  runSyftContainer: (imageRef) => ipcRenderer.invoke('run-syft-container', imageRef),

  // Vulnerability data
  fetchVulnerabilities: (packages) =>
    ipcRenderer.invoke('fetch-vulnerabilities', packages),

  // CVE database
  checkCveDb: () => ipcRenderer.invoke('check-cve-db'),
  buildCveDb: () => ipcRenderer.invoke('build-cve-db'),
  refreshCveDb: () => ipcRenderer.invoke('refresh-cve-db'),
  lookupCves: (cveIds) => ipcRenderer.invoke('lookup-cves', cveIds),
  getCveStats: () => ipcRenderer.invoke('get-cve-stats'),

  // Event subscription (main → renderer)
  on: (channel, callback) => {
    if (!ALLOWED_RECEIVE.has(channel)) return;
    const handler = (_event, ...args) => callback(...args);
    ipcRenderer.on(channel, handler);
    // Return an unsubscribe function
    return () => ipcRenderer.removeListener(channel, handler);
  },
});

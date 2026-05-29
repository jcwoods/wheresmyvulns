'use strict';

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_COLOR = {
  CRITICAL: '#ff4d6d',
  HIGH:     '#ff8800',
  MEDIUM:   '#ffd600',
  LOW:      '#69db7c',
  NONE:     '#74c0fc',
  UNKNOWN:  '#adb5bd',
};

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'];

function sevColor(sev) {
  return SEV_COLOR[sev] || SEV_COLOR.UNKNOWN;
}

function sevClass(sev) {
  return (sev || 'unknown').toLowerCase();
}

// ── Application state ─────────────────────────────────────────────────────────

const state = {
  sbom: null,           // parsed SBOM
  vulnData: null,       // Map<componentId, { advisories, highestSeverity }>
  cveDetails: {},       // Map<cveId, CVE record from local DB>
  selectedId: null,     // currently selected component id
  activeFilters: new Set(SEV_ORDER),
  searchText: '',
};

// ── Cytoscape instance ────────────────────────────────────────────────────────

let cy = null;

function initCytoscape() {
  cytoscape.use(cytoscapeDagre);

  cy = cytoscape({
    container: document.getElementById('cy'),
    style: buildCyStyle(),
    layout: { name: 'grid' },
    minZoom: 0.05,
    maxZoom: 4,
    wheelSensitivity: 0.3,
  });

  cy.on('tap', 'node', (e) => {
    const id = e.target.id();
    selectComponent(id);
  });

  cy.on('tap', (e) => {
    if (e.target === cy) {
      selectComponent(null);
    }
  });
}

function buildCyStyle() {
  return [
    {
      selector: 'node',
      style: {
        'background-color': (ele) => sevColor(ele.data('severity')),
        'label': (ele) => {
          const n = ele.data('label') || '';
          return n.length > 22 ? n.slice(0, 20) + '…' : n;
        },
        'color': '#ffffff',
        'font-size': '11px',
        'font-weight': 'bold',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 5,
        'text-outline-color': '#1e1e2e',
        'text-outline-width': 2,
        'width': (ele) => Math.max(22, Math.min(56, 22 + (ele.data('degree') || 0) * 2)),
        'height': (ele) => Math.max(22, Math.min(56, 22 + (ele.data('degree') || 0) * 2)),
        'border-width': 2,
        'border-color': '#ffffff',
        'border-opacity': 0.35,
      },
    },
    {
      selector: 'node.root',
      style: {
        'shape': 'diamond',
        'width': 40,
        'height': 40,
        'border-width': 2.5,
      },
    },
    {
      selector: 'node:selected',
      style: {
        'border-width': 3,
        'border-color': '#89b4fa',
        'border-opacity': 1,
      },
    },
    {
      selector: 'node.faded',
      style: { 'opacity': 0.15 },
    },
    {
      selector: 'edge',
      style: {
        'line-color': '#6272a4',
        'target-arrow-color': '#6272a4',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'width': 1.5,
        'opacity': 0.8,
        'arrow-scale': 0.8,
      },
    },
    {
      selector: 'edge.highlighted',
      style: {
        'line-color': '#89b4fa',
        'target-arrow-color': '#89b4fa',
        'opacity': 1,
        'width': 1.5,
      },
    },
    {
      selector: 'edge.faded',
      style: { 'opacity': 0.05 },
    },
  ];
}

// ── Build and render graph ────────────────────────────────────────────────────

function buildGraph() {
  if (!state.sbom) return;
  const { components, dependencies } = state.sbom;

  // Index components by id
  const compMap = new Map(components.map((c) => [c.id, c]));

  // Compute in-degree for sizing
  const degree = new Map();
  for (const c of components) degree.set(c.id, 0);
  for (const d of dependencies) {
    degree.set(d.to, (degree.get(d.to) || 0) + 1);
  }

  const nodes = components.map((c) => ({
    data: {
      id: c.id,
      label: c.name || c.id,
      version: c.version || '',
      purl: c.purl || '',
      ecosystem: c.ecosystem || '',
      severity: (state.vulnData && state.vulnData[c.id]?.highestSeverity) || 'UNKNOWN',
      degree: degree.get(c.id) || 0,
      isRoot: c.isRoot || false,
    },
    classes: c.isRoot ? 'root' : '',
  }));

  const edges = [];
  const seen = new Set();
  for (const d of dependencies) {
    if (!compMap.has(d.from) || !compMap.has(d.to)) continue;
    const key = `${d.from}→${d.to}`;
    if (seen.has(key)) continue;
    seen.add(key);
    edges.push({ data: { id: key, source: d.from, target: d.to } });
  }

  cy.elements().remove();
  cy.add([...nodes, ...edges]);

  applyLayout(document.getElementById('layout-select').value);
  applyFilters();
}

function applyLayout(layoutName) {
  if (!cy || cy.nodes().length === 0) return;

  const nodeCount = cy.nodes().length;
  let layout;

  if (layoutName === 'dagre') {
    layout = {
      name: 'dagre',
      rankDir: 'TB',
      ranker: 'network-simplex',
      nodeSep: 30,
      edgeSep: 10,
      rankSep: 60,
      padding: 20,
      animate: nodeCount < 500,
      animationDuration: 300,
    };
  } else if (layoutName === 'cose') {
    layout = {
      name: 'cose',
      animate: nodeCount < 300,
      animationDuration: 400,
      nodeRepulsion: 450000,
      idealEdgeLength: 80,
      padding: 20,
    };
  } else {
    layout = {
      name: layoutName,
      animate: nodeCount < 300,
      padding: 20,
    };
  }

  cy.layout(layout).run();
}

// ── Vulnerability severity overlay ───────────────────────────────────────────

function applyVulnData() {
  if (!cy || !state.vulnData) return;

  cy.nodes().forEach((node) => {
    const vuln = state.vulnData[node.id()];
    if (vuln) {
      node.data('severity', vuln.highestSeverity || 'NONE');
    }
  });

  refreshPkgList();
  if (state.selectedId) renderDetails(state.selectedId);
}

// ── Filter & search ───────────────────────────────────────────────────────────

function applyFilters() {
  if (!cy) return;
  const text = state.searchText.toLowerCase();

  cy.nodes().forEach((node) => {
    const sev = node.data('severity') || 'UNKNOWN';
    const label = (node.data('label') || '').toLowerCase();
    const version = (node.data('version') || '').toLowerCase();
    const visible = state.activeFilters.has(sev) &&
      (!text || label.includes(text) || version.includes(text));
    node.toggleClass('faded', !visible);
  });
}

// ── Package list (sidebar) ────────────────────────────────────────────────────

function refreshPkgList() {
  if (!state.sbom) return;
  const list = document.getElementById('pkg-list');
  list.innerHTML = '';

  const text = state.searchText.toLowerCase();

  let shown = 0;
  for (const comp of state.sbom.components) {
    const sev = (state.vulnData && state.vulnData[comp.id]?.highestSeverity) || 'UNKNOWN';
    const label = (comp.name || comp.id).toLowerCase();
    const visible = state.activeFilters.has(sev) &&
      (!text || label.includes(text) || (comp.version || '').toLowerCase().includes(text));

    const item = document.createElement('div');
    item.className = 'pkg-item' + (comp.id === state.selectedId ? ' selected' : '') + (visible ? '' : ' hidden');
    item.dataset.id = comp.id;

    const dot = document.createElement('div');
    dot.className = 'pkg-dot';
    dot.style.background = sevColor(sev);

    const info = document.createElement('div');
    info.className = 'pkg-info';

    const name = document.createElement('div');
    name.className = 'pkg-name';
    name.textContent = comp.name || comp.id;
    name.title = comp.name || comp.id;

    const ver = document.createElement('div');
    ver.className = 'pkg-version';
    ver.textContent = comp.version || '';

    info.appendChild(name);
    info.appendChild(ver);
    item.appendChild(dot);
    item.appendChild(info);

    item.addEventListener('click', () => selectComponent(comp.id));
    list.appendChild(item);
    if (visible) shown++;
  }

  const stats = document.getElementById('sidebar-stats');
  const total = state.sbom.components.length;
  const vulnCount = state.vulnData
    ? Object.values(state.vulnData).filter((v) => v.highestSeverity && v.highestSeverity !== 'NONE' && v.highestSeverity !== 'UNKNOWN').length
    : 0;
  stats.textContent = `${shown}/${total} packages${vulnCount > 0 ? ` · ${vulnCount} with vulns` : ''}`;
}

// ── Component selection & details ─────────────────────────────────────────────

function selectComponent(id) {
  state.selectedId = id;

  // Update sidebar highlight
  document.querySelectorAll('.pkg-item').forEach((el) => {
    el.classList.toggle('selected', el.dataset.id === id);
  });

  // Update graph selection
  if (cy) {
    cy.elements().removeClass('faded highlighted');
    if (id) {
      const node = cy.getElementById(id);
      if (node.length) {
        node.select();
        const neighborhood = node.neighborhood().add(node);
        cy.elements().not(neighborhood).addClass('faded');
        node.connectedEdges().addClass('highlighted');
      }
    } else {
      cy.elements().unselect();
      applyFilters();
    }
  }

  renderDetails(id);
}

async function renderDetails(id) {
  const empty = document.getElementById('details-empty');
  const content = document.getElementById('details-content');

  if (!id || !state.sbom) {
    empty.style.display = '';
    content.style.display = 'none';
    return;
  }

  const comp = state.sbom.components.find((c) => c.id === id);
  if (!comp) { empty.style.display = ''; content.style.display = 'none'; return; }

  empty.style.display = 'none';
  content.style.display = '';

  const vuln = (state.vulnData && state.vulnData[id]) || { advisories: [], highestSeverity: 'UNKNOWN' };
  const sev = vuln.highestSeverity || 'UNKNOWN';

  document.getElementById('details-severity-badge').style.background = sevColor(sev);
  document.getElementById('details-name').textContent = comp.name || comp.id;
  document.getElementById('details-version').textContent = comp.version ? `v${comp.version}` : '(version unknown)';
  document.getElementById('details-purl').textContent = comp.purl || '';
  document.getElementById('details-ecosystem').textContent = comp.ecosystem ? `Ecosystem: ${comp.ecosystem}` : '';

  // Advisories
  const advDiv = document.getElementById('details-advisories');
  advDiv.innerHTML = '';

  if (!state.vulnData) {
    advDiv.innerHTML = '<div class="no-data">Click "Fetch Vulnerabilities" to load advisory data.</div>';
  } else if (vuln.error) {
    advDiv.innerHTML = `<div class="no-data">Error: ${escHtml(vuln.error)}</div>`;
  } else if (vuln.advisories.length === 0) {
    advDiv.innerHTML = '<div class="no-data">No known vulnerabilities.</div>';
  } else {
    for (const adv of vuln.advisories) {
      advDiv.appendChild(renderAdvisoryCard(adv));
    }
  }

  // CVE details from local DB
  const cveTitle = document.getElementById('details-cve-title');
  const cveList = document.getElementById('details-cve-list');
  cveList.innerHTML = '';

  const cveIds = (vuln.advisories || [])
    .flatMap((a) => a.aliases || [])
    .filter((a) => /^CVE-/i.test(a));

  if (cveIds.length === 0) {
    cveTitle.style.display = 'none';
  } else {
    cveTitle.style.display = '';
    // Fetch any CVEs not already in cache
    const missing = cveIds.filter((id) => !(id in state.cveDetails));
    if (missing.length > 0) {
      try {
        const fetched = await window.wmv.lookupCves(missing);
        Object.assign(state.cveDetails, fetched);
      } catch {}
    }
    for (const cveId of cveIds) {
      const rec = state.cveDetails[cveId];
      cveList.appendChild(renderCveCard(cveId, rec));
    }
  }
}

function renderAdvisoryCard(adv) {
  const card = document.createElement('div');
  card.className = `advisory-card ${sevClass(adv.severity)}`;

  const score = adv.cvss3Score != null ? adv.cvss3Score.toFixed(1) : '?';

  card.innerHTML = `
    <div class="advisory-id">${escHtml(adv.id)}</div>
    <div class="advisory-title">${escHtml(adv.title || '')}</div>
    <div class="advisory-score">
      <span class="score-badge ${sevClass(adv.severity)}">${escHtml(adv.severity || '?')}</span>
      <span>CVSS: ${score}</span>
    </div>
    ${adv.aliases && adv.aliases.length ? `<div class="advisory-aliases">Aliases: ${adv.aliases.map(escHtml).join(', ')}</div>` : ''}
    ${adv.url ? `<div><a class="advisory-link" href="${escHtml(adv.url)}" target="_blank">${escHtml(adv.url)}</a></div>` : ''}
  `;

  if (adv.url) {
    card.querySelector('.advisory-link').addEventListener('click', (e) => {
      e.preventDefault();
      // In Electron renderer, we can't open external URLs directly without shell.
      // Use a data attribute and let the main process handle it, or just copy.
      // For simplicity, we display the URL as text that users can copy.
    });
  }

  return card;
}

function renderCveCard(cveId, rec) {
  const card = document.createElement('div');
  card.className = 'cve-card';

  if (!rec) {
    card.innerHTML = `<div class="advisory-id">${escHtml(cveId)}</div><div class="no-data">Not in local CVE database.</div>`;
    return card;
  }

  const sev = rec.cvss3Severity || '';
  const score = rec.cvss3Score != null ? rec.cvss3Score.toFixed(1) : '?';

  card.innerHTML = `
    <div class="advisory-score">
      <span class="advisory-id">${escHtml(cveId)}</span>
      ${sev ? `<span class="score-badge ${sevClass(sev)}">${escHtml(sev)}</span>` : ''}
      <span>CVSS: ${score}</span>
    </div>
    ${rec.description ? `<div class="cve-desc">${escHtml(rec.description)}</div>` : ''}
    ${rec.cwes && rec.cwes.length ? `<div class="advisory-aliases">CWE: ${rec.cwes.map(escHtml).join(', ')}</div>` : ''}
    ${rec.publishedDate ? `<div class="advisory-aliases">Published: ${escHtml(rec.publishedDate)}</div>` : ''}
  `;
  return card;
}

// ── SBOM loading ──────────────────────────────────────────────────────────────

async function loadSbomFile(filePath) {
  setStatus(`Loading SBOM: ${filePath}`);
  try {
    const sbom = await window.wmv.parseSbom(filePath);
    onSbomLoaded(sbom, filePath);
  } catch (e) {
    setStatus(`Error loading SBOM: ${e.message}`, true);
  }
}

async function runSyftDir(dirPath) {
  setStatus(`Running syft on ${dirPath}…`);
  showProgress(true, 'Scanning directory…');
  try {
    const cycloneDxJson = await window.wmv.runSyftDir(dirPath);
    // syft outputs CycloneDX JSON; parse it directly
    const sbom = parseSyftOutput(cycloneDxJson);
    onSbomLoaded(sbom, dirPath);
  } catch (e) {
    setStatus(`Syft scan failed: ${e.message}`, true);
  } finally {
    showProgress(false);
  }
}

async function runSyftContainer(imageRef) {
  setStatus(`Scanning container ${imageRef}…`);
  showProgress(true, `Scanning ${imageRef}…`);
  try {
    const cycloneDxJson = await window.wmv.runSyftContainer(imageRef);
    const sbom = parseSyftOutput(cycloneDxJson);
    onSbomLoaded(sbom, imageRef);
  } catch (e) {
    setStatus(`Container scan failed: ${e.message}`, true);
  } finally {
    showProgress(false);
  }
}

function parseSyftOutput(cycloneDxJson) {
  // syft already returns a parsed CycloneDX JSON object
  // We need to convert it to our internal SBOM format.
  // Re-use the same logic as the main-process parser by reconstructing it here.
  const components = [];
  const dependencies = [];

  const rootRef = cycloneDxJson.metadata?.component?.['bom-ref'] || null;
  if (cycloneDxJson.metadata?.component) {
    const mc = cycloneDxJson.metadata.component;
    components.push({
      id: mc['bom-ref'] || mc.purl || mc.name,
      name: mc.name || '',
      version: mc.version || '',
      purl: mc.purl || null,
      type: mc.type || 'application',
      ecosystem: mc.purl ? purlEcosystem(mc.purl) : null,
      isRoot: true,
    });
  }

  for (const c of cycloneDxJson.components || []) {
    components.push({
      id: c['bom-ref'] || c.purl || `${c.name}@${c.version}`,
      name: c.name || '',
      version: c.version || '',
      purl: c.purl || null,
      type: c.type || 'library',
      ecosystem: c.purl ? purlEcosystem(c.purl) : null,
      isRoot: false,
    });
  }

  for (const dep of cycloneDxJson.dependencies || []) {
    for (const to of dep.dependsOn || []) {
      dependencies.push({ from: dep.ref, to });
    }
  }

  return {
    format: 'cyclonedx',
    specVersion: cycloneDxJson.specVersion || 'unknown',
    metadata: {
      name: cycloneDxJson.metadata?.component?.name || 'unknown',
      version: cycloneDxJson.metadata?.component?.version || '',
      timestamp: cycloneDxJson.metadata?.timestamp || '',
    },
    components,
    dependencies,
  };
}

function purlEcosystem(purl) {
  const m = purl.match(/^pkg:([^/]+)\//);
  return m ? m[1].toLowerCase() : null;
}

function onSbomLoaded(sbom, source) {
  state.sbom = sbom;
  state.vulnData = null;
  state.selectedId = null;
  state.cveDetails = {};

  const compCount = sbom.components.length;
  const depCount = sbom.dependencies.length;
  const shortSource = source.length > 60 ? '…' + source.slice(-57) : source;

  document.getElementById('sbom-label').textContent =
    `${shortSource} — ${compCount} packages, ${depCount} dependencies`;

  document.getElementById('empty-state').classList.add('hidden');
  document.getElementById('btn-fetch-vulns').disabled = false;

  buildGraph();
  refreshPkgList();
  renderDetails(null);

  setStatus(`Loaded ${compCount} packages from ${sbom.format.toUpperCase()} (${sbom.specVersion})`);
}

// ── Vulnerability fetch ───────────────────────────────────────────────────────

async function fetchVulnerabilities() {
  if (!state.sbom) return;

  document.getElementById('btn-fetch-vulns').disabled = true;
  setStatus('Fetching vulnerability data…');
  showProgress(true, 'Querying deps.dev…');

  try {
    const vulnData = await window.wmv.fetchVulnerabilities(state.sbom.components);
    state.vulnData = vulnData;
    applyVulnData();

    const withVulns = Object.values(vulnData).filter(
      (v) => v.highestSeverity && !['NONE', 'UNKNOWN'].includes(v.highestSeverity)
    ).length;
    setStatus(`Vulnerability scan complete — ${withVulns} package(s) have known vulnerabilities.`);
  } catch (e) {
    setStatus(`Vulnerability fetch failed: ${e.message}`, true);
  } finally {
    document.getElementById('btn-fetch-vulns').disabled = false;
    showProgress(false);
  }
}

// ── CVE DB build / refresh (modal) ───────────────────────────────────────────

function showCveBuildModal() {
  document.getElementById('modal-overlay').style.display = '';
  document.getElementById('modal-progress').style.display = 'none';
  document.getElementById('modal-build-btn').disabled = false;
  document.getElementById('modal-skip-btn').disabled = false;
}

function hideCveBuildModal() {
  document.getElementById('modal-overlay').style.display = 'none';
}

async function startCveDbBuild(rebuild) {
  document.getElementById('modal-build-btn').disabled = true;
  document.getElementById('modal-skip-btn').disabled = true;
  document.getElementById('modal-progress').style.display = '';
  setModalProgress(0, 'Starting…');

  try {
    const fn = rebuild ? window.wmv.buildCveDb : window.wmv.buildCveDb;
    await fn();
    hideCveBuildModal();
    const stats = await window.wmv.getCveStats();
    setStatus(`CVE database ready — ${stats?.total?.toLocaleString() || 0} records.`);
  } catch (e) {
    setModalProgress(0, `Error: ${e.message}`);
    document.getElementById('modal-skip-btn').disabled = false;
  }
}

async function refreshCveDb() {
  setStatus('Refreshing CVE database…');
  showProgress(true, 'Refreshing CVE data…');
  try {
    await window.wmv.refreshCveDb();
    const stats = await window.wmv.getCveStats();
    setStatus(`CVE database refreshed — ${stats?.total?.toLocaleString() || 0} records.`);
  } catch (e) {
    setStatus(`CVE refresh failed: ${e.message}`, true);
  } finally {
    showProgress(false);
  }
}

// ── Progress helpers ──────────────────────────────────────────────────────────

function showProgress(visible, msg) {
  const area = document.getElementById('progress-area');
  area.style.display = visible ? '' : 'none';
  if (msg) document.getElementById('progress-text').textContent = msg;
  if (!visible) setProgressPct(0);
}

function setProgressPct(pct) {
  document.getElementById('progress-bar-inner').style.width = `${Math.min(100, pct)}%`;
}

function setStatus(msg, isError) {
  const el = document.getElementById('status-msg');
  el.textContent = msg;
  el.style.color = isError ? '#f38ba8' : '';
}

function setModalProgress(pct, msg) {
  document.getElementById('modal-progress-bar-inner').style.width = `${Math.min(100, pct)}%`;
  document.getElementById('modal-progress-text').textContent = msg;
}

// ── Event subscriptions (IPC from main process) ───────────────────────────────

function subscribeIpc() {
  window.wmv.on('load-sbom-file', (filePath) => loadSbomFile(filePath));
  window.wmv.on('scan-directory', (dirPath) => runSyftDir(dirPath));
  window.wmv.on('show-container-dialog', () => showContainerModal());
  window.wmv.on('offer-build-cve-db', () => showCveBuildModal());
  window.wmv.on('build-cve-db', () => startCveDbBuild(false));
  window.wmv.on('rebuild-cve-db', () => startCveDbBuild(true));
  window.wmv.on('refresh-cve-db', () => refreshCveDb());

  window.wmv.on('cve-db-ready', (stats) => {
    setStatus(`CVE database ready — ${stats?.total?.toLocaleString() || 0} records.`);
  });

  window.wmv.on('syft-progress', (msg) => {
    setStatus(msg.message || '');
    if (msg.status === 'done') showProgress(false);
  });

  window.wmv.on('vuln-fetch-progress', ({ processed, total }) => {
    const pct = total > 0 ? (processed / total) * 100 : 0;
    setProgressPct(pct);
    document.getElementById('progress-text').textContent =
      `Querying deps.dev: ${processed}/${total}`;
  });

  window.wmv.on('cve-db-progress', (prog) => {
    if (prog.phase === 'build' || prog.phase === 'update') {
      const pct = prog.total > 0 ? (prog.processed / prog.total) * 100 : 0;
      setProgressPct(pct);
      setModalProgress(pct, `${prog.processed?.toLocaleString() || 0} / ${prog.total?.toLocaleString() || 0}`);
      document.getElementById('progress-text').textContent =
        `CVE DB: ${prog.processed?.toLocaleString() || 0} / ${prog.total?.toLocaleString() || 0}`;
    } else if (prog.message) {
      setStatus(prog.message);
      setModalProgress(0, prog.message);
      document.getElementById('progress-text').textContent = prog.message;
    }
    if (prog.phase === 'done') showProgress(false);
  });
}

// ── Container modal ───────────────────────────────────────────────────────────

function showContainerModal() {
  document.getElementById('container-modal-overlay').style.display = '';
  document.getElementById('container-image-input').value = '';
  document.getElementById('container-image-input').focus();
}

function hideContainerModal() {
  document.getElementById('container-modal-overlay').style.display = 'none';
}

// ── Utility ───────────────────────────────────────────────────────────────────

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── DOM wiring ────────────────────────────────────────────────────────────────

function wireUi() {
  // Toolbar
  document.getElementById('btn-fetch-vulns').addEventListener('click', fetchVulnerabilities);
  document.getElementById('btn-fit').addEventListener('click', () => {
    cy && cy.fit(undefined, 30);
  });
  document.getElementById('layout-select').addEventListener('change', (e) => {
    if (state.sbom) applyLayout(e.target.value);
  });

  // Empty state buttons — open native dialogs directly
  document.getElementById('empty-load').addEventListener('click', async () => {
    const filePath = await window.wmv.openSbomDialog();
    if (filePath) loadSbomFile(filePath);
  });
  document.getElementById('empty-scan-dir').addEventListener('click', async () => {
    const dirPath = await window.wmv.openDirectoryDialog();
    if (dirPath) runSyftDir(dirPath);
  });
  document.getElementById('empty-scan-container').addEventListener('click', () => showContainerModal());

  // Severity filters
  document.querySelectorAll('.sev-filter').forEach((label) => {
    label.addEventListener('click', () => {
      const sev = label.dataset.sev;
      if (state.activeFilters.has(sev)) {
        state.activeFilters.delete(sev);
        label.classList.remove('active');
      } else {
        state.activeFilters.add(sev);
        label.classList.add('active');
      }
      applyFilters();
      refreshPkgList();
    });
  });

  // Package search
  document.getElementById('pkg-search').addEventListener('input', (e) => {
    state.searchText = e.target.value;
    applyFilters();
    refreshPkgList();
  });

  // CVE build modal
  document.getElementById('modal-build-btn').addEventListener('click', () => startCveDbBuild(false));
  document.getElementById('modal-skip-btn').addEventListener('click', hideCveBuildModal);

  // Container modal
  document.getElementById('container-scan-btn').addEventListener('click', () => {
    const ref = document.getElementById('container-image-input').value.trim();
    if (!ref) { document.getElementById('container-image-input').focus(); return; }
    hideContainerModal();
    runSyftContainer(ref);
  });
  document.getElementById('container-cancel-btn').addEventListener('click', hideContainerModal);
  document.getElementById('container-image-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('container-scan-btn').click();
    if (e.key === 'Escape') hideContainerModal();
  });
}

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initCytoscape();
  subscribeIpc();
  wireUi();
});

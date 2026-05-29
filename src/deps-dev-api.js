'use strict';

const https = require('https');

const BASE_URL = 'https://api.deps.dev/v3alpha';
const BATCH_SIZE = 10;           // concurrent requests per batch
const BATCH_DELAY_MS = 200;      // pause between batches (ms)
const MAX_RETRIES = 4;
const INITIAL_RETRY_MS = 2000;

// Map PURL ecosystem → deps.dev system name
const PURL_TO_SYSTEM = {
  npm: 'npm',
  pypi: 'pypi',
  golang: 'go',
  go: 'go',
  maven: 'maven',
  cargo: 'cargo',
  nuget: 'nuget',
  rubygems: 'rubygems',
  composer: 'packagist',
};

class DepsDevApi {
  /**
   * Fetch vulnerability data for an array of SBOM components.
   * Each component: { id, name, version, purl, ecosystem }
   * Returns: Map<componentId, { advisories, highestSeverity, highestScore }>
   */
  async fetchVulnerabilities(components, progressCb) {
    // Only process components we can query
    const queryable = components.filter((c) => this._canQuery(c));
    const total = queryable.length;
    const results = new Map();
    let processed = 0;

    for (let i = 0; i < queryable.length; i += BATCH_SIZE) {
      const batch = queryable.slice(i, i + BATCH_SIZE);
      const settled = await Promise.allSettled(
        batch.map((c) => this._fetchComponent(c))
      );

      for (let j = 0; j < batch.length; j++) {
        const comp = batch[j];
        const outcome = settled[j];
        if (outcome.status === 'fulfilled') {
          results.set(comp.id, outcome.value);
        } else {
          results.set(comp.id, { advisories: [], highestSeverity: 'UNKNOWN', highestScore: null, error: outcome.reason?.message });
        }
        processed++;
      }

      if (progressCb) {
        progressCb({ processed, total, phase: 'fetching' });
      }

      // Pause between batches to be polite to the API
      if (i + BATCH_SIZE < queryable.length) {
        await sleep(BATCH_DELAY_MS);
      }
    }

    // Components we couldn't query get an UNKNOWN result
    for (const c of components) {
      if (!results.has(c.id)) {
        results.set(c.id, { advisories: [], highestSeverity: 'UNKNOWN', highestScore: null });
      }
    }

    // Convert Map to plain object for IPC serialization
    const out = {};
    for (const [id, val] of results) out[id] = val;
    return out;
  }

  // ─── Internal ─────────────────────────────────────────────────────────────

  _canQuery(comp) {
    if (!comp.purl) return false;
    const parsed = parsePurl(comp.purl);
    if (!parsed) return false;
    return !!PURL_TO_SYSTEM[parsed.type];
  }

  async _fetchComponent(comp) {
    const parsed = parsePurl(comp.purl);
    const system = PURL_TO_SYSTEM[parsed.type];
    const name = this._encodeName(system, parsed.name, parsed.namespace);
    const version = parsed.version;

    if (!version) {
      return { advisories: [], highestSeverity: 'UNKNOWN', highestScore: null };
    }

    const url = `${BASE_URL}/systems/${system}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`;
    const versionData = await this._get(url);

    // advisoryKeys may be absent if there are no known vulnerabilities
    const advisoryKeys = versionData.advisoryKeys || [];
    if (advisoryKeys.length === 0) {
      return { advisories: [], highestSeverity: 'NONE', highestScore: 0 };
    }

    // Fetch advisory details in parallel (they're usually few)
    const advisories = await Promise.all(
      advisoryKeys.map((k) => this._fetchAdvisory(k.id))
    );

    const validAdvisories = advisories.filter(Boolean);
    const { highestSeverity, highestScore } = this._aggregate(validAdvisories);

    return { advisories: validAdvisories, highestSeverity, highestScore };
  }

  async _fetchAdvisory(advisoryId) {
    try {
      const url = `${BASE_URL}/advisories/${encodeURIComponent(advisoryId)}`;
      const data = await this._get(url);
      return {
        id: advisoryId,
        title: data.title || '',
        url: data.url || '',
        aliases: data.aliases || [],
        cvss3Score: data.cvss3Score ?? null,
        cvss3Vector: data.cvss3Vector || null,
        severity: data.severity || 'UNKNOWN',
      };
    } catch {
      return null;
    }
  }

  _aggregate(advisories) {
    const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'];
    let highestSeverity = 'NONE';
    let highestScore = 0;

    for (const adv of advisories) {
      const score = adv.cvss3Score ?? 0;
      if (score > highestScore) highestScore = score;

      const sev = adv.severity || 'UNKNOWN';
      if (SEVERITY_ORDER.indexOf(sev) < SEVERITY_ORDER.indexOf(highestSeverity)) {
        highestSeverity = sev;
      }
    }

    // Normalize: if score is known, derive severity from it if API didn't give one
    if (highestScore > 0 && highestSeverity === 'NONE') {
      highestSeverity = scoreToSeverity(highestScore);
    }

    return { highestSeverity, highestScore };
  }

  _encodeName(system, name, namespace) {
    if (system === 'maven') {
      // Maven: namespace is groupId, name is artifactId → "groupId:artifactId"
      return namespace ? `${namespace}:${name}` : name;
    }
    if (system === 'go') {
      // Go: namespace is the path prefix, name is the full module path
      return namespace ? `${namespace}/${name}` : name;
    }
    return namespace ? `${namespace}/${name}` : name;
  }

  // ─── HTTP with retry ──────────────────────────────────────────────────────

  _get(url, retryMs = INITIAL_RETRY_MS, attempt = 0) {
    return new Promise((resolve, reject) => {
      const req = https.get(url, { headers: { 'Accept': 'application/json' } }, (res) => {
        if (res.statusCode === 429) {
          // Rate limited – respect Retry-After header
          const retryAfter = parseInt(res.headers['retry-after'] || '0', 10) * 1000 || retryMs;
          res.resume();
          if (attempt >= MAX_RETRIES) {
            return reject(new Error(`Rate limited after ${MAX_RETRIES} retries: ${url}`));
          }
          setTimeout(() => {
            this._get(url, Math.min(retryMs * 2, 60000), attempt + 1)
              .then(resolve)
              .catch(reject);
          }, retryAfter);
          return;
        }

        if (res.statusCode === 404) {
          res.resume();
          return resolve({});
        }

        if (res.statusCode !== 200) {
          res.resume();
          if (attempt < MAX_RETRIES) {
            return setTimeout(() => {
              this._get(url, retryMs * 2, attempt + 1).then(resolve).catch(reject);
            }, retryMs);
          }
          return reject(new Error(`HTTP ${res.statusCode}: ${url}`));
        }

        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            reject(new Error(`JSON parse error for ${url}: ${e.message}`));
          }
        });
      });

      req.on('error', (err) => {
        if (attempt < MAX_RETRIES) {
          setTimeout(() => {
            this._get(url, retryMs * 2, attempt + 1).then(resolve).catch(reject);
          }, retryMs);
        } else {
          reject(err);
        }
      });

      req.setTimeout(15000, () => {
        req.destroy(new Error(`Timeout: ${url}`));
      });
    });
  }
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function parsePurl(purl) {
  if (!purl) return null;
  // pkg:type/namespace/name@version?qualifiers#subpath
  const m = purl.match(/^pkg:([^/]+)\/(?:([^/]+)\/)?([^@?#]+)(?:@([^?#]*))?/);
  if (!m) return null;
  return {
    type: m[1].toLowerCase(),
    namespace: m[2] ? decodeURIComponent(m[2]) : null,
    name: decodeURIComponent(m[3]),
    version: m[4] ? decodeURIComponent(m[4]) : null,
  };
}

function scoreToSeverity(score) {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { DepsDevApi, parsePurl, scoreToSeverity };

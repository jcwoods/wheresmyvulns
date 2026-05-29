'use strict';

const fs = require('fs');
const path = require('path');
const { XMLParser } = require('fast-xml-parser');

/**
 * Parsed SBOM result:
 * {
 *   format: 'cyclonedx' | 'spdx',
 *   specVersion: string,
 *   metadata: { name, version, timestamp },
 *   components: [{ id, name, version, purl, type, ecosystem }],
 *   dependencies: [{ from: id, to: id }],
 * }
 */
class SbomParser {
  parse(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const content = fs.readFileSync(filePath, 'utf8');

    // Detect format by content first, then fall back to extension
    if (content.includes('"bomFormat"') && content.includes('"CycloneDX"')) {
      return this._parseCycloneDxJson(JSON.parse(content));
    }
    if (content.includes('<bom') && content.includes('cyclonedx')) {
      return this._parseCycloneDxXml(content);
    }
    if (
      content.includes('"spdxVersion"') ||
      content.includes('SPDXVersion:') ||
      content.startsWith('SPDX')
    ) {
      if (ext === '.json') {
        return this._parseSpdxJson(JSON.parse(content));
      }
      return this._parseSpdxTagValue(content);
    }
    if (ext === '.json') {
      const obj = JSON.parse(content);
      if (obj.bomFormat === 'CycloneDX') return this._parseCycloneDxJson(obj);
      if (obj.spdxVersion) return this._parseSpdxJson(obj);
    }
    if (ext === '.xml' || ext === '.cdx') {
      return this._parseCycloneDxXml(content);
    }
    if (ext === '.spdx') {
      return this._parseSpdxTagValue(content);
    }
    throw new Error('Unrecognized SBOM format. Expected CycloneDX JSON/XML or SPDX JSON/tag-value.');
  }

  // ─── CycloneDX JSON ──────────────────────────────────────────────────────────

  _parseCycloneDxJson(obj) {
    const components = [];
    const depMap = new Map();

    const rootRef = obj.metadata?.component?.['bom-ref'] || null;

    for (const comp of obj.components || []) {
      components.push(this._cdxComponent(comp));
      depMap.set(comp['bom-ref'] || comp.name, comp['bom-ref'] || comp.name);
    }

    // Include root metadata component if present
    if (obj.metadata?.component) {
      const root = this._cdxComponent(obj.metadata.component);
      root.isRoot = true;
      components.unshift(root);
    }

    const dependencies = [];
    for (const dep of obj.dependencies || []) {
      const fromId = dep.ref;
      for (const toId of dep.dependsOn || []) {
        dependencies.push({ from: fromId, to: toId });
      }
    }

    return {
      format: 'cyclonedx',
      specVersion: obj.specVersion || 'unknown',
      metadata: {
        name: obj.metadata?.component?.name || path.basename(obj.serialNumber || 'unknown'),
        version: obj.metadata?.component?.version || '',
        timestamp: obj.metadata?.timestamp || '',
      },
      components,
      dependencies,
    };
  }

  _cdxComponent(comp) {
    const purl = comp.purl || null;
    return {
      id: comp['bom-ref'] || comp.purl || `${comp.name}@${comp.version}`,
      name: comp.name || '',
      version: comp.version || '',
      purl,
      type: comp.type || 'library',
      ecosystem: purl ? this._purlEcosystem(purl) : null,
      isRoot: false,
    };
  }

  // ─── CycloneDX XML ───────────────────────────────────────────────────────────

  _parseCycloneDxXml(xmlContent) {
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      isArray: (name) =>
        ['component', 'dependency', 'dependsOn'].includes(name),
    });
    const doc = parser.parse(xmlContent);
    const bom = doc.bom || doc['ns2:bom'] || Object.values(doc)[0];

    const components = [];
    for (const comp of bom?.components?.component || []) {
      components.push({
        id: comp['@_bom-ref'] || comp.purl || `${comp.name}@${comp.version}`,
        name: comp.name || '',
        version: comp.version || '',
        purl: comp.purl || null,
        type: comp['@_type'] || 'library',
        ecosystem: comp.purl ? this._purlEcosystem(comp.purl) : null,
        isRoot: false,
      });
    }

    const metaComp = bom?.metadata?.component;
    if (metaComp) {
      components.unshift({
        id: metaComp['@_bom-ref'] || metaComp.purl || metaComp.name,
        name: metaComp.name || '',
        version: metaComp.version || '',
        purl: metaComp.purl || null,
        type: metaComp['@_type'] || 'application',
        ecosystem: metaComp.purl ? this._purlEcosystem(metaComp.purl) : null,
        isRoot: true,
      });
    }

    const dependencies = [];
    for (const dep of bom?.dependencies?.dependency || []) {
      const fromId = dep['@_ref'];
      for (const to of dep.dependency || []) {
        dependencies.push({ from: fromId, to: to['@_ref'] });
      }
    }

    return {
      format: 'cyclonedx',
      specVersion: bom?.['@_version'] || bom?.version || 'unknown',
      metadata: {
        name: metaComp?.name || 'unknown',
        version: metaComp?.version || '',
        timestamp: bom?.metadata?.timestamp || '',
      },
      components,
      dependencies,
    };
  }

  // ─── SPDX JSON ───────────────────────────────────────────────────────────────

  _parseSpdxJson(obj) {
    const components = [];
    const idMap = new Map();

    for (const pkg of obj.packages || []) {
      const purl = this._spdxPurl(pkg);
      const comp = {
        id: pkg.SPDXID,
        name: pkg.name || '',
        version: pkg.versionInfo || '',
        purl,
        type: 'library',
        ecosystem: purl ? this._purlEcosystem(purl) : null,
        isRoot: pkg.SPDXID === 'SPDXRef-DOCUMENT',
      };
      components.push(comp);
      idMap.set(pkg.SPDXID, comp);
    }

    const dependencies = [];
    const DEPENDENCY_RELS = new Set([
      'DEPENDS_ON',
      'DYNAMIC_LINK',
      'STATIC_LINK',
      'RUNTIME_DEPENDENCY_OF',
      'DEV_DEPENDENCY_OF',
      'BUILD_DEPENDENCY_OF',
      'OPTIONAL_DEPENDENCY_OF',
    ]);
    for (const rel of obj.relationships || []) {
      if (DEPENDENCY_RELS.has(rel.relationshipType)) {
        dependencies.push({ from: rel.spdxElementId, to: rel.relatedSpdxElement });
      }
    }

    // Mark the document-described package as root
    for (const rel of obj.relationships || []) {
      if (rel.relationshipType === 'DESCRIBES') {
        const comp = idMap.get(rel.relatedSpdxElement);
        if (comp) comp.isRoot = true;
      }
    }

    return {
      format: 'spdx',
      specVersion: obj.spdxVersion || 'unknown',
      metadata: {
        name: obj.name || obj.documentNamespace || 'unknown',
        version: '',
        timestamp: obj.creationInfo?.created || '',
      },
      components,
      dependencies,
    };
  }

  // ─── SPDX tag-value ──────────────────────────────────────────────────────────

  _parseSpdxTagValue(content) {
    const lines = content.split('\n');
    const components = [];
    const relationships = [];
    let current = null;
    let docName = '';
    let spdxVersion = '';

    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const colonIdx = line.indexOf(':');
      if (colonIdx === -1) continue;
      const tag = line.slice(0, colonIdx).trim();
      const value = line.slice(colonIdx + 1).trim();

      switch (tag) {
        case 'SPDXVersion': spdxVersion = value; break;
        case 'DocumentName': docName = value; break;
        case 'PackageName':
          if (current) components.push(current);
          current = { id: null, name: value, version: '', purl: null, type: 'library', ecosystem: null, isRoot: false };
          break;
        case 'SPDXID':
          if (current) current.id = value;
          break;
        case 'PackageVersion':
          if (current) current.version = value;
          break;
        case 'ExternalRef':
          if (current) {
            const parts = value.split(/\s+/);
            if (parts.length >= 3 && parts[1] === 'purl') {
              current.purl = parts[2];
              current.ecosystem = this._purlEcosystem(parts[2]);
            }
          }
          break;
        case 'Relationship': {
          const parts = value.split(/\s+/);
          if (parts.length >= 3) {
            relationships.push({ from: parts[0], type: parts[1], to: parts[2] });
          }
          break;
        }
      }
    }
    if (current) components.push(current);

    const DEPENDENCY_RELS = new Set([
      'DEPENDS_ON', 'DYNAMIC_LINK', 'STATIC_LINK',
      'RUNTIME_DEPENDENCY_OF', 'DEV_DEPENDENCY_OF',
      'BUILD_DEPENDENCY_OF', 'OPTIONAL_DEPENDENCY_OF',
    ]);
    const dependencies = relationships
      .filter((r) => DEPENDENCY_RELS.has(r.type))
      .map((r) => ({ from: r.from, to: r.to }));

    for (const rel of relationships) {
      if (rel.type === 'DESCRIBES') {
        const comp = components.find((c) => c.id === rel.to);
        if (comp) comp.isRoot = true;
      }
    }

    return {
      format: 'spdx',
      specVersion: spdxVersion || 'unknown',
      metadata: { name: docName || 'unknown', version: '', timestamp: '' },
      components,
      dependencies,
    };
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────────

  _spdxPurl(pkg) {
    for (const ref of pkg.externalRefs || []) {
      if (
        ref.referenceType === 'purl' ||
        (ref.referenceCategory === 'PACKAGE-MANAGER' && ref.referenceType === 'purl')
      ) {
        return ref.referenceLocator;
      }
    }
    return null;
  }

  _purlEcosystem(purl) {
    if (!purl) return null;
    const m = purl.match(/^pkg:([^/]+)\//);
    return m ? m[1].toLowerCase() : null;
  }
}

module.exports = { SbomParser };

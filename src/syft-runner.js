'use strict';

const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

class SyftRunner {
  constructor() {
    this.syftPath = this._findSyft();
  }

  _findSyft() {
    // Common install locations
    const candidates = [
      '/usr/local/bin/syft',
      '/usr/bin/syft',
      path.join(os.homedir(), '.local', 'bin', 'syft'),
      path.join(os.homedir(), 'bin', 'syft'),
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }
    // Fall back to PATH lookup
    try {
      const found = execSync('which syft 2>/dev/null || command -v syft 2>/dev/null', { encoding: 'utf8' }).trim();
      if (found) return found;
    } catch {}
    throw new Error(
      'syft not found. Install it from https://github.com/anchore/syft or place it in your PATH.'
    );
  }

  /**
   * Scan a local directory and return parsed SBOM.
   */
  scanDirectory(dirPath, progressCb) {
    if (!fs.existsSync(dirPath)) {
      throw new Error(`Directory not found: ${dirPath}`);
    }
    if (progressCb) progressCb({ status: 'running', message: `Scanning directory: ${dirPath}` });
    return this._run(`dir:${dirPath}`, progressCb);
  }

  /**
   * Scan a container image reference and return parsed SBOM.
   * imageRef examples: "nginx:latest", "ubuntu:22.04", "docker.io/library/alpine:3.18"
   */
  scanContainer(imageRef, progressCb) {
    if (progressCb) progressCb({ status: 'running', message: `Scanning container: ${imageRef}` });
    return this._run(imageRef, progressCb);
  }

  /**
   * Remove `file`-type components from a CycloneDX SBOM.
   *
   * Some syft versions don't support `--exclude-catalogers files`, so instead we
   * strip file components after the fact. This also prunes the dependency graph
   * so no dangling references to the removed components remain. Applies to both
   * directory and container scans (both flow through `_run`).
   */
  _filterFileComponents(sbom) {
    if (!sbom || !Array.isArray(sbom.components)) return sbom;

    const removedRefs = new Set();
    sbom.components = sbom.components.filter((c) => {
      if (c && c.type === 'file') {
        if (c['bom-ref']) removedRefs.add(c['bom-ref']);
        return false;
      }
      return true;
    });

    if (removedRefs.size && Array.isArray(sbom.dependencies)) {
      sbom.dependencies = sbom.dependencies
        .filter((d) => !removedRefs.has(d.ref))
        .map((d) => {
          if (Array.isArray(d.dependsOn)) {
            d.dependsOn = d.dependsOn.filter((ref) => !removedRefs.has(ref));
          }
          return d;
        });
    }

    return sbom;
  }

  _run(source, progressCb) {
    return new Promise((resolve, reject) => {
      const tmpFile = path.join(os.tmpdir(), `wmv-sbom-${Date.now()}.json`);

      const args = [
        source,
        '--output', `cyclonedx-json=${tmpFile}`,
        '--quiet',
      ];

      const proc = spawn(this.syftPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });

      let stderrBuf = '';
      proc.stderr.on('data', (d) => {
        const msg = d.toString();
        stderrBuf += msg;
        if (progressCb) {
          for (const line of msg.split('\n')) {
            const l = line.trim();
            if (l) progressCb({ status: 'running', message: l });
          }
        }
      });

      // stdout would be the SBOM if we used --output=-, but we use a file
      proc.stdout.resume();

      proc.on('close', (code) => {
        if (code !== 0) {
          try { fs.unlinkSync(tmpFile); } catch {}
          return reject(
            new Error(`syft exited with code ${code}.\n${stderrBuf.slice(-500)}`)
          );
        }

        if (!fs.existsSync(tmpFile)) {
          return reject(new Error('syft did not produce an output file.'));
        }

        try {
          const json = JSON.parse(fs.readFileSync(tmpFile, 'utf8'));
          fs.unlinkSync(tmpFile);
          const filtered = this._filterFileComponents(json);
          if (progressCb) progressCb({ status: 'done', message: 'Syft scan complete.' });
          resolve(filtered);
        } catch (e) {
          try { fs.unlinkSync(tmpFile); } catch {}
          reject(new Error(`Failed to read syft output: ${e.message}`));
        }
      });

      proc.on('error', (err) => {
        try { fs.unlinkSync(tmpFile); } catch {}
        reject(new Error(`Failed to spawn syft: ${err.message}`));
      });
    });
  }
}

module.exports = { SyftRunner };

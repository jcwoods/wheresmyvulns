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

  _run(source, progressCb) {
    return new Promise((resolve, reject) => {
      const tmpFile = path.join(os.tmpdir(), `wmv-sbom-${Date.now()}.json`);

      const args = [
        source,
        '--output', `cyclonedx-json=${tmpFile}`,
        '--exclude-catalogers', 'files',
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
          if (progressCb) progressCb({ status: 'done', message: 'Syft scan complete.' });
          resolve(json);
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

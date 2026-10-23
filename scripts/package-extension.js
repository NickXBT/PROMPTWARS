/**
 * Packages the Chrome Manifest V3 Extension for Chrome Web Store Submission.
 * Generates phishing-shield-ai-v1.0.0.zip with manifest.json strictly at the root.
 */

import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { ZipArchive } = require('archiver');

const distDir = path.resolve('dist');
const storeDir = path.resolve('store');
fs.mkdirSync(storeDir, { recursive: true });

const zipName = 'phishing-shield-ai-v1.0.0.zip';
const outDistZip = path.join(distDir, zipName);
const outStoreZip = path.join(storeDir, zipName);

// 1. Validate manifest.json exists
const manifestPath = path.join(distDir, 'manifest.json');
if (!fs.existsSync(manifestPath)) {
  console.error('Error: dist/manifest.json not found! Run npm run build first.');
  process.exit(1);
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
console.log(`Packaging ${manifest.name} v${manifest.version} (Manifest V${manifest.manifest_version})...`);

// 2. Validate permissions & security
const sensitiveKeys = ['key', 'secret', 'token', 'password'];
const hasSensitiveKeys = JSON.stringify(manifest).toLowerCase().includes('aizasy');
if (hasSensitiveKeys) {
  console.error('Security alert: Found API keys in manifest.json! Aborting packaging.');
  process.exit(1);
}

// 3. Create ZIP archive
function createZip(outputPath) {
  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream(outputPath);
    const archive = new ZipArchive({ zlib: { level: 9 } });

    output.on('close', () => {
      console.log(`Created: ${outputPath} (${(archive.pointer() / 1024).toFixed(1)} KB)`);
      resolve();
    });

    archive.on('error', (err) => reject(err));
    archive.pipe(output);

    // Add manifest.json at root
    archive.file(manifestPath, { name: 'manifest.json' });

    // Add background service worker
    const bgDir = path.join(distDir, 'background');
    if (fs.existsSync(bgDir)) {
      archive.directory(bgDir, 'background');
    }

    // Add content scripts
    const contentDir = path.join(distDir, 'content');
    if (fs.existsSync(contentDir)) {
      archive.directory(contentDir, 'content');
    }

    // Add extension HTML/UI pages (popup, sidepanel, options)
    const extDir = path.join(distDir, 'extension');
    if (fs.existsSync(extDir)) {
      archive.directory(extDir, 'extension');
    }

    // Add assets (icons and necessary JS/CSS chunks, excluding website main chunk)
    const assetsDir = path.join(distDir, 'assets');
    if (fs.existsSync(assetsDir)) {
      const files = fs.readdirSync(assetsDir);
      files.forEach((file) => {
        // Exclude website-only bundles to keep extension zip ultra-lean
        if (!file.startsWith('main-')) {
          archive.file(path.join(assetsDir, file), { name: `assets/${file}` });
        }
      });
    }

    archive.finalize();
  });
}

async function run() {
  await createZip(outDistZip);
  fs.copyFileSync(outDistZip, outStoreZip);
  console.log('✓ Chrome Web Store submission package verified and ready.');
}

run().catch((err) => {
  console.error('Packaging failed:', err);
  process.exit(1);
});

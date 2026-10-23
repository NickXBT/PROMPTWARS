/**
 * Lightweight HTTP server for Phishing Shield AI local test pages.
 * Runs on http://localhost:3000
 */

import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = 3000;

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.png': 'image/png'
};

const server = http.createServer((req, res) => {
  let reqPath = req.url ? req.url.split('?')[0] : '/';
  if (reqPath === '/') {
    // Index page listing all test cases
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Phishing Shield AI - Demo Test Suite</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 650px; margin: 40px auto; padding: 20px; line-height: 1.6; }
          h1 { color: #0F172A; }
          .card { border: 1px solid #E2E8F0; border-radius: 8px; padding: 16px; margin-bottom: 16px; transition: transform 0.1s; }
          .card:hover { border-color: #3B82F6; }
          .tag { font-size: 11px; padding: 2px 6px; border-radius: 4px; font-weight: bold; text-transform: uppercase; }
          .tag-danger { background: #FEE2E2; color: #DC2626; }
          .tag-safe { background: #D1FAE5; color: #059669; }
          a { font-weight: 600; text-decoration: none; color: #2563EB; font-size: 16px; }
          p { margin: 6px 0 0 0; color: #64748B; font-size: 13px; }
        </style>
      </head>
      <body>
        <h1>🛡️ Phishing Shield AI — Demo Pages</h1>
        <p>Click any test scenario to open it and verify the Chrome extension's detection:</p>
        <div style="margin-top: 24px;">
          <div class="card">
            <span class="tag tag-danger">Simulated Phishing</span>
            <div><a href="/phishing-bank.html">1. Chase Online Banking Impersonation</a></div>
            <p>Impersonation, urgency pretext, password harvesting form, link-text mismatch.</p>
          </div>
          <div class="card">
            <span class="tag tag-danger">Simulated Phishing</span>
            <div><a href="/phishing-delivery.html">2. Express Delivery Customs Fee Scam</a></div>
            <p>24-hour urgency demand, credit card harvesting form, shortened tracking link.</p>
          </div>
          <div class="card">
            <span class="tag tag-danger">Simulated Phishing</span>
            <div><a href="/phishing-account.html">3. Microsoft Account Suspension & OTP Interception</a></div>
            <p>Account suspension alert, credential request, one-time verification password input.</p>
          </div>
          <div class="card">
            <span class="tag tag-safe">Legitimate Control</span>
            <div><a href="/legitimate-example.html">4. TechInsight Engineering Blog</a></div>
            <p>Ordinary content, newsletter signup, benign link labels, zero credential theft cues.</p>
          </div>
        </div>
      </body>
      </html>
    `);
    return;
  }

  const filePath = path.join(__dirname, reqPath);
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 Not Found');
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const mime = MIME_TYPES[ext] || 'application/octet-stream';

  res.writeHead(200, { 'Content-Type': mime });
  fs.createReadStream(filePath).pipe(res);
});

server.listen(PORT, () => {
  console.log(`Demo test server running on http://localhost:${PORT}`);
});

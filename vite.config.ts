import { defineConfig } from 'vite';
import { resolve } from 'path';
import { copyFileSync, mkdirSync, existsSync } from 'fs';

export default defineConfig({
  root: '.',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        popup: resolve(__dirname, 'extension/popup/popup.html'),
        options: resolve(__dirname, 'extension/options/options.html'),
        sidepanel: resolve(__dirname, 'extension/sidepanel/sidepanel.html'),
        'service-worker': resolve(__dirname, 'extension/background/service-worker.ts'),
        'content-script': resolve(__dirname, 'extension/content/content-script.ts')
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'service-worker') {
            return 'background/service-worker.js';
          }
          if (chunkInfo.name === 'content-script') {
            return 'content/content-script.js';
          }
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]'
      }
    }
  },
  plugins: [
    {
      name: 'copy-extension-manifest-and-assets',
      closeBundle() {
        const outDir = resolve(__dirname, 'dist');
        const manifestSrc = resolve(__dirname, 'extension/manifest.json');
        const manifestDist = resolve(outDir, 'manifest.json');
        
        if (existsSync(manifestSrc)) {
          copyFileSync(manifestSrc, manifestDist);
        }

        // Copy content stylesheet if exists
        const contentCssSrc = resolve(__dirname, 'extension/content/styles.css');
        const contentCssDistDir = resolve(outDir, 'content');
        if (!existsSync(contentCssDistDir)) {
          mkdirSync(contentCssDistDir, { recursive: true });
        }
        if (existsSync(contentCssSrc)) {
          copyFileSync(contentCssSrc, resolve(contentCssDistDir, 'styles.css'));
        }

        // Copy icons/assets
        const assetsSrcDir = resolve(__dirname, 'extension/assets');
        const assetsDistDir = resolve(outDir, 'assets');
        if (!existsSync(assetsDistDir)) {
          mkdirSync(assetsDistDir, { recursive: true });
        }
        ['icon-16.png', 'icon-48.png', 'icon-128.png'].forEach((icon) => {
          const iconSrc = resolve(assetsSrcDir, icon);
          if (existsSync(iconSrc)) {
            copyFileSync(iconSrc, resolve(assetsDistDir, icon));
          }
        });
      }
    }
  ]
});

/**
 * Phishing Shield AI - Premium Web Application & Landing Page Entrypoint
 */

import './style.css';
import { ShieldMascot } from './mascot.js';
import { initWebDemo } from './web-demo.js';
import { CHROME_STORE_URL, IS_STORE_PUBLISHED, EXTENSION_ZIP_FILENAME } from './config.js';

document.addEventListener('DOMContentLoaded', () => {
  // 1. Initialize 3D Mascot Robot
  const mascotContainer = document.getElementById('mascotCanvasContainer');
  if (mascotContainer) {
    try {
      new ShieldMascot({ container: mascotContainer });
    } catch (err) {
      console.warn('WebGL initialization failed, fallback active:', err);
      mascotContainer.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:center;height:100%;color:#A78BFA;font-size:72px;">
          🛡️
        </div>
      `;
    }
  }

  // 2. Initialize Interactive Threat Analysis Web Demo
  initWebDemo();

  // 3. Centralized "Add to Chrome" Installation Flow
  const ctaButtons = document.querySelectorAll('[data-cta="add-to-chrome"]');
  const installModal = document.getElementById('installModal');
  const closeInstallModalBtn = document.getElementById('closeInstallModal');

  ctaButtons.forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();

      if (IS_STORE_PUBLISHED && CHROME_STORE_URL) {
        // Direct Buyhatke journey: opens the official Chrome Web Store listing page
        window.open(CHROME_STORE_URL, '_blank', 'noopener,noreferrer');
      } else {
        // Pre-publication state: opens guided developer mode install modal
        if (installModal) {
          installModal.classList.remove('hidden');
        }
      }
    });
  });

  if (closeInstallModalBtn && installModal) {
    closeInstallModalBtn.addEventListener('click', () => {
      installModal.classList.add('hidden');
    });

    installModal.addEventListener('click', (e) => {
      if (e.target === installModal) {
        installModal.classList.add('hidden');
      }
    });
  }

  // 4. Mobile Navigation Toggle
  const mobileToggle = document.getElementById('mobileNavToggle');
  const navMenu = document.getElementById('navMenu');

  if (mobileToggle && navMenu) {
    mobileToggle.addEventListener('click', () => {
      const isExpanded = navMenu.style.display === 'flex';
      navMenu.style.display = isExpanded ? 'none' : 'flex';
      if (!isExpanded) {
        navMenu.style.flexDirection = 'column';
        navMenu.style.position = 'absolute';
        navMenu.style.top = '72px';
        navMenu.style.left = '0';
        navMenu.style.right = '0';
        navMenu.style.background = '#0B0B11';
        navMenu.style.padding = '24px';
        navMenu.style.borderBottom = '1px solid rgba(255,255,255,0.1)';
      }
    });
  }

  // 4. FAQ Accordion Logic
  const faqItems = document.querySelectorAll('.faq-item');
  faqItems.forEach((item) => {
    const questionBtn = item.querySelector('.faq-question');
    if (questionBtn) {
      questionBtn.addEventListener('click', () => {
        const isActive = item.classList.contains('active');
        faqItems.forEach(i => i.classList.remove('active'));
        if (!isActive) {
          item.classList.add('active');
        }
      });
    }
  });

  // 5. Smooth Anchor Scrolling
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener('click', function (e) {
      const href = this.getAttribute('href');
      if (href && href !== '#' && document.querySelector(href)) {
        e.preventDefault();
        document.querySelector(href)?.scrollIntoView({
          behavior: 'smooth'
        });
      }
    });
  });
});

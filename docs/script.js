/* ============================================
   LWRT Documentation — JavaScript
   Navigation, Search, Interactivity
   ============================================ */

(function() {
  'use strict';

  // ============================================
  // Sidebar Navigation
  // ============================================
  const sidebar = document.getElementById('sidebar');
  const sidebarToggle = document.getElementById('sidebarToggle');
  const mobileMenuBtn = document.getElementById('mobileMenuBtn');
  const mobileHeader = document.getElementById('mobileHeader');
  const content = document.getElementById('content');
  const navLinks = document.querySelectorAll('.nav-link');

  // Mobile sidebar toggle
  let overlay = document.createElement('div');
  overlay.className = 'sidebar-overlay';
  document.body.appendChild(overlay);

  function openSidebar() {
    sidebar.classList.add('open');
    overlay.classList.add('visible');
    document.body.style.overflow = 'hidden';
  }

  function closeSidebar() {
    sidebar.classList.remove('open');
    overlay.classList.remove('visible');
    document.body.style.overflow = '';
  }

  if (mobileMenuBtn) {
    mobileMenuBtn.addEventListener('click', openSidebar);
  }

  overlay.addEventListener('click', closeSidebar);

  // Close sidebar on nav link click (mobile)
  navLinks.forEach(link => {
    link.addEventListener('click', () => {
      if (window.innerWidth <= 900) {
        closeSidebar();
      }
    });
  });

  // ============================================
  // Active Section Tracking (Intersection Observer)
  // ============================================
  const sections = document.querySelectorAll('.doc-section, .hero');

  function updateActiveNav() {
    let current = '';
    const scrollPos = window.scrollY + 120;

    sections.forEach(section => {
      const sectionTop = section.offsetTop;
      const sectionHeight = section.offsetHeight;
      if (scrollPos >= sectionTop && scrollPos < sectionTop + sectionHeight) {
        current = section.getAttribute('id');
      }
    });

    navLinks.forEach(link => {
      link.classList.remove('active');
      if (link.getAttribute('data-section') === current) {
        link.classList.add('active');
        // Scroll nav into view
        const navContainer = document.querySelector('.sidebar-nav');
        if (navContainer && link.offsetTop < navContainer.scrollTop + 50) {
          link.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
      }
    });
  }

  let scrollTicking = false;
  window.addEventListener('scroll', () => {
    if (!scrollTicking) {
      requestAnimationFrame(() => {
        updateActiveNav();
        scrollTicking = false;
      });
      scrollTicking = true;
    }
  });

  // ============================================
  // Search Functionality
  // ============================================
  const searchInput = document.getElementById('searchInput');
  const allSections = document.querySelectorAll('.doc-section');

  function normalizeText(text) {
    return text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim();
  }

  // Build search index
  const searchIndex = [];
  allSections.forEach(section => {
    const id = section.getAttribute('id');
    const title = section.querySelector('h2')?.textContent || '';
    const content = section.textContent || '';
    searchIndex.push({
      id: id,
      title: title,
      content: normalizeText(content),
      element: section
    });
  });

  let searchTimeout;
  searchInput.addEventListener('input', (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      const query = normalizeText(e.target.value);

      if (!query) {
        // Show all sections
        allSections.forEach(s => s.style.display = '');
        navLinks.forEach(l => l.style.display = '');
        // Remove highlights
        document.querySelectorAll('.search-highlight').forEach(el => {
          el.outerHTML = el.textContent;
        });
        return;
      }

      const queryWords = query.split(' ').filter(w => w.length > 1);
      const results = searchIndex.map(item => {
        let score = 0;
        queryWords.forEach(word => {
          if (normalizeText(item.title).includes(word)) score += 10;
          if (item.content.includes(word)) score += 1;
        });
        return { ...item, score };
      }).filter(item => item.score > 0).sort((a, b) => b.score - a.score);

      // Show matching sections, hide others
      const matchedIds = new Set(results.map(r => r.id));
      allSections.forEach(s => {
        s.style.display = matchedIds.has(s.getAttribute('id')) ? '' : 'none';
      });

      // Show/hide nav links
      navLinks.forEach(link => {
        const section = link.getAttribute('data-section');
        link.style.display = matchedIds.has(section) ? '' : 'none';
      });

      // Scroll to first result
      if (results.length > 0) {
        results[0].element.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }, 300);
  });

  // ============================================
  // FAQ Accordion
  // ============================================
  document.querySelectorAll('.faq-question').forEach(btn => {
    btn.addEventListener('click', () => {
      const item = btn.closest('.faq-item');
      const isOpen = item.classList.contains('open');

      // Close all others
      document.querySelectorAll('.faq-item.open').forEach(openItem => {
        if (openItem !== item) openItem.classList.remove('open');
      });

      item.classList.toggle('open', !isOpen);
      btn.setAttribute('aria-expanded', !isOpen);
    });
  });

  // ============================================
  // Copy Code Buttons
  // ============================================
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const codeBlock = document.getElementById(targetId);
      if (!codeBlock) return;

      const text = codeBlock.textContent;
      navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = 'Copy';
          btn.classList.remove('copied');
        }, 2000);
      }).catch(() => {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
          document.execCommand('copy');
          btn.textContent = 'Copied!';
          btn.classList.add('copied');
          setTimeout(() => {
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
          }, 2000);
        } catch (e) {
          btn.textContent = 'Failed';
        }
        document.body.removeChild(textarea);
      });
    });
  });

  // ============================================
  // Back to Top Button
  // ============================================
  const backToTop = document.getElementById('backToTop');

  window.addEventListener('scroll', () => {
    if (window.scrollY > 400) {
      backToTop.classList.add('visible');
    } else {
      backToTop.classList.remove('visible');
    }
  });

  backToTop.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  // ============================================
  // Smooth Scroll for Anchor Links
  // ============================================
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', (e) => {
      e.preventDefault();
      const targetId = anchor.getAttribute('href').substring(1);
      const target = document.getElementById(targetId);
      if (target) {
        const offset = window.innerWidth <= 900 ? 70 : 20;
        const top = target.offsetTop - offset;
        window.scrollTo({ top, behavior: 'smooth' });
      }
    });
  });

  // ============================================
  // Keyboard Navigation
  // ============================================
  document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + K to focus search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      searchInput.focus();
    }

    // Escape to clear search
    if (e.key === 'Escape' && document.activeElement === searchInput) {
      searchInput.value = '';
      searchInput.dispatchEvent(new Event('input'));
      searchInput.blur();
    }
  });

  // ============================================
  // Checklist Persistence (localStorage)
  // ============================================
  const STORAGE_KEY = 'lwrt-checklist';

  function loadChecklist() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {};
    } catch {
      return {};
    }
  }

  function saveChecklist(data) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    } catch {}
  }

  const checklistData = loadChecklist();
  document.querySelectorAll('.check-item input[type="checkbox"]').forEach((cb, index) => {
    cb.checked = checklistData[index] || false;
    cb.addEventListener('change', () => {
      const data = loadChecklist();
      data[index] = cb.checked;
      saveChecklist(data);
    });
  });

  // ============================================
  // Print Button (add to sections)
  // ============================================
  // Keyboard shortcut: Ctrl+P works natively, no custom needed

  // ============================================
  // Initialize
  // ============================================
  updateActiveNav();

  // Set first nav link as active if none
  if (!document.querySelector('.nav-link.active') && navLinks.length > 0) {
    navLinks[0].classList.add('active');
  }

})();

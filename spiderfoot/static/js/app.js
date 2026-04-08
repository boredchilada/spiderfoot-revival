/**
 * SpiderFoot — New Scan Alpine.js component
 *
 * Registered via the alpine:init event so it is available before Alpine
 * boots (Alpine is loaded with `defer`, which fires after DOMContentLoaded).
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('scanForm', (initialModules) => ({
    // ------------------------------------------------------------------ state
    target: '',
    scanName: '',
    targetType: '',
    useCase: 'footprint',

    /**
     * modules — keyed by module name (sfp_xxx).
     * Each entry: { name, summary, category, useCases, enabled }
     * Populated from server-rendered JSON passed as `initialModules`.
     */
    modules: initialModules || {},

    // ----------------------------------------------------------------- init
    init() {
      // Apply default footprint selection on load
      this.selectUseCase('footprint');

      // Watch target for auto-detection
      this.$watch('target', () => {
        this.targetType = this.detectTargetType(this.target);
      });
    },

    // --------------------------------------------------------- target detection
    /**
     * Detect the target type from the raw input string.
     * Returns a short label string, or '' if nothing matches.
     */
    detectTargetType(value) {
      const v = (value || '').trim();
      if (!v) return '';

      // ASN  — AS12345 or ASN12345
      if (/^AS[N]?\d+$/i.test(v)) return 'ASN';

      // Email
      if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'Email';

      // IPv4 CIDR subnet
      if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(v)) return 'Subnet';

      // IPv6
      if (/^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/.test(v) && v.includes(':')) return 'IP Address';

      // IPv4
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'IP Address';

      // Phone — starts with + followed by digits/spaces/dashes
      if (/^\+?[\d\s\-().]{7,}$/.test(v) && /\d{7,}/.test(v.replace(/\D/g, ''))) return 'Phone';

      // Domain — has at least one dot, no spaces, no @ symbol
      if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$/.test(v)) return 'Domain';

      // Fallback — treat multi-word values as a name
      if (/\s/.test(v) && !/[@\/]/.test(v)) return 'Name';

      return '';
    },

    // -------------------------------------------------------- badge colour
    targetTypeBadgeClass() {
      const colours = {
        'Domain':     'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
        'IP Address': 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
        'Subnet':     'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300',
        'ASN':        'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
        'Email':      'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
        'Phone':      'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300',
        'Name':       'bg-pink-100 text-pink-700 dark:bg-pink-900/40 dark:text-pink-300',
      };
      return colours[this.targetType] || 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300';
    },

    // --------------------------------------------------------- use-case tabs
    /**
     * Select a use case and auto-toggle modules accordingly.
     * 'custom' leaves current selection untouched.
     */
    selectUseCase(uc) {
      this.useCase = uc;
      if (uc === 'custom') return;

      // Map tab id -> useCases label used in module metadata
      const ucMap = {
        footprint:   'Footprint',
        investigate: 'Investigate',
        passive:     'Passive',
      };
      const label = ucMap[uc];
      if (!label) return;

      for (const key of Object.keys(this.modules)) {
        this.modules[key].enabled = this.modules[key].useCases.includes(label);
      }
    },

    // --------------------------------------------------------- module helpers
    /** Count enabled modules in a given category. */
    enabledCount(category) {
      return Object.values(this.modules).filter(
        m => m.category === category && m.enabled
      ).length;
    },

    /** Total count of modules in a given category. */
    totalCount(category) {
      return Object.values(this.modules).filter(m => m.category === category).length;
    },

    /** Modules for a given category, sorted by name. */
    modulesForCategory(category) {
      return Object.entries(this.modules)
        .filter(([, m]) => m.category === category)
        .sort(([, a], [, b]) => a.name.localeCompare(b.name));
    },

    /** Total number of enabled modules across all categories. */
    totalEnabled() {
      return Object.values(this.modules).filter(m => m.enabled).length;
    },

    /** Enable or disable all modules in a category. */
    toggleCategory(category, state) {
      for (const key of Object.keys(this.modules)) {
        if (this.modules[key].category === category) {
          this.modules[key].enabled = state;
        }
      }
    },

    // ------------------------------------------------------------ submission
    async submitScan() {
      const scanname  = this.scanName.trim() || this.target.trim();
      const scantarget = this.target.trim();

      if (!scantarget) {
        alert('Please enter a scan target.');
        return;
      }

      const enabledMods = Object.keys(this.modules).filter(k => this.modules[k].enabled);
      if (enabledMods.length === 0) {
        alert('Please enable at least one module.');
        return;
      }

      const body = new URLSearchParams({
        scanname,
        scantarget,
        modulelist: enabledMods.join(','),
      });

      try {
        const resp = await fetch('/api/startscan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: body.toString(),
        });
        const data = await resp.json();

        if (Array.isArray(data) && data[0] === 'SUCCESS') {
          // Redirect to dashboard (or scan detail page when it exists)
          window.location.href = '/';
        } else {
          const msg = Array.isArray(data) ? data[1] : JSON.stringify(data);
          alert('Error: ' + msg);
        }
      } catch (err) {
        alert('Failed to start scan: ' + err.message);
      }
    },
  }));
});

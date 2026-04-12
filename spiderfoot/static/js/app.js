/**
 * SpiderFoot — New Scan Alpine.js component
 *
 * Defined as a plain window function so it's available when Alpine
 * evaluates x-data="scanForm(...)". No event registration needed.
 */
window.scanForm = (initialModules) => ({
    // ------------------------------------------------------------------ state
    target: '',
    scanName: '',
    targetType: '',
    useCase: 'footprint',
    moduleSearch: '',

    /**
     * modules — keyed by module name (sfp_xxx).
     * Each entry: { name, summary, category, useCases, enabled }
     * Populated from server-rendered JSON passed as `initialModules`.
     */
    modules: initialModules || {},

    // Track whether the current target is a private IP
    isPrivateTarget: false,

    // ----------------------------------------------------------------- init
    init() {
      // Apply default footprint selection on load
      this.selectUseCase('footprint');

      // Watch target for auto-detection + private IP module filtering
      this.$watch('target', () => {
        const targets = this.parsedTargets;
        this.targetType = targets.length === 1 ? targets[0].type : '';

        // Check if any target is a private IP
        const wasPrivate = this.isPrivateTarget;
        this.isPrivateTarget = targets.some(t =>
          (t.type === 'IP Address' || t.type === 'Subnet') && this._isPrivateIP(t.value)
        );

        // If private-IP state changed, update module availability
        if (this.isPrivateTarget !== wasPrivate) {
          this._applyPrivateIpFilter();
        }
      });
    },

    // --------------------------------------------------------- textarea resize
    autoResizeTextarea(el) {
      el.style.height = 'auto';
      el.style.height = el.scrollHeight + 'px';
    },

    // --------------------------------------------------------- multi-target parsing
    /**
     * Parse the target textarea into an array of { value, type } objects.
     * Splits on newlines and commas, trims whitespace, deduplicates.
     */
    get parsedTargets() {
      const raw = (this.target || '').trim();
      if (!raw) return [];
      const items = raw.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
      const seen = new Set();
      const results = [];
      for (const item of items) {
        if (seen.has(item.toLowerCase())) continue;
        seen.add(item.toLowerCase());
        results.push({ value: item, type: this.detectTargetType(item) });
      }
      return results;
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

    /** Count modules in a category that require an API key but don't have one configured. */
    keysNeededCount(category) {
      return Object.values(this.modules).filter(
        m => m.category === category && m.requiresKey && !m.keyConfigured
      ).length;
    },

    /** Total number of enabled modules across all categories. */
    totalEnabled() {
      return Object.values(this.modules).filter(m => m.enabled).length;
    },

    /** Filter modules by search query (matches name, summary, category, or module key). */
    filteredModules() {
      const q = (this.moduleSearch || '').trim().toLowerCase();
      if (!q) return [];
      return Object.entries(this.modules)
        .filter(([key, m]) =>
          m.name.toLowerCase().includes(q) ||
          m.summary.toLowerCase().includes(q) ||
          m.category.toLowerCase().includes(q) ||
          key.toLowerCase().includes(q)
        )
        .sort(([, a], [, b]) => a.name.localeCompare(b.name));
    },

    /** Enable or disable all modules in a category. */
    toggleCategory(category, state) {
      for (const key of Object.keys(this.modules)) {
        if (this.modules[key].category === category) {
          this.modules[key].enabled = state;
        }
      }
    },

    // --------------------------------------------------- local tools helpers
    /** All local tool modules, sorted by name. */
    localToolModules() {
      return Object.entries(this.modules)
        .filter(([, m]) => m.isLocalTool)
        .sort(([, a], [, b]) => a.name.localeCompare(b.name));
    },

    /** Local tool modules grouped by category. */
    localToolsByCategory() {
      const groups = {};
      for (const [key, mod] of this.localToolModules()) {
        const cat = mod.category;
        if (!groups[cat]) groups[cat] = [];
        groups[cat].push([key, mod]);
      }
      return Object.entries(groups).sort(([a], [b]) => a.localeCompare(b));
    },

    /** Count enabled local tools. */
    localToolsEnabledCount() {
      return Object.values(this.modules).filter(m => m.isLocalTool && m.enabled).length;
    },

    /** Total local tools count. */
    localToolsTotalCount() {
      return Object.values(this.modules).filter(m => m.isLocalTool).length;
    },

    /** Enable or disable all local tools. */
    toggleAllTools(state) {
      for (const key of Object.keys(this.modules)) {
        if (this.modules[key].isLocalTool) {
          this.modules[key].enabled = state;
        }
      }
    },

    // ----------------------------------------------- private IP filtering
    /**
     * Check if an IP string is RFC1918 private, loopback, or link-local.
     */
    _isPrivateIP(value) {
      const v = (value || '').split('/')[0]; // strip CIDR suffix
      const parts = v.split('.');
      if (parts.length !== 4) return false;
      const [a, b] = parts.map(Number);
      // 10.0.0.0/8
      if (a === 10) return true;
      // 172.16.0.0/12
      if (a === 172 && b >= 16 && b <= 31) return true;
      // 192.168.0.0/16
      if (a === 192 && b === 168) return true;
      // 127.0.0.0/8 (loopback)
      if (a === 127) return true;
      // 169.254.0.0/16 (link-local)
      if (a === 169 && b === 254) return true;
      return false;
    },

    /**
     * When target is a private IP, disable modules that only work with
     * public IPs and mark them as blocked. When target changes back to
     * public, restore their previous state.
     */
    _applyPrivateIpFilter() {
      for (const [key, mod] of Object.entries(this.modules)) {
        if (this.isPrivateTarget && !mod.privateIpOk) {
          // Save previous enabled state so we can restore it
          if (mod._savedEnabled === undefined) {
            mod._savedEnabled = mod.enabled;
          }
          mod.enabled = false;
          mod.blockedPrivateIp = true;
        } else if (mod.blockedPrivateIp) {
          // Restore previous state
          mod.enabled = mod._savedEnabled !== undefined ? mod._savedEnabled : mod.enabled;
          mod.blockedPrivateIp = false;
          delete mod._savedEnabled;
        }
      }
    },

    // ------------------------------------------------------------ toast
    toastMsg: '',
    toastType: '',  // 'error' or 'success'
    submitting: false,

    showToast(msg, type) {
      this.toastMsg = msg;
      this.toastType = type || 'error';
      setTimeout(() => { this.toastMsg = ''; }, 6000);
    },

    // ------------------------------------------------------------ submission
    async submitScan() {
      const targets = this.parsedTargets;

      if (targets.length === 0) {
        this.showToast('Please enter a scan target.', 'error');
        return;
      }

      const unknowns = targets.filter(t => !t.type);
      if (unknowns.length > 0) {
        this.showToast('Unrecognized target type: ' + unknowns.map(t => t.value).join(', '), 'error');
        return;
      }

      const enabledMods = Object.keys(this.modules).filter(k => this.modules[k].enabled);
      if (enabledMods.length === 0) {
        this.showToast('Please enable at least one module.', 'error');
        return;
      }

      this.submitting = true;
      const baseName = this.scanName.trim();
      const errors = [];
      let launched = 0;

      for (const t of targets) {
        const scanname = baseName
          ? (targets.length > 1 ? baseName + ' - ' + t.value : baseName)
          : t.value;

        const body = new URLSearchParams({
          scanname,
          scantarget: t.value,
          modulelist: enabledMods.join(','),
        });

        try {
          const resp = await fetch('/api/startscan', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || '',
            },
            body: body.toString(),
          });
          const data = await resp.json();

          if (Array.isArray(data) && data[0] === 'SUCCESS') {
            launched++;
          } else {
            const msg = Array.isArray(data) ? data[1] : JSON.stringify(data);
            errors.push(t.value + ': ' + msg);
          }
        } catch (err) {
          errors.push(t.value + ': ' + err.message);
        }
      }

      this.submitting = false;

      if (errors.length > 0) {
        this.showToast('Launched ' + launched + '/' + targets.length + ' scans. Errors: ' + errors.join('; '), 'error');
      }

      if (launched > 0) {
        window.location.href = '/';
      }
    },
  });

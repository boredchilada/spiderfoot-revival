/**
 * SpiderFoot — New Scan Alpine.js component
 *
 * Defined as a plain window function so it's available when Alpine
 * evaluates x-data="scanForm(...)". No event registration needed.
 */
window.scanForm = (initialModules, presets) => ({
    // ------------------------------------------------------------------ state
    target: '',
    scanName: '',
    targetType: '',
    moduleSearch: '',
    presets: presets || [],
    activePresetId: 'builtin:footprint',
    appliedSnapshot: [],  // module names enabled at last preset apply
    _suppressPersist: false,
    _persistTimer: null,
    manageOpen: false,
    pendingDeleteId: null,
    droppedModules: [],

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
      // Resolve the initial preset: last-used → DB default → Footprint
      this._restoreOrDefault();

      // Watch for module-enabled changes to persist last-used state
      this.$watch('modules', () => {
        if (this._suppressPersist) return;
        this._persistLastUsed();
      }, { deep: true });

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

    // ==================================================== preset state model

    /**
     * Apply a preset by id. Replaces the module selection with the preset's
     * module list and updates the snapshot used to compute `dirty`.
     *
     * Special id '__custom__' clears the active preset without changing the
     * module selection (the "Custom" chip).
     */
    applyPreset(presetId) {
      this.activePresetId = presetId;
      this.droppedModules = [];
      if (presetId === '__custom__') {
        this.appliedSnapshot = this._currentEnabledModules();
        this._persistLastUsed();
        return;
      }
      const preset = this.presets.find(p => p.id === presetId);
      if (!preset) {
        console.warn(`Preset ${presetId} not found, falling back`);
        this.applyPreset('builtin:footprint');
        return;
      }
      const wantedSet = new Set(preset.modules);
      const knownSet = new Set(Object.keys(this.modules));
      // Track preset modules that don't exist in this codebase
      this.droppedModules = preset.modules.filter(m => !knownSet.has(m));
      // Toggle every module to match the preset's valid set
      this._suppressPersist = true;
      try {
        for (const key of Object.keys(this.modules)) {
          this.modules[key].enabled = wantedSet.has(key);
        }
      } finally {
        this._suppressPersist = false;
      }
      // Snapshot is just the preset's *valid* module list (so isDirty doesn't
      // immediately fire because of dropped names that can never be enabled)
      this.appliedSnapshot = preset.modules.filter(m => knownSet.has(m)).sort();
      this._persistLastUsed();
    },

    /** Sorted list of currently-enabled module names. */
    _currentEnabledModules() {
      return Object.keys(this.modules)
        .filter(k => this.modules[k].enabled)
        .sort();
    },

    /** Has the selection diverged from `appliedSnapshot`? */
    get isDirty() {
      const cur = this._currentEnabledModules();
      if (cur.length !== this.appliedSnapshot.length) return true;
      for (let i = 0; i < cur.length; i++) {
        if (cur[i] !== this.appliedSnapshot[i]) return true;
      }
      return false;
    },

    /** Number of modules added or removed since last apply. */
    get changedCount() {
      const cur = new Set(this._currentEnabledModules());
      const snap = new Set(this.appliedSnapshot);
      let n = 0;
      for (const k of cur) if (!snap.has(k)) n++;
      for (const k of snap) if (!cur.has(k)) n++;
      return n;
    },

    /** The preset object currently applied (or null for Custom). */
    get activePreset() {
      if (!this.activePresetId || this.activePresetId === '__custom__') return null;
      return this.presets.find(p => p.id === this.activePresetId) || null;
    },

    // ==================================================== last-used persistence

    /** Schedule a debounced persist (200ms) to coalesce rapid module toggles
     *  into a single localStorage write batch. */
    _persistLastUsed() {
      if (this._persistTimer !== null) {
        clearTimeout(this._persistTimer);
      }
      this._persistTimer = setTimeout(() => {
        this._persistTimer = null;
        this._persistLastUsedNow();
      }, 200);
    },

    /** Synchronous write (debounced via _persistLastUsed). */
    _persistLastUsedNow() {
      try {
        localStorage.setItem('sf.lastPreset.id', this.activePresetId);
        localStorage.setItem('sf.lastPreset.dirty', String(this.isDirty));
        localStorage.setItem(
          'sf.lastPreset.modules',
          JSON.stringify(this._currentEnabledModules())
        );
      } catch (e) {
        // localStorage may be unavailable (Safari private mode etc.)
      }
    },

    /** Page-load resolution: localStorage → DB default → Footprint. */
    _restoreOrDefault() {
      let lastId, lastDirty, lastModules;
      try {
        lastId = localStorage.getItem('sf.lastPreset.id');
        lastDirty = localStorage.getItem('sf.lastPreset.dirty') === 'true';
        lastModules = JSON.parse(localStorage.getItem('sf.lastPreset.modules') || '[]');
      } catch (e) { /* ignore */ }

      // 1. Try last-used
      if (lastId && lastId !== '__custom__') {
        const preset = this.presets.find(p => p.id === lastId);
        if (preset) {
          this.applyPreset(lastId);
          if (lastDirty && Array.isArray(lastModules) && lastModules.length > 0) {
            this._restoreExactModules(lastModules);
            // Don't update snapshot — we want isDirty to remain true
          }
          return;
        }
      }
      if (lastId === '__custom__' && Array.isArray(lastModules) && lastModules.length > 0) {
        this._restoreExactModules(lastModules);
        this.activePresetId = '__custom__';
        this.appliedSnapshot = [];
        return;
      }

      // 2. Try DB-marked default
      const def = this.presets.find(p => p.is_default);
      if (def) {
        this.applyPreset(def.id);
        return;
      }

      // 3. Hard fallback
      this.applyPreset('builtin:footprint');
    },

    /** Replace module selection with an explicit list (filter unknowns). */
    _restoreExactModules(moduleNames) {
      const wanted = new Set(moduleNames.filter(n => this.modules[n] !== undefined));
      this._suppressPersist = true;
      try {
        for (const key of Object.keys(this.modules)) {
          this.modules[key].enabled = wanted.has(key);
        }
      } finally {
        this._suppressPersist = false;
      }
    },

    // ==================================================== save / update / delete

    /** CSRF header for mutation requests. */
    _csrfHeaders() {
      return {
        'Content-Type': 'application/json',
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || '',
      };
    },

    async savePresetAs(name, description) {
      const cleanName = (name || '').trim();
      if (!cleanName) {
        this.showToast('Please enter a name for this preset', 'error');
        return false;
      }
      const modules = this._currentEnabledModules();
      try {
        const resp = await fetch('/api/presets', {
          method: 'POST',
          headers: this._csrfHeaders(),
          body: JSON.stringify({ name: cleanName, description, modules }),
        });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          const msg = err?.error?.message || `Save failed (${resp.status})`;
          this.showToast(msg, 'error');
          return false;
        }
        const created = await resp.json();
        // Merge the new preset into the in-memory list rather than re-fetching.
        // Keep the list sorted by sort_order, then name (matches API ordering).
        this.presets = [...this.presets, created].sort((a, b) => {
          if (a.sort_order !== b.sort_order) return a.sort_order - b.sort_order;
          return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
        });
        this.applyPreset(created.id);
        this.showToast(`Saved "${created.name}"`, 'success');
        return true;
      } catch (e) {
        this.showToast(`Save failed: ${e.message}`, 'error');
        return false;
      }
    },

    async updateActivePreset() {
      if (!this.activePreset || this.activePreset.kind !== 'user') return;
      const modules = this._currentEnabledModules();
      try {
        const resp = await fetch(`/api/presets/${encodeURIComponent(this.activePresetId)}`, {
          method: 'PATCH',
          headers: this._csrfHeaders(),
          body: JSON.stringify({
            name: this.activePreset.name,
            description: this.activePreset.description,
            modules,
          }),
        });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          const msg = err?.error?.message || `Update failed (${resp.status})`;
          this.showToast(msg, 'error');
          return;
        }
        const presetName = this.activePreset.name;
        // Replace the updated preset in-memory rather than re-fetching.
        const updated = await resp.json();
        this.presets = this.presets.map(p => p.id === updated.id ? updated : p);
        // Re-apply to refresh snapshot (now == current selection => clean)
        this.applyPreset(this.activePresetId);
        this.showToast(`Updated "${presetName}"`, 'success');
      } catch (e) {
        this.showToast(`Update failed: ${e.message}`, 'error');
      }
    },

    async deletePreset(presetId) {
      // Two-stage flow: first call sets pendingDeleteId so the row shows the
      // confirm/cancel buttons; second call (with confirmed=true via the
      // template) actually deletes.
      try {
        const resp = await fetch(`/api/presets/${encodeURIComponent(presetId)}`, {
          method: 'DELETE',
          headers: this._csrfHeaders(),
        });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          const msg = err?.error?.message || `Delete failed (${resp.status})`;
          this.showToast(msg, 'error');
          this.pendingDeleteId = null;
          return;
        }
        // Remove the deleted preset from the in-memory list (no refetch needed).
        this.presets = this.presets.filter(p => p.id !== presetId);
        if (this.activePresetId === presetId) {
          this.applyPreset('builtin:footprint');
        }
        this.pendingDeleteId = null;
        this.showToast('Preset deleted', 'success');
      } catch (e) {
        this.pendingDeleteId = null;
        this.showToast(`Delete failed: ${e.message}`, 'error');
      }
    },

    async setDefaultPreset(presetId) {
      try {
        const resp = await fetch(
          `/api/presets/${encodeURIComponent(presetId)}/default`,
          { method: 'POST', headers: this._csrfHeaders() }
        );
        if (!resp.ok) {
          this.showToast(`Failed to set default (${resp.status})`, 'error');
          return;
        }
        // Toggle is_default flags locally: target gets true, others false.
        this.presets = this.presets.map(p => ({
          ...p,
          is_default: p.id === presetId,
        }));
        this.showToast('Default preset updated', 'success');
      } catch (e) {
        this.showToast(`Failed to set default: ${e.message}`, 'error');
      }
    },

    async clearDefaultPreset() {
      try {
        const resp = await fetch('/api/presets/default', {
          method: 'DELETE',
          headers: this._csrfHeaders(),
        });
        if (!resp.ok) return;
        // Clear all is_default flags locally.
        this.presets = this.presets.map(p => ({ ...p, is_default: false }));
        this.showToast('Default preset cleared', 'success');
      } catch (e) { /* ignore */ }
    },

    async _refreshPresets() {
      try {
        const resp = await fetch('/api/presets');
        if (!resp.ok) return;
        this.presets = await resp.json();
      } catch (e) { /* keep stale */ }
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

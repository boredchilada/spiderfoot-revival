/**
 * SpiderFoot Theme Manager
 *
 * Manages dark ("Operations") / light ("Analyst") / auto (system) theme switching.
 * Theme preference is stored in localStorage under the key "sf-theme".
 *
 * The initial theme is applied via an inline <script> in base.html
 * (before first paint) to prevent a flash of wrong theme. This module
 * provides the toggle behavior and exposes helpers for other scripts.
 */
(function () {
  'use strict';

  const STORAGE_KEY = 'sf-theme';
  const DARK = 'dark';
  const LIGHT = 'light';
  const AUTO = 'auto';

  /**
   * Resolve the effective theme (dark or light), accounting for 'auto'.
   * @returns {'dark'|'light'}
   */
  function resolveTheme() {
    return document.documentElement.classList.contains(DARK) ? DARK : LIGHT;
  }

  /**
   * Return the stored preference (dark, light, or auto).
   * @returns {'dark'|'light'|'auto'}
   */
  function getStoredTheme() {
    return localStorage.getItem(STORAGE_KEY) || DARK;
  }

  /**
   * Apply a theme.
   * @param {'dark'|'light'|'auto'} theme
   */
  function setTheme(theme) {
    if (theme === AUTO) {
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
        document.documentElement.classList.remove(DARK);
      } else {
        document.documentElement.classList.add(DARK);
      }
    } else if (theme === LIGHT) {
      document.documentElement.classList.remove(DARK);
    } else {
      document.documentElement.classList.add(DARK);
    }
    localStorage.setItem(STORAGE_KEY, theme);
    updateToggleIcons(resolveTheme());
  }

  /**
   * Toggle between dark and light themes (sidebar button cycles dark → light → dark).
   */
  function toggleTheme() {
    setTheme(resolveTheme() === DARK ? LIGHT : DARK);
  }

  /**
   * Update sun/moon icons on all theme toggle buttons.
   */
  function updateToggleIcons(effectiveTheme) {
    document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
      var sun = btn.querySelector('.icon-sun');
      var moon = btn.querySelector('.icon-moon');
      if (sun && moon) {
        if (effectiveTheme === DARK) {
          sun.classList.remove('hidden');
          moon.classList.add('hidden');
        } else {
          sun.classList.add('hidden');
          moon.classList.remove('hidden');
        }
      }
    });
  }

  // Bind click handlers once DOM is ready
  document.addEventListener('DOMContentLoaded', function () {
    updateToggleIcons(resolveTheme());

    document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
      btn.addEventListener('click', toggleTheme);
    });
  });

  // Listen for OS theme changes when auto is selected
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
      if (getStoredTheme() === AUTO) {
        setTheme(AUTO);
      }
    });
  }

  // Expose on window for programmatic access
  window.sfTheme = {
    get: resolveTheme,
    set: setTheme,
    toggle: toggleTheme,
  };
})();

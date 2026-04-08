/**
 * SpiderFoot Theme Manager
 *
 * Manages dark ("Operations") / light ("Analyst") theme switching.
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

  /**
   * Return the current theme.
   * @returns {'dark'|'light'}
   */
  function getTheme() {
    return document.documentElement.classList.contains(DARK) ? DARK : LIGHT;
  }

  /**
   * Apply a theme.
   * @param {'dark'|'light'} theme
   */
  function setTheme(theme) {
    if (theme === DARK) {
      document.documentElement.classList.add(DARK);
    } else {
      document.documentElement.classList.remove(DARK);
    }
    localStorage.setItem(STORAGE_KEY, theme);
    updateToggleIcons(theme);
  }

  /**
   * Toggle between dark and light themes.
   */
  function toggleTheme() {
    setTheme(getTheme() === DARK ? LIGHT : DARK);
  }

  /**
   * Update sun/moon icons on all theme toggle buttons.
   */
  function updateToggleIcons(theme) {
    document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
      var sun = btn.querySelector('.icon-sun');
      var moon = btn.querySelector('.icon-moon');
      if (sun && moon) {
        if (theme === DARK) {
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
    updateToggleIcons(getTheme());

    document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
      btn.addEventListener('click', toggleTheme);
    });
  });

  // Expose on window for programmatic access
  window.sfTheme = {
    get: getTheme,
    set: setTheme,
    toggle: toggleTheme,
  };
})();

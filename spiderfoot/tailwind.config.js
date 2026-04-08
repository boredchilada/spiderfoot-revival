/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './templates/**/*.html',
    './static/js/**/*.js',
  ],
  theme: {
    extend: {
      colors: {
        sf: {
          base: '#0a0e17',
          surface: '#111827',
          elevated: '#1e293b',
          border: '#334155',
          accent: '#06b6d4',
          warning: '#f59e0b',
          critical: '#ef4444',
          success: '#22c55e',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
};

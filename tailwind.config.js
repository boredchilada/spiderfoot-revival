/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './spiderfoot/templates/**/*.html',
  ],
  safelist: [
    // Badge colors — injected dynamically via {{ event.badge_color }} from Python,
    // so Tailwind CLI can't detect them from template scanning.
    'bg-red-900/40', 'text-red-300', 'border-red-500/30',
    'bg-orange-900/40', 'text-orange-300', 'border-orange-500/30',
    'bg-cyan-900/40', 'text-cyan-300', 'border-cyan-500/30',
    'bg-violet-900/40', 'text-violet-300', 'border-violet-500/30',
    'bg-emerald-900/40', 'text-emerald-300', 'border-emerald-500/30',
    'bg-amber-900/40', 'text-amber-300', 'border-amber-500/30',
    'bg-slate-700/40', 'text-slate-400', 'border-slate-500/30',
    'bg-green-500/10', 'text-green-400', 'border-green-500/20',
    'bg-amber-500/10', 'text-amber-400', 'border-amber-500/20',
    'bg-slate-500/10', 'bg-slate-500/20',
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
}

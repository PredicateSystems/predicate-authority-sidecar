/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Match TUI dark theme aesthetic
        'bg-primary': '#1a1a2e',
        'bg-secondary': '#16213e',
        'bg-card': '#0f3460',
        'text-primary': '#e4e4e7',
        'text-secondary': '#a1a1aa',
        'accent-allow': '#22c55e',
        'accent-deny': '#ef4444',
        'accent-info': '#3b82f6',
      },
    },
  },
  plugins: [],
}

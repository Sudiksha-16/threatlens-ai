/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#080D18',
          sidebar: '#0C1423',
          card: '#111C2E',
          card2: '#162338',
          teal: '#38D6C5',
          blue: '#668CFF',
          text: '#F4F7FB',
          muted: '#9AA9BC',
          border: '#25354B',
          safe: '#35C98A',
          warning: '#F5B84B',
          critical: '#D94C63',
          danger: '#F16B75',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace']
      }
    },
  },
  plugins: [],
}

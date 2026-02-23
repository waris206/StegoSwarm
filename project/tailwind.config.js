/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'cyber-green': '#00ff41',
        'cyber-blue': '#00d9ff',
        'cyber-purple': '#b537ff',
      },
      boxShadow: {
        'neon-green': '0 0 5px theme("colors.cyber-green"), 0 0 20px theme("colors.cyber-green")',
        'neon-blue': '0 0 5px theme("colors.cyber-blue"), 0 0 20px theme("colors.cyber-blue")',
      },
    },
  },
  plugins: [],
}

/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html",
  ],
  theme: {
    extend: {
      colors: {
        // Primary accent colors
        primary: {
          50:  '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
          950: '#082f49',
        },
        secondary: {
          50:  '#f5f3ff',
          100: '#ede9fe',
          200: '#ddd6fe',
          300: '#c4b5fd',
          400: '#a78bfa',
          500: '#8b5cf6',
          600: '#7c3aed',
          700: '#6d28d9',
          800: '#5b21b6',
          900: '#4c1d95',
          950: '#2e1065',
        },
        // Neutral text and background for light/dark modes
        light: {
          background: '#f8f8f8',
          text: '#333333',
          card: '#ffffff',
          border: '#e0e0e0',
        },
        dark: {
          background: '#1a202c',
          text: '#e2e8f0',
          card: '#2d3748',
          border: '#4a5568',
        },
        // Specific actions
        accent: '#34d399', // A vibrant green for success/highlight
        destructive: '#ef4444', // A clear red for danger/error
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        serif: ['Merriweather', 'serif'],
        mono: ['Fira Code', 'monospace'],
      },
      boxShadow: {
        'custom-light': '0 4px 12px rgba(0, 0, 0, 0.05)',
        'custom-dark': '0 4px 12px rgba(0, 0, 0, 0.3)',
      }
    },
  },
  plugins: [],
}; 
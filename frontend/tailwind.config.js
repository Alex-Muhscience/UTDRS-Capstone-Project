module.exports = {
  content: [
    "./src/**/*.{js,jsx}",
    "./public/**/*.html"
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#3B82F6',
          dark: '#2563EB'
        },
        secondary: {
          DEFAULT: '#10B981',
          dark: '#059669'
        },
        dark: {
          DEFAULT: '#1E293B',
          light: '#334155',
          lighter: '#475569',
          dark: '#0F172A',
          darker: '#020617'
        },
        danger: {
          DEFAULT: '#EF4444',
          dark: '#DC2626'
        },
        warning: {
          DEFAULT: '#F59E0B',
          dark: '#D97706'
        },
        success: {
          DEFAULT: '#10B981',
          dark: '#059669'
        },
        info: {
          DEFAULT: '#0EA5E9',
          dark: '#0284C7'
        },
        cyber: {
          teal: '#2DD4BF',
          blue: '#38BDF8',
          purple: '#A78BFA',
          pink: '#F472B6'
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['Fira Code', 'monospace']
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'ping-slow': 'ping 1.5s cubic-bezier(0, 0, 0.2, 1) infinite'
      }
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
    require('@tailwindcss/aspect-ratio')
  ],
}
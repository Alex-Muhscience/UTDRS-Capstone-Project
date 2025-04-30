import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { createHtmlPlugin } from 'vite-plugin-html';

export default defineConfig({
  plugins: [
    react(),
    createHtmlPlugin({
      minify: true,
      pages: [
        {
          entry: 'src/main.jsx',
          filename: 'index.html',
          template: 'public/index.html',
        },
        {
          entry: 'src/pages/LoginPage.jsx',
          filename: 'login.html',
          template: 'public/login.html',
        },
        {
          entry: 'src/pages/admin/DashboardPage.jsx',
          filename: 'admin/dashboard.html',
          template: 'public/admin/dashboard.html',
        },
        // Add all other pages similarly
      ]
    })
  ],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: 'public/index.html',
        login: 'public/login.html',
        adminDashboard: 'public/admin/dashboard.html',
        adminUsers: 'public/admin/users.html',
        adminAnalytics: 'public/admin/analytics.html',
        adminReports: 'public/admin/reports.html',
        adminSupport: 'public/admin/support.html',
        adminSettings: 'public/admin/settings.html',
        userDashboard: 'public/user/dashboard.html',
        userProfile: 'public/user/profile.html',
        userReports: 'public/user/reports.html',
        userDevices: 'public/user/devices.html',
        userVulnerabilities: 'public/user/vulnerabilities.html',
        userThreats: 'public/user/threats.html',
        userSettings: 'public/user/settings.html',
        notFound: 'public/404.html',
        unauthorized: 'public/403.html'
      }
    }
  },
  server: {
    port: 3001,
    open: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true
      }
    }
  }
});
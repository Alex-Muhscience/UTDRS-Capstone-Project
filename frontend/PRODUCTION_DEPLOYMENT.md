# UTDRS Frontend - Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the UTDRS frontend to production environments, including security hardening, performance optimization, and operational best practices.

## Pre-Deployment Checklist

### Security

- [ ] All sensitive data (API keys, tokens) removed from code
- [ ] Environment variables properly configured
- [ ] HTTPS enabled on all endpoints
- [ ] CORS properly configured for backend API
- [ ] CSP (Content Security Policy) headers configured
- [ ] XSS protection enabled
- [ ] CSRF tokens implemented
- [ ] Input validation and sanitization in place
- [ ] File upload validation implemented
- [ ] Rate limiting configured

### Performance

- [ ] Bundle size analyzed and optimized
- [ ] Code splitting implemented
- [ ] Lazy loading configured for routes
- [ ] Images optimized and compressed
- [ ] Caching headers configured
- [ ] Gzip compression enabled
- [ ] CDN configured for static assets
- [ ] Database queries optimized
- [ ] API response times acceptable

### Testing

- [ ] Unit tests passing (>80% coverage)
- [ ] Integration tests passing
- [ ] E2E tests passing
- [ ] Cross-browser testing completed
- [ ] Mobile responsiveness verified
- [ ] Accessibility audit passed
- [ ] Performance audit passed

### Documentation

- [ ] README updated
- [ ] API documentation complete
- [ ] Deployment procedures documented
- [ ] Troubleshooting guide created
- [ ] Runbook for common issues prepared

## Deployment Steps

### 1. Environment Setup

```bash
# Install dependencies
npm install

# Set environment variables
cp .env.example .env.production
# Edit .env.production with production values
```

### 2. Build Optimization

```bash
# Build with production optimizations
npm run build:prod

# Analyze bundle size
npm run analyze

# Test production build locally
npm run preview
```

### 3. Security Hardening

#### Content Security Policy (CSP)

Add to your web server configuration:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://api.example.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

#### Security Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### 4. Nginx Configuration Example

```nginx
server {
    listen 443 ssl http2;
    server_name app.example.com;

    # SSL configuration
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    # Gzip compression
    gzip on;
    gzip_types text/plain text/css text/javascript application/json application/javascript;
    gzip_min_length 1000;

    # Cache configuration
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # SPA routing
    location / {
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    # API proxy
    location /api/ {
        proxy_pass http://backend-api:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 5. Docker Deployment

```dockerfile
# Build stage
FROM node:18-alpine as builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build:prod

# Production stage
FROM node:18-alpine
WORKDIR /app
RUN npm install -g serve
COPY --from=builder /app/dist ./dist
EXPOSE 3000
CMD ["serve", "-s", "dist", "-l", "3000"]
```

### 6. Netlify Deployment

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Deploy
netlify deploy --prod --dir=dist
```

### 7. Monitoring and Logging

#### Application Monitoring

```javascript
// src/utils/monitoring.js
export const initializeMonitoring = () => {
  // Initialize error tracking (e.g., Sentry)
  if (window.Sentry) {
    window.Sentry.init({
      dsn: import.meta.env.VITE_SENTRY_DSN,
      environment: import.meta.env.MODE,
      tracesSampleRate: 0.1,
    });
  }

  // Initialize analytics (e.g., Google Analytics)
  if (window.gtag) {
    window.gtag('config', import.meta.env.VITE_GA_ID);
  }
};
```

#### Health Checks

```javascript
// src/pages/HealthCheck.jsx
export default function HealthCheck() {
  const [status, setStatus] = useState('unknown');

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await fetch('/api/health');
        setStatus(response.ok ? 'healthy' : 'unhealthy');
      } catch {
        setStatus('unhealthy');
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  return <div>{status}</div>;
}
```

## Performance Optimization

### 1. Code Splitting

```javascript
// src/App.jsx
import { lazy, Suspense } from 'react';

const Dashboard = lazy(() => import('./pages/Dashboard'));
const Reports = lazy(() => import('./pages/Reports'));

export default function App() {
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/reports" element={<Reports />} />
      </Routes>
    </Suspense>
  );
}
```

### 2. Image Optimization

```javascript
// Use WebP format with fallback
<picture>
  <source srcSet="image.webp" type="image/webp" />
  <img src="image.jpg" alt="Description" loading="lazy" />
</picture>
```

### 3. API Caching

```javascript
// src/utils/cache.js
export const createCache = (ttl = 5 * 60 * 1000) => {
  const cache = new Map();

  return {
    get: (key) => {
      const item = cache.get(key);
      if (!item) return null;
      if (Date.now() - item.timestamp > ttl) {
        cache.delete(key);
        return null;
      }
      return item.value;
    },
    set: (key, value) => {
      cache.set(key, { value, timestamp: Date.now() });
    },
    clear: () => cache.clear(),
  };
};
```

## Troubleshooting

### Common Issues

1. **CORS Errors**: Verify backend CORS configuration
2. **Blank Page**: Check browser console for errors
3. **Slow Loading**: Analyze bundle size and API response times
4. **Authentication Issues**: Verify token storage and refresh logic
5. **Mobile Issues**: Test on actual devices

### Debug Mode

Set `VITE_DEBUG=true` in environment to enable verbose logging.

## Rollback Procedure

```bash
# Revert to previous version
git revert <commit-hash>
npm run build:prod
npm run deploy
```

## Post-Deployment

1. Monitor error rates and performance metrics
2. Gather user feedback
3. Monitor security logs for suspicious activity
4. Schedule regular security audits
5. Plan for regular updates and patches

## Support and Maintenance

For issues or questions, refer to:
- GitHub Issues: https://github.com/Alex-Muhscience/UTDRS-frontend/issues
- Documentation: See README.md
- Support Email: support@example.com

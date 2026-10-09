# Security Guidelines

This document outlines security best practices and guidelines for the UTDRS API Gateway project.

## Security Scanning

We use the following tools for security analysis:

- **Bandit**: Static security analysis for Python code
- **Safety**: Dependency vulnerability scanning

### Running Security Scans

```bash
# Run Bandit security scan
bandit -r . -f json -o bandit-report.json

# Run Safety dependency check  
pip install safety
safety check

# Run both as part of CI/CD
python -m bandit -r . && python -m safety check
```

## Security Issues Addressed

### 1. Network Binding Security
- **Issue**: Hardcoded binding to all interfaces (0.0.0.0)
- **Solution**: Use environment variables with secure defaults
- **Configuration**:
  ```bash
  export HOST=127.0.0.1  # Default: localhost only
  export PORT=8000       # Default: port 8000
  export RELOAD=true     # Default: enable reload
  ```

### 2. SQL Injection Prevention
- **Practice**: Use parameterized queries and ORM methods
- **Logging**: Avoid f-strings in logging that could be misinterpreted as SQL

### 3. Test Security
- **Bandit Configuration**: Assert statements are allowed in test files
- **Test Isolation**: Tests should not affect production security

## Environment Configuration

### Production Environment Variables
```bash
# Network Configuration
HOST=127.0.0.1  # Bind to localhost only in production
PORT=8000

# Database Configuration  
DATABASE_URL=mongodb://localhost:27017/utdrs
DATABASE_NAME=utdrs

# Security Settings
SECRET_KEY=your-secure-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
JWT_EXPIRATION_HOURS=24

# Logging
LOG_LEVEL=INFO
```

### Docker Security
When deploying with Docker:
```dockerfile
# Use non-root user
USER 1000:1000

# Expose specific port only
EXPOSE 8000

# Set secure environment defaults
ENV HOST=0.0.0.0
ENV PORT=8000
```

## Dependency Management

### Regular Updates
- Update dependencies regularly
- Monitor security advisories
- Use `safety check` to scan for known vulnerabilities

### Requirements
```bash
# Install security scanning tools
pip install bandit safety

# Add to requirements-dev.txt
bandit>=1.8.0
safety>=3.0.0
```

## Code Security Best Practices

### 1. Input Validation
- Validate all user inputs
- Use Pydantic models for request/response validation
- Sanitize data before database operations

### 2. Authentication & Authorization
- Use strong JWT tokens
- Implement proper session management
- Follow principle of least privilege

### 3. Error Handling
- Don't expose internal details in error messages
- Log security events appropriately
- Use structured logging

### 4. Database Security
- Use connection pooling
- Implement proper indexing
- Regular backup and recovery testing

## Reporting Security Issues

If you discover a security vulnerability, please:

1. **DO NOT** create a public GitHub issue
2. Send details to: security@example.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Security Checklist

- [ ] All environment variables configured
- [ ] Bandit scan passes (excluding known false positives)
- [ ] Safety dependency check passes
- [ ] No hardcoded secrets in code
- [ ] Proper error handling implemented
- [ ] Input validation in place
- [ ] Authentication/authorization working
- [ ] Logging configured appropriately
- [ ] Database connections secured
- [ ] Network binding configured securely

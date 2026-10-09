import {
  sanitizeInput,
  validateEmail,
  validatePassword,
  validateURL,
  escapeHTML,
  isValidJSON,
  validateFileUpload,
  removeSensitiveData,
  checkRateLimit
} from '../security';

describe('Security Utilities', () => {
  describe('sanitizeInput', () => {
    it('should sanitize XSS attempts', () => {
      const malicious = '<script>alert("XSS")</script>';
      const sanitized = sanitizeInput(malicious);
      expect(sanitized).not.toContain('<script>');
    });

    it('should handle normal text', () => {
      const normal = 'Hello World';
      expect(sanitizeInput(normal)).toBe('Hello World');
    });

    it('should return empty string for non-string input', () => {
      expect(sanitizeInput(null)).toBe('');
      expect(sanitizeInput(undefined)).toBe('');
      expect(sanitizeInput(123)).toBe('');
    });
  });

  describe('validateEmail', () => {
    it('should validate correct email addresses', () => {
      expect(validateEmail('test@example.com')).toBe(true);
      expect(validateEmail('user.name@domain.co.uk')).toBe(true);
    });

    it('should reject invalid email addresses', () => {
      expect(validateEmail('invalid.email')).toBe(false);
      expect(validateEmail('@example.com')).toBe(false);
      expect(validateEmail('test@')).toBe(false);
    });
  });

  describe('validatePassword', () => {
    it('should validate strong passwords', () => {
      const result = validatePassword('SecurePass123!');
      expect(result.isValid).toBe(true);
      expect(result.strength).toBe('strong');
    });

    it('should reject weak passwords', () => {
      const result = validatePassword('weak');
      expect(result.isValid).toBe(false);
      expect(result.feedback.length).toBeGreaterThan(0);
    });

    it('should provide feedback for password requirements', () => {
      const result = validatePassword('NoSpecial123');
      expect(result.feedback).toContain('Password must contain at least one special character (!@#$%^&*)');
    });
  });

  describe('validateURL', () => {
    it('should validate correct URLs', () => {
      expect(validateURL('https://example.com')).toBe(true);
      expect(validateURL('http://localhost:3000')).toBe(true);
    });

    it('should reject invalid URLs', () => {
      expect(validateURL('not a url')).toBe(false);
      expect(validateURL('ht!tp://invalid')).toBe(false);
    });
  });

  describe('escapeHTML', () => {
    it('should escape HTML special characters', () => {
      expect(escapeHTML('<div>Test</div>')).toBe('&lt;div&gt;Test&lt;/div&gt;');
      expect(escapeHTML('Test & "quotes"')).toBe('Test &amp; &quot;quotes&quot;');
    });
  });

  describe('isValidJSON', () => {
    it('should validate correct JSON', () => {
      expect(isValidJSON('{"key": "value"}')).toBe(true);
      expect(isValidJSON('[]')).toBe(true);
    });

    it('should reject invalid JSON', () => {
      expect(isValidJSON('{invalid}')).toBe(false);
      expect(isValidJSON('undefined')).toBe(false);
    });
  });

  describe('validateFileUpload', () => {
    it('should validate correct files', () => {
      const file = new File(['content'], 'test.pdf', { type: 'application/pdf' });
      const result = validateFileUpload(file);
      expect(result.isValid).toBe(true);
    });

    it('should reject files with wrong type', () => {
      const file = new File(['content'], 'test.exe', { type: 'application/x-msdownload' });
      const result = validateFileUpload(file);
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject files that are too large', () => {
      const largeContent = new Array(11 * 1024 * 1024).fill('x').join('');
      const file = new File([largeContent], 'large.pdf', { type: 'application/pdf' });
      const result = validateFileUpload(file);
      expect(result.isValid).toBe(false);
    });
  });

  describe('removeSensitiveData', () => {
    it('should remove sensitive keys', () => {
      const obj = {
        username: 'user',
        password: 'secret123',
        email: 'user@example.com'
      };
      const cleaned = removeSensitiveData(obj);
      expect(cleaned.password).toBe('[REDACTED]');
      expect(cleaned.username).toBe('user');
    });

    it('should handle nested objects', () => {
      const obj = {
        user: {
          name: 'John',
          credentials: {
            password: 'secret'
          }
        }
      };
      const cleaned = removeSensitiveData(obj);
      expect(cleaned.user.credentials.password).toBe('[REDACTED]');
    });
  });

  describe('checkRateLimit', () => {
    beforeEach(() => {
      localStorage.clear();
    });

    it('should allow requests within limit', () => {
      const result = checkRateLimit('test', 5, 60000);
      expect(result.isLimited).toBe(false);
      expect(result.attempts).toBe(1);
    });

    it('should block requests exceeding limit', () => {
      for (let i = 0; i < 5; i++) {
        checkRateLimit('test', 5, 60000);
      }
      const result = checkRateLimit('test', 5, 60000);
      expect(result.isLimited).toBe(true);
    });
  });
});

/**
 * Security utilities for input validation, sanitization, and protection
 */

/**
 * Sanitize user input to prevent XSS attacks
 * @param {string} input - The input string to sanitize
 * @returns {string} - Sanitized string
 */
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return '';
  
  const div = document.createElement('div');
  div.textContent = input;
  return div.innerHTML;
};

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} - True if valid email format
 */
export const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {object} - Object with isValid and feedback
 */
export const validatePassword = (password) => {
  const feedback = [];
  let score = 0;

  if (password.length < 8) {
    feedback.push('Password must be at least 8 characters long');
  } else {
    score += 1;
  }

  if (!/[A-Z]/.test(password)) {
    feedback.push('Password must contain at least one uppercase letter');
  } else {
    score += 1;
  }

  if (!/[a-z]/.test(password)) {
    feedback.push('Password must contain at least one lowercase letter');
  } else {
    score += 1;
  }

  if (!/[0-9]/.test(password)) {
    feedback.push('Password must contain at least one number');
  } else {
    score += 1;
  }

  if (!/[!@#$%^&*]/.test(password)) {
    feedback.push('Password must contain at least one special character (!@#$%^&*)');
  } else {
    score += 1;
  }

  return {
    isValid: feedback.length === 0,
    score: score,
    feedback: feedback,
    strength: score <= 2 ? 'weak' : score <= 3 ? 'fair' : score <= 4 ? 'good' : 'strong'
  };
};

/**
 * Validate URL format
 * @param {string} url - URL to validate
 * @returns {boolean} - True if valid URL
 */
export const validateURL = (url) => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} - Escaped text
 */
export const escapeHTML = (text) => {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, (char) => map[char]);
};

/**
 * Check if a value is a valid JSON string
 * @param {string} str - String to validate
 * @returns {boolean} - True if valid JSON
 */
export const isValidJSON = (str) => {
  try {
    JSON.parse(str);
    return true;
  } catch {
    return false;
  }
};

/**
 * Generate a secure random token
 * @param {number} length - Length of token
 * @returns {string} - Random token
 */
export const generateSecureToken = (length = 32) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  
  for (let i = 0; i < length; i++) {
    token += chars[array[i] % chars.length];
  }
  
  return token;
};

/**
 * Validate CSRF token
 * @param {string} token - Token to validate
 * @returns {boolean} - True if token is valid format
 */
export const validateCSRFToken = (token) => {
  return typeof token === 'string' && token.length > 0;
};

/**
 * Remove sensitive data from objects (for logging)
 * @param {object} obj - Object to clean
 * @param {array} sensitiveKeys - Keys to remove
 * @returns {object} - Cleaned object
 */
export const removeSensitiveData = (obj, sensitiveKeys = ['password', 'token', 'secret', 'apiKey']) => {
  const cleaned = JSON.parse(JSON.stringify(obj));
  
  const removeKeys = (target) => {
    for (const key in target) {
      if (sensitiveKeys.includes(key.toLowerCase())) {
        target[key] = '[REDACTED]';
      } else if (typeof target[key] === 'object' && target[key] !== null) {
        removeKeys(target[key]);
      }
    }
  };
  
  removeKeys(cleaned);
  return cleaned;
};

/**
 * Validate and sanitize file uploads
 * @param {File} file - File to validate
 * @param {object} options - Validation options
 * @returns {object} - Validation result
 */
export const validateFileUpload = (file, options = {}) => {
  const {
    maxSize = 10 * 1024 * 1024, // 10MB
    allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'],
    allowedExtensions = ['pdf', 'jpg', 'jpeg', 'png']
  } = options;

  const errors = [];

  if (!file) {
    errors.push('No file selected');
    return { isValid: false, errors };
  }

  if (file.size > maxSize) {
    errors.push(`File size exceeds maximum of ${maxSize / 1024 / 1024}MB`);
  }

  if (!allowedTypes.includes(file.type)) {
    errors.push(`File type ${file.type} is not allowed`);
  }

  const fileExtension = file.name.split('.').pop().toLowerCase();
  if (!allowedExtensions.includes(fileExtension)) {
    errors.push(`File extension .${fileExtension} is not allowed`);
  }

  return {
    isValid: errors.length === 0,
    errors: errors
  };
};

/**
 * Hash sensitive data using SHA-256 (for client-side hashing only)
 * Note: This is for client-side use only. Always hash passwords on the server.
 * @param {string} data - Data to hash
 * @returns {Promise<string>} - Hash digest
 */
export const hashData = async (data) => {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
};

/**
 * Rate limiting helper
 * @param {string} key - Unique key for rate limiting
 * @param {number} maxAttempts - Maximum attempts allowed
 * @param {number} windowMs - Time window in milliseconds
 * @returns {object} - Rate limit status
 */
export const checkRateLimit = (key, maxAttempts = 5, windowMs = 60000) => {
  const now = Date.now();
  const storageKey = `rateLimit_${key}`;
  const stored = localStorage.getItem(storageKey);
  
  let attempts = [];
  
  if (stored) {
    attempts = JSON.parse(stored).filter(timestamp => now - timestamp < windowMs);
  }
  
  const isLimited = attempts.length >= maxAttempts;
  
  if (!isLimited) {
    attempts.push(now);
    localStorage.setItem(storageKey, JSON.stringify(attempts));
  }
  
  return {
    isLimited: isLimited,
    attempts: attempts.length,
    maxAttempts: maxAttempts,
    resetTime: attempts.length > 0 ? new Date(attempts[0] + windowMs) : null
  };
};

export default {
  sanitizeInput,
  validateEmail,
  validatePassword,
  validateURL,
  escapeHTML,
  isValidJSON,
  generateSecureToken,
  validateCSRFToken,
  removeSensitiveData,
  validateFileUpload,
  hashData,
  checkRateLimit
};

describe('Authentication Flow', () => {
  beforeEach(() => {
    cy.visit('/login');
  });

  it('should display login page', () => {
    cy.get('h1').should('contain', 'Login');
    cy.get('input[type="email"]').should('exist');
    cy.get('input[type="password"]').should('exist');
    cy.get('button[type="submit"]').should('exist');
  });

  it('should show validation errors for empty form', () => {
    cy.get('button[type="submit"]').click();
    cy.get('.error-message').should('be.visible');
  });

  it('should show validation error for invalid email', () => {
    cy.get('input[type="email"]').type('invalid-email');
    cy.get('input[type="password"]').type('password123');
    cy.get('button[type="submit"]').click();
    cy.get('.error-message').should('contain', 'Invalid email');
  });

  it('should login successfully with valid credentials', () => {
    cy.intercept('POST', '/api/v1/auth/login', {
      statusCode: 200,
      body: {
        access_token: 'test-token',
        refresh_token: 'test-refresh-token',
        user: {
          id: '1',
          email: 'test@example.com',
          name: 'Test User',
          role: 'user',
        },
      },
    }).as('loginRequest');

    cy.get('input[type="email"]').type('test@example.com');
    cy.get('input[type="password"]').type('Password123!');
    cy.get('button[type="submit"]').click();

    cy.wait('@loginRequest');
    cy.url().should('include', '/dashboard');
  });

  it('should show error for invalid credentials', () => {
    cy.intercept('POST', '/api/v1/auth/login', {
      statusCode: 401,
      body: {
        error: 'Invalid credentials',
      },
    }).as('loginRequest');

    cy.get('input[type="email"]').type('test@example.com');
    cy.get('input[type="password"]').type('wrongpassword');
    cy.get('button[type="submit"]').click();

    cy.wait('@loginRequest');
    cy.get('.error-message').should('contain', 'Invalid credentials');
  });

  it('should logout successfully', () => {
    // Login first
    cy.login('test@example.com', 'Password123!');
    
    // Logout
    cy.get('[data-testid="user-menu"]').click();
    cy.get('[data-testid="logout-button"]').click();
    
    cy.url().should('include', '/login');
  });
});

describe('Session Management', () => {
  it('should redirect to login if token expires', () => {
    cy.login('test@example.com', 'Password123!');
    cy.visit('/dashboard');

    // Simulate token expiration
    cy.intercept('GET', '/api/v1/user/dashboard', {
      statusCode: 401,
    }).as('expiredRequest');

    cy.reload();
    cy.wait('@expiredRequest');
    cy.url().should('include', '/login');
  });

  it('should refresh token automatically', () => {
    cy.login('test@example.com', 'Password123!');
    
    cy.intercept('POST', '/api/v1/auth/refresh', {
      statusCode: 200,
      body: {
        access_token: 'new-token',
      },
    }).as('refreshRequest');

    cy.visit('/dashboard');
    cy.wait('@refreshRequest');
    cy.url().should('include', '/dashboard');
  });
});

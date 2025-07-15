import { test, expect } from '@playwright/test';
import jwt from 'jsonwebtoken';
import { AuthenticationManager } from '@auth/AuthenticationManager';
import { AuthenticationStrategyFactory } from '@auth/strategies/StrategyFactory';
import { AuthenticationStrategyRegistry } from '@auth/strategies/base/AuthenticationStrategy';
import { SecureSessionManager } from '@auth/session/SecureSessionManager';
import { AuthConfigManager } from '@auth/config/AuthConfig';
import { logger } from '@auth/utils/SecureLogger';

/**
 * Enhanced Authentication Framework Examples
 *
 * This demonstrates the new pluggable authentication system that supports:
 * - Multiple authentication methods (password, OAuth2, SAML, API keys)
 * - Secure session management with encryption
 * - Comprehensive security features (rate limiting, CSRF protection, etc.)
 * - Audit logging and monitoring
 */


test.describe('Enhanced Authentication Framework Examples', () => {
  let authManager: AuthenticationManager;
  let factory: AuthenticationStrategyFactory;
  let registry: AuthenticationStrategyRegistry;

  test.beforeEach(async ({ page, context }) => {
    // Initialize the authentication system
    authManager = new AuthenticationManager(page, context);
    factory = AuthenticationStrategyFactory.getInstance();
    registry = AuthenticationStrategyRegistry.getInstance();

    // Clear any existing strategies
    registry.clear();
  });

  test.describe('Basic Password Authentication', () => {
    test('should authenticate with secure password strategy', async ({ page: _page }) => {
      // Create and register a secure password strategy
      const passwordStrategy = factory.createPasswordStrategy();
      registry.register(passwordStrategy);

      // Set as default for the auth manager
      registry.setDefault('secure-password');

      // Authenticate using environment variables (secure!)
      const success = await authManager.authenticateAs('admin');

      expect(success).toBe(true);
      expect(authManager.isAuthenticated()).toBe(true);
      expect(authManager.getCurrentUser()?.getName()).toBe('Admin');

      // Check that secure logging was used
      const auditTrail = logger.getAuditTrail();
      const authEvents = auditTrail.filter(entry => entry.message.includes('Auth action'));
      expect(authEvents.length).toBeGreaterThan(0);

      console.log('Secure password authentication successful');
    });

    test('should handle rate limiting', async ({ page: _page }) => {
      const passwordStrategy = factory.createPasswordStrategy();
      registry.register(passwordStrategy);

      // Make multiple failed attempts to trigger rate limiting
      const maxAttempts = 6;
      let rateLimited = false;

      for (let i = 0; i < maxAttempts; i++) {
        const result = await passwordStrategy.authenticate(
          {
            email: 'test@example.com',
            password: 'wrongpassword',
          },
          _page,
          _page.context(),
        );

        if (result.errorMessage?.toLowerCase().includes('rate limit')) {
          rateLimited = true;
          break;
        }
      }

      expect(rateLimited).toBe(true);
      console.log('Rate limiting protection working');
    });
  });

  test.describe('OAuth2 Authentication', () => {
    test('should support Google OAuth2', async ({ page: _page }) => {
      // Create Google OAuth2 strategy
      const googleStrategy = factory.createOAuth2Strategy('google');
      registry.register(googleStrategy);

      // Get the authentication flow for UI testing
      const flow = googleStrategy.getAuthenticationFlow!({
        email: 'testuser@gmail.com',
        password: 'userpassword',
      });

      expect(flow.steps).toHaveLength(3);
      expect(flow.steps[0].type).toBe('redirect');
      expect(flow.steps[0].url).toContain('accounts.google.com');
      expect(flow.successIndicators).toContain('code=');

      console.log('Google OAuth2 strategy configured');
    });

    test('should support multiple OAuth2 providers', async ({ page: _page }) => {
      const providers = ['google', 'facebook', 'github', 'microsoft'];

      for (const provider of providers) {
        const strategy = factory.createOAuth2Strategy(provider);
        registry.register(strategy);

        const config = strategy.getConfig?.();
        expect(config?.name).toBe(`oauth2-${provider}`);
        expect(config?.type).toBe('oauth');
        expect(config?.provider).toBe(provider);
      }

      const registeredStrategies = registry.list();
      expect(registeredStrategies).toHaveLength(providers.length);

      console.log('Multiple OAuth2 providers supported:', providers.join(', '));
    });

    test('should validate OAuth2 credentials', async ({ page: _page }) => {
      const facebookStrategy = factory.createOAuth2Strategy('facebook');

      const validation = facebookStrategy.validateCredentials!({
        email: 'invalid-email',
        password: '',
      });

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Invalid email format');
      expect(validation.errors).toContain('Password is required for OAuth simulation');

      console.log('OAuth2 credential validation working');
    });
  });

  test.describe('API Key Authentication', () => {
    test('should authenticate with API keys', async ({ page: _page }) => {
      const apiKeyStrategy = factory.createApiKeyStrategy();
      registry.register(apiKeyStrategy);

      // Test with different API key formats
      const apiKeys = [
        'sk_test_12345678901234567890123456789012', // Stripe-style
        'pk_test_98765432109876543210987654321098', // Public key style
        'abcdef1234567890abcdef1234567890abcdef12', // Hex format
      ];

      for (const apiKey of apiKeys) {
        const result = await apiKeyStrategy.authenticate(
          {
            apiKey,
          },
          _page,
          _page.context(),
        );

        expect(result.success).toBe(true);
        expect(result.token).toBeDefined();
        expect(result.userData?.provider).toBe('api-key');
      }

      console.log('API Key authentication working with multiple formats');
    });

    test('should support HMAC signature validation', async ({ page: _page }) => {
      const apiKeyStrategy = factory.createApiKeyStrategy();

      const result = await apiKeyStrategy.authenticate(
        {
          apiKey: 'sk_test_12345678901234567890123456789012',
          apiSecret: 'secret-key-for-hmac',
          algorithm: 'HMAC-SHA256',
        },
        _page,
        _page.context(),
      );

      expect(result.success).toBe(true);
      expect(result.userData?.permissions).toContain('api:read');

      console.log('API Key HMAC signature validation working');
    });
  });

  test.describe('SAML Authentication', () => {
    test('should support SAML providers', async ({ page: _page }) => {
      const samlProviders = ['okta', 'adfs', 'azuread'];

      for (const provider of samlProviders) {
        const strategy = factory.createSAMLStrategy(provider);
        registry.register(strategy);

        const config = strategy.getConfig?.();
        expect(config?.provider).toBe(provider);
        expect(config?.type).toBe('saml');
        expect(config?.attributeMapping).toBeDefined();
        expect(config?.attributeMapping).toBeDefined();
      }

      console.log('SAML providers supported:', samlProviders.join(', '));
    });

    test('should generate secure SAML requests', async ({ page: _page }) => {
      const oktaStrategy = factory.createSAMLStrategy('okta');

      const flow1 = oktaStrategy.getAuthenticationFlow?.({
        username: 'testuser',
        password: 'password123',
      });

      const flow2 = oktaStrategy.getAuthenticationFlow?.({
        username: 'testuser',
        password: 'password123',
      });

      // Each request should have unique URLs (different request IDs)
      expect(flow1?.steps[0].url).not.toBe(flow2?.steps[0].url);
      expect(flow1?.steps[0].url).toContain('SAMLRequest=');

      console.log('SAML request generation working');
    });
  });

  test.describe('Session Management', () => {
    test('should use encrypted session storage', async ({ page: _page, context }) => {
      const sessionManager = new SecureSessionManager(context);

      // Save a session with sensitive data
      await sessionManager.saveSession({
        personaType: 'admin',
        token: 'sensitive-jwt-token',
        userData: {
          secretData: 'highly-confidential-information',
          role: 'administrator',
        },
        expiresAt: new Date(Date.now() + 3600000),
      });

      // Check that the cookie data is encrypted
      const cookies = await context.cookies();
      const sessionCookie = cookies.find(c => c.name.startsWith('testwrightx_session_'));

      expect(sessionCookie).toBeDefined();
      expect(sessionCookie!.value).not.toContain('sensitive-jwt-token');
      expect(sessionCookie!.value).not.toContain('highly-confidential-information');
      expect(sessionCookie!.httpOnly).toBe(true);

      console.log('Session encryption working');
    });

    test('should support session refresh', async ({ page: _page, context }) => {
      const sessionManager = new SecureSessionManager(context);
      const config = AuthConfigManager.getInstance().getConfig();

      // Create a valid JWT token for testing
      const initialToken = jwt.sign(
        {
          persona: 'customer',
          role: 'customer',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
          aud: config.testDomain,
          iss: 'testwrightx-auth',
        },
        config.jwtSecret,
        { algorithm: 'HS256' }
      );

      // Create initial session
      await sessionManager.saveSession({
        personaType: 'customer',
        token: initialToken,
        userData: { role: 'customer' },
        expiresAt: new Date(Date.now() + 3600000),
      });

      // Wait a moment to ensure different timestamp for new token
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Refresh the session
      const refreshed = await sessionManager.refreshSession('customer');
      expect(refreshed).toBe(true);

      // Get the refreshed session
      const session = await sessionManager.getSession('customer');
      expect(session).toBeDefined();
      expect(session!.token).not.toBe(initialToken); // Should have new token

      console.log('Session refresh working');
    });
  });

  test.describe('Multi-Strategy Authentication', () => {
    test('should support strategy switching', async ({ page: _page }) => {
      // Register multiple strategies
      const passwordStrategy = factory.createPasswordStrategy();
      const apiKeyStrategy = factory.createApiKeyStrategy();
      const googleStrategy = factory.createOAuth2Strategy('google');

      registry.register(passwordStrategy);
      registry.register(apiKeyStrategy);
      registry.register(googleStrategy);

      // List all registered strategies
      const strategies = registry.list();
      expect(strategies).toHaveLength(3);

      // Get strategies by type
      const oauthStrategies = registry.getByType('oauth');
      expect(oauthStrategies).toHaveLength(1);

      const passwordStrategies = registry.getByType('password');
      expect(passwordStrategies).toHaveLength(1);

      console.log('Multi-strategy registration working');
    });

    test('should support fallback authentication', async ({ page: _page }) => {
      // Register strategies in order of preference
      const strategies = [
        factory.createPasswordStrategy(),
        factory.createApiKeyStrategy(),
        factory.createOAuth2Strategy('google'),
      ];

      strategies.forEach(strategy => registry.register(strategy));

      // Try authentication with different methods
      const passwordAuth = registry.get('secure-password');
      const apiKeyAuth = registry.get('api-key');
      const oauthAuth = registry.get('oauth2-google');

      expect(passwordAuth).toBeDefined();
      expect(apiKeyAuth).toBeDefined();
      expect(oauthAuth).toBeDefined();

      console.log('Fallback authentication strategy available');
    });
  });

  test.describe('Security Features', () => {
    test('should mask sensitive data in logs', async ({ page: _page }) => {
      const initialAuditCount = logger.getAuditTrail().length;

      const passwordStrategy = factory.createPasswordStrategy();
      await passwordStrategy.authenticate(
        {
          email: 'test@example.com',
          password: 'supersecretpassword123',
        },
        _page,
        _page.context(),
      );

      const auditTrail = logger.getAuditTrail();
      expect(auditTrail.length).toBeGreaterThan(initialAuditCount);

      // Sensitive data should be masked
      const logContent = JSON.stringify(auditTrail);
      expect(logContent).not.toContain('supersecretpassword123');
      expect(logContent).toContain('***MASKED***');

      console.log('Sensitive data masking working');
    });

    test('should validate JWT tokens properly', async ({ page: _page }) => {
      const passwordStrategy = factory.createPasswordStrategy();

      const result = await passwordStrategy.authenticate(
        {
          email: 'admin@testwrightx.com',
          password: 'Admin123!',
        },
        _page,
        _page.context(),
      );

      expect(result.success).toBe(true);
      expect(result.token).toBeDefined();

      // Validate the token
      const isValid = await passwordStrategy.isValid(result.token);
      expect(isValid).toBe(true);

      // Test with tampered token
      const tamperedToken = result.token!.replace(/.$/, 'X');
      const isTamperedValid = await passwordStrategy.isValid(tamperedToken);
      expect(isTamperedValid).toBe(false);

      console.log('JWT token validation working');
    });
  });

  test.describe('Configuration Examples', () => {
    test('should provide configuration templates', async () => {
      const factory = AuthenticationStrategyFactory.getInstance();

      // Get configuration templates for different strategy types
      const oauthTemplate = factory.getConfigTemplate('oauth', 'google');
      expect(oauthTemplate.clientId).toContain('GOOGLE_CLIENT_ID');
      expect(oauthTemplate.scope).toContain('openid');

      const samlTemplate = factory.getConfigTemplate('saml', 'okta');
      expect(samlTemplate.idpUrl).toContain('OKTA_IDP_URL');
      expect(samlTemplate.attributeMapping).toBeDefined();

      const apiKeyTemplate = factory.getConfigTemplate('apikey');
      expect(apiKeyTemplate.apiKey).toBeDefined();
      expect(apiKeyTemplate.algorithm).toContain('HMAC-SHA256');

      console.log('Configuration templates available');
    });

    test('should list available providers', async () => {
      const factory = AuthenticationStrategyFactory.getInstance();

      const oauth2Providers = factory.getAvailableOAuth2Providers();
      expect(oauth2Providers).toContain('google');
      expect(oauth2Providers).toContain('facebook');
      expect(oauth2Providers).toContain('github');

      const samlProviders = factory.getAvailableSAMLProviders();
      expect(samlProviders).toContain('okta');
      expect(samlProviders).toContain('adfs');
      expect(samlProviders).toContain('azuread');

      console.log('Provider lists available');
      console.log('OAuth2 providers:', oauth2Providers.join(', '));
      console.log('SAML providers:', samlProviders.join(', '));
    });
  });

  test.afterEach(async () => {
    // Clean up after each test
    registry.clear();
    logger.clearAuditTrail();
  });
});

/**
 * Real-world usage examples
 */
test.describe('Real-world Authentication Scenarios', () => {
  test('Enterprise SSO with SAML', async ({ page: _page }) => {
    const factory = AuthenticationStrategyFactory.getInstance();
    const registry = AuthenticationStrategyRegistry.getInstance();

    // Configure SAML for enterprise SSO
    const samlStrategy = factory.createSAMLStrategy('okta', {
      idpUrl: 'https://company.okta.com/app/saml/login',
      spEntityId: 'https://myapp.company.com/saml/metadata',
      spAcsUrl: 'https://myapp.company.com/auth/saml/acs',
      attributeMapping: {
        email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        role: 'http://schemas.company.com/claims/role',
        department: 'http://schemas.company.com/claims/department',
      },
    });

    registry.register(samlStrategy);
    registry.setDefault('saml');

    const flow = samlStrategy.getAuthenticationFlow?.({
      username: 'john.doe@company.com',
      password: 'enterprisePassword123!',
    });

    expect(flow?.steps[0].url).toContain('company.okta.com');
    console.log('Enterprise SSO scenario configured');
  });

  test('API-First Application with API Keys', async ({ page: _page }) => {
    const factory = AuthenticationStrategyFactory.getInstance();
    const registry = AuthenticationStrategyRegistry.getInstance();

    // Configure API key authentication for API-first app
    const apiKeyStrategy = factory.createApiKeyStrategy();
    registry.register(apiKeyStrategy);

    // Test API key authentication flow
    const result = await apiKeyStrategy.authenticate(
      {
        apiKey: 'sk_prod_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef',
        algorithm: 'HMAC-SHA256',
        apiSecret: 'super-secret-signing-key',
        customHeaders: {
          'X-API-Version': '2024-01-01',
          'X-Client-App': 'MyTestApp',
        },
      },
      _page,
      _page.context(),
    );

    expect(result.success).toBe(true);
    expect(result.userData?.provider).toBe('api-key');
    console.log('API-first application scenario configured');
  });

  test('Multi-tenant SaaS with Multiple OAuth Providers', async ({ page: _page }) => {
    const factory = AuthenticationStrategyFactory.getInstance();
    const registry = AuthenticationStrategyRegistry.getInstance();

    // Configure multiple OAuth providers for multi-tenant SaaS
    const providers = ['google', 'microsoft', 'github'];

    providers.forEach(provider => {
      const strategy = factory.createOAuth2Strategy(provider);
      registry.register(strategy);
    });

    // Each tenant can choose their preferred OAuth provider
    const googleStrategy = registry.get('oauth2-google');
    const microsoftStrategy = registry.get('oauth2-microsoft');
    const githubStrategy = registry.get('oauth2-github');

    expect(googleStrategy).toBeDefined();
    expect(microsoftStrategy).toBeDefined();
    expect(githubStrategy).toBeDefined();

    console.log('Multi-tenant SaaS scenario configured');
  });
});

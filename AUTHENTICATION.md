# TestWrightX Authentication Framework

A comprehensive, secure, and pluggable authentication testing framework that supports multiple authentication methods with enterprise-grade security features.

## 🔒 Security Features

### ✅ **Implemented Security Enhancements:**

- **Secure credential management** - No hardcoded credentials, environment variable-based configuration
- **Session encryption** - AES encryption for session data storage
- **JWT token validation** - Proper JWT validation with expiration checks and signature verification
- **Rate limiting** - Configurable rate limiting with automatic blocking
- **CSRF protection** - Cross-site request forgery protection with token validation
- **Secure logging** - Sensitive data masking and comprehensive audit trails
- **Input validation** - Robust input validation with detailed error reporting
- **Cookie security** - HttpOnly, Secure, and SameSite cookie configurations

## 🔌 Pluggable Authentication Methods

### Password Authentication

```typescript
const passwordStrategy = factory.createPasswordStrategy();
registry.register(passwordStrategy);

const result = await passwordStrategy.authenticate(
  {
    email: 'user@example.com',
    password: 'securePassword123!',
  },
  page,
  context,
);
```

### OAuth2 Authentication

Supports multiple providers: Google, Facebook, GitHub, Microsoft, LinkedIn

```typescript
const googleStrategy = factory.createOAuth2Strategy('google');
registry.register(googleStrategy);

const result = await googleStrategy.authenticate(
  {
    email: 'user@gmail.com',
    password: 'userPassword',
    scope: ['openid', 'email', 'profile'],
  },
  page,
  context,
);
```

### SAML Authentication

Supports enterprise SSO providers: Okta, ADFS, Azure AD

```typescript
const oktaStrategy = factory.createSAMLStrategy('okta');
registry.register(oktaStrategy);

const result = await oktaStrategy.authenticate(
  {
    username: 'user@company.com',
    password: 'enterprisePassword',
  },
  page,
  context,
);
```

### API Key Authentication

Supports multiple API key formats and HMAC signature validation

```typescript
const apiKeyStrategy = factory.createApiKeyStrategy();
registry.register(apiKeyStrategy);

const result = await apiKeyStrategy.authenticate(
  {
    apiKey: 'sk_test_12345678901234567890123456789012',
    algorithm: 'HMAC-SHA256',
    apiSecret: 'signing-secret',
  },
  page,
  context,
);
```

## 🛠️ Quick Start

### 1. Setup Environment Variables

Copy `.env.example` to `.env` and configure your settings:

```bash
cp .env.example .env
```

**Required variables:**

```env
ADMIN_EMAIL=admin@testwrightx.com
ADMIN_PASSWORD=Admin123!
CUSTOMER_EMAIL=customer@testwrightx.com
CUSTOMER_PASSWORD=Customer123!
JWT_SECRET=your-super-secure-jwt-secret-key-at-least-32-characters-long
SESSION_ENCRYPTION_KEY=your-session-encryption-key-at-least-32-characters-long
```

### 2. Basic Usage

```typescript
import { test, expect } from '@playwright/test';
import { AuthenticationManager } from '@auth/AuthenticationManager';
import { AuthenticationStrategyFactory } from '@auth/strategies/StrategyFactory';
import { AuthenticationStrategyRegistry } from '@auth/strategies/base/AuthenticationStrategy';

test('authentication example', async ({ page, context }) => {
  // Initialize components
  const authManager = new AuthenticationManager(page, context);
  const factory = AuthenticationStrategyFactory.getInstance();
  const registry = AuthenticationStrategyRegistry.getInstance();

  // Create and register strategies
  const passwordStrategy = factory.createPasswordStrategy();
  registry.register(passwordStrategy);
  registry.setDefault('secure-password');

  // Authenticate
  const success = await authManager.authenticateAs('admin');
  expect(success).toBe(true);
});
```

### 3. Advanced Multi-Strategy Setup

```typescript
test('multi-strategy authentication', async ({ page, context }) => {
  const factory = AuthenticationStrategyFactory.getInstance();
  const registry = AuthenticationStrategyRegistry.getInstance();

  // Register multiple strategies
  const strategies = [
    factory.createPasswordStrategy(),
    factory.createApiKeyStrategy(),
    factory.createOAuth2Strategy('google'),
    factory.createSAMLStrategy('okta'),
  ];

  strategies.forEach(strategy => registry.register(strategy));

  // Use different authentication methods
  const passwordAuth = registry.get('secure-password');
  const apiKeyAuth = registry.get('api-key');
  const oauthAuth = registry.get('oauth2-google');
  const samlAuth = registry.get('saml');

  // Test each method...
});
```

## 📋 Configuration

### Environment-Based Configuration

The authentication system uses a centralized configuration manager that supports:

- **Development/Staging/Production** environments
- **Automatic security setting adjustment** based on environment
- **Validation of all configuration parameters**
- **Environment variable fallbacks**

### OAuth2 Provider Configuration

```typescript
// Add custom OAuth2 provider
factory.addOAuth2Preset('custom-provider', {
  name: 'Custom Provider',
  authUrl: 'https://custom.com/oauth/authorize',
  tokenUrl: 'https://custom.com/oauth/token',
  userInfoUrl: 'https://custom.com/api/user',
  scope: ['profile', 'email'],
});

const customStrategy = factory.createOAuth2Strategy('custom-provider');
```

### SAML Provider Configuration

```typescript
// Add custom SAML provider
factory.addSAMLPreset('custom-saml', {
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  attributeMapping: {
    email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
    role: 'http://schemas.company.com/claims/role',
  },
});
```

## 🔐 Security Best Practices

### 1. Credential Management

- ✅ Never hardcode credentials in test files
- ✅ Use environment variables for all sensitive data
- ✅ Rotate secrets regularly
- ✅ Use different credentials for different environments

### 2. Session Security

- ✅ Sessions are encrypted with AES
- ✅ Automatic session expiration
- ✅ Secure cookie settings (HttpOnly, Secure, SameSite)
- ✅ Session refresh mechanism

### 3. Token Security

- ✅ JWT tokens with proper expiration
- ✅ Signature verification
- ✅ Token rotation for long-running tests
- ✅ Proper token storage and cleanup

### 4. Rate Limiting

- ✅ Configurable rate limiting per authentication method
- ✅ Automatic blocking after failed attempts
- ✅ Reset on successful authentication
- ✅ Different limits for different user types

### 5. Audit and Monitoring

- ✅ Comprehensive audit logging
- ✅ Sensitive data masking
- ✅ Security event tracking
- ✅ Configurable log levels

## 🧪 Testing

### Security Tests

```bash
# Run security-focused tests
npx playwright test tests/auth/security.spec.ts

# Run enhanced authentication examples
npx playwright test tests/examples/enhanced-auth-example.spec.ts
```

### Test Categories

1. **Input Validation Tests** - Email formats, password strength, API key formats
2. **Rate Limiting Tests** - Failed attempt blocking, reset mechanisms
3. **Session Security Tests** - Encryption, expiration, cookie security
4. **JWT Token Tests** - Validation, expiration, tampering detection
5. **Multi-Strategy Tests** - Strategy switching, fallback mechanisms

## 📖 API Reference

### AuthenticationStrategyFactory

```typescript
// Create strategies
createPasswordStrategy(): IAuthenticationStrategy
createOAuth2Strategy(provider: string, config?: Partial<OAuth2ProviderConfig>): IAuthenticationStrategy
createSAMLStrategy(provider: string, config?: Partial<SAMLConfig>): IAuthenticationStrategy
createApiKeyStrategy(): IAuthenticationStrategy

// Get available providers
getAvailableOAuth2Providers(): string[]
getAvailableSAMLProviders(): string[]

// Configuration templates
getConfigTemplate(type: string, provider?: string): Record<string, any>
validateConfig(config: StrategyConfig): { valid: boolean; errors: string[] }
```

### AuthenticationStrategyRegistry

```typescript
// Strategy management
register(strategy: IAuthenticationStrategy): void
unregister(name: string): void
get(name: string): IAuthenticationStrategy | undefined
list(): { name: string; type: string; provider?: string }[]

// Type and provider filtering
getByType(type: string): IAuthenticationStrategy[]
getByProvider(provider: string): IAuthenticationStrategy[]

// Default strategy
setDefault(name: string): void
getDefault(): IAuthenticationStrategy | undefined
```

### SecureSessionManager

```typescript
// Session management
saveSession(session: Omit<AuthSession, 'createdAt' | 'lastActivity' | 'csrfToken'>): Promise<void>
getSession(personaType: string): Promise<AuthSession | null>
restoreSession(session: AuthSession): Promise<void>
clearSession(personaType?: string): Promise<void>
refreshSession(personaType: string): Promise<boolean>

// Session info
getSessionInfo(): { activeUsers: string[], sessionCount: number, sessionId: string }
```

## 🔧 Advanced Usage

### Custom Authentication Strategy

```typescript
import {
  BaseAuthenticationStrategy,
  AuthenticationCredentials,
  AuthenticationResult,
} from '@auth/strategies/base/AuthenticationStrategy';

export class CustomStrategy extends BaseAuthenticationStrategy {
  public readonly name = 'custom-auth';
  public readonly type = 'custom' as const;

  public async authenticate(
    credentials: AuthenticationCredentials,
    page: Page,
    context: BrowserContext,
  ): Promise<AuthenticationResult> {
    // Implement your custom authentication logic
    return {
      success: true,
      token: 'custom-token',
      userData: {
        id: 'custom-user',
        email: 'user@custom.com',
        role: 'user',
        permissions: ['read'],
        provider: 'custom',
      },
    };
  }

  public async isValid(token?: string): Promise<boolean> {
    // Implement token validation
    return token === 'custom-token';
  }
}
```

### Custom Session Storage

```typescript
export class CustomSessionManager extends SecureSessionManager {
  protected async customEncryption(data: string): Promise<string> {
    // Implement custom encryption
    return data;
  }
}
```

## 🐛 Troubleshooting

### Common Issues

1. **"Required environment variable not set"**
   - Check your `.env` file
   - Ensure all required variables are set
   - Verify environment variable names match exactly

2. **"Rate limit exceeded"**
   - Clear rate limiting: `strategy.clearRateLimiting()`
   - Adjust rate limiting configuration
   - Check for failed authentication attempts

3. **"Invalid JWT token"**
   - Check JWT secret configuration
   - Verify token hasn't expired
   - Ensure token hasn't been tampered with

4. **"Session decryption failed"**
   - Check session encryption key
   - Clear browser cookies
   - Restart test session

### Debug Mode

Enable debug logging:

```env
LOG_LEVEL=debug
AUDIT_TRAIL=true
```

### Security Audit

Get security audit information:

```typescript
// Get audit trail
const auditTrail = logger.getAuditTrail();
console.log('Security events:', auditTrail);

// Get rate limiting status
const rateLimitStatus = passwordStrategy.getRateLimitStatus();
console.log('Rate limiting:', rateLimitStatus);

// Get session information
const sessionInfo = sessionManager.getSessionInfo();
console.log('Active sessions:', sessionInfo);
```

## 🤝 Contributing

When contributing to the authentication framework:

1. **Security First** - All changes must maintain or improve security
2. **Test Coverage** - Add tests for new authentication strategies
3. **Documentation** - Update this documentation for new features
4. **Environment Variables** - Add new variables to `.env.example`
5. **Backwards Compatibility** - Maintain compatibility with existing tests

## 📄 License

This authentication framework is part of TestWrightX and follows the same MIT license.

---

**⚠️ Security Notice**: This framework is designed for testing purposes. While it implements security best practices, ensure you're not using real production credentials or exposing sensitive data in your test environment.

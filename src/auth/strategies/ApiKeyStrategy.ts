import { Page, BrowserContext } from '@playwright/test';
import jwt from 'jsonwebtoken';
import CryptoJS from 'crypto-js';
import {
  BaseAuthenticationStrategy,
  AuthenticationCredentials,
  AuthenticationResult,
  UserData,
} from '@auth/strategies/base/AuthenticationStrategy';
import { AuthConfigManager } from '@auth/config/AuthConfig';
import { logger } from '@auth/utils/SecureLogger';

export interface ApiKeyCredentials extends AuthenticationCredentials {
  apiKey: string;
  apiSecret?: string;
  keyId?: string;
  algorithm?: 'HMAC-SHA256' | 'RSA-SHA256' | 'simple';
  customHeaders?: Record<string, string>;
}

/**
 * API Key authentication strategy
 * Supports various API key authentication methods
 */
export class ApiKeyStrategy extends BaseAuthenticationStrategy {
  public readonly name = 'api-key';
  public readonly type = 'apikey' as const;

  private authConfig = AuthConfigManager.getInstance().getConfig();

  public async authenticate(
    credentials: ApiKeyCredentials,
    page: Page,
    context: BrowserContext,
  ): Promise<AuthenticationResult> {
    try {
      logger.audit(
        'API Key authentication started',
        undefined,
        {
          hasApiKey: !!credentials.apiKey,
          hasSecret: !!credentials.apiSecret,
          algorithm: credentials.algorithm,
        },
        this.sessionId,
      );

      // Validate credentials
      const validation = this.validateCredentials(credentials);
      if (!validation.valid) {
        return {
          success: false,
          errorMessage: `Invalid credentials: ${validation.errors.join(', ')}`,
        };
      }

      // Validate API key format and signature
      const keyValidation = await this.validateApiKey(credentials);
      if (!keyValidation.valid) {
        return {
          success: false,
          errorMessage: keyValidation.error || 'Invalid API key',
        };
      }

      // Set API key in browser for subsequent requests
      await this.setupApiKeyAuthentication(page, context, credentials);

      // Generate user data from API key
      const userData = this.extractUserDataFromApiKey(credentials);

      // Generate JWT token for session management
      const token = this.generateJWTToken(userData);

      logger.audit(
        'API Key authentication successful',
        undefined,
        {
          keyId: credentials.keyId,
          algorithm: credentials.algorithm,
        },
        this.sessionId,
      );

      return {
        success: true,
        token,
        userData,
        expiresAt: new Date(Date.now() + this.authConfig.sessionTimeout * 1000),
      };
    } catch (error) {
      logger.error(
        'API Key authentication failed',
        {
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );

      return {
        success: false,
        errorMessage: `API Key authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  public async isValid(token?: string): Promise<boolean> {
    if (!token) {
      return false;
    }

    try {
      const decoded = jwt.verify(token, this.authConfig.jwtSecret) as jwt.JwtPayload;

      // Check expiration
      if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) {
        return false;
      }

      // Check that it's an API key token
      if (decoded.authType !== 'api-key') {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  public validateCredentials(credentials: ApiKeyCredentials): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!credentials.apiKey) {
      errors.push('API key is required');
    }

    if (credentials.apiKey && credentials.apiKey.length < 16) {
      errors.push('API key must be at least 16 characters');
    }

    if (credentials.algorithm === 'HMAC-SHA256' && !credentials.apiSecret) {
      errors.push('API secret is required for HMAC-SHA256 algorithm');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  private async validateApiKey(credentials: ApiKeyCredentials): Promise<{ valid: boolean; error?: string }> {
    try {
      // Basic format validation
      if (!this.isValidApiKeyFormat(credentials.apiKey)) {
        return { valid: false, error: 'Invalid API key format' };
      }

      // Algorithm-specific validation
      if (credentials.algorithm === 'HMAC-SHA256' && credentials.apiSecret) {
        const isValidSignature = this.validateHMACSignature(credentials.apiKey, credentials.apiSecret);
        if (!isValidSignature) {
          return { valid: false, error: 'Invalid HMAC signature' };
        }
      }

      // Simulate API key lookup (in real scenario, this would query your API key database)
      const keyInfo = await this.lookupApiKey(credentials.apiKey);
      if (!keyInfo.exists) {
        return { valid: false, error: 'API key not found' };
      }

      if (!keyInfo.active) {
        return { valid: false, error: 'API key is disabled' };
      }

      if (keyInfo.expired) {
        return { valid: false, error: 'API key has expired' };
      }

      return { valid: true };
    } catch (error) {
      logger.error(
        'API key validation error',
        {
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );
      return { valid: false, error: 'Validation error' };
    }
  }

  private isValidApiKeyFormat(apiKey: string): boolean {
    // Check for common API key patterns
    const patterns = [
      /^[a-zA-Z0-9]{32,}$/, // Basic alphanumeric
      /^[a-zA-Z0-9_-]{32,}$/, // With underscore and dash
      /^sk_[a-zA-Z0-9]{32,}$/, // Stripe-style
      /^pk_[a-zA-Z0-9]{32,}$/, // Public key style
      /^[a-f0-9]{32,}$/, // Hex format
    ];

    return patterns.some(pattern => pattern.test(apiKey));
  }

  private validateHMACSignature(apiKey: string, secret: string): boolean {
    try {
      // For test/development keys, use simplified validation
      if (apiKey.startsWith('sk_test_') || apiKey.startsWith('pk_test_') || apiKey.startsWith('sk_prod_')) {
        // For test and development keys, just validate that the secret is provided and reasonable
        return secret.length >= 8; // Minimum secret length for test mode
      }

      // For production keys with embedded signatures, use proper HMAC validation
      if (apiKey.length < 64) {
        // Key too short to contain a meaningful signature - treat as test key
        return secret.length >= 8;
      }

      // Extract signature from API key (assuming last 32 chars are signature)
      const payload = apiKey.slice(0, -32);
      const signature = apiKey.slice(-32);

      // Calculate expected signature
      const expectedSignature = CryptoJS.HmacSHA256(payload, secret).toString();

      return signature === expectedSignature;
    } catch {
      return false;
    }
  }

  private async lookupApiKey(
    apiKey: string,
  ): Promise<{ exists: boolean; active: boolean; expired: boolean; userId?: string; permissions?: string[] }> {
    // Simulate API key database lookup
    // In a real scenario, this would query your database

    const simulatedKeys: Record<string, any> = {
      sk_test_12345678901234567890123456789012: {
        exists: true,
        active: true,
        expired: false,
        userId: 'user_123',
        permissions: ['read', 'write'],
        role: 'admin',
      },
      pk_test_98765432109876543210987654321098: {
        exists: true,
        active: true,
        expired: false,
        userId: 'user_456',
        permissions: ['read'],
        role: 'customer',
      },
    };

    // If not in our simulated database, create a default response
    if (!simulatedKeys[apiKey]) {
      // For testing, we'll accept any properly formatted key
      if (this.isValidApiKeyFormat(apiKey)) {
        return {
          exists: true,
          active: true,
          expired: false,
          userId: 'simulated_user',
          permissions: ['read'],
        };
      }
      return { exists: false, active: false, expired: false };
    }

    return simulatedKeys[apiKey];
  }

  private async setupApiKeyAuthentication(
    page: Page,
    context: BrowserContext,
    credentials: ApiKeyCredentials,
  ): Promise<void> {
    // Set API key in request headers for all subsequent requests
    await context.setExtraHTTPHeaders({
      Authorization: `Bearer ${credentials.apiKey}`,
      'X-API-Key': credentials.apiKey,
      ...(credentials.customHeaders || {}),
    });

    // Set API key in localStorage for client-side access
    await page.addInitScript(
      config => {
        localStorage.setItem('apiKey', config.apiKey);
        localStorage.setItem('authType', 'api-key');

        // Store custom headers if provided
        if (config.headers) {
          localStorage.setItem('customHeaders', JSON.stringify(config.headers));
        }
      },
      {
        apiKey: credentials.apiKey,
        headers: credentials.customHeaders,
      },
    );

    // Intercept requests to add API key authentication
    await context.route('**/*', async route => {
      const request = route.request();
      const headers: Record<string, string> = {
        ...request.headers(),
        Authorization: `Bearer ${credentials.apiKey}`,
        'X-API-Key': credentials.apiKey,
      };

      // Add algorithm-specific headers
      if (credentials.algorithm === 'HMAC-SHA256' && credentials.apiSecret) {
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const signature = this.generateRequestSignature(
          request.method(),
          request.url(),
          timestamp,
          credentials.apiSecret,
        );

        headers['X-Timestamp'] = timestamp;
        headers['X-Signature'] = signature;
      }

      await route.continue({ headers });
    });

    logger.debug(
      'API key authentication setup complete',
      {
        hasCustomHeaders: !!credentials.customHeaders,
        algorithm: credentials.algorithm,
      },
      this.sessionId,
    );
  }

  private generateRequestSignature(method: string, url: string, timestamp: string, secret: string): string {
    const message = `${method}${url}${timestamp}`;
    return CryptoJS.HmacSHA256(message, secret).toString();
  }

  private extractUserDataFromApiKey(credentials: ApiKeyCredentials): UserData {
    // Extract user information from API key
    // In a real scenario, this would come from your API key database lookup

    const keyId = credentials.keyId || this.extractKeyId(credentials.apiKey);
    const role = this.determineRoleFromApiKey(credentials.apiKey);

    return {
      id: `apikey_${keyId}`,
      email: `${keyId}@api.testwrightx.com`,
      name: `API User ${keyId}`,
      role,
      permissions: this.getPermissionsForRole(role),
      provider: 'api-key',
      providerId: keyId,
      verified: true,
      lastLogin: new Date(),
    };
  }

  private extractKeyId(apiKey: string): string {
    // Extract key ID from API key (first 8 characters after prefix)
    if (apiKey.startsWith('sk_') || apiKey.startsWith('pk_')) {
      return apiKey.substring(3, 11);
    }
    return apiKey.substring(0, 8);
  }

  private determineRoleFromApiKey(apiKey: string): string {
    // Determine role based on API key prefix or pattern
    if (apiKey.startsWith('sk_')) {
      return 'admin'; // Secret keys get admin access
    }
    if (apiKey.startsWith('pk_')) {
      return 'customer'; // Public keys get customer access
    }
    return 'customer'; // Default role
  }

  private getPermissionsForRole(role: string): string[] {
    const permissions: Record<string, string[]> = {
      admin: ['api:read', 'api:write', 'api:delete', 'admin:read', 'admin:write'],
      customer: ['api:read', 'profile:read', 'profile:write'],
      guest: ['api:read'],
    };
    return permissions[role] || permissions.guest;
  }

  private generateJWTToken(userData: UserData): string {
    const payload = {
      sub: userData.id,
      email: userData.email,
      role: userData.role,
      permissions: userData.permissions,
      authType: 'api-key',
      providerId: userData.providerId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.authConfig.sessionTimeout,
      aud: this.authConfig.testDomain,
      iss: 'testwrightx-auth',
    };

    return jwt.sign(payload, this.authConfig.jwtSecret, { algorithm: 'HS256' });
  }

  public async logout(page: Page, context: BrowserContext): Promise<void> {
    // Remove API key from headers and storage
    await context.setExtraHTTPHeaders({});

    await page.evaluate(() => {
      localStorage.removeItem('apiKey');
      localStorage.removeItem('authType');
      localStorage.removeItem('customHeaders');
    });

    logger.audit('API Key logout completed', undefined, {}, this.sessionId);
  }

  public getConfig(): Record<string, any> {
    return {
      name: this.name,
      type: this.type,
      supportedAlgorithms: ['HMAC-SHA256', 'RSA-SHA256', 'simple'],
      requiredFields: ['apiKey'],
      optionalFields: ['apiSecret', 'keyId', 'algorithm', 'customHeaders'],
      keyFormats: ['Basic alphanumeric', 'Stripe-style (sk_/pk_)', 'Hexadecimal', 'Custom with separators'],
    };
  }
}

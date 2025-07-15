import { Page, BrowserContext } from '@playwright/test';
import jwt from 'jsonwebtoken';
import CryptoJS from 'crypto-js';
import {
  BaseAuthenticationStrategy,
  AuthenticationCredentials,
  AuthenticationResult,
  AuthenticationFlow,
  UserData,
} from '@auth/strategies/base/AuthenticationStrategy';
import { AuthConfigManager } from '@auth/config/AuthConfig';
import { logger } from '@auth/utils/SecureLogger';

export interface OAuth2Credentials extends AuthenticationCredentials {
  clientId?: string;
  clientSecret?: string;
  scope?: string[];
  state?: string;
  redirectUri?: string;
  authorizationCode?: string;
  email?: string; // For simulation purposes
  password?: string; // For simulation purposes
}

export interface OAuth2ProviderConfig {
  name: string;
  authUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  clientId: string;
  clientSecret: string;
  scope: string[];
  redirectUri: string;
  responseType: 'code' | 'token';
  grantType: 'authorization_code' | 'client_credentials';
  pkce?: boolean;
}

/**
 * OAuth2 authentication strategy supporting multiple providers
 */
export class OAuth2Strategy extends BaseAuthenticationStrategy {
  public readonly name: string;
  public readonly type = 'oauth' as const;
  public readonly provider: string;

  private config: OAuth2ProviderConfig;
  private authConfig = AuthConfigManager.getInstance().getConfig();

  constructor(provider: string, config: OAuth2ProviderConfig) {
    super();
    this.provider = provider;
    this.name = `oauth2-${provider}`;
    this.config = config;

    logger.info('OAuth2 strategy initialized', {
      provider: this.provider,
      name: this.name,
      scope: config.scope,
    });
  }

  public async authenticate(
    credentials: OAuth2Credentials,
    page: Page,
    _context: BrowserContext,
  ): Promise<AuthenticationResult> {
    try {
      logger.audit(
        'OAuth2 authentication started',
        undefined,
        {
          provider: this.provider,
          scope: this.config.scope,
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

      // Step 1: Initiate OAuth flow
      const authUrl = this.buildAuthorizationUrl(credentials);
      logger.debug('Starting OAuth flow', { authUrl: this.maskSensitiveData(authUrl) });

      // Step 2: Navigate to auth URL
      await page.goto(authUrl);

      // Step 3: Handle provider-specific login flow
      const loginResult = await this.handleProviderLogin(page, credentials);
      if (!loginResult.success) {
        return loginResult;
      }

      // Step 4: Wait for redirect with authorization code
      const authCode = await this.extractAuthorizationCode(page);
      if (!authCode) {
        return {
          success: false,
          errorMessage: 'Failed to receive authorization code',
        };
      }

      // Step 5: Exchange code for tokens
      const tokenResult = await this.exchangeCodeForTokens(authCode, credentials);
      if (!tokenResult.success) {
        return tokenResult;
      }

      // Step 6: Get user information
      const userInfo = await this.getUserInfo(tokenResult.providerData!.accessToken!);

      logger.audit(
        'OAuth2 authentication successful',
        undefined,
        {
          provider: this.provider,
          userId: userInfo.id,
        },
        this.sessionId,
      );

      const result: AuthenticationResult = {
        success: true,
        token: this.generateJWTToken(userInfo),
        userData: userInfo,
        expiresAt: new Date(Date.now() + tokenResult.providerData!.expiresIn! * 1000),
      };

      if (tokenResult.providerData) {
        result.providerData = tokenResult.providerData;
      }

      return result;
    } catch (error) {
      logger.error(
        'OAuth2 authentication failed',
        {
          provider: this.provider,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );

      return {
        success: false,
        errorMessage: `OAuth2 authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
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

      // Check provider
      if (decoded.provider !== this.provider) {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  public getAuthenticationFlow(credentials: OAuth2Credentials): AuthenticationFlow {
    return {
      steps: [
        {
          type: 'redirect',
          url: this.buildAuthorizationUrl(credentials),
        },
        {
          type: 'form',
          selector: this.getLoginFormSelector(),
          data: {
            email: credentials.email,
            password: credentials.password,
          },
        },
        {
          type: 'wait',
          waitFor: this.config.redirectUri,
        },
      ],
      finalRedirect: this.config.redirectUri,
      successIndicators: ['code=', 'access_token='],
      failureIndicators: ['error=', 'error_description='],
    };
  }

  public async refreshAuth(refreshToken: string): Promise<AuthenticationResult> {
    try {
      // Simulate token refresh
      const response = await this.simulateTokenRefresh(refreshToken);

      if (response.success) {
        logger.audit(
          'OAuth2 token refreshed',
          undefined,
          {
            provider: this.provider,
          },
          this.sessionId,
        );
      }

      return response;
    } catch (error) {
      logger.error(
        'OAuth2 token refresh failed',
        {
          provider: this.provider,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        this.sessionId,
      );

      return {
        success: false,
        errorMessage: 'Token refresh failed',
      };
    }
  }

  public validateCredentials(credentials: OAuth2Credentials): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // For simulation, we need email/password
    if (!credentials.email) {
      errors.push('Email is required for OAuth simulation');
    }

    if (!credentials.password) {
      errors.push('Password is required for OAuth simulation');
    }

    // Validate email format
    if (credentials.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(credentials.email)) {
      errors.push('Invalid email format');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  private buildAuthorizationUrl(credentials: OAuth2Credentials): string {
    const params = new URLSearchParams({
      client_id: credentials.clientId || this.config.clientId,
      redirect_uri: credentials.redirectUri || this.config.redirectUri,
      response_type: this.config.responseType,
      scope: (credentials.scope || this.config.scope).join(' '),
      state: credentials.state || this.generateState(),
    });

    return `${this.config.authUrl}?${params.toString()}`;
  }

  private async handleProviderLogin(page: Page, credentials: OAuth2Credentials): Promise<AuthenticationResult> {
    try {
      // Wait for login form
      const loginFormExists = await this.waitForElement(page, this.getLoginFormSelector(), 10000);
      if (!loginFormExists) {
        return {
          success: false,
          errorMessage: 'Login form not found',
        };
      }

      // Fill in credentials
      await page.fill(this.getEmailSelector(), credentials.email!);
      await page.fill(this.getPasswordSelector(), credentials.password!);

      // Submit form
      await page.click(this.getSubmitSelector());

      // Wait for redirect or error
      await page.waitForLoadState('networkidle');

      // Check for authorization success
      const currentUrl = page.url();
      if (currentUrl.includes('code=') || currentUrl.includes(this.config.redirectUri)) {
        return { success: true };
      }

      // Check for errors
      const errorElement = await page.locator('[data-testid="error-message"]').first();
      if (await errorElement.isVisible()) {
        const errorText = await errorElement.textContent();
        return {
          success: false,
          errorMessage: errorText || 'Login failed',
        };
      }

      return { success: true };
    } catch (error) {
      return {
        success: false,
        errorMessage: `Provider login failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  private async extractAuthorizationCode(page: Page): Promise<string | null> {
    try {
      // Wait for redirect to callback URL
      await this.waitForUrl(page, new RegExp(this.config.redirectUri), 15000);

      const url = new URL(page.url());
      return url.searchParams.get('code');
    } catch {
      return null;
    }
  }

  private async exchangeCodeForTokens(_code: string, _credentials: OAuth2Credentials): Promise<AuthenticationResult> {
    // Simulate token exchange (in real scenario, this would be an API call)
    try {
      const simulatedResponse = {
        access_token: this.generateAccessToken(),
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: this.generateRefreshToken(),
        scope: this.config.scope.join(' '),
      };

      return {
        success: true,
        providerData: {
          provider: this.provider,
          accessToken: simulatedResponse.access_token,
          tokenType: simulatedResponse.token_type,
          expiresIn: simulatedResponse.expires_in,
          scope: this.config.scope,
        },
      };
    } catch (error) {
      return {
        success: false,
        errorMessage: `Token exchange failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  private async getUserInfo(_accessToken: string): Promise<UserData> {
    // Simulate user info retrieval (in real scenario, this would be an API call)
    const userData: UserData = {
      id: this.generateUserId(),
      email: this.getSimulatedUserEmail(),
      name: this.getSimulatedUserName(),
      role: this.getSimulatedUserRole(),
      permissions: this.getSimulatedPermissions(),
      avatar: this.getSimulatedAvatar(),
      verified: true,
      lastLogin: new Date(),
      provider: this.provider,
      providerId: this.generateProviderId(),
    };

    return userData;
  }

  private async simulateTokenRefresh(_refreshToken: string): Promise<AuthenticationResult> {
    // Simulate token refresh
    return {
      success: true,
      token: this.generateJWTToken({
        id: 'refreshed-user',
        email: 'user@example.com',
        role: 'user',
        permissions: [],
        provider: this.provider,
      } as UserData),
      expiresAt: new Date(Date.now() + 3600000), // 1 hour
    };
  }

  // Provider-specific selectors
  private getLoginFormSelector(): string {
    const selectors: Record<string, string> = {
      google: '#identifierNext',
      facebook: '#email',
      github: '#login_field',
      microsoft: '[data-testid="i0116"]',
      default: '[data-testid="email"], input[type="email"], input[name="email"]',
    };
    return selectors[this.provider] || selectors.default;
  }

  private getEmailSelector(): string {
    const selectors: Record<string, string> = {
      google: '#identifierId',
      facebook: '#email',
      github: '#login_field',
      microsoft: '[data-testid="i0116"]',
      default: '[data-testid="email"], input[type="email"], input[name="email"]',
    };
    return selectors[this.provider] || selectors.default;
  }

  private getPasswordSelector(): string {
    const selectors: Record<string, string> = {
      google: '[name="password"]',
      facebook: '#pass',
      github: '#password',
      microsoft: '[data-testid="i0118"]',
      default: '[data-testid="password"], input[type="password"], input[name="password"]',
    };
    return selectors[this.provider] || selectors.default;
  }

  private getSubmitSelector(): string {
    const selectors: Record<string, string> = {
      google: '#passwordNext',
      facebook: '[data-testid="royal_login_button"]',
      github: '[name="commit"]',
      microsoft: '[data-testid="idSIButton9"]',
      default: '[data-testid="submit"], button[type="submit"], input[type="submit"]',
    };
    return selectors[this.provider] || selectors.default;
  }

  // Utility methods
  private generateState(): string {
    return CryptoJS.lib.WordArray.random(16).toString();
  }

  private generateAccessToken(): string {
    return CryptoJS.lib.WordArray.random(32).toString();
  }

  private generateRefreshToken(): string {
    return CryptoJS.lib.WordArray.random(32).toString();
  }

  private generateUserId(): string {
    return `${this.provider}_${CryptoJS.lib.WordArray.random(8).toString()}`;
  }

  private generateProviderId(): string {
    return CryptoJS.lib.WordArray.random(12).toString();
  }

  private generateJWTToken(userData: UserData): string {
    const payload = {
      sub: userData.id,
      email: userData.email,
      name: userData.name,
      role: userData.role,
      provider: this.provider,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.authConfig.sessionTimeout,
      aud: this.authConfig.testDomain,
      iss: 'testwrightx-auth',
    };

    return jwt.sign(payload, this.authConfig.jwtSecret, { algorithm: 'HS256' });
  }

  public getConfig(): Record<string, any> {
    return {
      name: this.name,
      type: this.type,
      provider: this.provider,
      authUrl: this.config.authUrl,
      scope: this.config.scope,
      redirectUri: this.config.redirectUri,
      responseType: this.config.responseType,
      grantType: this.config.grantType,
    };
  }

  // Simulation helpers
  private getSimulatedUserEmail(): string {
    const emails: Record<string, string> = {
      google: 'testuser@gmail.com',
      facebook: 'testuser@facebook.com',
      github: 'testuser@users.noreply.github.com',
      microsoft: 'testuser@outlook.com',
    };
    return emails[this.provider] || `testuser@${this.provider}.com`;
  }

  private getSimulatedUserName(): string {
    return `Test User (${this.provider})`;
  }

  private getSimulatedUserRole(): string {
    // Default role based on provider
    const roles: Record<string, string> = {
      google: 'customer',
      facebook: 'customer',
      github: 'developer',
      microsoft: 'customer',
    };
    return roles[this.provider] || 'customer';
  }

  private getSimulatedPermissions(): string[] {
    const permissions: Record<string, string[]> = {
      google: ['profile:read', 'email:read'],
      facebook: ['profile:read', 'email:read', 'friends:read'],
      github: ['profile:read', 'repos:read', 'email:read'],
      microsoft: ['profile:read', 'email:read', 'calendar:read'],
    };
    return permissions[this.provider] || ['profile:read'];
  }

  private getSimulatedAvatar(): string {
    return `https://api.dicebear.com/7.x/avataaars/svg?seed=${this.provider}`;
  }
}

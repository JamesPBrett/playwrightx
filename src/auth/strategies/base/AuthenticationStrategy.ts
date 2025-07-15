import { Page, BrowserContext } from '@playwright/test';

export interface AuthenticationCredentials {
  [key: string]: any;
}

export interface AuthenticationResult {
  success: boolean;
  token?: string;
  refreshToken?: string;
  userData?: UserData;
  errorMessage?: string;
  expiresAt?: Date;
  requiresMFA?: boolean;
  redirectUrl?: string;
  providerData?: ProviderSpecificData;
}

export interface UserData {
  id: string;
  email: string;
  name?: string;
  role: string;
  permissions: string[];
  avatar?: string;
  verified?: boolean;
  lastLogin?: Date;
  provider: string;
  providerId?: string;
}

export interface ProviderSpecificData {
  provider: string;
  scope?: string[];
  accessToken?: string;
  tokenType?: string;
  expiresIn?: number;
  state?: string;
  [key: string]: any;
}

export interface AuthenticationFlowStep {
  type: 'redirect' | 'form' | 'popup' | 'api' | 'wait';
  url?: string;
  selector?: string;
  data?: Record<string, any>;
  waitFor?: string | number;
  popup?: {
    url: string;
    windowName: string;
    features?: string;
  };
}

export interface AuthenticationFlow {
  steps: AuthenticationFlowStep[];
  finalRedirect?: string;
  successIndicators: string[];
  failureIndicators: string[];
}

/**
 * Base interface for all authentication strategies
 */
export interface IAuthenticationStrategy {
  readonly name: string;
  readonly type: 'password' | 'oauth' | 'saml' | 'apikey' | 'jwt' | 'social' | 'sso' | 'mfa';
  readonly provider?: string; // e.g., 'google', 'facebook', 'github'
  readonly version?: string;

  /**
   * Perform authentication with the given credentials
   */
  authenticate(
    credentials: AuthenticationCredentials,
    page: Page,
    context: BrowserContext,
  ): Promise<AuthenticationResult>;

  /**
   * Validate if a token/session is still valid
   */
  isValid(token?: string, userData?: UserData): Promise<boolean>;

  /**
   * Get the authentication flow for UI testing
   */
  getAuthenticationFlow?(credentials: AuthenticationCredentials): AuthenticationFlow;

  /**
   * Refresh authentication tokens
   */
  refreshAuth?(refreshToken: string): Promise<AuthenticationResult>;

  /**
   * Logout/cleanup
   */
  logout?(page: Page, context: BrowserContext): Promise<void>;

  /**
   * Get provider-specific configuration
   */
  getConfig?(): Record<string, any>;

  /**
   * Handle provider-specific redirects
   */
  handleRedirect?(url: string, page: Page): Promise<AuthenticationResult>;

  /**
   * Validate provider-specific requirements
   */
  validateCredentials?(credentials: AuthenticationCredentials): { valid: boolean; errors: string[] };
}

/**
 * Abstract base class for authentication strategies
 */
export abstract class BaseAuthenticationStrategy implements IAuthenticationStrategy {
  public abstract readonly name: string;
  public abstract readonly type: 'password' | 'oauth' | 'saml' | 'apikey' | 'jwt' | 'social' | 'sso' | 'mfa';
  public readonly provider?: string;
  public readonly version: string = '1.0.0';

  protected sessionId: string;

  constructor() {
    this.sessionId = this.generateSessionId();
  }

  public abstract authenticate(
    credentials: AuthenticationCredentials,
    page: Page,
    context: BrowserContext,
  ): Promise<AuthenticationResult>;

  public abstract isValid(token?: string, userData?: UserData): Promise<boolean>;

  protected generateSessionId(): string {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }

  protected async waitForElement(page: Page, selector: string, timeout: number = 5000): Promise<boolean> {
    try {
      await page.waitForSelector(selector, { timeout });
      return true;
    } catch {
      return false;
    }
  }

  protected async waitForUrl(page: Page, urlPattern: string | RegExp, timeout: number = 10000): Promise<boolean> {
    try {
      await page.waitForURL(urlPattern, { timeout });
      return true;
    } catch {
      return false;
    }
  }

  protected maskSensitiveData(data: any): any {
    if (typeof data === 'string') {
      return data.replace(/[a-zA-Z0-9+/]{20,}/g, '***MASKED***');
    }

    if (typeof data === 'object' && data !== null) {
      const masked = { ...data };
      const sensitiveKeys = ['password', 'token', 'secret', 'key', 'credential'];

      for (const key in masked) {
        if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {
          masked[key] = '***MASKED***';
        }
      }

      return masked;
    }

    return data;
  }

  public validateCredentials?(_credentials: AuthenticationCredentials): { valid: boolean; errors: string[] } {
    return { valid: true, errors: [] };
  }

  public async logout?(page: Page, context: BrowserContext): Promise<void> {
    // Default implementation - clear localStorage and cookies
    await context.clearCookies();
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  }
}

/**
 * Registry for managing authentication strategies
 */
export class AuthenticationStrategyRegistry {
  private static instance: AuthenticationStrategyRegistry;
  private strategies: Map<string, IAuthenticationStrategy> = new Map();
  private defaultStrategy?: string;

  private constructor() {}

  public static getInstance(): AuthenticationStrategyRegistry {
    if (!AuthenticationStrategyRegistry.instance) {
      AuthenticationStrategyRegistry.instance = new AuthenticationStrategyRegistry();
    }
    return AuthenticationStrategyRegistry.instance;
  }

  public register(strategy: IAuthenticationStrategy): void {
    this.strategies.set(strategy.name, strategy);
  }

  public unregister(name: string): void {
    this.strategies.delete(name);
  }

  public get(name: string): IAuthenticationStrategy | undefined {
    return this.strategies.get(name);
  }

  public getByType(type: string): IAuthenticationStrategy[] {
    return Array.from(this.strategies.values()).filter(s => s.type === type);
  }

  public getByProvider(provider: string): IAuthenticationStrategy[] {
    return Array.from(this.strategies.values()).filter(s => s.provider === provider);
  }

  public list(): { name: string; type: string; provider?: string }[] {
    return Array.from(this.strategies.values()).map(s => {
      const result: { name: string; type: string; provider?: string } = {
        name: s.name,
        type: s.type,
      };
      if (s.provider !== undefined) {
        result.provider = s.provider;
      }
      return result;
    });
  }

  public setDefault(name: string): void {
    if (this.strategies.has(name)) {
      this.defaultStrategy = name;
    } else {
      throw new Error(`Strategy ${name} not found`);
    }
  }

  public getDefault(): IAuthenticationStrategy | undefined {
    return this.defaultStrategy ? this.strategies.get(this.defaultStrategy) : undefined;
  }

  public clear(): void {
    this.strategies.clear();
    delete this.defaultStrategy;
  }
}
